/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* EDK headers */
#include <Chipset/AArch64.h>
#include <Library/ArmLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Uefi.h>

/* Package headers */
#include <vm.h>

/* Application headers */
#include <Allocation.h>
#include <Config.h>
#include <Hardware.h>
#include <Memory.h>
#include <Util.h>

/* Number of pages reserved for page table allocations.
 * TODO: This should be dynamic! MH 20160525
 */
#define PAGE_TABLE_PAGES 128

struct page_tables {
    void *page_table_pages_pool;
    size_t free_pages;
    size_t total_pages;

    union aarch64_descriptor *L0_table;
};

void *
get_root_table(struct hagfish_config *cfg) {
    ASSERT(cfg);
    ASSERT(cfg->tables);
    ASSERT(cfg->tables->L0_table);

    return cfg->tables->L0_table;
}

void
dump_table(uint64_t vbase, uint64_t *table, size_t level) {
    size_t i;

    ASSERT(level <= 3);

    for(i= 0; i < TT_ENTRY_COUNT; i++) {
        uint64_t virtual= vbase + TT_ADDRESS_AT_LEVEL(level) * i;
        uint64_t type= table[i] & TT_TYPE_MASK;
        uint64_t base= table[i] & TT_ADDRESS_MASK_DESCRIPTION_TABLE;

        if(level < 3 && type == TT_TYPE_TABLE_ENTRY) {
            AsciiPrint("%d.%d table\n", level, i);
            dump_table(virtual, (uint64_t *)base, level+1);
        }
        else if(type == TT_TYPE_BLOCK_ENTRY ||
                (level == 3 && type == TT_TYPE_BLOCK_ENTRY_LEVEL3)) {
            AsciiPrint("%d.%d block %012llx -> %012llx\n",
                       level, i, virtual, base);
        }
    }
}

/*
 * Get the offset for an address in the n-th page table level.
 * This assumes 4k granularity.
 */
static inline
uint64_t get_offset(uint64_t address, size_t level) {
    return (address >> (ARMv8_BASE_PAGE_BITS + (3 - level) * ARMv8_BLOCK_BITS))
            & ARMv8_BLOCK_MASK;
}

static inline
uint64_t pages_per_entry_at_level(size_t level) {
    return 1 << ((3 - level) * ARMv8_BLOCK_BITS);
}

#define BLOCK_16G (ARMv8_HUGE_PAGE_SIZE * 16ULL)

static EFI_STATUS allocate_pt_page(struct page_tables *tables, void** page) {
    if (!tables->free_pages) {
        DebugPrint(DEBUG_ERROR, "No more page table pages available.\n");
        return EFI_LOAD_ERROR;
    }
    *page = tables->page_table_pages_pool
            + PAGE_4k * (tables->total_pages - tables->free_pages);
    ASSERT(((uint64_t) *page & ARMv8_BASE_PAGE_MASK) == 0);
    tables->free_pages--;
    memset(*page, 0, PAGE_4k);
    return EFI_SUCCESS;
}

static EFI_STATUS pt_get_Ln_desc(struct page_tables *tables,
        EFI_PHYSICAL_ADDRESS pa, size_t level, union aarch64_descriptor **desc) {
    EFI_STATUS status;
    ASSERT(level > 0 && level <= 3);
    union aarch64_descriptor *Lnm1_desc;
    size_t Ln_index = get_offset(pa, level);

    if (level == 1) {
        Lnm1_desc = &tables->L0_table[get_offset(pa, 0)];
    } else {
        status = pt_get_Ln_desc(tables, pa, level - 1, &Lnm1_desc);
        if (EFI_ERROR(status)) {
            DebugPrint(DEBUG_ERROR,
                    "Failed to allocate page table page for L%d.\n", level);
            return status;
        }
    }

    union aarch64_descriptor *Ln_desc;

    union aarch64_descriptor *Ln_page;
    if (!Lnm1_desc->d.valid) {
        // we have to insert an L0 entry
        status = allocate_pt_page(tables, (void **) &Ln_page);
        if (EFI_ERROR(status)) {
            DebugPrint(DEBUG_ERROR,
                    "Failed to allocate page table page for L%d.\n", level);
            return status;
        }
        // Pointer to next page table.
        Lnm1_desc->d.base = (uint64_t) Ln_page >> ARMv8_BASE_PAGE_BITS;
        // Page table
        Lnm1_desc->d.mb1 = 1;

        // Enable
        Lnm1_desc->d.valid = 1;
    } else {
        if (Lnm1_desc->d.mb1 != 1) {
            DebugPrint(DEBUG_ERROR,
                    "Got block pte where page expected@L%d, pa %p.\n", level, pa);
            return status;
        }
        Ln_page = (union aarch64_descriptor *) (uint64_t) (Lnm1_desc->d.base << ARMv8_BASE_PAGE_BITS);
    }

    *desc = &Ln_page[Ln_index];
    return EFI_SUCCESS;
}

static
EFI_STATUS pt_insert_Ln(struct page_tables *tables,
        EFI_PHYSICAL_ADDRESS pa, size_t level, size_t pages, size_t mair_index) {
    EFI_STATUS status;
    ASSERT(tables);

    union aarch64_descriptor *Ln_desc;

    status = pt_get_Ln_desc(tables, pa, level, &Ln_desc);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR,
                "Failed to get L0 descriptor.\n");
        return status;
    }

    union aarch64_descriptor *end = Ln_desc + pages;

    while (Ln_desc < end) {

        if (!Ln_desc->d.valid) {
            switch (level) {
            case 1: {
                Ln_desc->block_l1.contiguous = 0;
                Ln_desc->block_l1.base = pa >> ARMv8_HUGE_PAGE_BITS;
                /* Mark the accessed flag, so we don't get a fault. */
                Ln_desc->block_l1.af = 1;
                /* Outer shareable - coherent. */
                Ln_desc->block_l1.sh = 0;
                /* EL1+ only. */
                Ln_desc->block_l1.ap = 0;
                /* Memory type */
                Ln_desc->block_l1.attrindex = mair_index;
                /* A block. */
                Ln_desc->block_l1.mb0 = 0;
                Ln_desc->block_l1.valid = 1;
                pa += ARMv8_HUGE_PAGE_SIZE;
                break;
            }
            case 2: {
                Ln_desc->block_l2.contiguous = 0;
                Ln_desc->block_l2.base = pa >> ARMv8_LARGE_PAGE_BITS;
                /* Mark the accessed flag, so we don't get a fault. */
                Ln_desc->block_l2.af = 1;
                /* Outer shareable - coherent. */
                Ln_desc->block_l2.sh = 0;
                /* EL1+ only. */
                Ln_desc->block_l2.ap = 0;
                /* Memory type */
                Ln_desc->block_l2.attrindex = mair_index;
                /* A block. */
                Ln_desc->block_l2.mb0 = 0;
                Ln_desc->block_l2.valid = 1;
                pa += ARMv8_LARGE_PAGE_SIZE;
                break;
            }
            case 3: {
            // we have to insert an L3 entry
                Ln_desc->page.af = 1;
                Ln_desc->page.sh = 0;
                Ln_desc->page.ap = 0;
                /* Memory type */
                Ln_desc->page.attrindex = mair_index;
                Ln_desc->page.mb1 = 1;
                Ln_desc->page.valid = 1;
                Ln_desc->d.base = (uint64_t) pa >> ARMv8_BASE_PAGE_BITS;
                pa += ARMv8_BASE_PAGE_SIZE;
                break;
            }
            default: {
                DebugPrint(DEBUG_ERROR, "%a: Incorrect level L%d, pa %p.\n", __FUNCTION__, level, pa);
                return EFI_LOAD_ERROR;
            }
            }
        } else {
            DebugPrint(DEBUG_ERROR, "Inserting duplicate pt entry@L%d, pa %p.\n", level, pa);
            return EFI_LOAD_ERROR;
        }
        Ln_desc++;
    }
    return EFI_SUCCESS;
}

size_t
map_attr_to_mair(UINT64 Attribute) {
    // TODO: BF on TMAS uses index 0 for normal memory and 1 for device
    if ((Attribute & 0xF) == 1) {
        // Memory only supports UC
        return 1;
    }
    return 0;
}

static EFI_STATUS
build_page_table_region(struct page_tables *tables, struct ram_region *desc) {
    EFI_STATUS status;
    size_t mair_index = map_attr_to_mair(desc->efi_attributes);

    uint64_t pages_left = desc->npages;

    uint64_t pos = desc->base;

    for (size_t i = 3; i > 0; i--) {
        if (get_offset(pos, i) > 0 && pages_left >= pages_per_entry_at_level(i)) {
            size_t pages_here = MIN(pages_left / pages_per_entry_at_level(i),
                    ARMv8_BLOCK_SIZE - get_offset(pos, i));
            status = pt_insert_Ln(tables, pos, i, pages_here, mair_index);
            if (EFI_ERROR(status)) {
                DebugPrint(DEBUG_ERROR, "Failed to insert into L%d.\n", i);
                return status;
            }
            size_t pages_added = pages_here * pages_per_entry_at_level(i);
            pages_left -= pages_added;
            size_t k = 0;
            pos += pages_added * PAGE_4k;
        }
    }

    // Here: pos mod 1G == 0 or pages_left == 0

    while (pages_left >= pages_per_entry_at_level(1)) {
        size_t pages_here = pages_left / pages_per_entry_at_level(1);
        status = pt_insert_Ln(tables, pos, 1, pages_here, mair_index);
        if (EFI_ERROR(status)) {
            DebugPrint(DEBUG_ERROR, "Failed to insert into L1.\n");
            return status;
        }
        // equivalent number of 4k pages.
        size_t pages_added = pages_here * pages_per_entry_at_level(1);
        pages_left -= pages_added;
        size_t k = 0;
        pos += pages_added * PAGE_4k;
    }

    for (size_t i = 2; i <= 3; i++) {
        size_t pages_here = pages_left / pages_per_entry_at_level(i);
        if (pages_here > 0) {
            status = pt_insert_Ln(tables, pos, i, pages_here, mair_index);
            if (EFI_ERROR(status)) {
                DebugPrint(DEBUG_ERROR, "Failed to insert into L%d.\n", i);
                return status;
            }
            pages_left -= pages_per_entry_at_level(i) * pages_here;
            pos += pages_per_entry_at_level(i) * PAGE_4k * pages_here;
        }
    }

    ASSERT(pos == desc->base + PAGE_4k * desc->npages);
    return EFI_SUCCESS;
}

EFI_STATUS
build_page_tables(struct hagfish_config *cfg) {
    EFI_STATUS status= EFI_SUCCESS;

    status= update_ram_regions(cfg);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Failed to get RAM regions.\n");
        goto build_page_tables_fail;
    }
    struct region_list *list= cfg->ram_regions;

    if(list->nregions == 0) {
        DebugPrint(DEBUG_ERROR, "No memory regions defined.\n");
        status= EFI_LOAD_ERROR;
        goto build_page_tables_fail;
    }

    cfg->tables= calloc(1, sizeof(struct page_tables));
    if(!cfg->tables) {
        DebugPrint(DEBUG_ERROR, "calloc: %a\n", strerror(errno));
        status= EFI_OUT_OF_RESOURCES;
        goto build_page_tables_fail;
    }

    uint64_t pages = PAGE_TABLE_PAGES;

    cfg->tables->page_table_pages_pool = allocate_pages(pages, EfiBarrelfishBootPageTable);
    if (!cfg->tables->page_table_pages_pool) {
        DebugPrint(DEBUG_ERROR, "allocate_pages: %a\n", strerror(errno));
        status= EFI_OUT_OF_RESOURCES;
        goto build_page_tables_fail;
    }
    cfg->tables->free_pages = pages;
    cfg->tables->total_pages = pages;

    status = allocate_pt_page(cfg->tables, (void **) &cfg->tables->L0_table);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "allocate_pt_pages failed.\n");
        goto build_page_tables_fail;
    }

    // TODO: Populate contiguous bit if possible

    for (size_t i= 0; i < cfg->ram_regions->nregions; i++) {
        struct ram_region *desc = &cfg->ram_regions->regions[i];

        status = build_page_table_region(cfg->tables, desc);

        if (EFI_ERROR(status)) {
            DebugPrint(DEBUG_ERROR, "Failed to insert memory region %d.\n", i);
            return status;
        }

    }

    return EFI_SUCCESS;

build_page_tables_fail:
    if(cfg->tables) {
        if(cfg->tables->page_table_pages_pool) {
            FreePages(cfg->tables->page_table_pages_pool, cfg->tables->total_pages);
        }
        free(cfg->tables);
    }

    return status;
}

void
free_page_table_bookkeeping(struct page_tables *tables) {
    free(tables);
}

EFI_STATUS
describe_tcr(UINTN tcr) {
    DebugPrint(DEBUG_INFO, "  Physical addresses are ");
    switch(tcr & TCR_EL23_PS_MASK) {
        case TCR_PS_4GB:
            DebugPrint(DEBUG_INFO, "32b (4GB)\n");
            break;
        case TCR_PS_64GB:
            DebugPrint(DEBUG_INFO, "36b (64GB)\n");
            break;
        case TCR_PS_1TB:
            DebugPrint(DEBUG_INFO, "40b (1TB)\n");
            break;
        case TCR_PS_4TB:
            DebugPrint(DEBUG_INFO, "42b (4TB)\n");
            break;
        case TCR_PS_16TB:
            DebugPrint(DEBUG_INFO, "44b (16TB)\n");
            break;
        case TCR_PS_256TB:
            DebugPrint(DEBUG_INFO, "48b (256TB)\n");
            break;
        default:
            DebugPrint(DEBUG_INFO, "unknown!\n");
            return EFI_UNSUPPORTED;
    }

    DebugPrint(DEBUG_INFO, "  Translation granule is ");
    switch(tcr & TCR_EL23_TG0_MASK) {
        case TCR_TG0_4KB:
            DebugPrint(DEBUG_INFO, "4kB\n");
            break;
        case 1:
            DebugPrint(DEBUG_INFO, "64kB\n");
            break;
        case 2:
            DebugPrint(DEBUG_INFO, "16kB\n");
            break;
        default:
            DebugPrint(DEBUG_INFO, "unknown or unsupported.\n");
            return EFI_UNSUPPORTED;
    }

    DebugPrint(DEBUG_INFO, "  Table walks are ");
    switch(tcr & TCR_EL23_SH0_MASK) {
        case TCR_SH_NON_SHAREABLE:
            DebugPrint(DEBUG_INFO, "unsharable (non-coherent).\n");
            break;
        case TCR_SH_OUTER_SHAREABLE:
            DebugPrint(DEBUG_INFO, "outer sharable (coherent).\n");
            break;
        case TCR_SH_INNER_SHAREABLE:
            DebugPrint(DEBUG_INFO, "inner sharable (coherent).\n");
            break;
        default:
            DebugPrint(DEBUG_INFO, "unknown or unsupported.\n");
            return EFI_UNSUPPORTED;
    }

    DebugPrint(DEBUG_INFO, "  Outer caching is ");
    switch(tcr & TCR_EL23_ORGN0_MASK) {
        case TCR_RGN_OUTER_NON_CACHEABLE:
            DebugPrint(DEBUG_INFO, "disabled.\n");
            break;
        case TCR_RGN_OUTER_WRITE_BACK_ALLOC:
            DebugPrint(DEBUG_INFO, "write-back, write-allocate.\n");
            break;
        case TCR_RGN_OUTER_WRITE_THROUGH:
            DebugPrint(DEBUG_INFO, "write-through.\n");
            break;
        case TCR_RGN_OUTER_WRITE_BACK_NO_ALLOC:
            DebugPrint(DEBUG_INFO, "write-back, no write-allocate.\n");
            break;
        default:
            DebugPrint(DEBUG_INFO, "unknown or unsupported.\n");
            return EFI_UNSUPPORTED;
    }

    DebugPrint(DEBUG_INFO, "  Inner caching is ");
    switch(tcr & TCR_EL23_IRGN0_MASK) {
        case TCR_RGN_INNER_NON_CACHEABLE:
            DebugPrint(DEBUG_INFO, "disabled.\n");
            break;
        case TCR_RGN_INNER_WRITE_BACK_ALLOC:
            DebugPrint(DEBUG_INFO, "write-back, write-allocate.\n");
            break;
        case TCR_RGN_INNER_WRITE_THROUGH:
            DebugPrint(DEBUG_INFO, "write-through.\n");
            break;
        case TCR_RGN_INNER_WRITE_BACK_NO_ALLOC:
            DebugPrint(DEBUG_INFO, "write-back, no write-allocate.\n");
            break;
        default:
            DebugPrint(DEBUG_INFO, "unknown or unsupported.\n");
            return EFI_UNSUPPORTED;
    }

    UINTN t0sz= tcr & TCR_T0SZ_MASK;
    DebugPrint(DEBUG_INFO, "  EL2 virtual address region is %db (%dGB)\n",
               64 - t0sz, 1 << (64 - t0sz - 30));

    return EFI_SUCCESS;
}

EFI_STATUS
arch_probe(void) {
    EFI_STATUS status;

    DebugPrint(DEBUG_INFO, "AArch64: CPU initialisation.\n");

    if(ArmMmuEnabled()) DebugPrint(DEBUG_INFO, "AArch64: MMU is enabled.\n");
    else {
        DebugPrint(DEBUG_ERROR,
                   "AArch64: MMU is disabled: I didn't expect that.\n");
        return EFI_UNSUPPORTED;
    }

    UINTN current_el= ArmReadCurrentEL();
    switch(current_el) {
        case AARCH64_EL2:
            DebugPrint(DEBUG_INFO, "AArch64: Executing at EL2.\n");
            break;
        default:
            DebugPrint(DEBUG_ERROR, "AArch64: Unknown or unsupported EL.\n");
            return EFI_UNSUPPORTED;
    }

    DebugPrint(DEBUG_INFO, "AArch64: EFI-supplied page table root is %p\n",
               ArmGetTTBR0BaseAddress());

    DebugPrint(DEBUG_INFO, "AArch64: Current configuration:\n");
    UINTN tcr= ArmGetTCR();
    status= describe_tcr(tcr);
    if(EFI_ERROR(status)) return status;

    return EFI_SUCCESS;
}

void
arch_init(void *L0_table) {
    /* Configure a 48b physical address space, with a 4kB translation granule,
     * and non-coherent non-shared table access, in a 48b virtual region. */
    /* XXX - Revisit the coherence/caching decision. */
    UINTN newtcr= TCR_PS_256TB | TCR_TG0_4KB | TCR_SH_NON_SHAREABLE
                | TCR_RGN_OUTER_NON_CACHEABLE | TCR_RGN_INNER_NON_CACHEABLE
                | (64 - 48) /* T0SZ */;

    /* We don't want an interrupt handler to fire during the table switch. */
    ArmDisableInterrupts();

    /* Clean the data cache, to ensure that all table entries are in RAM.
     * Note that we just set table walks to uncached.  This drains the write
     * buffer and does a store barrier internally. */
    ArmCleanDataCache();

    /* Switch the table root and translation configuration. */
    ArmSetTTBR0(L0_table);
    ArmSetTCR(newtcr);

    /* Invalidate the TLB, to flush the old table's mappings. */
    ArmInvalidateTlb();

    /* Invalidate the instruction cache, and perform a barrier to ensure that
     * all instructions from this point on are fetched via the new mappings. */
    ArmInvalidateInstructionCache();
    ArmInstructionSynchronizationBarrier();

    /* Interrupts are now safe again. */
    ArmEnableInterrupts();
}
