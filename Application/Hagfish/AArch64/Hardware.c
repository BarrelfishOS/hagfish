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
#include <Util.h>

struct page_tables {
    size_t nL1;

    union aarch64_descriptor *L0_table;
    union aarch64_descriptor **L1_tables;
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

#define BLOCK_16G (ARMv8_HUGE_PAGE_SIZE * 16ULL)

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

    /* Map up to the highest RAM address supplied by EFI.  XXX - this is a
     * heuristic, and may fail.  Unless there's a more clever way to do
     * discovery, we might need to bite the bullet and map all 48 bits (2MB of
     * kernel page tables!).  All we really need is that the kernel gets all
     * RAM, and the debug serial port - it shouldn't actually touch anything
     * else. */
    uint64_t first_address, last_address;
    first_address= 0;
    last_address= list->regions[list->nregions-1].base
                + list->regions[list->nregions-1].npages * PAGE_4k - 1;

    DebugPrint(DEBUG_INFO, "Kernel physical window from %llx to %llx\n",
               first_address, last_address);

    /* We will map in aligned 16G blocks, as each requires only one TLB
     * entry. */
    uint64_t window_start, window_length;
    window_start= first_address & ~BLOCK_16G;
    window_length= ROUNDUP(last_address - window_start, BLOCK_16G);

    DebugPrint(DEBUG_INFO, "Mapping 16GB blocks from %llx to %llx\n",
               window_start, window_start + window_length - 1);

    cfg->tables->L0_table= allocate_pages(1, EfiBarrelfishBootPageTable);
    if(!cfg->tables->L0_table) {
        DebugPrint(DEBUG_ERROR, "Failed to allocate L0 page table.\n");
        goto build_page_tables_fail;
    }
    memset(cfg->tables->L0_table, 0, PAGE_4k);

    /* Count the number of L1 tables (512GB) blocks required to cover the
     * physical mapping window. */
    cfg->tables->nL1= 0;
    uint64_t L1base= window_start & ~ARMv8_TOP_TABLE_SIZE;
    uint64_t L1addr;
    for(L1addr= window_start & ~ARMv8_TOP_TABLE_SIZE;
        L1addr < window_start + window_length;
        L1addr+= ARMv8_TOP_TABLE_SIZE) {
        cfg->tables->nL1++;
    }

    DebugPrint(DEBUG_INFO, "Allocating %d L1 tables\n", cfg->tables->nL1);

    /* ALlocate the L1 table pointers. */
    cfg->tables->L1_tables=
        calloc(cfg->tables->nL1, sizeof(union aarch64_descriptor *));
    if(!cfg->tables->L1_tables) {
        DebugPrint(DEBUG_ERROR,
                   "Failed to allocate L1 page table pointers.\n");
        goto build_page_tables_fail;
    }

    /* Allocate the L1 tables. */
    size_t i;
    for(i= 0; i < cfg->tables->nL1; i++) {
        cfg->tables->L1_tables[i]=
            allocate_pages(1, EfiBarrelfishBootPageTable);
        if(!cfg->tables->L1_tables[i]) {
            DebugPrint(DEBUG_ERROR, "Failed to allocate L1 page tables.\n");
            goto build_page_tables_fail;
        }
        memset(cfg->tables->L1_tables[i], 0, PAGE_4k);

        /* Map the L1 into the L0. */
        size_t L0_index= (L1base >> ARMv8_TOP_TABLE_BITS) + i;
        cfg->tables->L0_table[L0_index].d.base=
            (uint64_t)cfg->tables->L1_tables[i] >> ARMv8_BASE_PAGE_BITS;
        cfg->tables->L0_table[L0_index].d.mb1=   1; /* Page table */
        cfg->tables->L0_table[L0_index].d.valid= 1;
    }

    /* Install the 1GB block mappings. */
    uint64_t firstblock= window_start / ARMv8_HUGE_PAGE_SIZE;
    uint64_t nblocks= window_length / ARMv8_HUGE_PAGE_SIZE;
    uint64_t block;
    for(block= firstblock; block < firstblock + nblocks; block++) {
        size_t table_number= block >> ARMv8_BLOCK_BITS;
        size_t table_index= block & ARMv8_BLOCK_MASK;
        union aarch64_descriptor *desc =
            &cfg->tables->L1_tables[table_number][table_index];

        /* We're mapping 16GB contiguous blocks, to save TLB entries. */
        desc->block_l1.contiguous= 1;
        desc->block_l1.base= block;
        /* Mark the accessed flag, so we don't get a fault. */
        desc->block_l1.af= 1;
        /* Outer shareable - coherent. */
        desc->block_l1.sh= 2;
        /* EL1+ only. */
        desc->block_l1.ap= 0;
        /* Normal memory XXX set up MAIR_EL{1,2}[0]. */
        desc->block_l1.attrindex= 0;
        /* A block. */
        desc->block_l1.mb0= 0;
        desc->block_l1.valid= 1;
    }

    return EFI_SUCCESS;

build_page_tables_fail:
    if(cfg->tables) {
        if(cfg->tables->L1_tables) {
            size_t i;
            for(i= 0; i < cfg->tables->nL1; i++) {
                if(cfg->tables->L1_tables[i])
                    FreePages(cfg->tables->L1_tables[i], 1);
            }
            free(cfg->tables->L1_tables);
        }
        if(cfg->tables->L0_table) FreePages(cfg->tables->L0_table, 1);
        free(cfg->tables);
    }

    return status;
}

void
free_page_table_bookkeeping(struct page_tables *tables) {
    free(tables->L1_tables);
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
