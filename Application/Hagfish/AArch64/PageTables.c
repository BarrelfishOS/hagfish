#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* EDK headers */
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Uefi.h>

/* Package headers */
#include <vm.h>

/* Application headers */
#include <Allocation.h>
#include <Config.h>
#include <PageTables.h>
#include <Util.h>

struct page_tables {
    size_t nL1;

    union aarch64_descriptor *L0_table;
    union aarch64_descriptor **L1_tables;
};

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

    uint64_t first_address, last_address;
    first_address= list->regions[0].base;
    last_address= list->regions[list->nregions-1].base
                + list->regions[list->nregions-1].npages * PAGE_4k - 1;

    DebugPrint(DEBUG_INFO, "RAM window from %llx to %llx\n",
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
