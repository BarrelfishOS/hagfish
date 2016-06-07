/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_MEMORY_H
#define __HAGFISH_MEMORY_H

#include <stdint.h>

/* EDK headers */
#include <Uefi.h>

#define PAGE_4k (1<<12)

/* We preallocate space for the memory map, to avoid the recursion between
 * checking the memory map size and allocating memory for it.  This will
 * obviously fail if the memory map is particularly big. */
#define MEM_MAP_SIZE 8192
extern char mmap[];
extern UINTN mmap_size, mmap_key, mmap_d_size;
extern UINT32 mmap_d_ver;

struct ram_region {
    uint64_t base;
    uint64_t npages;
};

struct region_list {
    size_t nregions;
    struct ram_region regions[0];
};

/* Application headers */
#include <Config.h>

EFI_STATUS update_ram_regions(struct hagfish_config *cfg);
struct region_list *get_region_list(struct hagfish_config *cfg);
void free_region_list(struct region_list *list);
size_t search_region_list(struct region_list *list, uint64_t addr);
void print_ram_regions(struct region_list *region_list);
EFI_STATUS update_memory_map(void);
void print_memory_map(int update_map);

#endif /* __HAGFISH_MEMORY_H */
