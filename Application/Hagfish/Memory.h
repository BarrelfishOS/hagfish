#ifndef __HAGFISH_MEMORY_H
#define __HAGFISH_MEMORY_H

#include <Uefi.h>

#include <stdint.h>

#define PAGE_4k (1<<12)

struct ram_region {
    uint64_t base;
    uint64_t npages;
};

struct region_list {
    size_t nregions;
    struct ram_region regions[0];
};

struct region_list *get_region_list(EFI_SYSTEM_TABLE *SystemTable);
void print_ram_regions(struct region_list *region_list);
EFI_STATUS get_memory_map(EFI_SYSTEM_TABLE *SystemTable, UINTN *mmap_size,
                          UINTN *mmap_key, UINTN *mmap_d_size,
                          UINT32 *mmap_d_ver, void *mmap);
void print_memory_map(EFI_SYSTEM_TABLE *SystemTable);

#endif /* __HAGFISH_MEMORY_H */
