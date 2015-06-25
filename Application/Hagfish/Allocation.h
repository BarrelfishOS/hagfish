#ifndef __HAGFISH_ALLOCATION_H
#define __HAGFISH_ALLOCATION_H

#include <Library/UefiLib.h>

#include <unix.h> /* XXX switch to LibC */

/* We preallocate space for the memory map, to avoid the recursion between
 * checking the memory map size and allocating memory for it.  This will
 * obviously fail if the memory map is particularly big. */
#define MEM_MAP_SIZE 8192

/* We allocate three new EFI memory types to signal to the CPU driver where
 * its code, data, stack and Multiboot info block are located, so that it can
 * avoid trampling on them. */
typedef enum {
    EfiBarrelfishFirstMemType=   0x80000000,

    EfiBarrelfishCPUDriver=      0x80000000,
    EfiBarrelfishCPUDriverStack= 0x80000001,
    EfiBarrelfishMultibootData=  0x80000002,
    EfiBarrelfishELFData=        0x80000003,
    EfiBarrelfishBootPageTable=  0x80000004,

    EfiBarrelfishMaxMemType
} EFI_BARRELFISH_MEMORY_TYPE;

void *allocate_pages(size_t n, EFI_MEMORY_TYPE type);
void *allocate_pool(size_t size, EFI_MEMORY_TYPE type);
void *allocate_zero_pool(size_t size, EFI_MEMORY_TYPE type);

#endif /* __HAGFISH_ALLOCATION_H */
