#ifndef __HAGFISH_ALLOCATION_H
#define __HAGFISH_ALLOCATION_H

#include <Library/UefiLib.h>

#include <sys/types.h>

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
