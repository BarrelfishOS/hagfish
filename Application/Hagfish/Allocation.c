#include <string.h>

/* EDK headers */
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

/* Application headers */
#include <Allocation.h>

void *
allocate_pages(size_t n, EFI_MEMORY_TYPE type) {
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS memory;

    if(n == 0) return NULL;

    status = gBS->AllocatePages(AllocateAnyPages, type, n, &memory);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "AllocatePages: %r\n", status);
        return NULL;
    }

    return (void *)memory;
}

void *
allocate_pool(size_t size, EFI_MEMORY_TYPE type) {
    EFI_STATUS status;
    void *memory;

    if(size == 0) return NULL;

    status = gBS->AllocatePool(type, size, &memory);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "AllocatePages: %r\n", status);
        return NULL;
    }

    return memory;
}

void *
allocate_zero_pool(size_t size, EFI_MEMORY_TYPE type) {
    void *memory= allocate_pool(size, type);

    if(memory) memset(memory, 0, size);

    return memory;
}
