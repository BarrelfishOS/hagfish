/*
 * Copyright (c) 2016, ETH Zurich.
 * Copyright (c) 2016, Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_LOADER_H
#define __HAGFISH_LOADER_H

#include <Uefi.h>
#include <Protocol/PxeBaseCode.h>

struct hagfish_loader;

typedef EFI_STATUS (*loader_file_size_fn)
        (struct hagfish_loader *, char *path, UINT64 *size);
typedef EFI_STATUS (*loader_file_read_fn)
        (struct hagfish_loader *, char *path, UINT64 *size, UINT8 *buffer);
typedef EFI_STATUS (*loader_multiboot_prepare)
        (struct hagfish_loader *, void **cursor);
typedef EFI_STATUS (*loader_config_file_name_fn)
        (struct hagfish_loader *, char *config_file_name, UINT64 size);
typedef EFI_STATUS (*loader_done_fn)
        (struct hagfish_loader *loader);
typedef EFI_STATUS (*loader_prepare_multiboot_fn)
        (struct hagfish_loader *loader, void **cursor);

enum hagfish_loader_type {
    HAGFISH_LOADER_NONE, HAGFISH_LOADER_PXE, HAGFISH_LOADER_FS
};

struct hagfish_loader_pxe {
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_IP_ADDRESS server_ip, my_ip;
};

struct hagfish_loader_fs {
    CHAR16* image;
};

struct hagfish_loader {
    loader_file_size_fn size_fn;
    loader_file_read_fn read_fn;
    loader_config_file_name_fn config_file_name_fn;
    loader_done_fn done_fn;
    loader_prepare_multiboot_fn prepare_multiboot_fn;
    EFI_HANDLE imageHandle;
    EFI_SYSTEM_TABLE *systemTable;
    EFI_LOADED_IMAGE_PROTOCOL *hagfishImage;
    enum hagfish_loader_type type;
    union d {
        struct hagfish_loader_pxe pxe;
        struct hagfish_loader_fs fs;
    } d;
};

EFI_STATUS
hagfish_loader_pxe_init(struct hagfish_loader *loader);

EFI_STATUS
hagfish_loader_fs_init(struct hagfish_loader *loader, CHAR16 *image);

#endif // __HAGFISH_LOADER_H
