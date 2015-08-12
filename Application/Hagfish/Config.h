/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_CONFIG_H
#define __HAGFISH_CONFIG_H

#include <sys/types.h>

/* EDK headers */
#include <IndustryStandard/Acpi.h>

/* The default inital stack size for the CPU driver, if it's not specified in
 * the configuration file. */
#define DEFAULT_STACK_SIZE 16384

extern const char *hagfish_config_fmt;

struct component_config {
    /* The offset and length of the image path, and argument strings for this
     * component. */
    size_t path_start, path_len;
    size_t args_start, args_len;

    /* The size and address of the loaded ELF image. */
    size_t image_size;
    void *image_address;

    struct component_config *next;
};

struct hagfish_config {
    /* The raw configuration file. */
    char *buf;

    /* The UEFI-supplied system parameters. */
    EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi2_header;
    EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi1_header;

    /* The multiboot information structure. */
    void *multiboot;

    /* Pointers (within the multiboot structure), to the memory map that needs
     * to be filled in after all allocation is finished. */
    struct multiboot_tag_efi_mmap *mmap_tag;
    void *mmap_start;

    /* The list of physical memory regions. */
    struct region_list *ram_regions;

    /* The kernel's initial page tables. */
    struct page_tables *tables;

    /* The CPU driver load information. */
    struct component_config *kernel;
    struct region_list *kernel_segments;
    void *kernel_entry;
    void *kernel_stack;
    size_t stack_size;

    /* The additional modules. */
    struct component_config *first_module, *last_module;
};

/* Application headers */
#include <Allocation.h>
#include <Hardware.h>
#include <Memory.h>

struct hagfish_config *parse_config(char *buf, size_t size);
void free_bookkeeping(struct hagfish_config *cfg);

#endif /* __HAGFISH_CONFIG_H */
