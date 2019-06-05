/**
 * \file
 * \brief Data sent to a newly booted kernel
 */

/*
 * Copyright (c) 2012, 2017 ETH Zurich.
 * Copyright (c) 2015, 2016 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _AARCH64_COREDATA_H
#define _AARCH64_COREDATA_H

#include <Uefi.h>


#define ARMV8_BOOTMAGIC_BSP     0xb001b000
#define ARMV8_BOOTMAGIC_PSCI    0xb001b001
#define ARMV8_BOOTMAGIC_PARKING 0xb001b002

#define ARMV8_CORE_DATA_SIGNAL_BOOTING  0x4321
#define ARMV8_CORE_DATA_SIGNAL_READY    0x1234

/**
 * \brief Data sent to a newly booted kernel
 *
 */
struct armv8_core_data 
{
    /**
     * ARMv8 Boot magic field. Contains the value ARMV8_BOOTMAGIC_*
     */
    UINT64 boot_magic;

    /**
     * kernel virtual address of the cpudriver's stack
     */
    EFI_VIRTUAL_ADDRESS cpu_driver_stack;

    /**
     * kernel virtual address of the cpudriver's stack limit (including)
     */
    EFI_VIRTUAL_ADDRESS cpu_driver_stack_limit;

    /**
     * kernel virtual address of the globals pointer
     */
    EFI_VIRTUAL_ADDRESS cpu_driver_globals_pointer;

    /**
     * kernel virtual address of the cpudriver's entry point
     */
    EFI_VIRTUAL_ADDRESS cpu_driver_entry;

    /**
     * Physical address of the L0 page table in memory
     */
    EFI_PHYSICAL_ADDRESS page_table_root;

    /**
     * kernel virtual address of the cpudriver's kernel controll block
     * BSP: allocated by itself
     * APP: allocated by coreboot driver
     */
    EFI_VIRTUAL_ADDRESS kcb; 

    /**
     * CPU driver command line arguments
     */
    char cpu_driver_cmdline[256];

    /**
     * Memory region to be used for the new CPU driver's allocations
     * BSP: extracted from the EFI MMAP by the cpu driver
     * APP: set by coreboot driver
     */
    EFI_MEMORY_DESCRIPTOR alloc_memory;

    /**
     * Memory region that holds the inter-monitor URPC frame
     * BSP: unused
     * APP: set by coreboot driver
     */
    EFI_MEMORY_DESCRIPTOR urpc_frame;

    /**
     * Memory region that holds the monitor ELF for the app core
     * BSP: unused
     * APP: set by coreboot driver
     */
    EFI_MEMORY_DESCRIPTOR init_binary;

    /**
     * memory region of the multiboot image
     */
    union {
        EFI_VIRTUAL_ADDRESS multiboot_info_addr;
        struct multiboot_info *multiboot_info;
    };

    /**
     * pointer to the multiboot EFI mmap structure inside the multiboot image
     */
    union {
        EFI_VIRTUAL_ADDRESS efi_mmap_addr;
        struct multiboot_tag_efi_mmap *efi_mmap;
    };

    /**
     * the barrelfish coreid that started us
     */
    UINT16 src_core_id;

    /**
     * our own barrelfish coreid
     */
    UINT16 dst_core_id;

    /**
     * the hardware id of the core that started us
     */
    UINT64 src_arch_id;

    /**
     * our own hardware ID
     */
    UINT64 dst_arch_id;

    /**
     * the IPI channel identifier for the intermon channel
     */
    UINT64 chan_id;
    
    /**
     * signal the coreboot driver that we're up and running 
     */    
    UINT64 signal;
};

#endif
