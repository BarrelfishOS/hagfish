        DebugPrint(DEBUG_ERROR, "Relocation failed.\n");
        return EFI_LOAD_ERROR;
    }

    if(!found_entry_point) {
        DebugPrint(DEBUG_ERROR,
                   "Kernel entry point wasn't in any loaded segment.\n");
        return EFI_LOAD_ERROR;
    }
    cfg->kernel_entry= entry_point;

    /* Allocate a stack */
    cfg->kernel_stack= allocate_pages(COVER(cfg->stack_size, PAGE_4k),
                                      EfiBarrelfishCPUDriverStack);
    if(!cfg->kernel_stack) {
        DebugPrint(DEBUG_ERROR, "Failed allocate kernel stack\n");
        return EFI_OUT_OF_RESOURCES;
    }

    DebugPrint(DEBUG_INFO,
               "Relocated entry point is %p, stack at %p\n",
               cfg->kernel_entry, cfg->kernel_stack);

    /* Create the multiboot header. */
    if(!create_multiboot_info(cfg, pxe, img_elf, shnum)) {
        DebugPrint(DEBUG_ERROR, "Failed to create multiboot structure.\n");
        return EFI_SUCCESS;
    }

    /* Finished with the kernel ELF. */
    elf_end(img_elf);

    return EFI_SUCCESS;
}

void
acpi_search(struct hagfish_config *cfg) {
    DebugPrint(DEBUG_INFO, "Found %d EFI configuration tables\n",
               gST->NumberOfTableEntries);

    size_t i;
    for(i= 0; i < gST->NumberOfTableEntries; i++) {
        EFI_CONFIGURATION_TABLE *entry= &gST->ConfigurationTable[i];

        if(CompareGuid(&entry->VendorGuid, &gEfiAcpi20TableGuid)) {
            cfg->acpi2_header= entry->VendorTable;
            DebugPrint(DEBUG_INFO,
                       "ACPI 2.0 table at %p, signature \"% 8.8a\"\n",
                       cfg->acpi2_header,
                       (const char *)&cfg->acpi2_header->Signature);
        }
        else if(CompareGuid(&entry->VendorGuid, &gEfiAcpi10TableGuid)) {
            cfg->acpi1_header= entry->VendorTable;
            DebugPrint(DEBUG_INFO,
                       "ACPI 1.0 table at %p, signature \"% 8.8a\"\n",
                       cfg->acpi1_header,
                       (const char *)&cfg->acpi1_header->Signature);
        }
    }
}

EFI_LOADED_IMAGE_PROTOCOL *
my_image(void) {
    EFI_LOADED_IMAGE_PROTOCOL *hag_image;
    EFI_STATUS status;

    /* Connect to the loaded image protocol. */
    status= gST->BootServices->OpenProtocol(
                gImageHandle, &gEfiLoadedImageProtocolGuid,
                (void **)&hag_image, gImageHandle, NULL,
                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);

    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "OpenProtocol: %r\n", status);
        return NULL;
    }

    return hag_image;
}

EFI_STATUS
image_done(void) {
    EFI_STATUS status;

    status= gST->BootServices->CloseProtocol(
                gImageHandle, &gEfiLoadedImageProtocolGuid,
                gImageHandle, NULL);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "CloseProtocol: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

EFI_PXE_BASE_CODE_PROTOCOL *
pxe_loader(EFI_LOADED_IMAGE_PROTOCOL *image) {
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_STATUS status;

    status= gST->BootServices->OpenProtocol(
                image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                (void **)&pxe, gImageHandle, NULL,
                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);

    if(EFI_ERROR(status)) {
        AsciiPrint("OpenProtocol: %r\n", status);
        return NULL;
    }

    return pxe;
}

EFI_STATUS
pxe_done(EFI_LOADED_IMAGE_PROTOCOL *image) {
    EFI_STATUS status;

    status= gST->BootServices->CloseProtocol(
                image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                gImageHandle, NULL);

    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "CloseProtocol: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

/* Check that the PXE client is in a usable state, with networking configured,
 * and find both our and the server's IP addresses. */
EFI_STATUS
net_config(EFI_PXE_BASE_CODE_PROTOCOL *pxe,
           EFI_IP_ADDRESS *my_ip,
           EFI_IP_ADDRESS *server_ip) {
    DebugPrint(DEBUG_INFO, "PXE loader at %p, revision %x, %a\n",
               (UINT64)pxe,
               pxe->Revision,
               pxe->Mode->Started ? "running" : "stopped");

    if(!pxe->Mode->DhcpAckReceived) {
        DebugPrint(DEBUG_ERROR, "DHCP hasn't completed.\n");
        return EFI_NOT_READY;
    }

    if(pxe->Mode->UsingIpv6) {
        DebugPrint(DEBUG_ERROR, "PXE using IPv6, I can't handle that.\n");
        return EFI_LOAD_ERROR;
    }

    /* Grab the network details. */
    memcpy(my_ip, &pxe->Mode->StationIp, sizeof(EFI_IPv4_ADDRESS));
    DebugPrint(DEBUG_NET,
               "My IP address is %d.%d.%d.%d\n",
               my_ip->v4.Addr[0], my_ip->v4.Addr[1],
               my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    /* The octets in the DHCP packet are byte-aligned, but those in an
     * EFI_IP_ADDRESS are word-aligned, so we've got to copy by hand. */
    size_t i;
    for(i= 0; i < 4; i++)
        server_ip->v4.Addr[i]= pxe->Mode->DhcpAck.Dhcpv4.BootpSiAddr[i];
    DebugPrint(DEBUG_NET,
               "BOOTP server's IP address is %d.%d.%d.%d\n",
               server_ip->v4.Addr[0], server_ip->v4.Addr[1],
               server_ip->v4.Addr[2], server_ip->v4.Addr[3]);

    return EFI_SUCCESS;
}

struct hagfish_config *
load_config(EFI_PXE_BASE_CODE_PROTOCOL *pxe,
            EFI_IP_ADDRESS *my_ip,
            EFI_IP_ADDRESS *server_ip) {
    EFI_STATUS status;

    /* Load the host-specific configuration file. */
    char cfg_filename[256];
    UINTN cfg_size;
    snprintf(cfg_filename, 256, hagfish_config_fmt, 
             my_ip->v4.Addr[0], my_ip->v4.Addr[1],
             my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    DebugPrint(DEBUG_LOADFILE, "Loading \"%a\"\n", cfg_filename);

    /* Get the file size.  Note that even though this call doesn't touch the
     * supplied buffer (argument 3), it still fails if it's null.  Thus the
     * nonsense parameter. */
    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE, (void *)0x1,
                       FALSE, &cfg_size, NULL, server_ip,
                       (UINT8 *)cfg_filename, NULL, TRUE);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return NULL;
    }
    DebugPrint(DEBUG_LOADFILE, "File \"%a\" has size %dB\n",
               cfg_filename, cfg_size);

    void *cfg_buffer= malloc(cfg_size);
    if(!cfg_buffer) {
        DebugPrint(DEBUG_ERROR, "malloc: %a\n", strerror(errno));
        return NULL;
    }

    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_READ_FILE, cfg_buffer,
                       FALSE, &cfg_size, NULL, server_ip,
                       (UINT8 *)cfg_filename, NULL, FALSE);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return NULL;
    }
    DebugPrint(DEBUG_LOADFILE, "Loaded config at [%p-%p]\n",
               cfg_buffer, cfg_buffer + cfg_size - 1);

    DebugPrint(DEBUG_INFO, "Parsing configuration...");
    /* Parse the configuration file. */
    struct hagfish_config *cfg= parse_config(cfg_buffer, cfg_size);
    if(!cfg) {
        DebugPrint(DEBUG_ERROR, "Failed to parse Hagfish configuration.\n");
        return NULL;
    }
    DebugPrint(DEBUG_INFO, " done\n");

    return cfg;
}

EFI_STATUS
UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *hag_image;
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_IP_ADDRESS server_ip, my_ip;
    int i;

    AsciiPrint("Hagfish UEFI loader starting\n");

    DebugPrint(DEBUG_INFO, "UEFI vendor: %s\n", gST->FirmwareVendor);

    /* Get the details of our own process image. */
    hag_image= my_image();
    if(!hag_image) return EFI_SUCCESS;

    DebugPrint(DEBUG_INFO, "Hagfish loaded at %p, size %dB, by handle %p\n",
        hag_image->ImageBase, hag_image->ImageSize, hag_image->DeviceHandle);

    /* Find the PXE service that loaded us. */
    DebugPrint(DEBUG_INFO,
               "Connecting to the PXE service that loaded me.\n");
    pxe= pxe_loader(hag_image);
    if(!pxe) return EFI_SUCCESS;

    /* Check network status. */
    status= net_config(pxe, &my_ip, &server_ip);
    if(EFI_ERROR(status)) return EFI_SUCCESS;

    /* Load and parse the configuration file. */
    struct hagfish_config *cfg= load_config(pxe, &my_ip, &server_ip);
    if(!cfg) return EFI_SUCCESS;

    /* Load the kernel. */
    DebugPrint(DEBUG_INFO, "Loading the kernel [");
    if(!load_component(cfg->kernel, cfg->buf, pxe, &server_ip)) {
        DebugPrint(DEBUG_ERROR, "\nFailed to load the kernel.\n");
        return EFI_SUCCESS;
    }
    DebugPrint(DEBUG_INFO, "].\n");

    /* Load the modules */
    DebugPrint(DEBUG_INFO, "Loading init images [");
    {
        struct component_config *cmp;

        for(cmp= cfg->first_module; cmp; cmp= cmp->next) {
            if(cmp != cfg->first_module) DebugPrint(DEBUG_INFO, ", ");

            if(!load_component(cmp, cfg->buf, pxe, &server_ip)) {
                DebugPrint(DEBUG_ERROR, "Failed to load module.\n");
            return EFI_SUCCESS;
            }
        }
    }
    DebugPrint(DEBUG_INFO, "].\n");

    /* Print out the discovered RAM regions */
    status= update_ram_regions(cfg);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Failed to get RAM regions.\n");
        return EFI_SUCCESS;
    }
    print_ram_regions(cfg->ram_regions);

    /* Build the direct-mapped page tables for the kernel. */
    status= build_page_tables(cfg);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Failed to create initial page table.\n");
        return EFI_SUCCESS;
    }

    /* Load the CPU driver from its ELF image, and relocate it. */
    status= prepare_kernel(cfg, pxe);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Failed to prepare CPU driver.\n");
        return EFI_SUCCESS;
    }

    /* Finished with PXE. */
    status= pxe_done(hag_image);
    if(EFI_ERROR(status)) return EFI_SUCCESS;
    /* pxe is now invalid. */

    /* Finished with the loaded image protocol. */
    status= image_done();
    if(EFI_ERROR(status)) return EFI_SUCCESS;
    /* hag_image is now invalid. */

    status= arch_probe();
    if(EFI_ERROR(status)) return EFI_SUCCESS;

    /* Save the kernel entry point and other pointers (we're about to free
     * cfg).  As these copies are sitting on our stack, they'll be freed when
     * the CPU driver recycles Hagfish's memory regions. */
    void *kernel_entry= cfg->kernel_entry;
    void *multiboot= cfg->multiboot;
    void *kernel_stack= cfg->kernel_stack;
    size_t stack_size= cfg->stack_size;
    void *root_table= get_root_table(cfg);

    ASSERT(kernel_entry);
    ASSERT(multiboot);
    ASSERT(kernel_stack);
    ASSERT(stack_size > 0);
    ASSERT(root_table);

    /* Free all dynamically-allocated configuration that we're not passing to
     * the CPU driver. */
    free_bookkeeping(cfg);

    /* The last thing we do is to grab the final memory map, including any
     * allocations and deallocations we've done, as per the UEFI spec
     * recommendation.  This fills in the space we set aside in the multiboot
     * structure. */
    status= update_memory_map();
    if(EFI_ERROR(status)) return EFI_SUCCESS;

    /* Fill in the tag.  We can't use GetMemoryMap to fill these directly, as
     * the multiboot specification requires them to be 32 bit, while EFI may
     * return 64-bit values.  Note that 'mmap_tag' points *inside* the
     * structure pointed to by 'multiboot'. */
    cfg->mmap_tag->type= MULTIBOOT_TAG_TYPE_EFI_MMAP;
    cfg->mmap_tag->size= sizeof(struct multiboot_tag_efi_mmap) + mmap_size;
    cfg->mmap_tag->descr_size= mmap_d_size;
    cfg->mmap_tag->descr_vers= mmap_d_ver;

    /* Exit EFI boot services. */
    AsciiPrint("Terminating boot services and jumping to image at %p\n",
               kernel_entry);
    AsciiPrint("New stack pointer is %p\n",
               kernel_stack + stack_size - 16);

    status= gST->BootServices->ExitBootServices(
                gImageHandle, mmap_key);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ExitBootServices: %r\n", status);
        return EFI_SUCCESS;
    }

    /*** EFI boot services are now terminated, we're on our own. */

    /* Do MMU configuration, switch page tables. */
    arch_init(root_table);

    /* Jump to the start of the loaded image - doesn't return. */
    SwitchStack((SWITCH_STACK_ENTRY_POINT)kernel_entry,
                (void *)MULTIBOOT2_BOOTLOADER_MAGIC, multiboot,
                kernel_stack + stack_size - 16);

    return EFI_SUCCESS;
}
