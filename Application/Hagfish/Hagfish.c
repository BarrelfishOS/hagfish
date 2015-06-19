/* @file Hagfish.c
*/

#include <libelf.h>

#include <Uefi.h>

#include <Guid/Acpi.h>
#include <Guid/SmBios.h>

#include <IndustryStandard/Acpi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/PxeBaseCode.h>

void
dump(UINT32 *base, int len) {
    int j;

    AsciiPrint("Dump %p\n", base);
    for(j= 0; j*sizeof(UINT32) < len; j++) {
        AsciiPrint("%08.8x\n", base[j]);
    }
    AsciiPrint("\n");
}

typedef void (*cpu_driver_entry)(void *acpi_root, void *memory_map);

EFI_STATUS EFIAPI
UefiMain (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *hag_image;
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_IP_ADDRESS server_ip, *my_ip;
    EFI_ACPI_2_0_COMMON_HEADER *acpi_header= NULL;
    int i;

    AsciiPrint("Hagfish UEFI loader starting\n");
    AsciiPrint("UEFI vendor: ");
    Print(SystemTable->FirmwareVendor);
    AsciiPrint("\n");

    status= SystemTable->BootServices->OpenProtocol(
                ImageHandle, &gEfiLoadedImageProtocolGuid,
                (void **)&hag_image, ImageHandle, NULL,
                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("OpenProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    AsciiPrint("Hagfish loaded at %p, size %dB, by handle %p\n",
        hag_image->ImageBase, hag_image->ImageSize, hag_image->DeviceHandle);

    AsciiPrint("Found %d tables\n",
               SystemTable->NumberOfTableEntries);
    for(i= 0; i < SystemTable->NumberOfTableEntries; i++) {
        EFI_CONFIGURATION_TABLE *entry= &SystemTable->ConfigurationTable[i];

        if(CompareGuid(&entry->VendorGuid, &gEfiAcpi20TableGuid)) {
            acpi_header= entry->VendorTable;
            AsciiPrint("ACPI 2.0 table at 0x%p, signature \"% 8.8a\"\n",
                       acpi_header, (const char *)&acpi_header->Signature);
        }
    }

    AsciiPrint("Trying to connect to the PXE service that loaded me.\n");
    status= SystemTable->BootServices->OpenProtocol(
                hag_image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                (void **)&pxe, ImageHandle, NULL,
                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("OpenProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    AsciiPrint("PXE loader at %p, revision %x, %a\n",
               (UINT64)pxe,
               pxe->Revision,
               pxe->Mode->Started ? "running" : "stopped");

    if(!pxe->Mode->DhcpAckReceived) {
        AsciiPrint("DHCP hasn't completed.\n");
        return EFI_SUCCESS;
    }

    if(pxe->Mode->UsingIpv6) {
        AsciiPrint("PXE using IPv6, I can't handle that.\n");
        return EFI_SUCCESS;
    }

    my_ip= &pxe->Mode->StationIp;

    AsciiPrint("My IP %d.%d.%d.%d\n",
               my_ip->v4.Addr[0], my_ip->v4.Addr[1],
               my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    for(i= 0; i < 4; i++)
        server_ip.v4.Addr[i]= pxe->Mode->DhcpAck.Dhcpv4.BootpSiAddr[i];

    AsciiPrint("BOOTP server %d.%d.%d.%d\n",
               server_ip.v4.Addr[0], server_ip.v4.Addr[1],
               server_ip.v4.Addr[2], server_ip.v4.Addr[3]);

    char *filename= "xgene-test.elf";
    UINT64 size;
    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE, (void *)0x1,
                       FALSE, &size, NULL, &server_ip, (UINT8 *)filename,
                       NULL, TRUE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }
    AsciiPrint("File \"%a\" has size %dB\n", filename, size);

    /* Calculate number of 4k pages required (rounding up). */
    UINTN npages= (size + (4096-1)) / 4096;
    void *img_buffer;

    status= SystemTable->BootServices->AllocatePages(
                AllocateAnyPages, EfiLoaderData, npages,
                (EFI_PHYSICAL_ADDRESS *)&img_buffer);
    if(status != EFI_SUCCESS) {
        AsciiPrint("AllocatePages: %r\n", status);
        return EFI_SUCCESS;
    }
    AsciiPrint("Allocated %d pages at %p\n", npages, img_buffer);

    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_READ_FILE, img_buffer,
                       FALSE, &size, NULL, &server_ip, (UINT8 *)filename,
                       NULL, FALSE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }
    AsciiPrint("Loaded image at [%p-%p]\n", img_buffer, (img_buffer+size) - 1);

    status= SystemTable->BootServices->CloseProtocol(
                hag_image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                ImageHandle, NULL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("CloseProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    status= SystemTable->BootServices->CloseProtocol(
                ImageHandle, &gEfiLoadedImageProtocolGuid,
                ImageHandle, NULL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("CloseProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    elf_version(EV_CURRENT);

    Elf *img_elf= elf_memory(img_buffer, size);
    if(!img_elf) {
        AsciiPrint("elf_memory: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }

    size_t n_scn;
    status= elf_getshdrnum(img_elf, &n_scn);
    if(status) {
        AsciiPrint("elf_getshdrnum: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }

    const char *e_ident= elf_getident(img_elf, NULL);
    if(!e_ident) {
        AsciiPrint("elf_getident: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }

    if(e_ident[EI_CLASS] != ELFCLASS64 || e_ident[EI_DATA] != ELFDATA2LSB) {
        AsciiPrint("Error: Not a 64-bit little-endian ELF\n");
        return EFI_SUCCESS;
    }

    if(e_ident[EI_OSABI] != ELFOSABI_STANDALONE &&
       e_ident[EI_OSABI] != ELFOSABI_NONE) {
        AsciiPrint("Warn: Compiled for OS ABI %d.  Wrong compiler?\n",
                   e_ident[EI_OSABI]);
    }

    Elf64_Ehdr *ehdr= elf64_getehdr(img_elf);
    if(!ehdr) {
        AsciiPrint("elf64_getehdr: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }

    if(ehdr->e_type != ET_EXEC) {
        AsciiPrint("Error: Not an executable\n");
        return EFI_SUCCESS;
    }

    if(ehdr->e_machine != EM_AARCH64) {
        AsciiPrint("Error: Not AArch64\n");
        return EFI_SUCCESS;
    }

    AsciiPrint("ELF entry point is %x\n", ehdr->e_entry);

    size_t phnum;
    status= elf_getphdrnum(img_elf, &phnum);
    if(status) {
        AsciiPrint("elf64_getehdr: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }
    AsciiPrint("%d program header(s)\n", phnum);

    Elf64_Phdr *phdr= elf64_getphdr(img_elf);
    if(!phdr) {
        AsciiPrint("elf64_getphdr: %a\n", elf_errmsg(elf_errno()));
        return EFI_SUCCESS;
    }

    cpu_driver_entry enter_cpu_driver= (cpu_driver_entry)0;
    for(i= 0; i < phnum; i++) {
        AsciiPrint("Segment %d load address %p, file size %x, memory size %x",
                   i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
        if(phdr[i].p_type == PT_LOAD) AsciiPrint(" LOAD");
        AsciiPrint("\n");

        UINTN p_pages= (phdr[i].p_memsz + (4096-1)) / 4096;
        void *p_buf;

        p_buf= AllocatePages(p_pages);
        if(!p_buf) {
            AsciiPrint("AllocatePages: %r\n", status);
            return EFI_SUCCESS;
        }
        ZeroMem(p_buf, p_pages * 4096);
        AsciiPrint("Loading into %d pages at %p\n", p_pages, p_buf);

        CopyMem(p_buf, img_buffer + phdr[i].p_offset, phdr[i].p_filesz);

        if(ehdr->e_entry <= phdr[i].p_vaddr &&
           ehdr->e_entry - phdr[i].p_vaddr < phdr[i].p_memsz) {
            enter_cpu_driver=
                (cpu_driver_entry)(p_buf + (ehdr->e_entry - phdr[i].p_vaddr));
        }
    }

    AsciiPrint("Relocated entry point is %p\n", enter_cpu_driver);

    dump((UINT32 *)enter_cpu_driver, 256);

    elf_end(img_elf);

    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;
    EFI_MEMORY_DESCRIPTOR *mmap;

    mmap_size= 0;
    status= SystemTable->BootServices->GetMemoryMap(
                &mmap_size, NULL, &mmap_key, &mmap_d_size, &mmap_d_ver);
    if(status != EFI_BUFFER_TOO_SMALL) {
        AsciiPrint("GetMemoryMap: %r\n", status);
        return EFI_SUCCESS;
    }
    mmap_n_desc= mmap_size / mmap_d_size;
    AsciiPrint("Got %d memory map entries (%dB).\n", mmap_n_desc, mmap_size);

    status= SystemTable->BootServices->AllocatePool(
                EfiLoaderData, mmap_size, (void **)&mmap);
    if(status != EFI_SUCCESS) {
        AsciiPrint("AllocatePool: %r\n", status);
        return EFI_SUCCESS;
    }

    status= SystemTable->BootServices->GetMemoryMap(
                &mmap_size, mmap, &mmap_key, &mmap_d_size, &mmap_d_ver);
    if(status != EFI_SUCCESS) {
        AsciiPrint("GetMemoryMap: %r\n", status);
        return EFI_SUCCESS;
    }
    AsciiPrint("Memory map at %p, key: %x, descriptor version: %x\n",
               mmap, mmap_key, mmap_d_ver);

    AsciiPrint("Terminating boot services and jumping to image at %p\n",
               enter_cpu_driver);

    status= SystemTable->BootServices->ExitBootServices(
                ImageHandle, mmap_key);
    if(status != EFI_SUCCESS) {
        AsciiPrint("ExitBootServices: %r\n", status);
        return EFI_SUCCESS;
    }

    /*** EFI boot services are now terminated, we're on our own. */

    /* Jump to the start of the loaded image - doesn't return. */
    enter_cpu_driver(acpi_header, mmap);

    return EFI_SUCCESS;
}
