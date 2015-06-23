/* @file Hagfish.c
*/

#include <libelf.h>
#include <multiboot2.h>

#include <Uefi.h>

#include <Guid/Acpi.h>
#include <Guid/SmBios.h>

#include <IndustryStandard/Acpi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/PxeBaseCode.h>

#define ROUNDUP(x, y) (((x) + ((y)-1)) / (y));
#define PAGE_4k (1<<12)
#define roundpage(x) ROUNDUP((x), PAGE_4k)

/* We preallocate space for the memory map, to avoid the recursion between
 * checking the memory map size and allocating memory for it.  This will
 * obviously fail if the memory map is particularly big. */
#define MEM_MAP_SIZE 8192

void
dump(UINT32 *base, int len) {
    int j;

    AsciiPrint("Dump %p\n", base);
    for(j= 0; j*sizeof(UINT32) < len; j++) {
        AsciiPrint("%08.8x\n", base[j]);
    }
    AsciiPrint("\n");
}

/* Allocate pages below the 4GB boundary. */
void *
AllocateLowPages(UINTN Pages) {
    EFI_STATUS Status;
    EFI_PHYSICAL_ADDRESS Memory= UINT32_MAX;; 

    if(Pages == 0) return NULL;

    Status = gBS->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                Pages, &Memory);
    if(EFI_ERROR(Status)) {
        AsciiPrint("AllocatePages: %r\n", Status);
        return NULL;
    }

    return (void *)Memory;
}

typedef void (*cpu_driver_entry)(uint32_t multiboot_magic,
                                 void *multiboot_info);

/*** Hagfish configuration file loading and parsing. ***/
const char *config_fmt= "hagfish.%d.%d.%d.%d.cfg";

struct component_config {
    UINTN path_start, path_len;
    UINTN args_start, args_len;

    UINTN image_size;
    void *load_address;

    struct component_config *next;
};

struct hagfish_config {
    const char *buf;
    struct component_config *kernel;
    struct component_config *first_module, *last_module;
};

static inline int
isnewline(char c) {
    return c == '\n';
}

static inline int
iswhitespace(char c) {
    return c == ' ' || c == '\n' || c == '\t' || c == '\r';
}

static inline int
iscomment(char c) {
    return c == '#';
}

static inline int
istoken(char c) {
    return !iswhitespace(c) && !iscomment(c);
}

static UINTN
skip_whitespace(const char *buf, UINTN size, UINTN start, int skip_newlines) {
    ASSERT(0);
    ASSERT(start < size);
    UINTN i;

    for(i= start;
        i < size && (iswhitespace(buf[i]) |
                     (skip_newlines && isnewline(buf[i])));
        i++);

    ASSERT(start <= i);
    ASSERT(i <= size);
    ASSERT(i == size ||
           !iswhitespace(buf[i]) ||
           (!skip_newlines && isnewline(buf[i])));
    return i;
}

static UINTN
find_eol(const char *buf, UINTN size, UINTN start) {
    ASSERT(start < size);
    UINTN i;

    for(i= start; i < size && buf[i] != '\n'; i++);

    ASSERT(start <= i);
    ASSERT(i <= size);
    ASSERT(i == size || buf[i] == '\n');
    return i;
}

static UINTN
find_token(const char *buf, UINTN size, UINTN start, int skip_newlines) {
    ASSERT(start < size);
    UINTN i= start;

    while(i < size && !istoken(buf[i])) {
        if(iswhitespace(buf[i])) {
            /* Skip whitespace. */
            i= skip_whitespace(buf, size, i, skip_newlines);
        }
        else {
            /* Find the newline. */
            i= find_eol(buf, size, i);
            /* Skip over it, if not at EOF. */
            if(i < size) i++;
        }
    }

    ASSERT(start <= i);
    ASSERT(i <= size);
    ASSERT(i == size || istoken(buf[i]));
    return i;
}

static UINTN
get_token(const char *buf, UINTN size, UINTN start) {
    ASSERT(start < size);
    ASSERT(istoken(buf[start]));
    UINTN i;

    for(i= start; i < size && istoken(buf[i]); i++);

    ASSERT(start < i);
    ASSERT(i <= size);
    ASSERT(istoken(buf[i-1]));
    return i;
}

int
get_cmdline(const char *buf, UINTN size, UINTN *cursor,
            UINTN *cstart, UINTN *clen, UINTN *astart, UINTN *alen) {
    ASSERT(*cursor < size);
    *cursor= find_token(buf, size, *cursor, 0);
    if(!istoken(buf[*cursor])) {
        AsciiPrint("Missing command line\n");
        return 0;
    }
    *astart= *cstart= *cursor; /* Path starts here. */
    *cursor= get_token(buf, size, *cursor);
    *clen= *cursor - *cstart; /* Path ends here. */
    ASSERT(*clen <= size - *cursor);
    *cursor= find_eol(buf, size, *cursor);
    *alen= *cursor - *astart;
    ASSERT(*alen <= size - *cursor); /* Arguments end here. */

    return 1;
}

struct hagfish_config *
parse_config(const char *buf, UINTN size) {
    UINTN cursor= 0;
    struct hagfish_config *cfg;

    cfg= (struct hagfish_config *)AllocateZeroPool(
            sizeof(struct hagfish_config));
    if(!cfg) goto parse_fail;
    cfg->buf= buf;

    while(cursor < size) {
        cursor= find_token(buf, size, cursor, 1);
        if(cursor < size) {
            UINTN tstart= cursor, tlen;

            ASSERT(istoken(buf[cursor]));
            cursor= get_token(buf, size, cursor);
            tlen= cursor - tstart;
            ASSERT(tlen <= size - cursor);

            if(!AsciiStrnCmp("title", buf+tstart, 5)) {
                /* Ignore the title. */
                ASSERT(cursor < size);
                cursor= find_eol(buf, size, cursor);
            }
            if(!AsciiStrnCmp("kernel", buf+tstart, 6)) {
                if(cfg->kernel) {
                    AsciiPrint("Kernel defined twice\n");
                    goto parse_fail;
                }

                cfg->kernel= (struct component_config *)
                    AllocateZeroPool(sizeof(struct component_config));
                if(!cfg->kernel) goto parse_fail;

                /* Grab the command line. */
                if(!get_cmdline(buf, size, &cursor,
                                &cfg->kernel->path_start,
                                &cfg->kernel->path_len,
                                &cfg->kernel->args_start,
                                &cfg->kernel->args_len))
                    goto parse_fail;
            }
            else if(!AsciiStrnCmp("module", buf+tstart, 6)) {
                struct component_config *module=(struct component_config *)
                    AllocateZeroPool(sizeof(struct component_config));

                /* Grab the command line. */
                if(!get_cmdline(buf, size, &cursor,
                                &module->path_start,
                                &module->path_len,
                                &module->args_start,
                                &module->args_len))
                    goto parse_fail;

                if(cfg->first_module) {
                    ASSERT(cfg->last_module);
                    cfg->last_module->next= module;
                    cfg->last_module= module;
                }
                else {
                    ASSERT(!cfg->last_module);
                    cfg->first_module= module;
                    cfg->last_module= module;
                }
            }
            else {
                AsciiPrint("Unrecognised entry \"%.*a\", skipping line.\n",
                        tlen, buf + tstart);
                cursor= find_eol(buf, size, cursor);
            }
        }
    }

    if(!cfg->kernel) {
        AsciiPrint("No kernel image specified\n");
        goto parse_fail;
    }

    return cfg;

parse_fail:
    if(cfg) {
        if(cfg->kernel) free(cfg->kernel);

        struct component_config *cmp= cfg->first_module;
        while(cmp) {
            struct component_config *next= cmp->next;
            free(cmp);
            cmp= next;
        }

        free(cfg);
    }
    return NULL;
}

/* Load a component (kernel or module) over TFTP, and fill in the relevant
 * fields in the configuration structure. */
int
load_component(struct component_config *cmp, const char *buf,
               EFI_PXE_BASE_CODE_PROTOCOL *pxe, EFI_IP_ADDRESS server_ip) {
    EFI_STATUS status;

    ASSERT(cmp);

    /* Allocate a null-terminated string. */
    char *path= (char *)AllocatePool(cmp->path_len + 1);
    if(!path) return 0;
    CopyMem(path, buf + cmp->path_start, cmp->path_len);
    path[cmp->path_len]= '\0';

    /* Get the file size. */
    AsciiPrint("Loading \"%a\"...", path);
    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE, (void *)0x1,
                       FALSE, &cmp->image_size, NULL, &server_ip,
                       (UINT8 *)path, NULL, TRUE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("\nMtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }

    /* Allocate a page-aligned buffer. */
    UINTN npages= roundpage(cmp->image_size);
    cmp->load_address= AllocatePages(npages);
    if(!cmp->load_address) {
        AsciiPrint("\nFailed to allocate %d pages\n", npages);
        return 0;
    }

    /* Load the image. */
    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_READ_FILE,
                       cmp->load_address, FALSE, &cmp->image_size, NULL,
                       &server_ip, (UINT8 *)path, NULL, FALSE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }

    FreePool(path);

    AsciiPrint(" done (%p, %dB)\n", cmp->load_address, cmp->image_size);
    return 1;
}

/* Copy a base+length string into a null-terminated string.  Destination
 * buffer must be large enough to hold the terminator i.e. n+1 characters. */
static inline void
ntstring(char *dest, const char *src, size_t len) {
    CopyMem(dest, src, len);
    dest[len]= '\0';
}

/* Allocate and fill the Multiboot information structure.  The memory map is
 * preallocated, but left empty until all allocations are finished. */
void *
create_multiboot_info(struct hagfish_config *cfg,
                      EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi1_header,
                      EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi2_header,
                      EFI_PXE_BASE_CODE_PROTOCOL *pxe,
                      Elf *kernel_elf, size_t n_scn,
                      struct multiboot_tag_efi_mmap **mmap_tag,
                      EFI_MEMORY_DESCRIPTOR **mmap_start) {
    UINTN size, npages;
    struct component_config *cmp;
    void *multiboot, *cursor;

    /* Calculate the boot information size. */
    /* Fixed header - there's no struct for this in multiboot.h */
    size= 8;
    /* Kernel command line */
    size+= sizeof(struct multiboot_tag_string)
         + cfg->kernel->args_len+1;
    /* DCHP ack packet */
    size+= sizeof(struct multiboot_tag_network)
         + sizeof(EFI_PXE_BASE_CODE_PACKET);
    /* ACPI 1.0 header */
    if(acpi1_header) {
        size+= sizeof(struct multiboot_tag_old_acpi)
             + sizeof(EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
    }
    /* ACPI 2.0+ header */
    if(acpi2_header) {
        size+= sizeof(struct multiboot_tag_new_acpi)
             + sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
    }
/* XXX */
#if 0
    /* ELF section headers */
    size+= sizeof(struct multiboot_tag_elf_sections)
         + n_scn * sizeof(Elf64_Shdr);
#endif
/* XXX */
    /* Kernel module tag, including command line and ELF image */
    size+= sizeof(struct multiboot_tag_module_64)
         + cfg->kernel->args_len+1 + cfg->kernel->image_size;
    /* All other modules */
    for(cmp= cfg->first_module; cmp; cmp= cmp->next) {
        size+= sizeof(struct multiboot_tag_module_64)
             + cmp->args_len+1 + cmp->image_size;
    }
    /* EFI memory map */
    size+= sizeof(struct multiboot_tag_efi_mmap)
         + MEM_MAP_SIZE;

    AsciiPrint("Multiboot info header is %dB.\n", size);

    /* Round up to a page size and allocate. */
    npages= roundpage(size);
    multiboot= AllocatePages(npages);
    if(!multiboot) {
        AsciiPrint("AllocatePages: failed\n");
        return NULL;
    }
    ZeroMem(multiboot, npages * PAGE_4k);
    AsciiPrint("Allocated %d pages for multiboot info at %p.\n",
               npages, multiboot);

    cursor= multiboot;
    /* Write the fixed header. */
    *((uint32_t *)cursor)= size; /* total_size */
    cursor+= sizeof(uint32_t);
    *((uint32_t *)cursor)= 0;    /* reserved */
    cursor+= sizeof(uint32_t);

    /* Add the boot command line */
    {
        struct multiboot_tag_string *bootcmd=
            (struct multiboot_tag_string *)cursor;

        bootcmd->type= MULTIBOOT_TAG_TYPE_CMDLINE;
        bootcmd->size= sizeof(struct multiboot_tag_string)
                     + cfg->kernel->args_len+1;
        ntstring(bootcmd->string,
                 cfg->buf + cfg->kernel->args_start,
                 cfg->kernel->args_len);

        cursor+= sizeof(struct multiboot_tag_string)
               + cfg->kernel->args_len+1;
    }
    /* Add the DHCP ack packet. */
    {
        struct multiboot_tag_network *dhcp=
            (struct multiboot_tag_network *)cursor;

        dhcp->type= MULTIBOOT_TAG_TYPE_NETWORK;
        dhcp->size= sizeof(struct multiboot_tag_network)
                  + sizeof(EFI_PXE_BASE_CODE_PACKET);
        CopyMem(&dhcp->dhcpack, &pxe->Mode->DhcpAck,
                sizeof(EFI_PXE_BASE_CODE_PACKET));

        cursor+= sizeof(struct multiboot_tag_network)
               + sizeof(EFI_PXE_BASE_CODE_PACKET);
    }
    /* Add the ACPI 1.0 header */
    if(acpi1_header) {
        struct multiboot_tag_old_acpi *acpi=
            (struct multiboot_tag_old_acpi *)cursor;

        acpi->type= MULTIBOOT_TAG_TYPE_ACPI_OLD;
        acpi->size= sizeof(struct multiboot_tag_old_acpi)
                  + sizeof(EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
        CopyMem(&acpi->rsdp, acpi1_header,
                sizeof(EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER));

        cursor+= sizeof(struct multiboot_tag_old_acpi)
               + sizeof(EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
    }
    /* Add the ACPI 2.0+ header */
    if(acpi2_header) {
        struct multiboot_tag_new_acpi *acpi=
            (struct multiboot_tag_new_acpi *)cursor;

        acpi->type= MULTIBOOT_TAG_TYPE_ACPI_NEW;
        acpi->size= sizeof(struct multiboot_tag_new_acpi)
                  + sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
        CopyMem(&acpi->rsdp, acpi2_header,
                sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER));

        cursor+= sizeof(struct multiboot_tag_old_acpi)
               + sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER);
    }
    /* XXX - Add the ELF section headers. */
    /* Add the kernel module. */
    {
        struct multiboot_tag_module_64 *kernel=
            (struct multiboot_tag_module_64 *)cursor;

        kernel->type= MULTIBOOT_TAG_TYPE_MODULE_64;
        kernel->size= sizeof(struct multiboot_tag_module_64)
                    + cfg->kernel->args_len+1;
        kernel->mod_start=
            (multiboot_uint64_t)cfg->kernel->load_address;
        kernel->mod_end=
            (multiboot_uint64_t)(cfg->kernel->load_address +
                                 (cfg->kernel->image_size - 1));
        ntstring(kernel->cmdline,
                 cfg->buf + cfg->kernel->args_start,
                 cfg->kernel->args_len);

        cursor+= sizeof(struct multiboot_tag_module_64)
               + cfg->kernel->args_len+1 + cfg->kernel->image_size;
    }
    /* Add the remaining modules */
    for(cmp= cfg->first_module; cmp; cmp= cmp->next) {
        struct multiboot_tag_module_64 *module=
            (struct multiboot_tag_module_64 *)cursor;

        module->type= MULTIBOOT_TAG_TYPE_MODULE_64;
        module->size= sizeof(struct multiboot_tag_module_64)
                    + cmp->args_len+1;
        module->mod_start=
            (multiboot_uint64_t)cmp->load_address;
        module->mod_end=
            (multiboot_uint64_t)(cmp->load_address +
                                 (cmp->image_size - 1));
        ntstring(module->cmdline, cfg->buf + cmp->args_start, cmp->args_len);

        cursor+= sizeof(struct multiboot_tag_module_64)
               + cmp->args_len+1 + cmp->image_size;
    }
    /* Record the position of the memory map, to be filled in after we've
     * finished doing allocations. */
    *mmap_tag= (struct multiboot_tag_efi_mmap *)cursor;
    cursor+= sizeof(struct multiboot_tag_efi_mmap);
    *mmap_start= (EFI_MEMORY_DESCRIPTOR *)cursor;

    return multiboot;
}

const char *mmap_types[] = {
    "reserved",
    "LD code",
    "LD data",
    "BS code",
    "BS data",
    "RS code",
    "RS data",
    "memory",
    "unusable",
    "ACPI reclaim",
    "ACPI NVS",
    "MMIO",
    "ports",
    "PAL code",
    "persist"
};

void
print_memory_map(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    EFI_MEMORY_DESCRIPTOR *mmap;
    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;
    int i;

    mmap= AllocatePool(MEM_MAP_SIZE);
    if(!mmap) return;

    status= SystemTable->BootServices->GetMemoryMap(
                &mmap_size, mmap, &mmap_key, &mmap_d_size, &mmap_d_ver);
    if(status != EFI_SUCCESS) {
        AsciiPrint("GetMemoryMap: %r\n", status);
        return;
    }
    AsciiPrint("Memory map at %p, key: %x, descriptor version: %x\n",
               mmap, mmap_key, mmap_d_ver);
    mmap_n_desc= mmap_size / mmap_d_size;
    AsciiPrint("Got %d memory map entries of %dB (%dB).\n",
               mmap_n_desc, mmap_d_size, mmap_size);

    AsciiPrint("Type         PStart           PEnd        "
               "      Size      Attributes\n");
    for(i= 0; i < mmap_n_desc; i++) {
        EFI_MEMORY_DESCRIPTOR *desc= 
            ((void *)mmap) + (mmap_d_size * i);

        AsciiPrint("%-12a %016lx %016lx %9ldkB %01x\n",
            mmap_types[desc->Type],
            desc->PhysicalStart,
            desc->PhysicalStart + (desc->NumberOfPages<<12) - 1,
            (desc->NumberOfPages<<12)/1024, desc->Attribute);
    }

    FreePool(mmap);
}

EFI_STATUS EFIAPI
UefiMain (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *hag_image;
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_IP_ADDRESS server_ip, *my_ip;
    EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi2_header= NULL;
    EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER *acpi1_header= NULL;
    int i;

    AsciiPrint("Hagfish UEFI loader starting\n");
    AsciiPrint("UEFI vendor: ");
    Print(SystemTable->FirmwareVendor);
    AsciiPrint("\n");

    /* Get the details of our own process image. */
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

    print_memory_map(SystemTable);

    /* Search for the ACPI tables. */
    AsciiPrint("Found %d EFI configuration tables\n",
               SystemTable->NumberOfTableEntries);
    for(i= 0; i < SystemTable->NumberOfTableEntries; i++) {
        EFI_CONFIGURATION_TABLE *entry= &SystemTable->ConfigurationTable[i];

        if(CompareGuid(&entry->VendorGuid, &gEfiAcpi20TableGuid)) {
            acpi2_header= entry->VendorTable;
            AsciiPrint("ACPI 2.0 table at %p, signature \"% 8.8a\"\n",
                       acpi2_header, (const char *)&acpi2_header->Signature);
        }
        else if(CompareGuid(&entry->VendorGuid, &gEfiAcpi10TableGuid)) {
            acpi1_header= entry->VendorTable;
            AsciiPrint("ACPI 1.0 table at %p, signature \"% 8.8a\"\n",
                       acpi1_header, (const char *)&acpi1_header->Signature);
        }
    }

    /* Find the PXE service that loaded us. */
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

    /* Grab the network details. */
    my_ip= &pxe->Mode->StationIp;
    AsciiPrint("My IP %d.%d.%d.%d\n",
               my_ip->v4.Addr[0], my_ip->v4.Addr[1],
               my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    for(i= 0; i < 4; i++)
        server_ip.v4.Addr[i]= pxe->Mode->DhcpAck.Dhcpv4.BootpSiAddr[i];
    AsciiPrint("BOOTP server %d.%d.%d.%d\n",
               server_ip.v4.Addr[0], server_ip.v4.Addr[1],
               server_ip.v4.Addr[2], server_ip.v4.Addr[3]);

    /* Load the host-specific configuration file. */
    CHAR8 cfg_filename[256];
    UINTN cfg_size;
    AsciiSPrint(cfg_filename, 256, config_fmt, 
                my_ip->v4.Addr[0], my_ip->v4.Addr[1],
                my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    /* Get the file size. */
    AsciiPrint("Loading \"%a\"\n", cfg_filename);
    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE, (void *)0x1,
                       FALSE, &cfg_size, NULL, &server_ip, (UINT8 *)cfg_filename,
                       NULL, TRUE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }
    AsciiPrint("File \"%a\" has size %dB\n", cfg_filename, cfg_size);

    void *cfg_buffer= AllocatePool(cfg_size);
    if(!cfg_buffer) {
        AsciiPrint("AllocatePool: failed\n");
        return EFI_SUCCESS;
    }

    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_READ_FILE, cfg_buffer,
                       FALSE, &cfg_size, NULL, &server_ip,
                       (UINT8 *)cfg_filename, NULL, FALSE);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
        return EFI_SUCCESS;
    }
    AsciiPrint("Loaded config at [%p-%p]\n", cfg_buffer,
               (cfg_buffer+cfg_size) - 1);

    /* Parse the configuration file. */
    struct hagfish_config *cfg= parse_config(cfg_buffer, cfg_size);
    if(!cfg) {
        AsciiPrint("Failed to parse Hagfish configuration.\n");
        return EFI_SUCCESS;
    }

    /* Load the kernel. */
    if(!load_component(cfg->kernel, cfg_buffer, pxe, server_ip)) {
        AsciiPrint("Failed to load the kernel.\n");
    }

    /* Load modules */
    struct component_config *cmp;
    for(cmp= cfg->first_module; cmp; cmp= cmp->next) {
        if(!load_component(cmp, cfg_buffer, pxe, server_ip)) {
            AsciiPrint("Failed to load module.\n");
        }
    }

    /* Relocate the kernel image to a fresh page, and initialise the data
     * section. */
    elf_version(EV_CURRENT);
    Elf *img_elf= elf_memory(cfg->kernel->load_address,
                             cfg->kernel->image_size);
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

#if 0 /* XXX CPU driver isn't */
    if(ehdr->e_type != ET_EXEC) {
        AsciiPrint("Error: Not an executable\n");
        return EFI_SUCCESS;
    }
#endif

    if(ehdr->e_machine != EM_AARCH64) {
        AsciiPrint("Error: Not AArch64\n");
        return EFI_SUCCESS;
    }

    AsciiPrint("Kernel ELF entry point is %x\n", ehdr->e_entry);

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

        CopyMem(p_buf, cfg->kernel->load_address + phdr[i].p_offset,
                phdr[i].p_filesz);

        if(ehdr->e_entry <= phdr[i].p_vaddr &&
           ehdr->e_entry - phdr[i].p_vaddr < phdr[i].p_memsz) {
            enter_cpu_driver=
                (cpu_driver_entry)(p_buf + (ehdr->e_entry - phdr[i].p_vaddr));
        }
    }

    AsciiPrint("Relocated entry point is %p\n", enter_cpu_driver);

    /* Create multiboot info header. */
    EFI_MEMORY_DESCRIPTOR *mmap;
    struct multiboot_tag_efi_mmap *mmap_tag;
    void *multiboot=
        create_multiboot_info(cfg, acpi1_header, acpi2_header, pxe, img_elf,
                              n_scn, &mmap, &mmap_tag);
    if(!multiboot) {
        AsciiPrint("Failed to create multiboot header\n");
        return EFI_SUCCESS;
    }

    /* Finished with the kernel ELF. */
    elf_end(img_elf);

    /* Finished with the configuration (we just copied the last strings out of
     * it, in create_multiboot_info). */
    FreePool(cfg_buffer);

    /* Finished with PXE. */
    status= SystemTable->BootServices->CloseProtocol(
                hag_image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                ImageHandle, NULL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("CloseProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    /* Finished with our own image. */
    status= SystemTable->BootServices->CloseProtocol(
                ImageHandle, &gEfiLoadedImageProtocolGuid,
                ImageHandle, NULL);
    if(status != EFI_SUCCESS) {
        AsciiPrint("CloseProtocol: %r\n", status);
        return EFI_SUCCESS;
    }

    /* The last thing we do is to grab the memory map, including any
     * allocations and deallocations we've done, as per the UEFI spec
     * recommendation.  This fills in the space we set aside in the multiboot
     * structure. */
    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;

    mmap_size= MEM_MAP_SIZE; /* Preallocated buffer */
    status= SystemTable->BootServices->GetMemoryMap(
                &mmap_size, mmap, &mmap_key, &mmap_d_size, &mmap_d_ver);
    if(status == EFI_BUFFER_TOO_SMALL) {
        AsciiPrint("The memory map is %dB, but MEM_MAP_SIZE is %d.\n",
                   mmap_size, MEM_MAP_SIZE);
        AsciiPrint("This is compile-time limit in Hagfish - please report "
                   "this overflow, it's a bug.\n");
        return EFI_SUCCESS;
    }
    else if(status != EFI_SUCCESS) {
        AsciiPrint("GetMemoryMap: %r\n", status);
        return EFI_SUCCESS;
    }
    AsciiPrint("Memory map at %p, key: %x, descriptor version: %x\n",
               mmap, mmap_key, mmap_d_ver);
    mmap_n_desc= mmap_size / mmap_d_size;
    AsciiPrint("Got %d memory map entries (%dB).\n", mmap_n_desc, mmap_size);

    /* Fill in the tag.  We can't use GetMemoryMap to fill these directly, as
     * the multiboot specification requires them to be 32 bit, while EFI may
     * return 64-bit values.  Note that 'mmap_tag' points *inside* the
     * structure pointed to by 'multiboot'. */
    mmap_tag->type= MULTIBOOT_TAG_TYPE_EFI_MMAP;
    mmap_tag->size= sizeof(struct multiboot_tag_efi_mmap) + mmap_size;
    mmap_tag->descr_size= mmap_d_size;
    mmap_tag->descr_vers= mmap_d_ver;

    /* Exit EFI boot services. */
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
    enter_cpu_driver(MULTIBOOT2_HEADER_MAGIC, multiboot);

    return EFI_SUCCESS;
}
