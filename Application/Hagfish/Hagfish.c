/* @file Hagfish.c
*/

/* EDK Headers */
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
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/PxeBaseCode.h>

/* Package headers */
#include <libelf.h>
#include <multiboot2.h>

#include <AArch64/vm.h>

/* Application headers */
#include <Allocation.h>
#include <Config.h>

#define COVER(x, y) (((x) + ((y)-1)) / (y))
#define ROUNDUP(x, y) (COVER(x,y) * (y))
#define PAGE_4k (1<<12)
#define BLOCK_1G (1ULL<<30)
#define BLOCK_16G (16 * BLOCK_1G)
#define BLOCK_512G (1ULL<<39)
#define roundpage(x) COVER((x), PAGE_4k)

typedef void (*cpu_driver_entry)(uint32_t multiboot_magic,
                                 void *multiboot_info);

/* Load a component (kernel or module) over TFTP, and fill in the relevant
 * fields in the configuration structure. */
int
load_component(struct component_config *cmp, const char *buf,
               EFI_PXE_BASE_CODE_PROTOCOL *pxe, EFI_IP_ADDRESS server_ip) {
    EFI_STATUS status;

    ASSERT(cmp);

    /* Allocate a null-terminated string. */
    char *path= (char *)allocate_pool(cmp->path_len + 1, EfiLoaderData);
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
    cmp->load_address= allocate_pages(npages, EfiBarrelfishELFData);
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
    multiboot= allocate_pages(npages, EfiBarrelfishMultibootData);
    if(!multiboot) {
        AsciiPrint("allocate_pages: failed\n");
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
    "available",
    "unusable",
    "ACPI reclaim",
    "ACPI NVS",
    "MMIO",
    "ports",
    "PAL code",
    "persist"
};

const char *bf_mmap_types[] = {
    "BF code",
    "BF stack",
    "BF multiboot",
    "BF module",
    "BF page table",
};

void
print_memory_map(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    EFI_MEMORY_DESCRIPTOR *mmap;
    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;
    int i;

    mmap= allocate_pool(MEM_MAP_SIZE, EfiLoaderData);
    if(!mmap) return;

    mmap_size= MEM_MAP_SIZE;
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

    AsciiPrint("Type          PStart           PEnd        "
               "      Size      Attributes\n");
    for(i= 0; i < mmap_n_desc; i++) {
        EFI_MEMORY_DESCRIPTOR *desc= 
            ((void *)mmap) + (mmap_d_size * i);
        const char *description;

        if(desc->Type < EfiMaxMemoryType)
            description= mmap_types[desc->Type];
        else if(EfiBarrelfishFirstMemType <= desc->Type &&
                desc->Type < EfiBarrelfishMaxMemType)
            description= bf_mmap_types[desc->Type - EfiBarrelfishFirstMemType];
        else
            description= "???";

        AsciiPrint("%-13a %016lx %016lx %9ldkB %01x\n",
            description,
            desc->PhysicalStart,
            desc->PhysicalStart + (desc->NumberOfPages<<12) - 1,
            (desc->NumberOfPages<<12)/1024, desc->Attribute);
    }

    FreePool(mmap);
}

EFI_STATUS
get_memory_map(EFI_SYSTEM_TABLE *SystemTable,
               UINTN *mmap_size, UINTN *mmap_key,
               UINTN *mmap_d_size, UINT32 *mmap_d_ver,
               void *mmap) {
    EFI_STATUS status;

    status= SystemTable->BootServices->GetMemoryMap(
                mmap_size, mmap, mmap_key, mmap_d_size, mmap_d_ver);
    if(status == EFI_BUFFER_TOO_SMALL) {
        AsciiPrint("The memory map is %dB, but MEM_MAP_SIZE is %d.\n",
                   mmap_size, MEM_MAP_SIZE);
        AsciiPrint("This is compile-time limit in Hagfish - please report "
                   "this overflow, it's a bug.\n");
        return status;
    }
    else if(status != EFI_SUCCESS) {
        AsciiPrint("GetMemoryMap: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

struct ram_region {
    uint64_t base;
    uint64_t npages;
};

struct region_list {
    size_t nregions;
    struct ram_region regions[0];
};

struct page_tables {
    size_t nL1;

    union aarch64_descriptor *L0_table;
    union aarch64_descriptor **L1_tables;
};

struct page_tables *
build_page_tables(EFI_SYSTEM_TABLE *SystemTable,
                  struct region_list *list) {
    if(list->nregions == 0) {
        AsciiPrint("No memory regions defined.\n");
        goto build_page_tables_fail;
    }

    struct page_tables *tables=
        allocate_zero_pool(sizeof(struct page_tables), EfiLoaderData);
    if(!tables) goto build_page_tables_fail;

    uint64_t first_address, last_address;
    first_address= list->regions[0].base;
    last_address= list->regions[list->nregions-1].base
                + list->regions[list->nregions-1].npages * PAGE_4k - 1;

    AsciiPrint("Window from %llx to %llx\n", first_address, last_address);

    /* We will map in aligned 16G blocks, as each requires only one TLB
     * entry. */
    uint64_t window_start, window_length;
    window_start= first_address & ~BLOCK_16G;
    window_length= ROUNDUP(last_address - window_start, BLOCK_16G);

    AsciiPrint("Mapping from %llx to %llx\n", window_start,
            window_start + window_length - 1);

    tables->L0_table= allocate_pages(1, EfiBarrelfishBootPageTable);
    if(!tables->L0_table) {
        AsciiPrint("Failed to allocate L0 page table.\n");
        goto build_page_tables_fail;
    }
    ZeroMem(tables->L0_table, PAGE_4k);

    /* Count the number of L1 tables (512GB) blocks required to cover the
     * physical mapping window. */
    tables->nL1= 0;
    uint64_t L1base= window_start & ~BLOCK_512G;
    uint64_t L1addr;
    for(L1addr= window_start & ~BLOCK_512G;
        L1addr < window_start + window_length;
        L1addr+= BLOCK_512G) {
        tables->nL1++;
    }

    AsciiPrint("Allocating %d L1 tables\n", tables->nL1);

    /* ALlocate the L1 table pointers. */
    tables->L1_tables=
        allocate_zero_pool(tables->nL1 * sizeof(union aarch64_descriptor *),
                           EfiLoaderData);
    if(!tables->L1_tables) {
        AsciiPrint("Failed to allocate L1 page table pointers.\n");
        goto build_page_tables_fail;
    }

    /* Allocate the L1 tables. */
    size_t i;
    for(i= 0; i < tables->nL1; i++) {
        tables->L1_tables[i]= allocate_pages(1, EfiBarrelfishBootPageTable);
        if(!tables->L1_tables[i]) {
            AsciiPrint("Failed to allocate L1 page tables.\n");
            goto build_page_tables_fail;
        }
        AsciiPrint("  %p\n", tables->L1_tables[i]);
        ZeroMem(tables->L1_tables[i], PAGE_4k);

        /* Map the L1 into the L0. */
        size_t L0_index= (L1base >> ARMv8_TOP_TABLE_BITS) + i;
        tables->L0_table[L0_index].d.base=
            (uint64_t)tables->L1_tables[i] >> ARMv8_BASE_PAGE_BITS;
        tables->L0_table[L0_index].d.mb1=   1; /* Page table */
        tables->L0_table[L0_index].d.valid= 1;
    }

    /* Install the 1GB block mappings. */
    uint64_t firstblock= window_start / BLOCK_1G;
    uint64_t nblocks= window_length / BLOCK_1G;
    uint64_t block;
    for(block= firstblock; block < firstblock + nblocks; block++) {
        size_t table_number= block >> ARMv8_BLOCK_BITS;
        size_t table_index= block & ARMv8_BLOCK_MASK;

        AsciiPrint("%d %d %d %016llx\n", block, table_number, table_index,
                                         block * BLOCK_1G);

        /* We're mapping 16GB contiguous blocks, to save TLB entries. */
        tables->L1_tables[table_number][table_index].block_l1.contiguous= 1;
        tables->L1_tables[table_number][table_index].block_l1.base= block;
        /* Mark the accessed flag, so we don't get a fault. */
        tables->L1_tables[table_number][table_index].block_l1.af= 1;
        /* Outer shareable - coherent. */
        tables->L1_tables[table_number][table_index].block_l1.sh= 2;
        /* EL1+ only. */
        tables->L1_tables[table_number][table_index].block_l1.ap= 0;
        /* Normal memory XXX set up MAIR_EL{1,2}[0]. */
        tables->L1_tables[table_number][table_index].block_l1.attrindex= 0;
        /* A block. */
        tables->L1_tables[table_number][table_index].block_l1.mb0= 0;
        tables->L1_tables[table_number][table_index].block_l1.valid= 1;
    }

    return tables;

build_page_tables_fail:
    if(tables) {
        if(tables->L1_tables) {
            size_t i;
            for(i= 0; i < tables->nL1; i++) {
                if(tables->L1_tables[i]) FreePages(tables->L1_tables[i], 1);
            }
            FreePool(tables->L1_tables);
        }
        if(tables->L0_table) FreePages(tables->L0_table, 1);
        FreePool(tables);
    }

    return NULL;
}

void
free_page_table_bookkeeping(struct page_tables *tables) {
    FreePool(tables->L1_tables);
    FreePool(tables);
}

struct region_list *
get_region_list(EFI_SYSTEM_TABLE *SystemTable) {
    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;
    void *mmap;
    struct region_list *list;
    EFI_STATUS status;

    /* Get the current memory map. */
    mmap_size= MEM_MAP_SIZE;
    mmap= allocate_pool(mmap_size, EfiLoaderData);
    if(!mmap) {
        AsciiPrint("Failed to allocate memory map.\n");
        goto get_region_list_fail;
    }
    status= get_memory_map(SystemTable,
                           &mmap_size, &mmap_key,
                           &mmap_d_size, &mmap_d_ver, mmap);
    if(status != EFI_SUCCESS) {
        AsciiPrint("Failed to get memory map.\n");
        goto get_region_list_fail;
    }
    mmap_n_desc= mmap_size / mmap_d_size;

    /* There can be at most as many regions as memory descriptors, as we only
     * merge them. */
    list= allocate_pool(sizeof(struct region_list) +
                        mmap_n_desc * sizeof(struct ram_region),
                        EfiLoaderData);
    if(!list) {
        AsciiPrint("Failed to allocate region list.\n");
        goto get_region_list_fail;
    }
    list->nregions= 0;

    size_t i;
    for(i= 0; i < mmap_n_desc; i++) {
        /* { regions are non-overlapping and sorted by base address. } */
        EFI_MEMORY_DESCRIPTOR *desc= mmap + i * mmap_d_size;

        /* We're only looking for RAM. */
        if(desc->Type == EfiMemoryMappedIO ||
           desc->Type == EfiMemoryMappedIOPortSpace)
            continue;

        size_t j;
        for(j= list->nregions;
            j > 0 && list->regions[j-1].base > desc->PhysicalStart;
            j--) {
        }
        ASSERT(j == 0 || list->regions[j-1].base <= desc->PhysicalStart);
        /* Descriptors should not overlap. */
        ASSERT(j == 0 ||
               list->regions[j-1].base + list->regions[j-1].npages * PAGE_4k <=
               desc->PhysicalStart);
        ASSERT(j == list->nregions ||
               desc->PhysicalStart + desc->NumberOfPages * PAGE_4k <=
               list->regions[j].base);

        /* The new descriptor extends the previous region.  This is the common
         * case if the descriptor list is sorted.  Merge them. */
        int merge_left= j > 0 &&
            list->regions[j-1].base +
            list->regions[j-1].npages * PAGE_4k == 
            desc->PhysicalStart;
        /* We're plugging the hole before an existing region.  This should be
         * rare, but we'll handle it. */
        int merge_right= j < list->nregions &&
            desc->PhysicalStart + desc->NumberOfPages * PAGE_4k ==
            list->regions[j].base;

        if(merge_left) {
            if(merge_right) {
                size_t k;

                ASSERT(j > 0);
                ASSERT(j < list->nregions);

                /* Absorb the new descriptor and the existing region. */
                list->regions[j-1].npages +=
                    desc->NumberOfPages + list->regions[j].npages;

                /* Remove the right-hand descriptor. */
                for(k= j; k < list->nregions - 1; k++)
                    list->regions[k]= list->regions[k+1];

            }
            else {
                ASSERT(j > 0);

                /* Absorb the new descriptor.  The number of regions is
                 * unchanged. */
                list->regions[j-1].npages += desc->NumberOfPages;
            }
        }
        else {
            if(merge_right) {
                /* Absorb the new descriptor, and update the base address of
                 * the right-hand region.  The number of regions remains
                 * unchanged.  */
                ASSERT(j < list->nregions);
                list->regions[j].base-= desc->NumberOfPages * PAGE_4k;
                ASSERT(list->regions[j].base == desc->PhysicalStart);
                list->regions[j].npages+= desc->NumberOfPages;
            }
            else {
                size_t k;

                ASSERT(list->nregions + 1 <= mmap_n_desc);

                /* Make room for a new region. */
                for(k= list->nregions; k > j; k--)
                    list->regions[k]= list->regions[k-1];

                list->regions[j].base= desc->PhysicalStart;
                list->regions[j].npages= desc->NumberOfPages;

                list->nregions++;
            }
        }
    }

    FreePool(mmap);

    return list;

get_region_list_fail:
    if(list) FreePool(list);
    if(mmap) FreePool(mmap);

    return NULL;
}

void
print_ram_regions(struct region_list *region_list) {
    size_t i;
    uint64_t total= 0;

    AsciiPrint("%d RAM region(s)\n", region_list->nregions);

    for(i= 0; i < region_list->nregions; i++) {
        AsciiPrint("%2d %p-%p\n", i,
                   region_list->regions[i].base,
                   region_list->regions[i].base +
                   region_list->regions[i].npages * PAGE_4k);
        total+= region_list->regions[i].npages * PAGE_4k;
    }

    AsciiPrint("%lldkB total\n", total / 1024);
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
    AsciiSPrint(cfg_filename, 256, hagfish_config_fmt, 
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

    void *cfg_buffer= allocate_pool(cfg_size, EfiLoaderData);
    if(!cfg_buffer) {
        AsciiPrint("allocate_pool: failed\n");
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

    /* Load the CPU driver from its ELF image. */
    cpu_driver_entry enter_cpu_driver= (cpu_driver_entry)0;
    for(i= 0; i < phnum; i++) {
        AsciiPrint("Segment %d load address %p, file size %x, memory size %x",
                   i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
        if(phdr[i].p_type == PT_LOAD) AsciiPrint(" LOAD");
        AsciiPrint("\n");

        UINTN p_pages= (phdr[i].p_memsz + (4096-1)) / 4096;
        void *p_buf;

        p_buf= allocate_pages(p_pages, EfiBarrelfishCPUDriver);
        if(!p_buf) {
            AsciiPrint("allocate_pages: %r\n", status);
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

    /* Allocate a stack */
    void *kernel_stack=
        allocate_pages(cfg->stack_size / PAGE_4k, EfiBarrelfishCPUDriverStack);
    if(!kernel_stack) {
        AsciiPrint("Failed allocate kernel stack\n");
        return EFI_SUCCESS;
    }

    AsciiPrint("Relocated entry point is %p\n", enter_cpu_driver);

    /* Create multiboot info header. */
    EFI_MEMORY_DESCRIPTOR *mmap;
    struct multiboot_tag_efi_mmap *mmap_tag;
    void *multiboot=
        create_multiboot_info(cfg, acpi1_header, acpi2_header, pxe, img_elf,
                              n_scn, &mmap_tag, &mmap);
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

    struct region_list *region_list=
        get_region_list(SystemTable);
    if(!region_list) {
        AsciiPrint("Failed to get region list\n");
        return EFI_SUCCESS;
    }

    /* Print out the discovered RAM regions */
    print_ram_regions(region_list);

    /* Build the direct-mapped page tables for the kernel. */
    struct page_tables *tables= build_page_tables(SystemTable, region_list);
    if(!tables) {
        AsciiPrint("Failed to create initial page table.\n");
        return EFI_SUCCESS;
    }

    FreePool(region_list);

    free_page_table_bookkeeping(tables);

    print_memory_map(SystemTable);

    /* The last thing we do is to grab the final memory map, including any
     * allocations and deallocations we've done, as per the UEFI spec
     * recommendation.  This fills in the space we set aside in the multiboot
     * structure. */
    UINTN mmap_size, mmap_key, mmap_d_size, mmap_n_desc;
    UINT32 mmap_d_ver;

    mmap_size= MEM_MAP_SIZE; /* Preallocated buffer */
    status= get_memory_map(SystemTable,
                           &mmap_size, &mmap_key,
                           &mmap_d_size, &mmap_d_ver, mmap);
    if(status != EFI_SUCCESS) return EFI_SUCCESS;
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

#if 0

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
    SwitchStack((SWITCH_STACK_ENTRY_POINT)enter_cpu_driver,
                (void *)MULTIBOOT2_BOOTLOADER_MAGIC, multiboot,
                kernel_stack);

#endif

    return EFI_SUCCESS;
}
