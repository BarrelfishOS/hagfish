#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* EDK headers */
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Uefi.h>

/* Application headers */
#include <Allocation.h>
#include <Config.h>
#include <Memory.h>

/* The current UEFI memory map.  This is statically allocated, as it needs to
 * persist after we've cleaned up all of our heap allocations. */
char mmap[MEM_MAP_SIZE];
UINTN mmap_size, mmap_key, mmap_d_size;
UINT32 mmap_d_ver;

static const char *mmap_types[] = {
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

static const char *bf_mmap_types[] = {
    "BF code",
    "BF stack",
    "BF multiboot",
    "BF module",
    "BF page table",
};

void
print_memory_map(int update_map) {
    EFI_STATUS status= EFI_SUCCESS;
    size_t mmap_n_desc, i;

    if(update_map) status= update_memory_map();
    if(EFI_ERROR(status) || !mmap) {
        DebugPrint(DEBUG_ERROR, "Couldn't get the current memory map: %r\n",
                   status);
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
}

EFI_STATUS
update_memory_map(void) {
    EFI_STATUS status;

    /* Grab the current table from UEFI. */
    mmap_size= MEM_MAP_SIZE;
    status= gST->BootServices->GetMemoryMap(
                &mmap_size, (void *)&mmap,
                &mmap_key,  &mmap_d_size,
                &mmap_d_ver);
    if(status == EFI_BUFFER_TOO_SMALL) {
        DebugPrint(DEBUG_ERROR,
                   "The memory map is %dB, but MEM_MAP_SIZE is %d.\n",
                   mmap_size, MEM_MAP_SIZE);
        DebugPrint(DEBUG_ERROR,
                   "This is compile-time limit in Hagfish - please report "
                   "this overflow, it's a bug.\n");
        return status;
    }
    else if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "GetMemoryMap: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
update_ram_regions(struct hagfish_config *cfg) {
    ASSERT(cfg);

    /* Only create the list once - we assume that the RAM regions never
     * change. */
    if(!cfg->ram_regions) {
        cfg->ram_regions= get_region_list(cfg);
        if(!cfg->ram_regions) return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

struct region_list *
get_region_list(struct hagfish_config *cfg) {
    size_t mmap_n_desc, i;
    struct region_list *list= NULL;
    EFI_STATUS status;

    /* Get the current memory map. */
    status= update_memory_map();
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Couldn't get the current memory map: %r\n",
                   status);
        return NULL;
    }
    mmap_n_desc= mmap_size / mmap_d_size;

    /* There can be at most as many regions as memory descriptors, as we only
     * merge them. */
    list= malloc(sizeof(struct region_list) +
                 mmap_n_desc * sizeof(struct ram_region));
    if(!list) {
        DebugPrint(DEBUG_ERROR, "malloc: %a\n", strerror(errno));
        goto get_region_list_fail;
    }
    list->nregions= 0;

    for(i= 0; i < mmap_n_desc; i++) {
        /* { regions are non-overlapping and sorted by base address. } */
        EFI_MEMORY_DESCRIPTOR *desc=
            (EFI_MEMORY_DESCRIPTOR *)(mmap + i * mmap_d_size);

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

    return list;

get_region_list_fail:
    if(list) free(list);

    return NULL;
}


void
free_region_list(struct region_list *list) {
    free(list);
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
