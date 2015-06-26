/* EDK headers */
#include <Uefi.h>

/* Application headers */
#include <Allocation.h>
#include <Memory.h>

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
