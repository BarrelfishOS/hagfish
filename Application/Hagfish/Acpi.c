/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <string.h>

/* EDK headers */
#include <Uefi.h>
#include <Guid/Acpi.h>
#include <Guid/SmBios.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
/* Application headers */
#include <Config.h>
#include <Acpi.h>

#include <IndustryStandard/Acpi.h>

#include <Library/BaseLib.h>



static INT32 acpi_get_version(struct hagfish_config *cfg)
{
    if (cfg->acpi2_header) {
        return cfg->acpi2_header->Revision;
    } else if (cfg->acpi1_header) {
        return 1;
    } else {
        return -1;
    }
}

static uint8_t acpu_table_checksum(void * table, size_t len)
{
    uint8_t checksum = 0;
    uint8_t *val = (uint8_t *)table;
    for (uint32_t i = 0; i < len; i++) {
        checksum += val[i];
    }

    return checksum;
}

static void acpi_dump_description_header(EFI_ACPI_DESCRIPTION_HEADER *hdr)
{
    DebugPrint(DEBUG_INFO, "ACPI 2.0 Description header @ %p\n", hdr);

    uint8_t checksum = acpu_table_checksum(hdr, hdr->Length);

    DebugPrint(DEBUG_INFO, "   Signature      = % 4.4a\n", &hdr->Signature);
    DebugPrint(DEBUG_INFO, "   Length         = %u\n", hdr->Length);
    DebugPrint(DEBUG_INFO, "   Revision       = %u\n", hdr->Revision);
    DebugPrint(DEBUG_INFO, "   Checksum       = %u (valid=%a)\n", hdr->Checksum, (checksum == 0 ? "yes" : "no"));
    DebugPrint(DEBUG_INFO, "   OemId          = % 6.6a \n", hdr->OemId);
    DebugPrint(DEBUG_INFO, "   OemTableId     = % 8.8a\n", &hdr->OemTableId);
    DebugPrint(DEBUG_INFO, "   OemRevision    = %u\n", hdr->OemRevision);
    DebugPrint(DEBUG_INFO, "   CreatorId      = %x\n", hdr->CreatorId);
    DebugPrint(DEBUG_INFO, "   CreatorRevision= %x\n", hdr->CreatorRevision);
}

const char *madt_elm_string[EFI_ACPI_6_0_GIC_ITS + 1] = {
        "PROCESSOR_LOCAL_APIC           ",
        "IO_APIC                        ",
        "INTERRUPT_SOURCE_OVERRIDE      ",
        "NON_MASKABLE_INTERRUPT_SOURCE  ",
        "LOCAL_APIC_NMI                 ",
        "LOCAL_APIC_ADDRESS_OVERRIDE    ",
        "IO_SAPIC                       ",
        "LOCAL_SAPIC                    ",
        "PLATFORM_INTERRUPT_SOURCES     ",
        "PROCESSOR_LOCAL_X2APIC         ",
        "LOCAL_X2APIC_NMI               ",
        "GIC                            ",
        "GICD                           ",
        "GIC_MSI_FRAME                  ",
        "GICR                           ",
        "GIC_ITS                        ",
};

static void acpi_dump_madt_entry(EFI_ACPI_6_0_MADT_COMMON_ELEMENT *elm)
{
    DebugPrint(DEBUG_INFO, "ACPI 2.0 MADT Element @ %p\n", elm);

        DebugPrint(DEBUG_INFO, "   Type                          = 0x%x (%a)\n",
                    elm->Type, madt_elm_string[elm->Type]);
        DebugPrint(DEBUG_INFO, "   Length                        = %u\n",
                    elm->Length);

    switch(elm->Type) {
    case EFI_ACPI_6_0_GIC :
    {
        EFI_ACPI_6_0_GIC_STRUCTURE *gicc = (EFI_ACPI_6_0_GIC_STRUCTURE *)elm;
        DebugPrint(DEBUG_INFO, "   Reserved                      = %u\n",
                   gicc->Reserved);
        DebugPrint(DEBUG_INFO, "   CPUInterfaceNumber            = 0x%x (%u)\n",
                   gicc->CPUInterfaceNumber, gicc->CPUInterfaceNumber);
        DebugPrint(DEBUG_INFO, "   AcpiProcessorUid              = 0x%x (%u)\n",
                   gicc->AcpiProcessorUid, gicc->AcpiProcessorUid);
        DebugPrint(DEBUG_INFO, "   Flags                         = 0x%x\n",
                   gicc->Flags);
        DebugPrint(DEBUG_INFO, "   ParkingProtocolVersion        = 0x%x (%u)\n",
                   gicc->ParkingProtocolVersion, gicc->ParkingProtocolVersion);
        DebugPrint(DEBUG_INFO, "   PerformanceInterruptGsiv      = 0x%x (%u)\n",
                   gicc->PerformanceInterruptGsiv, gicc->PerformanceInterruptGsiv);
        DebugPrint(DEBUG_INFO, "   ParkedAddress                 = 0x%p\n",
                   gicc->ParkedAddress);
        DebugPrint(DEBUG_INFO, "   PhysicalBaseAddress           = 0x%p\n",
                   gicc->PhysicalBaseAddress);
        DebugPrint(DEBUG_INFO, "   GICV                          = 0x%p\n",
                   gicc->GICV);
        DebugPrint(DEBUG_INFO, "   GICH                          = 0x%p\n",
                   gicc->GICH);
        DebugPrint(DEBUG_INFO, "   VGICMaintenanceInterrupt      = 0x%x (%u)\n",
                gicc->VGICMaintenanceInterrupt, gicc->VGICMaintenanceInterrupt);
        DebugPrint(DEBUG_INFO, "   GICRBaseAddress               = 0x%p\n",
                   gicc->GICRBaseAddress);
        DebugPrint(DEBUG_INFO, "   MPIDR                         = 0x%x (%u)\n",
                gicc->MPIDR, gicc->MPIDR);
        if (elm->Length == 80) {
            DebugPrint(DEBUG_INFO, "   ProcessorPowerEfficiencyClass = 0x%x (%u)\n",
                        gicc->ProcessorPowerEfficiencyClass, gicc->ProcessorPowerEfficiencyClass);
        }
        break;
    }
    case EFI_ACPI_6_0_GICD :
    {
        EFI_ACPI_6_0_GIC_DISTRIBUTOR_STRUCTURE *gicd = (EFI_ACPI_6_0_GIC_DISTRIBUTOR_STRUCTURE*) elm;
        DebugPrint(DEBUG_INFO, "   Reserved1                     = \n",
                    gicd->Reserved1);
        DebugPrint(DEBUG_INFO, "   GicId                         = %u\n",
                    gicd->GicId);
        DebugPrint(DEBUG_INFO, "   PhysicalBaseAddress           = 0x%p\n",
                    gicd->PhysicalBaseAddress);
        DebugPrint(DEBUG_INFO, "   SystemVectorBase              = %u\n",
                    gicd->SystemVectorBase);
        break;
    }
    case EFI_ACPI_6_0_GIC_MSI_FRAME :
    {
        EFI_ACPI_6_0_GIC_MSI_FRAME_STRUCTURE *gicmsi = (EFI_ACPI_6_0_GIC_MSI_FRAME_STRUCTURE*)elm;
        DebugPrint(DEBUG_INFO, "   Reserved1                     = %u\n",
                    gicmsi->Reserved1);
        DebugPrint(DEBUG_INFO, "   GicMsiFrameId                 = %u\n",
                    gicmsi->GicMsiFrameId);
        DebugPrint(DEBUG_INFO, "   PhysicalBaseAddress           = 0x%p\n",
                    gicmsi->PhysicalBaseAddress);
        DebugPrint(DEBUG_INFO, "   Flags                         = 0x%x\n",
                    gicmsi->Flags);
        DebugPrint(DEBUG_INFO, "   SPICount                      = %u\n",
                    gicmsi->SPICount);
        DebugPrint(DEBUG_INFO, "   SPIBase                       = %u\n",
                    gicmsi->SPIBase);
        break;
    }
    case EFI_ACPI_6_0_GICR :
    {
        EFI_ACPI_6_0_GICR_STRUCTURE *gicr = (EFI_ACPI_6_0_GICR_STRUCTURE *)elm;
        DebugPrint(DEBUG_INFO, "   Reserved                      = %u\n",
                    gicr->Reserved);
        DebugPrint(DEBUG_INFO, "   DiscoveryRangeBaseAddress     = 0x%p\n",
                    gicr->DiscoveryRangeBaseAddress);
        DebugPrint(DEBUG_INFO, "   DiscoveryRangeLength          = 0x%x (%u)\n",
                    gicr->DiscoveryRangeLength, gicr->DiscoveryRangeLength);
        break;
    }
    case EFI_ACPI_6_0_GIC_ITS :
    {
        EFI_ACPI_6_0_GIC_ITS_STRUCTURE *gicits = (EFI_ACPI_6_0_GIC_ITS_STRUCTURE *)elm;
        DebugPrint(DEBUG_INFO, "   Reserved                      = \n",
                gicits->Reserved);
        DebugPrint(DEBUG_INFO, "   GicItsId                      = 0x%x (%u)\n",
                gicits->GicItsId, gicits->GicItsId);
        DebugPrint(DEBUG_INFO, "   PhysicalBaseAddress           = 0x%p\n", gicits->PhysicalBaseAddress);
        break;
    }

    default:
        DebugPrint(DEBUG_INFO, "   Implement element dumping...\n");
        break;
    }
}

void *
acpi_allocate_pages(EFI_PHYSICAL_ADDRESS memory, size_t n, EFI_MEMORY_TYPE type) {
    EFI_STATUS status;
    if(n == 0) return NULL;

    status = gBS->AllocatePages(AllocateAddress, type, n, &memory);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "AllocatePages: %r\n", status);
        return NULL;
    }

    return (void *)memory;
}

static void *acpi_get_table_xsdt(EFI_ACPI_COMMON_HEADER *hdr, uint32_t sig)
{
    EFI_ACPI_DESCRIPTION_HEADER *xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)hdr;

    acpi_dump_description_header(xsdt);

    if (xsdt->Signature != EFI_ACPI_6_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) {
        DebugPrint(DEBUG_ERROR, "ACPI: Table is not the XSDT!\n");
        return NULL;
    }

    if (acpu_table_checksum(xsdt, xsdt->Length)) {
        DebugPrint(DEBUG_ERROR, "ACPI: XSDT Table has invalid checksum!\n");
        return NULL;
    }

    if (hdr->Signature == sig) {
        return hdr;
    }

    void *table_end = ((uint8_t *)hdr) + xsdt->Length;
    void *p = ((uint8_t *)hdr) + 36;

    while(p < table_end) {
        EFI_PHYSICAL_ADDRESS *field = p;

        EFI_ACPI_DESCRIPTION_HEADER *sub_tab_hdr = (EFI_ACPI_DESCRIPTION_HEADER *) *field;

        DebugPrint(DEBUG_INFO, "Checking: % 4.4a | % 4.4a\n",
                   &sub_tab_hdr->Signature, &sig);

        if (sub_tab_hdr->Signature == sig) {
            return sub_tab_hdr;
        }

        p += 8;
    }

    return NULL;
}

static void *acpi_get_table_rdst(EFI_ACPI_COMMON_HEADER *hdr, uint32_t sig)
{
    EFI_ACPI_DESCRIPTION_HEADER *rdst = (EFI_ACPI_DESCRIPTION_HEADER *)hdr;

    acpi_dump_description_header(rdst);

    if (rdst->Signature != EFI_ACPI_6_0_ROOT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) {
        DebugPrint(DEBUG_ERROR, "ACPI: Table is not the XSDT!\n");
        return NULL;
    }

    if (acpu_table_checksum(rdst, rdst->Length)) {
        DebugPrint(DEBUG_ERROR, "ACPI: XSDT Table has invalid checksum!\n");
        return NULL;
    }

    if (hdr->Signature == sig) {
        return hdr;
    }

    acpi_dump_description_header(rdst);

    return NULL;
}

static void *acpi_get_table(struct hagfish_config *cfg, uint32_t sig)
{
    /* as = AcpiGetTable("APIC", 1, (ACPI_TABLE_HEADER **)&ath);*/
    if (cfg->acpi2_header) {
        if (cfg->acpi2_header->XsdtAddress) {
            return acpi_get_table_xsdt((void *)(cfg->acpi2_header->XsdtAddress), sig);
        } else {
            return acpi_get_table_rdst((void *)(uint64_t)(cfg->acpi2_header->RsdtAddress), sig);
        }
    } else if (cfg->acpi1_header) {
        return acpi_get_table_rdst((void *)(uint64_t)(cfg->acpi1_header->RsdtAddress), sig);
    }
    return NULL;
}

/*
 *  The system firmware must not request a virtual mapping for any memory descriptor of type
EfiACPIReclaimMemory or EfiACPIMemoryNVS.
 EFI memory descriptors of type EfiACPIReclaimMemory and EfiACPIMemoryNVS
must be aligned on a 4 KiB boundary and must be a multiple of 4 KiB in size
 */
static void *acpi_get_madt_table(struct hagfish_config *cfg)
{
    return acpi_get_table(cfg, EFI_ACPI_6_0_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE);
}


EFI_STATUS acpi_parse_madt(struct hagfish_config *cfg)
{
    EFI_ACPI_6_0_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER *madt;

    madt = acpi_get_madt_table(cfg);
    if (!madt) {
        DebugPrint(DEBUG_ERROR, "MADT Table not found!\n");
        return EFI_NOT_FOUND;
    }

    DebugPrint(DEBUG_INFO, "Parsing MADT table.\n");

    acpi_dump_description_header(&madt->Header);

    if (madt->Header.Signature != EFI_ACPI_6_0_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE) {
        DebugPrint(DEBUG_ERROR, "ACPI: Table is not the XSDT!\n");
        return EFI_INCOMPATIBLE_VERSION;
    }

    if (acpu_table_checksum(madt, madt->Header.Length)) {
        DebugPrint(DEBUG_ERROR, "ACPI: XSDT Table has invalid checksum!\n");
        return EFI_CRC_ERROR;
    }

    void *table_end = ((uint8_t *)madt) + madt->Header.Length;
    void *p = ((uint8_t *)madt) + 44;

    while(p < table_end) {
        EFI_ACPI_6_0_MADT_COMMON_ELEMENT *elm = p;
    //    acpi_dump_madt_entry(p);
        switch(elm->Type) {
        case EFI_ACPI_6_0_GIC :
        {
            EFI_ACPI_6_0_GIC_STRUCTURE *gicc = p;
            EFI_STATUS status;
            if (gicc->ParkingProtocolVersion && gicc->ParkedAddress) {
                DebugPrint(DEBUG_INFO, "ACPI: marking page 0x%p as EfiACPIReclaimMemory\n",
                            gicc->ParkedAddress);
                EFI_PHYSICAL_ADDRESS memory = gicc->ParkedAddress;
                status = gBS->AllocatePages(AllocateAddress, EfiACPIReclaimMemory, 1, &memory);
                if(EFI_ERROR(status)) {
                    DebugPrint(DEBUG_ERROR, "AllocatePages: %r\n", status);
                }
            }

            break;
        }
        case EFI_ACPI_6_0_GICD :
        case EFI_ACPI_6_0_GIC_MSI_FRAME :
        case EFI_ACPI_6_0_GICR :
        case EFI_ACPI_6_0_GIC_ITS :
            DebugPrint(DEBUG_INFO, "ACPI: MADT table skipping entry: %u\n",
                                   elm->Type);
            break;
        default:
            DebugPrint(DEBUG_ERROR, "ACPI: MADT table contained unexpected entry: %u\n",
                       elm->Type);
            break;
        }

        if (elm->Length == 0) {
            DebugPrint(DEBUG_ERROR, "ACPI: MADT table contained corrupted element: %u\n");
            return EFI_SUCCESS;
        }

        p += elm->Length;
    }


    return EFI_SUCCESS;

}

EFI_STATUS
acpi_find_root_table(struct hagfish_config *cfg) {
    DebugPrint(DEBUG_INFO, "Found %d EFI configuration tables\n",
               gST->NumberOfTableEntries);

    size_t i;
    for(i= 0; i < gST->NumberOfTableEntries; i++) {
        EFI_CONFIGURATION_TABLE *entry= &gST->ConfigurationTable[i];

        if(CompareGuid(&entry->VendorGuid, &gEfiAcpi20TableGuid)) {
            if (cfg->acpi2_header != NULL) {
                DebugPrint(DEBUG_INFO,
                        "ACPI 2.0 table already set at %p, signature \"% 8.8a\"\n",
                        cfg->acpi2_header,
                        (const char *)&cfg->acpi2_header->Signature);
            }
            cfg->acpi2_header= entry->VendorTable;
            DebugPrint(DEBUG_INFO,
                       "ACPI 2.0 table at %p, signature \"% 8.8a\"\n",
                       cfg->acpi2_header,
                       (const char *)&cfg->acpi2_header->Signature);
        }
        else if(CompareGuid(&entry->VendorGuid, &gEfiAcpi10TableGuid)) {
            if (cfg->acpi1_header) {
                DebugPrint(DEBUG_INFO,
                        "ACPI 1.0 table already set at %p, signature \"% 8.8a\"\n",
                        cfg->acpi1_header,
                        (const char *)&cfg->acpi1_header->Signature);
            }
            cfg->acpi1_header= entry->VendorTable;
            DebugPrint(DEBUG_INFO,
                       "ACPI 1.0 table at %p, signature \"% 8.8a\"\n",
                       cfg->acpi1_header,
                       (const char *)&cfg->acpi1_header->Signature);
        }
    }

    return EFI_SUCCESS;
}

