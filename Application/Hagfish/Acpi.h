/*
 * Copyright (c) 2017, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_ACPI_H
#define __HAGFISH_ACPI_H

#include <Library/UefiLib.h>

#include <sys/types.h>

/* XXX: this is not defined ?? */
typedef struct {
    UINT8   Type;
    UINT8   Length;
} EFI_ACPI_6_0_MADT_COMMON_ELEMENT;


EFI_STATUS acpi_find_root_table(struct hagfish_config *cfg);
EFI_STATUS acpi_parse_madt(struct hagfish_config *cfg);

#endif /* __HAGFISH_ACPI_H */
