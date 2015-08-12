/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_PAGE_TABLES_H
#define __HAGFISH_PAGE_TABLES_H

/* EDK headers. */

#include <Uefi.h>

struct page_tables;

/* Application headers. */
#include <Memory.h>

EFI_STATUS build_page_tables(struct hagfish_config *cfg);
void *get_root_table(struct hagfish_config *cfg);
EFI_STATUS arch_probe(void);
void arch_init(void *root_table);
void free_page_table_bookkeeping(struct page_tables *tables);

#endif /* __HAGFISH_PAGE_TABLES_H */
