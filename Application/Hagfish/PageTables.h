#ifndef __HAGFISH_PAGE_TABLES_H
#define __HAGFISH_PAGE_TABLES_H

/* EDK headers. */

#include <Uefi.h>

struct page_tables;

/* Application headers. */
#include <Memory.h>

EFI_STATUS build_page_tables(struct hagfish_config *cfg);
void free_page_table_bookkeeping(struct page_tables *tables);

#endif /* __HAGFISH_PAGE_TABLES_H */
