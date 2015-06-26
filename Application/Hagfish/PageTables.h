#ifndef __HAGFISH_PAGE_TABLES_H
#define __HAGFISH_PAGE_TABLES_H

#include <Uefi.h>

#include <Memory.h>

struct page_tables;

struct page_tables *build_page_tables(EFI_SYSTEM_TABLE *SystemTable,
                                      struct region_list *list);
void free_page_table_bookkeeping(struct page_tables *tables);

#endif /* __HAGFISH_PAGE_TABLES_H */
