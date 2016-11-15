/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

/*** Hagfish configuration file loading and parsing. ***/

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* EDK headers */
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>

/* Application headers */
#include <Allocation.h>
#include <Config.h>

const char *hagfish_config_fmt= "menu.lst.%d.%d.%d.%d";
const char *hagfish_config_fmt= "hagfish.%d.%d.%d.%d.cfg";

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

static size_t
skip_whitespace(const char *buf, size_t size, size_t start, int skip_newlines) {
    ASSERT(start < size);
    size_t i;

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

static size_t
find_eol(const char *buf, size_t size, size_t start) {
    ASSERT(start < size);
    size_t i;

    for(i= start; i < size && buf[i] != '\n'; i++);

    ASSERT(start <= i);
    ASSERT(i <= size);
    ASSERT(i == size || buf[i] == '\n');
    return i;
}

static size_t
find_token(const char *buf, size_t size, size_t start, int skip_newlines) {
    ASSERT(start < size);
    size_t i= start;

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

static size_t
get_token(const char *buf, size_t size, size_t start) {
    ASSERT(start < size);
    ASSERT(istoken(buf[start]));
    size_t i;

    for(i= start; i < size && istoken(buf[i]); i++);

    ASSERT(start < i);
    ASSERT(i <= size);
    ASSERT(istoken(buf[i-1]));
    return i;
}

static int
get_cmdline(const char *buf, size_t size, size_t *cursor,
            size_t *cstart, size_t *clen, size_t *astart, size_t *alen) {
    ASSERT(*cursor < size);
    *cursor= find_token(buf, size, *cursor, 0);
    if(!istoken(buf[*cursor])) {
        DebugPrint(DEBUG_ERROR, "Missing command line\n");
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
parse_config(char *buf, size_t size) {
    size_t cursor= 0;
    struct hagfish_config *cfg;

    cfg= calloc(1, sizeof(struct hagfish_config));
    if(!cfg) {
        DebugPrint(DEBUG_ERROR, "calloc: %a\n", strerror(errno));
        goto parse_fail;
    }
    cfg->buf= buf;
    cfg->stack_size= DEFAULT_STACK_SIZE;

    while(cursor < size) {
        cursor= find_token(buf, size, cursor, 1);
        if(cursor < size) {
            size_t tstart= cursor, tlen;

            ASSERT(istoken(buf[cursor]));
            cursor= get_token(buf, size, cursor);
            tlen= cursor - tstart;
            ASSERT(tlen <= size - cursor);

            if(!strncmp("title", buf+tstart, 5)) {
                /* Ignore the title. */
                ASSERT(cursor < size);
                cursor= find_eol(buf, size, cursor);
            }
            else if(!strncmp("stack", buf+tstart, 5)) {
                char arg[10];
                size_t astart, alen;

                cursor= skip_whitespace(buf, size, cursor, FALSE);
                if(!istoken(buf[cursor])) {
                    DebugPrint(DEBUG_ERROR, "Expected stack size\n");
                    goto parse_fail;
                }
                astart= cursor;

                cursor= get_token(buf, size, cursor);
                alen= cursor - astart;
                ASSERT(alen <= size - cursor);

                if(alen > 9) {
                    DebugPrint(DEBUG_ERROR, "Stack size field too long\n");
                    goto parse_fail;
                }

                memcpy(arg, buf+astart, alen);
                arg[alen]= '\0';
                cfg->stack_size= strtoul(arg, NULL, 10);
            }
            else if(!strncmp("kernel", buf+tstart, 6)) {
                if(cfg->kernel) {
                    DebugPrint(DEBUG_ERROR, "Kernel defined twice\n");
                    goto parse_fail;
                }

                cfg->kernel= calloc(1, sizeof(struct component_config));
                if(!cfg->kernel) {
                    DebugPrint(DEBUG_ERROR, "calloc: %a\n", strerror(errno));
                    goto parse_fail;
                }

                /* Grab the command line. */
                if(!get_cmdline(buf, size, &cursor,
                                &cfg->kernel->path_start,
                                &cfg->kernel->path_len,
                                &cfg->kernel->args_start,
                                &cfg->kernel->args_len))
                    goto parse_fail;
            }
            else if(!strncmp("module", buf+tstart, 6)) {
                struct component_config *module=
                    calloc(1, sizeof(struct component_config));
                if(!module) {
                    DebugPrint(DEBUG_ERROR, "calloc, %a\n", strerror(errno));
                    goto parse_fail;
                }

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
                DebugPrint(DEBUG_ERROR,
                           "Unrecognised entry \"%.*a\", skipping line.\n",
                           tlen, buf + tstart);
                cursor= find_eol(buf, size, cursor);
            }
        }
    }

    if(!cfg->kernel) {
        DebugPrint(DEBUG_ERROR, "No kernel image specified\n");
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

/* Free all heap-allocated bookkeeping, none of which will be passed to
 * Barrelfish.  Note that this leaves everything allocated explicitly into
 * frames untouched. */
void
free_bookkeeping(struct hagfish_config *cfg) {
    ASSERT(cfg);

    /* The configuration file itself. */
    if(cfg->buf) free(cfg->buf);

    /* The memory region list. */
    if(cfg->ram_regions) free_region_list(cfg->ram_regions);

    /* Root page table metadata.  The page tables themselves are untouched. */
    if(cfg->tables) free_page_table_bookkeeping(cfg->tables);

    /* The kernel. */
    if(cfg->kernel) free(cfg->kernel);
    if(cfg->kernel_segments) free_region_list(cfg->kernel_segments);

    /* All non-kernel components. */

    struct component_config *cmp, *next;
    for(cmp = cfg->first_module; cmp; cmp = next) {
        next = cmp->next;
        free(cmp);
    }
    cfg->first_module = NULL;
}
