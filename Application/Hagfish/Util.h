/*
 * Copyright (c) 2015, ETH Zuerich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __HAGFISH_UTIL_H
#define __HAGFISH_UTIL_H

#define COVER(x, y) (((x) + ((y)-1)) / (y))
#define ROUNDDOWN(x, y) (((x) / (y)) * (y))
#define ROUNDUP(x, y) (COVER(x,y) * (y))

#endif /* __HAGFISH_UTIL_H */
