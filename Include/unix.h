/** @file
  Root include file to support building OpenSSL Crypto Library.

Copyright (c) 2010 - 2011, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __OPEN_SSL_SUPPORT_H__
#define __OPEN_SSL_SUPPORT_H__

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>

typedef UINTN          size_t;
typedef INTN           ssize_t;
typedef INT64          off_t;
typedef UINT16         mode_t;
typedef long           time_t;
typedef unsigned long  clock_t;
typedef UINT32         uid_t;
typedef UINT32         gid_t;
typedef UINT32         ino_t;
typedef UINT32         dev_t;
typedef UINT16         nlink_t;
typedef int            pid_t;

typedef UINT8          uint8_t;
typedef UINT16         uint16_t;
typedef UINT32         uint32_t;
typedef UINT64         uint64_t;
typedef INT8           int8_t;
typedef INT16          int16_t;
typedef INT32          int32_t;
typedef INT64          int64_t;

/* Limits of integral types.  */

/* Minimum of signed integral types.  */
# define INT8_MIN		(-128)
# define INT16_MIN		(-32767-1)
# define INT32_MIN		(-2147483647-1)
# define INT64_MIN		(-__INT64_C(9223372036854775807)-1)
/* Maximum of signed integral types.  */
# define INT8_MAX		(127)
# define INT16_MAX		(32767)
# define INT32_MAX		(2147483647)
# define INT64_MAX		(__INT64_C(9223372036854775807))

/* Maximum of unsigned integral types. */
# define UINT8_MAX		(255)
# define UINT16_MAX		(65535)
# define UINT32_MAX		(4294967295U)
# define UINT64_MAX		(__UINT64_C(18446744073709551615))

/* Limit of `size_t' type.  */
#define SIZE_MAX __SIZE_MAX__

/* Types for `void *' pointers.  */
#if __SIZEOF_POINTER__ == 8
# ifndef __intptr_t_defined
typedef int64_t intptr_t;
#  define __intptr_t_defined
# endif
typedef uint64_t uintptr_t;
#else
# ifndef __intptr_t_defined
typedef int32_t intptr_t;
#  define __intptr_t_defined
# endif
typedef uint32_t uintptr_t;
#endif

#define ARMAG  "!<arch>\n"
#define SARMAG 8
#define ARFMAG "`\n"

struct ar_hdr {
    char ar_name[16];
    char ar_date[12];
    char ar_uid[6], ar_gid[6];
    char ar_mode[8];
    char ar_size[10];
    char ar_fmag[2];
};

//
// Externs from EFI Application Toolkit required to build libefi
//
extern int errno;

//
// Function prototypes from EFI Application Toolkit required to build libefi
//
void *calloc(size_t, size_t);

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define roundup2(x, y) roundup(x, y)

//
// Macros that directly map functions to BaseLib, BaseMemoryLib, and DebugLib
// functions
//
#define malloc(size)\
    AllocatePool(size)

#define calloc(nmemb, size)\
    AllocateZeroPool((nmemb) * (size))

#define free(size)\
    FreePool(size)

#define memcpy(dest, source, count)\
    CopyMem(dest, source, (UINTN)(count))

#define memset(dest, ch, count)\
    SetMem(dest, (UINTN)(count), (UINT8)(ch))

#define strncmp(string1, string2, count)\
    ((int)(AsciiStrnCmp(string1, string2, (UINTN)(count))))

#define strncpy(strDest, strSource, count)\
    AsciiStrnCpy(strDest, strSource, (UINTN)count)

#define snprintf(...)\
    AsciiSPrint(__VA_ARGS__)

#define strerror(errno)\
    "No OS error descriptions available"

#define assert(expression)\
    ASSERT(expression)

#endif
