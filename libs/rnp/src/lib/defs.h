/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef DEFS_H_
#define DEFS_H_

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NEWARRAY(type, ptr, size, where, action)                                \
    do {                                                                        \
        if ((ptr = (type *) calloc(sizeof(type), (unsigned) (size))) == NULL) { \
            (void) fprintf(stderr,                                              \
                           "%s: can't allocate %lu bytes\n",                    \
                           where,                                               \
                           (unsigned long) (size * sizeof(type)));              \
            action;                                                             \
        }                                                                       \
    } while (/* CONSTCOND */ 0)

#define RENEW(type, ptr, size, where, action)                             \
    do {                                                                  \
        type *_newptr;                                                    \
        _newptr = (type *) realloc(ptr, (size_t)(sizeof(type) * (size))); \
        if (_newptr == NULL) {                                            \
            (void) fprintf(stderr,                                        \
                           "%s: can't realloc %lu bytes\n",               \
                           where,                                         \
                           (unsigned long) (size * sizeof(type)));        \
            action;                                                       \
        } else {                                                          \
            ptr = _newptr;                                                \
        }                                                                 \
    } while (/* CONSTCOND */ 0)

#define NEW(type, ptr, where, action) NEWARRAY(type, ptr, 1, where, action)

#define FREE(ptr) (void) free(ptr)

#define ALLOC(type, v, size, c, init, incr, where, action)      \
    do {                                                        \
        uint32_t _newsize = size;                               \
        if (size == 0) {                                        \
            _newsize = init;                                    \
            NEWARRAY(type, v, _newsize, where ": new", action); \
        } else if (c == size) {                                 \
            _newsize = size + incr;                             \
            RENEW(type, v, _newsize, where ": renew", action);  \
        }                                                       \
        size = _newsize;                                        \
    } while (/* CONSTCOND */ 0)

#define DEFINE_ARRAY(name, type) \
    typedef struct name {        \
        uint32_t c;              \
        uint32_t size;           \
        type *   v;              \
    } name

/* A macro for defining a dynamic array. It expands to the following
 * members:
 *
 * - arr##c:     the number of elements currently populating the array
 * - arr##vsize: the current capacity of the array
 * - arr##s      a pointer to the backing array
 *
 * If you aren't familiar with macro ## syntax DYNARRAY(int, number)
 * would expand to:
 *
 * unsigned numberc;
 * unsigned numbervsize;
 * unsigned numbers;
 */

#define DYNARRAY(type, arr) \
    unsigned arr##c;        \
    unsigned arr##vsize;    \
    type *   arr##s

#define EXPAND_ARRAY(str, arr)                                                       \
    do {                                                                             \
        if (str->arr##c == str->arr##vsize) {                                        \
            void *   __newarr;                                                       \
            char *   __newarrc;                                                      \
            unsigned __newsize;                                                      \
            __newsize = (str->arr##vsize * 2) + 10;                                  \
            if ((__newarr = __newarrc = (char *) realloc(                            \
                   str->arr##s, __newsize * sizeof(*str->arr##s))) == NULL) {        \
                (void) fprintf(stderr, "EXPAND_ARRAY - bad realloc\n");              \
            } else {                                                                 \
                (void) memset(&__newarrc[str->arr##vsize * sizeof(*str->arr##s)],    \
                              0x0,                                                   \
                              (__newsize - str->arr##vsize) * sizeof(*str->arr##s)); \
                str->arr##s = static_cast<decltype(str->arr##s)>(__newarr);          \
                str->arr##vsize = __newsize;                                         \
            }                                                                        \
        }                                                                            \
    } while (/*CONSTCOND*/ 0)

#define EXPAND_ARRAY_EX(str, arr, num)                                               \
    do {                                                                             \
        if (str->arr##c == str->arr##vsize) {                                        \
            void *   __newarr;                                                       \
            char *   __newarrc;                                                      \
            unsigned __newsize;                                                      \
            __newsize = str->arr##vsize + num;                                       \
            if ((__newarr = __newarrc = (char *) realloc(                            \
                   str->arr##s, __newsize * sizeof(*str->arr##s))) == NULL) {        \
                (void) fprintf(stderr, "EXPAND_ARRAY - bad realloc\n");              \
            } else {                                                                 \
                (void) memset(&__newarrc[str->arr##vsize * sizeof(*str->arr##s)],    \
                              0x0,                                                   \
                              (__newsize - str->arr##vsize) * sizeof(*str->arr##s)); \
                str->arr##s = static_cast<decltype(str->arr##s)>(__newarr);          \
                str->arr##vsize = __newsize;                                         \
            }                                                                        \
        }                                                                            \
    } while (/*CONSTCOND*/ 0)

#define FREE_ARRAY(str, arr) \
    do {                     \
        free(str->arr##s);   \
        str->arr##s = NULL;  \
        str->arr##c = 0;     \
        str->arr##vsize = 0; \
    } while (/*CONSTCOND*/ 0)

#define DYNARRAY_IS_EMPTY(str, arr) (!(str)->arr##c || !(str)->arr##s || !(str)->arr##vsize)

#endif /* !DEFS_H_ */
