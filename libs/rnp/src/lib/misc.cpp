/*
 * Copyright (c) 2017-2018 [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009-2010 The NetBSD Foundation, Inc.
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: misc.c,v 1.41 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <botan/ffi.h>
#include "crypto.h"
#include <repgp/repgp.h>
#include <rnp/rnp_sdk.h>
#include "utils.h"
#include "memory.h"

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

/* utility function to zero out memory */
void
pgp_forget(void *vp, size_t size)
{
    botan_scrub_mem(vp, size);
}

/**
\ingroup HighLevel_Memory
\brief Memory to initialise
\param mem memory to initialise
\param needed Size to initialise to
*/
void
pgp_memory_init(pgp_memory_t *mem, size_t needed)
{
    uint8_t *temp;

    mem->length = 0;
    if (mem->buf) {
        if (mem->allocated < needed) {
            if ((temp = (uint8_t *) realloc(mem->buf, needed)) == NULL) {
                RNP_LOG("bad alloc");
            } else {
                mem->buf = temp;
                mem->allocated = needed;
            }
        }
    } else {
        if ((mem->buf = (uint8_t *) calloc(1, needed)) == NULL) {
            RNP_LOG("bad alloc");
        } else {
            mem->allocated = needed;
        }
    }
}

void
pgp_memory_ref(pgp_memory_t *mem, uint8_t *data, size_t data_len)
{
    mem->buf = data;
    mem->length = data_len;
    mem->allocated = 0;
    mem->mmapped = 0;
}

/**
\ingroup HighLevel_Memory
\brief Pad memory to required length
\param mem Memory to use
\param length New size
*/
bool
pgp_memory_pad(pgp_memory_t *mem, size_t length)
{
    uint8_t *temp;

    if (mem->allocated < mem->length) {
        RNP_LOG("bad alloc in");
        return false;
    }
    if (mem->allocated < mem->length + length) {
        mem->allocated = mem->allocated * 2 + length;
        temp = (uint8_t *) realloc(mem->buf, mem->allocated);
        if (temp == NULL) {
            RNP_LOG("bad realloc");
            return false;
        } else {
            mem->buf = temp;
        }
    }
    if (mem->allocated < mem->length + length) {
        RNP_LOG("bad alloc out");
        return false;
    }

    return true;
}

/**
\ingroup HighLevel_Memory
\brief Add data to memory
\param mem Memory to which to add
\param src Data to add
\param length Length of data to add
*/
bool
pgp_memory_add(pgp_memory_t *mem, const uint8_t *src, size_t length)
{
    if (!pgp_memory_pad(mem, length)) {
        return false;
    }
    (void) memcpy(mem->buf + mem->length, src, length);
    mem->length += length;
    return true;
}

/**
 * \ingroup HighLevel_Memory
 * \brief Retains allocated memory and set length of stored data to zero.
 * \param mem Memory to clear
 * \sa pgp_memory_release()
 * \sa pgp_memory_free()
 */
void
pgp_memory_clear(pgp_memory_t *mem)
{
    mem->length = 0;
}

/**
\ingroup HighLevel_Memory
\brief Free memory and associated data
\param mem Memory to free
\note This does not free mem itself
\sa pgp_memory_clear()
\sa pgp_memory_free()
*/
void
pgp_memory_release(pgp_memory_t *mem)
{
    if (mem->mmapped) {
        (void) munmap(mem->buf, mem->length);
    } else {
        free(mem->buf);
    }
    mem->buf = NULL;
    mem->length = 0;
}

/**
   \ingroup HighLevel_Memory
   \brief Create a new zeroed pgp_memory_t
   \return Pointer to new pgp_memory_t
   \note Free using pgp_memory_free() after use.
   \sa pgp_memory_free()
*/

pgp_memory_t *
pgp_memory_new(void)
{
    return (pgp_memory_t *) calloc(1, sizeof(pgp_memory_t));
}

/**
   \ingroup HighLevel_Memory
   \brief Free memory ptr and associated memory
   \param mem Memory to be freed
   \sa pgp_memory_release()
   \sa pgp_memory_clear()
*/

void
pgp_memory_free(pgp_memory_t *mem)
{
    if (!mem) {
        return;
    }
    pgp_memory_release(mem);
    free(mem);
}

/**
   \ingroup HighLevel_Memory
   \brief Get length of data stored in pgp_memory_t struct
   \return Number of bytes in data
*/
size_t
pgp_mem_len(const pgp_memory_t *mem)
{
    return mem->length;
}

/**
   \ingroup HighLevel_Memory
   \brief Get data stored in pgp_memory_t struct
   \return Pointer to data
*/
void *
pgp_mem_data(pgp_memory_t *mem)
{
    return mem->buf;
}

/* read a gile into an pgp_memory_t */
bool
pgp_mem_readfile(pgp_memory_t *mem, const char *f)
{
    struct stat st;
    FILE *      fp;
    int         cc;

    if ((fp = fopen(f, "rb")) == NULL) {
        RNP_LOG("can't open \"%s\"", f);
        return false;
    }
    (void) fstat(fileno(fp), &st);
    mem->allocated = (size_t) st.st_size;
    mem->buf =
      (uint8_t *) mmap(NULL, mem->allocated, PROT_READ, MAP_PRIVATE | MAP_FILE, fileno(fp), 0);
    if (mem->buf == MAP_FAILED) {
        /* mmap failed for some reason - try to allocate memory */
        if ((mem->buf = (uint8_t *) calloc(1, mem->allocated)) == NULL) {
            RNP_LOG("calloc failed");
            (void) fclose(fp);
            return false;
        }
        /* read into contents of mem */
        for (mem->length = 0; (cc = (int) read(fileno(fp),
                                               &mem->buf[mem->length],
                                               (size_t)(mem->allocated - mem->length))) > 0;
             mem->length += (size_t) cc) {
        }
    } else {
        mem->length = mem->allocated;
        mem->mmapped = 1;
    }
    (void) fclose(fp);
    return (mem->allocated == mem->length);
}

bool
pgp_mem_writefile(pgp_memory_t *mem, const char *f)
{
    FILE *fp;
    int   fd;
    char  tmp[MAXPATHLEN];

    snprintf(tmp, sizeof(tmp), "%s.rnp-tmp.XXXXXX", f);

    fd = mkstemp(tmp);
    if (fd < 0) {
        RNP_LOG("pgp_mem_writefile: can't open temp file: %s", strerror(errno));
        return false;
    }

    if ((fp = fdopen(fd, "wb")) == NULL) {
        RNP_LOG("pgp_mem_writefile: can't open \"%s\"", strerror(errno));
        return false;
    }

    fwrite(mem->buf, mem->length, 1, fp);
    if (ferror(fp)) {
        RNP_LOG("pgp_mem_writefile: can't write to file");
        fclose(fp);
        return false;
    }

    fclose(fp);

    if (rename(tmp, f)) {
        RNP_LOG("pgp_mem_writefile: can't rename to target file: %s", strerror(errno));
        return false;
    }

    return true;
}

/**
 * Searches the given map for the given type.
 * Returns a human-readable descriptive string if found,
 * returns NULL if not found
 *
 * It is the responsibility of the calling function to handle the
 * error case sensibly (i.e. don't just print out the return string.
 *
 */
static const char *
str_from_map_or_null(int type, pgp_map_t *map)
{
    pgp_map_t *row;

    for (row = map; row->string != NULL; row++) {
        if (row->type == type) {
            return row->string;
        }
    }
    return NULL;
}

/**
 * \ingroup Core_Print
 *
 * Searches the given map for the given type.
 * Returns a readable string if found, "Unknown" if not.
 */

const char *
pgp_str_from_map(int type, pgp_map_t *map)
{
    const char *str;

    str = str_from_map_or_null(type, map);
    return (str) ? str : "Unknown";
}

#define LINELEN 16

/* show hexadecimal/ascii dump */
void
hexdump(FILE *fp, const char *header, const uint8_t *src, size_t length)
{
    size_t i;
    char   line[LINELEN + 1];

    (void) fprintf(fp, "%s%s", (header) ? header : "", (header) ? "" : "");
    (void) fprintf(fp, " (%" PRIsize "u byte%s):\n", length, (length == 1) ? "" : "s");
    for (i = 0; i < length; i++) {
        if (i % LINELEN == 0) {
            (void) fprintf(fp, "%.5" PRIsize "u | ", i);
        }
        (void) fprintf(fp, "%.02x ", (uint8_t) src[i]);
        line[i % LINELEN] = (isprint(src[i])) ? src[i] : '.';
        if (i % LINELEN == LINELEN - 1) {
            line[LINELEN] = 0x0;
            (void) fprintf(fp, " | %s\n", line);
        }
    }
    if (i % LINELEN != 0) {
        for (; i % LINELEN != 0; i++) {
            (void) fprintf(fp, "   ");
            line[i % LINELEN] = ' ';
        }
        line[LINELEN] = 0x0;
        (void) fprintf(fp, " | %s\n", line);
    }
}

/* small useful functions for setting the file-level debugging levels */
/* if the debugv list contains the filename in question, we're debugging it */

enum { MAX_DEBUG_NAMES = 32 };

static int   debugc;
static char *debugv[MAX_DEBUG_NAMES];

/* set the debugging level per filename */
int
rnp_set_debug(const char *f)
{
    const char *name;
    int         i;

    if (f == NULL) {
        f = "all";
    }
    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; ((i < MAX_DEBUG_NAMES) && (i < debugc)); i++) {
        if (strcmp(debugv[i], name) == 0) {
            return 1;
        }
    }
    if (i == MAX_DEBUG_NAMES) {
        return false;
    }
    debugv[debugc++] = strdup(name);
    return true;
}

/* get the debugging level per filename */
int
rnp_get_debug(const char *f)
{
    const char *name;
    int         i;

    if (!debugc) {
        return 0;
    }

    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; i < debugc; i++) {
        if (strcmp(debugv[i], "all") == 0 || strcmp(debugv[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* return the version for the library */
const char *
rnp_get_info(const char *type)
{
    if (strcmp(type, "version") == 0) {
        return PACKAGE_STRING;
    }
    if (strcmp(type, "maintainer") == 0) {
        return PACKAGE_BUGREPORT;
    }
    return "[unknown]";
}

void
rnp_log(const char *fmt, ...)
{
    va_list vp;
    time_t  t;
    char    buf[BUFSIZ * 2];
    int     cc;

    (void) time(&t);
    cc = snprintf(buf, sizeof(buf), "%.24s: rnp: ", ctime(&t));
    va_start(vp, fmt);
    (void) vsnprintf(&buf[cc], sizeof(buf) - (size_t) cc, fmt, vp);
    va_end(vp);
    /* do something with message */
    /* put into log buffer? */
}

/* portable replacement for strcasecmp(3) */
int
rnp_strcasecmp(const char *s1, const char *s2)
{
    int n;

    for (n = 0; (n = tolower((uint8_t) *s1) - tolower((uint8_t) *s2)) == 0 && *s1;
         s1++, s2++) {
    }
    return n;
}

/* return the hexdump as a string */
char *
rnp_strhexdump(char *dest, const uint8_t *src, size_t length, const char *sep)
{
    unsigned i;
    int      n;

    for (n = 0, i = 0; i < length; i += 2) {
        n += snprintf(&dest[n], 3, "%02x", *src++);
        n += snprintf(&dest[n], 10, "%02x%s", *src++, sep);
    }
    return dest;
}

char *
rnp_strhexdump_upper(char *dest, const uint8_t *src, size_t length, const char *sep)
{
    unsigned i;
    int      n;

    for (n = 0, i = 0; i < length; i += 2) {
        n += snprintf(&dest[n], 3, "%02X", *src++);
        n += snprintf(&dest[n], 10, "%02X%s", *src++, sep);
    }
    return dest;
}

/* return the file modification time */
int64_t
rnp_filemtime(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return 0;
    } else {
        return st.st_mtime;
    }
}

/* return the filename from the given path */
const char *
rnp_filename(const char *path)
{
    char *res = strrchr((char *) path, '/');
    if (!res) {
        return path;
    } else {
        return res + 1;
    }
}

static char *
vcompose_path(char **buf, size_t *buf_len, const char *first, va_list ap)
{
    size_t curlen = 0;
    char * tmp_buf = NULL;
    size_t tmp_buf_len = 0;

    if (!first) {
        return NULL;
    }
    if (!buf) {
        buf = &tmp_buf;
    }
    if (!buf_len) {
        buf_len = &tmp_buf_len;
    }

    const char *s = first;
    do {
        size_t len = strlen(s);

        // current string len + NULL terminator + possible '/' +
        // len of this path component
        size_t reqsize = curlen + 1 + 1 + len;
        if (*buf_len < reqsize) {
            char *newbuf = (char *) realloc(*buf, reqsize);
            if (!newbuf) {
                // realloc failed, bail
                free(*buf);
                *buf = NULL;
                break;
            }
            *buf = newbuf;
            *buf_len = reqsize;
        }

        if (s != first) {
            if ((*buf)[curlen - 1] != '/' && *s != '/') {
                // add missing separator
                (*buf)[curlen] = '/';
                curlen += 1;
            } else if ((*buf)[curlen - 1] == '/' && *s == '/') {
                // skip duplicate separator
                s++;
                len--;
            }
        }
        memcpy(*buf + curlen, s, len + 1);
        curlen += len;
    } while ((s = va_arg(ap, const char *)));

    return *buf;
}

/** compose a path from one or more components
 *
 *  Notes:
 *  - The final argument must be NULL.
 *  - The caller must free the returned buffer.
 *  - The returned buffer is always NULL-terminated.
 *
 *  @param first the first path component
 *  @return the composed path buffer. The caller must free it.
 */
char *
rnp_compose_path(const char *first, ...)
{
    va_list ap;
    va_start(ap, first);
    char *path = vcompose_path(NULL, NULL, first, ap);
    va_end(ap);
    return path;
}

/** compose a path from one or more components
 *
 *  This version is useful when a function is composing
 *  multiple paths and wants to try to avoid unnecessary
 *  allocations.
 *
 *  Notes:
 *  - The final argument must be NULL.
 *  - The caller must free the returned buffer.
 *  - The returned buffer is always NULL-terminated.
 *
 *  @code
 *  char *buf = NULL;
 *  size_t buf_len = 0;
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", dir1, file1, NULL);
 *  // the calls below will realloc the buffer if needed
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", dir3, NULL);
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", something, NULL);
 *  free(buf);
 *  @endcode
 *
 *  @param buf pointer to the buffer where the result will be stored.
 *         If buf is NULL, the caller must use the returned value.
 *         If *buf is NULL, a new buffer will be allocated.
 *  @param buf_len pointer to the allocated buffer size.
 *         Can be NULL.
 *  @param first the first path component
 *  @return the composed path buffer. The caller must free it.
 */
char *
rnp_compose_path_ex(char **buf, size_t *buf_len, const char *first, ...)
{
    va_list ap;
    va_start(ap, first);
    char *path = vcompose_path(buf, buf_len, first, ap);
    va_end(ap);
    return path;
}

bool
rnp_path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

bool
rnp_dir_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool
rnp_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool
rnp_path_strip_ext(char *path)
{
    char *ptr;

    if (!path || !path[0]) {
        return false;
    }

    ptr = path + strlen(path) - 1;

    while (ptr >= path) {
        if (*ptr == '.') {
            *ptr = '\0';
            return true;
        }

        ptr--;
    }

    return false;
}

bool
rnp_path_has_ext(const char *path, const char *ext)
{
    size_t plen, elen;

    if (!path || !path[0] || !ext || !ext[0]) {
        return false;
    }

    if (ext[0] == '.') {
        ext++;
    }

    plen = strlen(path);
    elen = strlen(ext);

    return (elen < plen) && !rnp_strcasecmp(path + plen - elen, ext) &&
           (path[plen - elen - 1] == '.');
}

bool
rnp_path_add_ext(char *path, size_t len, const char *ext)
{
    size_t plen, elen;

    if (!path || !path[0] || !ext || !ext[0]) {
        return false;
    }

    if (ext[0] == '.') {
        ext++;
    }

    plen = strlen(path);
    elen = strlen(ext);

    if (len < plen + elen + 2) {
        return false;
    }

    if (path[plen - 1] != '.') {
        path[plen++] = '.';
    }

    memcpy(path + plen, ext, elen);
    path[plen + elen] = '\0';
    return true;
}

bool
rnp_hex_encode(
  const uint8_t *buf, size_t buf_len, char *hex, size_t hex_len, rnp_hex_format_t format)
{
    uint32_t flags = format == RNP_HEX_LOWERCASE ? BOTAN_FFI_HEX_LOWER_CASE : 0;

    if (hex_len < (buf_len * 2 + 1)) {
        return false;
    }
    hex[buf_len * 2] = '\0';
    return botan_hex_encode(buf, buf_len, hex, flags) == 0;
}

size_t
rnp_hex_decode(const char *hex, uint8_t *buf, size_t buf_len)
{
    if (botan_hex_decode(hex, strlen(hex), buf, &buf_len) != 0) {
        RNP_LOG("Hex decode failed on string: %s", hex);
        return 0;
    }
    return buf_len;
}

char *
rnp_strlwr(char *s)
{
    char *p = s;
    while (*p) {
        *p = tolower((unsigned char) *p);
        p++;
    }
    return s;
}

char *
rnp_strip_eol(char *s)
{
    size_t len = strlen(s);

    while ((len > 0) && ((s[len - 1] == '\n') || (s[len - 1] == '\r'))) {
        s[--len] = '\0';
    }

    return s;
}

/* small function to pretty print an 8-character raw userid */
char *
userid_to_id(const uint8_t *userid, char *id)
{
    static const char *hexes = "0123456789abcdef";
    int                i;

    for (i = 0; i < 8; i++) {
        id[i * 2] = hexes[(unsigned) (userid[i] & 0xf0) >> 4];
        id[(i * 2) + 1] = hexes[userid[i] & 0xf];
    }
    id[8 * 2] = 0x0;
    return id;
}

/* check whether string is hex */
bool
ishex(const char *hexid, size_t hexlen)
{
    /* check for 0x prefix */
    if ((hexlen >= 2) && (hexid[0] == '0') && ((hexid[1] == 'x') || (hexid[1] == 'X'))) {
        hexid += 2;
        hexlen -= 2;
    }

    for (size_t i = 0; i < hexlen; i++) {
        if ((hexid[i] >= '0') && (hexid[i] <= '9')) {
            continue;
        }
        if ((hexid[i] >= 'a') && (hexid[i] <= 'f')) {
            continue;
        }
        if ((hexid[i] >= 'A') && (hexid[i] <= 'F')) {
            continue;
        }
        if ((hexid[i] == ' ') || (hexid[i] == '\t')) {
            continue;
        }
        return false;
    }
    return true;
}
/* convert hex string, probably prefixes with 0x, to binary form */
bool
hex2bin(const char *hex, size_t hexlen, uint8_t *bin, size_t len, size_t *out)
{
    bool    haslow = false;
    uint8_t low = 0;
    size_t  binlen = 0;

    *out = 0;
    if (hexlen < 1) {
        return false;
    }

    /* check for 0x prefix */
    if ((hexlen >= 2) && (hex[0] == '0') && ((hex[1] == 'x') || (hex[1] == 'X'))) {
        hex += 2;
        hexlen -= 2;
    }

    haslow = hexlen % 2;
    for (size_t i = 0; i < hexlen; i++) {
        if ((hex[i] == ' ') || (hex[i] == '\t')) {
            continue;
        }

        if ((hex[i] >= '0') && (hex[i] <= '9')) {
            low = (low << 4) | (hex[i] - '0');
        } else if ((hex[i] >= 'a') && (hex[i] <= 'f')) {
            low = (low << 4) | (hex[i] - ('a' - 10));
        } else if ((hex[i] >= 'A') && (hex[i] <= 'F')) {
            low = (low << 4) | (hex[i] - ('A' - 10));
        } else {
            return false;
        }

        /* we had low bits before - so have the whole byte now */
        if (haslow) {
            if (binlen < len) {
                bin[binlen] = low;
            }
            binlen++;
            low = 0;
        }
        haslow = !haslow;
    }

    *out = binlen;
    return true;
}
