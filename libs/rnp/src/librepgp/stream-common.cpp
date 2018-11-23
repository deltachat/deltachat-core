/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <rnp/rnp_def.h>
#include "stream-common.h"
#include "types.h"
#include "utils.h"

ssize_t
src_read(pgp_source_t *src, void *buf, size_t len)
{
    size_t              left = len;
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;
    bool                readahead = cache ? cache->readahead : false;

    if (src->eof || (len == 0)) {
        return 0;
    }

    // Do not read more then available if source size is known
    if (src->knownsize && (src->readb + len > src->size)) {
        len = src->size - src->readb;
        left = len;
        readahead = false;
    }

    // Check whether we have cache and there is data inside
    if (cache && (cache->len > cache->pos)) {
        read = cache->len - cache->pos;
        if ((size_t) read >= len) {
            memcpy(buf, &cache->buf[cache->pos], len);
            cache->pos += len;
            goto finish;
        } else {
            memcpy(buf, &cache->buf[cache->pos], read);
            cache->pos += read;
            buf = (uint8_t *) buf + read;
            left = len - read;
        }
    }

    // If we got here then we have empty cache or no cache at all
    while (left > 0) {
        if (left > sizeof(cache->buf) || !readahead || !cache) {
            // If there is no cache or chunk is larger then read directly
            read = src->read(src, buf, left);
            if (read > 0) {
                left -= read;
                buf = (uint8_t *) buf + read;
            } else if (read == 0) {
                src->eof = 1;
                len = len - left;
                goto finish;
            } else {
                return -1;
            }
        } else {
            // Try to fill the cache to avoid small reads
            read = src->read(src, &cache->buf[0], sizeof(cache->buf));
            if (read == 0) {
                src->eof = 1;
                len = len - left;
                goto finish;
            } else if (read < 0) {
                return -1;
            } else if ((size_t) read < left) {
                memcpy(buf, &cache->buf[0], read);
                left -= read;
                buf = (uint8_t *) buf + read;
            } else {
                memcpy(buf, &cache->buf[0], left);
                cache->pos = left;
                cache->len = read;
                goto finish;
            }
        }
    }

finish:
    src->readb += len;

    if (src->knownsize && (src->readb == src->size)) {
        src->eof = 1;
    }

    return len;
}

bool
src_read_eq(pgp_source_t *src, void *buf, size_t len)
{
    ssize_t res = src_read(src, buf, len);
    return res == (ssize_t) len;
}

ssize_t
src_peek(pgp_source_t *src, void *buf, size_t len)
{
    ssize_t             read;
    pgp_source_cache_t *cache = src->cache;
    bool                readahead = cache->readahead;

    if (!cache || (len > sizeof(cache->buf))) {
        return -1;
    }

    if (src->eof) {
        return 0;
    }

    // Do not read more then available if source size is known
    if (src->knownsize && (src->readb + len > src->size)) {
        len = src->size - src->readb;
        readahead = false;
    }

    if (cache->len - cache->pos >= len) {
        if (buf) {
            memcpy(buf, &cache->buf[cache->pos], len);
        }
        return len;
    }

    if (cache->pos > 0) {
        memmove(&cache->buf[0], &cache->buf[cache->pos], cache->len - cache->pos);
        cache->len -= cache->pos;
        cache->pos = 0;
    }

    while (cache->len < len) {
        read = readahead ? sizeof(cache->buf) - cache->len : len - cache->len;
        if (src->knownsize && (src->readb + read > src->size)) {
            read = src->size - src->readb;
        }
        read = src->read(src, &cache->buf[cache->len], read);
        if (read == 0) {
            if (buf) {
                memcpy(buf, &cache->buf[0], cache->len);
            }
            return cache->len;
        } else if (read < 0) {
            return -1;
        } else {
            cache->len += read;
            if (cache->len >= len) {
                if (buf) {
                    memcpy(buf, &cache->buf[0], len);
                }
                return len;
            }
        }
    }

    return -1;
}

ssize_t
src_skip(pgp_source_t *src, size_t len)
{
    ssize_t res;
    void *  buf;
    uint8_t sbuf[16];

    if (src->cache && (src->cache->len - src->cache->pos >= len)) {
        src->readb += len;
        src->cache->pos += len;
        return len;
    }

    if (len < sizeof(sbuf)) {
        return src_read(src, sbuf, len);
    } else {
        buf = calloc(1, len);

        if (buf == NULL) {
            return -1;
        } else {
            res = src_read(src, buf, len);
            free(buf);
            return res;
        }
    }
}

rnp_result_t
src_finish(pgp_source_t *src)
{
    rnp_result_t res = RNP_SUCCESS;
    if (src->finish) {
        res = src->finish(src);
    }

    return res;
}

bool
src_eof(pgp_source_t *src)
{
    uint8_t check;

    if (src->eof) {
        return true;
    }

    return src_peek(src, &check, 1) == 0;
}

void
src_close(pgp_source_t *src)
{
    if (src->close) {
        src->close(src);
    }

    if (src->cache) {
        free(src->cache);
        src->cache = NULL;
    }
}

bool
src_skip_eol(pgp_source_t *src)
{
    uint8_t eol[2];
    ssize_t read;

    read = src_peek(src, eol, 2);
    if ((read >= 1) && (eol[0] == '\n')) {
        src_skip(src, 1);
        return true;
    } else if ((read == 2) && (eol[0] == '\r') && (eol[1] == '\n')) {
        src_skip(src, 2);
        return true;
    }

    return false;
}

ssize_t
src_peek_line(pgp_source_t *src, char *buf, size_t len)
{
    size_t  clen = 0;
    ssize_t read;

    /* we need some place for \0 */
    len--;

    do {
        read = clen + 64 > len ? len - clen : 64;
        read = src_peek(src, buf + clen, read);
        if (read <= 0) {
            return -1;
        }

        for (int i = 0; i < read; i++) {
            if (buf[clen] == '\n') {
                if ((clen > 0) && (buf[clen - 1] == '\r')) {
                    clen--;
                }
                buf[clen] = '\0';
                return clen;
            }
            clen++;
        }
    } while (clen < len);

    return -1;
}

bool
init_src_common(pgp_source_t *src, size_t paramsize)
{
    memset(src, 0, sizeof(*src));

    if ((src->cache = (pgp_source_cache_t *) calloc(1, sizeof(pgp_source_cache_t))) == NULL) {
        RNP_LOG("cache allocation failed");
        return false;
    }
    src->cache->readahead = true;

    if (paramsize > 0) {
        if ((src->param = calloc(1, paramsize)) == NULL) {
            RNP_LOG("param allocation failed");
            free(src->cache);
            src->cache = NULL;
            return false;
        }
    }

    return true;
}

typedef struct pgp_source_file_param_t {
    int fd;
} pgp_source_file_param_t;

static ssize_t
file_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_file_param_t *param = (pgp_source_file_param_t *) src->param;

    if (param == NULL) {
        return -1;
    } else {
        return read(param->fd, buf, len);
    }
}

static void
file_src_close(pgp_source_t *src)
{
    pgp_source_file_param_t *param = (pgp_source_file_param_t *) src->param;
    if (param) {
        if (src->type == PGP_STREAM_FILE) {
            close(param->fd);
        }
        free(src->param);
        src->param = NULL;
    }
}

rnp_result_t
init_file_src(pgp_source_t *src, const char *path)
{
    int                      fd;
    struct stat              st;
    pgp_source_file_param_t *param;

    if (stat(path, &st) != 0) {
        RNP_LOG("can't stat '%s'", path);
        return RNP_ERROR_READ;
    }

#ifdef O_BINARY
    fd = open(path, O_RDONLY | O_BINARY);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        RNP_LOG("can't open '%s'", path);
        return RNP_ERROR_READ;
    }

    if (!init_src_common(src, sizeof(pgp_source_file_param_t))) {
        close(fd);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_file_param_t *) src->param;
    param->fd = fd;
    src->read = file_src_read;
    src->close = file_src_close;
    src->type = PGP_STREAM_FILE;
    src->size = st.st_size;
    src->knownsize = 1;

    return RNP_SUCCESS;
}

rnp_result_t
init_stdin_src(pgp_source_t *src)
{
    pgp_source_file_param_t *param;

    if (!init_src_common(src, sizeof(pgp_source_file_param_t))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_file_param_t *) src->param;
    param->fd = 0;
    src->read = file_src_read;
    src->close = file_src_close;
    src->type = PGP_STREAM_STDIN;

    return RNP_SUCCESS;
}

typedef struct pgp_source_mem_param_t {
    const void *memory;
    bool        free;
    size_t      len;
    size_t      pos;
} pgp_source_mem_param_t;

typedef struct pgp_dest_mem_param_t {
    unsigned maxalloc;
    unsigned allocated;
    void *   memory;
    bool     free;
} pgp_dest_mem_param_t;

static ssize_t
mem_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_mem_param_t *param = (pgp_source_mem_param_t *) src->param;

    if (param == NULL) {
        return -1;
    } else {
        if (len > param->len - param->pos) {
            len = param->len - param->pos;
        }

        memcpy(buf, (uint8_t *) param->memory + param->pos, len);
        param->pos += len;
        return len;
    }
}

static void
mem_src_close(pgp_source_t *src)
{
    pgp_source_mem_param_t *param = (pgp_source_mem_param_t *) src->param;
    if (param) {
        if (param->free) {
            free((void *) param->memory);
        }
        free(src->param);
        src->param = NULL;
    }
}

rnp_result_t
init_mem_src(pgp_source_t *src, const void *mem, size_t len, bool free)
{
    pgp_source_mem_param_t *param;

    /* this is actually double buffering, but then src_peek will fail */
    if (!init_src_common(src, sizeof(pgp_source_mem_param_t))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_mem_param_t *) src->param;
    param->memory = mem;
    param->len = len;
    param->pos = 0;
    param->free = free;
    src->read = mem_src_read;
    src->close = mem_src_close;
    src->finish = NULL;
    src->size = len;
    src->knownsize = 1;
    src->type = PGP_STREAM_MEMORY;

    return RNP_SUCCESS;
}

rnp_result_t
read_mem_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    pgp_dest_t   dst;
    rnp_result_t ret;
    uint8_t      buf[4096];
    ssize_t      read;

    if ((ret = init_mem_dest(&dst, NULL, 0))) {
        return ret;
    }

    while (!src_eof(readsrc)) {
        read = src_read(readsrc, buf, sizeof(buf));
        if (read < 0) {
            goto done;
        }
        if (read > 0) {
            dst_write(&dst, buf, read);
        }
    }

    if (dst.werr) {
        ret = dst.werr;
        goto done;
    }

    if ((ret = init_mem_src(src, mem_dest_own_memory(&dst), dst.writeb, true))) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    dst_close(&dst, true);
    return ret;
}

const void *
mem_src_get_memory(pgp_source_t *src)
{
    pgp_source_mem_param_t *param;

    if (src->type != PGP_STREAM_MEMORY) {
        RNP_LOG("wrong function call");
        return NULL;
    }

    if (!src->param) {
        return NULL;
    }

    param = (pgp_source_mem_param_t *) src->param;
    return param->memory;
}

bool
init_dst_common(pgp_dest_t *dst, size_t paramsize)
{
    memset(dst, 0, sizeof(*dst));

    if (paramsize > 0) {
        if ((dst->param = calloc(1, paramsize)) == NULL) {
            RNP_LOG("allocation failed");
            return false;
        }
    }

    dst->werr = RNP_SUCCESS;

    return true;
}

void
dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    /* we call write function only if all previous calls succeeded */
    if ((len > 0) && (dst->write) && (dst->werr == RNP_SUCCESS)) {
        /* if cache non-empty and len will overflow it then fill it and write out */
        if ((dst->clen > 0) && (dst->clen + len > sizeof(dst->cache))) {
            memcpy(dst->cache + dst->clen, buf, sizeof(dst->cache) - dst->clen);
            buf = (uint8_t *) buf + sizeof(dst->cache) - dst->clen;
            len -= sizeof(dst->cache) - dst->clen;
            dst->werr = dst->write(dst, dst->cache, sizeof(dst->cache));
            dst->writeb += sizeof(dst->cache);
            dst->clen = 0;
            if (dst->werr != RNP_SUCCESS) {
                return;
            }
        }

        /* here everything will fit into the cache or cache is empty */
        if (dst->no_cache || (len > sizeof(dst->cache))) {
            dst->werr = dst->write(dst, buf, len);
            dst->writeb += len;
        } else {
            memcpy(dst->cache + dst->clen, buf, len);
            dst->clen += len;
        }
    }
}

void
dst_printf(pgp_dest_t *dst, const char *format, ...)
{
    char    buf[1024];
    size_t  len;
    va_list ap;

    va_start(ap, format);
    len = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    if (len >= sizeof(buf)) {
        RNP_LOG("too long dst_printf");
        len = sizeof(buf) - 1;
    }
    dst_write(dst, buf, len);
}

void
dst_flush(pgp_dest_t *dst)
{
    if ((dst->clen > 0) && (dst->write) && (dst->werr == RNP_SUCCESS)) {
        dst->werr = dst->write(dst, dst->cache, dst->clen);
        dst->writeb += dst->clen;
        dst->clen = 0;
    }
}

rnp_result_t
dst_finish(pgp_dest_t *dst)
{
    rnp_result_t res = RNP_SUCCESS;

    if (!dst->finished) {
        /* flush write cache in the dst */
        dst_flush(dst);
        if (dst->finish) {
            res = dst->finish(dst);
        }
        dst->finished = true;
    }

    return res;
}

void
dst_close(pgp_dest_t *dst, bool discard)
{
    if (!discard && !dst->finished) {
        dst_finish(dst);
    }

    if (dst->close) {
        dst->close(dst, discard);
    }
}

typedef struct pgp_dest_file_param_t {
    int  fd;
    int  errcode;
    char path[PATH_MAX];
} pgp_dest_file_param_t;

static rnp_result_t
file_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    ssize_t                ret;
    pgp_dest_file_param_t *param = (pgp_dest_file_param_t *) dst->param;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* we assyme that blocking I/O is used so everything is written or error received */
    ret = write(param->fd, buf, len);
    if (ret < 0) {
        param->errcode = errno;
        RNP_LOG("write failed, error %d", param->errcode);
        return RNP_ERROR_WRITE;
    } else {
        param->errcode = 0;
        return RNP_SUCCESS;
    }
}

static void
file_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_file_param_t *param = (pgp_dest_file_param_t *) dst->param;

    if (!param) {
        return;
    }

    if (dst->type == PGP_STREAM_FILE) {
        close(param->fd);
        if (discard) {
            unlink(param->path);
        }
    }

    free(param);
    dst->param = NULL;
}

rnp_result_t
init_file_dest(pgp_dest_t *dst, const char *path, bool overwrite)
{
    int                    fd;
    int                    flags;
    struct stat            st;
    pgp_dest_file_param_t *param;

    if (strlen(path) > sizeof(param->path)) {
        RNP_LOG("path too long");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!overwrite && !stat(path, &st)) {
        RNP_LOG("file already exists: '%s'", path);
        return RNP_ERROR_WRITE;
    }

    flags = O_WRONLY | O_CREAT;
    flags |= overwrite ? O_TRUNC : O_EXCL;
#ifdef O_BINARY
    flags |= O_BINARY;
#endif
    fd = open(path, flags, 0600);
    if (fd < 0) {
        RNP_LOG("failed to create file '%s'", path);
        return RNP_ERROR_WRITE;
    }

    if (!init_dst_common(dst, sizeof(*param))) {
        close(fd);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_dest_file_param_t *) dst->param;
    param->fd = fd;
    strcpy(param->path, path);
    dst->write = file_dst_write;
    dst->close = file_dst_close;
    dst->type = PGP_STREAM_FILE;

    return RNP_SUCCESS;
}

rnp_result_t
init_stdout_dest(pgp_dest_t *dst)
{
    pgp_dest_file_param_t *param;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_dest_file_param_t *) dst->param;
    param->fd = STDOUT_FILENO;
    dst->write = file_dst_write;
    dst->close = file_dst_close;
    dst->type = PGP_STREAM_STDOUT;

    return RNP_SUCCESS;
}

static rnp_result_t
mem_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    size_t                alloc;
    void *                newalloc;
    pgp_dest_mem_param_t *param = (pgp_dest_mem_param_t *) dst->param;

    if (!param) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* checking whether we need to realloc */
    if (dst->writeb + len > param->allocated) {
        if ((param->maxalloc > 0) && (dst->writeb + len > param->maxalloc)) {
            RNP_LOG("attempt to alloc more then allowed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        /* round up to the page boundary and do it exponentially */
        alloc = ((dst->writeb + len) * 2 + 4095) / 4096 * 4096;
        if ((param->maxalloc > 0) && (alloc > param->maxalloc)) {
            alloc = param->maxalloc;
        }

        if ((newalloc = realloc(param->memory, alloc)) == NULL) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        param->memory = newalloc;
        param->allocated = alloc;
    }

    memcpy((uint8_t *) param->memory + dst->writeb, buf, len);

    return RNP_SUCCESS;
}

static void
mem_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_mem_param_t *param = (pgp_dest_mem_param_t *) dst->param;

    if (param) {
        if (param->free) {
            free(param->memory);
        }
        free(param);
        dst->param = NULL;
    }
}

rnp_result_t
init_mem_dest(pgp_dest_t *dst, void *mem, unsigned len)
{
    pgp_dest_mem_param_t *param;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_dest_mem_param_t *) dst->param;

    param->maxalloc = len;
    param->allocated = mem ? len : 0;
    param->memory = mem;
    param->free = !mem;

    dst->write = mem_dst_write;
    dst->close = mem_dst_close;
    dst->type = PGP_STREAM_MEMORY;
    dst->werr = RNP_SUCCESS;
    dst->no_cache = true;

    return RNP_SUCCESS;
}

void *
mem_dest_get_memory(pgp_dest_t *dst)
{
    if (dst->type != PGP_STREAM_MEMORY) {
        RNP_LOG("wrong function call");
        return NULL;
    }

    pgp_dest_mem_param_t *param = (pgp_dest_mem_param_t *) dst->param;

    if (param) {
        return param->memory;
    }

    return NULL;
}

void *
mem_dest_own_memory(pgp_dest_t *dst)
{
    if (dst->type != PGP_STREAM_MEMORY) {
        RNP_LOG("wrong function call");
        return NULL;
    }

    pgp_dest_mem_param_t *param = (pgp_dest_mem_param_t *) dst->param;

    if (!param) {
        RNP_LOG("null param");
        return NULL;
    }

    dst_finish(dst);

    if (param->free) {
        /* it may be larger then required */
        param->memory = realloc(param->memory, dst->writeb);
        param->allocated = dst->writeb;
        param->free = false;
        return param->memory;
    }

    /* in this case we should copy the memory */
    void *res = malloc(dst->writeb);
    if (res) {
        memcpy(res, param->memory, dst->writeb);
    }
    return res;
}

static rnp_result_t
null_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    return RNP_SUCCESS;
}

static void
null_dst_close(pgp_dest_t *dst, bool discard)
{
    ;
}

rnp_result_t
init_null_dest(pgp_dest_t *dst)
{
    dst->param = NULL;
    dst->write = null_dst_write;
    dst->close = null_dst_close;
    dst->type = PGP_STREAM_NULL;
    dst->writeb = 0;
    dst->clen = 0;
    dst->werr = RNP_SUCCESS;
    dst->no_cache = true;

    return RNP_SUCCESS;
}
