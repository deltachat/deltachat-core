/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#ifndef RNPSDK_H_
#define RNPSDK_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#include <rnp/rnp_def.h>

#ifndef PRINTFLIKE
#define PRINTFLIKE(n, m) __attribute__((format(printf, n, m)))
#endif

typedef enum { RNP_HEX_LOWERCASE, RNP_HEX_UPPERCASE } rnp_hex_format_t;

const char *rnp_get_info(const char *type);

void rnp_log(const char *, ...) PRINTFLIKE(1, 2);

int rnp_strcasecmp(const char *, const char *);

char *rnp_strhexdump(char *dest, const uint8_t *src, size_t length, const char *sep);

char *rnp_strhexdump_upper(char *dest, const uint8_t *src, size_t length, const char *sep);

int64_t rnp_filemtime(const char *path);

const char *rnp_filename(const char *path);

char *rnp_compose_path(const char *first, ...);
char *rnp_compose_path_ex(char **buf, size_t *buf_len, const char *first, ...);

bool rnp_path_exists(const char *path);
bool rnp_dir_exists(const char *path);
bool rnp_file_exists(const char *path);

/** @brief strip extension from the path
 *  @param path NULL-terminated file path
 *  @return true if extension was located (via .) and stripped out, or false otherwise
 */
bool rnp_path_strip_ext(char *path);

/** @brief check whether given path has given extension
 *  @param path NULL-terminated file path
 *  @param ext NULL-terminated extension, with or without the leading dot
 *  @return true if path has given extension or false otherwise
 */
bool rnp_path_has_ext(const char *path, const char *ext);

/** @brief append given extension to the path
 *  @param path NULL-terminated file path
 *  @param len maximum number of bytes which may be stored in path
 *  @param ext NULL-terminated extension, with or without the leading dot
 *  @return true if extension was added successfully or false if there is no room in path
 */
bool rnp_path_add_ext(char *path, size_t len, const char *ext);

bool rnp_hex_encode(
  const uint8_t *buf, size_t buf_len, char *hex, size_t hex_len, rnp_hex_format_t format);
size_t rnp_hex_decode(const char *hex, uint8_t *buf, size_t buf_len);

char *rnp_strlwr(char *s);

/** @brief strip eol symbols (\r, \n) from the end of the string
 *  @param s NULL-terminated string, which will be modified
 *  @return string s itself
 */
char *rnp_strip_eol(char *s);

char *userid_to_id(const uint8_t *userid, char *id);

bool ishex(const char *hexid, size_t hexlen);

bool hex2bin(const char *hex, size_t hexlen, uint8_t *bin, size_t len, size_t *out);
}

#endif
