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

#ifndef CRYPTO_HASH_H_
#define CRYPTO_HASH_H_

#include <rnp/rnp_sdk.h>
#include <repgp/repgp_def.h>
#include "types.h"
#include "list.h"

/**
 * Output size (in bytes) of biggest supported hash algo
 */
#define PGP_MAX_HASH_SIZE (64)

/** pgp_hash_t */
typedef struct pgp_hash_t {
    void *         handle; /* hash object */
    size_t         _output_len;
    pgp_hash_alg_t _alg; /* algorithm */
} pgp_hash_t;

const char *pgp_hash_name_botan(const pgp_hash_alg_t alg);

bool pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg);
bool pgp_hash_copy(pgp_hash_t *dst, const pgp_hash_t *src);
void pgp_hash_add_int(pgp_hash_t *hash, unsigned n, size_t bytes);
int pgp_hash_add(pgp_hash_t *hash, const void *buf, size_t len);
size_t pgp_hash_finish(pgp_hash_t *hash, uint8_t *output);

const char *pgp_hash_name(const pgp_hash_t *hash);

pgp_hash_alg_t pgp_hash_alg_type(const pgp_hash_t *hash);

pgp_hash_alg_t pgp_str_to_hash_alg(const char *);

unsigned pgp_is_hash_alg_supported(const pgp_hash_alg_t *);

const char *pgp_show_hash_alg(uint8_t);

/* @brief   Returns output size of an digest algorithm
 *
 * @param   hash alg
 *
 * @return  size of the digest produced by the algorithm or 0
 *          is not known
 **/
size_t pgp_digest_length(pgp_hash_alg_t alg);

/*
 * @brief Add hash for the corresponding algorithm to the list
 *
 * @param hashes non-NULL pointer to the list structure
 * @param alg hash algorithm
 *
 * @return true if hash was added successfully or already exists in the list.
 *         false will be returned if memory allocation failed, or alg is not supported, or
 *         on other error
 **/
bool pgp_hash_list_add(list *hashes, pgp_hash_alg_t alg);

/* @brief Get hash structure for the corresponding algorithm
 *
 * @param hashes List of pgp_hash_t structures
 * @param alg Hash algorithm
 *
 * @return pointer to the pgp_hash_t structure or NULL if list doesn't contain alg
 **/
const pgp_hash_t *pgp_hash_list_get(list hashes, pgp_hash_alg_t alg);

/*
 * @brief Update list of hashes with the data
 *
 * @param hashes List of pgp_hash_t structures
 * @param buf buffer with data
 * @param len number of bytes in the buffer
 **/
void pgp_hash_list_update(list hashes, const void *buf, size_t len);

/* @brief Free the list of hashes and deallocate all internal structures
 *
 * @param hashes List of pgp_hash_t structures
 **/
void pgp_hash_list_free(list *hashes);

/*
 * @brief Hashes 4 bytes stored as big endian
 *
 * @param hash Initialized hash ctx
 * @param val value to hash
 *
 * @returns true if operation succeeded, otherwise false
 */
bool pgp_hash_uint32(pgp_hash_t *hash, uint32_t val);

#endif
