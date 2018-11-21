/*-
 * Copyright (c) 2017 Ribose Inc.
 * All rights reserved.
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

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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

#include <stdio.h>
#include <rnp/rnp_sdk.h>
#include <botan/ffi.h>
#include "hash.h"
#include "types.h"
#include "utils.h"
#include "defaults.h"

static const struct hash_alg_map_t {
    pgp_hash_alg_t type;
    const char *   name;
    const char *   botan_name;
    size_t         digest_size;
} hash_alg_map[] = {{PGP_HASH_MD5, "MD5", "MD5", 16},
                    {PGP_HASH_SHA1, "SHA1", "SHA-1", 20},
                    {PGP_HASH_RIPEMD, "RIPEMD160", "RIPEMD-160", 20},
                    {PGP_HASH_SHA256, "SHA256", "SHA-256", 32},
                    {PGP_HASH_SHA384, "SHA384", "SHA-384", 48},
                    {PGP_HASH_SHA512, "SHA512", "SHA-512", 64},
                    {PGP_HASH_SHA224, "SHA224", "SHA-224", 28},
                    {PGP_HASH_SM3, "SM3", "SM3", 32},
                    {PGP_HASH_CRC24, "CRC24", "CRC24", 3},
                    {PGP_HASH_SHA3_256, "SHA3-256", "SHA-3(256)", 32},
                    {PGP_HASH_SHA3_512, "SHA3-512", "SHA-3(512)", 64}};
/**
 * \ingroup Core_Print
 *
 * returns description of the Hash Algorithm type
 * \param hash Hash Algorithm type
 * \return string or "Unknown"
 */
const char *
pgp_show_hash_alg(uint8_t hash)
{
    const char *ret = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, name, hash, ret);
    return ret;
}

const char *
pgp_hash_name_botan(pgp_hash_alg_t hash)
{
    const char *ret = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, botan_name, hash, ret);
    return ret;
}

const char *
pgp_hash_name(const pgp_hash_t *hash)
{
    return pgp_show_hash_alg(hash->_alg);
}

/**
\ingroup Core_Hashes
\brief Returns hash enum corresponding to given string
\param hash Text name of hash algorithm i.e. "SHA1"
\returns Corresponding enum i.e. PGP_HASH_SHA1
*/
pgp_hash_alg_t
pgp_str_to_hash_alg(const char *hash)
{
    if (hash == NULL) {
        return DEFAULT_PGP_HASH_ALG;
    }
    for (size_t i = 0; i < ARRAY_SIZE(hash_alg_map); i++) {
        if (!rnp_strcasecmp(hash, hash_alg_map[i].name)) {
            return hash_alg_map[i].type;
        }
    }
    return PGP_HASH_UNKNOWN;
}

/**
\ingroup Core_Hashes
\brief Setup hash for given hash algorithm
\param hash Hash to set up
\param alg Hash algorithm to use
*/
bool
pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg)
{
    const char * hash_name = pgp_hash_name_botan(alg);
    botan_hash_t impl;
    size_t       outlen;
    int          rc;

    if (hash_name == NULL) {
        return false;
    }

    rc = botan_hash_init(&impl, hash_name, 0);
    if (rc != 0) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }

    rc = botan_hash_output_length(impl, &outlen);
    if (rc != 0) {
        botan_hash_destroy(impl);
        RNP_LOG("In pgp_hash_create, botan_hash_output_length failed");
        return false;
    }

    hash->_output_len = outlen;
    hash->_alg = alg;
    hash->handle = impl;
    return true;
}

bool
pgp_hash_copy(pgp_hash_t *dst, const pgp_hash_t *src)
{
    if (!src || !dst) {
        return false;
    }

    botan_hash_t handle;
    if (botan_hash_copy_state(&handle, (botan_hash_t) src->handle)) {
        return false;
    }

    dst->_output_len = src->_output_len;
    dst->_alg = src->_alg;
    dst->handle = handle;
    return true;
}

/**
\ingroup Core_Hashes
\brief Add to the hash
\param hash Hash to add to
\param n Int to add
\param length Length of int in bytes
*/
void
pgp_hash_add_int(pgp_hash_t *hash, unsigned n, size_t length)
{
    uint8_t c;

    while (length--) {
        c = n >> (length * 8);
        pgp_hash_add(hash, &c, 1);
    }
}

int
pgp_hash_add(pgp_hash_t *hash, const void *buf, size_t len)
{
    return botan_hash_update((botan_hash_t) hash->handle, (const uint8_t *) buf, len);
}

size_t
pgp_hash_finish(pgp_hash_t *hash, uint8_t *out)
{
    size_t outlen = hash->_output_len;
    if (!hash || !hash->handle) {
        return 0;
    }

    if (out && botan_hash_final((botan_hash_t) hash->handle, out)) {
        RNP_LOG("Hash finalization failed");
        return 0;
    }
    botan_hash_destroy((botan_hash_t) hash->handle);
    hash->handle = NULL;
    hash->_output_len = 0;
    return outlen;
}

pgp_hash_alg_t
pgp_hash_alg_type(const pgp_hash_t *hash)
{
    return hash->_alg;
}

/**
\ingroup HighLevel_Supported
\brief Is this Hash Algorithm supported?
\param hash_alg Hash Algorithm to check
\return 1 if supported; else 0
*/
unsigned
pgp_is_hash_alg_supported(const pgp_hash_alg_t *hash_alg)
{
    return pgp_hash_name_botan(*hash_alg) != NULL;
}

size_t
pgp_digest_length(pgp_hash_alg_t alg)
{
    size_t val = 0;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, digest_size, alg, val);
    return val;
}

bool
pgp_hash_list_add(list *hashes, pgp_hash_alg_t alg)
{
    pgp_hash_t hash = {0};

    if (!pgp_hash_list_get(*hashes, alg)) {
        if (!pgp_hash_create(&hash, alg)) {
            RNP_LOG("failed to initialize hash algorithm %d", (int) alg);
            return false;
        } else if (!list_append(hashes, &hash, sizeof(hash))) {
            pgp_hash_finish(&hash, NULL);
            RNP_LOG("allocation failed");
            return false;
        }
    }

    return true;
}

const pgp_hash_t *
pgp_hash_list_get(list hashes, pgp_hash_alg_t alg)
{
    for (list_item *hash = list_front(hashes); hash; hash = list_next(hash)) {
        if (pgp_hash_alg_type((pgp_hash_t *) hash) == alg) {
            return (pgp_hash_t *) hash;
        }
    }

    return NULL;
}

void
pgp_hash_list_update(list hashes, const void *buf, size_t len)
{
    for (list_item *hash = list_front(hashes); hash; hash = list_next(hash)) {
        pgp_hash_add((pgp_hash_t *) hash, buf, len);
    }
}

void
pgp_hash_list_free(list *hashes)
{
    for (list_item *hash = list_front(*hashes); hash; hash = list_next(hash)) {
        pgp_hash_finish((pgp_hash_t *) hash, NULL);
    }
    list_destroy(hashes);
}

bool
pgp_hash_uint32(pgp_hash_t *hash, uint32_t n)
{
    uint8_t ibuf[4];
    STORE32BE(ibuf, n);
    return !pgp_hash_add(hash, ibuf, sizeof(ibuf));
}
