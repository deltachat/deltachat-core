/*-
 * Copyright (c) 2018 Ribose Inc.
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

#include <string.h>
#include <stdlib.h>
#include "mpi.h"
#include "memory.h"
#include "hash.h"

bool
to_buf(buf_t *b, const uint8_t *in, size_t len)
{
    if (b->len < len) {
        return false;
    }
    memcpy(b->pbuf, in, len);
    b->len = len;
    return true;
}

const buf_t
mpi2buf(pgp_mpi_t *val, bool uselen)
{
    return (buf_t){.pbuf = val->mpi, .len = uselen ? val->len : sizeof(val->mpi)};
}

bignum_t *
mpi2bn(const pgp_mpi_t *val)
{
    return bn_bin2bn(val->mpi, val->len, NULL);
}

bool
bn2mpi(bignum_t *bn, pgp_mpi_t *val)
{
    return bn_num_bytes(bn, &val->len) && (bn_bn2bin(bn, val->mpi) == 0);
}

size_t
mpi_bits(const pgp_mpi_t *val)
{
    size_t  bits = 0;
    size_t  idx = 0;
    uint8_t bt;

    for (idx = 0; (idx < val->len) && !val->mpi[idx]; idx++)
        ;

    if (idx < val->len) {
        for (bits = (val->len - idx - 1) << 3, bt = val->mpi[idx]; bt; bits++, bt = bt >> 1)
            ;
    }

    return bits;
}

size_t
mpi_bytes(const pgp_mpi_t *val)
{
    return val->len;
}

bool
mem2mpi(pgp_mpi_t *val, const void *mem, size_t len)
{
    if (len > sizeof(val->mpi)) {
        return false;
    }

    memcpy(val->mpi, mem, len);
    val->len = len;
    return true;
}

void
mpi2mem(const pgp_mpi_t *val, void *mem)
{
    memcpy(mem, val->mpi, val->len);
}

bool
hex2mpi(pgp_mpi_t *val, const char* hex)
   {
   const size_t hex_len = strlen(hex);
   size_t buf_len = hex_len / 2;
   bool ok;

   uint8_t* buf = NULL;

   buf = (uint8_t*)malloc(buf_len);

   if(buf == NULL) {
      return false;
   }

   rnp_hex_decode(hex, buf, buf_len);

   ok = mem2mpi(val, buf, buf_len);
   free(buf);
   return ok;
   }

char *
mpi2hex(const pgp_mpi_t *val)
{
    static const char *hexes = "0123456789abcdef";
    char *             out;
    size_t             len;
    size_t             idx = 0;

    len = mpi_bytes(val);
    out = (char *) malloc(len * 2 + 1);

    if (!out) {
        return out;
    }

    for (size_t i = 0; i < len; i++) {
        out[idx++] = hexes[val->mpi[i] >> 4];
        out[idx++] = hexes[val->mpi[i] & 0xf];
    }
    out[idx] = '\0';
    return out;
}

bool
mpi_equal(const pgp_mpi_t *val1, const pgp_mpi_t *val2)
{
    size_t idx1 = 0;
    size_t idx2 = 0;

    for (idx1 = 0; (idx1 < val1->len) && !val1->mpi[idx1]; idx1++)
        ;

    for (idx2 = 0; (idx2 < val2->len) && !val2->mpi[idx2]; idx2++)
        ;

    return ((val1->len - idx1) == (val2->len - idx2) &&
            !memcmp(val1->mpi + idx1, val2->mpi + idx2, val1->len - idx1));
}

/* hashes 32-bit length + mpi body (paddded with 0 if high order byte is >= 0x80) */
bool
mpi_hash(const pgp_mpi_t *val, pgp_hash_t *hash)
{
    size_t  len;
    size_t  idx;
    uint8_t padbyte = 0;
    bool    res = true;

    len = mpi_bytes(val);
    for (idx = 0; (idx < len) && (val->mpi[idx] == 0); idx++)
        ;

    if (idx >= len) {
        return pgp_hash_uint32(hash, 0);
    }

    res = pgp_hash_uint32(hash, len - idx);
    if (val->mpi[idx] & 0x80) {
        res &= pgp_hash_add(hash, &padbyte, 1);
    }
    res &= pgp_hash_add(hash, val->mpi + idx, len - idx);

    return res;
}

void
mpi_forget(pgp_mpi_t *val)
{
    pgp_forget(val, sizeof(*val));
    val->len = 0;
}
