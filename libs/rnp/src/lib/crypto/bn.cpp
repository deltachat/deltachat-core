/*
 * Copyright (c) 2017-2018 Ribose Inc.
 * Copyright (c) 2012 Alistair Crooks <agc@NetBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "bn.h"
#include <botan/ffi.h>
#include <stdlib.h>
#include "utils.h"

/**************************************************************************/

/* essentiually, these are just wrappers around the botan functions */
/* usually the order of args changes */
/* the bignum_t API tends to have more const poisoning */
/* these wrappers also check the arguments passed for sanity */

bignum_t *
bn_bin2bn(const uint8_t *data, int len, bignum_t *ret)
{
    if (data == NULL) {
        return bn_new();
    }
    if (ret == NULL) {
        ret = bn_new();
    }

    if (ret == NULL) {
        return NULL;
    }

    return (botan_mp_from_bin(ret->mp, data, len) == 0) ? ret : NULL;
}

/* store in unsigned [big endian] format */
int
bn_bn2bin(const bignum_t *a, unsigned char *b)
{
    if (a == NULL || b == NULL) {
        return -1;
    }

    return botan_mp_to_bin(a->mp, b);
}

bignum_t *
bn_new(void)
{
    bignum_t *a;

    a = (bignum_t *) calloc(1, sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
    botan_mp_init(&a->mp);
    return a;
}

void
bn_free(bignum_t *a)
{
    if (a != NULL) {
        botan_mp_destroy(a->mp);
        free(a);
    }
}

bool
bn_num_bits(const bignum_t *a, size_t *bits)
{
    if (!a || botan_mp_num_bits(a->mp, bits)) {
        return false;
    }
    return true;
}

bool
bn_num_bytes(const bignum_t *a, size_t *bits)
{
    if (bn_num_bits(a, bits)) {
        *bits = BITS_TO_BYTES(*bits);
        return true;
    }
    return false;
}

int
bn_print_fp(FILE *fp, const bignum_t *a)
{
    int    ret;
    size_t num_bytes;
    char * buf;

    if (fp == NULL || a == NULL) {
        return 0;
    }
    if (botan_mp_num_bytes(a->mp, &num_bytes)) {
        return 0;
    }

    if (botan_mp_is_negative(a->mp)) {
        fprintf(fp, "-");
    }

    buf = (char *) calloc(num_bytes * 2 + 2, 1);
    botan_mp_to_hex(a->mp, buf);
    ret = fprintf(fp, "%s", buf);
    free(buf);
    return ret;
}
