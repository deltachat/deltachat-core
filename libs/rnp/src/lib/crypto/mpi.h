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

#ifndef RNP_MPI_H_
#define RNP_MPI_H_

#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "bn.h"

/* 16384 bits should be pretty enough for now */
#define PGP_MPINT_BITS (16384)
#define PGP_MPINT_SIZE (PGP_MPINT_BITS >> 3)

typedef struct pgp_hash_t pgp_hash_t;

/** multi-precision integer, used in signatures and public/secret keys */
typedef struct pgp_mpi_t {
    uint8_t mpi[PGP_MPINT_SIZE];
    size_t  len;
} pgp_mpi_t;

/*
 * Data structure for storing pointer to the buffer together with
 * it's length. Value of 'len' depends on context in which it is used.
 */
typedef struct buf_t {
    uint8_t *pbuf;
    size_t   len;
} buf_t;

bool to_buf(buf_t *b, const uint8_t *in, size_t len);

const buf_t mpi2buf(pgp_mpi_t *val, bool uselen);

bignum_t *mpi2bn(const pgp_mpi_t *val);

bool bn2mpi(bignum_t *bn, pgp_mpi_t *val);

bool mem2mpi(pgp_mpi_t *val, const void *mem, size_t len);

bool hex2mpi(pgp_mpi_t *val, const char* hex);

void mpi2mem(const pgp_mpi_t *val, void *mem);

char *mpi2hex(const pgp_mpi_t *val);

size_t mpi_bits(const pgp_mpi_t *val);

size_t mpi_bytes(const pgp_mpi_t *val);

bool mpi_hash(const pgp_mpi_t *val, pgp_hash_t *hash);

bool mpi_equal(const pgp_mpi_t *val1, const pgp_mpi_t *val2);

void mpi_forget(pgp_mpi_t *val);

#endif // MPI_H_
