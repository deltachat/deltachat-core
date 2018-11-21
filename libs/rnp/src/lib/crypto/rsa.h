/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_RSA_H_
#define RNP_RSA_H_

#include <rnp/rnp_def.h>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include "crypto/mpi.h"

typedef struct pgp_rsa_key_t {
    pgp_mpi_t n;
    pgp_mpi_t e;
    /* secret mpis */
    pgp_mpi_t d;
    pgp_mpi_t p;
    pgp_mpi_t q;
    pgp_mpi_t u;
} pgp_rsa_key_t;

typedef struct pgp_rsa_signature_t {
    pgp_mpi_t s;
} pgp_rsa_signature_t;

typedef struct pgp_rsa_encrypted_t {
    pgp_mpi_t m;
} pgp_rsa_encrypted_t;

/*
 * RSA encrypt/decrypt
 */

rnp_result_t rsa_validate_key(rng_t *rng, const pgp_rsa_key_t *key, bool secret);

rnp_result_t rsa_generate(rng_t *rng, pgp_rsa_key_t *key, size_t numbits);

rnp_result_t rsa_encrypt_pkcs1(rng_t *              rng,
                               pgp_rsa_encrypted_t *out,
                               const uint8_t *      in,
                               size_t               in_len,
                               const pgp_rsa_key_t *key);

rnp_result_t rsa_decrypt_pkcs1(rng_t *                    rng,
                               uint8_t *                  out,
                               size_t *                   out_len,
                               const pgp_rsa_encrypted_t *in,
                               const pgp_rsa_key_t *      key);

rnp_result_t rsa_verify_pkcs1(const pgp_rsa_signature_t *sig,
                              pgp_hash_alg_t             hash_alg,
                              const uint8_t *            hash,
                              size_t                     hash_len,
                              const pgp_rsa_key_t *      key);

rnp_result_t rsa_sign_pkcs1(rng_t *              rng,
                            pgp_rsa_signature_t *sig,
                            pgp_hash_alg_t       hash_alg,
                            const uint8_t *      hash,
                            size_t               hash_len,
                            const pgp_rsa_key_t *key);

#endif
