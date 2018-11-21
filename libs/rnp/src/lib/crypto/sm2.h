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

#ifndef RNP_SM2_H_
#define RNP_SM2_H_

#include "ec.h"

typedef struct pgp_sm2_encrypted_t {
    pgp_mpi_t m;
} pgp_sm2_encrypted_t;

rnp_result_t sm2_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret);

/**
* Compute the SM2 "ZA" field, and add it to the hash object
*
* If ident_field is null, uses the default value
*/
rnp_result_t sm2_compute_za(const pgp_ec_key_t * key,
                            pgp_hash_t * hash,
                            const char* ident_field = NULL);

rnp_result_t sm2_sign(rng_t *             rng,
                      pgp_ec_signature_t *sig,
                      pgp_hash_alg_t      hash_alg,
                      const uint8_t *     hash,
                      size_t              hash_len,
                      const pgp_ec_key_t *key);

rnp_result_t sm2_verify(const pgp_ec_signature_t *sig,
                        pgp_hash_alg_t            hash_alg,
                        const uint8_t *           hash,
                        size_t                    hash_len,
                        const pgp_ec_key_t *      key);

rnp_result_t sm2_encrypt(rng_t *              rng,
                         pgp_sm2_encrypted_t *out,
                         const uint8_t *      in,
                         size_t               in_len,
                         pgp_hash_alg_t       hash_algo,
                         const pgp_ec_key_t * key);

rnp_result_t sm2_decrypt(uint8_t *                  out,
                         size_t *                   out_len,
                         const pgp_sm2_encrypted_t *in,
                         const pgp_ec_key_t *       key);

#endif // SM2_H_
