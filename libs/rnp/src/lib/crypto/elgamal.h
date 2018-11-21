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

#ifndef RNP_ELG_H_
#define RNP_ELG_H_

#include <stdint.h>
#include "crypto/rng.h"
#include "crypto/mpi.h"

typedef struct pgp_eg_key_t {
    pgp_mpi_t p;
    pgp_mpi_t g;
    pgp_mpi_t y;
    /* secret mpi */
    pgp_mpi_t x;
} pgp_eg_key_t;

typedef struct pgp_eg_signature_t {
    /* This is kept only for packet reading. Implementation MUST
     * not create elgamal signatures */
    pgp_mpi_t r;
    pgp_mpi_t s;
} pgp_eg_signature_t;

typedef struct pgp_eg_encrypted_t {
    pgp_mpi_t g;
    pgp_mpi_t m;
} pgp_eg_encrypted_t;

rnp_result_t elgamal_validate_key(rng_t *rng, const pgp_eg_key_t *key, bool secret);

/*
 * Performs ElGamal encryption
 * Result of an encryption is composed of two parts - g2k and encm
 *
 * @param rng initialized rng_t
 * @param out encryption result
 * @param in plaintext to be encrypted
 * @param in_len length of the plaintext
 * @param key public key to be used for encryption
 *
 * @pre out: must be valid pointer to corresponding structure
 * @pre in_len: can't be bigger than byte size of `p'
 *
 * @return RNP_SUCCESS
 *         RNP_ERROR_OUT_OF_MEMORY  allocation failure
 *         RNP_ERROR_BAD_PARAMETERS wrong input provided
 */
rnp_result_t elgamal_encrypt_pkcs1(rng_t *             rng,
                                   pgp_eg_encrypted_t *out,
                                   const uint8_t *     in,
                                   size_t              in_len,
                                   const pgp_eg_key_t *key);

/*
 * Performs ElGamal decryption
 *
 * @param rng initialized rng_t
 * @param out decrypted plaintext. Must be capable of storing at least as much bytes as p size
 * @param out_len number of plaintext bytes written will be put here
 * @param in encrypted data
 * @param key private key
 *
 * @pre out, in: must be valid pointers
 * @pre out: length must be long enough to store decrypted data. Max size of
 *           decrypted data is equal to bytes size of `p'
 *
 * @return RNP_SUCCESS
 *         RNP_ERROR_OUT_OF_MEMORY  allocation failure
 *         RNP_ERROR_BAD_PARAMETERS wrong input provided
 */
rnp_result_t elgamal_decrypt_pkcs1(rng_t *                   rng,
                                   uint8_t *                 out,
                                   size_t *                  out_len,
                                   const pgp_eg_encrypted_t *in,
                                   const pgp_eg_key_t *      key);

/*
 * Generates ElGamal key
 *
 * @param rng pointer to PRNG
 * @param key generated key
 * @param keybits key bitlen
 *
 * @pre `keybits' > 1024
 *
 * @returns RNP_ERROR_BAD_PARAMETERS wrong parameters provided
 *          RNP_ERROR_GENERIC internal error
 *          RNP_SUCCESS key generated and coppied to `seckey'
 */
rnp_result_t elgamal_generate(rng_t *rng, pgp_eg_key_t *key, size_t keybits);
#endif
