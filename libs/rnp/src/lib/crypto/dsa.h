/*
 * Copyright (c) 2017-2018, [Ribose Inc](https://www.ribose.com).
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

#ifndef RNP_DSA_H_
#define RNP_DSA_H_

#include <rnp/rnp_def.h>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include "crypto/mpi.h"

#define DSA_MIN_P_BITLEN 1024
#define DSA_MAX_P_BITLEN 3072
#define DSA_DEFAULT_P_BITLEN 2048

typedef struct pgp_dsa_key_t {
    pgp_mpi_t p;
    pgp_mpi_t q;
    pgp_mpi_t g;
    pgp_mpi_t y;
    /* secret mpi */
    pgp_mpi_t x;
} pgp_dsa_key_t;

typedef struct pgp_dsa_signature_t {
    pgp_mpi_t r;
    pgp_mpi_t s;
} pgp_dsa_signature_t;

/**
 * @brief Checks DSA key fields for validity
 *
 * @param rng initialized PRNG
 * @param key initialized DSA key structure
 * @param secret flag which tells whether key has populated secret fields
 *
 * @return RNP_SUCCESS if key is valid or error code otherwise
 */
rnp_result_t dsa_validate_key(rng_t *rng, const pgp_dsa_key_t *key, bool secret);

/*
 * @brief   Performs DSA signing
 *
 * @param   rng       initialized PRNG
 * @param   sig[out]  created signature
 * @param   hash      hash to sign
 * @param   hash_len  length of `hash`
 * @param   key       DSA key (must include secret mpi)
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_SIGNING_FAILED internal error
 */
rnp_result_t dsa_sign(rng_t *              rng,
                      pgp_dsa_signature_t *sig,
                      const uint8_t *      hash,
                      size_t               hash_len,
                      const pgp_dsa_key_t *key);

/*
 * @brief   Performs DSA verification
 *
 * @param   hash      hash to verify
 * @param   hash_len  length of `hash`
 * @param   sig       signature to be verified
 * @param   key       DSA key (secret mpi is not needed)
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_GENERIC internal error
 *          RNP_ERROR_SIGNATURE_INVALID signature is invalid
 */
rnp_result_t dsa_verify(const pgp_dsa_signature_t *sig,
                        const uint8_t *            hash,
                        size_t                     hash_len,
                        const pgp_dsa_key_t *      key);

/*
 * @brief   Performs DSA key generation
 *
 * @param   rng          initialized PRNG
 * @param   key[out]     generated key data will be stored here
 * @param   keylen       length of the key, in bits
 * @param   qbits        subgroup size in bits
 *
 * @returns RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input provided
 *          RNP_ERROR_OUT_OF_MEMORY memory allocation failed
 *          RNP_ERROR_GENERIC internal error
 *          RNP_ERROR_SIGNATURE_INVALID signature is invalid
 */
rnp_result_t dsa_generate(rng_t *rng, pgp_dsa_key_t *key, size_t keylen, size_t qbits);

/*
 * @brief   Returns minimally sized hash which will work
 *          with the DSA subgroup.
 *
 * @param   qsize subgroup order
 *
 * @returns  Either ID of the hash algorithm, or PGP_HASH_UNKNOWN
 *           if not found
 */
pgp_hash_alg_t dsa_get_min_hash(size_t qsize);

/*
 * @brief   Helps to determine subgroup size by size of p
 *          In order not to confuse users, we use less complicated
 *          approach than suggested by FIPS-186, which is:
 *            p=1024  => q=160
 *            p<2048  => q=224
 *            p<=3072 => q=256
 *          So we don't generate (2048, 224) pair
 *
 * @return  Size of `q' or 0 in case `psize' is not in <1024,3072> range
 */
size_t dsa_choose_qsize_by_psize(size_t psize);

#endif
