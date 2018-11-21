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

#ifndef ECDH_H_
#define ECDH_H_

#include "crypto/ec.h"

/* Max size of wrapped and obfuscated key size
 *
 * RNP pads a key with PKCS-5 always to 8 byte granularity,
 * then 8 bytes is added by AES-wrap (RFC3394).
 */
#define ECDH_WRAPPED_KEY_SIZE 48

/* Forward declarations */
typedef struct pgp_fingerprint_t pgp_fingerprint_t;

typedef struct pgp_ecdh_encrypted_t {
    pgp_mpi_t p;
    uint8_t   m[ECDH_WRAPPED_KEY_SIZE];
    size_t    mlen;
} pgp_ecdh_encrypted_t;

rnp_result_t ecdh_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret);

/*
 * @brief   Sets hash algorithm and key wrapping algo
 *          based on curve_id
 *
 * @param   key   ec key to set parameters for
 * @param   curve       underlying ECC curve ID
 *
 * @returns false if curve is not supported, otherwise true
 */
bool ecdh_set_params(pgp_ec_key_t *key, pgp_curve_t curve_id);

/*
 * Encrypts session key with a KEK agreed during ECDH as specified in
 * RFC 4880 bis 01, 13.5
 *
 * @param rng initialized rng_t object
 * @param session_key key to be encrypted
 * @param session_key_len length of the key buffer
 * @param wrapped_key [out] resulting key wrapped in by some AES
 *        as specified in RFC 3394
 * @param wrapped_key_len [out] length of the `wrapped_key' buffer
 *        Current implementation always produces 48 bytes as key
 *        is padded with PKCS-5/7
 * @param ephemeral_key [out] public ephemeral ECDH key used for key
 *        agreement (private part). Must be initialized
 * @param pubkey public key to be used for encryption
 * @param fingerprint fingerprint of the pubkey
 *
 * @return RNP_SUCCESS on success and output parameters are populated
 * @return RNP_ERROR_NOT_SUPPORTED unknown curve
 * @return RNP_ERROR_BAD_PARAMETERS unexpected input provided
 * @return RNP_ERROR_SHORT_BUFFER `wrapped_key_len' to small to store result
 * @return RNP_ERROR_GENERIC implementation error
 */
rnp_result_t ecdh_encrypt_pkcs5(rng_t *                  rng,
                                pgp_ecdh_encrypted_t *   out,
                                const uint8_t *const     in,
                                size_t                   in_len,
                                const pgp_ec_key_t *     key,
                                const pgp_fingerprint_t *fingerprint);

/*
 * Decrypts session key with a KEK agreed during ECDH as specified in
 * RFC 4880 bis 01, 13.5
 *
 * @param session_key [out] resulting session key
 * @param session_key_len [out] length of the resulting session key
 * @param wrapped_key session key wrapped with some AES as specified
 *        in RFC 3394
 * @param wrapped_key_len length of the `wrapped_key' buffer
 * @param ephemeral_key public ephemeral ECDH key comming from
 *        encrypted packet.
 * @param seckey secret key to be used for decryption
 * @param fingerprint fingerprint of the key
 *
 * @return RNP_SUCCESS on success and output parameters are populated
 * @return RNP_ERROR_NOT_SUPPORTED unknown curve
 * @return RNP_ERROR_BAD_PARAMETERS unexpected input provided
 * @return RNP_ERROR_SHORT_BUFFER `session_key_len' to small to store result
 * @return RNP_ERROR_GENERIC decryption failed or implementation error
 */
rnp_result_t ecdh_decrypt_pkcs5(uint8_t *                   out,
                                size_t *                    out_len,
                                const pgp_ecdh_encrypted_t *in,
                                const pgp_ec_key_t *        key,
                                const pgp_fingerprint_t *   fingerprint);

#endif // ECDH_H_
