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
#ifndef EC_H_
#define EC_H_

#include <rnp/rnp_def.h>
#include <repgp/repgp_def.h>
#include "crypto/rng.h"
#include "crypto/mpi.h"

#define DEFAULT_CURVE PGP_CURVE_NIST_P_256
#define MAX_CURVE_BIT_SIZE 521 // secp521r1
/* Maximal byte size of elliptic curve order (NIST P-521) */
#define MAX_CURVE_BYTELEN ((MAX_CURVE_BIT_SIZE + 7) / 8)

/**
 * Maximal length of the OID in hex representation.
 *
 * \see RFC4880 bis01 - 9.2 ECC Curve OID
 */
#define MAX_CURVE_OID_HEX_LEN 10U

/**
 * Structure holds description of elliptic curve
 */
typedef struct ec_curve_desc_t {
    const pgp_curve_t rnp_curve_id;
    const size_t      bitlen;
    const uint8_t     OIDhex[MAX_CURVE_OID_HEX_LEN];
    const size_t      OIDhex_len;
    const char *      botan_name;
    const char *      pgp_name;
    /* Curve parameters below. Needed for grip calculation */
    const char *p;
    const char *a;
    const char *b;
    const char *n;
    const char *gx;
    const char *gy;
    const char *h;
} ec_curve_desc_t;

typedef struct pgp_ec_key_t {
    pgp_curve_t curve;
    pgp_mpi_t   p;
    /* secret mpi */
    pgp_mpi_t x;
    /* ecdh params */
    pgp_hash_alg_t kdf_hash_alg; /* Hash used by kdf */
    pgp_symm_alg_t key_wrap_alg; /* Symmetric algorithm used to wrap KEK*/
} pgp_ec_key_t;

typedef struct pgp_ec_signature_t {
    pgp_mpi_t r;
    pgp_mpi_t s;
} pgp_ec_signature_t;

/*
 * @brief   Finds curve ID by hex representation of OID
 *
 * @param   oid       buffer with OID in hex
 * @param   oid_len   length of oid buffer
 *
 * @returns success curve ID
 *          failure PGP_CURVE_MAX is returned
 *
 * @remarks see RFC 4880 bis 01 - 9.2 ECC Curve OID
 */
pgp_curve_t find_curve_by_OID(const uint8_t *oid, size_t oid_len);

pgp_curve_t find_curve_by_name(const char *name);

/*
 * @brief   Returns pointer to the curve descriptor
 *
 * @param   Valid curve ID
 *
 * @returns NULL if wrong ID provided, otherwise descriptor
 *
 */
const ec_curve_desc_t *get_curve_desc(const pgp_curve_t curve_id);

/*
 * @brief   Generates EC key in uncompressed format
 *
 * @param   rng initialized rng_t context*
 * @param   key key data to be generated
 * @param   alg_id ID of EC algorithm
 * @param   curve underlying ECC curve ID
 *
 * @pre     alg_id MUST be supported algorithm
 *
 * @returns RNP_ERROR_BAD_PARAMETERS unknown curve_id
 * @returns RNP_ERROR_OUT_OF_MEMORY memory allocation failed
 * @returns RNP_ERROR_KEY_GENERATION implementation error
 */
rnp_result_t ec_generate(rng_t *                rng,
                         pgp_ec_key_t *         key,
                         const pgp_pubkey_alg_t alg_id,
                         const pgp_curve_t      curve);

/*
 * @brief   Generates x25519 ECDH key in x25519-specific format
 *
 * @param   rng initialized rng_t context*
 * @param   key key data to be generated
 *
 * @returns RNP_ERROR_KEY_GENERATION implementation error
 */
rnp_result_t x25519_generate(rng_t *rng, pgp_ec_key_t *key);

#endif
