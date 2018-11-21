/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "ecdsa.h"
#include "utils.h"
#include <botan/ffi.h>
#include <string.h>

static bool
ecdsa_load_public_key(botan_pubkey_t *pubkey, const pgp_ec_key_t *keydata)
{
    botan_mp_t px = NULL;
    botan_mp_t py = NULL;
    bool       res = false;

    const ec_curve_desc_t *curve = get_curve_desc(keydata->curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }
    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);

    if (!mpi_bytes(&keydata->p) || (keydata->p.mpi[0] != 0x04)) {
        RNP_LOG("Failed to load public key");
        return false;
    }

    if (botan_mp_init(&px) || botan_mp_init(&py) ||
        botan_mp_from_bin(px, &keydata->p.mpi[1], curve_order) ||
        botan_mp_from_bin(py, &keydata->p.mpi[1 + curve_order], curve_order)) {
        goto end;
    }

    if (!(res = !botan_pubkey_load_ecdsa(pubkey, px, py, curve->botan_name))) {
        RNP_LOG("failed to load ecdsa public key");
    }
end:
    botan_mp_destroy(px);
    botan_mp_destroy(py);
    return res;
}

static bool
ecdsa_load_secret_key(botan_privkey_t *seckey, const pgp_ec_key_t *keydata)
{
    const ec_curve_desc_t *curve;
    bignum_t *             x = NULL;
    bool                   res = false;

    if (!(curve = get_curve_desc(keydata->curve))) {
        return false;
    }
    if (!(x = mpi2bn(&keydata->x))) {
        return false;
    }
    if (!(res = !botan_privkey_load_ecdsa(seckey, BN_HANDLE_PTR(x), curve->botan_name))) {
        RNP_LOG("Can't load private key");
    }
    bn_free(x);
    return res;
}

rnp_result_t
ecdsa_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_BAD_PARAMETERS;

    if (!ecdsa_load_public_key(&bpkey, key) ||
        botan_pubkey_check_key(bpkey, rng_handle(rng), 1)) {
        goto done;
    }
    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    if (!ecdsa_load_secret_key(&bskey, key) ||
        botan_privkey_check_key(bskey, rng_handle(rng), 1)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}

static const char *
ecdsa_padding_str_for(pgp_hash_alg_t hash_alg)
{
    switch (hash_alg) {
    case PGP_HASH_MD5:
        return "Raw(MD5)";
    case PGP_HASH_SHA1:
        return "Raw(SHA-1)";
    case PGP_HASH_RIPEMD:
        return "Raw(RIPEMD-160)";

    case PGP_HASH_SHA256:
        return "Raw(SHA-256)";
    case PGP_HASH_SHA384:
        return "Raw(SHA-384)";
    case PGP_HASH_SHA512:
        return "Raw(SHA-512)";
    case PGP_HASH_SHA224:
        return "Raw(SHA-224)";
    case PGP_HASH_SHA3_256:
        return "Raw(SHA3(256))";
    case PGP_HASH_SHA3_512:
        return "Raw(SHA3(512))";

    case PGP_HASH_SM3:
        return "Raw(SM3)";
    default:
        return "Raw";
    }
}

rnp_result_t
ecdsa_sign(rng_t *             rng,
           pgp_ec_signature_t *sig,
           pgp_hash_alg_t      hash_alg,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp_ec_key_t *key)
{
    botan_pk_op_sign_t     signer = NULL;
    botan_privkey_t        b_key = NULL;
    rnp_result_t           ret = RNP_ERROR_GENERIC;
    uint8_t                out_buf[2 * MAX_CURVE_BYTELEN] = {0};
    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    const char *           padding_str = ecdsa_padding_str_for(hash_alg);

    if (!curve) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);
    size_t       sig_len = 2 * curve_order;

    if (!ecdsa_load_secret_key(&b_key, key)) {
        RNP_LOG("Can't load private key");
        goto end;
    }

    if (botan_pk_op_sign_create(&signer, b_key, padding_str, 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(signer, hash, hash_len)) {
        goto end;
    }

    if (botan_pk_op_sign_finish(signer, rng_handle(rng), out_buf, &sig_len)) {
        RNP_LOG("Signing failed");
        goto end;
    }

    // Allocate memory and copy results
    if (mem2mpi(&sig->r, out_buf, curve_order) &&
        mem2mpi(&sig->s, out_buf + curve_order, curve_order)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_privkey_destroy(b_key);
    botan_pk_op_sign_destroy(signer);
    return ret;
}

rnp_result_t
ecdsa_verify(const pgp_ec_signature_t *sig,
             pgp_hash_alg_t            hash_alg,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp_ec_key_t *      key)
{
    botan_pubkey_t       pub = NULL;
    botan_pk_op_verify_t verifier = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;
    uint8_t              sign_buf[2 * MAX_CURVE_BYTELEN] = {0};
    size_t               r_blen, s_blen;
    const char *         padding_str = ecdsa_padding_str_for(hash_alg);

    const ec_curve_desc_t *curve = get_curve_desc(key->curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const size_t curve_order = BITS_TO_BYTES(curve->bitlen);

    if (!ecdsa_load_public_key(&pub, key)) {
        goto end;
    }

    if (botan_pk_op_verify_create(&verifier, pub, padding_str, 0)) {
        goto end;
    }

    if (botan_pk_op_verify_update(verifier, hash, hash_len)) {
        goto end;
    }

    r_blen = mpi_bytes(&sig->r);
    s_blen = mpi_bytes(&sig->s);
    if ((r_blen > curve_order) || (s_blen > curve_order) ||
        (curve_order > MAX_CURVE_BYTELEN)) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    // Both can't fail
    mpi2mem(&sig->r, &sign_buf[curve_order - r_blen]);
    mpi2mem(&sig->s, &sign_buf[curve_order + curve_order - s_blen]);

    if (!botan_pk_op_verify_finish(verifier, sign_buf, curve_order * 2)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_pubkey_destroy(pub);
    botan_pk_op_verify_destroy(verifier);
    return ret;
}

pgp_hash_alg_t
ecdsa_get_min_hash(pgp_curve_t curve)
{
    switch (curve) {
    case PGP_CURVE_NIST_P_256:
    case PGP_CURVE_BP256:
    case PGP_CURVE_P256K1:
        return PGP_HASH_SHA256;
    case PGP_CURVE_NIST_P_384:
    case PGP_CURVE_BP384:
        return PGP_HASH_SHA384;
    case PGP_CURVE_NIST_P_521:
    case PGP_CURVE_BP512:
        return PGP_HASH_SHA512;
    default:
        return PGP_HASH_UNKNOWN;
    }
}
