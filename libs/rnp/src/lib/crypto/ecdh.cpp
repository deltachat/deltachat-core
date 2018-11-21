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

#include <string.h>
#include <botan/ffi.h>
#include "ecdh.h"
#include "hash.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"

#define MAX_SP800_56A_OTHER_INFO 56
// Keys up to 312 bits (+1 bytes of PKCS5 padding)
#define MAX_SESSION_KEY_SIZE 40

/* Used by ECDH keys. Specifies which hash and wrapping algorithm
 * to be used (see point 15. of RFC 4880).
 *
 * Note: sync with ec_curves.
 */
static const struct ecdh_params_t {
    pgp_curve_t    curve;    /* Curve ID */
    pgp_hash_alg_t hash;     /* Hash used by kdf */
    pgp_symm_alg_t wrap_alg; /* Symmetric algorithm used to wrap KEK*/
} ecdh_params[] = {
  {.curve = PGP_CURVE_NIST_P_256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_NIST_P_384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_NIST_P_521, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_BP256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_BP384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_BP512, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_25519, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_P256K1, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
};

// "Anonymous Sender " in hex
static const unsigned char ANONYMOUS_SENDER[] = {0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F,
                                                 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64,
                                                 0x65, 0x72, 0x20, 0x20, 0x20, 0x20};

// returns size of data written to other_info
static size_t
kdf_other_info_serialize(uint8_t                  other_info[MAX_SP800_56A_OTHER_INFO],
                         const ec_curve_desc_t *  ec_curve,
                         const pgp_fingerprint_t *fingerprint,
                         const pgp_hash_alg_t     kdf_hash,
                         const pgp_symm_alg_t     wrap_alg)
{
    if (fingerprint->length < 20) {
        RNP_LOG("Implementation error: unexpected fingerprint length");
        return false;
    }

    uint8_t *buf_ptr = &other_info[0];

    /* KDF-OtherInfo: AlgorithmID
     *   Current implementation will alwyas use SHA-512 and AES-256 for KEK wrapping
     */
    *(buf_ptr++) = ec_curve->OIDhex_len;
    memcpy(buf_ptr, ec_curve->OIDhex, ec_curve->OIDhex_len);
    buf_ptr += ec_curve->OIDhex_len;
    *(buf_ptr++) = PGP_PKA_ECDH;
    // size of following 3 params (each 1 byte)
    *(buf_ptr++) = 0x03;
    // Value reserved for future use
    *(buf_ptr++) = 0x01;
    // Hash used with KDF
    *(buf_ptr++) = kdf_hash;
    // Algorithm ID used for key wrapping
    *(buf_ptr++) = wrap_alg;

    /* KDF-OtherInfo: PartyUInfo
     *   20 bytes representing "Anonymous Sender "
     */
    memcpy(buf_ptr, ANONYMOUS_SENDER, sizeof(ANONYMOUS_SENDER));

    buf_ptr += sizeof(ANONYMOUS_SENDER);

    // keep 20, as per spec
    memcpy(buf_ptr, fingerprint->fingerprint, 20);
    return (buf_ptr - other_info) + 20 /*anonymous_sender*/;
}

static bool
pad_pkcs7(uint8_t *buf, size_t buf_len, size_t offset)
{
    if (buf_len <= offset) {
        // Must have at least 1 byte of padding
        return false;
    }

    const uint8_t pad_byte = buf_len - offset;
    memset(buf + offset, pad_byte, pad_byte);
    return true;
}

static bool
unpad_pkcs7(uint8_t *buf, size_t buf_len, size_t *offset)
{
    if (!buf || !offset || !buf_len) {
        return false;
    }

    uint8_t        err = 0;
    const uint8_t  pad_byte = buf[buf_len - 1];
    const uint32_t pad_begin = buf_len - pad_byte;

    // TODO: Still >, <, and <=,==  are not constant time (maybe?)
    err |= (pad_byte > buf_len);
    err |= (pad_byte == 0);

    /* Check if padding is OK */
    for (size_t c = 0; c < buf_len; c++) {
        err |= (buf[c] ^ pad_byte) * (pad_begin <= c);
    }

    *offset = pad_begin;
    return (err == 0);
}

// Produces kek of size kek_len which corresponds to length of wrapping key
static bool
compute_kek(uint8_t *              kek,
            size_t                 kek_len,
            const uint8_t *        other_info,
            size_t                 other_info_size,
            const ec_curve_desc_t *curve_desc,
            const pgp_mpi_t *      ec_pubkey,
            const botan_privkey_t  ec_prvkey,
            const pgp_hash_alg_t   hash_alg)
{
    botan_pk_op_ka_t op_key_agreement = NULL;
    bool             ret = false;
    char             kdf_name[32] = {0};
    uint8_t          s[MAX_CURVE_BYTELEN * 2 + 1] = {0};
    size_t           s_len = sizeof(s);
    const uint8_t *  p = ec_pubkey->mpi;
    uint8_t          p_len = ec_pubkey->len;

    if (curve_desc->rnp_curve_id == PGP_CURVE_25519) {
        if ((p_len != 33) || (p[0] != 0x40)) {
            goto end;
        }
        p++;
        p_len--;
    }

    if (botan_pk_op_key_agreement_create(&op_key_agreement, ec_prvkey, "Raw", 0) ||
        botan_pk_op_key_agreement(op_key_agreement, s, &s_len, p, p_len, NULL, 0)) {
        goto end;
    }

    snprintf(kdf_name, sizeof(kdf_name), "SP800-56A(%s)", pgp_hash_name_botan(hash_alg));
    ret = !botan_kdf(kdf_name, kek, kek_len, s, s_len, NULL, 0, other_info, other_info_size);
end:
    pgp_forget(&s, sizeof(s));
    ret &= !botan_pk_op_key_agreement_destroy(op_key_agreement);
    return ret;
}

bool
ecdh_set_params(pgp_ec_key_t *key, pgp_curve_t curve_id)
{
    for (size_t i = 0; i < ARRAY_SIZE(ecdh_params); i++) {
        if (ecdh_params[i].curve == curve_id) {
            key->kdf_hash_alg = ecdh_params[i].hash;
            key->key_wrap_alg = ecdh_params[i].wrap_alg;
            return true;
        }
    }

    return false;
}

rnp_result_t
ecdh_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        return RNP_ERROR_NOT_SUPPORTED;
    }

    /* botan doesn't seem to have specific checks for ecdh keys yet, probably needs updating */
    return RNP_SUCCESS;
}

rnp_result_t
ecdh_encrypt_pkcs5(rng_t *                  rng,
                   pgp_ecdh_encrypted_t *   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp_ec_key_t *     key,
                   const pgp_fingerprint_t *fingerprint)
{
    botan_privkey_t eph_prv_key = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    uint8_t         kek[32] = {0}; // Size of SHA-256 or smaller
    // 'm' is padded to the 8-byte granularity
    uint8_t      m[MAX_SESSION_KEY_SIZE];
    const size_t m_padded_len = ((in_len / 8) + 1) * 8;

    if (!key || !fingerprint || !out || !in || (in_len > sizeof(m))) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unsupported curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // +8 because of AES-wrap adds 8 bytes
    if (ECDH_WRAPPED_KEY_SIZE < (m_padded_len + 8)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t kek_len = pgp_key_size(key->key_wrap_alg);
    size_t       tmp_len = kdf_other_info_serialize(
      other_info, curve_desc, fingerprint, key->kdf_hash_alg, key->key_wrap_alg);

    if (tmp_len != other_info_size) {
        RNP_LOG("Serialization of other info failed");
        return RNP_ERROR_GENERIC;
    }

    if (botan_privkey_create_ecdh(&eph_prv_key, rng_handle(rng), curve_desc->botan_name)) {
        goto end;
    }

    if (!compute_kek(kek,
                     kek_len,
                     other_info,
                     other_info_size,
                     curve_desc,
                     &key->p,
                     eph_prv_key,
                     key->kdf_hash_alg)) {
        RNP_LOG("KEK computation failed");
        goto end;
    }

    memcpy(m, in, in_len);
    if (!pad_pkcs7(m, m_padded_len, in_len)) {
        // Should never happen
        goto end;
    }

    out->mlen = sizeof(out->m);
    if (botan_key_wrap3394(m, m_padded_len, kek, kek_len, out->m, &out->mlen)) {
        goto end;
    }

    /* we need to prepend 0x40 for the x25519 */
    if (key->curve == PGP_CURVE_25519) {
        out->p.len = sizeof(out->p.mpi) - 1;
        if (botan_pk_op_key_agreement_export_public(
              eph_prv_key, out->p.mpi + 1, &out->p.len)) {
            goto end;
        }
        out->p.mpi[0] = 0x40;
        out->p.len++;
    } else {
        out->p.len = sizeof(out->p.mpi);
        if (botan_pk_op_key_agreement_export_public(eph_prv_key, out->p.mpi, &out->p.len)) {
            goto end;
        }
    }

    // All OK
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(eph_prv_key);
    return ret;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t *in,
                   const pgp_ec_key_t *        key,
                   const pgp_fingerprint_t *   fingerprint)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    // Size of SHA-256 or smaller
    uint8_t         kek[MAX_SYMM_KEY_SIZE];
    uint8_t         other_info[MAX_SP800_56A_OTHER_INFO];
    botan_privkey_t prv_key = NULL;
    uint8_t         deckey[MAX_SESSION_KEY_SIZE] = {0};
    size_t          deckey_len = sizeof(deckey);
    size_t          offset = 0;
    size_t          kek_len = 0;
    int             loadres = 0;

    if (!out_len || !in || !key || !mpi_bytes(&key->x)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const ec_curve_desc_t *curve_desc = get_curve_desc(key->curve);
    if (!curve_desc) {
        RNP_LOG("unknown curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    const pgp_symm_alg_t wrap_alg = key->key_wrap_alg;
    const pgp_hash_alg_t kdf_hash = key->kdf_hash_alg;
    /* Ensure that AES is used for wrapping */
    if ((wrap_alg != PGP_SA_AES_128) && (wrap_alg != PGP_SA_AES_192) &&
        (wrap_alg != PGP_SA_AES_256)) {
        RNP_LOG("non-aes wrap algorithm");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // See 13.5 of RFC 4880 for definition of other_info_size
    const size_t other_info_size = curve_desc->OIDhex_len + 46;
    const size_t tmp_len =
      kdf_other_info_serialize(other_info, curve_desc, fingerprint, kdf_hash, wrap_alg);

    if (other_info_size != tmp_len) {
        RNP_LOG("Serialization of other info failed");
        goto end;
    }

    if (key->curve == PGP_CURVE_25519) {
        uint8_t prkey[32] = {};
        if (key->x.len != 32) {
            RNP_LOG("wrong x25519 key");
            goto end;
        }
        /* need to reverse byte order since in mpi we have big-endian */
        for (int i = 0; i < 32; i++) {
            prkey[i] = key->x.mpi[31 - i];
        }
        loadres = botan_privkey_load_x25519(&prv_key, prkey);
        pgp_forget(prkey, sizeof(prkey));
    } else {
        bignum_t *x = NULL;
        if (!(x = mpi2bn(&key->x))) {
            goto end;
        }
        loadres = botan_privkey_load_ecdh(&prv_key, BN_HANDLE_PTR(x), curve_desc->botan_name);
        bn_free(x);
    }
    if (loadres) {
        goto end;
    }

    /* Security: Always return same error code in case compute_kek,
     *           botan_key_unwrap3394 or unpad_pkcs7 fails
     */
    kek_len = pgp_key_size(wrap_alg);
    if (!compute_kek(
          kek, kek_len, other_info, other_info_size, curve_desc, &in->p, prv_key, kdf_hash)) {
        goto end;
    }

    if (botan_key_unwrap3394(in->m, in->mlen, kek, kek_len, deckey, &deckey_len)) {
        goto end;
    }

    if (!unpad_pkcs7(deckey, deckey_len, &offset)) {
        goto end;
    }

    if (*out_len < offset) {
        ret = RNP_ERROR_SHORT_BUFFER;
        goto end;
    }

    *out_len = offset;
    memcpy(out, deckey, *out_len);
    pgp_forget(deckey, sizeof(deckey));
    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(prv_key);
    return ret;
}
