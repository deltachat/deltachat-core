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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>

#include <rnp/rnp_sdk.h>
#include <botan/ffi.h>

#include <librepgp/stream-packet.h>
#include "key_store_pgp.h"
#include "key_store_g10.h"

#include "crypto/common.h"
#include "pgp-key.h"
#include "utils.h"

#define G10_CBC_IV_SIZE 16

#define G10_OCB_NONCE_SIZE 12

#define G10_SHA1_HASH_SIZE 20

#define G10_PROTECTED_AT_SIZE 15

typedef struct {
    size_t   len;
    uint8_t *bytes;
} s_exp_block_t;

typedef struct sub_element_t sub_element_t;

typedef struct {
    list sub_elements; // list of sub_element_t
} s_exp_t;

struct sub_element_t {
    bool is_block;
    union {
        s_exp_t       s_exp;
        s_exp_block_t block;
    };
};

typedef struct format_info {
    pgp_symm_alg_t    cipher;
    pgp_cipher_mode_t cipher_mode;
    pgp_hash_alg_t    hash_alg;
    const char *      botan_cipher_name;
    size_t            chiper_block_size;
    const char *      g10_type;
    size_t            iv_size;
} format_info;

static bool    g10_calculated_hash(const pgp_key_pkt_t *key,
                                   const char *         protected_at,
                                   uint8_t *            checksum);
pgp_key_pkt_t *g10_decrypt_seckey(const uint8_t *      data,
                                  size_t               data_len,
                                  const pgp_key_pkt_t *pubkey,
                                  const char *         password);

static const format_info formats[] = {{PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-128/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_256,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-256/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes256-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_OCB,
                                       PGP_HASH_SHA1,
                                       "AES-128/OCB/NoPadding",
                                       16,
                                       "openpgp-s2k3-ocb-aes",
                                       G10_OCB_NONCE_SIZE}};

static const pgp_map_t g10_alg_aliases[] = {{PGP_PKA_RSA, "rsa"},
                                            {PGP_PKA_RSA, "openpgp-rsa"},
                                            {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
                                            {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
                                            {PGP_PKA_ELGAMAL, "elg"},
                                            {PGP_PKA_ELGAMAL, "elgamal"},
                                            {PGP_PKA_ELGAMAL, "openpgp-elg"},
                                            {PGP_PKA_ELGAMAL, "openpgp-elg-sig"},
                                            {PGP_PKA_DSA, "dsa"},
                                            {PGP_PKA_DSA, "openpgp-dsa"},
                                            {PGP_PKA_ECDSA, "ecc"},
                                            {PGP_PKA_ECDSA, "ecdsa"},
                                            {PGP_PKA_ECDH, "ecdh"},
                                            {PGP_PKA_EDDSA, "eddsa"}};

static const pgp_map_t g10_curve_aliases[] = {
  {PGP_CURVE_NIST_P_256, "NIST P-256"},   {PGP_CURVE_NIST_P_256, "1.2.840.10045.3.1.7"},
  {PGP_CURVE_NIST_P_256, "prime256v1"},   {PGP_CURVE_NIST_P_256, "secp256r1"},
  {PGP_CURVE_NIST_P_256, "nistp256"},

  {PGP_CURVE_NIST_P_384, "NIST P-384"},   {PGP_CURVE_NIST_P_384, "secp384r1"},
  {PGP_CURVE_NIST_P_384, "1.3.132.0.34"}, {PGP_CURVE_NIST_P_384, "nistp384"},

  {PGP_CURVE_NIST_P_521, "NIST P-521"},   {PGP_CURVE_NIST_P_521, "secp521r1"},
  {PGP_CURVE_NIST_P_521, "1.3.132.0.35"}, {PGP_CURVE_NIST_P_521, "nistp521"},

  {PGP_CURVE_25519, "Curve25519"},        {PGP_CURVE_25519, "1.3.6.1.4.1.3029.1.5.1"},
  {PGP_CURVE_ED25519, "Ed25519"},         {PGP_CURVE_ED25519, "1.3.6.1.4.1.11591.15.1"},

  {PGP_CURVE_BP256, "brainpoolP256r1"},   {PGP_CURVE_BP256, "1.3.36.3.3.2.8.1.1.7"},
  {PGP_CURVE_BP384, "brainpoolP384r1"},   {PGP_CURVE_BP384, "1.3.36.3.3.2.8.1.1.11"},
  {PGP_CURVE_BP512, "brainpoolP512r1"},   {PGP_CURVE_BP512, "1.3.36.3.3.2.8.1.1.13"},
  {PGP_CURVE_P256K1, "secp256k1"},        {PGP_CURVE_P256K1, "1.3.132.0.10"}};

static const pgp_map_t g10_curve_names[] = {{PGP_CURVE_NIST_P_256, "NIST P-256"},
                                            {PGP_CURVE_NIST_P_384, "NIST P-384"},
                                            {PGP_CURVE_NIST_P_521, "NIST P-521"},
                                            {PGP_CURVE_ED25519, "Ed25519"},
                                            {PGP_CURVE_25519, "Curve25519"},
                                            {PGP_CURVE_BP256, "brainpoolP256r1"},
                                            {PGP_CURVE_BP384, "brainpoolP384r1"},
                                            {PGP_CURVE_BP512, "brainpoolP512r1"},
                                            {PGP_CURVE_P256K1, "secp256k1"}};

static const format_info *
find_format(pgp_symm_alg_t cipher, pgp_cipher_mode_t mode, pgp_hash_alg_t hash_alg)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (formats[i].cipher == cipher && formats[i].cipher_mode == mode &&
            formats[i].hash_alg == hash_alg) {
            return &formats[i];
        }
    }
    return NULL;
}

static const format_info *
parse_format(const char *format, size_t format_len)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (strlen(formats[i].g10_type) == format_len &&
            !strncmp(formats[i].g10_type, format, format_len)) {
            return &formats[i];
        }
    }
    return NULL;
}

static void
destroy_s_exp(s_exp_t *s_exp)
{
    if (s_exp == NULL) {
        return;
    }

    for (list_item *li = list_front(s_exp->sub_elements); li; li = list_next(li)) {
        sub_element_t *sub_el = (sub_element_t *) li;
        if (sub_el->is_block) {
            free(sub_el->block.bytes);
            sub_el->block.bytes = NULL;
            sub_el->block.len = 0;
        } else {
            destroy_s_exp(&sub_el->s_exp);
        }
    }
    list_destroy(&s_exp->sub_elements);
}

static bool
add_block_to_sexp(s_exp_t *s_exp, const uint8_t *bytes, size_t len)
{
    sub_element_t *sub_el = NULL;

    for (list_item *li = list_front(s_exp->sub_elements); li; li = list_next(li)) {
        sub_el = (sub_element_t *) li;
        if (sub_el->is_block) {
            continue;
        }

        if (len == sub_el->block.len && !memcmp(sub_el->block.bytes, bytes, len)) {
            // do not duplicate blocks
            return true;
        }
    }

    sub_el = (sub_element_t *) list_append(&s_exp->sub_elements, NULL, sizeof(*sub_el));
    if (!sub_el) {
        RNP_LOG("alloc failed");
        return false;
    }

    sub_el->is_block = true;
    sub_el->block.len = len;
    sub_el->block.bytes = (uint8_t *) malloc(len);
    if (sub_el->block.bytes == NULL) {
        RNP_LOG("can't allocate block memory");
        return false;
    }

    memcpy(sub_el->block.bytes, bytes, sub_el->block.len);
    return true;
}

static bool
add_string_block_to_sexp(s_exp_t *s_exp, const char *s)
{
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static bool
add_sub_sexp_to_sexp(s_exp_t *s_exp, s_exp_t **sub_s_exp)
{
    sub_element_t *sub_el;

    sub_el = (sub_element_t *) list_append(&s_exp->sub_elements, NULL, sizeof(*sub_el));
    if (!sub_el) {
        return false;
    }

    sub_el->is_block = false;
    *sub_s_exp = &sub_el->s_exp;

    return true;
}

/*
 * Parse G10 S-exp.
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 * It should be parsed to:
 *   - a
 *   - ab
 *   + - asd
 *     - a
 *
 */
static bool
parse_sexp(s_exp_t *s_exp, const char **r_bytes, size_t *r_length)
{
    size_t      length = *r_length;
    const char *bytes = *r_bytes;

    s_exp_t new_s_exp = {0};

    if (bytes == NULL || length == 0) {
        RNP_LOG("empty s-exp");
        return true;
    }

    if (*bytes != '(') { // doesn't start from (
        return false;
    }

    bytes++;
    length--;

    do {
        if (length <= 0) { // unexpected end
            RNP_LOG("s-exp finished before ')'");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (*bytes == '(') {
            s_exp_t *new_sub_s_exp;

            if (!add_sub_sexp_to_sexp(&new_s_exp, &new_sub_s_exp)) {
                return false;
            }

            if (!parse_sexp(new_sub_s_exp, &bytes, &length)) {
                destroy_s_exp(&new_s_exp);
                return false;
            }

            continue;
        }

        char *next;
        long  len = strtol(bytes, &next, 10);

        if (*next != ':') { // doesn't contain :
            RNP_LOG("s-exp doesn't contain ':'");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        next++;

        length -= (next - bytes);
        bytes = next;

        if (len == LONG_MIN || len == LONG_MAX || len <= 0 || (size_t) len >= length) {
            RNP_LOG(
              "len over/under flow or bigger than remaining bytes, len: %ld, length: %zu",
              len,
              length);
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (!add_block_to_sexp(&new_s_exp, (uint8_t *) bytes, (size_t) len)) {
            destroy_s_exp(&new_s_exp);
            return false;
        }

        bytes += len;
        length -= len;

    } while (*bytes != ')');

    bytes++;
    length--;

    *s_exp = new_s_exp;
    *r_bytes = bytes;
    *r_length = length;

    return true;
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static unsigned
block_to_unsigned(s_exp_block_t *block)
{
    char s[sizeof(STR(UINT_MAX)) + 1] = {0};
    if (!block->len || block->len >= sizeof(s)) {
        return UINT_MAX;
    }

    memcpy(s, block->bytes, block->len);
    return (unsigned int) atoi(s);
}

static bool
add_unsigned_block_to_sexp(s_exp_t *s_exp, unsigned u)
{
    char s[sizeof(STR(UINT_MAX)) + 1];
    snprintf(s, sizeof(s), "%u", u);
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static size_t
sub_element_count(s_exp_t *s_exp)
{
    return list_length(s_exp->sub_elements);
}

static sub_element_t *
sub_element_at(s_exp_t *s_exp, size_t idx)
{
    size_t     i = 0;
    list_item *item = NULL;

    if (!s_exp || (sub_element_count(s_exp) < idx)) {
        return NULL;
    }

    for (item = list_front(s_exp->sub_elements); item && (i < idx); item = list_next(item)) {
        i++;
    }

    return (sub_element_t *) item;
}

static s_exp_t *
lookup_variable(s_exp_t *s_exp, const char *name)
{
    size_t name_len = strlen(name);

    for (list_item *li = list_front(s_exp->sub_elements); li; li = list_next(li)) {
        sub_element_t *name_el = NULL;
        sub_element_t *sub_el = (sub_element_t *) li;

        if (sub_el->is_block) {
            continue;
        }

        name_el = sub_element_at(&sub_el->s_exp, 0);
        if (sub_element_count(&sub_el->s_exp) < 2 || !name_el || !name_el->is_block) {
            RNP_LOG("Expected sub-s-exp with 2 first blocks");
            return NULL;
        }

        if (name_len != name_el->block.len) {
            continue;
        }

        if (!strncmp(name, (const char *) name_el->block.bytes, name_len)) {
            return &sub_el->s_exp;
        }
    }
    RNP_LOG("Haven't got variable '%s'", name);
    return NULL;
}

static s_exp_block_t *
lookup_variable_data(s_exp_t *s_exp, const char *name)
{
    s_exp_t *      var = lookup_variable(s_exp, name);
    sub_element_t *data = NULL;

    if (!var) {
        return NULL;
    }

    data = sub_element_at(var, 1);
    if (!data->is_block) {
        RNP_LOG("Expected block value");
        return NULL;
    }

    return &data->block;
}

static bool
read_mpi(s_exp_t *s_exp, const char *name, pgp_mpi_t *val)
{
    s_exp_block_t *data = lookup_variable_data(s_exp, name);

    if (!data) {
        return false;
    }

    /* strip leading zero */
    if ((data->len > 1) && !data->bytes[0] && (data->bytes[1] & 0x80)) {
        return mem2mpi(val, data->bytes + 1, data->len - 1);
    }

    return mem2mpi(val, data->bytes, data->len);
}

static bool
read_curve(s_exp_t *s_exp, const char *name, pgp_ec_key_t *key)
{
    s_exp_block_t *data = lookup_variable_data(s_exp, name);

    if (!data) {
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(g10_curve_aliases); i++) {
        if (strlen(g10_curve_aliases[i].string) != data->len) {
            continue;
        }
        if (!memcmp(g10_curve_aliases[i].string, data->bytes, data->len)) {
            key->curve = (pgp_curve_t) g10_curve_aliases[i].type;
            return true;
        }
    }

    RNP_LOG("Unknown curve: %.*s", (int) data->len, data->bytes);
    return false;
}

static bool
write_mpi(s_exp_t *s_exp, const char *name, const pgp_mpi_t *val)
{
    uint8_t  buf[PGP_MPINT_SIZE + 1] = {0};
    size_t   len;
    size_t   idx;
    s_exp_t *sub_s_exp;

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    len = mpi_bytes(val);
    for (idx = 0; (idx < len) && (val->mpi[idx] == 0); idx++)
        ;

    if (idx >= len) {
        return add_block_to_sexp(sub_s_exp, buf, 1);
    }

    if (val->mpi[idx] & 0x80) {
        memcpy(buf + 1, val->mpi + idx, len - idx);
        return add_block_to_sexp(sub_s_exp, buf, len - idx + 1);
    }

    return add_block_to_sexp(sub_s_exp, val->mpi + idx, len - idx);
}

static bool
write_curve(s_exp_t *s_exp, const char *name, const pgp_ec_key_t *key)
{
    const char *curve = NULL;
    s_exp_t *   sub_s_exp;

    ARRAY_LOOKUP_BY_ID(g10_curve_names, type, string, key->curve, curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, curve)) {
        return false;
    }

    if ((key->curve == PGP_CURVE_ED25519) || (key->curve == PGP_CURVE_25519)) {
        if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
            return false;
        }

        if (!add_string_block_to_sexp(sub_s_exp, "flags")) {
            return false;
        }

        if (!add_string_block_to_sexp(
              sub_s_exp, key->curve == PGP_CURVE_ED25519 ? "eddsa" : "djb-tweak")) {
            return false;
        }
    }

    return true;
}

static bool
parse_pubkey(pgp_key_pkt_t *pubkey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    pubkey->version = PGP_V4;
    pubkey->alg = alg;
    pubkey->material.alg = alg;
    switch (alg) {
    case PGP_PKA_DSA:
        if (!read_mpi(s_exp, "p", &pubkey->material.dsa.p) ||
            !read_mpi(s_exp, "q", &pubkey->material.dsa.q) ||
            !read_mpi(s_exp, "g", &pubkey->material.dsa.g) ||
            !read_mpi(s_exp, "y", &pubkey->material.dsa.y)) {
            return false;
        }
        break;

    case PGP_PKA_RSA:
        if (!read_mpi(s_exp, "n", &pubkey->material.rsa.n) ||
            !read_mpi(s_exp, "e", &pubkey->material.rsa.e)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
        if (!read_mpi(s_exp, "p", &pubkey->material.eg.p) ||
            !read_mpi(s_exp, "g", &pubkey->material.eg.g) ||
            !read_mpi(s_exp, "y", &pubkey->material.eg.y)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!read_curve(s_exp, "curve", &pubkey->material.ec) ||
            !read_mpi(s_exp, "q", &pubkey->material.ec.p)) {
            return false;
        }
        if (pubkey->material.ec.curve == PGP_CURVE_ED25519) {
            /* need to adjust it here since 'ecc' key type defaults to ECDSA */
            pubkey->alg = PGP_PKA_EDDSA;
            pubkey->material.alg = PGP_PKA_EDDSA;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    return true;
}

static bool
parse_seckey(pgp_key_pkt_t *seckey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_DSA:
        if (!read_mpi(s_exp, "x", &seckey->material.dsa.x)) {
            return false;
        }
        break;

    case PGP_PKA_RSA:
        if (!read_mpi(s_exp, "d", &seckey->material.rsa.d) ||
            !read_mpi(s_exp, "p", &seckey->material.rsa.p) ||
            !read_mpi(s_exp, "q", &seckey->material.rsa.q) ||
            !read_mpi(s_exp, "u", &seckey->material.rsa.u)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
        if (!read_mpi(s_exp, "x", &seckey->material.eg.x)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!read_mpi(s_exp, "d", &seckey->material.ec.x)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    seckey->material.secret = true;
    return true;
}

static bool
decrypt_protected_section(const uint8_t *      encrypted_data,
                          size_t               encrypted_data_len,
                          const pgp_key_pkt_t *seckey,
                          const char *         password,
                          s_exp_t *            r_s_exp)
{
    const format_info *info = NULL;
    unsigned           keysize = 0;
    uint8_t            derived_key[PGP_MAX_KEY_SIZE];
    uint8_t *          decrypted_data = NULL;
    size_t             decrypted_data_len = 0;
    size_t             output_written = 0;
    size_t             input_consumed = 0;
    botan_cipher_t     decrypt = NULL;
    bool               ret = false;

    const char *decrypted_bytes;
    size_t      s_exp_len;

    // sanity checks
    const pgp_key_protection_t *prot = &seckey->sec_protection;
    keysize = pgp_key_size(prot->symm_alg);
    if (!keysize) {
        RNP_LOG("parse_seckey: unknown symmetric algo");
        goto done;
    }
    // find the protection format in our table
    info = find_format(prot->symm_alg, prot->cipher_mode, prot->s2k.hash_alg);
    if (!info) {
        RNP_LOG("Unsupported format, alg: %d, chiper_mode: %d, hash: %d",
                prot->symm_alg,
                prot->cipher_mode,
                prot->s2k.hash_alg);
        goto done;
    }

    // derive the key
    if (pgp_s2k_iterated(prot->s2k.hash_alg,
                         derived_key,
                         keysize,
                         password,
                         prot->s2k.salt,
                         prot->s2k.iterations)) {
        RNP_LOG("pgp_s2k_iterated failed");
        goto done;
    }
    RNP_DHEX("input iv", prot->iv, G10_CBC_IV_SIZE);
    RNP_DHEX("key", derived_key, keysize);
    RNP_DHEX("encrypted", encrypted_data, encrypted_data_len);

    // decrypt
    decrypted_data = (uint8_t *) malloc(encrypted_data_len);
    if (decrypted_data == NULL) {
        RNP_LOG("can't allocate memory");
        goto done;
    }
    if (botan_cipher_init(&decrypt, info->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_DECRYPT)) {
        RNP_LOG("botan_cipher_init failed");
        goto done;
    }
    if (botan_cipher_set_key(decrypt, derived_key, keysize) ||
        botan_cipher_start(decrypt, prot->iv, info->iv_size)) {
        goto done;
    }
    if (botan_cipher_update(decrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            decrypted_data,
                            encrypted_data_len,
                            &output_written,
                            encrypted_data,
                            encrypted_data_len,
                            &input_consumed)) {
        RNP_LOG("botan_cipher_update failed");
        goto done;
    }
    decrypted_data_len = output_written;
    s_exp_len = decrypted_data_len;
    decrypted_bytes = (const char *) decrypted_data;
    RNP_DHEX("decrypted data", decrypted_data, decrypted_data_len);

    // parse and validate the decrypted s-exp
    if (!parse_sexp(r_s_exp, &decrypted_bytes, &s_exp_len)) {
        goto done;
    }
    if (!sub_element_count(r_s_exp) || sub_element_at(r_s_exp, 0)->is_block) {
        RNP_LOG("Hasn't got sub s-exp with key data.");
        goto done;
    }

    ret = true;

done:
    if (!ret) {
        destroy_s_exp(r_s_exp);
    }
    pgp_forget(decrypted_data, decrypted_data_len);
    free(decrypted_data);
    botan_cipher_destroy(decrypt);
    return ret;
}

static bool
parse_protected_seckey(pgp_key_pkt_t *seckey, s_exp_t *s_exp, const char *password)
{
    const format_info *   format;
    bool                  ret = false;
    s_exp_t               decrypted_s_exp = {0};
    s_exp_t *             alg = NULL;
    s_exp_t *             params = NULL;
    s_exp_block_t *       protected_at_data = NULL;
    sub_element_t *       sub_el = NULL;
    pgp_key_protection_t *prot;

    // find and validate the protected section
    s_exp_t *protected_key = lookup_variable(s_exp, "protected");
    if (!protected_key) {
        RNP_LOG("missing protected section");
        goto done;
    }
    if (sub_element_count(protected_key) != 4 || !sub_element_at(protected_key, 1)->is_block ||
        sub_element_at(protected_key, 2)->is_block ||
        !sub_element_at(protected_key, 3)->is_block) {
        RNP_LOG("Wrong protected format, expected: (protected mode (parms) "
                "encrypted_octet_string)\n");
        goto done;
    }

    // lookup the protection format
    sub_el = sub_element_at(protected_key, 1);
    format = parse_format((const char *) sub_el->block.bytes, sub_el->block.len);
    if (format == NULL) {
        RNP_LOG("Unsupported protected mode: '%.*s'\n",
                (int) sub_el->block.len,
                sub_el->block.bytes);
        goto done;
    }

    // fill in some fields based on the lookup above
    prot = &seckey->sec_protection;
    prot->symm_alg = format->cipher;
    prot->cipher_mode = format->cipher_mode;
    prot->s2k.hash_alg = format->hash_alg;

    // locate and validate the protection parameters
    params = &sub_element_at(protected_key, 2)->s_exp;
    if (sub_element_count(params) != 2 || sub_element_at(params, 0)->is_block ||
        !sub_element_at(params, 1)->is_block) {
        RNP_LOG("Wrong params format, expected: ((hash salt no_of_iterations) iv)\n");
        goto done;
    }

    // locate and validate the (hash salt no_of_iterations) exp
    alg = &sub_element_at(params, 0)->s_exp;
    if (sub_element_count(alg) != 3 || !sub_element_at(alg, 0)->is_block ||
        !sub_element_at(alg, 1)->is_block || !sub_element_at(alg, 2)->is_block) {
        RNP_LOG("Wrong params sub-level format, expected: (hash salt no_of_iterations)\n");
        goto done;
    }
    sub_el = sub_element_at(alg, 0);
    if (strncmp("sha1", (const char *) sub_el->block.bytes, sub_el->block.len) != 0) {
        RNP_LOG("Wrong hashing algorithm, should be sha1 but %.*s\n",
                (int) sub_el->block.len,
                sub_el->block.bytes);
        goto done;
    }

    // fill in some constant values
    prot->s2k.hash_alg = PGP_HASH_SHA1;
    prot->s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    prot->s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    // check salt size
    sub_el = sub_element_at(alg, 1);
    if (sub_el->block.len != PGP_SALT_SIZE) {
        RNP_LOG(
          "Wrong salt size, should be %d but %d\n", PGP_SALT_SIZE, (int) sub_el->block.len);
        goto done;
    }

    // salt
    memcpy(prot->s2k.salt, sub_el->block.bytes, sub_el->block.len);
    // s2k iterations
    sub_el = sub_element_at(alg, 2);
    prot->s2k.iterations = block_to_unsigned(&sub_el->block);
    if (prot->s2k.iterations == UINT_MAX) {
        RNP_LOG(
          "Wrong numbers of iteration, %.*s\n", (int) sub_el->block.len, sub_el->block.bytes);
        goto done;
    }

    // iv
    sub_el = sub_element_at(params, 1);
    if (sub_el->block.len != format->iv_size) {
        RNP_LOG("Wrong nonce size, should be %zu but %d\n",
                format->iv_size,
                (int) sub_el->block.len);
        goto done;
    }
    memcpy(prot->iv, sub_el->block.bytes, sub_el->block.len);

    // we're all done if no password was provided (decryption not requested)
    if (!password) {
        seckey->material.secret = false;
        ret = true;
        goto done;
    }

    // password was provided, so decrypt
    sub_el = sub_element_at(protected_key, 3);
    if (!decrypt_protected_section(
          sub_el->block.bytes, sub_el->block.len, seckey, password, &decrypted_s_exp)) {
        goto done;
    }
    // see if we have a protected-at section
    protected_at_data = lookup_variable_data(s_exp, "protected-at");
    char protected_at[G10_PROTECTED_AT_SIZE];
    if (protected_at_data) {
        if (protected_at_data->len != G10_PROTECTED_AT_SIZE) {
            RNP_LOG("protected-at has wrong length: %zu, expected, %d\n",
                    protected_at_data->len,
                    G10_PROTECTED_AT_SIZE);
            goto done;
        }
        memcpy(protected_at, protected_at_data->bytes, protected_at_data->len);
    }
    // parse MPIs
    if (!parse_seckey(seckey, &sub_element_at(&decrypted_s_exp, 0)->s_exp, seckey->alg)) {
        RNP_LOG("failed to parse seckey");
        goto done;
    }
    // check hash, if present
    if (sub_element_count(&decrypted_s_exp) > 1) {
        sub_el = sub_element_at(&decrypted_s_exp, 1);
        if (sub_el->is_block || sub_element_count(&sub_el->s_exp) < 3 ||
            !sub_element_at(&sub_el->s_exp, 0)->is_block ||
            !sub_element_at(&sub_el->s_exp, 1)->is_block ||
            !sub_element_at(&sub_el->s_exp, 2)->is_block ||
            strncmp("hash",
                    (const char *) sub_element_at(&sub_el->s_exp, 0)->block.bytes,
                    sub_element_at(&sub_el->s_exp, 0)->block.len) != 0) {
            RNP_LOG("Has got wrong hash block at encrypted key data.");
            goto done;
        }

        if (strncmp("sha1",
                    (const char *) sub_element_at(&sub_el->s_exp, 1)->block.bytes,
                    sub_element_at(&sub_el->s_exp, 1)->block.len) != 0) {
            RNP_LOG("Supported only sha1 hash at encrypted private key.");
            goto done;
        }

        uint8_t checkhash[G10_SHA1_HASH_SIZE];
        if (!g10_calculated_hash(seckey, protected_at, checkhash)) {
            RNP_LOG("failed to calculate hash");
            goto done;
        }

        sub_el = sub_element_at(&sub_el->s_exp, 2);
        if (sub_el->block.len != G10_SHA1_HASH_SIZE ||
            memcmp(checkhash, sub_el->block.bytes, G10_SHA1_HASH_SIZE) != 0) {
            RNP_DHEX("Expected hash", checkhash, G10_SHA1_HASH_SIZE);
            RNP_DHEX("Has hash", sub_el->block.bytes, sub_el->block.len);
            RNP_LOG("Incorrect hash at encrypted private key.");
            goto done;
        }
    }
    seckey->material.secret = true;
    ret = true;

done:
    destroy_s_exp(&decrypted_s_exp);
    return ret;
}

static bool
g10_parse_seckey(pgp_key_pkt_t *seckey,
                 const uint8_t *data,
                 size_t         data_len,
                 const char *   password)
{
    s_exp_t          s_exp = {0};
    bool             ret = false;
    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;
    s_exp_t *        algorithm_s_exp = NULL;
    s_exp_block_t *  block = NULL;
    bool             is_protected = false;

    RNP_DHEX("S-exp", (const uint8_t *) data, data_len);

    const char *bytes = (const char *) data;
    if (!parse_sexp(&s_exp, &bytes, &data_len)) {
        goto done;
    }

    /* expected format:
     *  (<type>
     *    (<algo>
     *	   (x <mpi>)
     *	   (y <mpi>)
     *    )
     *  )
     */

    if (sub_element_count(&s_exp) != 2 || !sub_element_at(&s_exp, 0)->is_block ||
        sub_element_at(&s_exp, 1)->is_block) {
        RNP_LOG("Wrong format, expected: (<type> (...))");
        goto done;
    }

    block = &sub_element_at(&s_exp, 0)->block;
    if (!strncmp("private-key", (const char *) block->bytes, block->len)) {
        is_protected = false;
    } else if (!strncmp("protected-private-key", (const char *) block->bytes, block->len)) {
        is_protected = true;
    } else {
        RNP_LOG("Unsupported top-level block: '%.*s'", (int) block->len, block->bytes);
        goto done;
    }

    algorithm_s_exp = &sub_element_at(&s_exp, 1)->s_exp;

    if (sub_element_count(algorithm_s_exp) < 2) {
        RNP_LOG("Wrong count of algorithm-level elements: %d, should great than 1",
                (int) sub_element_count(algorithm_s_exp));
        goto done;
    }

    if (!sub_element_at(algorithm_s_exp, 0)->is_block) {
        RNP_LOG("Expected block with algorithm name, but has s-exp");
        goto done;
    }

    block = &sub_element_at(algorithm_s_exp, 0)->block;
    alg = PGP_PKA_NOTHING;
    for (size_t i = 0; i < ARRAY_SIZE(g10_alg_aliases); i++) {
        if (strlen(g10_alg_aliases[i].string) != block->len) {
            continue;
        }
        if (!memcmp(g10_alg_aliases[i].string, block->bytes, block->len)) {
            alg = (pgp_pubkey_alg_t) g10_alg_aliases[i].type;
            break;
        }
    }

    if (alg == PGP_PKA_NOTHING) {
        RNP_LOG("Unsupported algorithm: '%.*s'", (int) block->len, block->bytes);
        goto done;
    }

    if (!parse_pubkey(seckey, algorithm_s_exp, alg)) {
        RNP_LOG("failed to parse pubkey");
        goto done;
    }

    if (is_protected) {
        if (!parse_protected_seckey(seckey, algorithm_s_exp, password)) {
            goto done;
        }
    } else {
        seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
        seckey->sec_protection.symm_alg = PGP_SA_PLAINTEXT;
        seckey->sec_protection.s2k.hash_alg = PGP_HASH_UNKNOWN;
        if (!parse_seckey(seckey, algorithm_s_exp, alg)) {
            RNP_LOG("failed to parse seckey");
            goto done;
        }
    }

    if (rnp_get_debug(__FILE__)) {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];
        if (rnp_key_store_get_key_grip(&seckey->material, grip)) {
            RNP_LOG("loaded G10 key with GRIP: %s\n",
                    rnp_strhexdump_upper(grips, grip, PGP_FINGERPRINT_SIZE, ""));
        }
    }
    ret = true;

done:
    destroy_s_exp(&s_exp);
    if (!ret) {
        free_key_pkt(seckey);
    }
    return ret;
}

pgp_key_pkt_t *
g10_decrypt_seckey(const uint8_t *      data,
                   size_t               data_len,
                   const pgp_key_pkt_t *pubkey,
                   const char *         password)
{
    pgp_key_pkt_t *seckey = NULL;
    bool           ok = false;

    if (!password) {
        return NULL;
    }

    seckey = (pgp_key_pkt_t *) calloc(1, sizeof(*seckey));
    if (pubkey && !copy_key_pkt(seckey, pubkey, false)) {
        goto done;
    }
    if (!g10_parse_seckey(seckey, data, data_len, password)) {
        goto done;
    }
    ok = true;

done:
    if (!ok) {
        free(seckey);
        seckey = NULL;
    }
    return seckey;
}

static bool
copy_secret_fields(pgp_key_pkt_t *dst, const pgp_key_pkt_t *src)
{
    switch (src->alg) {
    case PGP_PKA_DSA:
        dst->material.dsa.x = src->material.dsa.x;
        break;
    case PGP_PKA_RSA:
        dst->material.rsa.d = src->material.rsa.d;
        dst->material.rsa.p = src->material.rsa.p;
        dst->material.rsa.q = src->material.rsa.q;
        dst->material.rsa.u = src->material.rsa.u;
        break;
    case PGP_PKA_ELGAMAL:
        dst->material.eg.x = src->material.eg.x;
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        dst->material.ec.x = src->material.ec.x;
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) src->alg);
        return false;
    }

    dst->material.secret = src->material.secret;
    dst->sec_protection = src->sec_protection;
    dst->tag = pgp_is_subkey_tag((pgp_content_enum) dst->tag) ? PGP_PTAG_CT_SECRET_SUBKEY :
                                                                PGP_PTAG_CT_SECRET_KEY;

    return true;
}

bool
rnp_key_store_g10_from_mem(rnp_key_store_t *         key_store,
                           pgp_memory_t *            memory,
                           const pgp_key_provider_t *key_provider)
{
    const pgp_key_t *pubkey = NULL;
    pgp_key_t        key = {0};
    pgp_key_pkt_t    seckey = {0};
    bool             ret = false;

    /* parse secret key: fills material and sec_protection only */
    if (!g10_parse_seckey(&seckey, memory->buf, memory->length, NULL)) {
        goto done;
    }

    /* copy public key fields if any */
    if (key_provider) {
        pgp_key_search_t search = {.type = PGP_KEY_SEARCH_GRIP};
        if (!rnp_key_store_get_key_grip(&seckey.material, search.by.grip)) {
            goto done;
        }

        pgp_key_request_ctx_t req_ctx;
        memset(&req_ctx, 0, sizeof(req_ctx));
        req_ctx.op = PGP_OP_MERGE_INFO;
        req_ctx.secret = false;
        req_ctx.search = search;

        if (!(pubkey = pgp_request_key(key_provider, &req_ctx))) {
            goto done;
        }

        if (pgp_key_copy_fields(&key, pubkey)) {
            RNP_LOG("failed to copy key fields");
            goto done;
        }

        /* public key packet has some more info then the secret part */
        if (!copy_key_pkt(&key.pkt, pgp_get_key_pkt(pubkey), false)) {
            goto done;
        }

        if (!copy_secret_fields(&key.pkt, &seckey)) {
            goto done;
        }
    } else {
        key.pkt = seckey;
        memset(&seckey, 0, sizeof(seckey));
    }

    if (!pgp_key_add_rawpacket(&key, memory->buf, memory->length, PGP_PTAG_CT_RESERVED)) {
        RNP_LOG("failed to add packet");
        goto done;
    }
    key.format = G10_KEY_STORE;
    if (!rnp_key_store_add_key(key_store, &key)) {
        goto done;
    }
    ret = true;
done:
    if (!ret) {
        free_key_pkt(&seckey);
        pgp_key_free_data(&key);
    }
    return ret;
}

#define MAX_SIZE_T_LEN ((3 * sizeof(size_t) * CHAR_BIT / 8) + 2)

static bool
write_block(s_exp_block_t *block, pgp_memory_t *mem)
{
    if (!pgp_memory_pad(mem, MAX_SIZE_T_LEN)) {
        return false;
    }
    mem->length +=
      snprintf((char *) (mem->buf + mem->length), MAX_SIZE_T_LEN, "%zu", block->len);

    if (!pgp_memory_add(mem, (const uint8_t *) ":", 1)) {
        return false;
    }

    return pgp_memory_add(mem, block->bytes, block->len);
}

/*
 * Write G10 S-exp to buffer
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 */
static bool
write_sexp(s_exp_t *s_exp, pgp_memory_t *mem)
{
    if (!pgp_memory_add(mem, (const uint8_t *) "(", 1)) {
        return false;
    }

    for (list_item *item = list_front(s_exp->sub_elements); item; item = list_next(item)) {
        sub_element_t *sub_el = (sub_element_t *) item;

        if (sub_el->is_block) {
            if (!write_block(&sub_el->block, mem)) {
                return false;
            }
        } else {
            if (!write_sexp(&sub_el->s_exp, mem)) {
                return false;
            }
        }
    }

    return pgp_memory_add(mem, (const uint8_t *) ")", 1);
}

static bool
write_pubkey(s_exp_t *s_exp, const pgp_key_pkt_t *key)
{
    const pgp_key_material_t *kmaterial = &key->material;
    switch (key->alg) {
    case PGP_PKA_DSA:
        if (!add_string_block_to_sexp(s_exp, "dsa")) {
            return false;
        }
        if (!write_mpi(s_exp, "p", &kmaterial->dsa.p) ||
            !write_mpi(s_exp, "q", &kmaterial->dsa.q) ||
            !write_mpi(s_exp, "g", &kmaterial->dsa.g) ||
            !write_mpi(s_exp, "y", &kmaterial->dsa.y)) {
            return false;
        }
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!add_string_block_to_sexp(s_exp, "rsa")) {
            return false;
        }
        if (!write_mpi(s_exp, "n", &kmaterial->rsa.n) ||
            !write_mpi(s_exp, "e", &kmaterial->rsa.e)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
        if (!add_string_block_to_sexp(s_exp, "elg")) {
            return false;
        }
        if (!write_mpi(s_exp, "p", &kmaterial->eg.p) ||
            !write_mpi(s_exp, "g", &kmaterial->eg.g) ||
            !write_mpi(s_exp, "y", &kmaterial->eg.y)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!add_string_block_to_sexp(s_exp, "ecc")) {
            return false;
        }
        if (!write_curve(s_exp, "curve", &kmaterial->ec) ||
            !write_mpi(s_exp, "q", &kmaterial->ec.p)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key->alg);
        return false;
    }

    return true;
}

static bool
write_seckey(s_exp_t *s_exp, const pgp_key_pkt_t *key)
{
    switch (key->alg) {
    case PGP_PKA_DSA:
        if (!write_mpi(s_exp, "x", &key->material.dsa.x)) {
            return false;
        }
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!write_mpi(s_exp, "d", &key->material.rsa.d) ||
            !write_mpi(s_exp, "p", &key->material.rsa.p) ||
            !write_mpi(s_exp, "q", &key->material.rsa.q) ||
            !write_mpi(s_exp, "u", &key->material.rsa.u)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
        if (!write_mpi(s_exp, "x", &key->material.eg.x)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA: {
        if (!write_mpi(s_exp, "d", &key->material.ec.x)) {
            return false;
        }
        break;
    }
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key->alg);
        return false;
    }

    return true;
}

static bool
write_protected_seckey(s_exp_t *s_exp, pgp_key_pkt_t *seckey, const char *password)
{
    bool                  ret = false;
    const format_info *   format;
    s_exp_t               raw_s_exp = {0};
    s_exp_t *             sub_s_exp, *sub_sub_s_exp, *sub_sub_sub_s_exp;
    pgp_memory_t          raw = {0};
    uint8_t *             encrypted_data = NULL;
    botan_cipher_t        encrypt = NULL;
    unsigned              keysize;
    uint8_t               checksum[G10_SHA1_HASH_SIZE];
    uint8_t               derived_key[PGP_MAX_KEY_SIZE];
    pgp_key_protection_t *prot = &seckey->sec_protection;
    size_t                encrypted_data_len = 0;
    size_t                output_written, input_consumed;

    if (prot->s2k.specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        return false;
    }
    format = find_format(prot->symm_alg, prot->cipher_mode, prot->s2k.hash_alg);
    if (format == NULL) {
        return false;
    }

    // randomize IV and salt
    rng_t rng = {0};
    if (!rng_init(&rng, RNG_SYSTEM) || !rng_get_data(&rng, &prot->iv[0], sizeof(prot->iv)) ||
        !rng_get_data(&rng, &prot->s2k.salt[0], sizeof(prot->s2k.salt))) {
        rng_destroy(&rng);
        return false;
    }
    rng_destroy(&rng);

    if (!add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp) || !write_seckey(sub_s_exp, seckey)) {
        goto done;
    }

    // calculated hash
    time_t now;
    time(&now);
    char protected_at[G10_PROTECTED_AT_SIZE + 1];
    strftime(protected_at, sizeof(protected_at), "%Y%m%dT%H%M%S", gmtime(&now));

    if (!g10_calculated_hash(seckey, protected_at, checksum) ||
        !add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "hash") ||
        !add_string_block_to_sexp(sub_s_exp, "sha1") ||
        !add_block_to_sexp(sub_s_exp, checksum, sizeof(checksum)) ||
        !write_sexp(&raw_s_exp, &raw)) {
        goto done;
    }

    keysize = pgp_key_size(prot->symm_alg);
    if (keysize == 0) {
        goto done;
    }

    if (pgp_s2k_iterated(format->hash_alg,
                         derived_key,
                         keysize,
                         (const char *) password,
                         prot->s2k.salt,
                         prot->s2k.iterations)) {
        goto done;
    }

    // add padding!
    for (int i = (int) (format->chiper_block_size - raw.length % format->chiper_block_size);
         i > 0;
         i--) {
        if (!pgp_memory_add(&raw, (const uint8_t *) "X", 1)) {
            goto done;
        }
    }

    encrypted_data_len = raw.length;
    encrypted_data = (uint8_t *) malloc(encrypted_data_len);
    if (!encrypted_data) {
        goto done;
    }

    RNP_DHEX("input iv", prot->iv, G10_CBC_IV_SIZE);
    RNP_DHEX("key", derived_key, keysize);
    RNP_DHEX("raw data", raw.buf, raw.length);

    if (botan_cipher_init(
          &encrypt, format->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_ENCRYPT) ||
        botan_cipher_set_key(encrypt, derived_key, keysize) ||
        botan_cipher_start(encrypt, prot->iv, format->iv_size)) {
        goto done;
    }
    if (botan_cipher_update(encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            encrypted_data,
                            encrypted_data_len,
                            &output_written,
                            raw.buf,
                            raw.length,
                            &input_consumed)) {
        goto done;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "protected") ||
        !add_string_block_to_sexp(sub_s_exp, format->g10_type) ||
        !add_sub_sexp_to_sexp(sub_s_exp, &sub_sub_s_exp) ||
        !add_sub_sexp_to_sexp(sub_sub_s_exp, &sub_sub_sub_s_exp) ||
        !add_string_block_to_sexp(sub_sub_sub_s_exp, "sha1") ||
        !add_block_to_sexp(sub_sub_sub_s_exp, prot->s2k.salt, PGP_SALT_SIZE) ||
        !add_unsigned_block_to_sexp(sub_sub_sub_s_exp, prot->s2k.iterations) ||
        !add_block_to_sexp(sub_sub_s_exp, prot->iv, format->iv_size) ||
        !add_block_to_sexp(sub_s_exp, encrypted_data, encrypted_data_len) ||
        !add_sub_sexp_to_sexp(s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "protected-at") ||
        !add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
        goto done;
    }
    ret = true;

done:
    pgp_forget(derived_key, sizeof(derived_key));
    free(encrypted_data);
    destroy_s_exp(&raw_s_exp);
    pgp_memory_release(&raw);
    botan_cipher_destroy(encrypt);
    return ret;
}

bool
g10_write_seckey(pgp_dest_t *dst, pgp_key_pkt_t *seckey, const char *password)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp = NULL;
    pgp_memory_t mem = {0};
    bool         is_protected = true;
    bool         ret = false;

    switch (seckey->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
        is_protected = false;
        break;
    case PGP_S2KU_ENCRYPTED_AND_HASHED:
        is_protected = true;
        // TODO: these are forced for now, until openpgp-native is implemented
        seckey->sec_protection.symm_alg = PGP_SA_AES_128;
        seckey->sec_protection.cipher_mode = PGP_CIPHER_MODE_CBC;
        seckey->sec_protection.s2k.hash_alg = PGP_HASH_SHA1;
        break;
    default:
        RNP_LOG("unsupported s2k usage");
        goto done;
    }
    if (!add_string_block_to_sexp(&s_exp,
                                  is_protected ? "protected-private-key" : "private-key") ||
        !add_sub_sexp_to_sexp(&s_exp, &sub_s_exp) || !write_pubkey(sub_s_exp, seckey)) {
        goto done;
    }
    if (is_protected) {
        if (!write_protected_seckey(sub_s_exp, seckey, password)) {
            goto done;
        }
    } else {
        if (!write_seckey(sub_s_exp, seckey)) {
            goto done;
        }
    }
    if (!write_sexp(&s_exp, &mem)) {
        goto done;
    }
    dst_write(dst, mem.buf, mem.length);
    ret = !dst->werr;
done:
    pgp_memory_release(&mem);
    destroy_s_exp(&s_exp);
    return ret;
}

static bool
g10_calculated_hash(const pgp_key_pkt_t *key, const char *protected_at, uint8_t *checksum)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp;
    pgp_memory_t mem = {0};
    pgp_hash_t   hash = {0};

    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        goto error;
    }

    if (hash._output_len != G10_SHA1_HASH_SIZE) {
        RNP_LOG(
          "wrong hash size %zu, should be %d bytes", hash._output_len, G10_SHA1_HASH_SIZE);
        goto error;
    }

    if (!write_pubkey(&s_exp, key)) {
        RNP_LOG("failed to write pubkey");
        goto error;
    }

    if (!write_seckey(&s_exp, key)) {
        RNP_LOG("failed to write seckey");
        goto error;
    }

    if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
        goto error;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        goto error;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
        goto error;
    }

    if (!write_sexp(&s_exp, &mem)) {
        goto error;
    }

    destroy_s_exp(&s_exp);

    RNP_DHEX("data for hashing", mem.buf, mem.length);

    pgp_hash_add(&hash, mem.buf, mem.length);

    pgp_memory_release(&mem);

    if (!pgp_hash_finish(&hash, checksum)) {
        goto error;
    }

    return true;

error:
    destroy_s_exp(&s_exp);
    return false;
}

bool
rnp_key_store_g10_key_to_mem(pgp_key_t *key, pgp_memory_t *memory)
{
    pgp_rawpacket_t *packet = NULL;
    if (!pgp_key_get_rawpacket_count(key)) {
        return false;
    }
    if (key->format != G10_KEY_STORE) {
        RNP_LOG("incorrect format: %d", key->format);
        return false;
    }
    packet = pgp_key_get_rawpacket(key, 0);
    return pgp_memory_add(memory, packet->raw, packet->length);
}
