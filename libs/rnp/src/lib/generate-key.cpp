/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include <rekey/rnp_key_store.h>
#include <librekey/key_store_pgp.h>
#include <librekey/key_store_g10.h>
#include <librepgp/packet-show.h>
#include <librepgp/stream-packet.h>
#include "crypto.h"
#include "pgp-key.h"
#include "memory.h"
#include "packet-create.h"
#include "defaults.h"
#include "utils.h"

static const pgp_symm_alg_t DEFAULT_SYMMETRIC_ALGS[] = {
  PGP_SA_AES_256, PGP_SA_AES_192, PGP_SA_AES_128, PGP_SA_TRIPLEDES};
static const pgp_hash_alg_t DEFAULT_HASH_ALGS[] = {
  PGP_HASH_SHA256, PGP_HASH_SHA384, PGP_HASH_SHA512, PGP_HASH_SHA224, PGP_HASH_SHA1};
static const pgp_compression_type_t DEFAULT_COMPRESS_ALGS[] = {
  PGP_C_ZLIB, PGP_C_BZIP2, PGP_C_ZIP, PGP_C_NONE};

static bool
load_generated_g10_key(pgp_key_t *    dst,
                       pgp_key_pkt_t *newkey,
                       pgp_key_t *    primary_key,
                       pgp_key_t *    pubkey)
{
    bool               ok = false;
    pgp_memory_t       mem = {};
    pgp_dest_t         memdst = {};
    rnp_key_store_t *  key_store = NULL;
    list               key_ptrs = NULL; /* holds primary and pubkey, when used */
    pgp_key_provider_t prov = {};

    // this should generally be zeroed
    assert(pgp_get_key_type(dst) == 0);
    // if a primary is provided, make sure it's actually a primary key
    assert(!primary_key || pgp_key_is_primary_key(primary_key));
    // if a pubkey is provided, make sure it's actually a public key
    assert(!pubkey || pgp_is_key_public(pubkey));
    // G10 always needs pubkey here
    assert(pubkey);

    if (init_mem_dest(&memdst, NULL, 0)) {
        goto end;
    }

    if (!g10_write_seckey(&memdst, newkey, NULL)) {
        RNP_LOG("failed to write generated seckey");
        goto end;
    }

    // this would be better on the stack but the key store does not allow it
    key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    if (!key_store) {
        goto end;
    }

    // if this is a subkey, add the primary in first
    if (primary_key && !list_append(&key_ptrs, &primary_key, sizeof(primary_key))) {
        goto end;
    }
    // G10 needs the pubkey for copying some attributes (key version, creation time, etc)
    if (!list_append(&key_ptrs, &pubkey, sizeof(pubkey))) {
        goto end;
    }

    prov.callback = rnp_key_provider_key_ptr_list;
    prov.userdata = key_ptrs;

    pgp_memory_ref(&mem, (uint8_t *) mem_dest_get_memory(&memdst), memdst.writeb);

    if (!rnp_key_store_g10_from_mem(key_store, &mem, &prov)) {
        goto end;
    }
    // if a primary key is provided, it should match the sub with regards to type
    assert(!primary_key || (pgp_is_key_secret(primary_key) ==
                            pgp_is_key_secret((pgp_key_t *) list_back(key_store->keys))));
    if (list_length(key_store->keys) != 1) {
        goto end;
    }
    memcpy(dst, (pgp_key_t *) list_front(key_store->keys), sizeof(*dst));
    // we don't want the key store to free the internal key data
    rnp_key_store_remove_key(key_store, (pgp_key_t *) list_front(key_store->keys));
    ok = true;

end:
    rnp_key_store_free(key_store);
    dst_close(&memdst, true);
    list_destroy(&key_ptrs);
    return ok;
}

static uint8_t
pk_alg_default_flags(pgp_pubkey_alg_t alg)
{
    // just use the full capabilities as the ultimate fallback
    return pgp_pk_alg_capabilities(alg);
}

// TODO: Similar as pgp_pick_hash_alg but different enough to
//       keep another version. This will be changed when refactoring crypto
static void
adjust_hash_alg(rnp_keygen_crypto_params_t *crypto)
{
    if (!crypto->hash_alg) {
        crypto->hash_alg = DEFAULT_HASH_ALGS[0];
    }

    if ((crypto->key_alg != PGP_PKA_DSA) && (crypto->key_alg != PGP_PKA_ECDSA)) {
        return;
    }

    pgp_hash_alg_t min_hash = (crypto->key_alg == PGP_PKA_ECDSA) ?
                                ecdsa_get_min_hash(crypto->ecc.curve) :
                                dsa_get_min_hash(crypto->dsa.q_bitlen);

    if (pgp_digest_length(crypto->hash_alg) < pgp_digest_length(min_hash)) {
        crypto->hash_alg = min_hash;
    }
}

static void
keygen_merge_crypto_defaults(rnp_keygen_crypto_params_t *crypto)
{
    // default to RSA
    if (!crypto->key_alg) {
        crypto->key_alg = PGP_PKA_RSA;
    }

    switch (crypto->key_alg) {
    case PGP_PKA_RSA:
        if (!crypto->rsa.modulus_bit_len) {
            crypto->rsa.modulus_bit_len = DEFAULT_RSA_NUMBITS;
        }
        break;

    case PGP_PKA_SM2:
        if (!crypto->hash_alg) {
            crypto->hash_alg = PGP_HASH_SM3;
        }
        if (!crypto->ecc.curve) {
            crypto->ecc.curve = PGP_CURVE_SM2_P_256;
        }
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA: {
        if (!crypto->hash_alg) {
            crypto->hash_alg = DEFAULT_HASH_ALGS[0];
        }
        break;
    }

    case PGP_PKA_EDDSA:
        if (!crypto->ecc.curve) {
            crypto->ecc.curve = PGP_CURVE_ED25519;
        }
        break;

    case PGP_PKA_DSA: {
        if (!crypto->dsa.p_bitlen) {
            crypto->dsa.p_bitlen = DSA_DEFAULT_P_BITLEN;
            crypto->dsa.q_bitlen = dsa_choose_qsize_by_psize(DSA_DEFAULT_P_BITLEN);
        }
        break;
    }
    default:
        break;
    }

    adjust_hash_alg(crypto);
}

static bool
validate_keygen_primary(const rnp_keygen_primary_desc_t *desc)
{
    /* Confirm that the specified pk alg can certify.
     * gpg requires this, though the RFC only says that a V4 primary
     * key SHOULD be a key capable of certification.
     */
    if (!(pgp_pk_alg_capabilities(desc->crypto.key_alg) & PGP_KF_CERTIFY)) {
        RNP_LOG("primary key alg (%d) must be able to sign", desc->crypto.key_alg);
        return false;
    }

    // check key flags
    if (!desc->cert.key_flags) {
        // these are probably not *technically* required
        RNP_LOG("key flags are required");
        return false;
    } else if (desc->cert.key_flags & ~pgp_pk_alg_capabilities(desc->crypto.key_alg)) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }

    // require a userid
    if (!desc->cert.userid[0]) {
        RNP_LOG("userid is required for primary key");
        return false;
    }
    return true;
}

static uint32_t
get_numbits(const rnp_keygen_crypto_params_t *crypto)
{
    switch (crypto->key_alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return crypto->rsa.modulus_bit_len;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        if (const ec_curve_desc_t *curve = get_curve_desc(crypto->ecc.curve)) {
            return curve->bitlen;
        } else {
            return 0;
        }
    }
    case PGP_PKA_DSA:
        return crypto->dsa.p_bitlen;
    case PGP_PKA_ELGAMAL:
        return crypto->elgamal.key_bitlen;
    default:
        return 0;
    }
}

static bool
set_default_user_prefs(pgp_user_prefs_t *prefs)
{
    if (!prefs->symm_algs) {
        for (size_t i = 0; i < ARRAY_SIZE(DEFAULT_SYMMETRIC_ALGS); i++) {
            EXPAND_ARRAY(prefs, symm_alg);
            if (!prefs->symm_algs) {
                return false;
            }
            prefs->symm_algs[i] = DEFAULT_SYMMETRIC_ALGS[i];
            prefs->symm_algc++;
        }
    }
    if (!prefs->hash_algs) {
        for (size_t i = 0; i < ARRAY_SIZE(DEFAULT_HASH_ALGS); i++) {
            EXPAND_ARRAY(prefs, hash_alg);
            if (!prefs->hash_algs) {
                return false;
            }
            prefs->hash_algs[i] = DEFAULT_HASH_ALGS[i];
            prefs->hash_algc++;
        }
    }
    if (!prefs->compress_algs) {
        for (size_t i = 0; i < ARRAY_SIZE(DEFAULT_COMPRESS_ALGS); i++) {
            EXPAND_ARRAY(prefs, compress_alg);
            if (!prefs->compress_algs) {
                return false;
            }
            prefs->compress_algs[i] = DEFAULT_COMPRESS_ALGS[i];
            prefs->compress_algc++;
        }
    }
    return true;
}

static void
keygen_primary_merge_defaults(rnp_keygen_primary_desc_t *desc)
{
    keygen_merge_crypto_defaults(&desc->crypto);
    set_default_user_prefs(&desc->cert.prefs);

    if (!desc->cert.key_flags) {
        // set some default key flags if none are provided
        desc->cert.key_flags = pk_alg_default_flags(desc->crypto.key_alg);
    }
    if (desc->cert.userid[0] == '\0') {
        snprintf((char *) desc->cert.userid,
                 sizeof(desc->cert.userid),
                 "%s %d-bit key <%s@localhost>",
                 pgp_show_pka(desc->crypto.key_alg),
                 get_numbits(&desc->crypto),
                 getenv("LOGNAME"));
    }
}

bool
pgp_generate_primary_key(rnp_keygen_primary_desc_t *desc,
                         bool                       merge_defaults,
                         pgp_key_t *                primary_sec,
                         pgp_key_t *                primary_pub,
                         key_store_format_t         secformat)
{
    bool                       ok = false;
    pgp_transferable_key_t     tkeysec = {};
    pgp_transferable_key_t     tkeypub = {};
    pgp_transferable_userid_t *uid = NULL;

    // validate args
    if (!desc || !primary_pub || !primary_sec) {
        goto end;
    }
    if (pgp_get_key_type(primary_sec) || pgp_get_key_type(primary_pub)) {
        RNP_LOG("invalid parameters (should be zeroed)");
        goto end;
    }

    // merge some defaults in, if requested
    if (merge_defaults) {
        keygen_primary_merge_defaults(desc);
    }

    // now validate the keygen fields
    if (!validate_keygen_primary(desc)) {
        goto end;
    }

    // generate the raw key and fill tag/secret fields
    if (!pgp_generate_seckey(&desc->crypto, &tkeysec.key, true)) {
        goto end;
    }

    uid = transferable_key_add_userid(&tkeysec, (char *) desc->cert.userid);
    if (!uid) {
        RNP_LOG("failed to add userid");
        goto end;
    }

    if (!transferable_userid_certify(
          &tkeysec.key, uid, &tkeysec.key, desc->crypto.hash_alg, &desc->cert)) {
        RNP_LOG("failed to certify key");
        goto end;
    }

    if (!transferable_key_copy(&tkeypub, &tkeysec, true)) {
        RNP_LOG("failed to copy public key part");
        goto end;
    }

    if (!rnp_key_from_transferable_key(primary_pub, &tkeypub)) {
        goto end;
    }

    switch (secformat) {
    case GPG_KEY_STORE:
    case KBX_KEY_STORE:
        if (!rnp_key_from_transferable_key(primary_sec, &tkeysec)) {
            goto end;
        }
        break;
    case G10_KEY_STORE:
        if (!load_generated_g10_key(primary_sec, &tkeysec.key, NULL, primary_pub)) {
            RNP_LOG("failed to load generated key");
            goto end;
        }
        break;
    default:
        RNP_LOG("invalid format");
        goto end;
        break;
    }

    ok = true;
end:
    // free any user preferences
    pgp_free_user_prefs(&desc->cert.prefs);
    // we don't need this as we have loaded the encrypted key into primary_sec
    transferable_key_destroy(&tkeysec);
    transferable_key_destroy(&tkeypub);
    if (!ok) {
        pgp_key_free_data(primary_pub);
        pgp_key_free_data(primary_sec);
    }
    return ok;
}

static bool
validate_keygen_subkey(rnp_keygen_subkey_desc_t *desc)
{
    if (!desc->binding.key_flags) {
        RNP_LOG("key flags are required");
        return false;
    } else if (desc->binding.key_flags & ~pgp_pk_alg_capabilities(desc->crypto.key_alg)) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }
    return true;
}

static void
keygen_subkey_merge_defaults(rnp_keygen_subkey_desc_t *desc)
{
    keygen_merge_crypto_defaults(&desc->crypto);
    if (!desc->binding.key_flags) {
        // set some default key flags if none are provided
        desc->binding.key_flags = pk_alg_default_flags(desc->crypto.key_alg);
    }
}

bool
pgp_generate_subkey(rnp_keygen_subkey_desc_t *     desc,
                    bool                           merge_defaults,
                    pgp_key_t *                    primary_sec,
                    pgp_key_t *                    primary_pub,
                    pgp_key_t *                    subkey_sec,
                    pgp_key_t *                    subkey_pub,
                    const pgp_password_provider_t *password_provider,
                    key_store_format_t             secformat)
{
    pgp_transferable_subkey_t tskeysec = {};
    pgp_transferable_subkey_t tskeypub = {};
    const pgp_key_pkt_t *     primary_seckey = NULL;
    pgp_key_pkt_t *           decrypted_primary_seckey = NULL;
    pgp_password_ctx_t        ctx = {};
    bool                      ok = false;

    // validate args
    if (!desc || !primary_sec || !primary_pub || !subkey_sec || !subkey_pub) {
        RNP_LOG("NULL args");
        goto end;
    }
    if (!pgp_key_is_primary_key(primary_sec) || !pgp_key_is_primary_key(primary_pub) ||
        !pgp_is_key_secret(primary_sec) || !pgp_is_key_public(primary_pub)) {
        RNP_LOG("invalid parameters");
        goto end;
    }
    if (pgp_get_key_type(subkey_sec) || pgp_get_key_type(subkey_pub)) {
        RNP_LOG("invalid parameters (should be zeroed)");
        goto end;
    }

    // merge some defaults in, if requested
    if (merge_defaults) {
        keygen_subkey_merge_defaults(desc);
    }

    // now validate the keygen fields
    if (!validate_keygen_subkey(desc)) {
        goto end;
    }

    ctx = {.op = PGP_OP_ADD_SUBKEY, .key = primary_sec};

    // decrypt the primary seckey if needed (for signatures)
    if (pgp_is_key_encrypted(primary_sec)) {
        decrypted_primary_seckey = pgp_decrypt_seckey(primary_sec, password_provider, &ctx);
        if (!decrypted_primary_seckey) {
            goto end;
        }
        primary_seckey = decrypted_primary_seckey;
    } else {
        primary_seckey = pgp_get_key_pkt(primary_sec);
    }

    // generate the raw key pair
    if (!pgp_generate_seckey(&desc->crypto, &tskeysec.subkey, false)) {
        goto end;
    }

    if (!transferable_subkey_bind(
          primary_seckey, &tskeysec, desc->crypto.hash_alg, &desc->binding)) {
        RNP_LOG("failed to add subkey binding signature");
        goto end;
    }

    if (!transferable_subkey_copy(&tskeypub, &tskeysec, true)) {
        RNP_LOG("failed to copy public subkey part");
        goto end;
    }

    if (!rnp_key_from_transferable_subkey(subkey_pub, &tskeypub, primary_pub)) {
        goto end;
    }

    switch (secformat) {
    case GPG_KEY_STORE:
    case KBX_KEY_STORE:
        if (!rnp_key_from_transferable_subkey(subkey_sec, &tskeysec, primary_sec)) {
            goto end;
        }
        break;
    case G10_KEY_STORE:
        if (!load_generated_g10_key(subkey_sec, &tskeysec.subkey, primary_sec, subkey_pub)) {
            RNP_LOG("failed to load generated key");
            goto end;
        }
        break;
    default:
        RNP_LOG("invalid format");
        goto end;
        break;
    }

    ok = true;
end:
    transferable_subkey_destroy(&tskeysec);
    transferable_subkey_destroy(&tskeypub);
    if (!ok) {
        pgp_key_free_data(subkey_pub);
        pgp_key_free_data(subkey_sec);
    }
    if (decrypted_primary_seckey) {
        free_key_pkt(decrypted_primary_seckey);
        free(decrypted_primary_seckey);
    }
    return ok;
}

static void
keygen_merge_defaults(rnp_keygen_primary_desc_t *primary_desc,
                      rnp_keygen_subkey_desc_t * subkey_desc)
{
    if (!primary_desc->cert.key_flags && !subkey_desc->binding.key_flags) {
        // if no flags are set for either the primary key nor subkey,
        // we can set up some typical defaults here (these are validated
        // later against the alg capabilities)
        primary_desc->cert.key_flags = PGP_KF_SIGN | PGP_KF_CERTIFY;
        subkey_desc->binding.key_flags = PGP_KF_ENCRYPT;
    }
}

static void
print_keygen_crypto(const rnp_keygen_crypto_params_t *crypto)
{
    printf("key_alg: %s (%d)\n", pgp_show_pka(crypto->key_alg), crypto->key_alg);
    if (crypto->key_alg == PGP_PKA_RSA) {
        printf("bits: %u\n", crypto->rsa.modulus_bit_len);
    } else {
        printf("curve: %d\n", crypto->ecc.curve);
    }
    printf("hash_alg: %s (%d)\n", pgp_show_hash_alg(crypto->hash_alg), crypto->hash_alg);
}

static void
print_keygen_primary(const rnp_keygen_primary_desc_t *desc)
{
    printf("Keygen (primary)\n");
    print_keygen_crypto(&desc->crypto);
}

static void
print_keygen_subkey(const rnp_keygen_subkey_desc_t *desc)
{
    printf("Keygen (subkey)\n");
    print_keygen_crypto(&desc->crypto);
}

bool
pgp_generate_keypair(rng_t *                    rng,
                     rnp_keygen_primary_desc_t *primary_desc,
                     rnp_keygen_subkey_desc_t * subkey_desc,
                     bool                       merge_defaults,
                     pgp_key_t *                primary_sec,
                     pgp_key_t *                primary_pub,
                     pgp_key_t *                subkey_sec,
                     pgp_key_t *                subkey_pub,
                     key_store_format_t         secformat)
{
    bool ok = false;

    if (rnp_get_debug(__FILE__)) {
        print_keygen_primary(primary_desc);
        print_keygen_subkey(subkey_desc);
    }

    // validate args
    if (!primary_desc || !subkey_desc || !primary_sec || !primary_pub || !subkey_sec ||
        !subkey_pub) {
        RNP_LOG("NULL args");
        goto end;
    }

    // merge some defaults in, if requested
    if (merge_defaults) {
        keygen_merge_defaults(primary_desc, subkey_desc);
    }

    // generate the primary key
    primary_desc->crypto.rng = rng;
    if (!pgp_generate_primary_key(
          primary_desc, merge_defaults, primary_sec, primary_pub, secformat)) {
        RNP_LOG("failed to generate primary key");
        goto end;
    }

    // generate the subkey
    subkey_desc->crypto.rng = rng;
    if (!pgp_generate_subkey(subkey_desc,
                             merge_defaults,
                             primary_sec,
                             primary_pub,
                             subkey_sec,
                             subkey_pub,
                             NULL,
                             secformat)) {
        RNP_LOG("failed to generate subkey");
        goto end;
    }
    ok = true;
end:
    return ok;
}
