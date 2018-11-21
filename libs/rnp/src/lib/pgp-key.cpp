/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pgp-key.h"
#include "utils.h"
#include <librekey/key_store_pgp.h>
#include <librekey/key_store_g10.h>
#include "crypto/s2k.h"
#include "fingerprint.h"

#include <rnp/rnp_sdk.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-armor.h>
#include "packet-create.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "defaults.h"

void
pgp_free_user_prefs(pgp_user_prefs_t *prefs)
{
    if (!prefs) {
        return;
    }
    FREE_ARRAY(prefs, symm_alg);
    FREE_ARRAY(prefs, hash_alg);
    FREE_ARRAY(prefs, compress_alg);
    FREE_ARRAY(prefs, key_server_pref);
    free(prefs->key_server);
    prefs->key_server = NULL;
}

static void
subsig_free(pgp_subsig_t *subsig)
{
    if (!subsig) {
        return;
    }
    pgp_free_user_prefs(&subsig->prefs);
    free_signature(&subsig->sig);
}

static void
revoke_free(pgp_revoke_t *revoke)
{
    if (!revoke) {
        return;
    }
    free(revoke->reason);
    revoke->reason = NULL;
}

/**
   \ingroup HighLevel_Keyring

   \brief Creates a new pgp_key_t struct

   \return A new pgp_key_t struct, initialised to zero.

   \note The returned pgp_key_t struct must be freed after use with pgp_key_free.
*/

pgp_key_t *
pgp_key_new(void)
{
    return (pgp_key_t *) calloc(1, sizeof(pgp_key_t));
}

static void
pgp_rawpacket_free(pgp_rawpacket_t *packet)
{
    if (packet->raw == NULL) {
        return;
    }
    free(packet->raw);
    packet->raw = NULL;
}

static void
pgp_userid_free(uint8_t **id)
{
    if (!id) {
        return;
    }
    free(*id);
    *id = NULL;
}

bool
pgp_key_from_keypkt(pgp_key_t *key, const pgp_key_pkt_t *pkt, const pgp_content_enum tag)
{
    assert(!key->pkt.version);
    assert(is_key_pkt(tag));
    assert(pkt->material.alg);
    if (pgp_keyid(key->keyid, PGP_KEY_ID_SIZE, pkt) ||
        pgp_fingerprint(&key->fingerprint, pkt) ||
        !rnp_key_store_get_key_grip(&pkt->material, key->grip)) {
        return false;
    }
    /* this is correct since changes ownership */
    key->pkt = *pkt;
    key->pkt.tag = tag;
    return true;
}

void
pgp_key_free_data(pgp_key_t *key)
{
    unsigned n;

    if (key == NULL) {
        return;
    }

    if (key->uids != NULL) {
        for (n = 0; n < key->uidc; ++n) {
            pgp_userid_free(&key->uids[n]);
        }
        free(key->uids);
        key->uids = NULL;
        key->uidc = 0;
    }

    if (key->packets != NULL) {
        for (n = 0; n < key->packetc; ++n) {
            pgp_rawpacket_free(&key->packets[n]);
        }
        free(key->packets);
        key->packets = NULL;
        key->packetc = 0;
    }

    if (key->subsigs) {
        for (n = 0; n < key->subsigc; ++n) {
            subsig_free(&key->subsigs[n]);
        }
        free(key->subsigs);
        key->subsigs = NULL;
        key->subsigc = 0;
    }

    if (key->revokes) {
        for (n = 0; n < key->revokec; ++n) {
            revoke_free(&key->revokes[n]);
        }
        free(key->revokes);
        key->revokes = NULL;
        key->revokec = 0;
    }
    revoke_free(&key->revocation);

    free(key->primary_grip);
    key->primary_grip = NULL;

    list_destroy(&key->subkey_grips);

    free_key_pkt(&key->pkt);
}

void
pgp_key_free(pgp_key_t *key)
{
    pgp_key_free_data(key);
    free(key);
}

/**
 * @brief Copy key's raw packets. If pubonly is true then dst->pkt must be populated
 */
static rnp_result_t
pgp_key_copy_raw_packets(pgp_key_t *dst, const pgp_key_t *src, bool pubonly)
{
    size_t start = 0;

    if (pubonly) {
        if (!rnp_key_add_key_rawpacket(dst, &dst->pkt)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        start = 1;
    }

    for (size_t i = start; i < src->packetc; i++) {
        if (!rnp_key_add_rawpacket(dst, &src->packets[i])) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    return RNP_SUCCESS;
}

static rnp_result_t
pgp_key_copy_g10(pgp_key_t *dst, const pgp_key_t *src, bool pubonly)
{
    rnp_result_t  ret = RNP_ERROR_GENERIC;

    if (pubonly) {
        RNP_LOG("attempt to copy public part from g10 key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    memset(dst, 0, sizeof(*dst));

    if (src->packetc != 1) {
        RNP_LOG("wrong g10 key packets");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!copy_key_pkt(&dst->pkt, &src->pkt, false)) {
        RNP_LOG("failed to copy key pkt");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (pgp_key_copy_fields(dst, src)) {
        RNP_LOG("failed to copy key fields");
        goto done;
    }

    if (pgp_key_copy_raw_packets(dst, src, false)) {
        RNP_LOG("failed to copy raw packets");
        goto done;
    }

    dst->format = G10_KEY_STORE;
    ret = RNP_SUCCESS;
done:
    if (ret) {
        pgp_key_free_data(dst);
    }
    return ret;
}

rnp_result_t
pgp_key_copy(pgp_key_t *dst, const pgp_key_t *src, bool pubonly)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    rnp_result_t tmpret;
    memset(dst, 0, sizeof(*dst));

    if (src->format == G10_KEY_STORE) {
        return pgp_key_copy_g10(dst, src, pubonly);
    }

    if (!copy_key_pkt(&dst->pkt, &src->pkt, pubonly)) {
        RNP_LOG("failed to copy key pkt");
        goto error;
    }

    if ((tmpret = pgp_key_copy_fields(dst, src))) {
        ret = tmpret;
        goto error;
    }

    if ((tmpret = pgp_key_copy_raw_packets(dst, src, pubonly))) {
        ret = tmpret;
        goto error;
    }

    return RNP_SUCCESS;
error:
    pgp_key_free_data(dst);
    return ret;
}

static rnp_result_t
pgp_userprefs_copy(pgp_user_prefs_t *dst, const pgp_user_prefs_t *src)
{
    rnp_result_t ret = RNP_ERROR_OUT_OF_MEMORY;

    memset(dst, 0, sizeof(*dst));
    if (src->symm_algc) {
        EXPAND_ARRAY_EX(dst, symm_alg, src->symm_algc);
        if (!dst->symm_algs) {
            return ret;
        }
        memcpy(dst->symm_algs, src->symm_algs, src->symm_algc);
        dst->symm_algc = src->symm_algc;
    }

    if (src->hash_algc) {
        EXPAND_ARRAY_EX(dst, hash_alg, src->hash_algc);
        if (!dst->hash_algs) {
            goto error;
        }
        memcpy(dst->hash_algs, src->hash_algs, src->hash_algc);
        dst->hash_algc = src->hash_algc;
    }

    if (src->compress_algc) {
        EXPAND_ARRAY_EX(dst, compress_alg, src->compress_algc);
        if (!dst->compress_algs) {
            goto error;
        }
        memcpy(dst->compress_algs, src->compress_algs, src->compress_algc);
        dst->compress_algc = src->compress_algc;
    }

    if (src->key_server_prefc) {
        EXPAND_ARRAY_EX(dst, key_server_pref, src->key_server_prefc);
        if (!dst->key_server_prefs) {
            goto error;
        }
        memcpy(dst->key_server_prefs, src->key_server_prefs, src->key_server_prefc);
        dst->key_server_prefc = src->key_server_prefc;
    }

    if (src->key_server) {
        size_t len = strlen((char *) src->key_server) + 1;
        dst->key_server = (uint8_t *) malloc(len);
        if (!dst->key_server) {
            goto error;
        }
        memcpy(dst->key_server, src->key_server, len);
    }

    return RNP_SUCCESS;
error:
    pgp_free_user_prefs(dst);
    return ret;
}

static rnp_result_t
pgp_subsig_copy(pgp_subsig_t *dst, const pgp_subsig_t *src)
{
    memcpy(dst, src, sizeof(*dst));
    /* signature packet */
    if (!copy_signature_packet(&dst->sig, &src->sig)) {
        memset(dst, 0, sizeof(*dst));
        return RNP_ERROR_GENERIC;
    }
    /* user prefs */
    if (pgp_userprefs_copy(&dst->prefs, &src->prefs)) {
        free_signature(&dst->sig);
        memset(dst, 0, sizeof(*dst));
        return RNP_ERROR_GENERIC;
    }

    return RNP_SUCCESS;
}

static rnp_result_t
pgp_revoke_copy(pgp_revoke_t *dst, const pgp_revoke_t *src)
{
    memcpy(dst, src, sizeof(*dst));
    if (src->reason) {
        size_t len = strlen(src->reason) + 1;
        dst->reason = (char *) malloc(len);
        if (!dst->reason) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(dst->reason, src->reason, len);
    }
    return RNP_SUCCESS;
}

rnp_result_t
pgp_key_copy_fields(pgp_key_t *dst, const pgp_key_t *src)
{
    rnp_result_t ret = RNP_ERROR_OUT_OF_MEMORY;
    rnp_result_t tmpret;

    /* uids */
    if (src->uidc) {
        EXPAND_ARRAY_EX(dst, uid, src->uidc);
        if (!dst->uids) {
            goto error;
        }
        for (size_t i = 0; i < src->uidc; i++) {
            size_t len = strlen((char *) src->uids[i]) + 1;
            dst->uids[i] = (uint8_t *) malloc(len);
            if (!dst->uids[i]) {
                goto error;
            }
            memcpy(dst->uids[i], src->uids[i], len);
            dst->uidc++;
        }
    }

    /* signatures */
    if (src->subsigs) {
        EXPAND_ARRAY_EX(dst, subsig, src->subsigc);
        if (!dst->subsigs) {
            goto error;
        }
        for (size_t i = 0; i < src->subsigc; i++) {
            tmpret = pgp_subsig_copy(&dst->subsigs[i], &src->subsigs[i]);
            if (tmpret) {
                ret = tmpret;
                goto error;
            }
            dst->subsigc++;
        }
    }

    /* revocations */
    if (src->revokes) {
        EXPAND_ARRAY_EX(dst, revoke, src->revokec);
        if (!dst->revokes) {
            goto error;
        }
        for (size_t i = 0; i < src->revokec; i++) {
            tmpret = pgp_revoke_copy(&dst->revokes[i], &src->revokes[i]);
            if (tmpret) {
                ret = tmpret;
                goto error;
            }
            dst->revokec++;
        }
    }

    /* subkey grips */
    for (list_item *grip = list_front(src->subkey_grips); grip; grip = list_next(grip)) {
        if (!list_append(&dst->subkey_grips, grip, PGP_FINGERPRINT_SIZE)) {
            goto error;
        }
    }

    /* primary grip */
    if (src->primary_grip) {
        dst->primary_grip = (uint8_t *) malloc(PGP_FINGERPRINT_SIZE);
        if (!dst->primary_grip) {
            goto error;
        }
        memcpy(dst->primary_grip, src->primary_grip, PGP_FINGERPRINT_SIZE);
    }

    /* expiration */
    dst->expiration = src->expiration;

    /* key_flags */
    dst->key_flags = src->key_flags;

    /* key id / fingerprint / grip */
    memcpy(dst->keyid, src->keyid, PGP_KEY_ID_SIZE);
    memcpy(&dst->fingerprint, &src->fingerprint, sizeof(dst->fingerprint));
    memcpy(&dst->grip, &src->grip, sizeof(dst->grip));

    /* primary uid */
    dst->uid0 = src->uid0;
    dst->uid0_set = src->uid0_set;

    /* revocation */
    dst->revoked = src->revoked;
    tmpret = pgp_revoke_copy(&dst->revocation, &src->revocation);
    if (tmpret) {
        goto error;
    }

    /* key store format */
    dst->format = src->format;

    /* key validity */
    dst->valid = src->valid;

    return RNP_SUCCESS;
error:
    pgp_key_free_data(dst);
    return ret;
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the public key in the given key.
 \param key

  \return Pointer to public key

  \note This is not a copy, do not free it after use.
*/

const pgp_key_pkt_t *
pgp_get_key_pkt(const pgp_key_t *key)
{
    return &key->pkt;
}

const pgp_key_material_t *
pgp_get_key_material(const pgp_key_t *key)
{
    return &key->pkt.material;
}

pgp_pubkey_alg_t
pgp_get_key_alg(const pgp_key_t *key)
{
    return key->pkt.alg;
}

int
pgp_get_key_type(const pgp_key_t *key)
{
    return key->pkt.tag;
}

bool
pgp_is_key_public(const pgp_key_t *key)
{
    return pgp_is_public_key_tag((pgp_content_enum) key->pkt.tag);
}

bool
pgp_is_key_secret(const pgp_key_t *key)
{
    return pgp_is_secret_key_tag((pgp_content_enum) key->pkt.tag);
}

bool
pgp_is_key_encrypted(const pgp_key_t *key)
{
    if (!pgp_is_key_secret(key)) {
        return false;
    }

    const pgp_key_pkt_t *pkt = pgp_get_key_pkt(key);
    return !pkt->material.secret;
}

bool
pgp_key_can_sign(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_SIGN;
}

bool
pgp_key_can_certify(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_CERTIFY;
}

bool
pgp_key_can_encrypt(const pgp_key_t *key)
{
    return key->key_flags & PGP_KF_ENCRYPT;
}

bool
pgp_is_secret_key_tag(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_is_public_key_tag(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_is_primary_key_tag(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_SECRET_KEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_key_is_primary_key(const pgp_key_t *key)
{
    return pgp_is_primary_key_tag((pgp_content_enum) key->pkt.tag);
}

bool
pgp_is_subkey_tag(pgp_content_enum tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
pgp_key_is_subkey(const pgp_key_t *key)
{
    return pgp_is_subkey_tag((pgp_content_enum) key->pkt.tag);
}

pgp_key_pkt_t *
pgp_decrypt_seckey_pgp(const uint8_t *      data,
                       size_t               data_len,
                       const pgp_key_pkt_t *pubkey,
                       const char *         password)
{
    pgp_source_t   src = {0};
    pgp_key_pkt_t *res = NULL;

    res = (pgp_key_pkt_t *) calloc(1, sizeof(*res));
    if (!res) {
        return NULL;
    }

    if (init_mem_src(&src, data, data_len, false)) {
        return NULL;
    }

    if (stream_parse_key(&src, res)) {
        goto error;
    }

    if (decrypt_secret_key(res, password)) {
        goto error;
    }

    src_close(&src);
    return res;
error:
    src_close(&src);
    free_key_pkt(res);
    free(res);
    return NULL;
}

/* Note that this function essentially serves two purposes.
 * - In the case of a protected key, it requests a password and
 *   uses it to decrypt the key and fill in key->key.seckey.
 * - In the case of an unprotected key, it simply re-loads
 *   key->key.seckey by parsing the key data in packets[0].
 */
pgp_key_pkt_t *
pgp_decrypt_seckey(const pgp_key_t *              key,
                   const pgp_password_provider_t *provider,
                   const pgp_password_ctx_t *     ctx)
{
    pgp_key_pkt_t *               decrypted_seckey = NULL;
    typedef struct pgp_key_pkt_t *pgp_seckey_decrypt_t(
      const uint8_t *data, size_t data_len, const pgp_key_pkt_t *pubkey, const char *password);
    pgp_seckey_decrypt_t *decryptor = NULL;
    char                  password[MAX_PASSWORD_LENGTH] = {0};

    // sanity checks
    if (!key || !pgp_is_key_secret(key) || !provider) {
        RNP_LOG("invalid args");
        goto done;
    }
    switch (key->format) {
    case GPG_KEY_STORE:
    case KBX_KEY_STORE:
        decryptor = pgp_decrypt_seckey_pgp;
        break;
    case G10_KEY_STORE:
        decryptor = g10_decrypt_seckey;
        break;
    default:
        RNP_LOG("unexpected format: %d", key->format);
        goto done;
        break;
    }
    if (!decryptor) {
        RNP_LOG("missing decrypt callback");
        goto done;
    }

    if (pgp_key_is_protected(key)) {
        // ask the provider for a password
        if (!pgp_request_password(provider, ctx, password, sizeof(password))) {
            goto done;
        }
    }
    // attempt to decrypt with the provided password
    decrypted_seckey =
      decryptor(key->packets[0].raw, key->packets[0].length, pgp_get_key_pkt(key), password);

done:
    pgp_forget(password, sizeof(password));
    return decrypted_seckey;
}

/**
\ingroup Core_Keys
\brief Get Key ID from key
\param key Key to get Key ID from
\return Pointer to Key ID inside key
*/
const uint8_t *
pgp_get_key_id(const pgp_key_t *key)
{
    return key->keyid;
}

/**
\ingroup Core_Keys
\brief How many User IDs in this key?
\param key Key to check
\return Num of user ids
*/
unsigned
pgp_get_userid_count(const pgp_key_t *key)
{
    return key->uidc;
}

/**
\ingroup Core_Keys
\brief Get indexed user id from key
\param key Key to get user id from
\param index Which key to get
\return Pointer to requested user id
*/
const uint8_t *
pgp_get_userid(const pgp_key_t *key, unsigned subscript)
{
    return key->uids[subscript];
}

/* \todo check where userid pointers are copied */
/**
\ingroup Core_Keys
\brief Copy user id, including contents
\param dst Destination User ID
\param src Source User ID
\note If dst already has a userid, it will be freed.
*/
static uint8_t *
copy_userid(uint8_t **dst, const uint8_t *src)
{
    size_t len;

    len = strlen((const char *) src);
    if (*dst) {
        free(*dst);
    }
    if ((*dst = (uint8_t *) calloc(1, len + 1)) == NULL) {
        RNP_LOG("bad alloc");
    } else {
        /* this is correct - trailing 0 is set by calloc */
        (void) memcpy(*dst, src, len);
    }
    return *dst;
}

/**
\ingroup Core_Keys
\brief Add User ID to key
\param key Key to which to add User ID
\param userid User ID to add
\return Pointer to new User ID
*/
uint8_t *
pgp_add_userid(pgp_key_t *key, const uint8_t *userid)
{
    uint8_t **uidp;

    EXPAND_ARRAY(key, uid);
    if (key->uids == NULL) {
        return NULL;
    }
    /* initialise new entry in array */
    uidp = &key->uids[key->uidc++];
    *uidp = NULL;
    /* now copy it */
    return copy_userid(uidp, userid);
}

char *
pgp_export_key(rnp_t *rnp, const pgp_key_t *key)
{
    pgp_dest_t memdst = {};
    pgp_dest_t armordst = {};
    char *     cp = NULL;
    bool       res = false;

    if (!rnp || !key) {
        return NULL;
    }

    if (init_mem_dest(&memdst, NULL, 0)) {
        return NULL;
    }
    bool is_public = pgp_is_key_public(key);
    if (init_armored_dst(
          &armordst, &memdst, is_public ? PGP_ARMORED_PUBLIC_KEY : PGP_ARMORED_SECRET_KEY)) {
        dst_close(&memdst, true);
        return NULL;
    }
    if (is_public) {
        res = pgp_write_xfer_pubkey(&armordst, key, rnp->pubring);
    } else {
        res = pgp_write_xfer_seckey(&armordst, key, rnp->secring);
    }
    if (res && !dst_finish(&armordst)) {
        dst_write(&memdst, "\0", 1);
        dst_finish(&memdst);
        cp = (char *) mem_dest_own_memory(&memdst);
    }
    dst_close(&armordst, true);
    dst_close(&memdst, true);
    return cp;
}

pgp_key_flags_t
pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_RSA_SIGN_ONLY:
        // deprecated, but still usable
        return PGP_KF_SIGN;

    case PGP_PKA_RSA_ENCRYPT_ONLY:
        // deprecated, but still usable
        return PGP_KF_ENCRYPT;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: /* deprecated */
        // These are no longer permitted per the RFC
        return PGP_KF_NONE;

    case PGP_PKA_DSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    case PGP_PKA_SM2:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_ECDH:
    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;

    default:
        RNP_LOG("unknown pk alg: %d\n", alg);
        return PGP_KF_NONE;
    }
}

bool
pgp_key_is_locked(const pgp_key_t *key)
{
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    return pgp_is_key_encrypted(key);
}

bool
pgp_key_unlock(pgp_key_t *key, const pgp_password_provider_t *provider)
{
    pgp_key_pkt_t *decrypted_seckey = NULL;

    // sanity checks
    if (!key || !provider) {
        return false;
    }
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("key is not a secret key");
        return false;
    }

    // see if it's already unlocked
    if (!pgp_key_is_locked(key)) {
        return true;
    }

    pgp_password_ctx_t ctx = {.op = PGP_OP_UNLOCK, .key = key};
    decrypted_seckey = pgp_decrypt_seckey(key, provider, &ctx);

    if (decrypted_seckey) {
        // this shouldn't really be necessary, but just in case
        forget_secret_key_fields(&key->pkt.material);
        // copy the decrypted mpis into the pgp_key_t
        key->pkt.material = decrypted_seckey->material;
        key->pkt.material.secret = true;

        free_key_pkt(decrypted_seckey);
        // free the actual structure
        free(decrypted_seckey);
        return true;
    }
    return false;
}

bool
pgp_key_lock(pgp_key_t *key)
{
    // sanity checks
    if (!key || !pgp_is_key_secret(key)) {
        RNP_LOG("invalid args");
        return false;
    }

    // see if it's already locked
    if (pgp_key_is_locked(key)) {
        return true;
    }

    forget_secret_key_fields(&key->pkt.material);
    return true;
}

static bool
write_key_to_rawpacket(pgp_key_pkt_t *    seckey,
                       pgp_rawpacket_t *  packet,
                       pgp_content_enum   type,
                       key_store_format_t format,
                       const char *       password)
{
    pgp_dest_t memdst = {};
    bool       ret = false;

    if (init_mem_dest(&memdst, NULL, 0)) {
        goto done;
    }

    // encrypt+write the key in the appropriate format
    switch (format) {
    case GPG_KEY_STORE:
    case KBX_KEY_STORE:
        if (!pgp_write_struct_seckey(&memdst, type, seckey, password)) {
            RNP_LOG("failed to write seckey");
            goto done;
        }
        break;
    case G10_KEY_STORE:
        if (!g10_write_seckey(&memdst, seckey, password)) {
            RNP_LOG("failed to write g10 seckey");
            goto done;
        }
        break;
    default:
        RNP_LOG("invalid format");
        goto done;
        break;
    }
    // free the existing data if needed
    pgp_rawpacket_free(packet);
    // take ownership of this memory
    packet->raw = (uint8_t *) mem_dest_own_memory(&memdst);
    packet->length = memdst.writeb;
    ret = true;
done:
    dst_close(&memdst, true);
    return ret;
}

bool
rnp_key_add_protection(pgp_key_t *                    key,
                       key_store_format_t             format,
                       rnp_key_protection_params_t *  protection,
                       const pgp_password_provider_t *password_provider)
{
    char password[MAX_PASSWORD_LENGTH] = {0};

    if (!key || !password_provider) {
        return false;
    }

    pgp_password_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.op = PGP_OP_PROTECT;
    ctx.key = key;

    // ask the provider for a password
    if (!pgp_request_password(password_provider, &ctx, password, sizeof(password))) {
        return false;
    }

    bool ret = pgp_key_protect(key, &key->pkt, format, protection, password);
    pgp_forget(password, sizeof(password));
    return ret;
}

bool
pgp_key_protect(pgp_key_t *                  key,
                pgp_key_pkt_t *              decrypted_seckey,
                key_store_format_t           format,
                rnp_key_protection_params_t *protection,
                const char *                 new_password)
{
    bool                        ret = false;
    rnp_key_protection_params_t default_protection = {.symm_alg = DEFAULT_PGP_SYMM_ALG,
                                                      .cipher_mode = DEFAULT_PGP_CIPHER_MODE,
                                                      .iterations = 0,
                                                      .hash_alg = DEFAULT_PGP_HASH_ALG};
    pgp_key_pkt_t *             seckey = NULL;

    // sanity check
    if (!key || !decrypted_seckey || !new_password) {
        RNP_LOG("NULL args");
        goto done;
    }
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
        goto done;
    }
    if (!decrypted_seckey->material.secret) {
        RNP_LOG("Decrypted seckey must be provided");
        goto done;
    }

    seckey = &key->pkt;
    // force these, as it's the only method we support
    seckey->sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    seckey->sec_protection.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    if (!protection) {
        protection = &default_protection;
    }

    if (!protection->symm_alg) {
        protection->symm_alg = default_protection.symm_alg;
    }
    if (!protection->cipher_mode) {
        protection->cipher_mode = default_protection.cipher_mode;
    }
    if (!protection->hash_alg) {
        protection->hash_alg = default_protection.hash_alg;
    }
    if (!protection->iterations) {
        protection->iterations =
          pgp_s2k_compute_iters(protection->hash_alg, DEFAULT_S2K_MSEC, DEFAULT_S2K_TUNE_MSEC);
    }

    seckey->sec_protection.symm_alg = protection->symm_alg;
    seckey->sec_protection.cipher_mode = protection->cipher_mode;
    seckey->sec_protection.s2k.iterations = pgp_s2k_round_iterations(protection->iterations);
    seckey->sec_protection.s2k.hash_alg = protection->hash_alg;

    // write the protected key to packets[0]
    if (!write_key_to_rawpacket(decrypted_seckey,
                                &key->packets[0],
                                (pgp_content_enum) pgp_get_key_type(key),
                                format,
                                new_password)) {
        goto done;
    }
    key->format = format;
    ret = true;

done:
    return ret;
}

bool
pgp_key_unprotect(pgp_key_t *key, const pgp_password_provider_t *password_provider)
{
    bool           ret = false;
    pgp_key_pkt_t *seckey = NULL;
    pgp_key_pkt_t *decrypted_seckey = NULL;

    // sanity check
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
        goto done;
    }
    // already unprotected
    if (!pgp_key_is_protected(key)) {
        ret = true;
        goto done;
    }

    seckey = &key->pkt;

    if (pgp_is_key_encrypted(key)) {
        pgp_password_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.op = PGP_OP_UNPROTECT;
        ctx.key = key;

        decrypted_seckey = pgp_decrypt_seckey(key, password_provider, &ctx);
        if (!decrypted_seckey) {
            goto done;
        }
        seckey = decrypted_seckey;
    }
    seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
    if (!write_key_to_rawpacket(seckey,
                                &key->packets[0],
                                (pgp_content_enum) pgp_get_key_type(key),
                                key->format,
                                NULL)) {
        goto done;
    }
    if (decrypted_seckey) {
        free_key_pkt(&key->pkt);
        copy_key_pkt(&key->pkt, decrypted_seckey, false);
        /* current logic is that unprotected key should be additionally unlocked */
        forget_secret_key_fields(&key->pkt.material);
    }
    ret = true;

done:
    free_key_pkt(decrypted_seckey);
    free(decrypted_seckey);
    return ret;
}

bool
pgp_key_is_protected(const pgp_key_t *key)
{
    // sanity check
    if (!pgp_is_key_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
    }
    return key->pkt.sec_protection.s2k.usage != PGP_S2KU_NONE;
}

static bool
key_has_userid(const pgp_key_t *key, const uint8_t *userid)
{
    for (unsigned i = 0; i < key->uidc; i++) {
        if (strcmp((char *) key->uids[i], (char *) userid) == 0) {
            return true;
        }
    }
    return false;
}

bool
pgp_key_add_userid(pgp_key_t *              key,
                   const pgp_key_pkt_t *    seckey,
                   pgp_hash_alg_t           hash_alg,
                   rnp_selfsig_cert_info_t *cert)
{
    bool                      ret = false;
    pgp_transferable_userid_t uid = {};

    // sanity checks
    if (!key || !seckey || !cert || !cert->userid[0]) {
        RNP_LOG("wrong parameters");
        goto done;
    }
    // userids are only valid for primary keys, not subkeys
    if (!pgp_key_is_primary_key(key)) {
        RNP_LOG("cannot add a userid to a subkey");
        goto done;
    }
    // see if the key already has this userid
    if (key_has_userid(key, cert->userid)) {
        RNP_LOG("key already has this userid");
        goto done;
    }
    // this isn't really valid for this format
    if (key->format == G10_KEY_STORE) {
        RNP_LOG("Unsupported key store type");
        goto done;
    }
    // We only support modifying v4 and newer keys
    if (key->pkt.version < PGP_V4) {
        RNP_LOG("adding a userid to V2/V3 key is not supported");
        goto done;
    }
    // TODO: changing the primary userid is not currently supported
    if (key->uid0_set && cert->primary) {
        RNP_LOG("changing the primary userid is not supported");
        goto done;
    }

    /* Fill the transferable userid */
    uid.uid.tag = PGP_PTAG_CT_USER_ID;
    uid.uid.uid_len = strlen((char *) cert->userid);
    if (!(uid.uid.uid = (uint8_t *) malloc(uid.uid.uid_len))) {
        RNP_LOG("allocation failed");
        goto done;
    }
    /* uid.uid.uid looks really weird */
    memcpy(uid.uid.uid, (char *) cert->userid, uid.uid.uid_len);

    if (!transferable_userid_certify(seckey, &uid, seckey, hash_alg, cert)) {
        RNP_LOG("failed to add userid certification");
        goto done;
    }

    ret = rnp_key_add_transferable_userid(key, &uid);
done:
    transferable_userid_destroy(&uid);
    return ret;
}

bool
pgp_key_write_packets(const pgp_key_t *key, pgp_memory_t *mem)
{
    if (DYNARRAY_IS_EMPTY(key, packet)) {
        return false;
    }
    for (unsigned i = 0; i < key->packetc; i++) {
        pgp_rawpacket_t *pkt = &key->packets[i];
        if (!pkt->raw || !pkt->length) {
            return false;
        }
        if (!pgp_memory_add(mem, pkt->raw, pkt->length)) {
            return false;
        }
    }
    return true;
}

pgp_key_t *
find_suitable_key(pgp_op_t            op,
                  pgp_key_t *         key,
                  pgp_key_provider_t *key_provider,
                  uint8_t             desired_usage)
{
    assert(desired_usage);
    if (!key) {
        return NULL;
    }
    if (key->key_flags & desired_usage) {
        return key;
    }
    list_item *           subkey_grip = list_front(key->subkey_grips);
    pgp_key_request_ctx_t ctx{.op = op, .secret = pgp_is_key_secret(key)};
    ctx.search.type = PGP_KEY_SEARCH_GRIP;

    while (subkey_grip) {
        memcpy(ctx.search.by.grip, subkey_grip, PGP_FINGERPRINT_SIZE);
        pgp_key_t *subkey = pgp_request_key(key_provider, &ctx);
        if (subkey && (subkey->key_flags & desired_usage)) {
            return subkey;
        }
        subkey_grip = list_next(subkey_grip);
    }
    return NULL;
}

static const pgp_signature_t *
get_subkey_binding(const pgp_key_t *subkey)
{
    // find the subkey binding signature
    for (unsigned i = 0; i < subkey->subsigc; i++) {
        const pgp_signature_t *sig = &subkey->subsigs[i].sig;

        if (sig->type == PGP_SIG_SUBKEY) {
            return sig;
        }
    }
    return NULL;
}

static pgp_key_t *
find_signer(const pgp_signature_t *   sig,
            const rnp_key_store_t *   store,
            const pgp_key_provider_t *key_provider,
            bool                      secret)
{
    pgp_key_search_t search;
    pgp_key_t *      key = NULL;

    // prefer using the issuer fingerprint when available
    if (signature_has_keyfp(sig)) {
        search.type = PGP_KEY_SEARCH_FINGERPRINT;
        signature_get_keyfp(sig, &search.by.fingerprint);
        // search the store, if provided
        if (store && (key = rnp_key_store_search(store, &search, NULL)) &&
            pgp_is_key_secret(key) == secret) {
            return key;
        }

        pgp_key_request_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.op = PGP_OP_MERGE_INFO;
        ctx.secret = secret;
        ctx.search = search;

        // try the key provider
        if ((key = pgp_request_key(key_provider, &ctx))) {
            return key;
        }
    }
    if (signature_get_keyid(sig, search.by.keyid)) {
        search.type = PGP_KEY_SEARCH_KEYID;
        // search the store, if provided
        if (store && (key = rnp_key_store_search(store, &search, NULL)) &&
            pgp_is_key_secret(key) == secret) {
            return key;
        }

        pgp_key_request_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.op = PGP_OP_MERGE_INFO;
        ctx.secret = secret;
        ctx.search = search;

        if ((key = pgp_request_key(key_provider, &ctx))) {
            return key;
        }
    }
    return NULL;
}

/* Some background related to this function:
 * Given that
 * - It doesn't really make sense to support loading a subkey for which no primary is
 *   available, because:
 *   - We can't verify the binding signature without the primary.
 *   - The primary holds the userids.
 *   - The way we currently write keyrings out, orphan keys would be omitted.
 * - The way we maintain a link between primary and sub is via:
 *   - primary_grip in the subkey
 *   - subkey_grips in the primary
 *
 * We clearly need the primary to be available when loading a subkey.
 * Rather than requiring it to be loaded first, we just use the key provider.
 */
pgp_key_t *
pgp_get_primary_key_for(const pgp_key_t *         subkey,
                        const rnp_key_store_t *   store,
                        const pgp_key_provider_t *key_provider)
{
    const pgp_signature_t *binding_sig = NULL;

    // find the subkey binding signature
    binding_sig = get_subkey_binding(subkey);
    if (!binding_sig) {
        RNP_LOG("Missing subkey binding signature for key.");
        return NULL;
    }
    if (!signature_has_keyfp(binding_sig) && !signature_has_keyid(binding_sig)) {
        RNP_LOG("No issuer information in subkey binding signature.");
        return NULL;
    }
    return find_signer(binding_sig, store, key_provider, pgp_is_key_secret(subkey));
}

pgp_hash_alg_t
pgp_hash_adjust_alg_to_key(pgp_hash_alg_t hash, const pgp_key_pkt_t *pubkey)
{
    if ((pubkey->alg != PGP_PKA_DSA) && (pubkey->alg != PGP_PKA_ECDSA)) {
        return hash;
    }

    pgp_hash_alg_t hash_min;
    if (pubkey->alg == PGP_PKA_ECDSA) {
        hash_min = ecdsa_get_min_hash(pubkey->material.ec.curve);
    } else {
        hash_min = dsa_get_min_hash(mpi_bits(&pubkey->material.dsa.q));
    }

    if (pgp_digest_length(hash) < pgp_digest_length(hash_min)) {
        return hash_min;
    }
    return hash;
}
