/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "types.h"
#include "utils.h"
#include "stream-sig.h"
#include "stream-packet.h"
#include "pgp-key.h"
#include "crypto/signatures.h"

#include <time.h>

bool
signature_matches_onepass(pgp_signature_t *sig, pgp_one_pass_sig_t *onepass)
{
    uint8_t keyid[PGP_KEY_ID_SIZE];

    if (!sig || !onepass) {
        return false;
    }

    if (!signature_get_keyid(sig, keyid)) {
        return false;
    }

    return !memcmp(keyid, onepass->keyid, PGP_KEY_ID_SIZE) && (sig->halg == onepass->halg) &&
           (sig->palg == onepass->palg) && (sig->type == onepass->type);
}

pgp_sig_subpkt_t *
signature_get_subpkt(const pgp_signature_t *sig, pgp_sig_subpacket_type_t type)
{
    pgp_sig_subpkt_t *res = NULL;

    if (!sig || (sig->version < PGP_V4)) {
        return NULL;
    }

    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        pgp_sig_subpkt_t *subpkt = (pgp_sig_subpkt_t *) sp;
        if (subpkt->type == type) {
            return subpkt;
        }
    }

    return res;
}

pgp_sig_subpkt_t *
signature_add_subpkt(pgp_signature_t *        sig,
                     pgp_sig_subpacket_type_t type,
                     size_t                   datalen,
                     bool                     reuse)
{
    pgp_sig_subpkt_t *subpkt = NULL;

    if (!sig) {
        return NULL;
    }

    if (sig->version < PGP_V4) {
        RNP_LOG("wrong signature version");
        return NULL;
    }

    if (reuse && (subpkt = signature_get_subpkt(sig, type))) {
        free(subpkt->data);
        memset(subpkt, 0, sizeof(*subpkt));
    }

    if (!subpkt) {
        pgp_sig_subpkt_t s = {(pgp_sig_subpacket_type_t) 0};
        subpkt = (pgp_sig_subpkt_t *) list_append(&sig->subpkts, &s, sizeof(s));
    }

    if (!subpkt || ((datalen > 0) && !(subpkt->data = (uint8_t *) calloc(1, datalen)))) {
        RNP_LOG("data allocation failed");
        list_remove((list_item *) subpkt);
        return NULL;
    }

    subpkt->type = type;
    subpkt->len = datalen;

    return subpkt;
}

void
signature_remove_subpkt(pgp_signature_t *sig, pgp_sig_subpkt_t *subpkt)
{
    if (list_is_member(sig->subpkts, (list_item *) subpkt)) {
        free_signature_subpkt(subpkt);
        list_remove((list_item *) subpkt);
    }
}

bool
signature_has_keyfp(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR);
}

bool
signature_get_keyfp(const pgp_signature_t *sig, pgp_fingerprint_t *fp)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !fp || (sig->version < PGP_V4)) {
        return false;
    }

    fp->length = 0;
    if (!(subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR))) {
        return false;
    }
    fp->length = subpkt->fields.issuer_fp.len;
    if (subpkt->fields.issuer_fp.len <= sizeof(fp->fingerprint)) {
        memcpy(fp->fingerprint, subpkt->fields.issuer_fp.fp, subpkt->fields.issuer_fp.len);
        return true;
    }

    return false;
}

bool
signature_set_keyfp(pgp_signature_t *sig, const pgp_fingerprint_t *fp)
{
    pgp_sig_subpkt_t *subpkt = NULL;

    if (!sig || !fp) {
        return false;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR, 1 + fp->length, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = 4;
    memcpy(subpkt->data + 1, fp->fingerprint, fp->length);
    subpkt->fields.issuer_fp.len = fp->length;
    subpkt->fields.issuer_fp.version = subpkt->data[0];
    subpkt->fields.issuer_fp.fp = subpkt->data + 1;
    return true;
}

bool
signature_has_keyid(const pgp_signature_t *sig)
{
    if (!sig) {
        return false;
    }

    return (sig->version < PGP_V4) ||
           signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_KEY_ID) ||
           signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR);
}

bool
signature_get_keyid(const pgp_signature_t *sig, uint8_t *id)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !id) {
        return false;
    }

    /* version 3 uses signature field */
    if (sig->version < PGP_V4) {
        memcpy(id, sig->signer, PGP_KEY_ID_SIZE);
        return true;
    }

    /* version 4 and up use subpackets */
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_KEY_ID))) {
        memcpy(id, subpkt->fields.issuer, PGP_KEY_ID_SIZE);
        return true;
    }
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_FPR))) {
        memcpy(id,
               subpkt->fields.issuer_fp.fp + subpkt->fields.issuer_fp.len - PGP_KEY_ID_SIZE,
               PGP_KEY_ID_SIZE);
        return true;
    }

    return false;
}

bool
signature_set_keyid(pgp_signature_t *sig, uint8_t *id)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || !id) {
        return false;
    }

    if (sig->version < PGP_V4) {
        memcpy(sig->signer, id, PGP_KEY_ID_SIZE);
        return true;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_ISSUER_KEY_ID, PGP_KEY_ID_SIZE, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 0;
    memcpy(subpkt->data, id, PGP_KEY_ID_SIZE);
    subpkt->fields.issuer = subpkt->data;
    return true;
}

uint32_t
signature_get_creation(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig) {
        return 0;
    }
    if (sig->version < PGP_V4) {
        return sig->creation_time;
    }
    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_CREATION_TIME))) {
        return subpkt->fields.create;
    }

    return 0;
}

bool
signature_set_creation(pgp_signature_t *sig, uint32_t ctime)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig) {
        return false;
    }
    if (sig->version < PGP_V4) {
        sig->creation_time = ctime;
        return true;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_CREATION_TIME, 4, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    STORE32BE(subpkt->data, ctime);
    subpkt->fields.create = ctime;
    return true;
}

uint32_t
signature_get_expiration(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_EXPIRATION_TIME))) {
        return subpkt->fields.expiry;
    }

    return 0;
}

bool
signature_set_expiration(pgp_signature_t *sig, uint32_t etime)
{
    pgp_sig_subpkt_t *subpkt;

    if (!sig || (sig->version < PGP_V4)) {
        return false;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_EXPIRATION_TIME, 4, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    STORE32BE(subpkt->data, etime);
    subpkt->fields.expiry = etime;
    return true;
}

bool
signature_has_key_expiration(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEY_EXPIRY);
}

uint32_t
signature_get_key_expiration(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEY_EXPIRY))) {
        return subpkt->fields.expiry;
    }

    return 0;
}

bool
signature_set_key_expiration(pgp_signature_t *sig, uint32_t etime)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_KEY_EXPIRY, 4, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    STORE32BE(subpkt->data, etime);
    subpkt->fields.expiry = etime;
    return true;
}

bool
signature_has_key_flags(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEY_FLAGS);
}

uint8_t
signature_get_key_flags(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEY_FLAGS))) {
        return subpkt->fields.key_flags;
    }

    return 0;
}

bool
signature_set_key_flags(pgp_signature_t *sig, uint8_t flags)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_KEY_FLAGS, 1, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = flags;
    subpkt->fields.key_flags = flags;
    return true;
}

bool
signature_get_primary_uid(pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_PRIMARY_USER_ID))) {
        return subpkt->fields.primary_uid;
    }

    return false;
}

bool
signature_set_primary_uid(pgp_signature_t *sig, bool primary)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_PRIMARY_USER_ID, 1, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = primary;
    subpkt->fields.primary_uid = primary;
    return true;
}

static bool
signature_set_preferred_algs(pgp_signature_t *        sig,
                             uint8_t                  algs[],
                             size_t                   len,
                             pgp_sig_subpacket_type_t type)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, type, len, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    memcpy(subpkt->data, algs, len);
    subpkt->fields.preferred.arr = subpkt->data;
    subpkt->fields.preferred.len = len;
    return true;
}

static bool
signature_get_preferred_algs(const pgp_signature_t *  sig,
                             uint8_t **               algs,
                             size_t *                 len,
                             pgp_sig_subpacket_type_t type)
{
    pgp_sig_subpkt_t *subpkt;

    if (!algs || !len) {
        return false;
    }

    if ((subpkt = signature_get_subpkt(sig, type))) {
        *algs = subpkt->fields.preferred.arr;
        *len = subpkt->fields.preferred.len;
        return true;
    }

    return false;
}

bool
signature_has_preferred_symm_algs(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_PREFERRED_SKA);
}

bool
signature_get_preferred_symm_algs(const pgp_signature_t *sig, uint8_t **algs, size_t *count)
{
    return signature_get_preferred_algs(sig, algs, count, PGP_SIG_SUBPKT_PREFERRED_SKA);
}

bool
signature_set_preferred_symm_algs(pgp_signature_t *sig, uint8_t algs[], size_t len)
{
    return signature_set_preferred_algs(sig, algs, len, PGP_SIG_SUBPKT_PREFERRED_SKA);
}

bool
signature_has_preferred_hash_algs(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_PREFERRED_HASH);
}

bool
signature_get_preferred_hash_algs(const pgp_signature_t *sig, uint8_t **algs, size_t *count)
{
    return signature_get_preferred_algs(sig, algs, count, PGP_SIG_SUBPKT_PREFERRED_HASH);
}

bool
signature_set_preferred_hash_algs(pgp_signature_t *sig, uint8_t algs[], size_t len)
{
    return signature_set_preferred_algs(sig, algs, len, PGP_SIG_SUBPKT_PREFERRED_HASH);
}

bool
signature_has_preferred_z_algs(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_PREF_COMPRESS);
}

bool
signature_get_preferred_z_algs(const pgp_signature_t *sig, uint8_t **algs, size_t *count)
{
    return signature_get_preferred_algs(sig, algs, count, PGP_SIG_SUBPKT_PREF_COMPRESS);
}

bool
signature_set_preferred_z_algs(pgp_signature_t *sig, uint8_t algs[], size_t len)
{
    return signature_set_preferred_algs(sig, algs, len, PGP_SIG_SUBPKT_PREF_COMPRESS);
}

bool
signature_has_key_server_prefs(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEYSERV_PREFS);
}

uint8_t
signature_get_key_server_prefs(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_KEYSERV_PREFS))) {
        return subpkt->data[0];
    }

    return 0;
}

bool
signature_set_key_server_prefs(pgp_signature_t *sig, uint8_t prefs)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_KEYSERV_PREFS, 1, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = prefs;
    subpkt->fields.ks_prefs.no_modify = prefs & 0x80;
    return true;
}

bool
signature_set_preferred_key_server(pgp_signature_t *sig, const char *uri)
{
    pgp_sig_subpkt_t *subpkt;
    size_t            len = strlen(uri);

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_PREF_KEYSERV, len, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    memcpy(subpkt->data, uri, len);
    subpkt->fields.preferred_ks.uri = (char *) subpkt->data;
    subpkt->fields.preferred_ks.len = len;
    return true;
}

bool
signature_has_trust(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_TRUST);
}

bool
signature_get_trust(const pgp_signature_t *sig, uint8_t *level, uint8_t *amount)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_TRUST))) {
        if (level) {
            *level = subpkt->fields.trust.level;
        }
        if (amount) {
            *amount = subpkt->fields.trust.amount;
        }
        return true;
    }

    return false;
}

bool
signature_set_trust(pgp_signature_t *sig, uint8_t level, uint8_t amount)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_TRUST, 2, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = level;
    subpkt->data[1] = amount;
    subpkt->fields.trust.level = level;
    subpkt->fields.trust.amount = amount;
    return true;
}

bool
signature_get_revocable(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_REVOCABLE))) {
        return subpkt->fields.revocable;
    }

    return true;
}

bool
signature_set_revocable(pgp_signature_t *sig, bool revocable)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_REVOCABLE, 1, true);
    if (!subpkt) {
        return false;
    }

    subpkt->parsed = 1;
    subpkt->hashed = 1;
    subpkt->data[0] = revocable;
    subpkt->fields.revocable = revocable;
    return true;
}

bool
signature_set_features(pgp_signature_t *sig, uint8_t features)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_FEATURES, 1, true);
    if (!subpkt) {
        return false;
    }

    subpkt->hashed = 1;
    subpkt->data[0] = features;
    return signature_parse_subpacket(subpkt);
}

bool
signature_set_signer_uid(pgp_signature_t *sig, uint8_t *uid, size_t len)
{
    pgp_sig_subpkt_t *subpkt;

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_SIGNERS_USER_ID, len, true);
    if (!subpkt) {
        return false;
    }

    subpkt->hashed = 1;
    memcpy(subpkt->data, uid, len);
    return signature_parse_subpacket(subpkt);
}

bool
signature_set_embedded_sig(pgp_signature_t *sig, pgp_signature_t *esig)
{
    pgp_sig_subpkt_t *subpkt = NULL;
    pgp_dest_t        memdst = {};
    pgp_source_t      memsrc = {};
    ssize_t           len = 0;
    bool              res = false;

    if (init_mem_dest(&memdst, NULL, 0)) {
        RNP_LOG("alloc failed");
        return false;
    }
    if (!stream_write_signature(esig, &memdst)) {
        RNP_LOG("failed to write signature");
        goto finish;
    }
    if (init_mem_src(&memsrc, mem_dest_get_memory(&memdst), memdst.writeb, false)) {
        RNP_LOG("failed to init mem src");
        goto finish;
    }
    if ((len = stream_read_pkt_len(&memsrc)) < 0) {
        RNP_LOG("wrong pkt len");
        goto finish;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE, len, true);
    if (!subpkt) {
        RNP_LOG("failed to add subpkt");
        goto finish;
    }

    subpkt->hashed = 0;
    if (src_read(&memsrc, subpkt->data, len) != len) {
        RNP_LOG("failed to read back signature");
        goto finish;
    }
    if (!copy_signature_packet(&subpkt->fields.sig, esig)) {
        RNP_LOG("failed to copy signature");
        goto finish;
    }
    subpkt->parsed = 1;
    res = true;
finish:
    if (!res && subpkt) {
        signature_remove_subpkt(sig, subpkt);
    }
    src_close(&memsrc);
    dst_close(&memdst, true);
    return res;
}

bool
signature_add_notation_data(pgp_signature_t *sig,
                            bool             readable,
                            const char *     name,
                            const char *     value)
{
    pgp_sig_subpkt_t *subpkt;
    size_t            nlen, vlen;

    nlen = strlen(name);
    vlen = strlen(value);

    if ((nlen > 0xffff) || (vlen > 0xffff)) {
        RNP_LOG("wrong length");
        return false;
    }

    subpkt = signature_add_subpkt(sig, PGP_SIG_SUBPKT_NOTATION_DATA, 8 + nlen + vlen, false);
    if (!subpkt) {
        return false;
    }

    subpkt->hashed = 1;
    if (readable) {
        subpkt->data[0] = 0x80;
        subpkt->fields.notation.flags[0] = 0x80;
    }
    write_uint16(subpkt->data + 4, nlen);
    memcpy(subpkt->data + 6, name, nlen);
    write_uint16(subpkt->data + 6 + nlen, vlen);
    memcpy(subpkt->data + 8 + nlen, value, vlen);
    return signature_parse_subpacket(subpkt);
}

bool
signature_has_key_server(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_PREF_KEYSERV);
}

char *
signature_get_key_server(const pgp_signature_t *sig)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_PREF_KEYSERV))) {
        char *res = (char *) malloc(subpkt->len + 1);
        if (res) {
            memcpy(res, subpkt->data, subpkt->len);
            res[subpkt->len] = '\0';
        }
        return res;
    }

    return NULL;
}

bool
signature_has_revocation_reason(const pgp_signature_t *sig)
{
    return signature_get_subpkt(sig, PGP_SIG_SUBPKT_REVOCATION_REASON);
}

bool
signature_get_revocation_reason(const pgp_signature_t *sig, uint8_t *code, char **reason)
{
    pgp_sig_subpkt_t *subpkt;

    if ((subpkt = signature_get_subpkt(sig, PGP_SIG_SUBPKT_REVOCATION_REASON))) {
        if (code) {
            *code = subpkt->fields.revocation_reason.code;
        }
        if (reason) {
            size_t len = subpkt->fields.revocation_reason.len;
            *reason = (char *) malloc(len + 1);
            if (!*reason) {
                RNP_LOG("alloc failed");
                return false;
            }
            memcpy(*reason, subpkt->fields.revocation_reason.str, len);
            *reason[len] = '\0';
        }
        return true;
    }

    return false;
}

bool
signature_fill_hashed_data(pgp_signature_t *sig)
{
    pgp_packet_body_t hbody;
    bool              res;

    if (!sig) {
        RNP_LOG("null signature");
        return false;
    }
    /* we don't have a need to write v2-v3 signatures */
    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }

    if (!init_packet_body(&hbody, 0)) {
        RNP_LOG("allocation failed");
        return false;
    }

    if (sig->version < PGP_V4) {
        res = add_packet_body_byte(&hbody, sig->type) &&
              add_packet_body_uint32(&hbody, sig->creation_time);
    } else {
        res = add_packet_body_byte(&hbody, sig->version) &&
              add_packet_body_byte(&hbody, sig->type) &&
              add_packet_body_byte(&hbody, sig->palg) &&
              add_packet_body_byte(&hbody, sig->halg) &&
              add_packet_body_subpackets(&hbody, sig, true);
    }

    if (res) {
        /* get ownership on body data */
        sig->hashed_data = hbody.data;
        sig->hashed_len = hbody.len;
        return res;
    }

    free_packet_body(&hbody);
    return res;
}

bool
signature_hash_key(const pgp_key_pkt_t *key, pgp_hash_t *hash)
{
    uint8_t       hdr[3] = {0x99, 0x00, 0x00};
    pgp_key_pkt_t keycp = {0};
    bool          res = false;

    if (!key || !hash) {
        RNP_LOG("null key or hash");
        return false;
    }

    if (key->hashed_data) {
        write_uint16(hdr + 1, key->hashed_len);
        return !pgp_hash_add(hash, hdr, 3) &&
               !pgp_hash_add(hash, key->hashed_data, key->hashed_len);
    }

    /* call self recursively if hashed data is not filled, to overcome const restriction */
    res = copy_key_pkt(&keycp, key, true) && key_fill_hashed_data(&keycp) &&
          signature_hash_key(&keycp, hash);
    free_key_pkt(&keycp);
    return res;
}

bool
signature_hash_userid(const pgp_userid_pkt_t *uid, pgp_hash_t *hash, pgp_version_t sigver)
{
    uint8_t hdr[5] = {0};

    if (!uid || !hash) {
        RNP_LOG("null uid or hash");
        return false;
    }

    if (sigver < PGP_V4) {
        return !pgp_hash_add(hash, uid->uid, uid->uid_len);
    }

    switch (uid->tag) {
    case PGP_PTAG_CT_USER_ID:
        hdr[0] = 0xB4;
        break;
    case PGP_PTAG_CT_USER_ATTR:
        hdr[0] = 0xD1;
        break;
    default:
        RNP_LOG("wrong uid");
        return false;
    }
    STORE32BE(hdr + 1, uid->uid_len);

    return !pgp_hash_add(hash, hdr, 5) && !pgp_hash_add(hash, uid->uid, uid->uid_len);
}

bool
signature_hash_signature(pgp_signature_t *sig, pgp_hash_t *hash)
{
    uint8_t hdr[5] = {0x88, 0x00, 0x00, 0x00, 0x00};

    if (!sig || !hash) {
        RNP_LOG("null sig or hash");
        return false;
    }

    if (!sig->hashed_data) {
        RNP_LOG("hashed data not filled");
        return false;
    }

    STORE32BE(hdr + 1, sig->hashed_len);
    return !pgp_hash_add(hash, hdr, 5) &&
           !pgp_hash_add(hash, sig->hashed_data, sig->hashed_len);
}

bool
signature_hash_certification(const pgp_signature_t * sig,
                             const pgp_key_pkt_t *   key,
                             const pgp_userid_pkt_t *userid,
                             pgp_hash_t *            hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash) && signature_hash_userid(userid, hash, sig->version);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

bool
signature_hash_binding(const pgp_signature_t *sig,
                       const pgp_key_pkt_t *  key,
                       const pgp_key_pkt_t *  subkey,
                       pgp_hash_t *           hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash) && signature_hash_key(subkey, hash);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

bool
signature_hash_direct(const pgp_signature_t *sig, const pgp_key_pkt_t *key, pgp_hash_t *hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

rnp_result_t
signature_validate_certification(const pgp_signature_t *   sig,
                                 const pgp_key_pkt_t *     key,
                                 const pgp_userid_pkt_t *  uid,
                                 const pgp_key_material_t *signer)
{
    pgp_hash_t hash = {0};

    if (!signature_hash_certification(sig, key, uid, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_validate(sig, signer, &hash);
}

rnp_result_t
signature_validate_binding(const pgp_signature_t *sig,
                           const pgp_key_pkt_t *  key,
                           const pgp_key_pkt_t *  subkey)
{
    pgp_hash_t   hash = {};
    pgp_hash_t   hashcp = {};
    rnp_result_t res = RNP_ERROR_SIGNATURE_INVALID;

    if (!signature_hash_binding(sig, key, subkey, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!pgp_hash_copy(&hashcp, &hash)) {
        RNP_LOG("hash copy failed");
        return RNP_ERROR_BAD_STATE;
    }

    res = signature_validate(sig, &key->material, &hash);

    /* check primary key binding signature if any */
    if (!res && (signature_get_key_flags(sig) & PGP_KF_SIGN)) {
        pgp_sig_subpkt_t *subpkt =
          signature_get_subpkt(sig, PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE);
        if (!subpkt) {
            RNP_LOG("error! no primary key binding signature");
            res = RNP_ERROR_SIGNATURE_INVALID;
            goto finish;
        }
        if (!subpkt->parsed) {
            RNP_LOG("invalid embedded signature subpacket");
            res = RNP_ERROR_SIGNATURE_INVALID;
            goto finish;
        }
        if (subpkt->fields.sig.type != PGP_SIG_PRIMARY) {
            RNP_LOG("invalid primary key binding signature");
            res = RNP_ERROR_SIGNATURE_INVALID;
            goto finish;
        }
        if (subpkt->fields.sig.version < PGP_V4) {
            RNP_LOG("invalid primary key binding signature version");
            res = RNP_ERROR_SIGNATURE_INVALID;
            goto finish;
        }
        res = signature_validate(&subpkt->fields.sig, &subkey->material, &hashcp);
    }
finish:
    pgp_hash_finish(&hashcp, NULL);
    return res;
}

rnp_result_t
signature_validate_direct(const pgp_signature_t *   sig,
                          const pgp_key_pkt_t *     key,
                          const pgp_key_material_t *signer)
{
    pgp_hash_t hash = {0};

    if (!signature_hash_direct(sig, key, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_validate(sig, signer, &hash);
}

rnp_result_t
signature_check(pgp_signature_info_t *sinfo, pgp_hash_t *hash)
{
    time_t            now;
    uint32_t          create, expiry, kcreate;
    pgp_fingerprint_t fp = {};
    rnp_result_t      ret = RNP_ERROR_SIGNATURE_INVALID;

    sinfo->no_signer = !sinfo->signer;
    sinfo->valid = false;
    sinfo->expired = false;

    if (!sinfo->sig) {
        ret = RNP_ERROR_NULL_POINTER;
        goto finish;
    }

    if (!sinfo->signer) {
        ret = RNP_ERROR_NO_SUITABLE_KEY;
        goto finish;
    }

    /* Validate signature itself */
    if (sinfo->signer->valid) {
        sinfo->valid =
          !signature_validate(sinfo->sig, pgp_get_key_material(sinfo->signer), hash);
    } else {
        sinfo->valid = false;
        RNP_LOG("invalid or untrusted key");
    }

    /* Check signature's expiration time */
    now = time(NULL);
    create = signature_get_creation(sinfo->sig);
    expiry = signature_get_expiration(sinfo->sig);
    if (create > now) {
        /* signature created later then now */
        RNP_LOG("signature created %d seconds in future", (int) (create - now));
        sinfo->expired = true;
    }
    if (create && expiry && (create + expiry < now)) {
        /* signature expired */
        RNP_LOG("signature expired");
        sinfo->expired = true;
    }

    /* check key creation time vs signature creation */
    kcreate = pgp_get_key_pkt(sinfo->signer)->creation_time;
    if (kcreate > create) {
        RNP_LOG("key is newer than signature");
        sinfo->valid = false;
    }

    /* check whether key was not expired when sig created */
    if (sinfo->signer->expiration && (kcreate + sinfo->signer->expiration < create)) {
        RNP_LOG("signature made after key expiration");
        sinfo->valid = false;
    }

    /* Check signer's fingerprint */
    if (signature_get_keyfp(sinfo->sig, &fp) &&
        !fingerprint_equal(&fp, &sinfo->signer->fingerprint)) {
        RNP_LOG("issuer fingerprint doesn't match signer's one");
        sinfo->valid = false;
    }

    if (sinfo->expired && sinfo->valid) {
        ret = RNP_ERROR_SIGNATURE_EXPIRED;
    } else {
        ret = sinfo->valid ? RNP_SUCCESS : RNP_ERROR_SIGNATURE_INVALID;
    }
finish:
    pgp_hash_finish(hash, NULL);
    return ret;
}

rnp_result_t
signature_check_certification(pgp_signature_info_t *  sinfo,
                              const pgp_key_pkt_t *   key,
                              const pgp_userid_pkt_t *uid)
{
    pgp_hash_t   hash = {};
    uint8_t      keyid[PGP_KEY_ID_SIZE];
    rnp_result_t res = RNP_ERROR_SIGNATURE_INVALID;

    if (!signature_hash_certification(sinfo->sig, key, uid, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    res = signature_check(sinfo, &hash);

    if (res) {
        return res;
    }

    /* check key expiration time, only for self-signature. While sinfo->expired tells about
       the signature expiry, we'll use it for bkey expiration as well */
    if (signature_get_keyid(sinfo->sig, keyid) &&
        !memcmp(keyid, sinfo->signer->keyid, PGP_KEY_ID_SIZE)) {
        uint32_t expiry = signature_get_key_expiration(sinfo->sig);
        uint32_t now = time(NULL);

        if (expiry && (key->creation_time + expiry < now)) {
            RNP_LOG("key expired %d seconds ago", (int) now - expiry - key->creation_time);
            sinfo->expired = true;
        }
    }

    return res;
}

rnp_result_t
signature_check_binding(pgp_signature_info_t *sinfo,
                        const pgp_key_pkt_t * key,
                        const pgp_key_pkt_t * subkey)
{
    pgp_hash_t   hash = {};
    pgp_hash_t   hashcp = {};
    rnp_result_t res = RNP_ERROR_SIGNATURE_INVALID;

    if (!signature_hash_binding(sinfo->sig, key, subkey, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!pgp_hash_copy(&hashcp, &hash)) {
        RNP_LOG("hash copy failed");
        return RNP_ERROR_BAD_STATE;
    }

    res = signature_check(sinfo, &hash);

    /* check subkey expiration time. While sinfo->expired tells about the signature expiry,
       we'll use it for subkey expiration as well */
    if (!res) {
        uint32_t expiry = signature_get_key_expiration(sinfo->sig);
        uint32_t now = time(NULL);

        if (expiry && (subkey->creation_time + expiry < now)) {
            RNP_LOG("subkey expired %d seconds ago",
                    (int) now - expiry - subkey->creation_time);
            sinfo->expired = true;
        }
    }

    /* check primary key binding signature if any */
    if (!res && (signature_get_key_flags(sinfo->sig) & PGP_KF_SIGN)) {
        res = RNP_ERROR_SIGNATURE_INVALID;
        sinfo->valid = false;
        pgp_sig_subpkt_t *subpkt =
          signature_get_subpkt(sinfo->sig, PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE);
        if (!subpkt) {
            RNP_LOG("error! no primary key binding signature");
            goto finish;
        }
        if (!subpkt->parsed) {
            RNP_LOG("invalid embedded signature subpacket");
            goto finish;
        }
        if (subpkt->fields.sig.type != PGP_SIG_PRIMARY) {
            RNP_LOG("invalid primary key binding signature");
            goto finish;
        }
        if (subpkt->fields.sig.version < PGP_V4) {
            RNP_LOG("invalid primary key binding signature version");
            goto finish;
        }
        res = signature_validate(&subpkt->fields.sig, &subkey->material, &hashcp);
        sinfo->valid = !res;
    }
finish:
    pgp_hash_finish(&hashcp, NULL);
    return res;
}

rnp_result_t
signature_check_direct(pgp_signature_info_t *sinfo, const pgp_key_pkt_t *key)
{
    pgp_hash_t hash = {};

    if (!signature_hash_direct(sinfo->sig, key, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_check(sinfo, &hash);
}

bool
check_signatures_info(const pgp_signatures_info_t *info)
{
    return list_length(info->sigs) && !info->unknownc && !info->invalidc && !info->expiredc &&
           (info->validc == list_length(info->sigs));
}

void
free_signatures_info(pgp_signatures_info_t *info)
{
    for (list_item *si = list_front(info->sigs); si; si = list_next(si)) {
        pgp_signature_info_t *sinfo = (pgp_signature_info_t *) si;
        free_signature(sinfo->sig);
        free(sinfo->sig);
    }
    list_destroy(&info->sigs);
    memset(info, 0, sizeof(*info));
}
