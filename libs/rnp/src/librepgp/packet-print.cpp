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

/*
 * ! \file \brief Standard API print functions
 */
#include "config.h"

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: packet-print.c,v 1.42 2012/02/22 06:29:40 agc Exp $");
#endif

#ifdef RNP_DEBUG
#include <assert.h>
#endif

#include <string.h>
#include <rnp/rnp_sdk.h>
#include "crypto/ec.h"
#include "packet-print.h"
#include "packet-show.h"
#include "stream-sig.h"
#include "pgp-key.h"
#include "utils.h"
#include "time.h"

#define F_REVOKED 1

#define F_PRINTSIGS 2

#define PTIMESTR_LEN 10

#define SIGNATURE_PADDING "          "

/* static functions */
static bool format_key_usage(char *buffer, size_t size, uint8_t flags);

// returns bitlength of a key
size_t
key_bitlength(const pgp_key_material_t *key)
{
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return 8 * mpi_bytes(&key->rsa.n);
    case PGP_PKA_DSA:
        return 8 * mpi_bytes(&key->dsa.p);
    case PGP_PKA_ELGAMAL:
        return 8 * mpi_bytes(&key->eg.y);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        // bn_num_bytes returns value <= curve order
        const ec_curve_desc_t *curve = get_curve_desc(key->ec.curve);
        return curve ? curve->bitlen : 0;
    }
    default:
        RNP_LOG("Unknown public key alg in key_bitlength");
        return -1;
    }
}

static bool
key_expires(const pgp_key_t *key)
{
    return key->expiration > 0;
}

static bool
key_has_expired(const pgp_key_t *key, time_t t)
{
    return (key->expiration > 0) &&
           (pgp_get_key_pkt(key)->creation_time + key->expiration < t);
}

/* Write the time as a string to buffer `dest`. The time string is guaranteed
 * to be PTIMESTR_LEN characters long.
 */
static char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);

    /* Remember - we guarantee that the time string will be PTIMESTR_LEN
     * characters long.
     */
    snprintf(dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
#ifdef RNP_DEBUG
    assert(stelen(dest) == PTIMESTR_LEN);
#endif
    return dest;
}

/* Print the sub key binding signature info. */
static int
psubkeybinding(char *buf, size_t size, const pgp_key_t *key, const char *expired)
{
    char keyid[512];
    char t[32];
    char key_usage[8];

    format_key_usage(key_usage, sizeof(key_usage), key->key_flags);
    return snprintf(buf,
                    size,
                    "encryption %zu/%s %s %s [%s] %s\n",
                    key_bitlength(pgp_get_key_material(key)),
                    pgp_show_pka(pgp_get_key_alg(key)),
                    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, ""),
                    ptimestr(t, sizeof(t), (time_t) pgp_get_key_pkt(key)->creation_time),
                    key_usage,
                    expired);
}

/* Searches a key's revocation list for the given key UID. If it is found its
 * index is returned, otherwise -1 is returned.
 */
static int
isrevoked(const pgp_key_t *key, unsigned uid)
{
    for (size_t i = 0; i < pgp_key_get_revoke_count(key); i++) {
        if (pgp_key_get_revoke(key, i)->uid == uid) {
            return i;
        }
    }
    return -1;
}

static bool
iscompromised(const pgp_key_t *key, unsigned uid)
{
    int r = isrevoked(key, uid);

    return (r >= 0) && (pgp_key_get_revoke(key, r)->code == PGP_REVOCATION_COMPROMISED);
}

/* Formats a public key expiration notice. Assumes that the public key
 * expires. Return 1 on success and 0 on failure.
 */
static bool
format_pubkey_expiration_notice(char *buffer, const pgp_key_t *key, time_t time, size_t size)
{
    char *buffer_end = buffer + size;

    buffer[0] = '\0';

    /* Write the opening bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "[");
    if (buffer >= buffer_end) {
        return false;
    }

    /* Write the expiration state label. */
    buffer += snprintf(
      buffer, buffer_end - buffer, "%s ", key_has_expired(key, time) ? "EXPIRED" : "EXPIRES");

    /* Ensure that there will be space for tihe time. */
    if (buffer_end - buffer < PTIMESTR_LEN + 1) {
        return false;
    }

    /* Write the expiration time. */
    ptimestr(
      buffer, buffer_end - buffer, pgp_get_key_pkt(key)->creation_time + key->expiration);
    buffer += PTIMESTR_LEN;
    if (buffer >= buffer_end) {
        return false;
    }

    /* Write the closing bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "]");
    if (buffer >= buffer_end) {
        return false;
    }

    return true;
}

static int
format_uid_line(char *buffer, const char *uid, size_t size, int flags)
{
    return snprintf(buffer,
                    size,
                    "uid    %s%s%s\n",
                    flags & F_PRINTSIGS ? "" : SIGNATURE_PADDING,
                    uid,
                    flags & F_REVOKED ? " [REVOKED]" : "");
}

/* TODO: Consider replacing `trustkey` with an optional `uid` parameter. */
/* TODO: Consider passing only signer_id and creation. */
static int
format_sig_line(char *                 buffer,
                const pgp_signature_t *sig,
                const pgp_key_t *      trustkey,
                size_t                 size)
{
    char    keyid[PGP_KEY_ID_SIZE * 3];
    char    time[PTIMESTR_LEN + sizeof(char)];
    uint8_t signer[PGP_KEY_ID_SIZE];

    ptimestr(time, sizeof(time), signature_get_creation(sig));
    signature_get_keyid(sig, signer);
    return snprintf(buffer,
                    size,
                    "sig        %s  %s  %s\n",
                    rnp_strhexdump(keyid, signer, PGP_KEY_ID_SIZE, ""),
                    time,
                    trustkey != NULL ? (char *) pgp_get_primary_userid(trustkey) :
                                       "[unknown]");
}

static int
format_subsig_line(char *              buffer,
                   const pgp_key_t *   key,
                   const pgp_key_t *   trustkey,
                   const pgp_subsig_t *subsig,
                   size_t              size)
{
    char expired[128];
    int  n = 0;

    expired[0] = '\0';
    if (key_expires(key)) {
        format_pubkey_expiration_notice(expired, key, time(NULL), sizeof(expired));
    }
    if (subsig->sig.version == 4 && subsig->sig.type == PGP_SIG_SUBKEY) {
        /* XXX: The character count of this was previously ignored.
         *      This seems to have been incorrect, but if not
         *      you should revert it.
         */
        n += psubkeybinding(buffer, size, key, expired);
    } else {
        n += format_sig_line(buffer, &subsig->sig, trustkey, size);
    }

    return n;
}

static int
format_uid_notice(char *                 buffer,
                  const rnp_key_store_t *keyring,
                  const pgp_key_t *      key,
                  unsigned               uid,
                  size_t                 size,
                  int                    flags)
{
    unsigned n = 0;

    if (isrevoked(key, uid) >= 0)
        flags |= F_REVOKED;

    n += format_uid_line(buffer, pgp_get_userid(key, uid), size, flags);

    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        pgp_subsig_t *   subsig = pgp_key_get_subsig(key, i);
        const pgp_key_t *trustkey;

        /* TODO: To me this looks like an unnecessary consistency
         *       check that should be performed upstream before
         *       passing the information down here. Maybe not,
         *       if anyone can shed alternate light on this
         *       that would be great.
         */
        if (flags & F_PRINTSIGS && subsig->uid != uid) {
            continue;

            /* TODO: I'm also unsure about this one. */
        } else if (!(subsig->sig.version == 4 && subsig->sig.type == PGP_SIG_SUBKEY &&
                     uid == pgp_get_userid_count(key) - 1)) {
            continue;
        }

        uint8_t signer[PGP_KEY_ID_SIZE] = {0};
        signature_get_keyid(&subsig->sig, signer);
        trustkey = rnp_key_store_get_key_by_id(keyring, signer, NULL);

        n += format_subsig_line(buffer + n, key, trustkey, subsig, size - n);
    }

    return n;
}

static bool
format_key_usage(char *buffer, size_t size, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "E"},
      {PGP_KF_SIGN, "S"},
      {PGP_KF_CERTIFY, "C"},
      {PGP_KF_AUTH, "A"},
    };

    *buffer = '\0';
    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            const size_t current_length = strlen(buffer);
            if (current_length == size - 1) {
                return false;
            }
            strncat(buffer, flags_map[i].string, size - current_length - 1);
        }
    }
    return true;
}

static bool
format_key_usage_json(json_object *arr, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "encrypt"},
      {PGP_KF_SIGN, "sign"},
      {PGP_KF_CERTIFY, "certify"},
      {PGP_KF_AUTH, "authenticate"},
    };

    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            json_object *str = json_object_new_string(flags_map[i].string);
            if (!str) {
                return false;
            }
            if (json_object_array_add(arr, str) != 0) {
                return false;
            }
        }
    }
    return true;
}

#ifndef KB
#define KB(x) ((x) *1024)
#endif

/* XXX: Why 128KiB? */
#define NOTICE_BUFFER_SIZE KB(128)

/* print into a string (malloc'ed) the pubkeydata */
int
pgp_sprint_key(const rnp_key_store_t *keyring,
               const pgp_key_t *      key,
               char **                buf,
               const char *           header,
               const int              psigs)
{
    unsigned i;
    time_t   now;
    char *   uid_notices;
    int      uid_notices_offset = 0;
    char *   string;
    int      total_length;
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    char     expiration_notice[128];
    char     creation[32];
    char     key_usage[8];

    if (key->revoked) {
        return -1;
    }

    now = time(NULL);

    if (key_expires(key)) {
        format_pubkey_expiration_notice(
          expiration_notice, key, now, sizeof(expiration_notice));
    } else {
        expiration_notice[0] = '\0';
    }

    uid_notices = (char *) malloc(NOTICE_BUFFER_SIZE);
    if (uid_notices == NULL) {
        return -1;
    }

    /* TODO: Perhaps this should index key->uids instead of using the
     *       iterator index.
     */
    for (i = 0; i < pgp_get_userid_count(key); i++) {
        int flags = 0;

        if (iscompromised(key, i)) {
            continue;
        }

        if (psigs) {
            flags |= F_PRINTSIGS;
        }

        uid_notices_offset += format_uid_notice(uid_notices + uid_notices_offset,
                                                keyring,
                                                key,
                                                i,
                                                NOTICE_BUFFER_SIZE - uid_notices_offset,
                                                flags);
    }
    uid_notices[uid_notices_offset] = '\0';

    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "");

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, key->fingerprint.length, " ");

    ptimestr(creation, sizeof(creation), (time_t) pgp_get_key_pkt(key)->creation_time);

    if (!format_key_usage(key_usage, sizeof(key_usage), key->key_flags)) {
        free(uid_notices);
        return -1;
    }

    /* XXX: For now we assume that the output string won't exceed 16KiB
     *      in length but this is completely arbitrary. What this
     *      really needs is some objective facts to base this
     *      size on.
     */

    total_length = -1;
    string = (char *) malloc(KB(16));
    if (string != NULL) {
        total_length = snprintf(string,
                                KB(16),
                                "%s %zu/%s %s %s [%s] %s\n                 %s\n%s",
                                header,
                                key_bitlength(pgp_get_key_material(key)),
                                pgp_show_pka(pgp_get_key_alg(key)),
                                keyid,
                                creation,
                                key_usage,
                                expiration_notice,
                                fingerprint,
                                uid_notices);
        *buf = string;
    }

    free((void *) uid_notices);

    return total_length;
}

/* return the key info as a JSON encoded string */
int
repgp_sprint_json(const struct rnp_key_store_t *keyring,
                  const pgp_key_t *             key,
                  json_object *                 keyjson,
                  const char *                  header,
                  const int                     psigs)
{
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fp[PGP_FINGERPRINT_HEX_SIZE];
    int      r;
    unsigned i;
    unsigned j;

    if (key == NULL || key->revoked) {
        return -1;
    }

    // add the top-level values
    json_object_object_add(keyjson, "header", json_object_new_string(header));
    json_object_object_add(
      keyjson, "key bits", json_object_new_int(key_bitlength(pgp_get_key_material(key))));
    json_object_object_add(
      keyjson, "pka", json_object_new_string(pgp_show_pka(pgp_get_key_alg(key))));
    json_object_object_add(
      keyjson,
      "key id",
      json_object_new_string(rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "")));
    json_object_object_add(keyjson,
                           "fingerprint",
                           json_object_new_string(rnp_strhexdump(
                             fp, key->fingerprint.fingerprint, key->fingerprint.length, "")));
    json_object_object_add(
      keyjson, "creation time", json_object_new_int(pgp_get_key_pkt(key)->creation_time));
    json_object_object_add(keyjson, "expiration", json_object_new_int(key->expiration));
    json_object_object_add(keyjson, "key flags", json_object_new_int(key->key_flags));
    json_object *usage_arr = json_object_new_array();
    format_key_usage_json(usage_arr, key->key_flags);
    json_object_object_add(keyjson, "usage", usage_arr);

    // iterating through the uids
    json_object *uid_arr = json_object_new_array();
    for (i = 0; i < pgp_get_userid_count(key); i++) {
        if (((r = isrevoked(key, i)) >= 0) &&
            (pgp_key_get_revoke(key, r)->code == PGP_REVOCATION_COMPROMISED)) {
            continue;
        }
        // add an array of the uids (and checking whether is REVOKED and
        // indicate it as well)
        json_object *uidobj = json_object_new_object();
        json_object_object_add(
          uidobj, "user id", json_object_new_string((char *) pgp_get_userid(key, i)));
        json_object_object_add(
          uidobj, "revoked", json_object_new_boolean((r >= 0) ? TRUE : FALSE));
        for (j = 0; j < pgp_key_get_subsig_count(key); j++) {
            pgp_subsig_t *subsig = pgp_key_get_subsig(key, j);
            if (psigs) {
                if (subsig->uid != i) {
                    continue;
                }
            } else {
                if (!(subsig->sig.version == 4 && subsig->sig.type == PGP_SIG_SUBKEY &&
                      (i == pgp_get_userid_count(key) - 1))) {
                    continue;
                }
            }
            json_object *subsigc = json_object_new_object();
            uint8_t      signer[PGP_KEY_ID_SIZE] = {0};
            signature_get_keyid(&subsig->sig, signer);
            json_object_object_add(
              subsigc,
              "signer id",
              json_object_new_string(rnp_strhexdump(keyid, signer, PGP_KEY_ID_SIZE, "")));
            json_object_object_add(
              subsigc,
              "creation time",
              json_object_new_int((int64_t) signature_get_creation(&subsig->sig)));

            const pgp_key_t *trustkey = rnp_key_store_get_key_by_id(keyring, signer, NULL);

            json_object_object_add(
              subsigc,
              "user id",
              json_object_new_string((trustkey) ? (char *) pgp_get_primary_userid(trustkey) :
                                                  "[unknown]"));
            json_object_object_add(uidobj, "signature", subsigc);
        }
        json_object_array_add(uid_arr, uidobj);
    } // for uidc
    json_object_object_add(keyjson, "user ids", uid_arr);
    RNP_DLOG("The json object created: %s",
             json_object_to_json_string_ext(keyjson, JSON_C_TO_STRING_PRETTY));
    return 1;
}

int
pgp_hkp_sprint_key(const struct rnp_key_store_t *keyring,
                   const pgp_key_t *             key,
                   char **                       buf,
                   const int                     psigs)
{
    const pgp_key_t *trustkey;
    unsigned         i;
    unsigned         j;
    char             keyid[PGP_KEY_ID_SIZE * 3];
    char             uidbuf[KB(128)];
    char             fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    int              n;

    if (key->revoked) {
        return -1;
    }
    for (i = 0, n = 0; i < pgp_get_userid_count(key); i++) {
        n += snprintf(&uidbuf[n],
                      sizeof(uidbuf) - n,
                      "uid:%lld:%lld:%s\n",
                      (long long) pgp_get_key_pkt(key)->creation_time,
                      (long long) key->expiration,
                      pgp_get_userid(key, i));
        for (j = 0; j < pgp_key_get_subsig_count(key); j++) {
            pgp_subsig_t *subsig = pgp_key_get_subsig(key, j);
            if (psigs) {
                if (subsig->uid != i) {
                    continue;
                }
            } else {
                if (!(subsig->sig.version == 4 && subsig->sig.type == PGP_SIG_SUBKEY &&
                      i == pgp_get_userid_count(key) - 1)) {
                    continue;
                }
            }
            uint8_t signer[PGP_KEY_ID_SIZE] = {0};
            signature_get_keyid(&subsig->sig, signer);
            trustkey = rnp_key_store_get_key_by_id(keyring, signer, NULL);
            if (subsig->sig.version == 4 && subsig->sig.type == PGP_SIG_SUBKEY) {
                n += snprintf(&uidbuf[n],
                              sizeof(uidbuf) - n,
                              "sub:%zu:%d:%s:%lld:%lld\n",
                              key_bitlength(pgp_get_key_material(key)),
                              subsig->sig.palg,
                              rnp_strhexdump(keyid, signer, PGP_KEY_ID_SIZE, ""),
                              (long long) signature_get_creation(&subsig->sig),
                              (long long) key->expiration);
            } else {
                n += snprintf(&uidbuf[n],
                              sizeof(uidbuf) - n,
                              "sig:%s:%lld:%s\n",
                              rnp_strhexdump(keyid, signer, PGP_KEY_ID_SIZE, ""),
                              (long long) signature_get_creation(&subsig->sig),
                              (trustkey) ? (char *) pgp_get_primary_userid(trustkey) : "");
            }
        }
    }

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, "");

    n = -1;
    {
        /* XXX: This number is completely arbitrary. */
        char *buffer = (char *) malloc(KB(16));

        if (buffer != NULL) {
            n = snprintf(buffer,
                         KB(16),
                         "pub:%s:%d:%zu:%lld:%lld\n%s",
                         fingerprint,
                         pgp_get_key_alg(key),
                         key_bitlength(pgp_get_key_material(key)),
                         (long long) pgp_get_key_pkt(key)->creation_time,
                         (long long) key->expiration,
                         uidbuf);
            *buf = buffer;
        }
    }
    return n;
}

/* print the key data for a pub or sec key */
void
repgp_print_key(FILE *                 fp,
                const rnp_key_store_t *keyring,
                const pgp_key_t *      key,
                const char *           header,
                const int              psigs)
{
    char *cp;

    if (pgp_sprint_key(keyring, key, &cp, header, psigs) >= 0) {
        (void) fprintf(fp, "%s", cp);
        free(cp);
    }
}

int
pgp_sprint_pubkey(const pgp_key_t *key, char *out, size_t outsize)
{
    char fp[PGP_FINGERPRINT_HEX_SIZE];
    int  cc;

    const pgp_key_pkt_t *     pkt = pgp_get_key_pkt(key);
    const pgp_key_material_t *material = pgp_get_key_material(key);
    cc = snprintf(out,
                  outsize,
                  "key=%s\nname=%s\ncreation=%lld\nexpiry=%lld\nversion=%d\nalg=%d\n",
                  rnp_strhexdump(fp, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, ""),
                  pgp_get_primary_userid(key),
                  (long long) pkt->creation_time,
                  (long long) pkt->v3_days,
                  pkt->version,
                  pkt->alg);
    switch (pkt->alg) {
    case PGP_PKA_DSA: {
        char *p = mpi2hex(&material->dsa.p);
        char *q = mpi2hex(&material->dsa.q);
        char *g = mpi2hex(&material->dsa.g);
        char *y = mpi2hex(&material->dsa.y);
        cc += snprintf(&out[cc], outsize - cc, "p=%s\nq=%s\ng=%s\ny=%s\n", p, q, g, y);
        free(p);
        free(q);
        free(g);
        free(y);
        break;
    }
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY: {
        char *n = mpi2hex(&material->rsa.n);
        char *e = mpi2hex(&material->rsa.e);
        cc += snprintf(&out[cc], outsize - cc, "n=%s\ne=%s\n", n, e);
        free(n);
        free(e);
        break;
    }
    case PGP_PKA_EDDSA: {
        char *p = mpi2hex(&material->ec.p);
        cc += snprintf(&out[cc], outsize - cc, "point=%s\n", p);
        free(p);
        break;
    }
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *curve = get_curve_desc(material->ec.curve);
        if (curve) {
            char *p = mpi2hex(&material->ec.p);
            cc +=
              snprintf(&out[cc], outsize - cc, "curve=%s\npoint=%s\n", curve->botan_name, p);
            free(p);
        }
        break;
    }
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: {
        char *p = mpi2hex(&material->eg.p);
        char *g = mpi2hex(&material->eg.g);
        char *y = mpi2hex(&material->eg.y);
        cc += snprintf(&out[cc], outsize - cc, "p=%s\ng=%s\ny=%s\n", p, g, y);
        free(p);
        free(g);
        free(y);
        break;
    }
    default:
        RNP_LOG("pgp_print_pubkey: Unusual algorithm: %d", (int) pkt->alg);
    }
    return cc;
}
