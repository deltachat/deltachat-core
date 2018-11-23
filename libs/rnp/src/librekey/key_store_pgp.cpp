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

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#include <stdlib.h>
#include <string.h>

#include <rnp/rnp_sdk.h>
#include <librepgp/packet-show.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-armor.h>

#include "types.h"
#include "key_store_pgp.h"
#include "pgp-key.h"
#include "utils.h"

void print_packet_hex(const pgp_rawpacket_t *pkt);

static bool
rnp_key_add_stream_rawpacket(pgp_key_t *key, pgp_content_enum tag, pgp_dest_t *memdst)
{
    if (!pgp_key_add_rawpacket(key, mem_dest_get_memory(memdst), memdst->writeb, tag)) {
        RNP_LOG("Failed to add packet");
        dst_close(memdst, true);
        return false;
    }

    dst_close(memdst, false);
    return true;
}

bool
rnp_key_add_key_rawpacket(pgp_key_t *key, pgp_key_pkt_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_key(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, (pgp_content_enum) pkt->tag, &dst);
}

static bool
rnp_key_add_sig_rawpacket(pgp_key_t *key, pgp_signature_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_signature(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, PGP_PTAG_CT_SIGNATURE, &dst);
}

static bool
rnp_key_add_uid_rawpacket(pgp_key_t *key, pgp_userid_pkt_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_userid(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, (pgp_content_enum) pkt->tag, &dst);
}

static bool
create_key_from_pkt(pgp_key_t *key, pgp_key_pkt_t *pkt)
{
    pgp_key_pkt_t keypkt = {};

    memset(key, 0, sizeof(*key));

    if (!copy_key_pkt(&keypkt, pkt, false)) {
        RNP_LOG("failed to copy key packet");
        return false;
    }

    /* parse secret key if not encrypted */
    if (is_secret_key_pkt(keypkt.tag)) {
        bool cleartext = keypkt.sec_protection.s2k.usage == PGP_S2KU_NONE;
        if (cleartext && decrypt_secret_key(&keypkt, NULL)) {
            RNP_LOG("failed to setup key fields");
            free_key_pkt(&keypkt);
            return false;
        }
    }

    /* this call transfers ownership */
    if (!pgp_key_from_keypkt(key, &keypkt, (pgp_content_enum) pkt->tag)) {
        RNP_LOG("failed to setup key fields");
        free_key_pkt(&keypkt);
        return false;
    }

    /* add key rawpacket */
    if (!rnp_key_add_key_rawpacket(key, pkt)) {
        free_key_pkt(&keypkt);
        return false;
    }

    key->format = GPG_KEY_STORE;
    key->key_flags = pgp_pk_alg_capabilities(pgp_get_key_pkt(key)->alg);
    return true;
}

static bool
rnp_key_add_signature(pgp_key_t *key, pgp_signature_t *sig)
{
    pgp_subsig_t *subsig = NULL;
    uint8_t *     algs = NULL;
    size_t        count = 0;

    if (!(subsig = pgp_key_add_subsig(key))) {
        RNP_LOG("Failed to add subsig");
        return false;
    }

    /* add signature rawpacket */
    if (!rnp_key_add_sig_rawpacket(key, sig)) {
        return false;
    }

    subsig->uid = pgp_get_userid_count(key) - 1;
    if (!copy_signature_packet(&subsig->sig, sig)) {
        return false;
    }

    if (signature_has_key_expiration(&subsig->sig)) {
        key->expiration = signature_get_key_expiration(&subsig->sig);
    }
    if (signature_has_trust(&subsig->sig)) {
        signature_get_trust(&subsig->sig, &subsig->trustlevel, &subsig->trustamount);
    }
    if (signature_get_primary_uid(&subsig->sig)) {
        key->uid0 = pgp_get_userid_count(key) - 1;
        key->uid0_set = 1;
    }

    if (signature_get_preferred_symm_algs(&subsig->sig, &algs, &count) &&
        !pgp_user_prefs_set_symm_algs(&subsig->prefs, algs, count)) {
        RNP_LOG("failed to alloc symm algs");
        return false;
    }
    if (signature_get_preferred_hash_algs(&subsig->sig, &algs, &count) &&
        !pgp_user_prefs_set_hash_algs(&subsig->prefs, algs, count)) {
        RNP_LOG("failed to alloc hash algs");
        return false;
    }
    if (signature_get_preferred_z_algs(&subsig->sig, &algs, &count) &&
        !pgp_user_prefs_set_z_algs(&subsig->prefs, algs, count)) {
        RNP_LOG("failed to alloc z algs");
        return false;
    }
    if (signature_has_key_flags(&subsig->sig)) {
        subsig->key_flags = signature_get_key_flags(&subsig->sig);
        key->key_flags = subsig->key_flags;
    }
    if (signature_has_key_server_prefs(&subsig->sig)) {
        uint8_t ks_pref = signature_get_key_server_prefs(&subsig->sig);
        if (!pgp_user_prefs_set_ks_prefs(&subsig->prefs, &ks_pref, 1)) {
            RNP_LOG("failed to alloc ks prefs");
            return false;
        }
    }
    if (signature_has_key_server(&subsig->sig)) {
        subsig->prefs.key_server = (uint8_t *) signature_get_key_server(&subsig->sig);
    }
    if (signature_has_revocation_reason(&subsig->sig)) {
        /* not sure whether this logic is correct - we should check signature type? */
        pgp_revoke_t *revocation = NULL;
        if (!pgp_get_userid_count(key)) {
            /* revoke whole key */
            key->revoked = 1;
            revocation = &key->revocation;
        } else {
            /* revoke the user id */
            if (!(revocation = pgp_key_add_revoke(key))) {
                RNP_LOG("failed to add revoke");
                return false;
            }
            revocation->uid = pgp_get_userid_count(key) - 1;
        }
        signature_get_revocation_reason(&subsig->sig, &revocation->code, &revocation->reason);
        if (!strlen(revocation->reason)) {
            free(revocation->reason);
            revocation->reason = strdup(pgp_show_ss_rr_code(revocation->code));
        }
    }

    return true;
}

static bool
rnp_key_add_signatures(pgp_key_t *key, list signatures)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!rnp_key_add_signature(key, (pgp_signature_t *) sig)) {
            return false;
        }
    }
    return true;
}

bool
rnp_key_add_subkey_grip(pgp_key_t *key, uint8_t *grip)
{
    for (list_item *li = list_front(key->subkey_grips); li; li = list_next(li)) {
        if (!memcmp(grip, (uint8_t *) li, PGP_FINGERPRINT_SIZE)) {
            return true;
        }
    }

    return list_append(&key->subkey_grips, grip, PGP_FINGERPRINT_SIZE);
}

bool
rnp_key_store_add_transferable_subkey(rnp_key_store_t *          keyring,
                                      pgp_transferable_subkey_t *tskey,
                                      pgp_key_t *                pkey)
{
    pgp_key_t skey = {};

    /* create subkey */
    if (!rnp_key_from_transferable_subkey(&skey, tskey, pkey)) {
        RNP_LOG("failed to create subkey");
        return false;
    }

    /* add it to the storage */
    if (!rnp_key_store_add_key(keyring, &skey)) {
        RNP_LOG("Failed to add subkey to key store.");
        goto error;
    }

    return true;
error:
    pgp_key_free_data(&skey);
    return false;
}

bool
rnp_key_add_transferable_userid(pgp_key_t *key, pgp_transferable_userid_t *uid)
{
    uint8_t *uidz;

    if (!rnp_key_add_uid_rawpacket(key, &uid->uid)) {
        return false;
    }

    if (!(uidz = (uint8_t *) calloc(1, uid->uid.uid_len + 1))) {
        RNP_LOG("uid alloc failed");
        return false;
    }

    memcpy(uidz, uid->uid.uid, uid->uid.uid_len);
    uidz[uid->uid.uid_len] = 0;
    if (!pgp_add_userid(key, uidz)) {
        RNP_LOG("failed to add user id");
        free(uidz);
        return false;
    }
    free(uidz);
    if (!rnp_key_add_signatures(key, uid->signatures)) {
        return false;
    }

    return true;
}

bool
rnp_key_store_add_transferable_key(rnp_key_store_t *keyring, pgp_transferable_key_t *tkey)
{
    pgp_key_t  key = {};
    pgp_key_t *addkey = NULL;

    /* create key from transferable key */
    if (!rnp_key_from_transferable_key(&key, tkey)) {
        RNP_LOG("failed to create key");
        return false;
    }

    /* add key to the storage before subkeys */
    if (!(addkey = rnp_key_store_add_key(keyring, &key))) {
        RNP_LOG("Failed to add key to key store.");
        goto error;
    }

    /* add subkeys */
    for (list_item *skey = list_front(tkey->subkeys); skey; skey = list_next(skey)) {
        pgp_transferable_subkey_t *subkey = (pgp_transferable_subkey_t *) skey;
        if (!rnp_key_store_add_transferable_subkey(keyring, subkey, addkey)) {
            goto error;
        }
    }

    return true;
error:
    if (addkey) {
        /* during key addition all fields are copied so will be cleaned below */
        rnp_key_store_remove_key(keyring, addkey);
        pgp_key_free_data(addkey);
    } else {
        pgp_key_free_data(&key);
    }
    return false;
}

bool
rnp_key_from_transferable_key(pgp_key_t *key, pgp_transferable_key_t *tkey)
{
    memset(key, 0, sizeof(*key));
    /* create key */
    if (!create_key_from_pkt(key, &tkey->key)) {
        return false;
    }

    /* add direct-key signatures */
    if (!rnp_key_add_signatures(key, tkey->signatures)) {
        goto error;
    }

    /* add userids and their signatures */
    for (list_item *uid = list_front(tkey->userids); uid; uid = list_next(uid)) {
        pgp_transferable_userid_t *tuid = (pgp_transferable_userid_t *) uid;
        if (!rnp_key_add_transferable_userid(key, tuid)) {
            goto error;
        }
    }

    return true;
error:
    pgp_key_free_data(key);
    return false;
}

bool
rnp_key_from_transferable_subkey(pgp_key_t *                subkey,
                                 pgp_transferable_subkey_t *tskey,
                                 pgp_key_t *                primary)
{
    memset(subkey, 0, sizeof(*subkey));

    /* create key */
    if (!create_key_from_pkt(subkey, &tskey->subkey)) {
        return false;
    }

    /* add subkey binding signatures */
    if (!rnp_key_add_signatures(subkey, tskey->signatures)) {
        RNP_LOG("failed to add subkey signatures");
        goto error;
    }

    /* setup key grips if primary is available */
    if (primary) {
        subkey->primary_grip = (uint8_t *) malloc(PGP_FINGERPRINT_SIZE);
        if (!subkey->primary_grip) {
            RNP_LOG("alloc failed");
            goto error;
        }
        memcpy(subkey->primary_grip, primary->grip, PGP_FINGERPRINT_SIZE);
        if (!rnp_key_add_subkey_grip(primary, subkey->grip)) {
            RNP_LOG("failed to add subkey grip");
            goto error;
        }
    }
    return true;
error:
    pgp_key_free_data(subkey);
    return false;
}

rnp_result_t
rnp_key_store_pgp_read_from_src(rnp_key_store_t *keyring, pgp_source_t *src)
{
    pgp_key_sequence_t        keys = {};
    pgp_transferable_subkey_t tskey = {};
    rnp_result_t              ret = RNP_ERROR_GENERIC;

    /* check whether we have transferable subkey in source */
    if (is_subkey_pkt(stream_pkt_type(src))) {
        if ((ret = process_pgp_subkey(src, &tskey))) {
            return ret;
        }
        ret = rnp_key_store_add_transferable_subkey(keyring, &tskey, NULL) ?
                RNP_SUCCESS :
                RNP_ERROR_BAD_STATE;
        transferable_subkey_destroy(&tskey);
        return ret;
    }

    /* process armored or raw transferable key packets sequence(s) */
    if ((ret = process_pgp_keys(src, &keys))) {
        return ret;
    }

    for (list_item *key = list_front(keys.keys); key; key = list_next(key)) {
        if (!rnp_key_store_add_transferable_key(keyring, (pgp_transferable_key_t *) key)) {
            ret = RNP_ERROR_BAD_STATE;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    key_sequence_destroy(&keys);
    return ret;
}

bool
rnp_key_store_pgp_read_from_mem(rnp_key_store_t *         keyring,
                                pgp_memory_t *            mem,
                                const pgp_key_provider_t *key_provider)
{
    pgp_source_t src = {};
    bool         res = false;

    if (init_mem_src(&src, mem->buf, mem->length, false)) {
        return false;
    }

    res = !rnp_key_store_pgp_read_from_src(keyring, &src);

    src_close(&src);
    return res;
}

bool
rnp_key_write_packets_stream(const pgp_key_t *key, pgp_dest_t *dst)
{
    if (!pgp_key_get_rawpacket_count(key)) {
        return false;
    }
    for (size_t i = 0; i < pgp_key_get_rawpacket_count(key); i++) {
        pgp_rawpacket_t *pkt = pgp_key_get_rawpacket(key, i);
        if (!pkt->raw || !pkt->length) {
            return false;
        }
        dst_write(dst, pkt->raw, pkt->length);
    }
    return !dst->werr;
}

bool
rnp_key_to_src(const pgp_key_t *key, pgp_source_t *src)
{
    pgp_dest_t dst = {};
    bool       res;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    res = rnp_key_write_packets_stream(key, &dst) &&
          !init_mem_src(src, mem_dest_own_memory(&dst), dst.writeb, true);
    dst_close(&dst, true);
    return res;
}

static bool
do_write(rnp_key_store_t *key_store, pgp_dest_t *dst, bool secret)
{
    pgp_key_search_t search;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_is_key_secret(key) != secret) {
            continue;
        }
        // skip subkeys, they are written below (orphans are ignored)
        if (!pgp_key_is_primary_key(key)) {
            continue;
        }

        if (key->format != GPG_KEY_STORE) {
            RNP_LOG("incorrect format (conversions not supported): %d", key->format);
            return false;
        }
        if (!rnp_key_write_packets_stream(key, dst)) {
            return false;
        }
        for (list_item *subkey_grip = list_front(key->subkey_grips); subkey_grip;
             subkey_grip = list_next(subkey_grip)) {
            search.type = PGP_KEY_SEARCH_GRIP;
            memcpy(search.by.grip, (uint8_t *) subkey_grip, PGP_FINGERPRINT_SIZE);
            pgp_key_t *subkey = NULL;
            for (list_item *subkey_item = list_front(key_store->keys); subkey_item;
                 subkey_item = list_next(subkey_item)) {
                pgp_key_t *candidate = (pgp_key_t *) subkey_item;
                if (pgp_is_key_secret(candidate) != secret) {
                    continue;
                }
                if (rnp_key_matches_search(candidate, &search)) {
                    subkey = candidate;
                    break;
                }
            }
            if (!subkey) {
                RNP_LOG("Missing subkey");
                continue;
            }
            if (!rnp_key_write_packets_stream(subkey, dst)) {
                return false;
            }
        }
    }
    return true;
}

bool
rnp_key_store_pgp_write_to_dst(rnp_key_store_t *key_store, bool armor, pgp_dest_t *dst)
{
    pgp_dest_t armordst;
    bool       res = false;

    if (armor) {
        pgp_armored_msg_t type = PGP_ARMORED_PUBLIC_KEY;
        if (list_length(key_store->keys) &&
            pgp_is_key_secret((pgp_key_t *) list_front(key_store->keys))) {
            type = PGP_ARMORED_SECRET_KEY;
        }
        if (init_armored_dst(&armordst, dst, type)) {
            return false;
        }
        dst = &armordst;
    }
    // two separate passes (public keys, then secret keys)
    res = do_write(key_store, dst, false) && do_write(key_store, dst, true);

    if (armor) {
        dst_close(&armordst, !res);
    }

    return res;
}

bool
rnp_key_store_pgp_write_to_mem(rnp_key_store_t *key_store, bool armor, pgp_memory_t *mem)
{
    pgp_dest_t dst = {};
    bool       res = false;

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    res = rnp_key_store_pgp_write_to_dst(key_store, armor, &dst) &&
          pgp_memory_add(mem, (uint8_t *) mem_dest_get_memory(&dst), dst.writeb);

    dst_close(&dst, true);
    return res;
}
