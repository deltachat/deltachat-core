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

#ifndef STREAM_KEY_H_
#define STREAM_KEY_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"
#include "stream-sig.h"

/* userid/userattr with all the corresponding signatures */
typedef struct pgp_transferable_userid_t {
    pgp_userid_pkt_t uid;
    list             signatures;
} pgp_transferable_userid_t;

/* subkey with all corresponding signatures */
typedef struct pgp_transferable_subkey_t {
    pgp_key_pkt_t subkey;
    list          signatures;
} pgp_transferable_subkey_t;

/* transferable key with userids, subkeys and revocation signatures */
typedef struct pgp_transferable_key_t {
    pgp_key_pkt_t key; /* main key packet */
    list          userids;
    list          subkeys;
    list          signatures;
} pgp_transferable_key_t;

/* sequence of OpenPGP transferable keys */
typedef struct pgp_key_sequence_t {
    list keys; /* list of pgp_transferable_key_t records */
} pgp_key_sequence_t;

void transferable_subkey_destroy(pgp_transferable_subkey_t *subkey);

void transferable_key_destroy(pgp_transferable_key_t *key);

void transferable_userid_destroy(pgp_transferable_userid_t *userid);

bool transferable_key_copy(pgp_transferable_key_t *      dst,
                           const pgp_transferable_key_t *src,
                           bool                          pubonly);

bool transferable_key_to_public(pgp_transferable_key_t *key);

rnp_result_t transferable_key_from_key(pgp_transferable_key_t *dst, const pgp_key_t *key);

rnp_result_t transferable_key_merge(pgp_transferable_key_t *      dst,
                                    const pgp_transferable_key_t *src);

bool transferable_subkey_copy(pgp_transferable_subkey_t *      dst,
                              const pgp_transferable_subkey_t *src,
                              bool                             pubonly);

bool transferable_subkey_to_public(pgp_transferable_subkey_t *key);

rnp_result_t transferable_subkey_from_key(pgp_transferable_subkey_t *dst,
                                          const pgp_key_t *          key);

rnp_result_t transferable_subkey_merge(pgp_transferable_subkey_t *      dst,
                                       const pgp_transferable_subkey_t *src);

pgp_transferable_userid_t *transferable_key_add_userid(pgp_transferable_key_t *key,
                                                       const char *            userid);

pgp_signature_t *transferable_userid_certify(const pgp_key_pkt_t *          key,
                                             pgp_transferable_userid_t *    userid,
                                             const pgp_key_pkt_t *          signer,
                                             pgp_hash_alg_t                 hash_alg,
                                             const rnp_selfsig_cert_info_t *cert);

pgp_signature_t *transferable_subkey_bind(const pgp_key_pkt_t *             primary_key,
                                          pgp_transferable_subkey_t *       subkey,
                                          pgp_hash_alg_t                    hash_alg,
                                          const rnp_selfsig_binding_info_t *binding);

void key_sequence_destroy(pgp_key_sequence_t *keys);

rnp_result_t process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t *keys);

rnp_result_t process_pgp_key(pgp_source_t *src, pgp_transferable_key_t *key);

rnp_result_t process_pgp_subkey(pgp_source_t *src, pgp_transferable_subkey_t *subkey);

rnp_result_t process_pgp_userid(pgp_source_t *src, pgp_transferable_userid_t *uid);
/**
 * @brief Validate key signatures and fill pgp_signatures_info_t structure. It should be freed
 *        with free_signatures_info. To check status of validated signatures function
 *        check_signatures_info should be used.
 *
 * @param result pointer to the structure
 * @param key pgp primary key which signatures should be validated
 * @param keyring keyring where signing keys are looked for
 * @return RNP_SUCCESS if all signatures are validated successfully or error code otherwise.
 *         Please note that this doesn't mean that all signatures are valid.
 *         Use method check_signatures_info for this purpose.
 */
rnp_result_t validate_pgp_key_signatures(pgp_signatures_info_t *result,
                                         const pgp_key_t *      key,
                                         const rnp_key_store_t *keyring);

/**
 * @brief Validate whether pgp key or subkey is usable, i.e. has all valid signatures, valid
 *        key material and so on.
 *
 * @param key pgp key which is being validated.
 * @param keyring additional keys which could be required for certifications validation
 * @return rnp_result_t RNP_SUCCESS if key is valid and usable or error code otherwise
 */
rnp_result_t validate_pgp_key(const pgp_key_t *key, const rnp_key_store_t *keyring);

rnp_result_t write_pgp_key(pgp_transferable_key_t *key, pgp_dest_t *dst, bool armor);

rnp_result_t write_pgp_keys(pgp_key_sequence_t *keys, pgp_dest_t *dst, bool armor);

rnp_result_t decrypt_secret_key(pgp_key_pkt_t *key, const char *password);

rnp_result_t encrypt_secret_key(pgp_key_pkt_t *key, const char *password, rng_t *rng);

void forget_secret_key_fields(pgp_key_material_t *key);

#endif
