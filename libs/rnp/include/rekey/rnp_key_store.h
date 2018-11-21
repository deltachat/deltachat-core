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

#ifndef KEY_STORE_H_
#define KEY_STORE_H_

#include <rnp/rnp.h>
#include <json.h>

#include <stdint.h>
#include <stdbool.h>

#include "memory.h"

typedef struct rnp_t     rnp_t;
typedef struct pgp_key_t pgp_key_t;

typedef enum {
    KBX_EMPTY_BLOB = 0,
    KBX_HEADER_BLOB = 1,
    KBX_PGP_BLOB = 2,
    KBX_X509_BLOB = 3
} kbx_blob_type;

typedef struct {
    uint32_t      length;
    kbx_blob_type type;

    uint8_t *image;
} kbx_blob_t;

typedef struct {
    kbx_blob_t blob;
    uint8_t    version;
    uint16_t   flags;
    uint32_t   file_created_at;
    uint32_t   last_maintenance_run;
} kbx_header_blob_t;

typedef struct {
    uint8_t  fp[PGP_FINGERPRINT_SIZE];
    uint32_t keyid_offset;
    uint16_t flags;
} kbx_pgp_key_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
    uint16_t flags;
    uint8_t  validity;
} kbx_pgp_uid_t;

typedef struct {
    uint32_t expired;
} kbx_pgp_sig_t;

typedef struct {
    kbx_blob_t blob;
    uint8_t    version;
    uint16_t   flags;
    uint32_t   keyblock_offset;
    uint32_t   keyblock_length;

    uint16_t nkeys;
    uint16_t keys_len;
    DYNARRAY(kbx_pgp_key_t, key);

    uint16_t sn_size;
    uint8_t *sn;

    uint16_t nuids;
    uint16_t uids_len;
    DYNARRAY(kbx_pgp_uid_t, uid);

    uint16_t nsigs;
    uint16_t sigs_len;
    DYNARRAY(kbx_pgp_sig_t, sig);

    uint8_t ownertrust;
    uint8_t all_Validity;

    uint32_t recheck_after;
    uint32_t latest_timestamp;
    uint32_t blob_created_at;
} kbx_pgp_blob_t;

typedef enum key_store_format_t {
    UNKNOW_KEY_STORE = 0,
    GPG_KEY_STORE,
    KBX_KEY_STORE,
    G10_KEY_STORE,
} key_store_format_t;

#define RNP_KEYSTORE_GPG "GPG" /* GPG keystore format */
#define RNP_KEYSTORE_KBX "KBX" /* KBX keystore format */
#define RNP_KEYSTORE_G10 "G10" /* G10 keystore format */

// combinated keystores
#define RNP_KEYSTORE_GPG21 "GPG21" /* KBX + G10 keystore format */

typedef struct rnp_key_store_t {
    const char *            path;
    const char *            format_label;
    enum key_store_format_t format;
    bool disable_validation; /* do not automatically validate keys, added to this key store */

    list keys;
    DYNARRAY(kbx_blob_t *, blob);
} rnp_key_store_t;

rnp_key_store_t *rnp_key_store_new(const char *format, const char *path);

bool rnp_key_store_load_keys(rnp_t *rnp, bool loadsecret);

int  rnp_key_store_load_from_file(rnp_key_store_t *, const pgp_key_provider_t *key_provider);
bool rnp_key_store_load_from_mem(rnp_key_store_t *,
                                 pgp_memory_t *,
                                 const pgp_key_provider_t *key_provider);

bool rnp_key_store_write_to_file(rnp_key_store_t *, const unsigned);
bool rnp_key_store_write_to_mem(rnp_key_store_t *, const unsigned, pgp_memory_t *);

void rnp_key_store_clear(rnp_key_store_t *);
void rnp_key_store_free(rnp_key_store_t *);

bool rnp_key_store_list(FILE *fp, const rnp_key_store_t *, const int);
bool rnp_key_store_json(const rnp_key_store_t *, json_object *, const int);

pgp_key_t *rnp_key_store_add_key(rnp_key_store_t *, pgp_key_t *);

bool rnp_key_store_remove_key(rnp_key_store_t *, const pgp_key_t *);
bool rnp_key_store_remove_key_by_id(rnp_key_store_t *, const uint8_t *);

pgp_key_t *rnp_key_store_get_key_by_id(const rnp_key_store_t *,
                                       const unsigned char *,
                                       pgp_key_t *);

pgp_key_t *rnp_key_store_get_key_by_name(const rnp_key_store_t *, const char *, pgp_key_t *);

pgp_key_t *rnp_key_store_get_key_by_userid(const rnp_key_store_t *, const char *, pgp_key_t *);

bool rnp_key_store_get_key_grip(const pgp_key_material_t *, uint8_t *);

pgp_key_t *rnp_key_store_get_key_by_grip(const rnp_key_store_t *, const uint8_t *);
pgp_key_t *rnp_key_store_get_key_by_fpr(const rnp_key_store_t *, const pgp_fingerprint_t *fpr);
pgp_key_t *rnp_key_store_get_primary_key(const rnp_key_store_t *, const pgp_key_t *);
pgp_key_t *rnp_key_store_search(const rnp_key_store_t *, const pgp_key_search_t *, pgp_key_t *);

#endif /* KEY_STORE_H_ */
