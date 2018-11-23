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
#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>
#include <rnp/rnp_def.h>
#include "memory.h"
#include "list.h"
#include "crypto/common.h"

#define PGP_KEY_ID_SIZE 8
#define PGP_FINGERPRINT_HEX_SIZE (PGP_FINGERPRINT_SIZE * 3) + 1

/* SHA1 Hash Size */
#define PGP_SHA1_HASH_SIZE 20

/* Maximum length of the packet header */
#define PGP_MAX_HEADER_SIZE 6

/** pgp_map_t
 */
typedef struct {
    int         type;
    const char *string;
} pgp_map_t;

typedef struct pgp_crypt_t pgp_crypt_t;

/** pgp_hash_t */
typedef struct pgp_hash_t pgp_hash_t;

/** Revocation Reason type */
typedef uint8_t pgp_ss_rr_code_t;

/** pgp_fingerprint_t */
typedef struct pgp_fingerprint_t {
    uint8_t  fingerprint[PGP_FINGERPRINT_SIZE];
    unsigned length;
} pgp_fingerprint_t;

/**
 * Type to keep public/secret key mpis without any openpgp-dependent data.
 */
typedef struct pgp_key_material_t {
    pgp_pubkey_alg_t alg;    /* algorithm of the key */
    bool             secret; /* secret part of the key material is populated */

    union {
        pgp_rsa_key_t rsa;
        pgp_dsa_key_t dsa;
        pgp_eg_key_t  eg;
        pgp_ec_key_t  ec;
    };
} pgp_key_material_t;

/**
 * Type to keep signature without any openpgp-dependent data.
 */
typedef struct pgp_signature_material_t {
    union {
        pgp_rsa_signature_t rsa;
        pgp_dsa_signature_t dsa;
        pgp_ec_signature_t  ecc;
        pgp_eg_signature_t  eg;
    };
} pgp_signature_material_t;

/**
 * Type to keep pk-encrypted data without any openpgp-dependent data.
 */
typedef struct pgp_encrypted_material_t {
    union {
        pgp_rsa_encrypted_t  rsa;
        pgp_eg_encrypted_t   eg;
        pgp_sm2_encrypted_t  sm2;
        pgp_ecdh_encrypted_t ecdh;
    };
} pgp_encrypted_material_t;

typedef struct pgp_s2k_t {
    pgp_s2k_usage_t usage;

    /* below fields may not all be valid, depending on the usage field above */
    pgp_s2k_specifier_t specifier;
    pgp_hash_alg_t      hash_alg;
    uint8_t             salt[PGP_SALT_SIZE];
    unsigned            iterations;
} pgp_s2k_t;

typedef struct pgp_key_protection_t {
    pgp_s2k_t         s2k;         /* string-to-key kdf params */
    pgp_symm_alg_t    symm_alg;    /* symmetric alg */
    pgp_cipher_mode_t cipher_mode; /* block cipher mode */
    uint8_t           iv[PGP_MAX_BLOCK_SIZE];
} pgp_key_protection_t;

/** Struct to hold a key packet. May contain public or private key/subkey */
typedef struct pgp_key_pkt_t {
    int              tag;           /* packet tag: public key/subkey or private key/subkey */
    pgp_version_t    version;       /* Key packet version */
    uint32_t         creation_time; /* Key creation time */
    pgp_pubkey_alg_t alg;
    uint16_t         v3_days; /* v2/v3 validity time */

    uint8_t *hashed_data; /* key's hashed data used for signature calculation */
    size_t   hashed_len;

    pgp_key_material_t material;

    /* secret key data, if available. sec_len == 0, sec_data == NULL for public key/subkey */
    pgp_key_protection_t sec_protection;
    uint8_t *            sec_data;
    size_t               sec_len;
} pgp_key_pkt_t;

typedef struct pgp_key_t pgp_key_t;

/** Struct to hold userid or userattr packet. We don't parse userattr now, just storing the
 *  binary blob as it is. It may be distinguished by tag field.
 */
typedef struct pgp_userid_pkt_t {
    int      tag;
    uint8_t *uid;
    size_t   uid_len;
} pgp_userid_pkt_t;

typedef struct pgp_signature_t {
    pgp_version_t version;
    /* common v3 and v4 fields */
    pgp_sig_type_t   type;
    pgp_pubkey_alg_t palg;
    pgp_hash_alg_t   halg;
    uint8_t          lbits[2];
    uint8_t *        hashed_data;
    size_t           hashed_len;

    pgp_signature_material_t material;

    /* v3 - only fields */
    uint32_t creation_time;
    uint8_t  signer[PGP_KEY_ID_SIZE];

    /* v4 - only fields */
    list subpkts;
} pgp_signature_t;

/* Signature subpacket, see 5.2.3.1 in RFC 4880 and RFC 4880 bis 02 */
typedef struct pgp_sig_subpkt_t {
    pgp_sig_subpacket_type_t type;         /* type of the subpacket */
    unsigned                 len;          /* length of the data */
    uint8_t *                data;         /* raw subpacket data, excluding the header */
    unsigned                 critical : 1; /* critical flag */
    unsigned                 hashed : 1;   /* whether subpacket is hashed or not */
    unsigned                 parsed : 1;   /* whether subpacket was successfully parsed */
    union {
        uint32_t create; /* 5.2.3.4.   Signature Creation Time */
        uint32_t expiry; /* 5.2.3.6.   Key Expiration Time */
                         /* 5.2.3.10.  Signature Expiration Time */
        bool exportable; /* 5.2.3.11.  Exportable Certification */
        struct {
            uint8_t level;
            uint8_t amount;
        } trust; /* 5.2.3.13.  Trust Signature */
        struct {
            const char *str;
            unsigned    len;
        } regexp;       /* 5.2.3.14.  Regular Expression */
        bool revocable; /* 5.2.3.12.  Revocable */
        struct {
            uint8_t *arr;
            unsigned len;
        } preferred; /* 5.2.3.7.  Preferred Symmetric Algorithms */
                     /* 5.2.3.8.  Preferred Hash Algorithms */
                     /* 5.2.3.9.  Preferred Compression Algorithms */
        struct {
            uint8_t          klass;
            pgp_pubkey_alg_t pkalg;
            uint8_t *        fp;
        } revocation_key; /* 5.2.3.15.  Revocation Key */
        uint8_t *issuer;  /* 5.2.3.5.   Issuer */
        struct {
            uint8_t     flags[4];
            unsigned    nlen;
            unsigned    vlen;
            const char *name;
            const char *value;
        } notation; /* 5.2.3.16.  Notation Data */
        struct {
            bool no_modify;
        } ks_prefs; /* 5.2.3.17.  Key Server Preferences */
        struct {
            const char *uri;
            unsigned    len;
        } preferred_ks;   /* 5.2.3.18.  Preferred Key Server */
        bool primary_uid; /* 5.2.3.19.  Primary User ID */
        struct {
            const char *uri;
            unsigned    len;
        } policy;          /* 5.2.3.20.  Policy URI */
        uint8_t key_flags; /* 5.2.3.21.  Key Flags */
        struct {
            const char *uid;
            unsigned    len;
        } signer; /* 5.2.3.22.  Signer's User ID */
        struct {
            uint8_t     code;
            const char *str;
            unsigned    len;
        } revocation_reason; /* 5.2.3.23.  Reason for Revocation */
        struct {
            bool mdc;
            bool aead;
            bool key_v5;
        } features; /* 5.2.3.24.  Features */
        struct {
            pgp_pubkey_alg_t pkalg;
            pgp_hash_alg_t   halg;
            uint8_t *        hash;
            unsigned         hlen;
        } sig_target;        /* 5.2.3.25.  Signature Target */
        pgp_signature_t sig; /* 5.2.3.27. Embedded Signature */
        struct {
            uint8_t  version;
            uint8_t *fp;
            unsigned len;
        } issuer_fp; /* 5.2.3.28.  Issuer Fingerprint, RFC 4880 bis 04 */
    } fields;        /* parsed contents of the subpacket */
} pgp_sig_subpkt_t;

/** pgp_rawpacket_t */
typedef struct pgp_rawpacket_t {
    pgp_content_enum tag;
    size_t           length;
    uint8_t *        raw;
} pgp_rawpacket_t;

typedef enum {
    /* first octet */
    PGP_KEY_SERVER_NO_MODIFY = 0x80
} pgp_key_server_prefs_t;

/** pgp_one_pass_sig_t */
typedef struct pgp_one_pass_sig_t {
    uint8_t          version;
    pgp_sig_type_t   type;
    pgp_hash_alg_t   halg;
    pgp_pubkey_alg_t palg;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    unsigned         nested;
} pgp_one_pass_sig_t;

typedef struct pgp_literal_hdr_t {
    uint8_t  format;
    char     fname[256];
    uint8_t  fname_len;
    uint32_t timestamp;
} pgp_literal_hdr_t;

/** litdata_type_t */
typedef enum {
    PGP_LDT_BINARY = 'b',
    PGP_LDT_TEXT = 't',
    PGP_LDT_UTF8 = 'u',
    PGP_LDT_LOCAL = 'l',
    PGP_LDT_LOCAL2 = '1'
} pgp_litdata_enum;

/** public-key encrypted session key packet */
typedef struct pgp_pk_sesskey_t {
    unsigned         version;
    uint8_t          key_id[PGP_KEY_ID_SIZE];
    pgp_pubkey_alg_t alg;

    pgp_encrypted_material_t material;
} pgp_pk_sesskey_t;

/** pkp_sk_sesskey_t */
typedef struct {
    unsigned       version;
    pgp_symm_alg_t alg;
    pgp_s2k_t      s2k;
    uint8_t        enckey[PGP_MAX_KEY_SIZE + PGP_AEAD_MAX_TAG_LEN + 1];
    unsigned       enckeylen;
    /* v5 specific fields */
    pgp_aead_alg_t aalg;
    uint8_t        iv[PGP_MAX_BLOCK_SIZE];
    unsigned       ivlen;
} pgp_sk_sesskey_t;

/* user revocation info */
typedef struct pgp_revoke_t {
    uint32_t uid;    /* index in uid array */
    uint8_t  code;   /* revocation code */
    char *   reason; /* c'mon, spill the beans */
} pgp_revoke_t;

typedef struct pgp_user_prefs_t {
    // preferred symmetric algs (pgp_symm_alg_t)
    uint8_t *symm_algs;
    size_t   symm_alg_count;
    // preferred hash algs (pgp_hash_alg_t)
    uint8_t *hash_algs;
    size_t   hash_alg_count;
    // preferred compression algs (pgp_compression_type_t)
    uint8_t *z_algs;
    size_t   z_alg_count;
    // key server preferences (pgp_key_server_prefs_t)
    uint8_t *ks_prefs;
    size_t   ks_pref_count;
    // preferred key server
    uint8_t *key_server;
} pgp_user_prefs_t;

/** information about the signature */
typedef struct pgp_subsig_t {
    uint32_t         uid;         /* index in userid array in key for certification sig */
    pgp_signature_t  sig;         /* signature packet */
    uint8_t          trustlevel;  /* level of trust */
    uint8_t          trustamount; /* amount of trust */
    uint8_t          key_flags;   /* key flags for certification/direct key sig */
    pgp_user_prefs_t prefs;       /* user preferences for certification sig */
} pgp_subsig_t;

struct rnp_keygen_ecc_params_t {
    pgp_curve_t curve;
};

struct rnp_keygen_rsa_params_t {
    uint32_t modulus_bit_len;
};

struct rnp_keygen_dsa_params_t {
    size_t p_bitlen;
    size_t q_bitlen;
};

struct rnp_keygen_elgamal_params_t {
    size_t key_bitlen;
};

/* structure used to hold context of key generation */
typedef struct rnp_keygen_crypto_params_t {
    // Asymmteric algorithm that user requesed key for
    pgp_pubkey_alg_t key_alg;
    // Hash to be used for key signature
    pgp_hash_alg_t hash_alg;
    // Pointer to initialized RNG engine
    rng_t *rng;
    union {
        struct rnp_keygen_ecc_params_t     ecc;
        struct rnp_keygen_rsa_params_t     rsa;
        struct rnp_keygen_dsa_params_t     dsa;
        struct rnp_keygen_elgamal_params_t elgamal;
    };
} rnp_keygen_crypto_params_t;

typedef struct rnp_selfsig_cert_info_t {
    uint8_t          userid[MAX_ID_LENGTH]; /* userid, required */
    uint8_t          key_flags;             /* key flags */
    uint32_t         key_expiration;        /* key expiration time (sec), 0 = no expiration */
    pgp_user_prefs_t prefs;                 /* user preferences, optional */
    unsigned         primary : 1;           /* mark this as the primary user id */
} rnp_selfsig_cert_info_t;

typedef struct rnp_selfsig_binding_info_t {
    uint8_t  key_flags;
    uint32_t key_expiration;
} rnp_selfsig_binding_info_t;

typedef struct rnp_keygen_primary_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_cert_info_t    cert;
} rnp_keygen_primary_desc_t;

typedef struct rnp_keygen_subkey_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_binding_info_t binding;
} rnp_keygen_subkey_desc_t;

typedef struct rnp_key_protection_params_t {
    pgp_symm_alg_t    symm_alg;
    pgp_cipher_mode_t cipher_mode;
    unsigned          iterations;
    pgp_hash_alg_t    hash_alg;
} rnp_key_protection_params_t;

#endif /* TYPES_H_ */
