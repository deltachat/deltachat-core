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

#ifndef __RNP_TYPES__
#define __RNP_TYPES__

#include <stdint.h>
#include <repgp/repgp.h>

#include "types.h"
#include "pass-provider.h"
#include "key-provider.h"
#include "list.h"
#include "crypto/rng.h"

typedef struct rnp_action_keygen_t {
    struct {
        rnp_keygen_primary_desc_t   keygen;
        rnp_key_protection_params_t protection;
    } primary;
    struct {
        rnp_keygen_subkey_desc_t    keygen;
        rnp_key_protection_params_t protection;
    } subkey;
} rnp_action_keygen_t;

typedef struct rnp_key_store_t rnp_key_store_t;

/* structure used to keep application-wide rnp configuration: keyrings, password io, whatever
 * else */
typedef struct rnp_t {
    rnp_key_store_t *pubring;       /* public key ring */
    rnp_key_store_t *secring;       /* s3kr1t key ring */
    FILE *           resfp;         /* where to put result messages, defaults to stdout */
    FILE *           user_input_fp; /* file pointer for user input */
    FILE *           passfp;        /* file pointer for password input */
    char *           defkey;        /* default key id */
    int              pswdtries;     /* number of password tries, -1 for unlimited */

    union {
        rnp_action_keygen_t generate_key_ctx;
    } action;

    pgp_password_provider_t password_provider;
    pgp_key_provider_t      key_provider;
    rng_t                   rng; /* handle to rng_t */
} rnp_t;

/* rnp initialization parameters : keyring pathes, flags, whatever else */
typedef struct rnp_params_t {
    unsigned enable_coredumps; /* enable coredumps: if it is allowed then they are disabled by
                                  default to not leak confidential information */

    int         passfd; /* password file descriptor */
    int         userinputfd;
    const char *ress; /* results stream : maye be <stdout>, <stderr> or file name/path */

    const char *ks_pub_format;     /* format of the public key store */
    const char *ks_sec_format;     /* format of the secret key store */
    char *      pubpath;           /* public keystore path */
    char *      secpath;           /* secret keystore path */
    char *      defkey;            /* default/preferred key id */
    bool        keystore_disabled; /* indicates wether keystore must be initialized */
    pgp_password_provider_t password_provider;
} rnp_params_t;

typedef struct rnp_symmetric_pass_info_t {
    pgp_s2k_t      s2k;
    pgp_symm_alg_t s2k_cipher;
    uint8_t        key[PGP_MAX_KEY_SIZE];
} rnp_symmetric_pass_info_t;

typedef enum rnp_operation_t {
    RNP_OP_UNKNOWN = 0,
    RNP_OP_DECRYPT_VERIFY = 1,
    RNP_OP_ENCRYPT_SIGN = 2,
    RNP_OP_ARMOR = 3
} rnp_operation_t;

/** rnp operation context : contains configuration data about the currently ongoing operation.
 *
 *  Common fields which make sense for every operation:
 *  - overwrite : silently overwrite output file if exists
 *  - armor : except cleartext signing, which outputs text in clear and always armor signature,
 *    this controls whether output is armored (base64-encoded). For armor/dearmor operation it
 *    controls the direction of the conversion (true means enarmor, false - dearmor),
 *  - rng : random number generator
 *  - operation : current operation type
 *
 *  For operations with OpenPGP embedded data (i.e. encrypted data and attached signatures):
 *  - filename, filemtime : to specify information about the contents of literal data packet
 *  - zalg, zlevel : compression algorithm and level, zlevel = 0 to disable compression
 *
 *  For encryption operation (including encrypt-and-sign):
 *  - halg : hash algorithm used during key derivation for password-based encryption
 *  - ealg, aalg, abits : symmetric encryption algorithm and AEAD parameters if used
 *  - recipients : list of key ids used to encrypt data to
 *  - passwords : list of passwords used for password-based encryption
 *  - filename, filemtime, zalg, zlevel : see previous
 *
 *  For signing of any kind (attached, detached, cleartext):
 *  - clearsign, detached : controls kind of the signed data. Both are mutually-exclusive.
 *    If both are false then attached signing is used.
 *  - halg : hash algorithm used to calculate signature(s)
 *  - signers : list of key pointers used to sign data
 *  - sigcreate, sigexpire : signature(s) creation and expiration times
 *  - filename, filemtime, zalg, zlevel : only for attached signatures, see previous
 *
 *  For data decryption and/or verification there is not much of fields:
 *  - on_signatures: callback, called when signature verification information is available.
 *    If we have just encrypted data then it will not be called.
 *  - sig_cb_param: parameter to be passed to on_signatures callback.
 *  - discard: dicard the output data (i.e. just decrypt and/or verify signatures)
 *
 *  For enarmor/dearmor:
 *  - armortype: type of the armor headers (message, key, whatever else)
 */
typedef struct rnp_ctx_t {
    rnp_t *         rnp;           /* Pointer to initialized rnp_t (temporary solution) */
    char *          filename;      /* name of the input file to store in literal data packet */
    int64_t         filemtime;     /* file modification time to store in literal data packet */
    int64_t         sigcreate;     /* signature creation time */
    uint64_t        sigexpire;     /* signature expiration time */
    bool            clearsign;     /* cleartext signature */
    bool            detached;      /* detached signature */
    pgp_hash_alg_t  halg;          /* hash algorithm */
    pgp_symm_alg_t  ealg;          /* encryption algorithm */
    int             zalg;          /* compression algorithm used */
    int             zlevel;        /* compression level */
    pgp_aead_alg_t  aalg;          /* non-zero to use AEAD */
    int             abits;         /* AEAD chunk bits */
    bool            overwrite;     /* allow to overwrite output file if exists */
    bool            armor;         /* whether to use ASCII armor on output */
    list            recipients;    /* recipients of the encrypted message */
    list            passwords;     /* list of rnp_symmetric_pass_info_t */
    list            signers;       /* list of signer key ids/user ids */
    unsigned        armortype;     /* type of the armored message, used in enarmor command */
    bool            discard;       /* discard the output */
    void *          on_signatures; /* handler for signed messages */
    void *          sig_cb_param;  /* callback data passed to on_signatures */
    rng_t *         rng;           /* pointer to rng_t */
    rnp_operation_t operation;     /* current operation type */
} rnp_ctx_t;

#endif // __RNP_TYPES__
