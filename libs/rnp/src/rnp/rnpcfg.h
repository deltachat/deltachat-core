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
#ifndef RNP_CFG_H_
#define RNP_CFG_H_

#include <rnp/rnp.h>
#include <stdbool.h>
#include "list.h"

/* cfg variables known by rnp */
#define CFG_OVERWRITE "overwrite" /* overwrite output file if it is already exist or fail */
#define CFG_ARMOR "armor"         /* armor output data or not */
#define CFG_ARMOR_DATA_TYPE "armor_type" /* armor data type, used with ``enarmor`` option */
#define CFG_COMMAND "command"            /* command to execute over input data */
#define CFG_DETACHED "detached"          /* produce the detached signature */
#define CFG_CLEARTEXT "cleartext"        /* cleartext signing should be used */
#define CFG_SIGN_NEEDED "sign_needed"    /* signing is needed during data protection */
#define CFG_OUTFILE "outfile"            /* name/path of the output file */
#define CFG_NO_OUTPUT "no_output"        /* do not output any data - just verify or process */
#define CFG_INFILE "infile"              /* name/path of the input file */
#define CFG_RESULTS "results"            /* name/path for results, not used right now */
#define CFG_KEYSTOREFMT "keystorefmt"    /* keyring format : GPG, G10, KBX */
#define CFG_SUBDIRGPG "subdirgpg"        /* gpg/rnp files subdirectory: .rnp by default */
#define CFG_COREDUMPS "coredumps"        /* enable/disable core dumps. 1 or 0. */
#define CFG_NEEDSSECKEY "needsseckey"    /* needs secret key for the ongoing operation */
#define CFG_KEYRING "keyring"       /* path to the keyring ?? seems not to be used anywhere */
#define CFG_USERID "userid"         /* userid for the ongoing operation */
#define CFG_RECIPIENTS "recipients" /* list of encrypted data recipients */
#define CFG_SIGNERS "signers"       /* list of signers */
#define CFG_VERBOSE "verbose"       /* verbose logging */
#define CFG_HOMEDIR "homedir"       /* home directory - folder with keyrings and so on */
#define CFG_KEYFILE "keyfile"       /* path to the file with key(s), used instead of keyring */
#define CFG_PASSFD "pass-fd"        /* password file descriptor */
#define CFG_PASSWD "password"       /* password as command-line constant */
#define CFG_PASSWORDC "passwordc"   /* number of passwords for symmetric encryption */
#define CFG_USERINPUTFD "user-input-fd" /* user input file descriptor */
#define CFG_NUMTRIES "numtries"         /* number of password request tries, or 'unlimited' */
#define CFG_EXPIRATION "expiration"     /* signature expiration time */
#define CFG_CREATION "creation"         /* signature validity start */
#define CFG_CIPHER "cipher"             /* symmetric encryption algorithm as string */
#define CFG_HASH "hash"                 /* hash algorithm used, string like 'SHA1'*/
#define CFG_S2K_ITER "s2k-iter"         /* number of S2K hash iterations to perform */
#define CFG_S2K_MSEC "s2k-msec"         /* number of milliseconds S2K should target */
#define CFG_ENCRYPT_PK "encrypt_pk"     /* public key should be used during encryption */
#define CFG_ENCRYPT_SK "encrypt_sk"     /* password encryption should be used */
#define CFG_IO_RESS "ress"              /* results stream */
#define CFG_NUMBITS "numbits"           /* number of bits in generated key */
#define CFG_KEYFORMAT "format"          /* key format : "human" for human-readable or ... */
#define CFG_EXPERT "expert"             /* expert key generation mode */
#define CFG_ZLEVEL "zlevel"             /* compression level: 0..9 (0 for no compression) */
#define CFG_ZALG "zalg"                 /* compression algorithm: zip, zlib or bzip2 */
#define CFG_AEAD "aead"                 /* if nonzero then AEAD enryption mode, int */
#define CFG_AEAD_CHUNK "aead_chunk"     /* AEAD chunk size bits, int from 0 to 56 */
#define CFG_KEYSTORE_DISABLED \
    "disable_keystore"      /* indicates wether keystore must be initialized */
#define CFG_FORCE "force"   /* force command to succeed operation */
#define CFG_SECRET "secret" /* indicates operation on secret key */

/* rnp CLI config : contains all the system-dependent and specified by the user configuration
 * options */
typedef struct rnp_cfg_t {
    list vals;
} rnp_cfg_t;

typedef struct rnp_cfg_val_t rnp_cfg_val_t;

/** @brief initialize rnp_cfg structure internals. When structure is not needed anymore
 *         it should be freed via rnp_cfg_free function call
 *  @param cfg allocated rnp_cfg_t structure
 **/
void rnp_cfg_init(rnp_cfg_t *cfg);

/** @brief load default settings to the rnp_cfg_t structure
 *  @param cfg allocated and initialized rnp_cfg_t structure
 **/
void rnp_cfg_load_defaults(rnp_cfg_t *cfg);

/** @brief apply configuration from keys-vals storage to rnp_params_t structure
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] this structure will be filled so can be further feed into rnp_init.
 *                Must be later freed using the rnp_params_free even if rnp_cfg_apply fails.
 *
 *  @return true on success, false if something went wrong
 **/
bool rnp_cfg_apply(rnp_cfg_t *cfg, rnp_params_t *params);

/** @brief set string value for the key in config
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be set
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool rnp_cfg_setstr(rnp_cfg_t *cfg, const char *key, const char *val);

/** @brief set integer value for the key in config
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be set
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val);

/** @brief set boolean value for the key in config
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be set
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool rnp_cfg_setbool(rnp_cfg_t *cfg, const char *key, bool val);

/** @brief add string item to the list value
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be appended to the list
 *
 *  @return true if operation succeeds or false otherwise
 **/
bool rnp_cfg_addstr(rnp_cfg_t *cfg, const char *key, const char *str);

/** @brief unset value for the key in config, deleting it
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return true if value was found and deleted or false otherwise
 **/
bool rnp_cfg_unset(rnp_cfg_t *cfg, const char *key);

/** @brief return true if key is set in the configuration
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return if the key exists within the configuration or not
 **/
bool rnp_cfg_hasval(const rnp_cfg_t *cfg, const char *key);

/** @brief return string value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return stored string if item is found and has string value or NULL otherwise
 **/
const char *rnp_cfg_getstr(const rnp_cfg_t *cfg, const char *key);

/** @brief return integer value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return integer value or 0 if there is no value or it is non-integer
 **/
int rnp_cfg_getint(rnp_cfg_t *cfg, const char *key);

/** @brief return boolean value for the key if there is one
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return true if 'true', 'True', or non-zero integer is stored in value, false otherwise
 **/
bool rnp_cfg_getbool(rnp_cfg_t *cfg, const char *key);

/** @brief return list value for the key if there is one. Each list's element contains
 *  rnp_cfg_val_t element with the corresponding value. List may be modified.
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *
 *  @return pointer to the list on success or NULL if value was not found or has other type
 **/
list *rnp_cfg_getlist(rnp_cfg_t *cfg, const char *key);

/** @brief copy string values as char * from the list to destination
 *  @param cfg rnp config, must be allocated and initialized
 *  @param dst pointer to the list structure, where strings will be stored
 *  @param key must be null-terminated string
 *
 *  @return true on success or false otherwise
 **/
bool rnp_cfg_copylist_str(rnp_cfg_t *cfg, list *dst, const char *key);

/** @brief free the memory allocated in rnp_cfg_t
 *  @param cfg rnp config, must be allocated and initialized
 **/
void rnp_cfg_free(rnp_cfg_t *cfg);

/** @brief get the string value from rnp_cfg_val_t record
 *  @param val pointer to the value of rnp_cfg_val_t type, may be NULL
 *  @return pointer to the NULL-terminated string if value has string, or NULL otherwise
 */
const char *rnp_cfg_val_getstr(rnp_cfg_val_t *val);

/** @brief return integer value for the key if there is one, or default value otherwise
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param def default value
 *
 *  @return integer value or def if there is no value or it is non-integer
 **/
int rnp_cfg_getint_default(rnp_cfg_t *cfg, const char *key, int def);

/** @brief Copies or overrides configuration
 *  @param dst resulting configuration object
 *  @param src vals in dst will be overriden (if key exist) or coppied (if not)
 *         from this object
 *
 *  @pre   dst is correctly initialized and not NULL
 *
 **/
void rnp_cfg_copy(rnp_cfg_t *dst, const rnp_cfg_t *src);

/** @brief Return the desired hash algorithm.
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @return desired hash algorithm, or default value if not set by user
 */
const char* rnp_cfg_gethashalg(rnp_cfg_t* cfg);

/** @brief Fill the keyring pathes according to user-specified settings
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] in this structure public and secret keyring pathes  will be filled
 *  @return true on success or false if something went wrong
 */
bool rnp_cfg_get_ks_info(rnp_cfg_t *cfg, rnp_params_t *params);

/** @brief Attempt to get the default key id/name in a number of ways
 *  Tries to find via user-specified parameters and  GnuPG conffile.
 *
 *  @param cfg [in] rnp config, must be allocated and initialized
 *  @param params [out] in this structure defkey will be filled if found
 */
void rnp_cfg_get_defkey(rnp_cfg_t *cfg, rnp_params_t *params);

/** @brief Get number of password tries according to defaults and value, stored in cfg
 *  @param cfg allocated and initalized config
 *  @return number of password tries or INFINITE_ATTEMPTS
 */
int rnp_cfg_get_pswdtries(rnp_cfg_t *cfg);

/* rnp CLI helper functions */

/** @brief Get signature validity expiration time from the user input
 *
 *  Signature expiration may be specified in different formats:
 *  - 10d : 10 days (you can use [h]ours, d[ays], [w]eeks, [m]onthes)
 *  - 2017-07-12 : as the exact date when signature becomes invalid
 *  - 60000 : number of seconds
 *
 *  @param s [in] NULL-terminated string with the date
 *  @param t [out] On successfull return result will be placed here
 *  @return expiration time in seconds
 */
uint64_t get_expiration(const char *s);

/** @brief Get signature validity start time from the user input
 *
 *  Signature validity may be specified in different formats:
 *  - 2017-07-12 : as the exact date when signature becomes invalid
 *  - 1499334073 : timestamp
 *
 *  @param s [in] NULL-terminated string with the date
 *  @return timestamp of the validity start
 */
int64_t get_creation(const char *s);

#endif
