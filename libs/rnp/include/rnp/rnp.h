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
#ifndef RNP_H_
#define RNP_H_

#include <stddef.h>
#include <stdbool.h>

#include <rnp/rnp_def.h>
#include <rnp/rnp_types.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct rnp_t        rnp_t;
typedef struct rnp_params_t rnp_params_t;
typedef struct rnp_ctx_t    rnp_ctx_t;

/* initialize rnp using the init structure  */
rnp_result_t rnp_init(rnp_t *, const rnp_params_t *);
/* finish work with rnp and cleanup the memory */
void rnp_end(rnp_t *);

/* rnp initialization parameters : init and free */
void rnp_params_init(rnp_params_t *);
void rnp_params_free(rnp_params_t *);

/* init, reset and free rnp operation context */
rnp_result_t     rnp_ctx_init(rnp_ctx_t *, rnp_t *);
void             rnp_ctx_reset(rnp_ctx_t *);
void             rnp_ctx_free(rnp_ctx_t *);
struct rng_st_t *rnp_ctx_rng_handle(const rnp_ctx_t *ctx);

/* debugging, reflection and information */
int         rnp_set_debug(const char *);
int         rnp_get_debug(const char *);
const char *rnp_get_info(const char *);

/* set key store format information */
int rnp_set_key_store_format(rnp_t *, const char *);

/* key management */
bool   rnp_list_keys(rnp_t *, const int);
bool   rnp_list_keys_json(rnp_t *, char **, const int);
bool   rnp_find_key(rnp_t *, const char *);
char * rnp_get_key(rnp_t *, const char *, const char *);
char * rnp_export_key(rnp_t *, const char *, bool);
bool   rnp_add_key(rnp_t *rnp, const char *path, bool print);
bool   rnp_import_key(rnp_t *, const char *);
bool   rnp_generate_key(rnp_t *);
size_t rnp_secret_count(rnp_t *);
size_t rnp_public_count(rnp_t *);

/* file management */
rnp_result_t rnp_process_file(rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_protect_file(rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_dump_file(rnp_ctx_t *, const char *, const char *);

/* memory signing and encryption */
rnp_result_t rnp_process_mem(rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);
rnp_result_t rnp_protect_mem(rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);

/* match and hkp-related functions */
int rnp_match_keys_json(rnp_t *, char **, char *, const char *, const int);
int rnp_match_keys(rnp_t *, char *, const char *, void *, const int);
int rnp_match_pubkeys(rnp_t *, char *, void *);
int rnp_format_json(void *, const char *, const int);

/**
 * @brief   Armor (convert to ASCII) or dearmor (convert back to binary) PGP data
 *
 * @param   ctx  Initialized rnp context. Field armortype may specify the type of armor
 *               header used, otherwise it will be detected automatically from the source.
 * @param   in   Input file path
 * @param   out  Output file path
 *
 * @return  RNP_SUCCESS on success, error code on failure
 */
rnp_result_t rnp_armor_stream(rnp_ctx_t *ctx, bool armor, const char *in, const char *out);

rnp_result_t rnp_encrypt_set_pass_info(rnp_symmetric_pass_info_t *info,
                                       const char *               password,
                                       pgp_hash_alg_t             hash_alg,
                                       size_t                     iterations,
                                       pgp_symm_alg_t             s2k_cipher);
rnp_result_t rnp_encrypt_add_password(rnp_ctx_t *ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !RNP_H_ */
