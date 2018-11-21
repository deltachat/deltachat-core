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

/** \file
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <limits.h>
#include <librepgp/packet-print.h>
#include "memory.h"
#include "crypto/common.h"
#include <rekey/rnp_key_store.h>

/* raw key generation */
bool pgp_generate_seckey(const rnp_keygen_crypto_params_t *params,
                         pgp_key_pkt_t *                   seckey,
                         bool                              primary);

/** generate a new primary key
 *
 *  @param desc keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to store the generated secret key, must not be NULL
 *  @param primary_pub pointer to store the generated public key, must not be NULL
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_primary_key(rnp_keygen_primary_desc_t *desc,
                              bool                       merge_defaults,
                              pgp_key_t *                primary_sec,
                              pgp_key_t *                primary_pub,
                              key_store_format_t         secformat);

/** generate a new subkey
 *
 *  @param desc keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to the primary secret key that will own this
 *         subkey, must not be NULL
 *  @param primary_pub pointer to the primary public key that will own this
 *         subkey, must not be NULL
 *  @param subkey_sec pointer to store the generated secret key, must not be NULL
 *  @param subkey_pub pointer to store the generated public key, must not be NULL
 *  @param password_provider the password provider that will be used to
 *         decrypt the primary key, may be NULL if primary key is unlocked
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_subkey(rnp_keygen_subkey_desc_t *     desc,
                         bool                           merge_defaults,
                         pgp_key_t *                    primary_sec,
                         pgp_key_t *                    primary_pub,
                         pgp_key_t *                    subkey_sec,
                         pgp_key_t *                    subkey_pub,
                         const pgp_password_provider_t *password_provider,
                         key_store_format_t             secformat);

/** generate a new primary key and subkey
 *
 *  @param rng initialized RNG
 *  @param primary_desc primary keygen description
 *  @param subkey_desc subkey keygen description
 *  @param merge_defaults true if you want defaults to be set for unset
 *         keygen description parameters.
 *  @param primary_sec pointer to store the generated secret key, must not be NULL
 *  @param primary_pub pointer to store the generated public key, must not be NULL
 *  @param subkey_sec pointer to store the generated secret key, must not be NULL
 *  @param subkey_pub pointer to store the generated public key, must not be NULL
 *  @return true if successful, false otherwise.
 **/
bool pgp_generate_keypair(rng_t *                    rng,
                          rnp_keygen_primary_desc_t *primary_desc,
                          rnp_keygen_subkey_desc_t * subkey_desc,
                          bool                       merge_defaults,
                          pgp_key_t *                primary_sec,
                          pgp_key_t *                primary_pub,
                          pgp_key_t *                subkey_sec,
                          pgp_key_t *                subkey_pub,
                          key_store_format_t         secformat);

/**
 * @brief Check two key material for equality. Only public part is checked, so this can be
 *        called on public/secret key material
 *
 * @param key1 first key material
 * @param key2 second key material
 * @return true if both key materials are equal or false otherwise
 */
bool key_material_equal(const pgp_key_material_t *key1, const pgp_key_material_t *key2);

rnp_result_t validate_pgp_key_material(const pgp_key_material_t *material, rng_t *rng);

#endif /* CRYPTO_H_ */
