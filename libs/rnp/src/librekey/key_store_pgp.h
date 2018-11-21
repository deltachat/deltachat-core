/*
 * Copyright (c) 2017-2018, [Ribose Inc](https://www.ribose.com).
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

#ifndef KEY_STORE_PGP_H_
#define KEY_STORE_PGP_H_

#include <rekey/rnp_key_store.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-key.h>
#include "memory.h"

rnp_result_t rnp_key_store_pgp_read_from_src(rnp_key_store_t *keyring, pgp_source_t *src);

bool rnp_key_store_pgp_read_from_mem(rnp_key_store_t *,
                                     pgp_memory_t *,
                                     const pgp_key_provider_t *);

bool rnp_key_store_pgp_write_to_mem(rnp_key_store_t *, bool, pgp_memory_t *);

bool rnp_key_store_pgp_write_to_dst(rnp_key_store_t *key_store, bool armor, pgp_dest_t *dst);

bool rnp_key_store_add_transferable_subkey(rnp_key_store_t *          keyring,
                                           pgp_transferable_subkey_t *tskey,
                                           pgp_key_t *                pkey);

bool rnp_key_store_add_transferable_key(rnp_key_store_t *       keyring,
                                        pgp_transferable_key_t *tkey);

bool rnp_key_from_transferable_key(pgp_key_t *key, pgp_transferable_key_t *tkey);

bool rnp_key_from_transferable_subkey(pgp_key_t *                subkey,
                                      pgp_transferable_subkey_t *tskey,
                                      pgp_key_t *                primary);

bool rnp_key_add_transferable_userid(pgp_key_t *key, pgp_transferable_userid_t *uid);

bool rnp_key_write_packets_stream(const pgp_key_t *key, pgp_dest_t *dst);

bool rnp_key_add_key_rawpacket(pgp_key_t *key, pgp_key_pkt_t *pkt);

bool rnp_key_add_rawpacket(pgp_key_t *key, const pgp_rawpacket_t *packet);

bool rnp_key_to_src(const pgp_key_t *key, pgp_source_t *src);

bool rnp_key_add_subkey_grip(pgp_key_t *key, uint8_t *grip);

#endif /* KEY_STORE_PGP_H_ */
