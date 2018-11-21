/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_ARMOUR_H_
#define STREAM_ARMOUR_H_

#include "stream-common.h"

typedef enum {
    PGP_ARMORED_UNKNOWN,
    PGP_ARMORED_MESSAGE,
    PGP_ARMORED_PUBLIC_KEY,
    PGP_ARMORED_SECRET_KEY,
    PGP_ARMORED_SIGNATURE,
    PGP_ARMORED_CLEARTEXT
} pgp_armored_msg_t;

/* @brief Init dearmoring stream
 * @param src allocated pgp_source_t structure
 * @param readsrc source to read data from
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t init_armored_src(pgp_source_t *src, pgp_source_t *readsrc);

/* @brief Init armoring stream
 * @param dst allocated pgp_dest_t structure
 * @param writedst destination to write armored data to
 * @param msgtype type of the message (see pgp_armored_msg_t)
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t init_armored_dst(pgp_dest_t *      dst,
                              pgp_dest_t *      writedst,
                              pgp_armored_msg_t msgtype);

/* @brief Dearmor the source, outputing binary data
 * @param src initialized source with armored data
 * @param dst initialized dest to write binary data to
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t rnp_dearmor_source(pgp_source_t *src, pgp_dest_t *dst);

/* @brief Armor the source, outputing base64-encoded data with headers
 * @param src initialized source with binary data
 * @param dst destination to write armored data
 * @msgtype type of the message, to write correct armor headers
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t rnp_armor_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armored_msg_t msgtype);

/* @brief Guess the corresponding armored message type by first byte(s) of PGP message
 * @param src initialized source with binary PGP message data
 * @return corresponding enum element or PGP_ARMORED_UNKNOWN
 **/
pgp_armored_msg_t rnp_armor_guess_type(pgp_source_t *src);

/* @brief Check whether source could be an armored source
 * @param src initialized source with some data
 * @return true if source could be an armored data or false otherwise
 **/
bool is_armored_source(pgp_source_t *src);

/* @brief Check whether source is cleartext signed
 * @param src initialized source with some data
 * @return true if source could be a cleartext signed data or false otherwise
 **/
bool is_cleartext_source(pgp_source_t *src);

#endif
