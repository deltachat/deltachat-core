/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 *******************************************************************************
 *
 * File:    mrpgp.h
 * Purpose: Frontend for the crypto-engine
 *
 ******************************************************************************/



#ifndef __MRPGP_H__
#define __MRPGP_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mrkey_t mrkey_t;
typedef struct mrkeyring_t mrkeyring_t;

void mrpgp_init             (mrmailbox_t*);
void mrpgp_exit             (mrmailbox_t*);
void mrpgp_rand_seed        (mrmailbox_t*, const void* buf, size_t bytes);
int  mrpgp_create_keypair   (mrmailbox_t*, const char* addr, mrkey_t* public_key, mrkey_t* private_key);
int  mrpgp_is_valid_key     (mrmailbox_t*, const mrkey_t*);
int  mrpgp_calc_fingerprint (mrmailbox_t*, const mrkey_t*, uint8_t** fingerprint, size_t* fingerprint_bytes);
int  mrpgp_split_key        (mrmailbox_t*, const mrkey_t* private_in, mrkey_t* public_out);
int  mrpgp_encrypt          (mrmailbox_t*, const void* plain, size_t plain_bytes, const mrkeyring_t*, int use_armor, void** ret_ctext, size_t* ret_ctext_bytes);
int  mrpgp_decrypt          (mrmailbox_t*, const void* ctext, size_t ctext_bytes, const mrkeyring_t*, int use_armor, void** plain, size_t* plain_bytes);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRPGP_H__ */
