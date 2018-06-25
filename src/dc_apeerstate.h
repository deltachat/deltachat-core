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
 ******************************************************************************/


#ifndef __DC_APEERSTATE_H__
#define __DC_APEERSTATE_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "dc_key.h"


typedef struct dc_aheader_t dc_aheader_t;


#define DC_PE_NOPREFERENCE   0 /* prefer-encrypt states */
#define DC_PE_MUTUAL         1
#define DC_PE_RESET         20


/**
 * Library-internal.
 */
typedef struct dc_apeerstate_t
{
	/** @privatesection */
	dc_context_t*  m_context;

	char*          m_addr;
	time_t         m_last_seen;  /* may be 0 if the peer was created by gossipping */

	time_t         m_last_seen_autocrypt;
	int            m_prefer_encrypt;

	#define        DC_NOT_VERIFIED      0
	#define        DC_BIDIRECT_VERIFIED 2

	dc_key_t*      m_public_key; /* may be NULL, however, in the database, either public_key or gossip_key is set */
	char*          m_public_key_fingerprint;

	dc_key_t*      m_gossip_key; /* may be NULL */
	time_t         m_gossip_timestamp;
	char*          m_gossip_key_fingerprint;

	dc_key_t*      m_verified_key; // may be NULL
	char*          m_verified_key_fingerprint;

	#define        DC_SAVE_TIMESTAMPS 0x01
	#define        DC_SAVE_ALL        0x02
	int            m_to_save;

	#define        DC_DE_ENCRYPTION_PAUSED   0x01 // recoverable by an incoming encrypted mail
	#define        DC_DE_FINGERPRINT_CHANGED 0x02 // recoverable by a new verify
	int            m_degrade_event;

} dc_apeerstate_t;


dc_apeerstate_t* dc_apeerstate_new                  (dc_context_t*); /* the returned pointer is ref'd and must be unref'd after usage */
void             dc_apeerstate_unref                (dc_apeerstate_t*);

int              dc_apeerstate_init_from_header     (dc_apeerstate_t*, const dc_aheader_t*, time_t message_time);
int              dc_apeerstate_init_from_gossip     (dc_apeerstate_t*, const dc_aheader_t*, time_t message_time);

int              dc_apeerstate_degrade_encryption   (dc_apeerstate_t*, time_t message_time);

void             dc_apeerstate_apply_header         (dc_apeerstate_t*, const dc_aheader_t*, time_t message_time);
void             dc_apeerstate_apply_gossip         (dc_apeerstate_t*, const dc_aheader_t*, time_t message_time);

char*            dc_apeerstate_render_gossip_header (const dc_apeerstate_t*, int min_verified);

dc_key_t*        dc_apeerstate_peek_key             (const dc_apeerstate_t*, int min_verified);

int              dc_apeerstate_recalc_fingerprint   (dc_apeerstate_t*);

#define          DC_PS_GOSSIP_KEY 0
#define          DC_PS_PUBLIC_KEY 1
int              dc_apeerstate_set_verified         (dc_apeerstate_t*, int which_key, const char* fingerprint, int verfied);

int              dc_apeerstate_load_by_addr__       (dc_apeerstate_t*, dc_sqlite3_t*, const char* addr);
int              dc_apeerstate_load_by_fingerprint__(dc_apeerstate_t*, dc_sqlite3_t*, const char* fingerprint);
int              dc_apeerstate_save_to_db__         (const dc_apeerstate_t*, dc_sqlite3_t*, int create);

int              dc_apeerstate_has_verified_key     (const dc_apeerstate_t*, const dc_hash_t* fingerprints);

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_APEERSTATE_H__ */

