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


#ifndef __MRKEY_H__
#define __MRKEY_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct sqlite3_stmt sqlite3_stmt;


#define MR_PUBLIC  0
#define MR_PRIVATE 1


/**
 * Library-internal.
 */
typedef struct dc_key_t
{
	void*          m_binary;
	int            m_bytes;
	int            m_type;

	/** @privatesection */
	int            _m_heap_refcnt; /* !=0 for objects created with dc_key_new(), 0 for stack objects  */
} dc_key_t;


dc_key_t* dc_key_new           ();
dc_key_t* dc_key_ref           (dc_key_t*);
void     dc_key_unref         (dc_key_t*);

int   dc_key_set_from_binary  (dc_key_t*, const void* data, int bytes, int type);
int   dc_key_set_from_key     (dc_key_t*, const dc_key_t*);
int   dc_key_set_from_stmt    (dc_key_t*, sqlite3_stmt*, int index, int type);
int   dc_key_set_from_base64  (dc_key_t*, const char* base64, int type);
int   dc_key_set_from_file    (dc_key_t*, const char* file, mrmailbox_t* mailbox);

int   dc_key_equals        (const dc_key_t*, const dc_key_t*);

int   dc_key_save_self_keypair__(const dc_key_t* public_key, const dc_key_t* private_key, const char* addr, int is_default, dc_sqlite3_t* sql);
int   dc_key_load_self_public__ (dc_key_t*, const char* self_addr, dc_sqlite3_t* sql);
int   dc_key_load_self_private__(dc_key_t*, const char* self_addr, dc_sqlite3_t* sql);

char* mr_render_base64   (const void* buf, size_t buf_bytes, int break_every, const char* break_chars, int add_checksum); /* the result must be freed */
char* dc_key_render_base64(const dc_key_t* ths, int break_every, const char* break_chars, int add_checksum); /* the result must be freed */
char* dc_key_render_asc   (const dc_key_t*, const char* add_header_lines); /* each header line must be terminated by \r\n, the result must be freed */
int   dc_key_render_asc_to_file(const dc_key_t*, const char* file, mrmailbox_t* mailbox);

char* mr_format_fingerprint          (const char*);
char* mr_normalize_fingerprint       (const char*);
char* dc_key_get_fingerprint          (const dc_key_t*);
char* dc_key_get_formatted_fingerprint(const dc_key_t*);

void  mr_wipe_secret_mem(void* buf, size_t buf_bytes);

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRKEY_H__ */

