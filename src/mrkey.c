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
 * File:    mrkey.c
 * Purpose: Handle keys
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrkey.h"
#include "mrtools.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mrkey_init(mrkey_t* ths)
{
	if( ths ) {
		memset(ths, 0, sizeof(mrkey_t));
	}
}


int mrkey_set_from_raw(mrkey_t* ths, const unsigned char* data, int bytes, int type)
{
    mrkey_empty(ths);
    if( ths==NULL || data==NULL || bytes <= 0 ) {
		return 0;
    }
    ths->m_binary = malloc(bytes);
    if( ths->m_binary == NULL ) {
		exit(40);
    }
    memcpy(ths->m_binary, data, bytes);
    ths->m_bytes = bytes;
    ths->m_type = type;
    return 1;
}


int mrkey_set_from_key(mrkey_t* ths, const mrkey_t* o, int type)
{
	mrkey_empty(ths);
	if( ths==NULL || o==NULL ) {
		return 0;
	}
	return mrkey_set_from_raw(ths, o->m_binary, o->m_bytes, type);
}


int mrkey_set_from_stmt(mrkey_t* ths, sqlite3_stmt* stmt, int index, int type)
{
	mrkey_empty(ths);
	if( ths==NULL || stmt==NULL ) {
		return 0;
	}
	return mrkey_set_from_raw(ths, (unsigned char*)sqlite3_column_blob(stmt, index), sqlite3_column_bytes(stmt, index), type);
}


void mrkey_empty(mrkey_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	if( ths->m_type==MR_PRIVATE ) {
		if( ths->m_binary && ths->m_bytes>0 ) {
			/* wipe private keys with different patterns. Don't know, if this helps, however, it should not hurt.
			(in general, we keep the private keys in memory as short as possible and only if really needed.
			on disk, eg. on Android, it is not accessible for other Apps - so all this should be quite safe) */
			memset(ths->m_binary, 0xFF, ths->m_bytes); /* pattern 11111111 */
			memset(ths->m_binary, 0xAA, ths->m_bytes); /* pattern 10101010 */
			memset(ths->m_binary, 0x55, ths->m_bytes); /* pattern 01010101 */
			memset(ths->m_binary, 0x00, ths->m_bytes); /* pattern 00000000 */
		}
	}

	free(ths->m_binary);
	ths->m_binary = NULL;
	ths->m_bytes = 0;
	ths->m_type = MR_PUBLIC;
}


int mrkey_equals(const mrkey_t* ths, const mrkey_t* o)
{
	if( ths==NULL || o==NULL
	 || ths->m_binary==NULL || ths->m_bytes<=0 || o->m_binary==NULL || o->m_bytes<=0 ) {
		return 0; /*error*/
	}

	if( ths->m_bytes != o->m_bytes ) {
		return 0; /*different size -> the keys cannot be equal*/
	}

	if( ths->m_type != o->m_type ) {
		return 0; /* cannot compare public with private keys */
	}

	return memcmp(ths->m_binary, o->m_binary, o->m_bytes)==0? 1 : 0;
}


/*******************************************************************************
 * Save/Load keys
 ******************************************************************************/


int mrkey_save_self_keypair__(const mrkey_t* public_key, const mrkey_t* private_key, const char* addr, mrsqlite3_t* sql)
{
	sqlite3_stmt* stmt;

	if( public_key==NULL || private_key==NULL || addr==NULL || sql==NULL
	 || public_key->m_binary==NULL || private_key->m_binary==NULL ) {
		return 0;
	}

	stmt = mrsqlite3_predefine__(sql, INSERT_INTO_keypairs_aippc,
		"INSERT INTO keypairs (addr, is_default, public_key, private_key, created) VALUES (?,?,?,?,?);");
	sqlite3_bind_text (stmt, 1, addr, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt, 2, 1);
	sqlite3_bind_blob (stmt, 3, public_key->m_binary, public_key->m_bytes, SQLITE_STATIC);
	sqlite3_bind_blob (stmt, 4, private_key->m_binary, private_key->m_bytes, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 5, time(NULL));
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		return 0;
	}

	return 1;
}


int mrkey_load_self_public__(mrkey_t* ths, const char* self_addr, mrsqlite3_t* sql)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || self_addr==NULL || sql==NULL ) {
		return 0;
	}

	mrkey_empty(ths);
	stmt = mrsqlite3_predefine__(sql, SELECT_public_key_FROM_keypairs_WHERE_default,
		"SELECT public_key FROM keypairs WHERE addr=? AND is_default=1;");
	sqlite3_bind_text (stmt, 1, self_addr, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}
	mrkey_set_from_stmt(ths, stmt, 0, MR_PUBLIC);
	return 1;
}


int mrkey_load_self_private__(mrkey_t* ths, const char* self_addr, mrsqlite3_t* sql)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || sql==NULL ) {
		return 0;
	}

	mrkey_empty(ths);
	stmt = mrsqlite3_predefine__(sql, SELECT_private_key_FROM_keypairs_WHERE_default,
		"SELECT private_key FROM keypairs WHERE addr=? AND is_default=1;");
	sqlite3_bind_text (stmt, 1, self_addr, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}
	mrkey_set_from_stmt(ths, stmt, 0, MR_PRIVATE);
	return 1;
}



/*******************************************************************************
 * Render keys
 ******************************************************************************/


char* mrkey_render_base64(const mrkey_t* ths, int break_every, const char* break_chars)
{
	char* ret = NULL;
	char* temp = NULL;

	if( (ret = encode_base64((const char*)ths->m_binary, ths->m_bytes))==NULL ) {
		goto cleanup;
	}

	if( break_every>0 ) {
		temp = ret;
		if( (ret=mr_insert_breaks(temp, break_every, break_chars)) == NULL ) {
			goto cleanup;
		}
	}

cleanup:
	free(temp);
	return ret;
}

