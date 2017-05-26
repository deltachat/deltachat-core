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
 * File:    mrapeerstate.c
 * Purpose: mrapeerstate_t represents the state of an Autocrypt peer
 *
 *******************************************************************************
 *
 * Delta Chat aims to implement Autocrypt-Level0, see
 * https://autocrypt.readthedocs.io/en/latest/level0.html for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrapeerstate.h"
#include "mraheader.h"


/*******************************************************************************
 * Load/save
 ******************************************************************************/


static void mrapeerstate_empty(mrapeerstate_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	ths->m_changed          = 0;
	ths->m_last_seen        = 0;
	ths->m_prefer_encrypted = 0;
	ths->m_to_save          = 0;

	free(ths->m_addr);
	ths->m_addr = NULL;

	if( ths->m_public_key->m_binary ) {
		mrkey_unref(ths->m_public_key);
		ths->m_public_key = mrkey_new();
	}
}


int mrapeerstate_load_from_db__(mrapeerstate_t* ths, mrsqlite3_t* sql, const char* addr)
{
	int           success = 0;
	sqlite3_stmt* stmt;

	if( ths==NULL || sql == NULL || addr == NULL ) {
		return 0;
	}

	mrapeerstate_empty(ths);

	stmt = mrsqlite3_predefine__(sql, SELECT_aclpp_FROM_apeerstates_WHERE_a,
		"SELECT addr, changed, last_seen, prefer_encrypted, public_key FROM apeerstates WHERE addr=? COLLATE NOCASE;");
	sqlite3_bind_text(stmt, 1, addr, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}
	ths->m_addr             = safe_strdup((char*)sqlite3_column_text  (stmt, 0));
	ths->m_changed          =                    sqlite3_column_int64 (stmt, 1);
	ths->m_last_seen        =                    sqlite3_column_int64 (stmt, 2);
	ths->m_prefer_encrypted =                    sqlite3_column_int   (stmt, 3);
	mrkey_set_from_stmt     (ths->m_public_key,                        stmt, 4, MR_PUBLIC);

	success = 1;

cleanup:
	return success;
}


int mrapeerstate_save_to_db__(const mrapeerstate_t* ths, mrsqlite3_t* sql, int create)
{
	int           success = 0;
	sqlite3_stmt* stmt;

	if( ths==NULL || sql==NULL
	 || ths->m_addr==NULL || ths->m_public_key->m_binary==NULL || ths->m_public_key->m_bytes<=0 ) {
		return 0;
	}

	if( create ) {
		stmt = mrsqlite3_predefine__(sql, INSERT_INTO_apeerstates_a, "INSERT INTO apeerstates (addr) VALUES(?);");
		sqlite3_bind_text(stmt, 1, ths->m_addr, -1, SQLITE_STATIC);
		sqlite3_step(stmt);
	}

	if( (ths->m_to_save&MRA_SAVE_ALL) || create )
	{
		stmt = mrsqlite3_predefine__(sql, UPDATE_apeerstates_SET_lcpp_WHERE_a,
			"UPDATE apeerstates SET last_seen=?, changed=?, prefer_encrypted=?, public_key=? WHERE addr=?;");
		sqlite3_bind_int64(stmt, 1, ths->m_last_seen);
		sqlite3_bind_int64(stmt, 2, ths->m_changed);
		sqlite3_bind_int64(stmt, 3, ths->m_prefer_encrypted);
		sqlite3_bind_blob (stmt, 4, ths->m_public_key->m_binary, ths->m_public_key->m_bytes, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 5, ths->m_addr, -1, SQLITE_STATIC);
		if( sqlite3_step(stmt) != SQLITE_DONE ) {
			goto cleanup;
		}
	}
	else if( ths->m_to_save&MRA_SAVE_LAST_SEEN )
	{
		stmt = mrsqlite3_predefine__(sql, UPDATE_apeerstates_SET_l_WHERE_a,
			"UPDATE apeerstates SET last_seen=? WHERE addr=?;");
		sqlite3_bind_int64(stmt, 1, ths->m_last_seen);
		sqlite3_bind_text (stmt, 2, ths->m_addr, -1, SQLITE_STATIC);
		if( sqlite3_step(stmt) != SQLITE_DONE ) {
			goto cleanup;
		}
	}

	success = 1;

cleanup:
	return success;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrapeerstate_t* mrapeerstate_new()
{
	mrapeerstate_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrapeerstate_t)))==NULL ) {
		exit(43); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_public_key = mrkey_new();

	return ths;
}


void mrapeerstate_unref(mrapeerstate_t* ths)
{
	if( ths==NULL ) {
		return;
	}

	free(ths->m_addr);
	mrkey_unref(ths->m_public_key);
	free(ths);
}


/*******************************************************************************
 * Change state
 ******************************************************************************/


int mrapeerstate_init_from_header(mrapeerstate_t* ths, const mraheader_t* header, time_t message_time)
{
	if( ths == NULL || header == NULL ) {
		return 0;
	}

	mrapeerstate_empty(ths);
	ths->m_addr             = safe_strdup(header->m_to);
	ths->m_changed          = message_time;
	ths->m_last_seen        = message_time;
	ths->m_to_save          = MRA_SAVE_ALL;
	ths->m_prefer_encrypted = header->m_prefer_encrypted;
	mrkey_set_from_key(ths->m_public_key, header->m_public_key);
	return 1;
}


int mrapeerstate_degrade_encryption(mrapeerstate_t* ths, time_t message_time)
{
	if( ths==NULL ) {
		return 0;
	}

	ths->m_prefer_encrypted = MRA_PE_NO;
	ths->m_changed = message_time; /*last_seen is not updated as there was not Autocrypt:-header seen*/
	ths->m_to_save = MRA_SAVE_ALL;
	return 1;
}


int mrapeerstate_apply_header(mrapeerstate_t* ths, const mraheader_t* header, time_t message_time)
{
	if( ths==NULL || header==NULL
	 || ths->m_addr==NULL
	 || header->m_to==NULL || header->m_public_key->m_binary==NULL
	 || strcasecmp(ths->m_addr, header->m_to)!=0 ) {
		return 0;
	}

	if( message_time > ths->m_last_seen )
	{
		ths->m_last_seen = message_time;
		ths->m_to_save |= MRA_SAVE_LAST_SEEN;

		if( (header->m_prefer_encrypted==MRA_PE_NO || header->m_prefer_encrypted==MRA_PE_YES || header->m_prefer_encrypted==MRA_PE_NOPREFERENCE)
		 &&  header->m_prefer_encrypted != ths->m_prefer_encrypted )
		{
			ths->m_changed = message_time;
			ths->m_prefer_encrypted = header->m_prefer_encrypted;
			ths->m_to_save |= MRA_SAVE_ALL;
		}

		if( !mrkey_equals(ths->m_public_key, header->m_public_key) )
		{
			ths->m_changed = message_time;
			mrkey_set_from_key(ths->m_public_key, header->m_public_key);
			ths->m_to_save |= MRA_SAVE_ALL;
		}
	}

	return ths->m_to_save? 1 : 0;
}

