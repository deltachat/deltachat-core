/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
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
 * File:    mrsqlite3.c
 * Authors: Björn Petersen
 * Purpose: MrSqlite3 wraps around SQLite
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrsqlite3.h"
#include "mrerror.h"
#include "mrtools.h"
#include "mrcontact.h"


mrsqlite3_t* mrsqlite3_new(mrmailbox_t* mailbox)
{
	mrsqlite3_t* ths = NULL;
	int          i;

	if( (ths=malloc(sizeof(mrsqlite3_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_cobj             = NULL;
	ths->m_dbfile           = NULL;
	ths->m_mailbox          = mailbox;
	ths->m_transactionCount = 0;

	for( i = 0; i < PREDEFINED_CNT; i++ ) {
		ths->m_pd[i] = NULL;
	}

	pthread_mutex_init(&ths->m_critical_, NULL);

	return ths;
}


void mrsqlite3_delete(mrsqlite3_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	mrsqlite3_close(ths);
	pthread_mutex_destroy(&ths->m_critical_);
	free(ths);
}


int mrsqlite3_open(mrsqlite3_t* ths, const char* dbfile)
{
	int i;

	if( ths == NULL || dbfile == NULL ) {
		MrLogError("MrSqlite3::Open(): No database file given.");
		goto Open_Error;
	}

	if( ths->m_dbfile ) {
		MrLogError("MrSqlite3::Open(): Database already opend.");
		goto Open_Error;
	}

	ths->m_dbfile = safe_strdup(dbfile);
	if( ths->m_dbfile == NULL ) {
		MrLogError("MrSqlite3::Open(): Out of memory.");
		goto Open_Error;
	}

	if( sqlite3_open(dbfile, &ths->m_cobj) != SQLITE_OK ) {
		MrLogSqliteError(ths->m_cobj); /* ususally, even for errors, the pointer is set up (if not, this is also checked by MrLogSqliteError()) */
		MrLogError("MrSqlite3::Open(): sqlite3_open() failed.");
		goto Open_Error;
	}

	/* Init the tables, if not yet done
	NB: we use `sqlite3_last_insert_rowid()` to find out created records - for this purpose, the primary ID has to be marked using
	`INTEGER PRIMARY KEY`, see https://www.sqlite.org/c3ref/last_insert_rowid.html */
	if( !mrsqlite3_table_exists_(ths, "contacts") )
	{
		mrsqlite3_execute_(ths, "CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		mrsqlite3_execute_(ths, "CREATE INDEX config_index1 ON config (keyname);");

		mrsqlite3_execute_(ths, "CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, email TEXT);");
		mrsqlite3_execute_(ths, "CREATE INDEX contacts_index1 ON contacts (email);");

		mrsqlite3_execute_(ths, "CREATE TABLE chats (id INTEGER PRIMARY KEY, type INTEGER, name TEXT);");
		mrsqlite3_execute_(ths, "CREATE TABLE chats_contacts (chat_id INTEGER, contact_id);");
		mrsqlite3_execute_(ths, "CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);");

		mrsqlite3_execute_(ths, "CREATE TABLE msg (id INTEGER PRIMARY KEY, rfc724_mid TEXT, chat_id INTEGER, from_id INTEGER, timestamp INTEGER, type INTEGER, state INTEGER, msg TEXT, msg_raw TEXT);"); /* msg_raw is mainly for debugging purposes */
		mrsqlite3_execute_(ths, "CREATE INDEX msg_index1 ON msg (rfc724_mid);"); /* in our database, one E-Mail may be split up to several messages (eg. one per image), so the E-Mail-Message-ID may be used for several records; id is always unique */
		mrsqlite3_execute_(ths, "CREATE INDEX msg_index2 ON msg (timestamp);");
		mrsqlite3_execute_(ths, "CREATE TABLE msg_to (msg_id INTEGER, contact_id INTEGER);");
		mrsqlite3_execute_(ths, "CREATE INDEX msg_to_index1 ON msg_to (msg_id);");
		mrsqlite3_execute_(ths, "CREATE TABLE msg_blob (msg_id INTEGER PRIMARY KEY, blobdata BLOB);");

		if( !mrsqlite3_table_exists_(ths, "config") || !mrsqlite3_table_exists_(ths, "contacts")
		 || !mrsqlite3_table_exists_(ths, "chats") || !mrsqlite3_table_exists_(ths, "chats_contacts")
		 || !mrsqlite3_table_exists_(ths, "msg") )
		{
			MrLogSqliteError(ths->m_cobj);
			MrLogError("mrsqlite3_open(): Cannot create tables.");
			goto Open_Error; /* cannot create the tables - maybe we cannot write? */
		}
	}

	/* prepare statements (we do it when the tables really exists, however, I do not know if sqlite relies on this) */
	ths->m_pd[BEGIN_transaction]          = mrsqlite3_prepare_v2_(ths, "BEGIN;");
	ths->m_pd[ROLLBACK_transaction]       = mrsqlite3_prepare_v2_(ths, "ROLLBACK;");
	ths->m_pd[COMMIT_transaction]         = mrsqlite3_prepare_v2_(ths, "COMMIT;");

	ths->m_pd[SELECT_value_FROM_config_k] = mrsqlite3_prepare_v2_(ths, "SELECT value FROM config WHERE keyname=?;");
	ths->m_pd[INSERT_INTO_config_kv]      = mrsqlite3_prepare_v2_(ths, "INSERT INTO config (keyname, value) VALUES (?, ?);");
	ths->m_pd[UPDATE_config_vk]           = mrsqlite3_prepare_v2_(ths, "UPDATE config SET value=? WHERE keyname=?;");
	ths->m_pd[DELETE_FROM_config_k]       = mrsqlite3_prepare_v2_(ths, "DELETE FROM config WHERE keyname=?;");

	ths->m_pd[SELECT_COUNT_FROM_contacts] = mrsqlite3_prepare_v2_(ths, "SELECT COUNT(*) FROM contacts;");
	ths->m_pd[SELECT_FROM_contacts_e]     = mrsqlite3_prepare_v2_(ths, "SELECT id, name FROM contacts WHERE email=?;");
	ths->m_pd[INSERT_INTO_contacts_ne]    = mrsqlite3_prepare_v2_(ths, "INSERT INTO contacts (name, email) VALUES(?, ?);");
	ths->m_pd[UPDATE_contacts_ni]         = mrsqlite3_prepare_v2_(ths, "UPDATE contacts SET name=? WHERE id=?;");

	ths->m_pd[SELECT_COUNT_FROM_chats]    = mrsqlite3_prepare_v2_(ths, "SELECT COUNT(*) FROM chats;");

	ths->m_pd[SELECT_COUNT_FROM_msg]      = mrsqlite3_prepare_v2_(ths, "SELECT COUNT(*) FROM msg;");
	ths->m_pd[SELECT_id_FROM_msg_m]       = mrsqlite3_prepare_v2_(ths, "SELECT id FROM msg WHERE rfc724_mid=?;");
	ths->m_pd[INSERT_INTO_msg_mcfttsmm]   = mrsqlite3_prepare_v2_(ths, "INSERT INTO msg (rfc724_mid,chat_id,from_id, timestamp,type,state, msg,msg_raw) VALUES (?,?,?, ?,?,?, ?,?);");
	ths->m_pd[INSERT_INTO_msg_to_mc]      = mrsqlite3_prepare_v2_(ths, "INSERT INTO msg_to (msg_id, contact_id) VALUES (?,?);");

	for( i = 0; i < PREDEFINED_CNT; i++ ) {
		if( ths->m_pd[i] == NULL ) {
			MrLogSqliteError(ths->m_cobj);
			MrLogError("MrSqlite3::Open(): Cannot prepare SQL statements.");
			goto Open_Error;
		}
	}

	/* success */
	return 1;

	/* error */
Open_Error:
	mrsqlite3_close(ths);
	return 0;
}


void mrsqlite3_close(mrsqlite3_t* ths)
{
	int i;

	if( ths == NULL ) {
		return;
	}

	if( ths->m_cobj )
	{
		for( i = 0; i < PREDEFINED_CNT; i++ ) {
			if( ths->m_pd[i] ) {
				sqlite3_finalize(ths->m_pd[i]);
				ths->m_pd[i] = NULL;
			}
		}

		sqlite3_close(ths->m_cobj);
		ths->m_cobj = NULL;
	}

	if( ths->m_dbfile )
	{
		free(ths->m_dbfile);
		ths->m_dbfile = NULL;
	}
}


int mrsqlite3_ok(mrsqlite3_t* ths)
{
	if( ths == NULL || ths->m_cobj == NULL ) {
		return 0;
	}
	return 1;
}


sqlite3_stmt* mrsqlite3_prepare_v2_(mrsqlite3_t* ths, const char* querystr)
{
	sqlite3_stmt* retStmt = NULL;

	if( ths == NULL || querystr == NULL ) {
		MrLogError("MrSqlite3::sqlite3_prepare_v2_(): Bad argument.");
		return NULL; /* error */
	}

	if( ths->m_cobj == NULL )
	{
		MrLogError("MrSqlite3::sqlite3_prepare_v2_(): Database not ready.");
		return NULL; /* error */
	}

	if( sqlite3_prepare_v2(ths->m_cobj,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		MrLogSqliteError(ths->m_cobj);
		MrLogError("MrSqlite3::sqlite3_prepare_v2_(): sqlite3_prepare_v2() failed.");
		return NULL; /* error */
	}

	/* success - the result mus be freed using sqlite3_finalize() */
	return retStmt;
}


int mrsqlite3_execute_(mrsqlite3_t* ths, const char* querystr)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	stmt = mrsqlite3_prepare_v2_(ths, querystr);
	if( stmt == NULL ) {
		goto sqlite3_execute_Error; /* error already logged */
	}

	sqlState = sqlite3_step(stmt);
	if( sqlState != SQLITE_DONE && sqlState != SQLITE_ROW )  {
		MrLogSqliteError(ths->m_cobj);
		MrLogError("MrSqlite3::sqlite3_execute_(): sqlite3_step() failed.");
		goto sqlite3_execute_Error;
	}

	/* success - fall through to free objects */
	ret = 1;

	/* error */
sqlite3_execute_Error:
	if( stmt ) {
		sqlite3_finalize(stmt);
	}
	return ret;
}


int mrsqlite3_table_exists_(mrsqlite3_t* ths, const char* name)
{
	int           ret = 0;
	char*         querystr = NULL;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	if( (querystr=sqlite3_mprintf("PRAGMA table_info(%s)", name)) == NULL ) { /* this statement cannot be used with binded variables */
		MrLogError("MrSqlite3::sqlite3_table_exists_(): Out of memory.");
		goto table_exists_Error;
	}

	if( (stmt=mrsqlite3_prepare_v2_(ths, querystr)) == NULL ) {
		goto table_exists_Error; /* error already logged */
	}

	sqlState = sqlite3_step(stmt);
	if( sqlState == SQLITE_ROW ) {
		ret = 1; /* the table exists. Other states are SQLITE_DONE or SQLITE_ERROR in both cases we return 0. */
	}

	/* success - fall through to free allocated objects */
	;

	/* error/cleanup */
table_exists_Error:
	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	if( querystr ) {
		sqlite3_free(querystr);
	}

	return ret;
}


/*******************************************************************************
 * Handle configuration
 ******************************************************************************/


int mrsqlite3_set_config(mrsqlite3_t* ths, const char* key, const char* value)
{
	int state;

	if( key == NULL ) {
		MrLogError("MrSqlite3::SetConfig(): Bad parameter.");
		return 0;
	}

	if( !mrsqlite3_ok(ths) ) {
		MrLogError("MrSqlite3::SetConfig(): Database not ready.");
		return 0;
	}

	if( value )
	{
		/* insert/update key=value */
		sqlite3_reset     (ths->m_pd[SELECT_value_FROM_config_k]);
		sqlite3_bind_text (ths->m_pd[SELECT_value_FROM_config_k], 1, key, -1, SQLITE_STATIC);
		state=sqlite3_step(ths->m_pd[SELECT_value_FROM_config_k]);
		if( state == SQLITE_DONE ) {
			sqlite3_reset     (ths->m_pd[INSERT_INTO_config_kv]);
			sqlite3_bind_text (ths->m_pd[INSERT_INTO_config_kv], 1, key,   -1, SQLITE_STATIC);
			sqlite3_bind_text (ths->m_pd[INSERT_INTO_config_kv], 2, value, -1, SQLITE_STATIC);
			state=sqlite3_step(ths->m_pd[INSERT_INTO_config_kv]);

		}
		else if( state == SQLITE_ROW ) {
			sqlite3_reset     (ths->m_pd[UPDATE_config_vk]);
			sqlite3_bind_text (ths->m_pd[UPDATE_config_vk], 1, value, -1, SQLITE_STATIC);
			sqlite3_bind_text (ths->m_pd[UPDATE_config_vk], 2, key,   -1, SQLITE_STATIC);
			state=sqlite3_step(ths->m_pd[UPDATE_config_vk]);
		}
		else {
			MrLogError("MrSqlite3::SetConfig(): Cannot read value.");
			return 0;
		}
	}
	else
	{
		/* delete key */
		sqlite3_reset     (ths->m_pd[DELETE_FROM_config_k]);
		sqlite3_bind_text (ths->m_pd[DELETE_FROM_config_k], 1, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(ths->m_pd[DELETE_FROM_config_k]);
	}

	if( state != SQLITE_DONE )  {
		MrLogError("MrSqlite3::SetConfig(): Cannot change value.");
		return 0; /* error */
	}

	return 1;
}


char* mrsqlite3_get_config(mrsqlite3_t* ths, const char* key, const char* def) /* the returned string must be free()'d */
{
	if( !mrsqlite3_ok(ths) || key == NULL ) {
		return NULL;
	}

	sqlite3_reset    (ths->m_pd[SELECT_value_FROM_config_k]);
	sqlite3_bind_text(ths->m_pd[SELECT_value_FROM_config_k], 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(ths->m_pd[SELECT_value_FROM_config_k]) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(ths->m_pd[SELECT_value_FROM_config_k], 0); /* Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free(). */
		if( ptr )
		{
			/* success, fall through below to free objects */
			return safe_strdup((const char*)ptr);
		}
	}

	/* return the default value */
	if( def ) {
		return safe_strdup(def);
	}
	return NULL;
}


int32_t mrsqlite3_get_config_int(mrsqlite3_t* ths, const char* key, int32_t def)
{
    char* str = mrsqlite3_get_config(ths, key, NULL);
    if( str == NULL ) {
		return def;
    }
    return atol(str);
}


int mrsqlite3_set_config_int(mrsqlite3_t* ths, const char* key, int32_t value)
{
    char* value_str = sqlite3_mprintf("%i", (int)value);
    if( value_str == NULL ) {
		return 0;
    }
    int ret = mrsqlite3_set_config(ths, key, value_str);
    sqlite3_free(value_str);
    return ret;
}


/*******************************************************************************
 * Locking
 ******************************************************************************/


void mrsqlite3_lock(mrsqlite3_t* ths) /* wait and lock */
{
	pthread_mutex_lock(&ths->m_critical_);
}


void mrsqlite3_unlock(mrsqlite3_t* ths)
{
	pthread_mutex_unlock(&ths->m_critical_);
}


/*******************************************************************************
 * Transactions
 ******************************************************************************/


void mrsqlite3_begin_transaction(mrsqlite3_t* ths)
{
	ths->m_transactionCount++; /* this is safe, as the database should be locked when using a transaction */

	if( ths->m_transactionCount == 1 )
	{
		sqlite3_reset(ths->m_pd[BEGIN_transaction]);
		if( sqlite3_step(ths->m_pd[BEGIN_transaction]) != SQLITE_DONE ) {
			MrLogSqliteError(ths->m_cobj);
		}
	}
}


void mrsqlite3_rollback(mrsqlite3_t* ths)
{
	if( ths->m_transactionCount >= 1 )
	{
		if( ths->m_transactionCount == 1 )
		{
			sqlite3_reset(ths->m_pd[ROLLBACK_transaction]);
			if( sqlite3_step(ths->m_pd[ROLLBACK_transaction]) != SQLITE_DONE ) {
				MrLogSqliteError(ths->m_cobj);
			}
		}

		ths->m_transactionCount--;
	}
}


void mrsqlite3_commit(mrsqlite3_t* ths)
{
	if( ths->m_transactionCount >= 1 )
	{
		if( ths->m_transactionCount == 1 )
		{
			sqlite3_reset(ths->m_pd[COMMIT_transaction]);
			if( sqlite3_step(ths->m_pd[COMMIT_transaction]) != SQLITE_DONE ) {
				MrLogSqliteError(ths->m_cobj);
			}
		}

		ths->m_transactionCount--;
	}
}
