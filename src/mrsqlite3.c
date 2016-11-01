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
#include "mrlog.h"
#include "mrtools.h"
#include "mrchat.h"
#include "mrcontact.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


void mrsqlite3_log_error(mrsqlite3_t* ths, const char* msg_format, ...)
{
	char*       msg;
	const char* notSetUp = "SQLite object not set up.";
	va_list     va;

	va_start(va, msg_format);
		msg = sqlite3_vmprintf(msg_format, va); if( msg == NULL ) { mrlog_error("Bad log format string \"%s\".", msg_format); }
			mrlog_error("%s SQLite says: %s", msg, ths->m_cobj? sqlite3_errmsg(ths->m_cobj) : notSetUp);
		sqlite3_free(msg);
	va_end(va);
}


sqlite3_stmt* mrsqlite3_prepare_v2_(mrsqlite3_t* ths, const char* querystr)
{
	sqlite3_stmt* retStmt = NULL;

	if( ths == NULL || querystr == NULL ) {
		mrlog_error("mrsqlite3_prepare_v2_(): Bad argument.");
		return NULL; /* error */
	}

	if( ths->m_cobj == NULL )
	{
		mrlog_error("Database not ready for query: %s", querystr);
		return NULL; /* error */
	}

	if( sqlite3_prepare_v2(ths->m_cobj,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		mrsqlite3_log_error(ths, "Query failed: %s", querystr);
		return NULL; /* error */
	}

	/* success - the result mus be freed using sqlite3_finalize() */
	return retStmt;
}


int mrsqlite3_execute(mrsqlite3_t* ths, const char* querystr)
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
		mrsqlite3_log_error(ths, "mrsqlite3_execute_(): sqlite3_step() failed.");
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


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrsqlite3_t* mrsqlite3_new(mrmailbox_t* mailbox)
{
	mrsqlite3_t* ths = NULL;
	int          i;

	if( (ths=calloc(1, sizeof(mrsqlite3_t)))==NULL ) {
		exit(24); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_mailbox          = mailbox;

	for( i = 0; i < PREDEFINED_CNT; i++ ) {
		ths->m_pd[i] = NULL;
	}

	pthread_mutex_init(&ths->m_critical_, NULL);

	return ths;
}


void mrsqlite3_unref(mrsqlite3_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_cobj ) {
		mrsqlite3_close_(ths);
	}

	pthread_mutex_destroy(&ths->m_critical_);
	free(ths);
}


int mrsqlite3_open_(mrsqlite3_t* ths, const char* dbfile)
{
	if( ths == NULL || dbfile == NULL ) {
		mrlog_error("Cannot open, bad parameters.");
		goto Open_Error;
	}

	if( ths->m_cobj ) {
		mrlog_error("Cannot open, database \"%s\" already opend.", dbfile);
		goto Open_Error;
	}

	if( sqlite3_open(dbfile, &ths->m_cobj) != SQLITE_OK ) {
		mrsqlite3_log_error(ths, "Cannot open database \"%s\".", dbfile); /* ususally, even for errors, the pointer is set up (if not, this is also checked by mrsqlite3_log_error()) */
		goto Open_Error;
	}

	/* `PRAGMA cache_size` and `PRAGMA page_size`: As we save BLOBs in external files, caching is not that important;
	we rely on the system defaults here (normally 2 MB cache, 1 KB page size on sqlite < 3.12.0, 4 KB for newer versions) */

	/* Init the tables, if not yet done.
	NB: We only define default values for columns not present in all INSERT statements.
	NB: We use `sqlite3_last_insert_rowid()` to find out created records - for this purpose, the primary ID has to be marked using
	`INTEGER PRIMARY KEY`, see https://www.sqlite.org/c3ref/last_insert_rowid.html

	Some words to the "param" fields:  These fields contains a string with additonal, named parameters which must
	not be accessed by a search and/or are very seldomly used. Moreover, this allows smart minor database updates. */
	if( !mrsqlite3_table_exists(ths, "contacts") )
	{
		mrlog_info("First time init: creating tables in \"%s\".", dbfile);

		mrsqlite3_execute(ths, "CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		mrsqlite3_execute(ths, "CREATE INDEX config_index1 ON config (keyname);");

		mrsqlite3_execute(ths, "CREATE TABLE contacts (id INTEGER PRIMARY KEY,"
					" name TEXT DEFAULT '',"
					" addr TEXT DEFAULT '' COLLATE NOCASE,"
					" origin INTEGER DEFAULT 0,"
					" blocked INTEGER DEFAULT 0,"
					" last_seen INTEGER DEFAULT 0,"   /* last_seen is for future use */
					" param TEXT DEFAULT '');");      /* param is for future use, eg. for the status */
		mrsqlite3_execute(ths, "CREATE INDEX contacts_index1 ON contacts (addr COLLATE NOCASE);");
		mrsqlite3_execute(ths, "INSERT INTO contacts (id,name,origin) VALUES (1,'self',262144), (2,'system',262144), (3,'rsvd',262144), (4,'rsvd',262144), (5,'rsvd',262144), (6,'rsvd',262144), (7,'rsvd',262144), (8,'rsvd',262144), (9,'rsvd',262144);");
		#if !defined(MR_ORIGIN_INTERNAL) || MR_ORIGIN_INTERNAL!=262144
			#error
		#endif

		mrsqlite3_execute(ths, "CREATE TABLE chats (id INTEGER PRIMARY KEY, "
					" type INTEGER,"
					" name TEXT,"
					" draft_timestamp INTEGER DEFAULT 0,"
					" draft_txt TEXT DEFAULT '',"
					" param TEXT DEFAULT '');");      /* param is for future use */
		mrsqlite3_execute(ths, "CREATE TABLE chats_contacts (chat_id INTEGER, contact_id);");
		mrsqlite3_execute(ths, "CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);");
		mrsqlite3_execute(ths, "INSERT INTO chats (id,type,name) VALUES (1,120,'strangers'), (2,120,'trash'), (3,120,'blocked_users'), (4,120,'msgs_in_creation'), (5,120,'rsvd'), (6,120,'rsvd'), (7,100,'rsvd'), (8,100,'rsvd'), (9,100,'rsvd');");
		#if !defined(MR_CHAT_NORMAL) || MR_CHAT_NORMAL!=100 || MR_CHAT_GROUP!=120 || MR_CHAT_ID_STRANGERS!=1 || MR_CHAT_ID_TRASH!=2 || MR_CHAT_ID_BLOCKED_USERS!=3 || MR_CHAT_ID_MSGS_IN_CREATION!=4
			#error
		#endif

		mrsqlite3_execute(ths, "CREATE TABLE msgs (id INTEGER PRIMARY KEY,"
					" rfc724_mid TEXT DEFAULT '',"
					" chat_id INTEGER,"
					" from_id INTEGER,"
					" to_id INTEGER DEFAULT 0," /* to_id is needed to allow moving messages eg. from "strangers" to a normal chat, may be unset */
					" timestamp INTEGER,"
					" type INTEGER, state INTEGER,"
					" bytes INTEGER DEFAULT 0,"
					" txt TEXT," /* as this is also used for (fulltext) searching, nothing but normal, plain text should go here */
					" param TEXT DEFAULT '');");
		mrsqlite3_execute(ths, "CREATE INDEX msgs_index1 ON msgs (rfc724_mid);");     /* in our database, one E-Mail may be split up to several messages (eg. one per image), so the E-Mail-Message-ID may be used for several records; id is always unique */
		mrsqlite3_execute(ths, "CREATE INDEX msgs_index2 ON msgs (chat_id);");
		mrsqlite3_execute(ths, "CREATE INDEX msgs_index3 ON msgs (timestamp);");      /* for sorting */
		mrsqlite3_execute(ths, "CREATE INDEX msgs_index4 ON msgs (state);");          /* for selecting the count of unread messages (as there are normally only few unread messages, an index over the chat_id is not required for _this_ purpose */

		mrsqlite3_execute(ths, "CREATE TABLE jobs (id INTEGER PRIMARY KEY,"
					" added_timestamp INTEGER,"
					" desired_timestamp INTEGER DEFAULT 0,"
					" action INTEGER,"
					" foreign_id INTEGER,"
					" param TEXT DEFAULT '');");
		mrsqlite3_execute(ths, "CREATE INDEX jobs_index1 ON jobs (action);");

		if( !mrsqlite3_table_exists(ths, "config") || !mrsqlite3_table_exists(ths, "contacts")
		 || !mrsqlite3_table_exists(ths, "chats") || !mrsqlite3_table_exists(ths, "chats_contacts")
		 || !mrsqlite3_table_exists(ths, "msgs") || !mrsqlite3_table_exists(ths, "jobs") )
		{
			mrsqlite3_log_error(ths, "Cannot create tables in new database \"%s\".", dbfile);
			goto Open_Error; /* cannot create the tables - maybe we cannot write? */
		}
	}

	/* prepare statements that are used at different source code positions and/or are always needed.
	other statements are prepared just-in-time as needed.
	(we do it when the tables really exists, however, I do not know if sqlite relies on this) */
	if( !mrsqlite3_predefine(ths, SELECT_v_FROM_config_k, "SELECT value FROM config WHERE keyname=?;") )
	{
		mrsqlite3_log_error(ths, "Cannot open, cannot prepare SQL statements for database \"%s\".", dbfile);
		goto Open_Error;
	}

	/* success */
	mrlog_info("Opened \"%s\" successfully.", dbfile);
	return 1;

	/* error */
Open_Error:
	mrsqlite3_close_(ths);
	return 0;
}


void mrsqlite3_close_(mrsqlite3_t* ths)
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

	mrlog_info("Database closed."); /* We log the information even if not real closing took place; this is to detect logic errors. */
}


int mrsqlite3_is_open(const mrsqlite3_t* ths)
{
	if( ths == NULL || ths->m_cobj == NULL ) {
		return 0;
	}
	return 1;
}


sqlite3_stmt* mrsqlite3_predefine(mrsqlite3_t* ths, size_t idx, const char* querystr)
{
	/* predefines a statement or resets and reuses a statment.
	Subsequent call may ommit the querystring.
	CAVE: you must not call this function with different strings for the same index! */

	if( ths == NULL || ths->m_cobj == NULL || idx >= PREDEFINED_CNT ) {
		mrlog_error("mrsqlite3_predefine_stmt(): Bad argument.");
		return NULL; /* error*/
	}

	if( ths->m_pd[idx] ) {
		sqlite3_reset(ths->m_pd[idx]);
		return ths->m_pd[idx]; /* fine, already prepared before */
	}

	/*prepare for the first time - this requires the querystring*/
	if( querystr == NULL ) {
		mrlog_error("mrsqlite3_predefine_stmt(): query not given.");
		return NULL; /* error */
	}

	if( sqlite3_prepare_v2(ths->m_cobj,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &ths->m_pd[idx],
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		mrsqlite3_log_error(ths, "mrsqlite3_predefine_stmt(): sqlite3_prepare_v2() failed.");
		return NULL; /* error */
	}

	return ths->m_pd[idx];
}


int mrsqlite3_table_exists(mrsqlite3_t* ths, const char* name)
{
	int           ret = 0;
	char*         querystr = NULL;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	if( (querystr=sqlite3_mprintf("PRAGMA table_info(%s)", name)) == NULL ) { /* this statement cannot be used with binded variables */
		mrlog_error("mrsqlite3_table_exists_(): Out of memory.");
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


int mrsqlite3_set_config_(mrsqlite3_t* ths, const char* key, const char* value)
{
	int           state;
	sqlite3_stmt* stmt;

	if( key == NULL ) {
		mrlog_error("mrsqlite3_set_config(): Bad parameter.");
		return 0;
	}

	if( !mrsqlite3_is_open(ths) ) {
		mrlog_error("mrsqlite3_set_config(): Database not ready.");
		return 0;
	}

	if( value )
	{
		/* insert/update key=value */
		stmt = mrsqlite3_predefine(ths, SELECT_v_FROM_config_k, NULL /*predefined on construction*/);
		sqlite3_bind_text (stmt, 1, key, -1, SQLITE_STATIC);
		state=sqlite3_step(stmt);
		if( state == SQLITE_DONE ) {
			stmt = mrsqlite3_predefine(ths, INSERT_INTO_config_kv, "INSERT INTO config (keyname, value) VALUES (?, ?);");
			sqlite3_bind_text (stmt, 1, key,   -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt, 2, value, -1, SQLITE_STATIC);
			state=sqlite3_step(stmt);

		}
		else if( state == SQLITE_ROW ) {
			stmt = mrsqlite3_predefine(ths, UPDATE_config_vk, "UPDATE config SET value=? WHERE keyname=?;");
			sqlite3_bind_text (stmt, 1, value, -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt, 2, key,   -1, SQLITE_STATIC);
			state=sqlite3_step(stmt);
		}
		else {
			mrlog_error("mrsqlite3_set_config(): Cannot read value.");
			return 0;
		}
	}
	else
	{
		/* delete key */
		stmt = mrsqlite3_predefine(ths, DELETE_FROM_config_k, "DELETE FROM config WHERE keyname=?;");
		sqlite3_bind_text (stmt, 1, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(stmt);
	}

	if( state != SQLITE_DONE )  {
		mrlog_error("mrsqlite3_set_config(): Cannot change value.");
		return 0; /* error */
	}

	return 1;
}


char* mrsqlite3_get_config_(mrsqlite3_t* ths, const char* key, const char* def) /* the returned string must be free()'d */
{
	sqlite3_stmt* stmt;

	if( !mrsqlite3_is_open(ths) || key == NULL ) {
		return safe_strdup(def);
	}

	stmt = mrsqlite3_predefine(ths, SELECT_v_FROM_config_k, NULL /*predefined on construction*/);
	sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(stmt, 0); /* Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free(). */
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


int32_t mrsqlite3_get_config_int_(mrsqlite3_t* ths, const char* key, int32_t def)
{
    char* str = mrsqlite3_get_config_(ths, key, NULL);
    if( str == NULL ) {
		return def;
    }
    int32_t ret = atol(str);
    free(str);
    return ret;
}


int mrsqlite3_set_config_int_(mrsqlite3_t* ths, const char* key, int32_t value)
{
    char* value_str = sqlite3_mprintf("%i", (int)value);
    if( value_str == NULL ) {
		return 0;
    }
    int ret = mrsqlite3_set_config_(ths, key, value_str);
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
	sqlite3_stmt* stmt;

	ths->m_transactionCount++; /* this is safe, as the database should be locked when using a transaction */

	if( ths->m_transactionCount == 1 )
	{
		stmt = mrsqlite3_predefine(ths, BEGIN_transaction, "BEGIN;");
		if( sqlite3_step(stmt) != SQLITE_DONE ) {
			mrsqlite3_log_error(ths, "Cannot begin transaction.");
		}
	}
}


void mrsqlite3_rollback(mrsqlite3_t* ths)
{
	sqlite3_stmt* stmt;

	if( ths->m_transactionCount >= 1 )
	{
		if( ths->m_transactionCount == 1 )
		{
			stmt = mrsqlite3_predefine(ths, ROLLBACK_transaction, "ROLLBACK;");
			if( sqlite3_step(stmt) != SQLITE_DONE ) {
				mrsqlite3_log_error(ths, "Cannot rollback transaction.");
			}
		}

		ths->m_transactionCount--;
	}
}


void mrsqlite3_commit(mrsqlite3_t* ths)
{
	sqlite3_stmt* stmt;

	if( ths->m_transactionCount >= 1 )
	{
		if( ths->m_transactionCount == 1 )
		{
			stmt = mrsqlite3_predefine(ths, COMMIT_transaction, "COMMIT;");
			if( sqlite3_step(stmt) != SQLITE_DONE ) {
				mrsqlite3_log_error(ths, "Cannot commit transaction.");
			}
		}

		ths->m_transactionCount--;
	}
}
