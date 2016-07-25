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
 * File:    mrsqlite3.cpp
 * Authors: Björn Petersen
 * Purpose: MrSqlite3 wraps around SQLite
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrsqlite3.h"
#include "mrerror.h"


MrSqlite3::MrSqlite3()
{
	m_cobj                       = NULL;
	m_dbfile                     = NULL;

	for( int i = 0; i < PREDEFINED_CNT; i++ ) {
		m_pd[i] = NULL;
	}

	pthread_mutex_init(&m_critical, NULL);
}


MrSqlite3::~MrSqlite3()
{
	Close();

	pthread_mutex_destroy(&m_critical);
}


bool MrSqlite3::Open(const char* dbfile)
{
	if( dbfile == NULL ) {
		MrLogError("MrSqlite3::Open(): No database file given.");
		goto Open_Error;
	}

	if( m_dbfile ) {
		MrLogError("MrSqlite3::Open(): Database already opend.");
		goto Open_Error;
	}

	m_dbfile = strdup(dbfile);
	if( m_dbfile == NULL ) {
		MrLogError("MrSqlite3::Open(): Out of memory.");
		goto Open_Error;
	}

	if( sqlite3_open(dbfile, &m_cobj) != SQLITE_OK ) {
		MrLogSqliteError(m_cobj); // ususally, even for errors, the pointer is set up (if not, this is also checked by MrLogSqliteError())
		MrLogError("MrSqlite3::Open(): sqlite3_open() failed.", dbfile);
		goto Open_Error;
	}

	// Init the tables, if not yet done
	// NB: we use `sqlite3_last_insert_rowid()` to find out created records - for this purpose, the primary ID has to be marked using
	// `INTEGER PRIMARY KEY`, see https://www.sqlite.org/c3ref/last_insert_rowid.html
	if( !sqlite3_table_exists_("contacts") )
	{
		sqlite3_execute_("CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		sqlite3_execute_("CREATE INDEX config_index1 ON config (keyname);");

		sqlite3_execute_("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, email TEXT);");
		sqlite3_execute_("CREATE INDEX contacts_index1 ON contacts (email);");

		sqlite3_execute_("CREATE TABLE chats (id INTEGER PRIMARY KEY, type INTEGER, name TEXT);");
		sqlite3_execute_("CREATE TABLE chats_contacts (chat_id INTEGER, contact_id);");
		sqlite3_execute_("CREATE INDEX chats_contacts_index1 ON chats_contacts (chat_id);");

		sqlite3_execute_("CREATE TABLE msg (id INTEGER PRIMARY KEY, message_id TEXT, chat INTEGER, from_contact_id INTEGER, timestamp INTEGER, type INTEGER, msg TEXT);");
		sqlite3_execute_("CREATE INDEX msg_index1 ON msg (message_id);"); // in our database, one E-Mail may be split up to several messages (eg. one per image), so the E-Mail-Message-ID may be used for several records; id is always unique
		sqlite3_execute_("CREATE INDEX msg_index2 ON msg (timestamp);");
		sqlite3_execute_("CREATE TABLE msg_to (msg_id INTEGER, contact_id);");
		sqlite3_execute_("CREATE INDEX msg_to_index1 ON msg_to (msg_id);");

		if( !sqlite3_table_exists_("config") || !sqlite3_table_exists_("contacts")
		 || !sqlite3_table_exists_("chats") || !sqlite3_table_exists_("chats_contacts")
		 || !sqlite3_table_exists_("msg") )
		{
			MrLogSqliteError(m_cobj);
			MrLogError("MrSqlite3::Open(): Cannot create tables.", dbfile);
			goto Open_Error; // cannot create the tables - maybe we cannot write?
		}
	}

	// prepare statements (we do it when the tables really exists, however, I do not know if sqlite relies on this)
	m_pd[SELECT_value_FROM_config_k] = sqlite3_prepare_v2_("SELECT value FROM config WHERE keyname=?;");
	m_pd[INSERT_INTO_config_kv]      = sqlite3_prepare_v2_("INSERT INTO config (keyname, value) VALUES (?, ?);");
	m_pd[UPDATE_config_vk]           = sqlite3_prepare_v2_("UPDATE config SET value=? WHERE keyname=?;");
	m_pd[DELETE_FROM_config_k]       = sqlite3_prepare_v2_("DELETE FROM config WHERE keyname=?;");

	m_pd[SELECT_COUNT_FROM_contacts] = sqlite3_prepare_v2_("SELECT COUNT(*) FROM contacts;");
	m_pd[SELECT_FROM_contacts_e]     = sqlite3_prepare_v2_("SELECT id, name FROM contacts WHERE email=?;");
	m_pd[INSERT_INTO_contacts_ne]    = sqlite3_prepare_v2_("INSERT INTO contacts (name, email) VALUES(?, ?);");
	m_pd[UPDATE_contacts_ni]         = sqlite3_prepare_v2_("UPDATE contacts SET name=? WHERE id=?;");

	m_pd[SELECT_COUNT_FROM_chats]    = sqlite3_prepare_v2_("SELECT COUNT(*) FROM chats;");

	m_pd[SELECT_COUNT_FROM_msg]      = sqlite3_prepare_v2_("SELECT COUNT(*) FROM msg;");
	m_pd[SELECT_id_FROM_msg_m]       = sqlite3_prepare_v2_("SELECT id FROM msg WHERE message_id=?;");
	m_pd[INSERT_INTO_msg_mctm]       = sqlite3_prepare_v2_("INSERT INTO msg (message_id, from_contact_id, timestamp, msg) VALUES (?,?,?,?);");
	m_pd[INSERT_INTO_msg_to_mc]      = sqlite3_prepare_v2_("INSERT INTO msg_to (msg_id, contact_id) VALUES (?,?);");

	for( int i = 0; i < PREDEFINED_CNT; i++ ) {
		if( m_pd[i] == NULL ) {
			MrLogSqliteError(m_cobj);
			MrLogError("MrSqlite3::Open(): Cannot prepare SQL statements.", dbfile);
			goto Open_Error;
		}
	}

	// success
	return true;

	// error
Open_Error:
	Close();
	return false;
}


void MrSqlite3::Close()
{
	#define SQLITE3_FINALIZE_(a) \
	if((a)) { \
		sqlite3_finalize((a)); \
		(a) = NULL; \
	}

	if( m_cobj )
	{
		for( int i = 0; i < PREDEFINED_CNT; i++ ) {
			if( m_pd[i] ) {
				sqlite3_finalize(m_pd[i]);
				m_pd[i] = NULL;
			}
		}

		sqlite3_close(m_cobj);
		m_cobj = NULL;
	}

	if( m_dbfile )
	{
		free(m_dbfile);
		m_dbfile = NULL;
	}
}


sqlite3_stmt* MrSqlite3::sqlite3_prepare_v2_(const char* querystr)
{
	sqlite3_stmt* retStmt = NULL;

	if( m_cobj == NULL )
	{
		MrLogError("MrSqlite3::sqlite3_prepare_v2_(): Database not ready.");
		return NULL; // error
	}

	if( sqlite3_prepare_v2(m_cobj,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		MrLogSqliteError(m_cobj);
		MrLogError("MrSqlite3::sqlite3_prepare_v2_(): sqlite3_prepare_v2() failed.");
		return NULL; // error
	}

	// success - the result mus be freed using sqlite3_finalize()
	return retStmt;
}


bool MrSqlite3::sqlite3_execute_(const char* querystr)
{
	bool          ret = false;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	stmt = sqlite3_prepare_v2_(querystr);
	if( stmt == NULL ) {
		goto sqlite3_execute_Error; // error already logged
	}

	sqlState = sqlite3_step(stmt);
	if( sqlState != SQLITE_DONE && sqlState != SQLITE_ROW )  {
		MrLogSqliteError(m_cobj);
		MrLogError("MrSqlite3::sqlite3_execute_(): sqlite3_step() failed.");
		goto sqlite3_execute_Error;
	}

	// success - fall through to free objects
	ret = true;

	// error
sqlite3_execute_Error:
	if( stmt ) {
		sqlite3_finalize(stmt);
	}
	return ret;
}


bool MrSqlite3::sqlite3_table_exists_(const char* name)
{
	bool          ret = false;
	char*         querystr = NULL;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	if( (querystr=sqlite3_mprintf("PRAGMA table_info(%s)", name)) == NULL ) { // this statement cannot be used with binded variables
		MrLogError("MrSqlite3::sqlite3_table_exists_(): Out of memory.");
		goto table_exists_Error;
	}

	if( (stmt=sqlite3_prepare_v2_(querystr)) == NULL ) {
		goto table_exists_Error; // error already logged
	}

	sqlState = sqlite3_step(stmt);
	if( sqlState == SQLITE_ROW ) {
		ret = true; // the table exists. Other states are SQLITE_DONE or SQLITE_ERROR in both cases we return false.
	}

	// success - fall through to free allocated objects
	;

	// error
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


bool MrSqlite3::SetConfig(const char* key, const char* value)
{
	int state;

	if( key == NULL ) {
		MrLogError("MrSqlite3::SetConfig(): Bad parameter.");
		return false;
	}

	if( !Ok() ) {
		MrLogError("MrSqlite3::SetConfig(): Database not ready.");
		return false;
	}

	if( value )
	{
		// insert/update key=value
		sqlite3_reset     (m_pd[SELECT_value_FROM_config_k]);
		sqlite3_bind_text (m_pd[SELECT_value_FROM_config_k], 1, key, -1, SQLITE_STATIC);
		state=sqlite3_step(m_pd[SELECT_value_FROM_config_k]);
		if( state == SQLITE_DONE ) {
			sqlite3_reset     (m_pd[INSERT_INTO_config_kv]);
			sqlite3_bind_text (m_pd[INSERT_INTO_config_kv], 1, key,   -1, SQLITE_STATIC);
			sqlite3_bind_text (m_pd[INSERT_INTO_config_kv], 2, value, -1, SQLITE_STATIC);
			state=sqlite3_step(m_pd[INSERT_INTO_config_kv]);

		}
		else if( state == SQLITE_ROW ) {
			sqlite3_reset     (m_pd[UPDATE_config_vk]);
			sqlite3_bind_text (m_pd[UPDATE_config_vk], 1, value, -1, SQLITE_STATIC);
			sqlite3_bind_text (m_pd[UPDATE_config_vk], 2, key,   -1, SQLITE_STATIC);
			state=sqlite3_step(m_pd[UPDATE_config_vk]);
		}
		else {
			MrLogError("MrSqlite3::SetConfig(): Cannot read value.");
			return false;
		}
	}
	else
	{
		// delete key
		sqlite3_reset     (m_pd[DELETE_FROM_config_k]);
		sqlite3_bind_text (m_pd[DELETE_FROM_config_k], 1, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(m_pd[DELETE_FROM_config_k]);
	}

	if( state != SQLITE_DONE )  {
		MrLogError("MrSqlite3::SetConfig(): Cannot change value.");
		return false; // error
	}

	return true;
}


char* MrSqlite3::GetConfig(const char* key, const char* def) // the returned string must be free()'d
{
	if( key == NULL || !Ok() ) {
		return NULL;
	}

	sqlite3_reset    (m_pd[SELECT_value_FROM_config_k]);
	sqlite3_bind_text(m_pd[SELECT_value_FROM_config_k], 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(m_pd[SELECT_value_FROM_config_k]) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(m_pd[SELECT_value_FROM_config_k], 0); // Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free().
		if( ptr )
		{
			// success, fall through below to free objects
			return strdup((const char*)ptr);
		}
	}

	// return the default value
	if( def ) {
		return strdup(def);
	}
	return NULL;
}


int32_t MrSqlite3::GetConfigInt(const char* key, int32_t def)
{
    char* str = GetConfig(key, NULL);
    if( str == NULL ) {
		return def;
    }
    return atol(str);
}


bool MrSqlite3::SetConfigInt(const char* key, int32_t value)
{
    char* value_str = sqlite3_mprintf("%i", (int)value);
    if( value_str == NULL ) {
		return false;
    }
    bool ret = SetConfig(key, value_str);
    sqlite3_free(value_str);
    return ret;
}


/*******************************************************************************
 * Handle contacts
 ******************************************************************************/


size_t MrSqlite3::GetContactCnt()
{
	if( m_cobj==NULL ) {
		return 0; // no database, no contacts - this is no error (needed eg. for information)
	}

	sqlite3_reset (m_pd[SELECT_COUNT_FROM_contacts]);
	if( sqlite3_step(m_pd[SELECT_COUNT_FROM_contacts]) != SQLITE_ROW ) {
		MrLogSqliteError(m_cobj);
		MrLogError("MrSqlite3::GetContactCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(m_pd[SELECT_COUNT_FROM_contacts], 0); // success
}


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


size_t MrSqlite3::GetChatCnt()
{
	if( m_cobj==NULL ) {
		return 0; // no database, no chats - this is no error (needed eg. for information)
	}

	sqlite3_reset (m_pd[SELECT_COUNT_FROM_chats]);
	if( sqlite3_step(m_pd[SELECT_COUNT_FROM_chats]) != SQLITE_ROW ) {
		MrLogSqliteError(m_cobj);
		MrLogError("MrSqlite3::GetChatCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(m_pd[SELECT_COUNT_FROM_chats], 0); // success
}


uint32_t MrSqlite3::ChatExists(MrChatType type, uint32_t contact_id)
{
	bool chat_id = 0;

	if( type == MR_CHAT_NORMAL )
	{
		char* querystr=sqlite3_mprintf("SELECT id FROM chats LEFT JOIN chats_contacts ON id=chat_id WHERE type=%i AND contact_id=%i", type, contact_id);

		sqlite3_stmt* stmt = sqlite3_prepare_v2_(querystr);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				chat_id = sqlite3_column_int(stmt, 0);
			}
			else if( r == SQLITE_ERROR ) {
				;
			}
			sqlite3_finalize(stmt);
		}
		else {
			MrLogSqliteError(m_cobj);
			MrLogError("MrSqlite3::ChatExists() failed.");
		}
		sqlite3_free(querystr);
	}

	return chat_id;
}


uint32_t MrSqlite3::CreateNormalChat(const char* name, uint32_t contact_id)
{
	uint32_t chat_id = 0;

	if( ChatExists(MR_CHAT_NORMAL, contact_id) ) {
		return chat_id;
	}

	return chat_id;
}


/*******************************************************************************
 * Handle messages
 ******************************************************************************/


size_t MrSqlite3::GetMsgCnt()
{
	if( m_cobj==NULL ) {
		return 0; // no database, no messages - this is no error (needed eg. for information)
	}

	sqlite3_reset (m_pd[SELECT_COUNT_FROM_msg]);
	if( sqlite3_step(m_pd[SELECT_COUNT_FROM_msg]) != SQLITE_ROW ) {
		MrLogSqliteError(m_cobj);
		MrLogError("MrSqlite3::GetMsgCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(m_pd[SELECT_COUNT_FROM_msg], 0); // success
}


bool MrSqlite3::MessageIdExists(const char* message_id)
{
	// check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	// so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space)
	sqlite3_reset (m_pd[SELECT_id_FROM_msg_m]);
	sqlite3_bind_text(m_pd[SELECT_id_FROM_msg_m], 1, message_id, -1, SQLITE_STATIC);
	if( sqlite3_step(m_pd[SELECT_id_FROM_msg_m]) != SQLITE_ROW ) {
		return false; // record does not exist
	}

	return true; // record does exist
}
