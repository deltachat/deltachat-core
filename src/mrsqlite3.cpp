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


MrSqlite3::MrSqlite3()
{
	m_cobj                       = NULL;
	m_dbfile                     = NULL;

	m_SELECT_value_FROM_config_k = NULL;
	m_INSERT_INTO_config_kv      = NULL;
	m_UPDATE_config_vk           = NULL;
	m_DELETE_FROM_config_k       = NULL;

	m_SELECT_COUNT_FROM_contacts = NULL;
	m_SELECT_COUNT_FROM_chats    = NULL;
	m_SELECT_COUNT_FROM_msg      = NULL;

	pthread_mutex_init(&m_critical, NULL);
}


MrSqlite3::~MrSqlite3()
{
	Close();

	pthread_mutex_destroy(&m_critical);
}


bool MrSqlite3::Open(const char* dbfile)
{
	if( dbfile == NULL || m_dbfile/*already a file opened?*/ ) {
		goto Open_Error;
	}

	m_dbfile = strdup(dbfile);
	if( m_dbfile == NULL ) {
		goto Open_Error;
	}

	if( sqlite3_open(dbfile, &m_cobj) != SQLITE_OK ) {
		goto Open_Error;
	}

	// Init the tables, if not yet done
	if( !sqlite3_table_exists_("contacts") )
	{
		sqlite3_execute_("CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		sqlite3_execute_("CREATE INDEX config_index1 ON config (keyname);");

		sqlite3_execute_("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, email TEXT);");
		sqlite3_execute_("CREATE INDEX contacts_index1 ON contacts (name);");

		sqlite3_execute_("CREATE TABLE chats (id INTEGER PRIMARY KEY, type INTEGER, name TEXT);");
		sqlite3_execute_("CREATE TABLE chats_contacts (chat_id INTEGER, contact_id);");
		sqlite3_execute_("CREATE INDEX chats_contacts_index1 ON chat_contacts (chat_id);");

		sqlite3_execute_("CREATE TABLE msg (id INTEGER PRIMARY KEY, chat INTEGER, time INTEGER, type INTEGER, msg TEXT);");
		sqlite3_execute_("CREATE INDEX msg_index1 ON msg (time);");

		if( !sqlite3_table_exists_("config") || !sqlite3_table_exists_("contacts")
		 || !sqlite3_table_exists_("chats") || !sqlite3_table_exists_("chats_contacts")
		 || !sqlite3_table_exists_("msg") ) {
			goto Open_Error; // cannot create the tables - maybe we cannot write?
		}
	}

	// prepare statements (we do it when the tables really exists, however, I do not know if sqlite relies on this)
	m_SELECT_value_FROM_config_k = sqlite3_prepare_v2_("SELECT value FROM config WHERE keyname=?;");
	m_INSERT_INTO_config_kv      = sqlite3_prepare_v2_("INSERT INTO config (keyname, value) VALUES (?, ?);");
	m_UPDATE_config_vk           = sqlite3_prepare_v2_("UPDATE config SET value=? WHERE keyname=?;");
	m_DELETE_FROM_config_k       = sqlite3_prepare_v2_("DELETE FROM config WHERE keyname=?;");

	m_SELECT_COUNT_FROM_contacts = sqlite3_prepare_v2_("SELECT COUNT(*) FROM contacts;");
	m_SELECT_COUNT_FROM_chats    = sqlite3_prepare_v2_("SELECT COUNT(*) FROM chats;");
	m_SELECT_COUNT_FROM_msg      = sqlite3_prepare_v2_("SELECT COUNT(*) FROM msg;");

	if( m_SELECT_value_FROM_config_k==NULL || m_INSERT_INTO_config_kv==NULL || m_UPDATE_config_vk==NULL || m_DELETE_FROM_config_k==NULL
	 || m_SELECT_COUNT_FROM_contacts==NULL || m_SELECT_COUNT_FROM_chats==NULL || m_SELECT_COUNT_FROM_msg ) {
		goto Open_Error;
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
		SQLITE3_FINALIZE_(m_SELECT_value_FROM_config_k)
		SQLITE3_FINALIZE_(m_INSERT_INTO_config_kv)
		SQLITE3_FINALIZE_(m_UPDATE_config_vk)
		SQLITE3_FINALIZE_(m_DELETE_FROM_config_k)

		SQLITE3_FINALIZE_(m_SELECT_COUNT_FROM_contacts);
		SQLITE3_FINALIZE_(m_SELECT_COUNT_FROM_chats);
		SQLITE3_FINALIZE_(m_SELECT_COUNT_FROM_msg);

		sqlite3_close(m_cobj);
		m_cobj = NULL;
	}

	if( m_dbfile )
	{
		free(m_dbfile);
		m_dbfile = NULL;
	}
}


char* MrSqlite3::GetDbFile()
{
	if( m_dbfile == NULL ) {
		return NULL;
	}

	return strdup(m_dbfile); // the caller should free() the returned string
}


sqlite3_stmt* MrSqlite3::sqlite3_prepare_v2_(const char* querystr)
{
	sqlite3_stmt* retStmt = NULL;

	if( m_cobj == NULL )
	{
		return NULL; // error
	}

	if( sqlite3_prepare_v2(m_cobj,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
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
		goto sqlite3_execute_Error;
	}

	sqlState = sqlite3_step(stmt);
	if( sqlState != SQLITE_DONE && sqlState != SQLITE_ROW )  {
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
		goto table_exists_Error;
	}

	if( (stmt=sqlite3_prepare_v2_(querystr)) == NULL ) {
		goto table_exists_Error;
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

	if( key == NULL || !Ok() ) {
		return false;
	}

	if( value )
	{
		// insert/update key=value
		sqlite3_reset     (m_SELECT_value_FROM_config_k);
		sqlite3_bind_text (m_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
		state=sqlite3_step(m_SELECT_value_FROM_config_k);
		if( state == SQLITE_DONE ) {
			sqlite3_reset     (m_INSERT_INTO_config_kv);
			sqlite3_bind_text (m_INSERT_INTO_config_kv, 1, key,   -1, SQLITE_STATIC);
			sqlite3_bind_text (m_INSERT_INTO_config_kv, 2, value, -1, SQLITE_STATIC);
			state=sqlite3_step(m_INSERT_INTO_config_kv);

		}
		else if( state == SQLITE_ROW ) {
			sqlite3_reset     (m_UPDATE_config_vk);
			sqlite3_bind_text (m_UPDATE_config_vk, 1, value, -1, SQLITE_STATIC);
			sqlite3_bind_text (m_UPDATE_config_vk, 2, key,   -1, SQLITE_STATIC);
			state=sqlite3_step(m_UPDATE_config_vk);
		}
		else {
			return false;
		}
	}
	else
	{
		// delete key
		sqlite3_reset     (m_DELETE_FROM_config_k);
		sqlite3_bind_text (m_DELETE_FROM_config_k, 1, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(m_DELETE_FROM_config_k);
	}

	if( state != SQLITE_DONE )  {
		return false;
	}

	return true;
}


char* MrSqlite3::GetConfig(const char* key, const char* def) // the returned string must be free()'d
{
	if( key == NULL || !Ok() ) {
		return NULL;
	}

	sqlite3_reset    (m_SELECT_value_FROM_config_k);
	sqlite3_bind_text(m_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(m_SELECT_value_FROM_config_k) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(m_SELECT_value_FROM_config_k, 0); // Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free().
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


/*******************************************************************************
 * Handle tables
 ******************************************************************************/


size_t MrSqlite3::GetContactCnt()
{
	sqlite3_reset (m_SELECT_COUNT_FROM_contacts);
	if( sqlite3_step(m_SELECT_COUNT_FROM_contacts) != SQLITE_ROW ) {
		return 0; // error
	}

	return sqlite3_column_int(m_SELECT_COUNT_FROM_contacts, 0); // success
}


size_t MrSqlite3::GetChatCnt()
{
	sqlite3_reset (m_SELECT_COUNT_FROM_chats);
	if( sqlite3_step(m_SELECT_COUNT_FROM_chats) != SQLITE_ROW ) {
		return 0; // error
	}

	return sqlite3_column_int(m_SELECT_COUNT_FROM_chats, 0); // success
}


size_t MrSqlite3::GetMsgCnt()
{
	sqlite3_reset (m_SELECT_COUNT_FROM_msg);
	if( sqlite3_step(m_SELECT_COUNT_FROM_msg) != SQLITE_ROW ) {
		return 0; // error
	}

	return sqlite3_column_int(m_SELECT_COUNT_FROM_msg, 0); // success
}
