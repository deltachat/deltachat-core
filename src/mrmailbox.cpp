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
 * File:    mrmailbox.cpp
 * Authors: Björn Petersen
 * Purpose: MrMailbox represents a single mailbox, see header for details.
 *
 ******************************************************************************/


#include <iostream>
#include <string.h>
#include <libetpan/libetpan.h>
#include <sqlite3.h>
#include "mrmailbox.h"


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


MrMailbox::MrMailbox()
{
	m_sqlite = NULL;
}


MrMailbox::~MrMailbox()
{
	Exit();
}


bool MrMailbox::Init(const char* dbname)
{
	// Init() sets up the object and connects to the given database
	// from which all configuration is read/written to.

	// Create/open sqlite database
	if( sqlite3_open(dbname, &m_sqlite) != SQLITE_OK ) {
		goto Init_Error;
	}

	// Init the tables, if not yet done
	if( !sqlite3_table_exists_("config") )
	{
		sqlite3_execute_("CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		sqlite3_execute_("CREATE INDEX configindex01 ON config (keyname);");

		if( !sqlite3_table_exists_("config") ) {
			goto Init_Error; // cannot create the tables - maybe we cannot write?
		}


	}

	// prepare statements
	m_stmt_SELECT_value_FROM_config_k = sqlite3_prepare_v2_("SELECT value FROM config WHERE keyname=?;");
	m_stmt_INSERT_INTO_config_kv      = sqlite3_prepare_v2_("INSERT INTO config (keyname, value) VALUES (?, ?);");
	m_stmt_UPDATE_config_vk           = sqlite3_prepare_v2_("UPDATE config SET value=? WHERE keyname=?;");

	if( m_stmt_SELECT_value_FROM_config_k==NULL || m_stmt_INSERT_INTO_config_kv==NULL || m_stmt_UPDATE_config_vk==NULL ) {
		goto Init_Error;
	}

	// test LibEtPan
	#if 0
	struct mailimf_mailbox * mb;
	char * display_name;
	char * address;

	display_name = strdup("DINH =?iso-8859-1?Q?Vi=EAt_Ho=E0?=");
	address = strdup("dinh.viet.hoa@free.fr");
	mb = mailimf_mailbox_new(display_name, address); // mailimf_mailbox_new() takes ownership of the given strings!
	mailimf_mailbox_free(mb);
	#endif

	// success
	return true;

	// error
Init_Error:
	Exit();
	return false;
}


void MrMailbox::Exit()
{
	#define SQLITE3_FINALIZE_(a) \
	if((a)) { \
		sqlite3_finalize((a)); \
		(a) = NULL; \
	}

	if( m_sqlite )
	{
		SQLITE3_FINALIZE_(m_stmt_SELECT_value_FROM_config_k)
		SQLITE3_FINALIZE_(m_stmt_INSERT_INTO_config_kv)
		SQLITE3_FINALIZE_(m_stmt_UPDATE_config_vk)

		sqlite3_close(m_sqlite);
		m_sqlite = NULL;
	}
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


bool MrMailbox::Connect()
{
	return false;
}


/*******************************************************************************
 * Handle contacts
 ******************************************************************************/


size_t MrMailbox::GetContactCnt()
{
	return 0;
}


MrContact* MrMailbox::GetContact(size_t i)
{
	return NULL;
}


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


size_t MrMailbox::GetChatCnt()
{
	return 0;
}


MrChat* MrMailbox::GetChat(size_t i)
{
	return NULL;
}


/*******************************************************************************
 * Handle configuration
 ******************************************************************************/


bool MrMailbox::SetConfig(const char* key, const char* value)
{
	int state;

	sqlite3_reset     (m_stmt_SELECT_value_FROM_config_k);
	sqlite3_bind_text (m_stmt_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
	state=sqlite3_step(m_stmt_SELECT_value_FROM_config_k);

	if( state == SQLITE_DONE )
	{
		sqlite3_reset     (m_stmt_INSERT_INTO_config_kv);
		sqlite3_bind_text (m_stmt_INSERT_INTO_config_kv, 1, key,   -1, SQLITE_STATIC);
		sqlite3_bind_text (m_stmt_INSERT_INTO_config_kv, 2, value, -1, SQLITE_STATIC);
		state=sqlite3_step(m_stmt_INSERT_INTO_config_kv);

	}
	else if( state == SQLITE_ROW )
	{
		sqlite3_reset     (m_stmt_UPDATE_config_vk);
		sqlite3_bind_text (m_stmt_UPDATE_config_vk, 1, value, -1, SQLITE_STATIC);
		sqlite3_bind_text (m_stmt_UPDATE_config_vk, 2, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(m_stmt_UPDATE_config_vk);
	}
	else
	{
		return false;
	}

	if( state != SQLITE_DONE )  {
		return false;
	}

	return true;
}


char* MrMailbox::GetConfig(const char* key, const char* def) // the returned string must be free()'d
{
	sqlite3_reset    (m_stmt_SELECT_value_FROM_config_k);
	sqlite3_bind_text(m_stmt_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(m_stmt_SELECT_value_FROM_config_k) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(m_stmt_SELECT_value_FROM_config_k, 0); // Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free().
		if( ptr )
		{
			// success, fall through below to free objects
			return strdup((const char*)ptr);
		}
	}

	// return the default value
	return strdup(def);
}


/*******************************************************************************
 * Tools
 ******************************************************************************/


sqlite3_stmt* MrMailbox::sqlite3_prepare_v2_(const char* querystr)
{
	sqlite3_stmt* retStmt = NULL;

	if( m_sqlite == NULL )
	{
		return NULL; // error
	}

	if( sqlite3_prepare_v2(m_sqlite,
	         querystr, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		return NULL; // error
	}

	// success - the result mus be freed using sqlite3_finalize()
	return retStmt;
}


bool MrMailbox::sqlite3_execute_(const char* querystr)
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


bool MrMailbox::sqlite3_table_exists_(const char* name)
{
	bool          ret = false;
	char*         querystr = NULL;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	if( (querystr=sqlite3_mprintf("PRAGMA table_info(%s)", name)) == NULL ) {
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
