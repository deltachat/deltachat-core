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

		SetConfig("just-a-test", "test-value");
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
	if( m_sqlite ) {
		sqlite3_close(m_sqlite);
		m_sqlite = NULL;
	}
}


/*******************************************************************************
 * Handle configuration
 ******************************************************************************/


bool MrMailbox::SetConfig(const char* key, const char* value)
{
	return false;
}


const char* GetConfig(const char* key, const char* def) // the returned string must be free()'d
{
	return NULL;
}



/*******************************************************************************
 * Tools
 ******************************************************************************/


sqlite3_stmt* MrMailbox::sqlite3_prepare_v2_(const char* sql)
{
	sqlite3_stmt* retStmt = NULL;

	if( m_sqlite == NULL )
	{
		return NULL; // error
	}

	if( sqlite3_prepare_v2(m_sqlite,
	         sql, -1 /*read `sql` up to the first null-byte*/,
	         &retStmt,
	         NULL /*tail not interesing, we use only single statements*/) != SQLITE_OK )
	{
		return NULL; // error
	}

	// success - the result mus be freed using sqlite3_finalize()
	return retStmt;
}


bool MrMailbox::sqlite3_execute_(const char* sql)
{
	bool          ret = false;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	stmt = sqlite3_prepare_v2_(sql);
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
	char*         sql = NULL;
	sqlite3_stmt* stmt = NULL;
	int           sqlState;

	sql = sqlite3_mprintf("PRAGMA table_info(%s)", name);
	if( sql == NULL ) {
		goto table_exists_Error; // error
	}

	if( (stmt=sqlite3_prepare_v2_(sql)) == NULL ) {
		goto table_exists_Error; // error
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

	if( sql ) {
		sqlite3_free(sql);
	}

	return ret;
}
