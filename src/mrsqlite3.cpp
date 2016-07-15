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
}


MrSqlite3::~MrSqlite3()
{
	Close();
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
	if( !sqlite3_table_exists_("config") )
	{
		sqlite3_execute_("CREATE TABLE config (id INTEGER PRIMARY KEY, keyname TEXT, value TEXT);");
		sqlite3_execute_("CREATE INDEX configindex01 ON config (keyname);");

		if( !sqlite3_table_exists_("config") ) {
			goto Open_Error; // cannot create the tables - maybe we cannot write?
		}
	}

	// prepare statements (we do it when the tables really exists, however, I do not know if sqlite relies on this)
	m_SELECT_value_FROM_config_k = sqlite3_prepare_v2_("SELECT value FROM config WHERE keyname=?;");
	m_INSERT_INTO_config_kv      = sqlite3_prepare_v2_("INSERT INTO config (keyname, value) VALUES (?, ?);");
	m_UPDATE_config_vk           = sqlite3_prepare_v2_("UPDATE config SET value=? WHERE keyname=?;");
	m_DELETE_FROM_config_k       = sqlite3_prepare_v2_("DELETE FROM config WHERE keyname=?;");

	if( m_SELECT_value_FROM_config_k==NULL || m_INSERT_INTO_config_kv==NULL || m_UPDATE_config_vk==NULL ) {
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
