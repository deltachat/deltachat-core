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
 * File:    mrsqlite3.h
 * Authors: Björn Petersen
 * Purpose: MrSqlite3 wraps around SQLite
 *
 ******************************************************************************/


#ifndef __MRSQLITE3_H__
#define __MRSQLITE3_H__


#include <sqlite3.h>


class MrSqlite3
{
public:
	              MrSqlite3            ();
	              ~MrSqlite3           ();
	bool          Open                 (const char* dbfile);
	void          Close                ();

	// misc
	char*         GetDbFile            (); // the returned string must be free()'d, returns NULL on errors or if no database is open

	// prepared statements - this is the favourite way for the caller to use SQLite
	sqlite3_stmt  *m_SELECT_value_FROM_config_k,
	              *m_INSERT_INTO_config_kv,
	              *m_UPDATE_config_vk;
private:
	// m_sqlite is the database given as dbfile to Open()
	char*         m_dbfile;
	sqlite3*      m_cobj;

	// tools, these functions are compatible to the corresponding sqlite3_* functions
	sqlite3_stmt* sqlite3_prepare_v2_  (const char* sql); // the result mus be freed using sqlite3_finalize()
	bool          sqlite3_execute_     (const char* sql);
	bool          sqlite3_table_exists_(const char* name);
};


#endif // __MRSQLITE3_H__

