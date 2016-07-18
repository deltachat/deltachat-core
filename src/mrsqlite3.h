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
#include <libetpan.h>
#include <pthread.h>


class MrSqlite3
{
public:
	              MrSqlite3            ();
	              ~MrSqlite3           ();
	bool          Open                 (const char* dbfile);
	void          Close                ();
	bool          Ok                   () const { return (m_cobj!=NULL); }

	// handle configurations
	bool          SetConfig            (const char* key, const char* value);
	char*         GetConfig            (const char* key, const char* def); // the returned string must be free()'d, returns NULL on errors
	int32_t       GetConfigInt         (const char* key, int32_t def);

	// get counts
	size_t        GetContactCnt        ();
	size_t        GetChatCnt           ();

	// handle  messages
	size_t        GetMsgCnt            (); // total number of messages, just for statistics, normally not needed for the program flow
	bool          MsgExists            (uint32_t uid);

	// misc
	char*         GetDbFile            (); // the returned string must be free()'d, returns NULL on errors or if no database is open

	// prepared statements - this is the favourite way for the caller to use SQLite
	sqlite3_stmt  *m_SELECT_value_FROM_config_k,
	              *m_INSERT_INTO_config_kv,
	              *m_UPDATE_config_vk,
	              *m_DELETE_FROM_config_k,
	              *m_SELECT_COUNT_FROM_contacts,
	              *m_SELECT_COUNT_FROM_chats,
	              *m_SELECT_COUNT_FROM_msg,
	              *m_SELECT_id_FROM_msg_i;

private:
	// m_sqlite is the database given as dbfile to Open()
	char*         m_dbfile;
	sqlite3*      m_cobj;

	// tools, these functions are compatible to the corresponding sqlite3_* functions
	sqlite3_stmt* sqlite3_prepare_v2_  (const char* sql); // the result mus be freed using sqlite3_finalize()
	bool          sqlite3_execute_     (const char* sql);
	bool          sqlite3_table_exists_(const char* name);

	pthread_mutex_t m_critical;
	friend class    MrSqlite3Locker;
	friend class    MrImap;
};


class MrSqlite3Locker
{
public:
	// the user of MrSqlite3 must make sure that the MrSqlite3-object is only used by one thread at the same time.
	// for this purpose, he can use MrSqlite3Locker as a helper:
	// By the simple existance of a object, all other object creation will be halted until the first is deleted again.
	MrSqlite3Locker(MrSqlite3& sqlite3)
	{
		m_sqlite3 = &sqlite3;
		pthread_mutex_lock(&m_sqlite3->m_critical);
	}

	~MrSqlite3Locker()
	{
		pthread_mutex_unlock(&m_sqlite3->m_critical);
	}

private:
	MrSqlite3* m_sqlite3;
};


#endif // __MRSQLITE3_H__

