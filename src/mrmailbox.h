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
 * File:    mrmailbox.h
 * Authors: Björn Petersen
 * Purpose: MrMailbox represents a single mailbox, normally, typically is only
 *          one instance of this class present.
 *          Each mailbox is linked to an IMAP/POP3 account and uses a separate
 *          SQLite database for offline functionality and for mailbox-related
 *          settings.
 *
 ******************************************************************************/


#ifndef __MRMAILBOX_H__
#define __MRMAILBOX_H__


#include <stdlib.h> // eg. for size_t

struct sqlite3;
struct sqlite3_stmt;
class MrChat;
class MrContact;


#define MR_VERSION_MAJOR    0
#define MR_VERSION_MINOR    1
#define MR_VERSION_REVISION 2


class MrMailbox
{
public:
	              MrMailbox            ();
	              ~MrMailbox           ();

	// open/close a mailbox object, if the given file does not exist, it is created
	// and can be set up using SetConfig() and Connect() afterwards.
	// sth. like "~/file" won't work on all systems, if in doubt, use absolute paths for dbfile.
	bool          Open                 (const char* dbfile);
	void          Close                ();

	// connect to the mailbox: error are be received asynchronously.
	void          Connect              ();

	// iterate contacts
	size_t        GetContactCnt        ();
	MrContact*    GetContact           (size_t i); // the returned objects must be Release()'d, returns NULL on errors

	// iterate chats
	size_t        GetChatCnt           ();
	MrChat*       GetChat              (size_t i); // the returned objects must be Release()'d, returns NULL on errors

	// handle configurations
	bool          SetConfig            (const char* key, const char* value);
	char*         GetConfig            (const char* key, const char* def); // the returned string must be free()'d, returns NULL on errors

	// misc
	char*         GetDbFile            (); // the returned string must be free()'d, returns NULL on errors or if no database is open

private:
	// m_sqlite is the database given as dbfile to Open()
	char*         m_dbfile;
	sqlite3*      m_sqlite;
	sqlite3_stmt  *m_stmt_SELECT_value_FROM_config_k,
	              *m_stmt_INSERT_INTO_config_kv,
	              *m_stmt_UPDATE_config_vk;

	// database tools
	sqlite3_stmt* sqlite3_prepare_v2_  (const char* sql); // the result mus be freed using sqlite3_finalize()
	bool          sqlite3_execute_     (const char* sql);
	bool          sqlite3_table_exists_(const char* name);
};


#endif // __MRMAILBOX_H__

