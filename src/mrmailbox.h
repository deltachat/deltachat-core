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


class MrMailbox
{
public:
	            MrMailbox   ();
	            ~MrMailbox  ();

	// init/exit a mailbox object, if the given file does not exist, it is created
	// and can be set up using SetConfig() and Connect() afterwards.
	// sth. like "~/file" won't work on all systems, if in doubt, use absolute paths for dbfile.
	bool        Init        (const char* dbfile);
	void        Exit        ();

	// handle configurations
	bool        SetConfig   (const char* key, const char* value);
	const char* GetConfig   (const char* key, const char* def); // the returned string must be free()'d, returns NULL on errors

private:
	// m_sqlite is the database given as dbfile to Init()
	struct sqlite3*  m_sqlite;

	// database tools
	struct sqlite3_stmt* sqlite3_prepare_v2_  (const char* sql); // the result mus be freed using sqlite3_finalize()
	bool                 sqlite3_execute_     (const char* sql);
	bool                 sqlite3_table_exists_(const char* name);
};


#endif // __MRBACKEND_H__
