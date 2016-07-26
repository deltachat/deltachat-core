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


#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrimfparser.h"


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


MrMailbox::MrMailbox()
	: m_sql(this), m_imap(this)
{
}


MrMailbox::~MrMailbox()
{
	Close();
}


bool MrMailbox::Open(const char* dbfile)
{
	{
		MrSqlite3Locker locker(m_sql);

		// Open() sets up the object and connects to the given database
		// from which all configuration is read/written to.

		// Create/open sqlite database
		if( !m_sql.Open(dbfile) ) {
			goto Open_Error; // error already logged
		}
	}

	// success
	return true;

	// error
Open_Error:
	Close();
	return false;
}


void MrMailbox::Close()
{
	MrSqlite3Locker locker(m_sql);

	m_sql.Close();
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


bool MrMailbox::Connect()
{
	if( m_imap.IsConnected() ) {
		return true;
	}

	// read parameter, unset parameters are still NULL afterwards
	{
		MrSqlite3Locker locker(m_sql);

		m_loginParam.Clear();

		m_loginParam.m_email       = m_sql.GetConfig   ("email",       NULL);

		m_loginParam.m_mail_server = m_sql.GetConfig   ("mail_server", NULL);
		m_loginParam.m_mail_port   = m_sql.GetConfigInt("mail_port",   0);
		m_loginParam.m_mail_user   = m_sql.GetConfig   ("mail_user",   NULL);
		m_loginParam.m_mail_pw     = m_sql.GetConfig   ("mail_pw",     NULL);

		m_loginParam.m_send_server = m_sql.GetConfig   ("send_server", NULL);
		m_loginParam.m_send_port   = m_sql.GetConfigInt("send_port",   0);
		m_loginParam.m_send_user   = m_sql.GetConfig   ("send_user",   NULL);
		m_loginParam.m_send_pw     = m_sql.GetConfig   ("send_pw",     NULL);
	}

	// try to suggest unset parameters
	m_loginParam.Complete();

	// connect
	return m_imap.Connect(&m_loginParam);
}


void MrMailbox::Disconnect()
{
	m_imap.Disconnect();
}


bool MrMailbox::Fetch()
{
	return m_imap.Fetch();
}


/*******************************************************************************
 * Receive an IMF as an result to calling Fetch()
 * the new IMF may be old or new and should be parsed, contacts created etc.
 * However, the caller should make sure, it does not exist in the database.
 ******************************************************************************/

void MrMailbox::ReceiveImf(const char* imf, size_t imf_len)
{
	MrImfParser parser(this);

	if( !parser.Imf2Msg(imf, imf_len) ) {
		return; // error already logged
	}


}


/*******************************************************************************
 * Handle contacts
 ******************************************************************************/


// ...


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


MrChatList* MrMailbox::GetChats()
{
	MrSqlite3Locker locker(m_sql);

	return m_sql.GetChatList();
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


char* MrMailbox::GetDbFile()
{
	if( m_sql.m_dbfile == NULL ) {
		return NULL; // database not opened
	}

	return strdup(m_sql.m_dbfile); // must be freed by the caller
}


char* MrMailbox::GetInfo()
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	#define BUF_BYTES 10000
	char* buf = (char*)malloc(BUF_BYTES+1);
	if( buf == NULL ) {
		MrLogError("MrMailbox::GetInfo(): Out of memory.");
		return NULL; // error
	}

	// read data (all pointers may be NULL!)
	char *email, *mail_server, *mail_port, *mail_user, *mail_pw, *send_server, *send_port, *send_user, *send_pw, *debug_dir;
	int contacts, chats, messages;
	{
		MrSqlite3Locker locker(m_sql);

		email       = m_sql.GetConfig("email", NULL);

		mail_server = m_sql.GetConfig("mail_server", NULL);
		mail_port   = m_sql.GetConfig("mail_port", NULL);
		mail_user   = m_sql.GetConfig("mail_user", NULL);
		mail_pw     = m_sql.GetConfig("mail_pw", NULL);

		send_server = m_sql.GetConfig("send_server", NULL);
		send_port   = m_sql.GetConfig("send_port", NULL);
		send_user   = m_sql.GetConfig("send_user", NULL);
		send_pw     = m_sql.GetConfig("send_pw", NULL);

		debug_dir   = m_sql.GetConfig("debug_dir", NULL);

		contacts    = m_sql.GetContactCnt();
		chats       = m_sql.GetChatCnt();
		messages    = m_sql.GetMsgCnt();
	}

	// create info
    snprintf(buf, BUF_BYTES,
		"Backend version  %i.%i.%i\n"
		"SQLite version   %s, threadsafe=%i\n"
		"libEtPan version %i.%i\n"
		"Database file    %s\n"
		"Contacts         %i\n"
		"Chats/Messages   %i/%i\n"

		"email            %s\n"
		"mail_server      %s\n"
		"mail_port        %s\n"
		"mail_user        %s\n"
		"mail_pw          %s\n"

		"send_server      %s\n"
		"send_port        %s\n"
		"send_user        %s\n"
		"send_pw          %s\n"

		"debug_dir        %s\n"
		"If possible, unset values are filled by the program with typical values.\n"

		, MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION
		, SQLITE_VERSION, sqlite3_threadsafe()
		, libetpan_get_version_major(), libetpan_get_version_minor()
		, m_sql.m_dbfile? m_sql.m_dbfile : unset

		, contacts
		, chats, messages

		, email? email : unset
		, mail_server? mail_server : unset
		, mail_port? mail_port : unset
		, mail_user? mail_user : unset
		, mail_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get mail_pw`

		, send_server? send_server : unset
		, send_port? send_port : unset
		, send_user? send_user : unset
		, send_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get send_pw`

		, debug_dir? debug_dir : unset
		);

	// free data
	#define GI_FREE_(a) if((a)) { free((a)); }
	GI_FREE_(email);

	GI_FREE_(mail_server);
	GI_FREE_(mail_port);
	GI_FREE_(mail_user);
	GI_FREE_(mail_pw);

	GI_FREE_(send_server);
	GI_FREE_(send_port);
	GI_FREE_(send_user);
	GI_FREE_(send_pw);
	return buf; // must be freed by the caller
}


bool MrMailbox::Empty()
{
	MrSqlite3Locker locker(m_sql);

	m_sql.sqlite3_execute_("DELETE FROM contacts;");
	m_sql.sqlite3_execute_("DELETE FROM chats;");
	m_sql.sqlite3_execute_("DELETE FROM chats_contacts;");
	m_sql.sqlite3_execute_("DELETE FROM msg;");
	m_sql.sqlite3_execute_("DELETE FROM msg_to;");
	m_sql.sqlite3_execute_("DELETE FROM config WHERE keyname LIKE 'folder.%';");

	return true;
}
