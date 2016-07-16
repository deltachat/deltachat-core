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


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


MrMailbox::MrMailbox()
	: m_sql(), m_imap(this)
{
}


MrMailbox::~MrMailbox()
{
	Close();
}


bool MrMailbox::Open(const char* dbfile)
{
	MrSqlite3Locker locker(m_sql);

	// Open() sets up the object and connects to the given database
	// from which all configuration is read/written to.

	// Create/open sqlite database
	if( !m_sql.Open(dbfile) ) {
		goto Open_Error;
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


void MrMailbox::Connect()
{
	MrLoginParam param(this);

	param.ReadFromSql();

	param.Complete();

	m_imap.Connect(&param);
}


void MrMailbox::Disconnect()
{
	m_imap.Disconnect();
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


size_t MrMailbox::GetMsgCnt()
{
	return 0;
}


/*******************************************************************************
 * Handle configuration
 ******************************************************************************/


bool MrMailbox::SetConfig(const char* key, const char* value)
{
	MrSqlite3Locker locker(m_sql);
	int state;

	if( key == NULL || !m_sql.Ok() ) {
		return false;
	}

	if( value )
	{
		// insert/update key=value
		sqlite3_reset     (m_sql.m_SELECT_value_FROM_config_k);
		sqlite3_bind_text (m_sql.m_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
		state=sqlite3_step(m_sql.m_SELECT_value_FROM_config_k);
		if( state == SQLITE_DONE ) {
			sqlite3_reset     (m_sql.m_INSERT_INTO_config_kv);
			sqlite3_bind_text (m_sql.m_INSERT_INTO_config_kv, 1, key,   -1, SQLITE_STATIC);
			sqlite3_bind_text (m_sql.m_INSERT_INTO_config_kv, 2, value, -1, SQLITE_STATIC);
			state=sqlite3_step(m_sql.m_INSERT_INTO_config_kv);

		}
		else if( state == SQLITE_ROW ) {
			sqlite3_reset     (m_sql.m_UPDATE_config_vk);
			sqlite3_bind_text (m_sql.m_UPDATE_config_vk, 1, value, -1, SQLITE_STATIC);
			sqlite3_bind_text (m_sql.m_UPDATE_config_vk, 2, key,   -1, SQLITE_STATIC);
			state=sqlite3_step(m_sql.m_UPDATE_config_vk);
		}
		else {
			return false;
		}
	}
	else
	{
		// delete key
		sqlite3_reset     (m_sql.m_DELETE_FROM_config_k);
		sqlite3_bind_text (m_sql.m_DELETE_FROM_config_k, 1, key,   -1, SQLITE_STATIC);
		state=sqlite3_step(m_sql.m_DELETE_FROM_config_k);
	}

	if( state != SQLITE_DONE )  {
		return false;
	}

	return true;
}


char* MrMailbox::GetConfig(const char* key, const char* def) // the returned string must be free()'d
{
	MrSqlite3Locker locker(m_sql);

	if( key == NULL || !m_sql.Ok() ) {
		return false;
	}

	sqlite3_reset    (m_sql.m_SELECT_value_FROM_config_k);
	sqlite3_bind_text(m_sql.m_SELECT_value_FROM_config_k, 1, key, -1, SQLITE_STATIC);
	if( sqlite3_step(m_sql.m_SELECT_value_FROM_config_k) == SQLITE_ROW )
	{
		const unsigned char* ptr = sqlite3_column_text(m_sql.m_SELECT_value_FROM_config_k, 0); // Do not pass the pointers returned from sqlite3_column_text(), etc. into sqlite3_free().
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


int32_t MrMailbox::GetConfigInt(const char* key, int32_t def)
{
    char* str = GetConfig(key, NULL);
    if( str == NULL ) {
		return def;
    }
    return atol(str);
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


char* MrMailbox::GetInfo()
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	#define BUF_BYTES 4096
	char* buf = (char*)malloc(BUF_BYTES+1);
	if( buf == NULL ) {
		return NULL; // error
	}

	// read data (all pointers may be NULL!)
	char* dbfile      = GetDbFile();
	char* email       = GetConfig("email", NULL);

	char* mail_server = GetConfig("mail_server", NULL);
	char* mail_port   = GetConfig("mail_port", NULL);
	char* mail_user   = GetConfig("mail_user", NULL);
	char* mail_pw     = GetConfig("mail_pw", NULL);

	char* send_server = GetConfig("send_server", NULL);
	char* send_port   = GetConfig("send_port", NULL);
	char* send_user   = GetConfig("send_user", NULL);
	char* send_pw     = GetConfig("send_pw", NULL);
	int   chats       = GetChatCnt();
	int   messages    = GetMsgCnt();
	int   contacts    = GetContactCnt();

	// create info
    snprintf(buf, BUF_BYTES,
		"Backend version  %i.%i.%i\n"
		"SQLite version   %s, threadsafe=%i\n"
		"libEtPan version %i.%i\n"
		"Database file    %s\n"
		"Chats/Messages   %i/%i\n"
		"Contacts         %i\n"

		"mail_server      %s\n"
		"mail_port        %s\n"
		"mail_user        %s\n"
		"mail_pw          %s\n"

		"send_server      %s\n"
		"send_port        %s\n"
		"send_user        %s\n"
		"send_pw          %s\n"
		"If possible, unset values are filled by the program with typical values.\n"

		, MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION
		, SQLITE_VERSION, sqlite3_threadsafe()
		, libetpan_get_version_major(), libetpan_get_version_minor()
		, dbfile? dbfile : unset

		, chats, messages
		, contacts

		, mail_server? mail_server : unset
		, mail_port? mail_port : unset
		, mail_user? mail_user : unset
		, mail_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get mail_pw`

		, send_server? send_server : unset
		, send_port? send_port : unset
		, send_user? send_user : unset
		, send_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get send_pw`
		);

	// free data
	#define GI_FREE_(a) if((a)) { free((a)); }
	GI_FREE_(dbfile);
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

