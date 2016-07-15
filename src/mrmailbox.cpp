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
	: m_sql(), m_imap(this)
{
}


MrMailbox::~MrMailbox()
{
	Close();
}


bool MrMailbox::Open(const char* dbfile)
{
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
	m_sql.Close();
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


void MrMailbox::Connect()
{
}


void MrMailbox::Disconnect()
{
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

