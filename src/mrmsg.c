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
 * File:    mrmsg.cpp
 * Authors: Björn Petersen
 * Purpose: MrMsg represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrmsg.h"
#include "mrtools.h"


MrMsg::MrMsg(MrMailbox* mailbox)
{
	m_mailbox   = mailbox;
	m_id        = 0;
	m_fromId    = 0;
	m_timestamp = 0;
	m_type      = MR_MSG_UNDEFINED;
	m_state     = MR_STATE_UNDEFINED;
	m_msg       = NULL;
}


void MrMsg::Empty()
{
	if( m_msg ) {
		free(m_msg);
		m_msg = NULL;
	}
}


MrMsg::~MrMsg()
{
	Empty();
}


bool MrMsg::SetMsgFromStmt(sqlite3_stmt* row, int row_offset)
{
	Empty();

	m_id        =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	m_fromId    =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	m_timestamp =            (time_t)sqlite3_column_int64(row, row_offset++);
	m_type      =         (MrMsgType)sqlite3_column_int  (row, row_offset++);
	m_state     =        (MrMsgState)sqlite3_column_int  (row, row_offset++);
	m_msg       = safe_strdup((char*)sqlite3_column_text (row, row_offset++));

	return true;
}


char* MrMsg::GetSummary(long flags)
{
	char* from = NULL;
	char* message = NULL;

	if( m_fromId == 0 ) {
		from = safe_strdup("You");
	}
	else {
		MrContact* contact = new MrContact(m_mailbox);
		contact->LoadFromDb(m_fromId);
		if( contact->m_name ) {
			from = safe_strdup(contact->m_name);
			delete contact;
		}
		else {
			from = safe_strdup("BadContactId");
		}
	}

	if( m_msg ) {
		message = safe_strdup(m_msg); // we do not shorten the message, this can be done by the caller
		if( flags & DO_UNWRAP ) {
			mr_unwrap_str(message);
		}
	}

	char* ret;
	char* temp = sqlite3_mprintf("%s: %s", from, message);
	ret = safe_strdup(temp);
	free(from);
	free(message);
	sqlite3_free(temp);
	return ret;
}


/*******************************************************************************
 * Static functions
 ******************************************************************************/


size_t MrMsg::GetMsgCnt(MrMailbox* mailbox) // static function
{
	if( mailbox->m_sql.m_cobj==NULL ) {
		return 0; // no database, no messages - this is no error (needed eg. for information)
	}

	sqlite3_stmt* s = mailbox->m_sql.m_pd[SELECT_COUNT_FROM_msg];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		MrLogSqliteError(mailbox->m_sql.m_cobj);
		MrLogError("MrSqlite3::GetMsgCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(s, 0); // success
}


bool MrMsg::MessageIdExists(MrMailbox* mailbox, const char* rfc724_mid) // static function
{
	// check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	// so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space)
	sqlite3_stmt* s = mailbox->m_sql.m_pd[SELECT_id_FROM_msg_m];
	sqlite3_reset (s);
	sqlite3_bind_text(s, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		return false; // record does not exist
	}

	return true; // record does exist
}


/*******************************************************************************
 * Message lists
 ******************************************************************************/


MrMsgList::MrMsgList()
{
	m_msgs = carray_new(128);
}


MrMsgList::~MrMsgList()
{
	if( m_msgs )
	{
		int cnt = carray_count(m_msgs);
		for( int i = 0; i < cnt; i++ )
		{
			MrMsg* msg = (MrMsg*)carray_get(m_msgs, i);
			if( msg )
			{
				delete msg;
			}
		}

		carray_free(m_msgs);
		m_msgs = NULL;
	}
}
