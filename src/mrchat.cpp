/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any laterMrChat
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
 * File:    mrchat.cpp
 * Authors: Björn Petersen
 * Purpose: MrChat represents a single chat, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrchat.h"
#include "mrtools.h"
#include "mrmsg.h"
#include "mrcontact.h"


MrChat::MrChat(MrMailbox* mailbox)
{
	m_mailbox        = mailbox;
	m_type           = MR_CHAT_UNDEFINED;
	m_name           = NULL;
	m_lastMsg        = NULL;
}


MrChat::~MrChat()
{
	Empty();
}


void MrChat::Empty()
{
	if( m_name ) {
		free(m_name);
		m_name = NULL;
	}

	if( m_lastMsg ) {
		delete m_lastMsg;
		m_lastMsg = NULL;
	}
}


bool MrChat::SetChatFromStmt(sqlite3_stmt* row)
{
	Empty();

	int row_offset = 0;
	m_id             =                    sqlite3_column_int  (row, row_offset++); // the columns are defined in MR_CHAT_FIELDS
	m_type           = (MrChatType)       sqlite3_column_int  (row, row_offset++);
	m_name           = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	m_lastMsg        = new MrMsg(m_mailbox);
	m_lastMsg->SetMsgFromStmt(row, row_offset);

	if( m_name == NULL || m_lastMsg == NULL || m_lastMsg->m_msg == NULL ) {
		return false;
	}

	return true;
}


bool MrChat::LoadFromDb(const char* name, uint32_t id)
{
	bool          success = false;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	Empty();

	if( name ) {
		q = sqlite3_mprintf(MR_GET_CHATS_PREFIX " WHERE c.name=%Q " MR_GET_CHATS_POSTFIX ";", name);
	}
	else {
		q = sqlite3_mprintf(MR_GET_CHATS_PREFIX " WHERE c.id=%i" MR_GET_CHATS_POSTFIX ";", id);
	}

	stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto LoadFromDb_Cleanup;
	}

	if( !SetChatFromStmt(stmt) ) {
		goto LoadFromDb_Cleanup;
	}

	// success
	success  = true;

	// cleanup
LoadFromDb_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	return success;
}


char* MrChat::GetSubtitle()
{
	// returns either the e-mail-address or the number of chat members
	char *q1 = NULL, *q2 = NULL;
	char* ret = NULL;

	if( m_type == MR_CHAT_NORMAL || m_type == MR_CHAT_PRIVATE )
	{
		q1 = sqlite3_mprintf("SELECT c.email FROM chats_contacts cc LEFT JOIN contacts c ON c.id=cc.contact_id WHERE cc.chat_id=%i", m_id);
		sqlite3_stmt* stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q1);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				ret = safe_strdup((const char*)sqlite3_column_text(stmt, 0));
			}
			sqlite3_finalize(stmt);
		}
	}
	else if( m_type == MR_CHAT_GROUP )
	{
		int cnt = 0;
		q1 = sqlite3_mprintf("SELECT COUNT(*) FROM chats_contacts WHERE chat_id=%i", m_id);
		sqlite3_stmt* stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q1);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				cnt = sqlite3_column_int(stmt, 0);
			}
			sqlite3_finalize(stmt);
		}

		q2 = sqlite3_mprintf("%i members", cnt + 1 /*do not forget ourself!*/);
		ret = safe_strdup(q2);
	}
	else
	{
		q1 = sqlite3_mprintf("Chat type #%i", (int)m_type);
		ret = safe_strdup(q1);
	}

	// cleanup
	sqlite3_free(q1);
	sqlite3_free(q2);

	return ret? ret : safe_strdup("");
}


/*******************************************************************************
 * Static funcions
 ******************************************************************************/


size_t MrChat::GetChatCnt(MrMailbox* mailbox) // static function
{
	if( mailbox->m_sql.m_cobj==NULL ) {
		return 0; // no database, no chats - this is no error (needed eg. for information)
	}

	sqlite3_stmt* s = mailbox->m_sql.m_pd[SELECT_COUNT_FROM_chats];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		MrLogSqliteError(mailbox->m_sql.m_cobj);
		MrLogError("MrSqlite3::GetChatCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(s, 0); // success
}


uint32_t MrChat::ChatExists(MrMailbox* mailbox, MrChatType type, uint32_t contact_id) // static function
{
	uint32_t chat_id = 0;

	if( type == MR_CHAT_NORMAL )
	{
		char* q=sqlite3_mprintf("SELECT id FROM chats INNER JOIN chats_contacts ON id=chat_id WHERE type=%i AND contact_id=%i", type, contact_id);

		sqlite3_stmt* stmt = mailbox->m_sql.sqlite3_prepare_v2_(q);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				chat_id = sqlite3_column_int(stmt, 0);
			}
			sqlite3_finalize(stmt);
		}
		else {
			MrLogSqliteError(mailbox->m_sql.m_cobj);
			MrLogError("MrSqlite3::ChatExists() failed.");
		}

		sqlite3_free(q);
	}

	return chat_id;
}


uint32_t MrChat::CreateChatRecord(MrMailbox* mailbox, uint32_t contact_id) // static function
{
	uint32_t      chat_id = 0;
	MrContact*    contact = NULL;
	char*         chat_name;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( (chat_id=ChatExists(mailbox, MR_CHAT_NORMAL, contact_id)) != 0 ) {
		return chat_id; // soon success
	}

	// get fine chat name
	contact = new MrContact(mailbox);
	if( !contact->LoadFromDb(contact_id) ) {
		goto CreateNormalChat_Cleanup;
	}

	chat_name = (contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_email;

	// create chat record
	q = sqlite3_mprintf("INSERT INTO chats (type, name) VALUES(%i, %Q)", MR_CHAT_NORMAL, chat_name);
	stmt = mailbox->m_sql.sqlite3_prepare_v2_(q);
	if( stmt == NULL) {
		goto CreateNormalChat_Cleanup;
	}

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

    chat_id = sqlite3_last_insert_rowid(mailbox->m_sql.m_cobj);

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

    // add contact IDs to the new chat record
	q = sqlite3_mprintf("INSERT INTO chats_contacts (chat_id, contact_id) VALUES(%i, %i)", chat_id, contact_id);
	stmt = mailbox->m_sql.sqlite3_prepare_v2_(q);

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

	// add already existing messages to the chat record

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	q = sqlite3_mprintf("UPDATE msg SET chat_id=%i WHERE chat_id=0 AND from_id=%i;", chat_id, contact_id);
	stmt = mailbox->m_sql.sqlite3_prepare_v2_(q);

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

	// cleanup
CreateNormalChat_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	if( contact ) {
		delete contact;
	}
	return chat_id;
}


uint32_t MrChat::FindOutChatId(MrMailbox* mailbox, carray* contact_ids_from, carray* contact_ids_to) // static function
{
	if( carray_count(contact_ids_from)==1 ) {
		return ChatExists(mailbox, MR_CHAT_NORMAL, (uint32_t)(uintptr_t)carray_get(contact_ids_from, 0));
	}

	return 0;
}


/*******************************************************************************
 * List messages
 ******************************************************************************/


MrMsgList* MrChat::ListMsgs() // the caller must delete the result
{
	MrSqlite3Locker locker(m_mailbox->m_sql); // function is called from user-level, needs locking therefore

	bool          success = false;
	MrMsgList*    ret = NULL;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	// create return object
	if( (ret=new MrMsgList()) == NULL ) {
		goto ListMsgs_Cleanup;
	}

	// query
	q = sqlite3_mprintf("SELECT " MR_MSG_FIELDS " FROM msg m WHERE m.chat_id=%i ORDER BY m.timestamp;", m_id);
	stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q);
	if( stmt == NULL ) {
		goto ListMsgs_Cleanup;
	}

	while( sqlite3_step(stmt) == SQLITE_ROW )
	{
		MrMsg* msg = new MrMsg(m_mailbox);
		if( msg && msg->SetMsgFromStmt(stmt) ) {
			carray_add(ret->m_msgs, (void*)msg, NULL);
		}
	}

	// success
	success = true;

	// cleanup
ListMsgs_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	if( success ) {
		return ret;
	}
	else {
		delete ret;
		return NULL;
	}
}


/*******************************************************************************
 * Send Messages
 ******************************************************************************/


void MrChat::SendMsg(const char* text)
{
}


/*******************************************************************************
 * Chat lists
 ******************************************************************************/


MrChatList::MrChatList(MrMailbox* mailbox)
{
	m_mailbox = mailbox;
	m_chats = carray_new(128);
}


MrChatList::~MrChatList()
{
	Empty();
	carray_free(m_chats);
	m_chats = NULL;
}


void MrChatList::Empty()
{
	if( m_chats )
	{
		int cnt = carray_count(m_chats);
		for( int i = 0; i < cnt; i++ )
		{
			MrChat* chat = (MrChat*)carray_get(m_chats, i);
			if( chat )
			{
				delete chat;
			}
		}

		carray_set_size(m_chats, 0);
	}
}


bool MrChatList::LoadFromDb()
{
	bool          success = false;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	Empty();

	// select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min
	q = sqlite3_mprintf(MR_GET_CHATS_PREFIX MR_GET_CHATS_POSTFIX " ORDER BY timestamp;");
	stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q);
	if( stmt==NULL ) {
		goto GetChatList_Cleanup;
	}

    while( sqlite3_step(stmt) == SQLITE_ROW ) {
		MrChat* chat = new MrChat(m_mailbox);
		if( chat->SetChatFromStmt(stmt) ) {
			carray_add(m_chats, (void*)chat, NULL);
		}
    }

	// success
	success = true;

	// cleanup
GetChatList_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	return success;
}
