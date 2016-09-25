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
 * File:    mrchat.c
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
#include "mrlog.h"


mrchat_t* mrchat_new_(mrmailbox_t* mailbox)
{
	mrchat_t* ths = NULL;

	if( (ths=malloc(sizeof(mrchat_t)))==NULL ) {
		return NULL; /* error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox        = mailbox;
	ths->m_type           = MR_CHAT_UNDEFINED;
	ths->m_name           = NULL;
	ths->m_lastMsg        = NULL;
    ths->m_id             = 0;

    return ths;
}


mrchat_t* mrchat_ref_(mrchat_t* ths)
{
	MR_INC_REFERENCE
}


void mrchat_unref(mrchat_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrchat_empty_(ths);
	free(ths);
}


void mrchat_empty_(mrchat_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_name ) {
		free(ths->m_name);
		ths->m_name = NULL;
	}

	if( ths->m_lastMsg ) {
		mrmsg_unref(ths->m_lastMsg);
		ths->m_lastMsg = NULL;
	}

	ths->m_type = MR_CHAT_UNDEFINED;
	ths->m_id   = 0;
}


mrmsg_t* mrchat_get_last_msg(mrchat_t* ths)
{
	return mrmsg_ref(ths->m_lastMsg);
}


static int mrchat_set_chat_from_stmt_(mrchat_t* ths, sqlite3_stmt* row)
{
	if( ths == NULL || row == NULL ) {
		return 0; /* error */
	}

	mrchat_empty_(ths);

	int row_offset = 0;
	ths->m_id        =                    sqlite3_column_int  (row, row_offset++); /* the columns are defined in MR_CHAT_FIELDS */
	ths->m_type      =                    sqlite3_column_int  (row, row_offset++);
	ths->m_name      = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_lastMsg   = mrmsg_new(ths->m_mailbox);
	mrmsg_set_msg_from_stmt(ths->m_lastMsg, row, row_offset);

	if( ths->m_name == NULL || ths->m_lastMsg == NULL || ths->m_lastMsg->m_msg == NULL ) {
		return 0; /* error */
	}

	return 1; /* success */
}


int mrchat_load_from_db_(mrchat_t* ths, const char* name, uint32_t id)
{
	#define       MR_CHAT_FIELDS " c.id,c.type,c.name "
	#define       MR_GET_CHATS_PREFIX "SELECT " MR_CHAT_FIELDS "," MR_MSG_FIELDS " FROM chats c " \
							"LEFT JOIN msg m ON (c.id=m.chat_id AND m.timestamp=(SELECT MIN(timestamp) FROM msg WHERE chat_id=c.id)) "
	#define       MR_GET_CHATS_POSTFIX " GROUP BY c.id " /* GROUP BY is needed as there may be several messages with the same timestamp */

	int           success = 0;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ths==NULL ) {
		return 0; /* error (name may be NULL) */
	}

	mrchat_empty_(ths);

	if( name ) {
		q = sqlite3_mprintf(MR_GET_CHATS_PREFIX " WHERE c.name=%Q " MR_GET_CHATS_POSTFIX ";", name);
	}
	else {
		q = sqlite3_mprintf(MR_GET_CHATS_PREFIX " WHERE c.id=%i" MR_GET_CHATS_POSTFIX ";", id);
	}

	stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto LoadFromDb_Cleanup;
	}

	if( !mrchat_set_chat_from_stmt_(ths, stmt) ) {
		goto LoadFromDb_Cleanup;
	}

	/* success */
	success  = 1;

	/* cleanup */
LoadFromDb_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	return success;
}


char* mrchat_get_subtitle(mrchat_t* ths)
{
	/* returns either the e-mail-address or the number of chat members */
	char *q1 = NULL, *q2 = NULL;
	char* ret = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ths == NULL ) {
		return NULL; /* error */
	}

	if( ths->m_type == MR_CHAT_NORMAL || ths->m_type == MR_CHAT_PRIVATE )
	{
		q1 = sqlite3_mprintf("SELECT c.email FROM chats_contacts cc LEFT JOIN contacts c ON c.id=cc.contact_id WHERE cc.chat_id=%i", ths->m_id);
		stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q1);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				ret = safe_strdup((const char*)sqlite3_column_text(stmt, 0));
			}
			sqlite3_finalize(stmt);
		}
	}
	else if( ths->m_type == MR_CHAT_GROUP )
	{
		int cnt = 0;
		q1 = sqlite3_mprintf("SELECT COUNT(*) FROM chats_contacts WHERE chat_id=%i", ths->m_id);
		stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q1);
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
		q1 = sqlite3_mprintf("Chat type #%i", (int)ths->m_type);
		ret = safe_strdup(q1);
	}

	/* cleanup */
	sqlite3_free(q1);
	sqlite3_free(q2);

	return ret? ret : safe_strdup("");
}


/*******************************************************************************
 * Static funcions
 ******************************************************************************/


size_t mr_get_chat_cnt_(mrmailbox_t* mailbox)
{
	sqlite3_stmt* s;

	if( mailbox == NULL || mailbox->m_sql == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	s = mailbox->m_sql->m_pd[SELECT_COUNT_FROM_chats];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql);
		mr_log_error("mr_get_chat_cnt() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(s, 0); /* success */
}


uint32_t mr_chat_exists_(mrmailbox_t* mailbox, int type, uint32_t contact_id) /* static function */
{
	uint32_t chat_id = 0;

	if( mailbox == NULL || mailbox->m_sql == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	if( type == MR_CHAT_NORMAL )
	{
		char* q=sqlite3_mprintf("SELECT id FROM chats INNER JOIN chats_contacts ON id=chat_id WHERE type=%i AND contact_id=%i", type, contact_id);

		sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);
		if( stmt ) {
			int r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				chat_id = sqlite3_column_int(stmt, 0);
			}
			sqlite3_finalize(stmt);
		}
		else {
			mrsqlite3_log_error(mailbox->m_sql);
			mr_log_error("mr_chat_exists() failed.");
		}

		sqlite3_free(q);
	}

	return chat_id;
}


uint32_t mr_create_chat_record_(mrmailbox_t* mailbox, uint32_t contact_id) /* static function */
{
	uint32_t      chat_id = 0;
	mrcontact_t*  contact = NULL;
	char*         chat_name;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( mailbox == NULL || mailbox->m_sql == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	if( (chat_id=mr_chat_exists_(mailbox, MR_CHAT_NORMAL, contact_id)) != 0 ) {
		return chat_id; /* soon success */
	}

	/* get fine chat name */
	contact = mrcontact_new(mailbox);
	if( !mrcontact_load_from_db(contact, contact_id) ) {
		goto CreateNormalChat_Cleanup;
	}

	chat_name = (contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_email;

	/* create chat record */
	q = sqlite3_mprintf("INSERT INTO chats (type, name) VALUES(%i, %Q)", MR_CHAT_NORMAL, chat_name);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);
	if( stmt == NULL) {
		goto CreateNormalChat_Cleanup;
	}

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

    chat_id = sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj);

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

    /* add contact IDs to the new chat record */
	q = sqlite3_mprintf("INSERT INTO chats_contacts (chat_id, contact_id) VALUES(%i, %i)", chat_id, contact_id);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

	/* add already existing messages to the chat record */

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	q = sqlite3_mprintf("UPDATE msg SET chat_id=%i WHERE chat_id=0 AND from_id=%i;", chat_id, contact_id);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto CreateNormalChat_Cleanup;
    }

	/* cleanup */
CreateNormalChat_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	if( contact ) {
		mrcontact_unref(contact);
	}
	return chat_id;
}


uint32_t mr_find_out_chat_id_(mrmailbox_t* mailbox, carray* contact_ids_from, carray* contact_ids_to)
{
	if( carray_count(contact_ids_from)==1 ) {
		return mr_chat_exists_(mailbox, MR_CHAT_NORMAL, (uint32_t)(uintptr_t)carray_get(contact_ids_from, 0));
	}

	return 0;
}


/*******************************************************************************
 * List messages
 ******************************************************************************/


mrmsglist_t* mrchat_get_msgs_by_index(mrchat_t* ths, size_t index, size_t amount) /* the caller must unref the result */
{
	int           success = 0;
	mrmsglist_t*  ret = NULL;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ths==NULL ) {
		return NULL;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE: No return until unlock! */

			/* create return object */
			if( (ret=mrmsglist_new()) == NULL ) {
				goto ListMsgs_Cleanup;
			}

			/* query */
			q = sqlite3_mprintf("SELECT " MR_MSG_FIELDS " FROM msg m WHERE m.chat_id=%i ORDER BY m.timestamp;", ths->m_id);
			stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q);
			if( stmt == NULL ) {
				goto ListMsgs_Cleanup;
			}

			while( sqlite3_step(stmt) == SQLITE_ROW )
			{
				mrmsg_t* msg = mrmsg_new(ths->m_mailbox);
				if( msg && mrmsg_set_msg_from_stmt(msg, stmt, 0) ) {
					carray_add(ret->m_msgs, (void*)msg, NULL);
				}
			}

			/* success */
			success = 1;

			/* cleanup */
		ListMsgs_Cleanup:
			if( q ) {
				sqlite3_free(q);
			}

			if( stmt ) {
				sqlite3_finalize(stmt);
			}

	mrsqlite3_unlock(ths->m_mailbox->m_sql); /* /CAVE: No return until unlock! */

	if( success ) {
		return ret;
	}
	else {
		mrmsglist_unref(ret);
		return NULL;
	}
}


/*******************************************************************************
 * Send Messages
 ******************************************************************************/


void mrchat_send_msg(mrchat_t* ths, const char* text)
{
}


/*******************************************************************************
 * Chat lists
 ******************************************************************************/


mrchatlist_t* mrchatlist_new_(mrmailbox_t* mailbox)
{
	mrchatlist_t* ths = NULL;

	if( (ths=malloc(sizeof(mrchatlist_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_mailbox = mailbox;
	ths->m_chats = carray_new(128);

	return ths;
}


void mrchatlist_unref(mrchatlist_t* ths)
{
	if( ths==NULL ) {
		return; /* error */
	}

	mrchatlist_empty_(ths);
	carray_free(ths->m_chats);
	free(ths);
}


void mrchatlist_empty_(mrchatlist_t* ths)
{
	if( ths && ths->m_chats )
	{
		size_t i, cnt = (size_t)carray_count(ths->m_chats);
		for( i = 0; i < cnt; i++ )
		{
			mrchat_t* chat = (mrchat_t*)carray_get(ths->m_chats, i);
			mrchat_unref(chat);
		}

		carray_set_size(ths->m_chats, 0);
	}
}


size_t mrchatlist_get_cnt(mrchatlist_t* ths)
{
	return (size_t)carray_count(ths->m_chats);
}


mrchat_t* mrchatlist_get_chat(mrchatlist_t* ths, size_t index)
{
	return mrchat_ref_((mrchat_t*)carray_get(ths->m_chats, index));
}


int mrchatlist_load_from_db_(mrchatlist_t* ths)
{
	int           success = 0;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		return 0; /* error */
	}

	mrchatlist_empty_(ths);

	/* select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min */
	q = sqlite3_mprintf(MR_GET_CHATS_PREFIX MR_GET_CHATS_POSTFIX " ORDER BY timestamp;");
	stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q);
	if( stmt==NULL ) {
		goto GetChatList_Cleanup;
	}

    while( sqlite3_step(stmt) == SQLITE_ROW ) {
		mrchat_t* chat = mrchat_new_(ths->m_mailbox);
		if( mrchat_set_chat_from_stmt_(chat, stmt) ) {
			carray_add(ths->m_chats, (void*)chat, NULL);
		}
    }

	/* success */
	success = 1;

	/* cleanup */
GetChatList_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	return success;
}
