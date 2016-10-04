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
 * File:    mrchat.c
 * Authors: Björn Petersen
 * Purpose: mrchat_t represents a single chat, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrcontact.h"
#include "mrlog.h"


mrchat_t* mrchat_new(mrmailbox_t* mailbox)
{
	mrchat_t* ths = NULL;

	if( (ths=malloc(sizeof(mrchat_t)))==NULL ) {
		exit(14); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox         = mailbox;
	ths->m_type            = MR_CHAT_UNDEFINED;
	ths->m_name            = NULL;
	ths->m_last_msg_       = NULL;
	ths->m_draft_timestamp = 0;
	ths->m_draft_text      = NULL;
	ths->m_id              = 0;

    return ths;
}


mrchat_t* mrchat_ref(mrchat_t* ths)
{
	MR_INC_REFERENCE
}


void mrchat_unref(mrchat_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrchat_empty(ths);
	free(ths);
}


void mrchat_empty(mrchat_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	free(ths->m_name);
	ths->m_name = NULL;

	mrmsg_unref(ths->m_last_msg_);
	ths->m_last_msg_ = NULL;

	ths->m_draft_timestamp = 0;

	free(ths->m_draft_text);
	ths->m_draft_text = NULL;

	ths->m_type = MR_CHAT_UNDEFINED;
	ths->m_id   = 0;
}


int mrchat_set_from_stmt_(mrchat_t* ths, sqlite3_stmt* row)
{
	int row_offset = 0;
	const char* draft_text;

	if( ths == NULL || row == NULL ) {
		return 0; /* error */
	}

	mrchat_empty(ths);

	ths->m_id              =                    sqlite3_column_int  (row, row_offset++); /* the columns are defined in MR_CHAT_FIELDS */
	ths->m_type            =                    sqlite3_column_int  (row, row_offset++);
	ths->m_name            = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_draft_timestamp =                    sqlite3_column_int  (row, row_offset++);
	draft_text             =       (const char*)sqlite3_column_text (row, row_offset++);

	/* We leave a NULL-pointer for the very usual situation of "no draft".
	Also make sure, m_draft_text and m_draft_timestamp are set together */
	if( ths->m_draft_timestamp && draft_text && draft_text[0] ) {
		ths->m_draft_text = safe_strdup(draft_text);
	}
	else {
		ths->m_draft_timestamp = 0;
	}

	return row_offset; /* success, return the next row offset */
}


int mrchat_load_from_db_(mrchat_t* ths, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL ) {
		return 0; /* error (name may be NULL) */
	}

	mrchat_empty(ths);

	stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_itn_FROM_chats_i,
		"SELECT " MR_CHAT_FIELDS " FROM chats c WHERE c.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0; /* error */
	}

	if( !mrchat_set_from_stmt_(ths, stmt) ) {
		return 0; /* error */
	}

	/* success */
	return 1;
}


char* mrchat_get_subtitle(mrchat_t* ths)
{
	/* returns either the e-mail-address or the number of chat members */
	char* ret = NULL;
	sqlite3_stmt* stmt;

	if( ths == NULL ) {
		return safe_strdup("Err"); /* error */
	}

	if( ths->m_type == MR_CHAT_NORMAL || ths->m_type == MR_CHAT_ENCRYPTED )
	{
		int r;
		stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_e_FROM_chats_contacts_WHERE_i,
			"SELECT c.email FROM chats_contacts cc "
				" LEFT JOIN contacts c ON c.id=cc.contact_id "
				" WHERE cc.chat_id=?;");
		sqlite3_bind_int(stmt, 1, ths->m_id);

		r = sqlite3_step(stmt);
		if( r == SQLITE_ROW ) {
			ret = safe_strdup((const char*)sqlite3_column_text(stmt, 0));
		}
	}
	else if( ths->m_type == MR_CHAT_GROUP )
	{
		int r, cnt = 0;
		stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_COUNT_FROM_chats_contacts_WHERE_i,
			"SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;");
		sqlite3_bind_int(stmt, 1, ths->m_id);

		r = sqlite3_step(stmt);
		if( r == SQLITE_ROW ) {
			cnt = sqlite3_column_int(stmt, 0);
		}

		ret = mr_mprintf("%i members", cnt + 1 /*do not forget ourself!*/);
	}

	return ret? ret : safe_strdup("Err");
}


int mrchat_get_unread_count(mrchat_t* ths)
{
	if( ths == NULL ) {
		return 0; /* error */
	}

	return 1; /* TODO */
}


mrpoortext_t* mrchat_get_summary(mrchat_t* ths)
{
	/* The summary is created by the chat, not by the last message.
	This is because we may want to display drafts here or stuff as
	"is typing".
	Also, sth. as "No messages" would not work if the summary comes from a
	message. */

	mrpoortext_t* ret = mrpoortext_new();
	if( ret == NULL ) {
		return NULL;
	}

	if( ths == NULL ) {
		ret->m_text = safe_strdup("ErrNoChat"); /* should not happen */
		return ret;
	}

	#define SUMMARY_BYTES (160*5) /* 160 characters may take up 5 bytes each */

	if( ths->m_draft_timestamp
	 && ths->m_draft_text
	 && (ths->m_last_msg_ == NULL || ths->m_draft_timestamp>ths->m_last_msg_->m_timestamp) )
	{
		/* show the draft as the last message */
		ret->m_title = safe_strdup(mrstock_str(MR_STR_DRAFT));
		ret->m_title_meaning = MR_TITLE_DRAFT;

		ret->m_text = safe_strdup(ths->m_draft_text);
		mr_unwrap_str(ret->m_text, SUMMARY_BYTES);

		ret->m_timestamp = ths->m_draft_timestamp;
	}
	else if( ths->m_last_msg_ == NULL )
	{
		/* no messages */
		ret->m_text = safe_strdup(mrstock_str(MR_STR_NO_MESSAGES));
	}
	else
	{
		/* show the last message */
		if( ths->m_last_msg_->m_from_id == 0 ) {
			ret->m_title = safe_strdup(mrstock_str(MR_STR_YOU));
			ret->m_title_meaning = MR_TITLE_USERNAME;
		}
		else {
			mrcontact_t* contact = mrcontact_new(ths->m_mailbox);
			mrcontact_load_from_db_(contact, ths->m_last_msg_->m_from_id);
			if( contact->m_name ) {
				ret->m_title = safe_strdup(contact->m_name);
				ret->m_title_meaning = MR_TITLE_USERNAME;
				mrcontact_unref(contact);
			}
			else {
				ret->m_title = safe_strdup("Unknown contact");
				ret->m_title_meaning = MR_TITLE_USERNAME;
			}
		}

		if( ths->m_last_msg_->m_msg ) {
			ret->m_text = safe_strdup(ths->m_last_msg_->m_msg);
			mr_unwrap_str(ret->m_text, SUMMARY_BYTES);
		}

		ret->m_timestamp = ths->m_last_msg_->m_timestamp;
		ret->m_state     = ths->m_last_msg_->m_state;
	}

	return ret;
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

	if( (s=mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_chats, "SELECT COUNT(*) FROM chats;"))==NULL ) {
		return 0;
	}

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
		mr_log_error("mr_create_chat_record_(): Database not opened.");
		return 0; /* database not opened - error */
	}

	if( contact_id == 0 ) {
		mr_log_error("mr_create_chat_record_(): Contact missing.");
		return 0; /* error */
	}

	if( (chat_id=mr_chat_exists_(mailbox, MR_CHAT_NORMAL, contact_id)) != 0 ) {
		return chat_id; /* soon success */
	}

	/* get fine chat name */
	contact = mrcontact_new(mailbox);
	if( !mrcontact_load_from_db_(contact, contact_id) ) {
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


mrmsglist_t* mrchat_get_msglist(mrchat_t* ths, size_t offset, size_t amount) /* the caller must unref the result */
{
	int           success = 0;
	mrmsglist_t*  ret = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ths==NULL ) {
		return NULL;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE: No return until unlock! */

			/* create return object */
			if( (ret=mrmsglist_new(ths)) == NULL ) {
				goto ListMsgs_Cleanup;
			}

			/* query */
			stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_ifttsm_FROM_msg_i,
				"SELECT " MR_MSG_FIELDS " FROM msg m WHERE m.chat_id=? ORDER BY m.timestamp,m.id LIMIT ? OFFSET ?;");
			if( stmt == NULL ) {
				goto ListMsgs_Cleanup;
			}
			sqlite3_bind_int(stmt, 1, ths->m_id);
			sqlite3_bind_int(stmt, 2, amount);
			sqlite3_bind_int(stmt, 3, offset);

			while( sqlite3_step(stmt) == SQLITE_ROW )
			{
				mrmsg_t* msg = mrmsg_new(ths->m_mailbox);
				mrmsg_set_from_stmt_(msg, stmt, 0);

				carray_add(ret->m_msgs, (void*)msg, NULL);
			}

			/* success */
			success = 1;

			/* cleanup */
		ListMsgs_Cleanup:

			/* (nothing to cleanup at the moment) */

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
 * Handle drafts
 ******************************************************************************/


int mrchat_save_draft(mrchat_t* ths, const char* msg)
{
	sqlite3_stmt* stmt;

	if( ths == NULL ) {
		return 0; /* error */
	}

	if( msg && msg[0]==0 ) {
		msg = NULL; /*an empty draft is no draft*/
	}

	/* save draft in object - NULL or empty: clear draft */
	free(ths->m_draft_text);
	ths->m_draft_text      = msg? safe_strdup(msg) : NULL;
	ths->m_draft_timestamp = msg? time(NULL) : 0;

	/* save draft in database */
	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE: No return until unlock! */

		stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, UPDATE_chats_dd,
			"UPDATE chats SET draft_timestamp=?, draft_txt=? WHERE id=?;");
		sqlite3_bind_int (stmt, 1, ths->m_draft_timestamp);
		sqlite3_bind_text(stmt, 2, ths->m_draft_text? ths->m_draft_text : "", -1, SQLITE_STATIC); /* SQLITE_STATIC: we promise the buffer to be valid until the query is done */
		sqlite3_bind_int (stmt, 3, ths->m_id);

		sqlite3_step(stmt);

	mrsqlite3_unlock(ths->m_mailbox->m_sql); /* /CAVE: No return until unlock! */

	/* success */
	return 1;
}


/*******************************************************************************
 * Send Messages
 ******************************************************************************/


int mrchat_send_msg(mrchat_t* ths, const mrmsg_t* msg)
{
	return 0; /* not yet implemented */
}


