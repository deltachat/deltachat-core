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
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrcontact.h"
#include "mrlog.h"
#include "mrjob.h"
#include "mrsmtp.h"
#include "mrimap.h"

#define CLASS_MAGIC 1279756140


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrmailbox_get_unseen_count__(mrmailbox_t* mailbox, uint32_t chat_id)
{
	sqlite3_stmt* stmt = NULL;

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_state_AND_chat_id,
		"SELECT COUNT(*) FROM msgs WHERE state=? AND chat_id=?;"); /* we have an index over the state-column, this should be sufficient as there are typically only few unseen messages */
	sqlite3_bind_int(stmt, 1, MR_IN_UNSEEN);
	sqlite3_bind_int(stmt, 2, chat_id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


int mrmailbox_get_total_msg_count__(mrmailbox_t* mailbox, uint32_t chat_id)
{
	sqlite3_stmt* stmt = NULL;

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_chat_id,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_total_msg_count_() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


size_t mrmailbox_get_chat_cnt__(mrmailbox_t* mailbox)
{
	sqlite3_stmt* stmt;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_chats, "SELECT COUNT(*) FROM chats WHERE id>?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_chat_cnt() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


uint32_t mrmailbox_real_chat_exists__(mrmailbox_t* mailbox, int type, uint32_t contact_id) /* checks for "real" chats (non-trash, non-unknown) */
{
	sqlite3_stmt* stmt;
	uint32_t chat_id = 0;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	if( type == MR_CHAT_NORMAL )
	{
		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_chats_WHERE_contact_id,
				"SELECT c.id"
				" FROM chats c"
				" INNER JOIN chats_contacts j ON c.id=j.chat_id"
				" WHERE c.type=? AND c.id>? AND j.contact_id=?;");
		sqlite3_bind_int(stmt, 1, type);
		sqlite3_bind_int(stmt, 2, MR_CHAT_ID_LAST_SPECIAL);
		sqlite3_bind_int(stmt, 3, contact_id);

		if( sqlite3_step(stmt) == SQLITE_ROW ) {
			chat_id = sqlite3_column_int(stmt, 0);
		}
	}

	return chat_id;
}


uint32_t mrmailbox_create_or_lookup_chat_record__(mrmailbox_t* mailbox, uint32_t contact_id)
{
	uint32_t      chat_id = 0;
	mrcontact_t*  contact = NULL;
	char*         chat_name;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* database not opened - error */
	}

	if( contact_id == 0 ) {
		return 0;
	}

	if( (chat_id=mrmailbox_real_chat_exists__(mailbox, MR_CHAT_NORMAL, contact_id)) != 0 ) {
		return chat_id; /* soon success */
	}

	/* get fine chat name */
	contact = mrcontact_new(mailbox);
	if( !mrcontact_load_from_db__(contact, mailbox->m_sql, contact_id) ) {
		goto cleanup;
	}

	chat_name = (contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_addr;

	/* create chat record */
	q = sqlite3_mprintf("INSERT INTO chats (type, name) VALUES(%i, %Q)", MR_CHAT_NORMAL, chat_name);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);
	if( stmt == NULL) {
		goto cleanup;
	}

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
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
		goto cleanup;
    }

	/* add already existing messages to the chat record */

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	q = sqlite3_mprintf("UPDATE msgs SET chat_id=%i WHERE (chat_id=%i AND from_id=%i) OR (chat_id=%i AND to_id=%i);",
		chat_id,
		MR_CHAT_ID_DEADDROP, contact_id,
		MR_CHAT_ID_TO_DEADDROP, contact_id);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
    }

	/* cleanup */
cleanup:
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


int mrchat_set_from_stmt__(mrchat_t* ths, sqlite3_stmt* row)
{
	int row_offset = 0;
	const char* draft_text;

	if( ths == NULL || row == NULL ) {
		return 0;
	}

	mrchat_empty(ths);

	ths->m_id              =                    sqlite3_column_int  (row, row_offset++); /* the columns are defined in MR_CHAT_FIELDS */
	ths->m_type            =                    sqlite3_column_int  (row, row_offset++);
	ths->m_name            = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_draft_timestamp =                    sqlite3_column_int64(row, row_offset++);
	draft_text             =       (const char*)sqlite3_column_text (row, row_offset++);

	/* We leave a NULL-pointer for the very usual situation of "no draft".
	Also make sure, m_draft_text and m_draft_timestamp are set together */
	if( ths->m_draft_timestamp && draft_text && draft_text[0] ) {
		ths->m_draft_text = safe_strdup(draft_text);
	}
	else {
		ths->m_draft_timestamp = 0;
	}

	/* correct the title of some special groups */
	if( ths->m_id == MR_CHAT_ID_DEADDROP ) {
		free(ths->m_name);
		ths->m_name = mrstock_str(MR_STR_DEADDROP);
	}

	return row_offset; /* success, return the next row offset */
}


int mrchat_load_from_db__(mrchat_t* ths, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL ) {
		return 0;
	}

	mrchat_empty(ths);

	stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_itndd_FROM_chats_WHERE_i,
		"SELECT " MR_CHAT_FIELDS " FROM chats c WHERE c.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	if( !mrchat_set_from_stmt__(ths, stmt) ) {
		return 0;
	}

	return 1;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrchatlist_t* mrmailbox_get_chatlist(mrmailbox_t* ths)
{
	int success = 0;
	int db_locked = 0;
	mrchatlist_t* obj = mrchatlist_new(ths);

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

	if( !mrchatlist_load_from_db__(obj) ) {
		goto cleanup;
	}

	/* success */
	mrjob_ping__(ths);

	success = 1;

	/* cleanup */
cleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( success ) {
		return obj;
	}
	else {
		mrchatlist_unref(obj);
		return NULL;
	}
}


mrchat_t* mrmailbox_get_chat(mrmailbox_t* ths, uint32_t id)
{
	int success = 0;
	int db_locked = 0;
	mrchat_t* obj = mrchat_new(ths);

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

	if( !mrchat_load_from_db__(obj, id) ) {
		goto cleanup;
	}

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( success ) {
		return obj;
	}
	else {
		mrchat_unref(obj);
		return NULL;
	}
}


int mrmailbox_markseen_chat(mrmailbox_t* ths, uint32_t chat_id)
{
	sqlite3_stmt* stmt;
	uint32_t      msg_id;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	mrsqlite3_begin_transaction__(ths->m_sql);

		stmt = mrsqlite3_predefine__(ths->m_sql, SELECT_id_FROM_msgs_WHERE_chat_id_AND_state,
			"SELECT id FROM msgs WHERE chat_id=? AND state=?;");
		sqlite3_bind_int(stmt, 1, chat_id);
		sqlite3_bind_int(stmt, 2, MR_IN_UNSEEN);
		while( sqlite3_step(stmt) == SQLITE_ROW )
		{
			msg_id = sqlite3_column_int(stmt, 0);
			mrmailbox_update_msg_state__(ths, msg_id, MR_IN_SEEN);
			mrjob_add__(ths, MRJ_MARKSEEN_MSG_ON_IMAP, msg_id, NULL);
		}

	mrsqlite3_commit__(ths->m_sql);
	mrsqlite3_unlock(ths->m_sql);

	return 1;
}


uint32_t mrmailbox_get_chat_id_by_contact_id(mrmailbox_t* mailbox, uint32_t contact_id)
{
	uint32_t chat_id = 0;

	mrsqlite3_lock(mailbox->m_sql);

		chat_id = mrmailbox_real_chat_exists__(mailbox, MR_CHAT_NORMAL, contact_id);

	mrsqlite3_unlock(mailbox->m_sql);

	return chat_id;
}


uint32_t mrmailbox_create_chat_by_contact_id(mrmailbox_t* ths, uint32_t contact_id)
{
	uint32_t      chat_id = 0;
	int           send_event = 0, locked = 0;
	sqlite3_stmt* stmt;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	locked = 1;

		chat_id = mrmailbox_real_chat_exists__(ths, MR_CHAT_NORMAL, contact_id);
		if( chat_id ) {
			mrlog_warning("Chat with contact %i already exists.", (int)contact_id);
			goto cleanup;
		}

        if( 0==mrmailbox_real_contact_exists__(ths, contact_id) ) {
			mrlog_error("Cannot create chat, contact %i does not exist.", (int)contact_id);
			goto cleanup;
        }

		chat_id = mrmailbox_create_or_lookup_chat_record__(ths, contact_id);
		if( chat_id ) {
			send_event = 1;
		}

		stmt = mrsqlite3_predefine__(ths->m_sql, UPDATE_contacts_SET_origin_WHERE_id, "UPDATE contacts SET origin=? WHERE id=?;");
		sqlite3_bind_int(stmt, 1, MR_ORIGIN_CREATE_CHAT);
		sqlite3_bind_int(stmt, 2, contact_id);
		sqlite3_step(stmt);

	mrsqlite3_unlock(ths->m_sql);
	locked = 0;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( send_event ) {
		ths->m_cb(ths, MR_EVENT_MSGS_UPDATED, 0, 0);
	}

	return chat_id;
}


int mrmailbox_delete_chat(mrmailbox_t* mailbox, uint32_t chat_id)
{
	int       success = 0, send_event = 0, locked = 0, pending_transaction = 0;
	mrchat_t* obj = mrchat_new(mailbox);
	char*     q3 = NULL;

	if( mailbox == NULL || chat_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

        if( !mrchat_load_from_db__(obj, chat_id) ) {
			goto cleanup;
        }

        if( obj->m_type == MR_CHAT_NORMAL )
        {
			/* delete a single-user-chat; all messages go to the deaddrop chat */
			mrsqlite3_begin_transaction__(mailbox->m_sql);
			pending_transaction = 1;

			q3 = sqlite3_mprintf("UPDATE msgs SET chat_id=%i WHERE chat_id=%i AND from_id=1;", MR_CHAT_ID_TO_DEADDROP, chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}

			sqlite3_free(q3);
			q3 = sqlite3_mprintf("UPDATE msgs SET chat_id=%i WHERE chat_id=%i AND from_id!=1;", MR_CHAT_ID_DEADDROP, chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}

			sqlite3_free(q3);
			q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i;", chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}

			sqlite3_free(q3);
			q3 = sqlite3_mprintf("DELETE FROM chats WHERE id=%i;", chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}
        }
        else
        {
			/* cannot delete chats of other types, for now.
			If we do, we should think over, how and if they can be restored - to_id as used to restore single-user-chats is not sufficient.
			Maybe it is okay (and maybe even expected) that messages from deleted chats do not show up again if a chat is re-created. */
			goto cleanup;
        }

        if( pending_transaction ) {
			mrsqlite3_commit__(mailbox->m_sql);
			pending_transaction = 0;
        }

        send_event = 1;

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	success = 1;

cleanup:
	if( pending_transaction ) {
		mrsqlite3_rollback__(mailbox->m_sql);
	}
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	if( send_event ) {
		mailbox->m_cb(mailbox, MR_EVENT_MSGS_UPDATED, 0, 0);
	}
	mrchat_unref(obj);
	sqlite3_free(q3);
	return success;
}


carray* mrmailbox_get_chat_media(mrmailbox_t* mailbox, uint32_t chat_id, int msg_type, int or_msg_type)
{
	carray*       ret = carray_new(100);
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_WHERE_ctt,
			"SELECT id FROM msgs WHERE chat_id=? AND (type=? OR type=?) ORDER BY timestamp, id;");
		sqlite3_bind_int(stmt, 1, chat_id);
		sqlite3_bind_int(stmt, 2, msg_type);
		sqlite3_bind_int(stmt, 3, or_msg_type>0? or_msg_type : msg_type);
		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

	mrsqlite3_unlock(mailbox->m_sql);

cleanup:
	return ret;
}


carray* mrmailbox_get_chat_contacts(mrmailbox_t* mailbox, uint32_t chat_id)
{
	carray*       ret = carray_new(100);
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);

		if( chat_id == MR_CHAT_ID_DEADDROP )
		{
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_contacts_WHERE_chat_id,
				"SELECT DISTINCT from_id FROM msgs WHERE chat_id=? and from_id!=0 ORDER BY id DESC;"); /* from_id in the deaddrop chat may be 0, see comment [**] */
			sqlite3_bind_int(stmt, 1, chat_id);
		}
		else
		{
			#define GET_CHATS_CONTACTS "SELECT contact_id FROM chats_contacts WHERE chat_id=?;"
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_c_FROM_chats_contacts_WHERE_c, GET_CHATS_CONTACTS);
			sqlite3_bind_int(stmt, 1, chat_id);
		}

		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

	mrsqlite3_unlock(mailbox->m_sql);

cleanup:
	return ret;
}


mrchat_t* mrchat_new(mrmailbox_t* mailbox)
{
	mrchat_t* ths = NULL;

	if( mailbox == NULL || (ths=calloc(1, sizeof(mrchat_t)))==NULL ) {
		exit(14); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox         = mailbox;
	ths->m_type            = MR_CHAT_UNDEFINED;

    return ths;
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
		return;
	}

	free(ths->m_name);
	ths->m_name = NULL;

	ths->m_draft_timestamp = 0;

	free(ths->m_draft_text);
	ths->m_draft_text = NULL;

	ths->m_type = MR_CHAT_UNDEFINED;
	ths->m_id   = 0;
}


carray* mrmailbox_get_chat_msgs(mrmailbox_t* mailbox, uint32_t chat_id)
{
	int           success = 0, locked = 0;
	carray*       ret = carray_new(512);
	sqlite3_stmt* stmt = NULL;

	if( mailbox==NULL || ret == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_LEFT_JOIN_contacts_WHERE_c,
			"SELECT m.id"
				" FROM msgs m"
				" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.chat_id=? AND ct.blocked=0"
				" ORDER BY m.timestamp DESC,m.id DESC;"); /* the list starts with the newest messages*/
		sqlite3_bind_int(stmt, 1, chat_id);

		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

		/* success */
		mrjob_ping__(mailbox);

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	success = 1;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}

	if( success ) {
		return ret;
	}
	else {
		if( ret ) {
			carray_free(ret);
		}
		return NULL;
	}
}


int mrchat_set_draft(mrchat_t* ths, const char* msg)
{
	sqlite3_stmt* stmt;

	if( ths == NULL ) {
		return 0;
	}

	if( msg && msg[0]==0 ) {
		msg = NULL; /* an empty draft is no draft */
	}

	if( ths->m_draft_text==NULL && msg==NULL
	 && ths->m_draft_timestamp==0 ) {
		return 1; /* nothing to do - there is no old and no new draft */
	}

	if( ths->m_draft_timestamp && ths->m_draft_text && msg && strcmp(ths->m_draft_text, msg)==0 ) {
		return 1; /* for equal texts, we do not update the timestamp */
	}

	/* save draft in object - NULL or empty: clear draft */
	free(ths->m_draft_text);
	ths->m_draft_text      = msg? safe_strdup(msg) : NULL;
	ths->m_draft_timestamp = msg? time(NULL) : 0;

	/* save draft in database */
	mrsqlite3_lock(ths->m_mailbox->m_sql);

		stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, UPDATE_chats_SET_draft_WHERE_id,
			"UPDATE chats SET draft_timestamp=?, draft_txt=? WHERE id=?;");
		sqlite3_bind_int64(stmt, 1, ths->m_draft_timestamp);
		sqlite3_bind_text (stmt, 2, ths->m_draft_text? ths->m_draft_text : "", -1, SQLITE_STATIC); /* SQLITE_STATIC: we promise the buffer to be valid until the query is done */
		sqlite3_bind_int  (stmt, 3, ths->m_id);

		sqlite3_step(stmt);

	mrsqlite3_unlock(ths->m_mailbox->m_sql);

	ths->m_mailbox->m_cb(ths->m_mailbox, MR_EVENT_MSGS_UPDATED, 0, 0);

	return 1;
}


char* mrchat_get_subtitle(mrchat_t* ths)
{
	/* returns either the address or the number of chat members */
	char* ret = NULL;
	sqlite3_stmt* stmt;

	if( ths == NULL ) {
		return safe_strdup("Err");
	}

	if( ths->m_type == MR_CHAT_NORMAL )
	{
		int r;
		mrsqlite3_lock(ths->m_mailbox->m_sql);

			stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_a_FROM_chats_contacts_WHERE_i,
				"SELECT c.addr FROM chats_contacts cc "
					" LEFT JOIN contacts c ON c.id=cc.contact_id "
					" WHERE cc.chat_id=?;");
			sqlite3_bind_int(stmt, 1, ths->m_id);

			r = sqlite3_step(stmt);
			if( r == SQLITE_ROW ) {
				ret = safe_strdup((const char*)sqlite3_column_text(stmt, 0));
			}

		mrsqlite3_unlock(ths->m_mailbox->m_sql);
	}
	else if( ths->m_type == MR_CHAT_GROUP )
	{
		int cnt = 0;
		if( ths->m_id == MR_CHAT_ID_DEADDROP )
		{
			mrsqlite3_lock(ths->m_mailbox->m_sql);

				stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_COUNT_DISTINCT_f_FROM_msgs_WHERE_c,
					"SELECT COUNT(DISTINCT from_id) FROM msgs WHERE chat_id=?;");
				sqlite3_bind_int(stmt, 1, ths->m_id);
				if( sqlite3_step(stmt) == SQLITE_ROW ) {
					cnt = sqlite3_column_int(stmt, 0);
					ret = mrstock_str_pl(MR_STR_CONTACT, cnt);
				}

			mrsqlite3_unlock(ths->m_mailbox->m_sql);
		}
		else
		{
			mrsqlite3_lock(ths->m_mailbox->m_sql);

				stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_COUNT_FROM_chats_contacts_WHERE_chat_id,
					"SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;");
				sqlite3_bind_int(stmt, 1, ths->m_id);
				if( sqlite3_step(stmt) == SQLITE_ROW ) {
					cnt = sqlite3_column_int(stmt, 0);
					ret = mrstock_str_pl(MR_STR_MEMBER, cnt + 1 /*do not forget ourself!*/);
				}

			mrsqlite3_unlock(ths->m_mailbox->m_sql);
		}
	}

	return ret? ret : safe_strdup("Err");
}


int mrchat_get_total_msg_count(mrchat_t* ths)
{
	int ret;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql);
		ret = mrmailbox_get_total_msg_count__(ths->m_mailbox, ths->m_id);
	mrsqlite3_unlock(ths->m_mailbox->m_sql);

	return ret;
}


int mrchat_get_unseen_count(mrchat_t* ths)
{
	int ret;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql);
		ret = mrmailbox_get_unseen_count__(ths->m_mailbox, ths->m_id);
	mrsqlite3_unlock(ths->m_mailbox->m_sql);

	return ret;
}


/*******************************************************************************
 * Create IMF from mrmsg_t
 ******************************************************************************/


static struct mailmime* build_body_text(char* text)
{
	struct mailmime_fields*    mime_fields;
	struct mailmime*           message_part;
	struct mailmime_content*   content;

	content = mailmime_content_new_with_str("text/plain");
	clist_append(content->ct_parameters, mailmime_param_new_with_data("charset", "utf-8")); /* format=flowed currently does not really affect us, see https://www.ietf.org/rfc/rfc3676.txt */

	mime_fields = mailmime_fields_new_encoding(MAILMIME_MECHANISM_8BIT);

	message_part = mailmime_new_empty(content, mime_fields);
	mailmime_set_body_text(message_part, text, strlen(text));

	return message_part;
}


static struct mailmime* build_body_file(const mrmsg_t* msg)
{
	struct mailmime_fields*  mime_fields;
	struct mailmime*         mime_sub = NULL;
	struct mailmime_content* content;

	char* filename = mrparam_get(msg->m_param, 'f', NULL);
	char* mimetype = mrparam_get(msg->m_param, 'm', NULL);
	char* original_filename = NULL; /* do not send the original path together with the attachment; this is a potential security/privacy risk */

	if( filename == NULL ) {
		goto cleanup;
	}

	{
		const char* p = strrchr(filename, '.');
		if( p ) {
			p++;
			original_filename = mr_mprintf("file.%s", p);
			if( mimetype == NULL ) {
				if( strcasecmp(p, "png")==0 ) {
					mimetype = safe_strdup("image/png");
				}
				else if( strcasecmp(p, "jpg")==0 || strcasecmp(p, "jpeg")==0 || strcasecmp(p, "jpe")==0 ) {
					mimetype = safe_strdup("image/jpeg");
				}
				else if( strcasecmp(p, "gif")==0 ) {
					mimetype = safe_strdup("image/gif");
				}
			}
		}
		else {
			original_filename = safe_strdup("file.dat");
		}
	}

	if( mimetype == NULL ) {
		goto cleanup;
	}

	mime_fields = mailmime_fields_new_filename(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
		safe_strdup(original_filename), MAILMIME_MECHANISM_BASE64);

	content = mailmime_content_new_with_str(mimetype);

	mime_sub = mailmime_new_empty(content, mime_fields);

	mailmime_set_body_file(mime_sub, safe_strdup(filename));

cleanup:
	free(filename);
	free(mimetype);
	free(original_filename);
	return mime_sub;
}


static char* get_subject(const mrmsg_t* msg)
{
	char *ret, *raw_subject = mrmsg_get_summary(msg->m_type, msg->m_text, APPROX_SUBJECT_CHARS);

	ret = mr_mprintf(MR_CHAT_PREFIX " %s", raw_subject);

	free(raw_subject);
	return ret;
}


static MMAPString* create_mime_msg(const mrmsg_t* msg, const char* from_addr, const char* from_displayname, const clist* recipients)
{
	struct mailimf_fields*       imf_fields;
	struct mailmime*             message = NULL;
	char*                        message_text = NULL;
	int                          col = 0;
	MMAPString*                  ret = NULL;
	int                          parts = 0;

	/* create empty mail */
	{
		struct mailimf_mailbox_list* from = mailimf_mailbox_list_new_empty();
		mailimf_mailbox_list_add(from, mailimf_mailbox_new(from_displayname? mr_encode_header_string(from_displayname) : NULL, safe_strdup(from_addr)));

		struct mailimf_address_list* to = NULL;
		if( recipients && clist_count(recipients)>0 ) {
			clistiter* iter;
			to = mailimf_address_list_new_empty();
			for( iter=clist_begin(recipients); iter!=NULL; iter=clist_next(iter)) {
				const char* rcpt = clist_content(iter);
				mailimf_address_list_add(to, mailimf_address_new(MAILIMF_ADDRESS_MAILBOX, mailimf_mailbox_new(NULL, strdup(rcpt)), NULL));
			}
		}

		char* subject = get_subject(msg);
		imf_fields = mailimf_fields_new_with_data(from,
			NULL /* sender */, NULL /* reply-to */,
			to, NULL /* cc */, NULL /* bcc */, NULL /* in-reply-to */,
			NULL /* references */,
			mr_encode_header_string(subject));
		/* mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-Mailer"), strdup("Messenger Backend"))); */
		free(subject);
	}

	message = mailmime_new_message_data(NULL);
	mailmime_set_imf_fields(message, imf_fields);

	/* add text part - we even add empty text and force a MIME-message as:
	- some Apps have problems with Non-text in the main part (eg. "Mail" from stock Android)
	- it looks better */
	{
		char* footer = mrstock_str(MR_STR_STATUSLINE);
		message_text = mr_mprintf("%s%s%s%s",
			msg->m_text? msg->m_text : "",
			(msg->m_text&&msg->m_text[0]&&footer&&footer[0])? "\n\n" : "",
			(footer&&footer[0])? "-- \n"  : "",
			(footer&&footer[0])? footer       : "");
		free(footer);
		struct mailmime* text_part = build_body_text(message_text);
		mailmime_smart_add_part(message, text_part);
		parts++;
	}

	/* add attachment part */
	if( msg->m_type == MR_MSG_AUDIO || msg->m_type == MR_MSG_VIDEO || msg->m_type == MR_MSG_IMAGE || msg->m_type == MR_MSG_FILE ) {
		struct mailmime* file_part = build_body_file(msg);
		if( file_part ) {
			mailmime_smart_add_part(message, file_part);
			parts++;
		}
	}

	if( parts == 0 ) {
		goto cleanup;
	}

	/* correct the Message-ID (libEtPan creates one himself, however, we cannot use this as smtp and imap are independent from each other and we may want to add an group identifier to the Message-ID) */
	{
		int found_and_set = 0;
		clistiter* cur1;
		for( cur1 = clist_begin(imf_fields->fld_list); cur1!=NULL ; cur1=clist_next(cur1) ) {
			struct mailimf_field* field = (struct mailimf_field*)clist_content(cur1);
			if( field && field->fld_type == MAILIMF_FIELD_MESSAGE_ID ) {
				free(field->fld_data.fld_message_id->mid_value);
				field->fld_data.fld_message_id->mid_value = safe_strdup(msg->m_rfc724_mid);
				found_and_set = 1;
				break;
			}
		}
		if( !found_and_set ) {
			mailimf_fields_add(imf_fields, mailimf_field_new(MAILIMF_FIELD_MESSAGE_ID, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, mailimf_message_id_new(strdup("my@foobar-1")), NULL, NULL, NULL, NULL, NULL, NULL));
		}
	}

	/* create the full mail and return */
	ret = mmap_string_new("");
	mailmime_write_mem(ret, &col, message); /* implementation inspired by libetpan/tests/compose-msg.c */
	//printf("%s\n", ret->str);

cleanup:
	if( message ) {
		mailmime_free(message);
	}
	free(message_text); /* mailmime_set_body_text() does not take ownership of "text" */
	return ret;
}


/*******************************************************************************
 * Sending messages
 ******************************************************************************/


static void load_data_to_send(mrmailbox_t* mailbox, uint32_t msg_id,
                              mrmsg_t* ret_msg, char** ret_from, char** ret_displayname, clist* ret_recipients)
{
	mrsqlite3_lock(mailbox->m_sql);
		if( mrmsg_load_from_db__(ret_msg, mailbox->m_sql, msg_id) ) {
			sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_addr_FROM_contacts_WHERE_chat_id,
				"SELECT c.addr FROM chats_contacts cc LEFT JOIN contacts c ON cc.contact_id=c.id WHERE cc.chat_id=?;");
			sqlite3_bind_int(stmt, 1, ret_msg->m_chat_id);
			while( sqlite3_step(stmt) == SQLITE_ROW ) {
				const char* rcpt = (const char*)sqlite3_column_text(stmt, 0);
				clist_append(ret_recipients, (void*)safe_strdup(rcpt));
			}
			*ret_from        = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
			*ret_displayname = mrsqlite3_get_config__(mailbox->m_sql, "displayname", NULL);
		}
	mrsqlite3_unlock(mailbox->m_sql);
}


void mrmailbox_send_msg_to_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrmsg_t*      msg = mrmsg_new();
	clist*	      recipients = clist_new();
	MMAPString*   data = NULL;
	char*         from_addr = NULL;
	char*         from_displayname = NULL;
	char*         server_folder = NULL;
	uint32_t      server_uid = 0;

	/* connect to IMAP-server */
	if( !mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job);
			goto cleanup;
		}
	}

	/* create message */
	load_data_to_send(mailbox, job->m_foreign_id, msg, &from_addr, &from_displayname, recipients);
	if( from_addr == NULL || clist_count(recipients) == 0 ) {
		goto cleanup; /* should not happen as we've send the message to the SMTP server before */
	}

	data = create_mime_msg(msg, from_addr, from_displayname, recipients);
	if( data == NULL ) {
		goto cleanup; /* should not happen as we've send the message to the SMTP server before */
	}

	if( !mrimap_append_msg(mailbox->m_imap, msg->m_timestamp, data->str, data->len, &server_folder, &server_uid) ) {
		mrjob_try_again_later(job);
		goto cleanup;
	}
	else {
		mrsqlite3_lock(mailbox->m_sql);
			mrmailbox_update_server_uid__(mailbox, msg->m_rfc724_mid, server_folder, server_uid);
		mrsqlite3_unlock(mailbox->m_sql);
	}

cleanup:
	clist_free_content(recipients);
	clist_free(recipients);
	mrmsg_unref(msg);
	mmap_string_free(data);
	free(from_addr);
	free(from_displayname);
	free(server_folder);
}


void mrmailbox_send_msg_to_smtp(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrmsg_t*      msg = mrmsg_new();
	clist*	      recipients = clist_new();
	MMAPString*   data = NULL;
	char*         from_addr = NULL;
	char*         from_displayname = NULL;

	/* connect to SMTP server, if not yet done */
	if( !mrsmtp_is_connected(mailbox->m_smtp) ) {
		mrloginparam_t* loginparam = mrloginparam_new();
			mrsqlite3_lock(mailbox->m_sql);
				mrloginparam_read__(loginparam, mailbox->m_sql, "configured_");
			mrsqlite3_unlock(mailbox->m_sql);
			int connected = mrsmtp_connect(mailbox->m_smtp, loginparam);
		mrloginparam_unref(loginparam);
		if( !connected ) {
			mrjob_try_again_later(job);
			goto cleanup;
		}
	}

	/* load message data */
	load_data_to_send(mailbox, job->m_foreign_id, msg, &from_addr, &from_displayname, recipients);
	if( from_addr == NULL || clist_count(recipients) == 0 ) {
		mrlog_error("No recipients and/or no sender address.");
		goto cleanup; /* no redo, no IMAP - there won't be more recipients next time. */
	}

	/* send message */
	data = create_mime_msg(msg, from_addr, from_displayname, recipients);
	if( data == NULL ) {
		mrlog_error("Empty message.");
		goto cleanup; /* no redo, no IMAP - there won't be more recipients next time. */
	}

	if( !mrsmtp_send_msg(mailbox->m_smtp, recipients, data->str, data->len) ) {
		mrsmtp_disconnect(mailbox->m_smtp);
		mrjob_try_again_later(job);
		goto cleanup;
	}

	/* done */
	mrsqlite3_lock(mailbox->m_sql);
	mrsqlite3_begin_transaction__(mailbox->m_sql);
		mrmailbox_update_msg_state__(mailbox, msg->m_id, MR_OUT_DELIVERED);
		mrjob_add__(mailbox, MRJ_SEND_MSG_TO_IMAP, msg->m_id, NULL); /* send message to IMAP in another job */
	mrsqlite3_commit__(mailbox->m_sql);
	mrsqlite3_unlock(mailbox->m_sql);

	mailbox->m_cb(mailbox, MR_EVENT_MSG_DELIVERED, msg->m_chat_id, msg->m_id);

cleanup:
	clist_free_content(recipients);
	clist_free(recipients);
	mrmsg_unref(msg);
	mmap_string_free(data);
	free(from_addr);
	free(from_displayname);
}


uint32_t mrchat_send_msg(mrchat_t* ths, const mrmsg_t* msg)
{
	time_t        timestamp = time(NULL);
	char*         text = NULL;
	mrparam_t*    param = mrparam_new();
	size_t        bytes = 0;
	uint32_t      msg_id = 0, to_id = 0;
	char*         rfc724_mid = NULL;
	int           locked = 0, transaction_pending = 0;
	sqlite3_stmt* stmt;

	if( ths == NULL || msg == NULL || ths->m_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	mrparam_set_packed(param, msg->m_param->m_packed);

	if( msg->m_type == MR_MSG_TEXT ) {
		text = safe_strdup(msg->m_text); /* the caller should check if the message text is empty */
	}
	else if( msg->m_type == MR_MSG_IMAGE || msg->m_type == MR_MSG_AUDIO || msg->m_type == MR_MSG_VIDEO || msg->m_type == MR_MSG_FILE ) {
		char* file = mrparam_get(msg->m_param, 'f', NULL);
		if( file ) {
			bytes = mr_get_filebytes(file);
			if( bytes > 0 ) {
				mrlog_info("Attaching \"%s\" with %i bytes for message type #%i.", file, (int)bytes, (int)msg->m_type);
				free(file);
			}
			else {
				mrlog_error("File \"%s\" not found or has zero bytes.", file);
				free(file);
				goto cleanup;
			}
		}
		else {
			mrlog_warning("Attachment missing for message of type #%i.", (int)msg->m_type);
		}
	}
	else {
		mrlog_warning("Cannot send messages of type #%i.", (int)msg->m_type);
		goto cleanup;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql);
	locked = 1;
	mrsqlite3_begin_transaction__(ths->m_mailbox->m_sql);
	transaction_pending = 1;

		{
			char* from = mrsqlite3_get_config__(ths->m_mailbox->m_sql, "configured_addr", NULL);
			if( from == NULL ) { goto cleanup; }
				rfc724_mid = mr_create_outgoing_rfc724_mid(from);
			free(from);
		}

		if( ths->m_type == MR_CHAT_NORMAL )
		{
			stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_c_FROM_chats_contacts_WHERE_c, GET_CHATS_CONTACTS);
			sqlite3_bind_int(stmt, 1, ths->m_id);
			if( sqlite3_step(stmt) != SQLITE_ROW ) {
				goto cleanup;
			}
			to_id = sqlite3_column_int(stmt, 0);
		}

		/* add message to the database */
		stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, INSERT_INTO_msgs_mcftttstpb,
			"INSERT INTO msgs (rfc724_mid,chat_id,from_id,to_id, timestamp,type,state, txt,param,bytes) VALUES (?,?,?,?, ?,?,?, ?,?,?);");
		sqlite3_bind_text (stmt,  1, rfc724_mid, -1, SQLITE_STATIC);
		sqlite3_bind_int  (stmt,  2, MR_CHAT_ID_MSGS_IN_CREATION);
		sqlite3_bind_int  (stmt,  3, MR_CONTACT_ID_SELF);
		sqlite3_bind_int  (stmt,  4, to_id);
		sqlite3_bind_int64(stmt,  5, timestamp);
		sqlite3_bind_int  (stmt,  6, msg->m_type);
		sqlite3_bind_int  (stmt,  7, MR_OUT_PENDING);
		sqlite3_bind_text (stmt,  8, text? text : "",  -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  9, param->m_packed, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 10, bytes);
		if( sqlite3_step(stmt) != SQLITE_DONE ) {
			goto cleanup;
		}

		msg_id = sqlite3_last_insert_rowid(ths->m_mailbox->m_sql->m_cobj);

		/* set up blobs etc. */

		/* ... */

		/* finalize message object on database, we set the chat ID late as we don't know it sooner */
		mrmailbox_update_msg_chat_id__(ths->m_mailbox, msg_id, ths->m_id);
		mrjob_add__(ths->m_mailbox, MRJ_SEND_MSG_TO_SMTP, msg_id, NULL); /* resuts on an asynchronous call to mrmailbox_send_msg_to_smtp()  */

	mrsqlite3_commit__(ths->m_mailbox->m_sql);
	transaction_pending = 0;
	mrsqlite3_unlock(ths->m_mailbox->m_sql);
	locked = 0;

	/* done */
cleanup:
	if( transaction_pending ) {
		mrsqlite3_rollback__(ths->m_mailbox->m_sql);
	}
	if( locked ) {
		mrsqlite3_unlock(ths->m_mailbox->m_sql);
	}
	free(text);
	free(rfc724_mid);
	mrparam_unref(param);
	return msg_id;
}
