/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
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
 * Purpose: mrchat_t represents a single chat, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrcontact.h"
#include "mrjob.h"
#include "mrsmtp.h"
#include "mrimap.h"
#include "mre2ee.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


#define IS_SELF_IN_GROUP__ (mrmailbox_is_contact_in_chat__(mailbox, chat_id, MR_CONTACT_ID_SELF)==1)
#define DO_SEND_STATUS_MAILS (mrparam_get_int(chat->m_param, 'U', 0)==0)


#define MR_SYSTEM_GROUPNAME_CHANGED           2
#define MR_SYSTEM_GROUPIMAGE_CHANGED          3
#define MR_SYSTEM_MEMBER_ADDED_TO_GROUP       4
#define MR_SYSTEM_MEMBER_REMOVED_FROM_GROUP   5


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
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


uint32_t mrmailbox_lookup_real_nchat_by_contact_id__(mrmailbox_t* mailbox, uint32_t contact_id) /* checks for "real" chats (non-trash, non-unknown) */
{
	sqlite3_stmt* stmt;
	uint32_t chat_id = 0;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_chats_WHERE_contact_id,
			"SELECT c.id"
			" FROM chats c"
			" INNER JOIN chats_contacts j ON c.id=j.chat_id"
			" WHERE c.type=? AND c.id>? AND j.contact_id=?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_NORMAL);
	sqlite3_bind_int(stmt, 2, MR_CHAT_ID_LAST_SPECIAL);
	sqlite3_bind_int(stmt, 3, contact_id);

	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		chat_id = sqlite3_column_int(stmt, 0);
	}

	return chat_id;
}


uint32_t mrmailbox_create_or_lookup_nchat_by_contact_id__(mrmailbox_t* mailbox, uint32_t contact_id)
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

	if( (chat_id=mrmailbox_lookup_real_nchat_by_contact_id__(mailbox, contact_id)) != 0 ) {
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

	/* add contact IDs to the new chat record (may be replaced by mrmailbox_add_contact_to_chat__()) */
	q = sqlite3_mprintf("INSERT INTO chats_contacts (chat_id, contact_id) VALUES(%i, %i)", chat_id, contact_id);
	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q);

	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
	}

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	/* add already existing messages to the chat record */
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


static int mrchat_update_param__(mrchat_t* ths)
{
	int success = 0;
	sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, "UPDATE chats SET param=? WHERE id=?");
	sqlite3_bind_text(stmt, 1, ths->m_param->m_packed, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, ths->m_id);
	success = sqlite3_step(stmt)==SQLITE_DONE? 1 : 0;
	sqlite3_finalize(stmt);
	return success;
}


static int mrchat_set_from_stmt__(mrchat_t* ths, sqlite3_stmt* row)
{
	int row_offset = 0;
	const char* draft_text;

	if( ths == NULL || row == NULL ) {
		return 0;
	}

	mrchat_empty(ths);

	#define MR_CHAT_FIELDS " c.id,c.type,c.name, c.draft_timestamp,c.draft_txt,c.grpid,c.param "
	ths->m_id              =                    sqlite3_column_int  (row, row_offset++); /* the columns are defined in MR_CHAT_FIELDS */
	ths->m_type            =                    sqlite3_column_int  (row, row_offset++);
	ths->m_name            = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_draft_timestamp =                    sqlite3_column_int64(row, row_offset++);
	draft_text             =       (const char*)sqlite3_column_text (row, row_offset++);
	ths->m_grpid           = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	mrparam_set_packed(ths->m_param,     (char*)sqlite3_column_text (row, row_offset++));

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


mrchatlist_t* mrmailbox_get_chatlist(mrmailbox_t* ths, const char* query)
{
	int success = 0;
	int db_locked = 0;
	mrchatlist_t* obj = mrchatlist_new(ths);

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

	if( !mrchatlist_load_from_db__(obj, query) ) {
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
	int           transaction_pending = 0;
	sqlite3_stmt* stmt;
	uint32_t      msg_id;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);

		stmt = mrsqlite3_predefine__(ths->m_sql, SELECT_id_FROM_msgs_WHERE_chat_id_AND_state,
			"SELECT id FROM msgs WHERE chat_id=? AND state=?;");
		sqlite3_bind_int(stmt, 1, chat_id);
		sqlite3_bind_int(stmt, 2, MR_IN_UNSEEN);
		while( sqlite3_step(stmt) == SQLITE_ROW )
		{
			if( transaction_pending == 0 ) {
				mrsqlite3_begin_transaction__(ths->m_sql);
				transaction_pending = 1;
			}

			msg_id = sqlite3_column_int(stmt, 0);
			mrmailbox_update_msg_state__(ths, msg_id, MR_IN_SEEN);
			mrjob_add__(ths, MRJ_MARKSEEN_MSG_ON_IMAP, msg_id, NULL);
		}

		if( transaction_pending ) {
			mrsqlite3_commit__(ths->m_sql);
		}

	mrsqlite3_unlock(ths->m_sql);

	return 1;
}


uint32_t mrmailbox_get_chat_id_by_contact_id(mrmailbox_t* mailbox, uint32_t contact_id)
{
	uint32_t chat_id = 0;

	mrsqlite3_lock(mailbox->m_sql);

		chat_id = mrmailbox_lookup_real_nchat_by_contact_id__(mailbox, contact_id);

	mrsqlite3_unlock(mailbox->m_sql);

	return chat_id;
}


uint32_t mrmailbox_create_chat_by_contact_id(mrmailbox_t* ths, uint32_t contact_id)
{
	uint32_t      chat_id = 0;
	int           send_event = 0, locked = 0;

	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	locked = 1;

		chat_id = mrmailbox_lookup_real_nchat_by_contact_id__(ths, contact_id);
		if( chat_id ) {
			mrmailbox_log_warning(ths, 0, "Chat with contact %i already exists.", (int)contact_id);
			goto cleanup;
		}

        if( 0==mrmailbox_real_contact_exists__(ths, contact_id) ) {
			mrmailbox_log_warning(ths, 0, "Cannot create chat, contact %i does not exist.", (int)contact_id);
			goto cleanup;
        }

		chat_id = mrmailbox_create_or_lookup_nchat_by_contact_id__(ths, contact_id);
		if( chat_id ) {
			send_event = 1;
		}

		mrmailbox_scaleup_contact_origin__(ths, contact_id, MR_ORIGIN_CREATE_CHAT);

	mrsqlite3_unlock(ths->m_sql);
	locked = 0;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( send_event ) {
		ths->m_cb(ths, MR_EVENT_MSGS_CHANGED, 0, 0);
	}

	return chat_id;
}


static carray* mrmailbox_get_chat_media__(mrmailbox_t* mailbox, uint32_t chat_id, int msg_type, int or_msg_type)
{
	carray* ret = carray_new(100);

	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_WHERE_ctt,
		"SELECT id FROM msgs WHERE chat_id=? AND (type=? OR type=?) ORDER BY timestamp, id;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_type);
	sqlite3_bind_int(stmt, 3, or_msg_type>0? or_msg_type : msg_type);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
	}

	return ret;
}


carray* mrmailbox_get_chat_media(mrmailbox_t* mailbox, uint32_t chat_id, int msg_type, int or_msg_type)
{
	carray* ret = NULL;

	if( mailbox ) {
		mrsqlite3_lock(mailbox->m_sql);
			ret = mrmailbox_get_chat_media__(mailbox, chat_id, msg_type, or_msg_type);
		mrsqlite3_unlock(mailbox->m_sql);
	}

	return ret;
}


uint32_t mrmailbox_get_next_media(mrmailbox_t* mailbox, uint32_t curr_msg_id, int dir)
{
	uint32_t ret_msg_id = 0;
	mrmsg_t* msg = mrmsg_new();
	int      locked = 0;
	carray*  list = NULL;
	int      i, cnt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db__(msg, mailbox, curr_msg_id) ) {
			goto cleanup;
		}

		if( (list=mrmailbox_get_chat_media__(mailbox, msg->m_chat_id, msg->m_type, 0))==NULL ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	cnt = carray_count(list);
	for( i = 0; i < cnt; i++ ) {
		if( curr_msg_id == (uint32_t)(uintptr_t)carray_get(list, i) )
		{
			if( dir > 0 ) {
				/* get the next message from the current position */
				if( i+1 < cnt ) {
					ret_msg_id = (uint32_t)(uintptr_t)carray_get(list, i+1);
				}
			}
			else if( dir < 0 ) {
				/* get the previous message from the current position */
				if( i-1 >= 0 ) {
					ret_msg_id = (uint32_t)(uintptr_t)carray_get(list, i-1);
				}
			}
			break;
		}
	}


cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( list ) { carray_free(list); }
	mrmsg_unref(msg);
	return ret_msg_id;
}


carray* mrmailbox_get_chat_contacts(mrmailbox_t* mailbox, uint32_t chat_id)
{
	/* Normal chats to not include SELF.  Group chats do (as it may happen that one is deleted from a
	groupchat but the chats stays visible, moreover, this makes displaying lists easier) */
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
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_c_FROM_chats_contacts_WHERE_c_ORDER_BY,
				"SELECT cc.contact_id FROM chats_contacts cc"
					" LEFT JOIN contacts c ON c.id=cc.contact_id"
					" WHERE cc.chat_id=?"
					" ORDER BY c.id=1, LOWER(c.name||c.addr), c.id;");
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

	ths->m_mailbox  = mailbox;
	ths->m_type     = MR_CHAT_UNDEFINED;
	ths->m_param    = mrparam_new();

    return ths;
}


void mrchat_unref(mrchat_t* ths)
{
	if( ths==NULL ) {
		return;
	}

	mrchat_empty(ths);
	mrparam_unref(ths->m_param);
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

	free(ths->m_grpid);
	ths->m_grpid = NULL;

	mrparam_set_packed(ths->m_param, NULL);
}


carray* mrmailbox_get_unseen_msgs(mrmailbox_t* mailbox)
{
	int           show_deaddrop, success = 0, locked = 0;
	carray*       ret = carray_new(128);
	sqlite3_stmt* stmt = NULL;

	if( mailbox==NULL || ret == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		show_deaddrop = mrsqlite3_get_config_int__(mailbox->m_sql, "show_deaddrop", 0);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_LEFT_JOIN_contacts_WHERE_unseen,
			"SELECT m.id"
				" FROM msgs m"
				" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.state=? AND m.chat_id!=? AND ct.blocked=0"
				" ORDER BY m.timestamp DESC,m.id DESC;"); /* the list starts with the newest messages*/
		sqlite3_bind_int(stmt, 1, MR_IN_UNSEEN);
		sqlite3_bind_int(stmt, 2, show_deaddrop? 0 : MR_CHAT_ID_DEADDROP);

		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

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


carray* mrmailbox_get_chat_msgs(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t flags, uint32_t marker1before)
{
	int           success = 0, locked = 0;
	carray*       ret = carray_new(512);
	sqlite3_stmt* stmt = NULL;

	uint32_t      curr_id;
	time_t        curr_local_timestamp;
	int           curr_day, last_day = 0;
	long          cnv_to_local = mr_gm2local_offset();
	#define       SECONDS_PER_DAY 86400

	if( mailbox==NULL || ret == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_LEFT_JOIN_contacts_WHERE_c,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.chat_id=? AND ct.blocked=0"
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
		sqlite3_bind_int(stmt, 1, chat_id);

		while( sqlite3_step(stmt) == SQLITE_ROW )
		{
			curr_id = sqlite3_column_int(stmt, 0);

			/* add user marker */
			if( curr_id == marker1before ) {
				carray_add(ret, (void*)MR_MSG_ID_MARKER1, NULL);
			}

			/* add daymarker, if needed */
			if( flags&MR_GCM_ADDDAYMARKER ) {
				curr_local_timestamp = (time_t)sqlite3_column_int64(stmt, 1) + cnv_to_local;
				curr_day = curr_local_timestamp/SECONDS_PER_DAY;
				if( curr_day != last_day ) {
					carray_add(ret, (void*)MR_MSG_ID_DAYMARKER, NULL);
					last_day = curr_day;
				}
			}

			carray_add(ret, (void*)(uintptr_t)curr_id, NULL);
		}

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


carray* mrmailbox_search_msgs(mrmailbox_t* mailbox, uint32_t chat_id, const char* query__)
{
	int           success = 0, locked = 0;
	carray*       ret = carray_new(100);
	char*         strLikeInText = NULL, *strLikeBeg=NULL, *query = NULL;
	sqlite3_stmt* stmt = NULL;

	if( mailbox==NULL || ret == NULL || query__ == NULL ) {
		goto cleanup;
	}

	query = safe_strdup(query__);
	mr_trim(query);
	if( query[0]==0 ) {
		success = 1; /*empty result*/
		goto cleanup;
	}

	strLikeInText = mr_mprintf("%%%s%%", query);
	strLikeBeg = mr_mprintf("%s%%", query); /*for the name search, we use "Name%" which is fast as it can use the index ("%Name%" could not). */

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* Incremental search with "LIKE %query%" cannot take advantages from any index
		("query%" could for COLLATE NOCASE indexes, see http://www.sqlite.org/optoverview.html#like_opt )
		An alternative may be the FULLTEXT sqlite stuff, however, this does not really help with incremental search.
		An extra table with all words and a COLLATE NOCASE indexes may help, however,
		this must be updated all the time and probably consumes more time than we can save in tenthousands of searches.
		For now, we just expect the following query to be fast enough :-) */
		#define QUR1  "SELECT m.id, m.timestamp" \
		                  " FROM msgs m" \
		                  " LEFT JOIN contacts ct ON m.from_id=ct.id" \
		                  " WHERE"
		#define QUR2      " AND ct.blocked=0 AND (txt LIKE ? OR ct.name LIKE ?)"
		if( chat_id ) {
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_WHERE_chat_id_AND_query,
				QUR1 " m.chat_id=? " QUR2 " ORDER BY m.timestamp,m.id;"); /* chats starts with the oldest message*/
			sqlite3_bind_int (stmt, 1, chat_id);
			sqlite3_bind_text(stmt, 2, strLikeInText, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, strLikeBeg, -1, SQLITE_STATIC);
		}
		else {
			int show_deaddrop = mrsqlite3_get_config_int__(mailbox->m_sql, "show_deaddrop", 0);
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_msgs_WHERE_query,
				QUR1 " (m.chat_id>? OR m.chat_id=?) " QUR2 " ORDER BY m.timestamp DESC,m.id DESC;"); /* chat overview starts with the newest message*/
			sqlite3_bind_int (stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
			sqlite3_bind_int (stmt, 2, show_deaddrop? MR_CHAT_ID_DEADDROP : MR_CHAT_ID_LAST_SPECIAL+1 /*just any ID that is already selected*/);
			sqlite3_bind_text(stmt, 3, strLikeInText, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 4, strLikeBeg, -1, SQLITE_STATIC);
		}

		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	success = 1;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	free(strLikeInText);
	free(strLikeBeg);
	free(query);
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

	ths->m_mailbox->m_cb(ths->m_mailbox, MR_EVENT_MSGS_CHANGED, 0, 0);

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
					ret = mrstock_str_repl_pl(MR_STR_CONTACT, cnt);
				}

			mrsqlite3_unlock(ths->m_mailbox->m_sql);
		}
		else
		{
			mrsqlite3_lock(ths->m_mailbox->m_sql);

				cnt = mrmailbox_get_chat_contact_count__(ths->m_mailbox, ths->m_id);
				ret = mrstock_str_repl_pl(MR_STR_MEMBER, cnt /*SELF is included in group chats (if not removed)*/);

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
 * Delete a chat
 ******************************************************************************/


/* Deleting a group chat implies to leave the group which required to send a
message before the chat is deleted physically.  To make things even more complicated,
there may be other chat messages waiting to be send.

We use the following approach:
1. If we do not need to send a message, we delete the chat directly
2. If we need to send a message, we set chats.blocked=1 and add the parameter
   'P' with a random value to both, the last message to be send and to the
   chat (we would use msg_id, however, we may not get this in time)
3. When the messag with the 'P'-value of the chat was send to IMAP, we physically
   delete the chat. */


int mrmailbox_delete_chat_part2(mrmailbox_t* mailbox, uint32_t chat_id)
{
	int       success = 0, locked = 0, pending_transaction = 0;
	mrchat_t* obj = mrchat_new(mailbox);
	char*     q3 = NULL;

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
			q3 = NULL;

			q3 = sqlite3_mprintf("UPDATE msgs SET chat_id=%i WHERE chat_id=%i AND from_id!=1;", MR_CHAT_ID_DEADDROP, chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;
        }
        else if( obj->m_type == MR_CHAT_GROUP )
        {
			/* delete a group-chat; all messages are deleted from the device but stay on the server.
			Currently, they cannot be restored - "to_id" as used to restore single-user-chats is not sufficient.
			Maybe it is okay (and maybe even expected :-) that messages from deleted chats do not show up again if a chat is re-created. */
			mrsqlite3_begin_transaction__(mailbox->m_sql);
			pending_transaction = 1;

			q3 = sqlite3_mprintf("DELETE FROM msgs WHERE chat_id=%i;", chat_id);
			if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;
        }
        else
        {
			/* Bad type. */
			goto cleanup;
        }

		q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i;", chat_id);
		if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

		q3 = sqlite3_mprintf("DELETE FROM chats WHERE id=%i;", chat_id);
		if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

        if( pending_transaction ) {
			mrsqlite3_commit__(mailbox->m_sql);
			pending_transaction = 0;
        }

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	success = 1;

cleanup:
	if( pending_transaction ) { mrsqlite3_rollback__(mailbox->m_sql); }
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrchat_unref(obj);
	if( q3 ) { sqlite3_free(q3); }
	return success;
}


int mrmailbox_delete_chat(mrmailbox_t* mailbox, uint32_t chat_id)
{
	int          success = 0;
	mrchat_t*    chat = mrmailbox_get_chat(mailbox, chat_id);
	mrcontact_t* contact = NULL;
	mrmsg_t*     msg = mrmsg_new();

	if( mailbox == NULL || chat_id <= MR_CHAT_ID_LAST_SPECIAL || chat == NULL ) {
		goto cleanup;
	}

	if( chat->m_type == MR_CHAT_GROUP
	 && mrmailbox_is_contact_in_chat(mailbox, chat_id, MR_CONTACT_ID_SELF)
	 && DO_SEND_STATUS_MAILS )
	{
		/* _first_ mark chat to being delete and _then_ send the message to inform others that we've quit the group
		(the order is important - otherwise the message may be send asynchronous before we update the group. */
		int link_msg_to_chat_deletion = (int)time(NULL);

		mrparam_set_int(chat->m_param, 'P', link_msg_to_chat_deletion);
		mrsqlite3_lock(mailbox->m_sql);
			sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, "UPDATE chats SET blocked=1, param=? WHERE id=?;");
			sqlite3_bind_text (stmt, 1, chat->m_param->m_packed, -1, SQLITE_STATIC);
			sqlite3_bind_int  (stmt, 2, chat_id);
			sqlite3_step(stmt);
			mrmailbox_set_group_explicitly_left__(mailbox, chat->m_grpid);
		mrsqlite3_unlock(mailbox->m_sql);

		contact = mrmailbox_get_contact(mailbox, MR_CONTACT_ID_SELF);
		msg->m_type = MR_MSG_TEXT;
		msg->m_text = mrstock_str(MR_STR_MSGGROUPLEFT);
		mrparam_set_int(msg->m_param, 'S', MR_SYSTEM_MEMBER_REMOVED_FROM_GROUP);
		mrparam_set    (msg->m_param, 'E', contact->m_addr);
		mrparam_set_int(msg->m_param, 'P', link_msg_to_chat_deletion);
		mrchat_send_msg(chat, msg);
	}
	else
	{
		/* directly delete the chat */
		mrmailbox_delete_chat_part2(mailbox, chat_id);
	}

	mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, 0, 0);
	success = 1;

cleanup:
	mrchat_unref(chat);
	mrcontact_unref(contact);
	mrmsg_unref(msg);
	return success;
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

	char* pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
	char* mimetype = mrparam_get(msg->m_param, 'm', NULL);
	char* suffix = mr_get_filesuffix_lc(pathNfilename);
	char* filename_to_send = NULL;

	if( pathNfilename == NULL ) {
		goto cleanup;
	}

	/* get file name to use for sending (for privacy purposes, we do not transfer the original filenames eg. for images; these names are normally not needed and contain timesamps, running numbers etc.) */
	if( msg->m_type == MR_MSG_VOICE ) {
		struct tm wanted_struct;
		memcpy(&wanted_struct, localtime(&msg->m_timestamp), sizeof(struct tm));
		filename_to_send = mr_mprintf("voice-message_%04i-%02i-%02i_%02i-%02i-%02i.%s",
			(int)wanted_struct.tm_year+1900, (int)wanted_struct.tm_mon+1, (int)wanted_struct.tm_mday,
			(int)wanted_struct.tm_hour, (int)wanted_struct.tm_min, (int)wanted_struct.tm_sec,
			suffix? suffix : "dat");
	}
	else if( msg->m_type == MR_MSG_AUDIO ) {
		char* author = mrparam_get(msg->m_param, 'N', NULL);
		char* title = mrparam_get(msg->m_param, 'n', NULL);
		if( author && author[0] && title && title[0] && suffix ) {
			filename_to_send = mr_mprintf("%s - %s.%s",  author, title, suffix); /* the separator ` - ` is used on the receiver's side to construct the information; we avoid using ID3-scanners for security purposes */
		}
		else {
			filename_to_send = mr_get_filename(pathNfilename);
		}
		free(author);
		free(title);
	}
	else if( msg->m_type == MR_MSG_IMAGE || msg->m_type == MR_MSG_GIF ) {
		filename_to_send = mr_mprintf("image.%s", suffix? suffix : "dat");
	}
	else if( msg->m_type == MR_MSG_VIDEO ) {
		filename_to_send = mr_mprintf("video.%s", suffix? suffix : "dat");
	}
	else {
		filename_to_send = mr_get_filename(pathNfilename);
	}

	/* check mimetype */
	if( mimetype == NULL && suffix != NULL ) {
		if( strcmp(suffix, "png")==0 ) {
			mimetype = safe_strdup("image/png");
		}
		else if( strcmp(suffix, "jpg")==0 || strcmp(suffix, "jpeg")==0 || strcmp(suffix, "jpe")==0 ) {
			mimetype = safe_strdup("image/jpeg");
		}
		else if( strcmp(suffix, "gif")==0 ) {
			mimetype = safe_strdup("image/gif");
		}
		else {
			mimetype = safe_strdup("application/octet-stream");
		}
	}

	if( mimetype == NULL ) {
		goto cleanup;
	}

	/* create mime part */
	mime_fields = mailmime_fields_new_filename(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
		safe_strdup(filename_to_send), MAILMIME_MECHANISM_BASE64);

	content = mailmime_content_new_with_str(mimetype);

	mime_sub = mailmime_new_empty(content, mime_fields);

	mailmime_set_body_file(mime_sub, safe_strdup(pathNfilename));

cleanup:
	free(pathNfilename);
	free(mimetype);
	free(filename_to_send);
	free(suffix);
	return mime_sub;
}


static char* get_subject(const mrchat_t* chat, const mrmsg_t* msg, const char* afwd_email)
{
	char *ret, *raw_subject = mrmsg_get_summarytext_by_raw(msg->m_type, msg->m_text, msg->m_param, APPROX_SUBJECT_CHARS);
	const char* fwd = afwd_email? "Fwd: " : "";

	if( chat->m_type==MR_CHAT_GROUP )
	{
		ret = mr_mprintf(MR_CHAT_PREFIX " %s: %s%s", chat->m_name, fwd, raw_subject);
	}
	else
	{
		ret = mr_mprintf(MR_CHAT_PREFIX " %s%s", fwd, raw_subject);
	}

	free(raw_subject);
	return ret;
}


static MMAPString* create_mime_msg(const mrchat_t* chat, const mrmsg_t* msg, const char* from_addr, const char* from_displayname,
                                   const clist* recipients_names, const clist* recipients_addr, const char* predecessor)
{
	struct mailimf_fields*       imf_fields;
	struct mailmime*             message = NULL;
	char*                        message_text = NULL, *subject_str = NULL;
	char*                        afwd_email = mrparam_get(msg->m_param, 'a', NULL);
	int                          col = 0;
	MMAPString*                  ret = NULL;
	int                          parts = 0;
	mre2ee_helper_t              e2ee_helper;

	/* create empty mail */
	{
		struct mailimf_mailbox_list* from = mailimf_mailbox_list_new_empty();
		mailimf_mailbox_list_add(from, mailimf_mailbox_new(from_displayname? mr_encode_header_string(from_displayname) : NULL, safe_strdup(from_addr)));

		struct mailimf_address_list* to = NULL;
		if( recipients_names && recipients_addr && clist_count(recipients_addr)>0 ) {
			clistiter *iter1, *iter2;
			to = mailimf_address_list_new_empty();
			for( iter1=clist_begin(recipients_names),iter2=clist_begin(recipients_addr);  iter1!=NULL&&iter2!=NULL;  iter1=clist_next(iter1),iter2=clist_next(iter2)) {
				const char* name = clist_content(iter1);
				const char* addr = clist_content(iter2);
				mailimf_address_list_add(to, mailimf_address_new(MAILIMF_ADDRESS_MAILBOX, mailimf_mailbox_new(name? mr_encode_header_string(name) : NULL, safe_strdup(addr)), NULL));
			}
		}

		imf_fields = mailimf_fields_new_with_data_all(mailimf_get_date(msg->m_timestamp), from,
			NULL /* sender */, NULL /* reply-to */,
			to, NULL /* cc */, NULL /* bcc */, safe_strdup(msg->m_rfc724_mid), NULL /* in-reply-to */,
			NULL /* references */,
			NULL /* subject set later */);

		/* add additional basic parameters */
		mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-Mailer"), mr_mprintf("MrMsg %i.%i.%i", MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION))); /* only informational, for debugging, may be removed in the release */
		mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrMsg"), strdup("1.0"))); /* mark message as being sent by a messenger */
		if( predecessor ) {
			mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrPredecessor"), strdup(predecessor)));
		}

		/* add additional group paramters */
		if( chat->m_type==MR_CHAT_GROUP )
		{
			mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrGrpId"), safe_strdup(chat->m_grpid)));
			mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrGrpName"), mr_encode_header_string(chat->m_name)));

			int system_command = mrparam_get_int(msg->m_param, 'S', 0);
			if( system_command == MR_SYSTEM_MEMBER_REMOVED_FROM_GROUP ) {
				char* email_to_remove = mrparam_get(msg->m_param, 'E', NULL);
				if( email_to_remove ) {
					mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrRemoveFromGrp"), email_to_remove));
				}
			}
			else if( system_command == MR_SYSTEM_MEMBER_ADDED_TO_GROUP ) {
				char* email_to_add = mrparam_get(msg->m_param, 'E', NULL);
				if( email_to_add ) {
					mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrAddToGrp"), email_to_add));
				}
			}
			else if( system_command == MR_SYSTEM_GROUPNAME_CHANGED ) {
				mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrGrpNameChanged"), strdup("1")));
			}
		}

		/* add additional media paramters */
		if( msg->m_type == MR_MSG_VOICE || msg->m_type == MR_MSG_AUDIO || msg->m_type == MR_MSG_VIDEO )
		{
			if( msg->m_type == MR_MSG_VOICE ) {
				mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrVoiceMessage"), strdup("1")));
			}

			int duration_ms = mrparam_get_int(msg->m_param, 'd', 0);
			if( duration_ms > 0 ) {
				mailimf_fields_add(imf_fields, mailimf_field_new_custom(strdup("X-MrDurationMs"), mr_mprintf("%i", (int)duration_ms)));
			}
		}

	}

	message = mailmime_new_message_data(NULL);
	mailmime_set_imf_fields(message, imf_fields);

	/* add text part - we even add empty text and force a MIME-message as:
	- some Apps have problems with Non-text in the main part (eg. "Mail" from stock Android)
	- we can add "forward hints" this way
	- it looks better */
	{
		char* fwdhint = NULL;
		if( afwd_email ) {
			char* afwd_name = mrparam_get(msg->m_param, 'A', NULL);
				char* nameNAddr = mr_get_headerlike_name(afwd_email, afwd_name);
					fwdhint = mr_mprintf("---------- Forwarded message ----------\nFrom: %s\n\n", nameNAddr); /* no not chage this! expected this way in the simplifier to detect forwarding! */
				free(nameNAddr);
			free(afwd_name);
		}

		int write_m_text = 0;
		if( msg->m_type==MR_MSG_TEXT && msg->m_text && msg->m_text[0] ) { /* m_text may also contain data otherwise, eg. the filename of attachments */
			write_m_text = 1;
		}

		char* footer = mrstock_str(MR_STR_STATUSLINE);
		message_text = mr_mprintf("%s%s%s%s%s",
			fwdhint? fwdhint : "",
			write_m_text? msg->m_text : "",
			(write_m_text&&footer&&footer[0])? "\n\n" : "",
			(footer&&footer[0])? "-- \n"  : "",
			(footer&&footer[0])? footer       : "");
		free(footer);
		struct mailmime* text_part = build_body_text(message_text);
		mailmime_smart_add_part(message, text_part);
		parts++;

		free(fwdhint);
	}

	/* add attachment part */
	if( MR_MSG_NEEDS_ATTACHMENT(msg->m_type) ) {
		struct mailmime* file_part = build_body_file(msg);
		if( file_part ) {
			mailmime_smart_add_part(message, file_part);
			parts++;
		}
	}

	if( parts == 0 ) {
		goto cleanup;
	}

	/* encrypt the message, if possible; add Autocrypt:-header
	(encryption may modifiy or replace the given object) */
	mre2ee_encrypt(chat->m_mailbox, recipients_addr, message, &e2ee_helper);

	/* add a subject line */
	if( e2ee_helper.m_encryption_successfull ) {
		char* e = mrstock_str(MR_STR_ENCRYPTEDMSG); subject_str = mr_mprintf(MR_CHAT_PREFIX " %s", e); free(e);
	}
	else {
		subject_str = get_subject(chat, msg, afwd_email);
	}
	struct mailimf_subject* subject = mailimf_subject_new(mr_encode_header_string(subject_str));
	mailimf_fields_add(imf_fields, mailimf_field_new(MAILIMF_FIELD_SUBJECT, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, subject, NULL, NULL, NULL));

	/* create the full mail and return */
	ret = mmap_string_new("");
	mailmime_write_mem(ret, &col, message);

cleanup:
	if( message ) {
		mailmime_free(message);
	}
	mre2ee_thanks(&e2ee_helper); /* frees data referenced by "mailmime" but not freed by mailmime_free() */
	free(message_text); /* mailmime_set_body_text() does not take ownership of "text" */
	free(subject_str);
	free(afwd_email);
	return ret;
}


/*******************************************************************************
 * Sending messages
 ******************************************************************************/


static int load_data_to_send(mrmailbox_t* mailbox, uint32_t msg_id,
                             mrchat_t* ret_chat, mrmsg_t* ret_msg, char** ret_from, char** ret_displayname,
                             clist* ret_recipients_names, clist* ret_recipients_addr,
                             int* ret_increation,
                             char** ret_predecessor)
{
	int success = 0;
	mrsqlite3_lock(mailbox->m_sql);
		if( mrmsg_load_from_db__(ret_msg, mailbox, msg_id)
		 && mrchat_load_from_db__(ret_chat, ret_msg->m_chat_id) )
		{
			sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_na_FROM_chats_contacs_JOIN_contacts_WHERE_cc,
				"SELECT c.authname, c.addr FROM chats_contacts cc LEFT JOIN contacts c ON cc.contact_id=c.id WHERE cc.chat_id=? AND cc.contact_id>?;");
			sqlite3_bind_int(stmt, 1, ret_msg->m_chat_id);
			sqlite3_bind_int(stmt, 2, MR_CONTACT_ID_LAST_SPECIAL);
			while( sqlite3_step(stmt) == SQLITE_ROW )
			{
				const char* authname = (const char*)sqlite3_column_text(stmt, 0);
				const char* addr = (const char*)sqlite3_column_text(stmt, 1);
				if( clist_search_string_nocase(ret_recipients_addr, addr)==0 )
				{
					clist_append(ret_recipients_names, (void*)((authname&&authname[0])? safe_strdup(authname) : NULL));
					clist_append(ret_recipients_addr,  (void*)safe_strdup(addr));
				}
			}

			int system_command = mrparam_get_int(ret_msg->m_param, 'S', 0);
			if( system_command==MR_SYSTEM_MEMBER_REMOVED_FROM_GROUP /* for added members, the list is just fine */) {
				char* email_to_remove = mrparam_get(ret_msg->m_param, 'E', NULL);
				char* self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", "");
				if( email_to_remove && strcasecmp(email_to_remove, self_addr)!=0 )
				{
					if( clist_search_string_nocase(ret_recipients_addr, email_to_remove)==0 )
					{
						clist_append(ret_recipients_names, NULL);
						clist_append(ret_recipients_addr,  (void*)email_to_remove);
					}
				}
				free(self_addr);
			}

			*ret_from        = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
			*ret_displayname = mrsqlite3_get_config__(mailbox->m_sql, "displayname", NULL);

			/* Get a predecessor of the mail to send.
			For simplicity, we use the last message send not by us.
			This is not 100% accurate and may even be a newer message if first sending fails and new messages arrive -
			however, as we currently only use it to identifify answers from different email addresses, this is sufficient.

			Our first idea was to write the predecessor to the `In-Reply-To:` header, however, this results
			in infinite depth thread views eg. in thunderbird.  Maybe we can work around this issue by using only one
			predecessor anchor a day, however, for the moment, we just use the `X-MrPredecessor` header that does not
			disturb other mailers.

			Finally, maybe the Predecessor/In-Reply-To header is not needed for all answers but only to the first ones -
			or after the sender has changes its email address. */
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_rfc724_FROM_msgs_ORDER_BY_timestamp_LIMIT_1,
				"SELECT rfc724_mid FROM msgs WHERE timestamp=(SELECT max(timestamp) FROM msgs WHERE chat_id=? AND from_id!=?);");
			sqlite3_bind_int  (stmt, 1, ret_msg->m_chat_id);
			sqlite3_bind_int  (stmt, 2, MR_CONTACT_ID_SELF);
			if( sqlite3_step(stmt) == SQLITE_ROW ) {
				*ret_predecessor = strdup_keep_null((const char*)sqlite3_column_text(stmt, 0));
			}

			success = 1;
		}

		*ret_increation = 0;
		if( success ) {
			*ret_increation = mrmsg_is_increation__(ret_msg);
		}
	mrsqlite3_unlock(mailbox->m_sql);
	return success;
}


void mrmailbox_send_msg_to_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrchat_t*     chat = mrchat_new(mailbox);
	mrmsg_t*      msg = mrmsg_new();
	clist*	      recipients_names = clist_new();
	clist*	      recipients_addr = clist_new();
	MMAPString*   data = NULL;
	char*         from_addr = NULL;
	char*         from_displayname = NULL;
	char*         predecessor = NULL;
	char*         server_folder = NULL;
	uint32_t      server_uid = 0;
	int           increation; /* we can ignore this state here as it already checked when sending to SMTP */

	/* connect to IMAP-server */
	if( !mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* create message */
	if( load_data_to_send(mailbox, job->m_foreign_id, chat, msg, &from_addr, &from_displayname, recipients_names, recipients_addr, &increation, &predecessor)==0
	 || from_addr == NULL ) {
		goto cleanup; /* should not happen as we've send the message to the SMTP server before */
	}

	data = create_mime_msg(chat, msg, from_addr, from_displayname, recipients_names, recipients_addr, predecessor);
	if( data == NULL ) {
		goto cleanup; /* should not happen as we've send the message to the SMTP server before */
	}

	if( !mrimap_append_msg(mailbox->m_imap, msg->m_timestamp, data->str, data->len, &server_folder, &server_uid) ) {
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
		goto cleanup;
	}
	else {
		mrsqlite3_lock(mailbox->m_sql);
			mrmailbox_update_server_uid__(mailbox, msg->m_rfc724_mid, server_folder, server_uid);
		mrsqlite3_unlock(mailbox->m_sql);
	}

	/* check, if the chat shall be deleted pysically */
	if( mrparam_get_int(chat->m_param, 'P', 0)!=0
	 && mrparam_get_int(chat->m_param, 'P', 0)==mrparam_get_int(msg->m_param, 'P', 0) ) {
		mrmailbox_delete_chat_part2(mailbox, chat->m_id);
	}

cleanup:
	clist_free_content(recipients_names);
	clist_free(recipients_names);
	clist_free_content(recipients_addr);
	clist_free(recipients_addr);
	mrmsg_unref(msg);
	mrchat_unref(chat);
	mmap_string_free(data);
	free(from_addr);
	free(from_displayname);
	free(predecessor);
	free(server_folder);
}


void mrmailbox_send_msg_to_smtp(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrchat_t*     chat = mrchat_new(mailbox);
	mrmsg_t*      msg = mrmsg_new();
	clist*	      recipients_names = clist_new();
	clist*	      recipients_addr = clist_new();
	MMAPString*   data = NULL;
	char*         from_addr = NULL;
	char*         from_displayname = NULL;
	char*         predecessor = NULL;
	int           increation;

	/* connect to SMTP server, if not yet done */
	if( !mrsmtp_is_connected(mailbox->m_smtp) ) {
		mrloginparam_t* loginparam = mrloginparam_new();
			mrsqlite3_lock(mailbox->m_sql);
				mrloginparam_read__(loginparam, mailbox->m_sql, "configured_");
			mrsqlite3_unlock(mailbox->m_sql);
			int connected = mrsmtp_connect(mailbox->m_smtp, loginparam);
		mrloginparam_unref(loginparam);
		if( !connected ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* load message data */
	if( load_data_to_send(mailbox, job->m_foreign_id, chat, msg, &from_addr, &from_displayname, recipients_names, recipients_addr, &increation, &predecessor)==0
	 || from_addr == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot load data to send, maybe the message is deleted in between.");
		goto cleanup; /* no redo, no IMAP - there won't be more recipients next time. */
	}

	/* check if the message is ready (normally, only video files may be delayed this way) */
	if( increation ) {
		mrmailbox_log_info(mailbox, 0, "File is in creation, retrying later.");
		mrjob_try_again_later(job, MR_INCREATION_POLL);
		goto cleanup;
	}

	/* send message - it's okay if there are not recipients, this is a group with only OURSELF; we only upload to IMAP in this case */
	if( clist_count(recipients_addr) > 0 ) {
		data = create_mime_msg(chat, msg, from_addr, from_displayname, recipients_names, recipients_addr, predecessor);
		if( data == NULL ) {
			mrmailbox_log_error(mailbox, 0, "Empty message."); /* should not happen */
			goto cleanup; /* no redo, no IMAP - there won't be more recipients next time. */
		}

		if( !mrsmtp_send_msg(mailbox->m_smtp, recipients_addr, data->str, data->len) ) {
			mrsmtp_disconnect(mailbox->m_smtp);
			mrjob_try_again_later(job, MR_AT_ONCE); /* MR_AT_ONCE is only the _initial_ delay, if the second try failes, the delay gets larger */
			goto cleanup;
		}
	}

	/* done */
	mrsqlite3_lock(mailbox->m_sql);
	mrsqlite3_begin_transaction__(mailbox->m_sql);
		mrmailbox_update_msg_state__(mailbox, msg->m_id, MR_OUT_DELIVERED);
		if( (mailbox->m_imap->m_server_flags&MR_NO_EXTRA_IMAP_UPLOAD)==0 ) {
			mrjob_add__(mailbox, MRJ_SEND_MSG_TO_IMAP, msg->m_id, NULL); /* send message to IMAP in another job */
		}
	mrsqlite3_commit__(mailbox->m_sql);
	mrsqlite3_unlock(mailbox->m_sql);

	mailbox->m_cb(mailbox, MR_EVENT_MSG_DELIVERED, msg->m_chat_id, msg->m_id);

cleanup:
	clist_free_content(recipients_names);
	clist_free(recipients_names);
	clist_free_content(recipients_addr);
	clist_free(recipients_addr);
	mrmsg_unref(msg);
	mrchat_unref(chat);
	mmap_string_free(data);
	free(from_addr);
	free(from_displayname);
	free(predecessor);
}


uint32_t mrchat_send_msg__(mrchat_t* ths, const mrmsg_t* msg, time_t timestamp)
{
	char*         rfc724_mid = NULL;
	sqlite3_stmt* stmt;
	uint32_t      msg_id = 0, to_id = 0;

	if( ths->m_type==MR_CHAT_GROUP && !mrmailbox_is_contact_in_chat__(ths->m_mailbox, ths->m_id, MR_CONTACT_ID_SELF) ) {
		mrmailbox_log_error(ths->m_mailbox, MR_ERR_SELF_NOT_IN_GROUP, NULL);
		goto cleanup;
	}

	{
		char* from = mrsqlite3_get_config__(ths->m_mailbox->m_sql, "configured_addr", NULL);
		if( from == NULL ) { goto cleanup; }
			rfc724_mid = mr_create_outgoing_rfc724_mid(ths->m_type==MR_CHAT_GROUP? ths->m_grpid : NULL, from);
		free(from);
	}

	if( ths->m_type == MR_CHAT_NORMAL )
	{
		stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_c_FROM_chats_contacts_WHERE_c,
			"SELECT contact_id FROM chats_contacts WHERE chat_id=?;");
		sqlite3_bind_int(stmt, 1, ths->m_id);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			goto cleanup;
		}
		to_id = sqlite3_column_int(stmt, 0);
	}
	else if( ths->m_type == MR_CHAT_GROUP )
	{
		if( mrparam_get_int(ths->m_param, 'U', 0)==1 ) {
			/* mark group as being no longer 'U'npromoted */
			mrparam_set(ths->m_param, 'U', NULL);
			mrchat_update_param__(ths);
		}
	}

	/* add message to the database */
	stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, INSERT_INTO_msgs_mcftttstpb,
		"INSERT INTO msgs (rfc724_mid,chat_id,from_id,to_id, timestamp,type,state, txt,param) VALUES (?,?,?,?, ?,?,?, ?,?);");
	sqlite3_bind_text (stmt,  1, rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt,  2, MR_CHAT_ID_MSGS_IN_CREATION);
	sqlite3_bind_int  (stmt,  3, MR_CONTACT_ID_SELF);
	sqlite3_bind_int  (stmt,  4, to_id);
	sqlite3_bind_int64(stmt,  5, timestamp);
	sqlite3_bind_int  (stmt,  6, msg->m_type);
	sqlite3_bind_int  (stmt,  7, MR_OUT_PENDING);
	sqlite3_bind_text (stmt,  8, msg->m_text? msg->m_text : "",  -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt,  9, msg->m_param->m_packed, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
	}

	msg_id = sqlite3_last_insert_rowid(ths->m_mailbox->m_sql->m_cobj);

	/* finalize message object on database, we set the chat ID late as we don't know it sooner */
	mrmailbox_update_msg_chat_id__(ths->m_mailbox, msg_id, ths->m_id);
	mrjob_add__(ths->m_mailbox, MRJ_SEND_MSG_TO_SMTP, msg_id, NULL); /* resuts on an asynchronous call to mrmailbox_send_msg_to_smtp()  */

cleanup:
	free(rfc724_mid);
	return msg_id;
}


uint32_t mrchat_send_msg(mrchat_t* ths, mrmsg_t* msg)
{
	char* pathNfilename = NULL;

	if( ths == NULL || msg == NULL || ths->m_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		return 0;
	}

	msg->m_id      = 0;
	msg->m_mailbox = ths->m_mailbox;

	if( msg->m_type == MR_MSG_TEXT )
	{
		; /* the caller should check if the message text is empty */
	}
	else if( MR_MSG_NEEDS_ATTACHMENT(msg->m_type) )
	{
		pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
		if( pathNfilename )
		{
			/* Got an attachment. Take care, the file may not be ready in this moment!
			This is useful eg. if a video should be sended and already shown as "being processed" in the chat.
			In this case, the user should create an `.increation`; when the file is deleted later on, the message is sended.
			(we do not use a state in the database as this would make eg. forwarding such messages much more complicated) */

			if( msg->m_type == MR_MSG_FILE || msg->m_type == MR_MSG_IMAGE )
			{
				/* Correct the type, take care not to correct already very special formats as GIF or VOICE.
				Typical conversions:
				- from FILE to AUDIO/VIDEO/IMAGE
				- from FILE/IMAGE to GIF */
				int   better_type = 0;
				char* better_mime = NULL;
				mr_guess_msgtype_from_suffix(pathNfilename, &better_type, &better_mime);
				if( better_type ) {
					msg->m_type = better_type;
					mrparam_set(msg->m_param, 'm', better_mime);
				}
				free(better_mime);
			}

			if( (msg->m_type == MR_MSG_IMAGE || msg->m_type == MR_MSG_GIF)
			 && (mrparam_get_int(msg->m_param, 'w', 0)<=0 || mrparam_get_int(msg->m_param, 'h', 0)<=0) ) {
				/* set width/height of images, if not yet done */
				unsigned char* buf = NULL; size_t buf_bytes; uint32_t w, h;
				if( mr_read_file(pathNfilename, (void**)&buf, &buf_bytes, msg->m_mailbox) ) {
					if( mr_get_filemeta(buf, buf_bytes, &w, &h) ) {
						mrparam_set_int(msg->m_param, 'w', w);
						mrparam_set_int(msg->m_param, 'h', h);
					}
				}
				free(buf);
			}

			mrmailbox_log_info(ths->m_mailbox, 0, "Attaching \"%s\" for message type #%i.", pathNfilename, (int)msg->m_type);

			if( msg->m_text ) { free(msg->m_text); }
			if( msg->m_type == MR_MSG_AUDIO ) {
				char* filename = mr_get_filename(pathNfilename);
				char* author = mrparam_get(msg->m_param, 'N', "");
				char* title = mrparam_get(msg->m_param, 'n', "");
				msg->m_text = mr_mprintf("%s %s %s", filename, author, title); /* for outgoing messages, also add the mediainfo. For incoming messages, this is not needed as the filename is build from these information */
				free(filename);
				free(author);
				free(title);
			}
			else if( MR_MSG_MAKE_FILENAME_SEARCHABLE(msg->m_type) ) {
				msg->m_text = mr_get_filename(pathNfilename);
			}
			else if( MR_MSG_MAKE_SUFFIX_SEARCHABLE(msg->m_type) ) {
				msg->m_text = mr_get_filesuffix_lc(pathNfilename);
			}
		}
		else
		{
			mrmailbox_log_error(ths->m_mailbox, 0, "Attachment missing for message of type #%i.", (int)msg->m_type); /* should not happen */
			goto cleanup;
		}
	}
	else
	{
		mrmailbox_log_error(ths->m_mailbox, 0, "Cannot send messages of type #%i.", (int)msg->m_type); /* should not happen */
		goto cleanup;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql);
	mrsqlite3_begin_transaction__(ths->m_mailbox->m_sql);

		ths->m_mailbox->m_smtp->m_log_connect_errors = 1;

		msg->m_id = mrchat_send_msg__(ths, msg, mr_create_smeared_timestamp__());

	mrsqlite3_commit__(ths->m_mailbox->m_sql);
	mrsqlite3_unlock(ths->m_mailbox->m_sql);

cleanup:
	free(pathNfilename);
	return msg->m_id;
}


/*******************************************************************************
 * Handle Group Chats
 ******************************************************************************/


int mrmailbox_group_explicitly_left__(mrmailbox_t* mailbox, const char* grpid)
{
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_FROM_leftgrps_WHERE_grpid, "SELECT id FROM leftgrps WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	return (sqlite3_step(stmt)==SQLITE_ROW);
}


void mrmailbox_set_group_explicitly_left__(mrmailbox_t* mailbox, const char* grpid)
{
	if( !mrmailbox_group_explicitly_left__(mailbox, grpid) )
	{
		sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, "INSERT INTO leftgrps (grpid) VALUES(?);");
		sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
}


static int mrmailbox_real_group_exists__(mrmailbox_t* mailbox, uint32_t chat_id)
{
	sqlite3_stmt* stmt;
	int           ret = 0;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL
	 || chat_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		return 0;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_chats_WHERE_id,
		"SELECT id FROM chats WHERE id=? AND type=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, MR_CHAT_GROUP);

	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = 1;
	}

	return ret;
}


int mrmailbox_add_contact_to_chat__(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t contact_id)
{
	/* add a contact to a chat; the function does not check the type or if any of the record exist or are already added to the chat! */
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, INSERT_INTO_chats_contacts,
		"INSERT INTO chats_contacts (chat_id, contact_id) VALUES(?, ?)");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	return (sqlite3_step(stmt)==SQLITE_DONE)? 1 : 0;
}


uint32_t mrmailbox_create_group_chat(mrmailbox_t* mailbox, const char* chat_name)
{
	uint32_t      chat_id = 0;
	int           locked = 0;
	char*         draft_txt = NULL, *grpid = NULL;
	sqlite3_stmt* stmt = NULL;

	if( mailbox == NULL || chat_name==NULL || chat_name[0]==0 ) {
		return 0;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		draft_txt = mrstock_str_repl_string(MR_STR_NEWGROUPDRAFT, chat_name);
		grpid = mr_create_id();

		stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
			"INSERT INTO chats (type, name, draft_timestamp, draft_txt, grpid, param) VALUES(?, ?, ?, ?, ?, 'U=1');" /*'U'npromoted group*/ );
		sqlite3_bind_int  (stmt, 1, MR_CHAT_GROUP);
		sqlite3_bind_text (stmt, 2, chat_name, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 3, time(NULL));
		sqlite3_bind_text (stmt, 4, draft_txt, -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 5, grpid, -1, SQLITE_STATIC);
		if(  sqlite3_step(stmt)!=SQLITE_DONE ) {
			goto cleanup;
		}

		if( (chat_id=sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj)) == 0 ) {
			goto cleanup;
		}

		if( mrmailbox_add_contact_to_chat__(mailbox, chat_id, MR_CONTACT_ID_SELF) ) {
			goto cleanup;
		}

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( stmt) { sqlite3_finalize(stmt); }
	free(draft_txt);
	free(grpid);

	if( chat_id ) {
		mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, 0, 0);
	}

	return chat_id;
}


int mrmailbox_set_chat_name(mrmailbox_t* mailbox, uint32_t chat_id, const char* new_name)
{
	/* the function only sets the names of group chats; normal chats get their names from the contacts */
	int       success = 0, locked = 0;
	mrchat_t* chat = mrchat_new(mailbox);
	mrmsg_t*  msg = mrmsg_new();
	char*     q3 = NULL;

	if( mailbox==NULL || new_name==NULL || new_name[0]==0 ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( 0==mrmailbox_real_group_exists__(mailbox, chat_id)
		 || 0==mrchat_load_from_db__(chat, chat_id) ) {
			goto cleanup;
		}

		if( !IS_SELF_IN_GROUP__ ) {
			mrmailbox_log_error(mailbox, MR_ERR_SELF_NOT_IN_GROUP, NULL);
			goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
		}

		q3 = sqlite3_mprintf("UPDATE chats SET name=%Q WHERE id=%i;", new_name, chat_id);
		if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* send a status mail to all group members */
	if( DO_SEND_STATUS_MAILS )
	{
		msg->m_type = MR_MSG_TEXT;
		msg->m_text = mrstock_str_repl_string2(MR_STR_MSGGRPNAME, chat->m_name, new_name);
		mrparam_set_int(msg->m_param, 'S', MR_SYSTEM_GROUPNAME_CHANGED);
		msg->m_id = mrchat_send_msg(chat, msg);
		mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
	}
	mailbox->m_cb(mailbox, MR_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( q3 ) { sqlite3_free(q3); }
	mrchat_unref(chat);
	mrmsg_unref(msg);
	return success;
}


int mrmailbox_get_chat_contact_count__(mrmailbox_t* mailbox, uint32_t chat_id)
{
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_chats_contacts_WHERE_chat_id,
		"SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		return sqlite3_column_int(stmt, 0);
	}
	return 0;
}


int mrmailbox_is_contact_in_chat__(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t contact_id)
{
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_void_FROM_chats_contacts_WHERE_chat_id_AND_contact_id,
		"SELECT contact_id FROM chats_contacts WHERE chat_id=? AND contact_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	return (sqlite3_step(stmt) == SQLITE_ROW)? 1 : 0;
}


int mrmailbox_is_contact_in_chat(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t contact_id)
{
	/* this function works for group and for normal chats, however, it is more useful for group chats.
	MR_CONTACT_ID_SELF may be used to check, if the user itself is in a group chat (MR_CONTACT_ID_SELF is not added to normal chats) */
	int ret = 0;
	if( mailbox ) {
		mrsqlite3_lock(mailbox->m_sql);
			ret = mrmailbox_is_contact_in_chat__(mailbox, chat_id, contact_id);
		mrsqlite3_unlock(mailbox->m_sql);
	}
	return ret;
}


int mrmailbox_add_contact_to_chat(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t contact_id /*may be MR_CONTACT_ID_SELF*/)
{
	int          success = 0, locked = 0;
	mrcontact_t* contact = mrmailbox_get_contact(mailbox, contact_id); /* mrcontact_load_from_db__() does not load SELF fields */
	mrchat_t*    chat = mrchat_new(mailbox);
	mrmsg_t*     msg = mrmsg_new();
	char*        self_addr = NULL;

	if( mailbox == NULL || contact == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( 0==mrmailbox_real_group_exists__(mailbox, chat_id) /*this also makes sure, not contacts are added to special or normal chats*/
		 || (0==mrmailbox_real_contact_exists__(mailbox, contact_id) && contact_id!=MR_CONTACT_ID_SELF)
		 || 0==mrchat_load_from_db__(chat, chat_id) ) {
			goto cleanup;
		}

		if( !IS_SELF_IN_GROUP__ ) {
			mrmailbox_log_error(mailbox, MR_ERR_SELF_NOT_IN_GROUP, NULL);
			goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
		}

		self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", "");
		if( strcasecmp(contact->m_addr, self_addr)==0 ) {
			goto cleanup; /* ourself is added using MR_CONTACT_ID_SELF, do not add it explicitly. if SELF is not in the group, members cannot be added at all. */
		}

		if( 1==mrmailbox_is_contact_in_chat__(mailbox, chat_id, contact_id) ) {
			success = 1;
			goto cleanup;
		}

		if( 0==mrmailbox_add_contact_to_chat__(mailbox, chat_id, contact_id) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* send a status mail to all group members */
	if( DO_SEND_STATUS_MAILS )
	{
		msg->m_type = MR_MSG_TEXT;
		msg->m_text = mrstock_str_repl_string(MR_STR_MSGADDMEMBER, (contact->m_authname&&contact->m_authname[0])? contact->m_authname : contact->m_addr);
		mrparam_set_int(msg->m_param, 'S', MR_SYSTEM_MEMBER_ADDED_TO_GROUP);
		mrparam_set    (msg->m_param, 'E', contact->m_addr);
		msg->m_id = mrchat_send_msg(chat, msg);
		mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
	}
	mailbox->m_cb(mailbox, MR_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrchat_unref(chat);
	mrcontact_unref(contact);
	mrmsg_unref(msg);
	free(self_addr);
	return success;
}


int mrmailbox_remove_contact_from_chat(mrmailbox_t* mailbox, uint32_t chat_id, uint32_t contact_id /*may be MR_CONTACT_ID_SELF*/)
{
	int          success = 0, locked = 0;
	mrcontact_t* contact = mrmailbox_get_contact(mailbox, contact_id); /* mrcontact_load_from_db__() does not load SELF fields */
	mrchat_t*    chat = mrchat_new(mailbox);
	mrmsg_t*     msg = mrmsg_new();
	char*        q3 = NULL;

	if( mailbox == NULL || (contact_id<=MR_CONTACT_ID_LAST_SPECIAL && contact_id!=MR_CONTACT_ID_SELF) ) {
		goto cleanup; /* we do not check if "contact_id" exists but just delete all records with the id from chats_contacts */
	}                 /* this allows to delete pending references to deleted contacts.  Of course, this should _not_ happen. */

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( 0==mrmailbox_real_group_exists__(mailbox, chat_id)
		 || 0==mrchat_load_from_db__(chat, chat_id) ) {
			goto cleanup;
		}

		if( !IS_SELF_IN_GROUP__ ) {
			mrmailbox_log_error(mailbox, MR_ERR_SELF_NOT_IN_GROUP, NULL);
			goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* send a status mail to all group members - we need to do this before we update the database -
	otherwise the !IS_SELF_IN_GROUP__-check in mrchat_send_msg() will fail. */
	if( contact )
	{
		if( DO_SEND_STATUS_MAILS )
		{
			msg->m_type = MR_MSG_TEXT;
			if( contact->m_id == MR_CONTACT_ID_SELF ) {
				mrmailbox_set_group_explicitly_left__(mailbox, chat->m_grpid);
				msg->m_text = mrstock_str(MR_STR_MSGGROUPLEFT);
			}
			else {
				msg->m_text = mrstock_str_repl_string(MR_STR_MSGDELMEMBER, (contact->m_authname&&contact->m_authname[0])? contact->m_authname : contact->m_addr);
			}
			mrparam_set_int(msg->m_param, 'S', MR_SYSTEM_MEMBER_REMOVED_FROM_GROUP);
			mrparam_set    (msg->m_param, 'E', contact->m_addr);
			msg->m_id = mrchat_send_msg(chat, msg);
			mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
		}
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i AND contact_id=%i;", chat_id, contact_id);
		if( !mrsqlite3_execute__(mailbox->m_sql, q3) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	mailbox->m_cb(mailbox, MR_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( q3 ) { sqlite3_free(q3); }
	mrchat_unref(chat);
	mrcontact_unref(contact);
	mrmsg_unref(msg);
	return success;
}
