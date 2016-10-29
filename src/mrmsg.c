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
 * File:    mrmsg.c
 * Authors: Björn Petersen
 * Purpose: mrmsg_t represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"
#include "mrjob.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrmsg_set_from_stmt_(mrmsg_t* ths, sqlite3_stmt* row, int row_offset) /* field order must be MR_MSG_FIELDS */
{
	mrmsg_empty(ths);

	ths->m_id        =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_chat_id   =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_from_id   =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_to_id     =           (uint32_t)sqlite3_column_int  (row, row_offset++);

	ths->m_timestamp =             (time_t)sqlite3_column_int64(row, row_offset++);
	ths->m_type      =                     sqlite3_column_int  (row, row_offset++);
	ths->m_state     =                     sqlite3_column_int  (row, row_offset++);

	ths->m_text      =  safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	mrparam_set_packed(ths->m_param,(char*)sqlite3_column_text (row, row_offset++));
	ths->m_bytes     =                     sqlite3_column_int  (row, row_offset++);

	return 1;
}


int mrmsg_load_from_db_(mrmsg_t* ths, mrmailbox_t* mailbox, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || mailbox == NULL ) {
		return 0;
	}

	mrmsg_empty(ths);

	stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_fields_FROM_msg_i,
		"SELECT " MR_MSG_FIELDS " FROM msgs m WHERE m.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	if( !mrmsg_set_from_stmt_(ths, stmt, 0) ) {
		return 0;
	}

	return 1;
}


void mrmailbox_update_msg_chat_id_(mrmailbox_t* mailbox, uint32_t msg_id, uint32_t chat_id)
{
    sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, UPDATE_msgs_SET_chat_id_WHERE_id,
		"UPDATE msgs SET chat_id=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
}



size_t mrmailbox_get_real_msg_cnt_(mrmailbox_t* mailbox)
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_assigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id>?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_assigned_msg_cnt_() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


size_t mrmailbox_get_strangers_msg_cnt_(mrmailbox_t* mailbox)
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_unassigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_STRANGERS);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_unassigned_msg_cnt_() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0); /* success */
}


int mrmailbox_message_id_exists_(mrmailbox_t* mailbox, const char* rfc724_mid) /* static function */
{
	/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space) */
	sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_i_FROM_msgs_m, "SELECT id FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0; /* record does not exist */
	}

	return 1; /* record does exist */
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrmsg_t* mrmsg_new()
{
	mrmsg_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrmsg_t)))==NULL ) {
		exit(15); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_type      = MR_MSG_UNDEFINED;
	ths->m_state     = MR_STATE_UNDEFINED;
	ths->m_param     = mrparam_new();

	return ths;
}


mrmsg_t* mrmsg_ref(mrmsg_t* ths)
{
	MR_INC_REFERENCE
}


void mrmsg_unref(mrmsg_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrmsg_empty(ths);
	mrparam_unref(ths->m_param);
	free(ths);
}


void mrmsg_empty(mrmsg_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	free(ths->m_text);
	ths->m_text = NULL;

	mrparam_set_packed(ths->m_param, NULL);
}


mrmsg_t* mrmailbox_get_msg_by_id(mrmailbox_t* ths, uint32_t id)
{
	int success = 0;
	int db_locked = 0;
	mrmsg_t* obj = mrmsg_new();

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

		if( !mrmsg_load_from_db_(obj, ths, id) ) {
			goto cleanup;
		}

		success = 1;

cleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( success ) {
		return obj;
	}
	else {
		mrmsg_unref(obj);
		return NULL;
	}
}


/*******************************************************************************
 * Delete messages
 ******************************************************************************/


void mrmailbox_delete_msg_from_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
}


int mrmailbox_delete_msg_by_id(mrmailbox_t* ths, uint32_t msg_id)
{
	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	mrsqlite3_begin_transaction(ths->m_sql);

		mrmailbox_update_msg_chat_id_(ths, msg_id, MR_CHAT_ID_TRASH);
		mrjob_add_(ths, MRJ_DELETE_MSG_FROM_IMAP, msg_id, NULL); /* results in a call to mrmailbox_delete_msg_from_imap() */

	mrsqlite3_commit(ths->m_sql);
	mrsqlite3_unlock(ths->m_sql);

	return 1;
}

