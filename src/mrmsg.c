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


mrmsg_t* mrmsg_new(struct mrmailbox_t* mailbox)
{
	mrmsg_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmsg_t)))==NULL ) {
		exit(15); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox   = mailbox;
	ths->m_id        = 0;
	ths->m_chat_id   = 0; /* 0=unset, 1=unknwon sender ... >9=real chats */
	ths->m_from_id   = 0; /* 0=unset, 1=self ... >9=real contacts */
	ths->m_to_id     = 0; /* 0=unset, 1=self ... >9=real contacts */
	ths->m_timestamp = 0;
	ths->m_type      = MR_MSG_UNDEFINED;
	ths->m_state     = MR_STATE_UNDEFINED;
	ths->m_text      = NULL;
	ths->m_param     = NULL;
	ths->m_bytes     = 0;

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
	free(ths);
}


void mrmsg_empty(mrmsg_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	free(ths->m_text);
	ths->m_text = NULL;

	free(ths->m_param);
	ths->m_param = NULL;
}



int mrmsg_set_from_stmt_(mrmsg_t* ths, sqlite3_stmt* row, int row_offset) /* field order must be MR_MSG_FIELDS */
{
	mrmsg_empty(ths);

	ths->m_id        =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_chat_id   =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_from_id   =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_to_id     =          (uint32_t)sqlite3_column_int  (row, row_offset++);

	ths->m_timestamp =            (time_t)sqlite3_column_int64(row, row_offset++);
	ths->m_type      =                    sqlite3_column_int  (row, row_offset++);
	ths->m_state     =                    sqlite3_column_int  (row, row_offset++);

	ths->m_text      = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_param     = safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_bytes     =                    sqlite3_column_int  (row, row_offset++);

	return 1;
}


/*******************************************************************************
 * Static functions
 ******************************************************************************/


size_t mr_get_assigned_msg_cnt_(mrmailbox_t* mailbox) /* the number of messages assigned to a chat */
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no messages - this is no error (needed eg. for information) */
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_assigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id>?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_assigned_msg_cnt_() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(stmt, 0); /* success */
}


size_t mr_get_unassigned_msg_cnt_(mrmailbox_t* mailbox) /* the number of messages not assigned to a chat */
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no messages - this is no error (needed eg. for information) */
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_unassigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id<=?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_unassigned_msg_cnt_() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(stmt, 0); /* success */
}


int mr_message_id_exists_(mrmailbox_t* mailbox, const char* rfc724_mid) /* static function */
{
	/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space) */
	sqlite3_stmt* s = mrsqlite3_predefine(mailbox->m_sql, SELECT_i_FROM_msgs_m, "SELECT id FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(s, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		return 0; /* record does not exist */
	}

	return 1; /* record does exist */
}


