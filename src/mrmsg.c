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
 * Purpose: MrMsg represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrmsg.h"
#include "mrtools.h"
#include "mrlog.h"


mrmsg_t* mrmsg_new(struct mrmailbox_t* mailbox)
{
	mrmsg_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmsg_t)))==NULL ) {
		return NULL; /* error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox   = mailbox;
	ths->m_id        = 0;
	ths->m_chat_id   = 0;
	ths->m_from_id   = 0;
	ths->m_timestamp = 0;
	ths->m_type      = MR_MSG_UNDEFINED;
	ths->m_state     = MR_STATE_UNDEFINED;
	ths->m_msg       = NULL;

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

	if( ths->m_msg ) {
		free(ths->m_msg);
		ths->m_msg = NULL;
	}
}



int mrmsg_set_msg_from_stmt(mrmsg_t* ths, sqlite3_stmt* row, int row_offset)
{
	mrmsg_empty(ths);

	ths->m_id        =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_from_id   =          (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_timestamp =            (time_t)sqlite3_column_int64(row, row_offset++);
	ths->m_type      =                    sqlite3_column_int  (row, row_offset++);
	ths->m_state     =                    sqlite3_column_int  (row, row_offset++);
	ths->m_msg       = safe_strdup((char*)sqlite3_column_text (row, row_offset++));

	return 1;
}


char* mrmsg_get_summary(mrmsg_t* ths, long flags)
{
	char* from = NULL;
	char* message = NULL;

	if( ths->m_from_id == 0 ) {
		from = safe_strdup("You");
	}
	else {
		mrcontact_t* contact = mrcontact_new(ths->m_mailbox);
		mrcontact_load_from_db(contact, ths->m_from_id);
		if( contact->m_name ) {
			from = safe_strdup(contact->m_name);
			mrcontact_unref(contact);
		}
		else {
			from = safe_strdup("BadContactId");
		}
	}

	if( ths->m_msg ) {
		message = safe_strdup(ths->m_msg); /* we do not shorten the message, this can be done by the caller */
		if( flags & MR_UNWRAP ) {
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


size_t mr_get_msg_cnt_(mrmailbox_t* mailbox) /* static function */
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no messages - this is no error (needed eg. for information) */
	}

	sqlite3_stmt* s = mailbox->m_sql->m_pd[SELECT_COUNT_FROM_msg];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql);
		mr_log_error("mr_get_msg_cnt() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(s, 0); /* success */
}


int mr_message_id_exists(mrmailbox_t* mailbox, const char* rfc724_mid) /* static function */
{
	/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space) */
	sqlite3_stmt* s = mailbox->m_sql->m_pd[SELECT_id_FROM_msg_m];
	sqlite3_reset (s);
	sqlite3_bind_text(s, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		return 0; /* record does not exist */
	}

	return 1; /* record does exist */
}


/*******************************************************************************
 * Message lists
 ******************************************************************************/


mrmsglist_t* mrmsglist_new(void)
{
	mrmsglist_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmsglist_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_msgs = carray_new(128);

	return ths;
}


void mrmsglist_unref(mrmsglist_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_msgs )
	{
		int i, cnt = carray_count(ths->m_msgs);
		for( i = 0; i < cnt; i++ )
		{
			mrmsg_t* msg = (mrmsg_t*)carray_get(ths->m_msgs, i);
			mrmsg_unref(msg);
		}

		carray_free(ths->m_msgs);
		ths->m_msgs = NULL;
	}
}
