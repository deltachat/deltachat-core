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
 * File:    mrchatlist.c
 * Authors: Björn Petersen
 * Purpose: See header
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"


mrchatlist_t* mrchatlist_new(mrmailbox_t* mailbox)
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

	mrchatlist_empty(ths);
	carray_free(ths->m_chats);
	free(ths);
}


void mrchatlist_empty(mrchatlist_t* ths)
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
	if( ths == NULL || ths->m_chats == NULL ) {
		return 0; /* error */
	}

	return (size_t)carray_count(ths->m_chats);
}


mrchat_t* mrchatlist_get_chat(mrchatlist_t* ths, size_t index)
{
	if( ths == NULL || ths->m_chats == NULL || index >= (size_t)carray_count(ths->m_chats) ) {
		return 0; /* error */
	}

	return mrchat_ref((mrchat_t*)carray_get(ths->m_chats, index));
}


int mrchatlist_load_from_db_(mrchatlist_t* ths)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		return 0; /* error */
	}

	mrchatlist_empty(ths);

	/* select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min */
	stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_fields_FROM_chats,
		MR_GET_CHATS_PREFIX MR_GET_CHATS_POSTFIX " ORDER BY timestamp;");
	if( stmt==NULL ) {
		goto GetChatList_Cleanup;
	}

    while( sqlite3_step(stmt) == SQLITE_ROW ) {
		mrchat_t* chat = mrchat_new(ths->m_mailbox);
		if( mrchat_set_from_stmt(chat, stmt) ) {
			carray_add(ths->m_chats, (void*)chat, NULL);
		}
    }

	/* success */
	success = 1;

	/* cleanup */
GetChatList_Cleanup:
	return success;
}
