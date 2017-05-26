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
 * File:    mrchatlist.c
 * Purpose: See header
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrtools.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrchatlist_load_from_db__(mrchatlist_t* ths, const char* query__)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;
	int           show_deaddrop;
	char*         strLikeCmd = NULL, *query = NULL;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		goto cleanup;
	}

	mrchatlist_empty(ths);

	show_deaddrop = mrsqlite3_get_config_int__(ths->m_mailbox->m_sql, "show_deaddrop", 0);

	/* select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min */
	#define QUR1 "SELECT c.id, m.id FROM chats c " \
	                " LEFT JOIN msgs m ON (c.id=m.chat_id AND m.timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=c.id)) " \
	                " WHERE (c.id>? OR c.id=?) AND blocked=0"
	#define QUR2    " GROUP BY c.id " /* GROUP BY is needed as there may be several messages with the same timestamp */ \
	                " ORDER BY MAX(c.draft_timestamp, IFNULL(m.timestamp,0)) DESC,m.id DESC;" /* the list starts with the newest chats */

	if( query__ )
	{
		query = safe_strdup(query__);
		mr_trim(query);
		if( query[0]==0 ) {
			success = 1; /*empty result*/
			goto cleanup;
		}
		strLikeCmd = mr_mprintf("%%%s%%", query);
		stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs_WHERE_query,
			QUR1 " AND c.name LIKE ? " QUR2);
		sqlite3_bind_text(stmt, 3, strLikeCmd, -1, SQLITE_STATIC);
	}
	else
	{
		stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs,
			QUR1 QUR2);
	}

	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
	sqlite3_bind_int(stmt, 2, show_deaddrop? MR_CHAT_ID_DEADDROP : 0);


    while( sqlite3_step(stmt) == SQLITE_ROW )
    {
		#define IDS_PER_RESULT 2
		carray_add(ths->m_chatNlastmsg_ids, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		carray_add(ths->m_chatNlastmsg_ids, (void*)(uintptr_t)sqlite3_column_int(stmt, 1), NULL);
    }

	ths->m_cnt = carray_count(ths->m_chatNlastmsg_ids)/IDS_PER_RESULT;
	success = 1;

cleanup:
	free(query);
	free(strLikeCmd);
	return success;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrchatlist_t* mrchatlist_new(mrmailbox_t* mailbox)
{
	mrchatlist_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrchatlist_t)))==NULL ) {
		exit(20);
	}

	ths->m_mailbox = mailbox;
	if( (ths->m_chatNlastmsg_ids=carray_new(128))==NULL ) {
		exit(32);
	}

	return ths;
}


void mrchatlist_unref(mrchatlist_t* ths)
{
	if( ths==NULL ) {
		return;
	}

	mrchatlist_empty(ths);
	carray_free(ths->m_chatNlastmsg_ids);
	free(ths);
}


void mrchatlist_empty(mrchatlist_t* ths)
{
	if( ths  ) {
		ths->m_cnt = 0;
		carray_set_size(ths->m_chatNlastmsg_ids, 0);
	}
}


size_t mrchatlist_get_cnt(mrchatlist_t* ths)
{
	if( ths == NULL ) {
		return 0;
	}

	return ths->m_cnt;
}


mrchat_t* mrchatlist_get_chat_by_index(mrchatlist_t* ths, size_t index)
{
	if( ths == NULL || ths->m_chatNlastmsg_ids == NULL || index >= ths->m_cnt ) {
		return 0;
	}

	return mrmailbox_get_chat(ths->m_mailbox, (uint32_t)(uintptr_t)carray_get(ths->m_chatNlastmsg_ids, index*IDS_PER_RESULT));
}


mrpoortext_t* mrchatlist_get_summary_by_index(mrchatlist_t* chatlist, size_t index, mrchat_t* chat)
{
	/* The summary is created by the chat, not by the last message.
	This is because we may want to display drafts here or stuff as
	"is typing".
	Also, sth. as "No messages" would not work if the summary comes from a
	message. */

	mrpoortext_t* ret = mrpoortext_new();
	uint32_t      lastmsg_id = 0;
	mrmsg_t*      lastmsg = NULL;
	mrcontact_t*  lastcontact = NULL;

	if( chatlist == NULL || index >= chatlist->m_cnt || chat == NULL ) {
		ret->m_text2 = safe_strdup("ErrNoChat");
		goto cleanup;
	}

	lastmsg_id = (uint32_t)(uintptr_t)carray_get(chatlist->m_chatNlastmsg_ids, index*IDS_PER_RESULT+1);

	/* load data from database */
	if( lastmsg_id )
	{
		mrsqlite3_lock(chatlist->m_mailbox->m_sql);

			lastmsg = mrmsg_new();
			mrmsg_load_from_db__(lastmsg, chatlist->m_mailbox, lastmsg_id);

			if( lastmsg->m_from_id != MR_CONTACT_ID_SELF  &&  chat->m_type == MR_CHAT_GROUP )
			{
				lastcontact = mrcontact_new();
				mrcontact_load_from_db__(lastcontact, chatlist->m_mailbox->m_sql, lastmsg->m_from_id);
			}

		mrsqlite3_unlock(chatlist->m_mailbox->m_sql);
	}

	if( chat->m_draft_timestamp
	 && chat->m_draft_text
	 && (lastmsg==NULL || chat->m_draft_timestamp>lastmsg->m_timestamp) )
	{
		/* show the draft as the last message */
		ret->m_text1 = mrstock_str(MR_STR_DRAFT);
		ret->m_text1_meaning = MR_TEXT1_DRAFT;

		ret->m_text2 = safe_strdup(chat->m_draft_text);
		mr_truncate_n_unwrap_str(ret->m_text2, MR_SUMMARY_CHARACTERS, 1);

		ret->m_timestamp = chat->m_draft_timestamp;
	}
	else if( lastmsg == NULL || lastmsg->m_from_id == 0 )
	{
		/* no messages */
		ret->m_text2 = mrstock_str(MR_STR_NOMESSAGES);
	}
	else
	{
		/* show the last message */
		mrpoortext_fill(ret, lastmsg, chat, lastcontact);
	}

cleanup:
	mrmsg_unref(lastmsg);
	mrcontact_unref(lastcontact);
	return ret;
}



