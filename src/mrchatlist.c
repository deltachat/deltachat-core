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
#include "mrtools.h"
#include "mrlog.h"

#define CLASS_MAGIC 1279576749


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrchatlist_load_from_db__(mrchatlist_t* ths)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;
	int           show_deaddrop;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		goto cleanup;
	}

	mrchatlist_empty(ths);

	show_deaddrop = mrsqlite3_get_config_int__(ths->m_mailbox->m_sql, "show_deaddrop", 0);

	/* select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min */
	stmt = mrsqlite3_predefine__(ths->m_mailbox->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs,
		"SELECT c.id, m.id FROM chats c "
			" LEFT JOIN msgs m ON (c.id=m.chat_id AND m.timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=c.id)) "
			" WHERE (c.id>? OR c.id=?) AND blocked=0"
			" GROUP BY c.id " /* GROUP BY is needed as there may be several messages with the same timestamp */
			" ORDER BY MAX(c.draft_timestamp, m.timestamp) DESC,m.id DESC;" /* the list starts with the newest chats */
			);
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

	MR_INIT_REFERENCE

	ths->m_mailbox = mailbox;
	if( (ths->m_chatNlastmsg_ids=carray_new(128))==NULL ) {
		exit(32);
	}

	return ths;
}


void mrchatlist_unref(mrchatlist_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

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

	#define       SUMMARY_CHARACTERS 160 /* in practice, the user additinally cuts the string himself pixel-accurate */
	mrpoortext_t* ret = mrpoortext_new();
	uint32_t      lastmsg_id = 0;
	mrmsg_t*      lastmsg = NULL;
	mrcontact_t*  lastcontact = NULL;

	if( chatlist == NULL || index >= chatlist->m_cnt || chat == NULL ) {
		ret->m_text = safe_strdup("ErrNoChat");
		goto cleanup;
	}

	lastmsg_id = (uint32_t)(uintptr_t)carray_get(chatlist->m_chatNlastmsg_ids, index*IDS_PER_RESULT+1);

	/* load data from database */
	if( lastmsg_id )
	{
		mrsqlite3_lock(chatlist->m_mailbox->m_sql);

			lastmsg = mrmsg_new();
			mrmsg_load_from_db__(lastmsg, chatlist->m_mailbox->m_sql, lastmsg_id);

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
		ret->m_title = mrstock_str(MR_STR_DRAFT);
		ret->m_title_meaning = MR_TITLE_DRAFT;

		ret->m_text = safe_strdup(chat->m_draft_text);
		mr_truncate_n_unwrap_str(ret->m_text, SUMMARY_CHARACTERS, 1);

		ret->m_timestamp = chat->m_draft_timestamp;
	}
	else if( lastmsg == NULL || lastmsg->m_from_id == 0 )
	{
		/* no messages */
		ret->m_text = mrstock_str(MR_STR_NO_MESSAGES);
	}
	else
	{
		/* show the last message */
		if( lastmsg->m_from_id == MR_CONTACT_ID_SELF )
		{
			ret->m_title = mrstock_str(MR_STR_SELF);
			ret->m_title_meaning = MR_TITLE_SELF;
		}
		else if( chat->m_type==MR_CHAT_GROUP )
		{
			if( lastcontact->m_name && lastcontact->m_name[0] ) {
				ret->m_title = mr_get_first_name(lastcontact->m_name);
				ret->m_title_meaning = MR_TITLE_USERNAME;
			}
			else if( lastcontact->m_addr && lastcontact->m_addr[0] ) {
				ret->m_title = safe_strdup(lastcontact->m_addr);
				ret->m_title_meaning = MR_TITLE_USERNAME;
			}
			else {
				ret->m_title = safe_strdup("Unknown contact");
				ret->m_title_meaning = MR_TITLE_USERNAME;
			}
		}

		ret->m_text = mrmsg_get_summary_by_raw(lastmsg->m_type, lastmsg->m_text, SUMMARY_CHARACTERS);

		ret->m_timestamp = lastmsg->m_timestamp;
		ret->m_state     = lastmsg->m_state;
	}

cleanup:
	mrmsg_unref(lastmsg);
	mrcontact_unref(lastcontact);
	return ret;
}



