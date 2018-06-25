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
 ******************************************************************************/


#include "dc_context.h"


#define MR_CHATLIST_MAGIC 0xc4a71157


/**
 * Create a chatlist object in memory.
 *
 * @private @memberof dc_chatlist_t
 *
 * @param mailbox The mailbox object that should be stored in the chatlist object.
 *
 * @return New and empty chatlist object, must be freed using dc_chatlist_unref().
 */
dc_chatlist_t* dc_chatlist_new(dc_context_t* mailbox)
{
	dc_chatlist_t* ths = NULL;

	if( (ths=calloc(1, sizeof(dc_chatlist_t)))==NULL ) {
		exit(20);
	}

	ths->m_magic   = MR_CHATLIST_MAGIC;
	ths->m_context = mailbox;
	if( (ths->m_chatNlastmsg_ids=dc_array_new(mailbox, 128))==NULL ) {
		exit(32);
	}

	return ths;
}


/**
 * Free a chatlist object.
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object to free, created eg. by dc_get_chatlist(), dc_search_msgs().
 *
 * @return None.
 *
 */
void dc_chatlist_unref(dc_chatlist_t* chatlist)
{
	if( chatlist==NULL || chatlist->m_magic != MR_CHATLIST_MAGIC ) {
		return;
	}

	dc_chatlist_empty(chatlist);
	dc_array_unref(chatlist->m_chatNlastmsg_ids);
	chatlist->m_magic = 0;
	free(chatlist);
}


/**
 * Empty a chatlist object.
 *
 * @private @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object to empty.
 *
 * @return None.
 */
void dc_chatlist_empty(dc_chatlist_t* chatlist)
{
	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC ) {
		return;
	}

	chatlist->m_cnt = 0;
	dc_array_empty(chatlist->m_chatNlastmsg_ids);
}


/**
 * Find out the number of chats in a chatlist.
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object as created eg. by dc_get_chatlist().
 *
 * @return Returns the number of items in a dc_chatlist_t object. 0 on errors or if the list is empty.
 */
size_t dc_chatlist_get_cnt(dc_chatlist_t* chatlist)
{
	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC ) {
		return 0;
	}

	return chatlist->m_cnt;
}


/**
 * Get a single chat ID of a chatlist.
 *
 * To get the message object from the message ID, use dc_get_chat().
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object as created eg. by dc_get_chatlist().
 *
 * @param index The index to get the chat ID for.
 *
 * @return Returns the chat_id of the item at the given index.  Index must be between
 *     0 and dc_chatlist_get_cnt()-1.
 */
uint32_t dc_chatlist_get_chat_id(dc_chatlist_t* chatlist, size_t index)
{
	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC || chatlist->m_chatNlastmsg_ids == NULL || index >= chatlist->m_cnt ) {
		return 0;
	}

	return dc_array_get_id(chatlist->m_chatNlastmsg_ids, index*MR_CHATLIST_IDS_PER_RESULT);
}


/**
 * Get a single message ID of a chatlist.
 *
 * To get the message object from the message ID, use dc_get_msg().
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object as created eg. by dc_get_chatlist().
 *
 * @param index The index to get the chat ID for.
 *
 * @return Returns the message_id of the item at the given index.  Index must be between
 *     0 and dc_chatlist_get_cnt()-1.  If there is no message at the given index (eg. the chat may be empty), 0 is returned.
 */
uint32_t dc_chatlist_get_msg_id(dc_chatlist_t* chatlist, size_t index)
{
	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC || chatlist->m_chatNlastmsg_ids == NULL || index >= chatlist->m_cnt ) {
		return 0;
	}

	return dc_array_get_id(chatlist->m_chatNlastmsg_ids, index*MR_CHATLIST_IDS_PER_RESULT+1);
}


/**
 * Get a summary for a chatlist index.
 *
 * The summary is returned by a dc_lot_t object with the following fields:
 *
 * - dc_lot_t::m_text1: contains the username or the strings "Me", "Draft" and so on.
 *   The string may be colored by having a look at m_text1_meaning.
 *   If there is no such name or it should not be displayed, the element is NULL.
 *
 * - dc_lot_t::m_text1_meaning: one of DC_TEXT1_USERNAME, DC_TEXT1_SELF or DC_TEXT1_DRAFT.
 *   Typically used to show dc_lot_t::m_text1 with different colors. 0 if not applicable.
 *
 * - dc_lot_t::m_text2: contains an excerpt of the message text or strings as
 *   "No messages".  May be NULL of there is no such text (eg. for the archive link)
 *
 * - dc_lot_t::m_timestamp: the timestamp of the message.  0 if not applicable.
 *
 * - dc_lot_t::m_state: The state of the message as one of the DC_STATE_* constants (see #dc_msg_get_state()).  0 if not applicable.
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist to query as returned eg. from dc_get_chatlist().
 * @param index The index to query in the chatlist.
 * @param chat To speed up things, pass an already available chat object here.
 *     If the chat object is not yet available, it is faster to pass NULL.
 *
 * @return The summary as an dc_lot_t object. Must be freed using dc_lot_unref().  NULL is never returned.
 */
dc_lot_t* dc_chatlist_get_summary(dc_chatlist_t* chatlist, size_t index, dc_chat_t* chat /*may be NULL*/)
{
	/* The summary is created by the chat, not by the last message.
	This is because we may want to display drafts here or stuff as
	"is typing".
	Also, sth. as "No messages" would not work if the summary comes from a
	message. */

	dc_lot_t*      ret = dc_lot_new(); /* the function never returns NULL */
	int           locked = 0;
	uint32_t      lastmsg_id = 0;
	dc_msg_t*      lastmsg = NULL;
	dc_contact_t*  lastcontact = NULL;
	dc_chat_t*     chat_to_delete = NULL;

	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC || index >= chatlist->m_cnt ) {
		ret->m_text2 = safe_strdup("ErrBadChatlistIndex");
		goto cleanup;
	}

	lastmsg_id = dc_array_get_id(chatlist->m_chatNlastmsg_ids, index*MR_CHATLIST_IDS_PER_RESULT+1);

	/* load data from database */
	dc_sqlite3_lock(chatlist->m_context->m_sql);
	locked = 1;

		if( chat==NULL ) {
			chat = dc_chat_new(chatlist->m_context);
			chat_to_delete = chat;
			if( !dc_chat_load_from_db__(chat, dc_array_get_id(chatlist->m_chatNlastmsg_ids, index*MR_CHATLIST_IDS_PER_RESULT)) ) {
				ret->m_text2 = safe_strdup("ErrCannotReadChat");
				goto cleanup;
			}
		}

		if( lastmsg_id )
		{

			lastmsg = dc_msg_new();
			dc_msg_load_from_db__(lastmsg, chatlist->m_context, lastmsg_id);

			if( lastmsg->m_from_id != MR_CONTACT_ID_SELF  &&  MR_CHAT_TYPE_IS_MULTI(chat->m_type) )
			{
				lastcontact = dc_contact_new(chatlist->m_context);
				dc_contact_load_from_db__(lastcontact, chatlist->m_context->m_sql, lastmsg->m_from_id);
			}

		}

	dc_sqlite3_unlock(chatlist->m_context->m_sql);
	locked = 0;

	if( chat->m_id == MR_CHAT_ID_ARCHIVED_LINK )
	{
		ret->m_text2 = safe_strdup(NULL);
	}
	else if( chat->m_draft_timestamp
	      && chat->m_draft_text
	      && (lastmsg==NULL || chat->m_draft_timestamp>lastmsg->m_timestamp) )
	{
		/* show the draft as the last message */
		ret->m_text1 = mrstock_str(MR_STR_DRAFT);
		ret->m_text1_meaning = MR_TEXT1_DRAFT;

		ret->m_text2 = safe_strdup(chat->m_draft_text);
		mr_truncate_n_unwrap_str(ret->m_text2, MR_SUMMARY_CHARACTERS, 1/*unwrap*/);

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
		dc_lot_fill(ret, lastmsg, chat, lastcontact);
	}

cleanup:
	if( locked ) { dc_sqlite3_unlock(chatlist->m_context->m_sql); }
	dc_msg_unref(lastmsg);
	dc_contact_unref(lastcontact);
	dc_chat_unref(chat_to_delete);
	return ret;
}


/**
 * Helper function to get the associated mailbox object.
 *
 * @memberof dc_chatlist_t
 *
 * @param chatlist The chatlist object to empty.
 *
 * @return Mailbox object associated with the chatlist. NULL if none or on errors.
 */
dc_context_t* dc_chatlist_get_context(dc_chatlist_t* chatlist)
{
	if( chatlist == NULL || chatlist->m_magic != MR_CHATLIST_MAGIC ) {
		return NULL;
	}
	return chatlist->m_context;
}


/**
 * Library-internal.
 *
 * Calling this function is not thread-safe, locking is up to the caller.
 *
 * @private @memberof dc_chatlist_t
 */
int dc_chatlist_load_from_db__(dc_chatlist_t* ths, int listflags, const char* query__, uint32_t query_contact_id)
{
	//clock_t       start = clock();

	int           success = 0;
	int           add_archived_link_item = 0;
	sqlite3_stmt* stmt = NULL;
	char*         strLikeCmd = NULL, *query = NULL;

	if( ths == NULL || ths->m_magic != MR_CHATLIST_MAGIC || ths->m_context == NULL ) {
		goto cleanup;
	}

	dc_chatlist_empty(ths);

	/* select example with left join and minimum: http://stackoverflow.com/questions/7588142/mysql-left-join-min */
	#define QUR1 "SELECT c.id, m.id FROM chats c " \
	                " LEFT JOIN msgs m ON (c.id=m.chat_id AND m.hidden=0 AND m.timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=c.id AND hidden=0)) " /* not: `m.hidden` which would refer the outer select and takes lot of time*/ \
	                " WHERE c.id>" DC_STRINGIFY(MR_CHAT_ID_LAST_SPECIAL) " AND c.blocked=0"
	#define QUR2    " GROUP BY c.id " /* GROUP BY is needed as there may be several messages with the same timestamp */ \
	                " ORDER BY MAX(c.draft_timestamp, IFNULL(m.timestamp,0)) DESC,m.id DESC;" /* the list starts with the newest chats */

	// nb: the query currently shows messages from blocked contacts in groups.
	// however, for normal-groups, this is okay as the message is also returned by dc_get_chat_msgs()
	// (otherwise it would be hard to follow conversations, wa and tg do the same)
	// for the deaddrop, however, they should really be hidden, however, _currently_ the deaddrop is not
	// shown at all permanent in the chatlist.

	if( query_contact_id )
	{
		// show chats shared with a given contact
		stmt = dc_sqlite3_predefine__(ths->m_context->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs_WHERE_contact_id,
			QUR1 " AND c.id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?) " QUR2);
		sqlite3_bind_int(stmt, 1, query_contact_id);
	}
	else if( listflags & MR_GCL_ARCHIVED_ONLY )
	{
		/* show archived chats */
		stmt = dc_sqlite3_predefine__(ths->m_context->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs_WHERE_archived,
			QUR1 " AND c.archived=1 " QUR2);
	}
	else if( query__==NULL )
	{
		/* show normal chatlist  */
		if( !(listflags & MR_GCL_NO_SPECIALS) ) {
			uint32_t last_deaddrop_fresh_msg_id = dc_get_last_deaddrop_fresh_msg__(ths->m_context);
			if( last_deaddrop_fresh_msg_id > 0 ) {
				dc_array_add_id(ths->m_chatNlastmsg_ids, MR_CHAT_ID_DEADDROP); /* show deaddrop with the last fresh message */
				dc_array_add_id(ths->m_chatNlastmsg_ids, last_deaddrop_fresh_msg_id);
			}
			add_archived_link_item = 1;
		}

		stmt = dc_sqlite3_predefine__(ths->m_context->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs_WHERE_unarchived,
			QUR1 " AND c.archived=0 " QUR2);
	}
	else
	{
		/* show chatlist filtered by a search string, this includes archived and unarchived */
		query = safe_strdup(query__);
		mr_trim(query);
		if( query[0]==0 ) {
			success = 1; /*empty result*/
			goto cleanup;
		}
		strLikeCmd = dc_mprintf("%%%s%%", query);
		stmt = dc_sqlite3_predefine__(ths->m_context->m_sql, SELECT_ii_FROM_chats_LEFT_JOIN_msgs_WHERE_query,
			QUR1 " AND c.name LIKE ? " QUR2);
		sqlite3_bind_text(stmt, 1, strLikeCmd, -1, SQLITE_STATIC);
	}

    while( sqlite3_step(stmt) == SQLITE_ROW )
    {
		dc_array_add_id(ths->m_chatNlastmsg_ids, sqlite3_column_int(stmt, 0));
		dc_array_add_id(ths->m_chatNlastmsg_ids, sqlite3_column_int(stmt, 1));
    }

    if( add_archived_link_item && dc_get_archived_count__(ths->m_context)>0 )
    {
		dc_array_add_id(ths->m_chatNlastmsg_ids, MR_CHAT_ID_ARCHIVED_LINK);
		dc_array_add_id(ths->m_chatNlastmsg_ids, 0);
    }

	ths->m_cnt = dc_array_get_cnt(ths->m_chatNlastmsg_ids)/MR_CHATLIST_IDS_PER_RESULT;
	success = 1;

cleanup:
	//dc_log_info(ths->m_context, 0, "Chatlist for search \"%s\" created in %.3f ms.", query__?query__:"", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	free(query);
	free(strLikeCmd);
	return success;
}
