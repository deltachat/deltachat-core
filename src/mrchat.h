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
 * File:    mrchat.h
 * Authors: Björn Petersen
 * Purpose: mrchat_t represents a single chat - this is a conversation with
 *          a single user or a group
 *
 ******************************************************************************/


#ifndef __MRCHAT_H__
#define __MRCHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "mrmsg.h"
#include "mrmsglist.h"
typedef struct mrpoortext_t mrpoortext_t;


/* chat type */
#define MR_CHAT_UNDEFINED    0
#define MR_CHAT_NORMAL     100 /* a normal chat is a chat with a single contact - the constants must NOT change as they're used in the database, the frontends etc.*/
#define MR_CHAT_GROUP      120


/* specical chat IDs */
#define MR_CHAT_ID_STRANGERS        1 /* for strangers, chats_contacts is not set up. */
#define MR_CHAT_ID_TRASH            2 /* messages that should be deleted get this chat_id; the messages are deleted from the working thread later then. This is also needed as rfc724_mid should be preset as long as the message is not deleted on the server (otherwise it is downloaded again) */
#define MR_CHAT_ID_BLOCKED_USERS    3 /* messages of blocked users go here; they do not even pop up in the "strangers" chat */
#define MR_CHAT_ID_MSGS_IN_CREATION 4 /* a message is just in creation but not yet assigned to a chat (eg. we may need the message ID to set up blobs; this avoids unready message to be send and shown) */
#define MR_CHAT_ID_LAST_SPECIAL     9 /* larger chat IDs are "real" chats, their messages are "real" messages. */


typedef struct mrchat_t
{
	uint32_t        m_id;
	int             m_type;
	char*           m_name;            /* NULL if unset */
	time_t          m_draft_timestamp; /* 0 if there is no draft */
	char*           m_draft_text;      /* NULL if unset */
	mrmailbox_t*    m_mailbox;         /* != NULL */
	mrmsg_t*        m_last_msg_;       /* Only set, if the chat was read by mrmailbox_get_chatlist(); use mrchat_get_summary() to read this field. */
	int             m_refcnt;
} mrchat_t;


void          mrchat_unref                 (mrchat_t*);
char*         mrchat_get_subtitle          (mrchat_t*); /* either the e-mail-address or the number of group members, the result must be free()'d! */
mrmsglist_t*  mrchat_get_msglist           (mrchat_t*, size_t offset, size_t amount); /* the caller must unref the result */
int           mrchat_get_total_msg_count   (mrchat_t*);
int           mrchat_get_unread_count      (mrchat_t*);
int           mrchat_set_draft             (mrchat_t*, const char*); /* Save draft in object and, if changed, in database.  May result in "MR_EVENT_MSGS_UPDATED".  Returns true/false. */

/* the following function gets information about the last message or draft;
the function only works, if the chat is a part of a chatlist (otherwise, for speed reasons, the last messages are not loaded) */
mrpoortext_t* mrchat_get_summary           (mrchat_t*); /* result must be unref'd */

/* sending messages */
uint32_t      mrchat_send_msg              (mrchat_t*, const mrmsg_t*); /* save message in database and send it, the given message object is not unref'd by the function! */


/*** library-private **********************************************************/

mrchat_t*     mrchat_new                   (mrmailbox_t*); /* result must be unref'd */
mrchat_t*     mrchat_ref                   (mrchat_t*);
void          mrchat_empty                 (mrchat_t*);
int           mrchat_load_from_db_         (mrchat_t*, uint32_t id);

#define       MR_CHAT_FIELDS               " c.id,c.type,c.name, c.draft_timestamp,c.draft_txt "
int           mrchat_set_from_stmt_        (mrchat_t* ths, sqlite3_stmt* row); /* `row` must be MR_CHAT_FIELDS */

size_t        mr_get_chat_cnt_             (mrmailbox_t*);
uint32_t      mr_create_or_lookup_chat_record_(mrmailbox_t*, uint32_t contact_id);
uint32_t      mr_real_chat_exists_         (mrmailbox_t*, int type, uint32_t contact_id);
int           mr_get_total_msg_count_      (mrmailbox_t*, uint32_t chat_id);
int           mr_get_unread_count_         (mrmailbox_t*, uint32_t chat_id);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCHAT_H__ */
