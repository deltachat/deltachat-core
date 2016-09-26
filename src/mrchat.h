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
 * Purpose: MrChat represents a single chat - this is a conversation with
 *          a single user or a group
 *
 ******************************************************************************/


#ifndef __MRCHAT_H__
#define __MRCHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "mrmsg.h"


/* chat type */
#define MR_CHAT_UNDEFINED    0
#define MR_CHAT_NORMAL     100 /* a normal chat is a chat with a single contact */
#define MR_CHAT_PRIVATE    110
#define MR_CHAT_GROUP      120
#define MR_CHAT_FEED       130


typedef struct mrchat_t
{
	uint32_t        m_id;
	int             m_type;
	char*           m_name;    /* NULL if unset */
	mrmsg_t*        m_lastMsg; /* NULL if unset */
	mrmailbox_t*    m_mailbox; /* always set */
	int             m_refcnt;
} mrchat_t;


typedef struct mrchatlist_t
{
	carray*      m_chats; /* contains mrchat_t objects */
	mrmailbox_t* m_mailbox;
} mrchatlist_t;


void          mrchat_unref                 (mrchat_t*);
mrmsg_t*      mrchat_get_last_msg          (mrchat_t*); /* result must be unref'd, as an alternative, you can use m_lastMsg directly */
char*         mrchat_get_subtitle          (mrchat_t*); /* either the e-mail-address or the number of group members, the result must be free()'d! */
mrmsglist_t*  mrchat_get_msgs_by_index     (mrchat_t*, size_t index, size_t amount); /* the caller must unref the result */
void          mrchat_send_msg              (mrchat_t*, const char* text);

void          mrchatlist_unref             (mrchatlist_t*);
size_t        mrchatlist_get_cnt           (mrchatlist_t*);
mrchat_t*     mrchatlist_get_chat          (mrchatlist_t*, size_t index); /* result must be unref'd, you can also use m_chats directly */


/*** library-private **********************************************************/

mrchat_t*     mrchat_new                   (mrmailbox_t*); /* result must be unref'd */
mrchat_t*     mrchat_ref                   (mrchat_t*);
void          mrchat_empty                 (mrchat_t*);
int           mrchat_load_from_db          (mrchat_t*, const char* name, uint32_t id);

mrchatlist_t* mrchatlist_new               (mrmailbox_t*);
void          mrchatlist_empty             (mrchatlist_t*);
int           mrchatlist_load_from_db      (mrchatlist_t*);

size_t        mr_get_chat_cnt_             (mrmailbox_t*);
uint32_t      mr_chat_exists_              (mrmailbox_t*, int chat_type, uint32_t contact_id); /* returns chat_id or 0 */
uint32_t      mr_create_chat_record_       (mrmailbox_t*, uint32_t contact_id);
uint32_t      mr_find_out_chat_id_         (mrmailbox_t*, carray* contact_ids_from, carray* contact_ids_to);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCHAT_H__ */
