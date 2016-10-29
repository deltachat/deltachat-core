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
 * File:    mrmsg.h
 * Authors: Björn Petersen
 * Purpose: mrmsg_t represents a single message in a chat.  One E-Mail can
 *          result in different messages!
 *
 ******************************************************************************/


#ifndef __MRMSG_H__
#define __MRMSG_H__
#ifdef __cplusplus
extern "C" {
#endif


#include "mrparam.h"
typedef struct mrjob_t mrjob_t;


/* message types */
#define MR_MSG_UNDEFINED   0
#define MR_MSG_TEXT        10
#define MR_MSG_IMAGE       20 /* param: 'f'ile, 'w', 'h' */
#define MR_MSG_AUDIO       40 /* param: 'f'ile, 't'ime */
#define MR_MSG_VIDEO       50 /* param: 'f'ile, 'w', 'h', 't'ime */
#define MR_MSG_FILE        60 /* param: 'f'ile */


/* message states */
#define MR_STATE_UNDEFINED  0
#define MR_IN_UNREAD       10 /* incoming message not read */
#define MR_IN_READ         16 /* incoming message read, to check for incoming messages you can check for state<=3 */
#define MR_OUT_PENDING     20 /* hit "send" button - but the message is pending in some way, maybe we're offline (no checkmark) */
#define MR_OUT_SENDING     22 /* the message is just now being sending */
#define MR_OUT_ERROR       24 /* unrecoverable error (recoverable errors result in pending messages) */
#define MR_OUT_DELIVERED   26 /* outgoing message successfully delivered to server (one checkmark) */
#define MR_OUT_READ        28 /* outgoing message read (two checkmarks; this requires goodwill on the receiver's side) */


typedef struct mrmsg_t
{
	uint32_t      m_id;
	uint32_t      m_from_id;   /* contact, 0=unset, 1=self .. >9=real contacts */
	uint32_t      m_to_id;     /* contact, 0=unset, 1=self .. >9=real contacts */
	uint32_t      m_chat_id;   /* the chat, the message belongs to: 0=unset, 1=unknwon sender .. >9=real chats */
	time_t        m_timestamp; /* unix time the message was sended */

	int           m_type;      /* MR_MSG_* */
	int           m_state;     /* MR_STATE_* etc. */
	char*         m_text;      /* message text or NULL if unset */
	mrparam_t*    m_param;     /* 'f'ile, 'm'ime, 'w', 'h', 't'ime/ms etc. depends on the type, != NULL */
	int           m_bytes;     /* used for external BLOBs, BLOB data itself is stored in plain files with <8-chars-hex-id>.ext, 0 for plain text */

	int           m_refcnt;
} mrmsg_t;


mrmsg_t*     mrmsg_new                    ();
mrmsg_t*     mrmsg_ref                    (mrmsg_t*);
void         mrmsg_unref                  (mrmsg_t*); /* this also free()s all strings; so if you set up the object yourself, make sure to use strdup()! */
void         mrmsg_empty                  (mrmsg_t*);


/*** library-private **********************************************************/

#define      MR_MSG_FIELDS                    " m.id,m.chat_id,m.from_id,m.to_id, m.timestamp,m.type,m.state, m.txt,m.param,m.bytes "
int          mrmsg_set_from_stmt_             (mrmsg_t*, sqlite3_stmt* row, int row_offset); /* row order is MR_MSG_FIELDS */
int          mrmsg_load_from_db_              (mrmsg_t*, mrmailbox_t*, uint32_t id);
size_t       mrmailbox_get_real_msg_cnt_      (mrmailbox_t*); /* the number of messages assigned to real chat (!=strangers, !=trash) */
size_t       mrmailbox_get_strangers_msg_cnt_ (mrmailbox_t*);
int          mrmailbox_message_id_exists_     (mrmailbox_t*, const char* rfc724_mid);
void         mrmailbox_update_msg_chat_id_    (mrmailbox_t*, uint32_t msg_id, uint32_t chat_id);
void         mrmailbox_delete_msg_from_imap   (mrmailbox_t* mailbox, mrjob_t* job);

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMSG_H__ */

