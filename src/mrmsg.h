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


/* message types */
#define MR_MSG_UNDEFINED   0
#define MR_MSG_TEXT        10
#define MR_MSG_IMAGE       20
#define MR_MSG_STICKER     30 /* not sure, if we will really support this, maybe a image message will do the job. */
#define MR_MSG_AUDIO       40
#define MR_MSG_VIDEO       50
#define MR_MSG_FILE        60
#define MR_MSG_LINK        61 /* not sure, if we will really support this, maybe a normal text message will do the job. */
#define MR_MSG_CONTACT     70 /* not sure, if we will really support this, maybe a normal text message will do the job. */
#define MR_MSG_LOCATION    80 /* not sure, if we will really support this, maybe a normal text message will do the job. */
#define MR_MSG_SYSTEM      90 /* service messages as "You created the group.", not always spread via e-mail and equal on all clients, m_text is a stock ID, m_param may contain additional information; not sure, if we will use this, we also have the special user ID #2 which may be a better choice (as system messages can be of any type then) */


/* message states */
#define MR_STATE_UNDEFINED 0
#define MR_IN_UNREAD       1 /* incoming message not read */
#define MR_IN_READ         3 /* incoming message read */
#define MR_OUT_PENDING     5 /* hit "send" button - but the message is pending in some way, maybe we're offline (no checkmark) */
#define MR_OUT_ERROR       6 /* unrecoverable error (recoverable errors result in pending messages) */
#define MR_OUT_DELIVERED   7 /* outgoing message successfully delivered to server (one checkmark) */
#define MR_OUT_READ        9 /* outgoing message read (two checkmarks; this requires goodwill on the receiver's side) */


typedef struct mrmsg_t
{
	uint32_t      m_id;
	uint32_t      m_from_id;   /* contact, 0=unset, 1=self */
	uint32_t      m_chat_id;   /* the chat, the message belongs to */
	time_t        m_timestamp; /* unix time the message was sended */

	int           m_type;      /* MR_MSG_* */
	int           m_state;     /* MR_STATE_* etc. */
	char*         m_text;      /* plain text; NULL if unset */
	char*         m_param;     /* additional parameters as "key=value; key2=value2"; possible keys: mime, w, h, ms, lat, lng, url, ...; NULL if unset */
	int           m_bytes;     /* used for external BLOBs, BLOB data itself is stored in plain files with <8-chars-hex-id>.ext, 0 for plain text */

	mrmailbox_t*  m_mailbox;

	int           m_refcnt;
} mrmsg_t;


mrmsg_t*     mrmsg_new               (mrmailbox_t*); /* constructor needed for sending messages */
void         mrmsg_unref             (mrmsg_t*); /* this also free()s all strings; so if you set up the object yourself, make sure to use strdup()! */


/*** library-private **********************************************************/

mrmsg_t*     mrmsg_ref               (mrmsg_t*);
void         mrmsg_empty             (mrmsg_t*);

#define      MR_MSG_FIELDS           " m.id,m.chat_id,m.from_id, m.timestamp,m.type,m.state, m.txt,m.param,m.bytes "
int          mrmsg_set_from_stmt_    (mrmsg_t*, sqlite3_stmt* row, int row_offset); /* row order is MR_MSG_FIELDS */

size_t       mr_get_msg_cnt_         (mrmailbox_t*);
int          mr_message_id_exists_   (mrmailbox_t*, const char* rfc724_mid);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMSG_H__ */

