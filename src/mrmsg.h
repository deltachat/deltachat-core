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
 * Purpose: MrMsg represents a single message in a chat.  One E-Mail can
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


/* message states */
#define MR_STATE_UNDEFINED 0
#define MR_IN_UNREAD       1 /* incoming message not read */
#define MR_IN_READ         3 /* incoming message read */
#define MR_OUT_SEND        5 /* outgoing message put to server without errors (one check) */
#define MR_OUT_DELIVERED   7 /* outgoing message successfully delivered (one check) */
#define MR_OUT_READ        9 /* outgoing message read (two checks) */


typedef struct mrmsg_t
{
	/* the following data should be read only and are valid until the object is Release()'d. unset strings are set to NULL. */

	uint32_t      m_id;
	uint32_t      m_fromId;    /* 0 = self */
	time_t        m_timestamp; /* unix time the message was sended */

	int           m_type;      /* MR_MSG_* */
	int           m_state;     /* MR_STATE_* etc. */

	char*         m_msg;       /* meaning dedpends on m_type */

	mrmailbox_t*  m_mailbox;
} mrmsg_t;


mrmsg_t* mrmsg_new               (struct mrmailbox_t*);
void     mrmsg_delete            (mrmsg_t*);
void     mrmsg_empty             (mrmsg_t*);

#define  DO_UNWRAP 0x01
char*    mrmsg_get_summary       (mrmsg_t*, long flags); /* the result should be free()'d */

/* private tools */
#define  MR_MSG_FIELDS " m.id,m.from_id,m.timestamp, m.type,m.state,m.msg " /* we use a define for easier string concatenation */
int      mrmsg_set_msg_from_stmt (mrmsg_t*, sqlite3_stmt* row, int row_offset); /* row order is MR_MSG_FIELDS */
size_t   mr_get_msg_cnt          (mrmailbox_t*);
int      mr_message_id_exists    (mrmailbox_t*, const char* rfc724_mid);


/* list of messages */
typedef struct mrmsglist_t
{
	carray*      m_msgs; /* contains MrMsg objects */
} mrmsglist_t;

mrmsglist_t* mrmsglist_new        (void);
void         mrmsglist_delete     (mrmsglist_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMSG_H__ */

