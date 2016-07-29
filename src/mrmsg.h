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


class MrMailbox;


enum MrMsgType
{
	 MR_MSG_UNDEFINED =   0
	,MR_MSG_TEXT      =  10
	,MR_MSG_IMAGE     =  20
	,MR_MSG_STICKER   =  30 // not sure, if we will really support this, maybe a image	 message will do the job.
	,MR_MSG_AUDIO     =  40
	,MR_MSG_VIDEO     =  50
	,MR_MSG_FILE      =  60
	,MR_MSG_LINK      =  61 // not sure, if we will really support this, maybe a normal text message will do the job.
	,MR_MSG_CONTACT   =  70 // not sure, if we will really support this, maybe a normal text message will do the job.
	,MR_MSG_LOCATION  =  80 // not sure, if we will really support this, maybe a normal text message will do the job.
};


enum MrMsgState
{
	 MR_STATE_UNDEFINED = 0
	,MR_IN_UNREAD       = 1 // incoming message not read
	,MR_IN_READ         = 3 // incoming message read
	,MR_OUT_SEND        = 5 // outgoing message put to server without errors (one check)
	,MR_OUT_DELIVERED   = 7 // outgoing message successfully delivered (one check)
	,MR_OUT_READ        = 9 // outgoing message read (two checks)
};


class MrMsg
{
public:
	              MrMsg          (MrMailbox*);
	              ~MrMsg         ();

	#define       MR_MSG_FIELDS " m.id,m.from_id,m.timestamp, m.type,m.state,m.msg " // we use a define for easier string concatenation
	bool          SetMsgFromStmt (sqlite3_stmt* row, int row_offset=0); // row order is MR_MSG_FIELDS

	static size_t GetMsgCnt      (MrMailbox*);
	static bool   MessageIdExists(MrMailbox*, const char* rfc724_mid);

	// the data should be read only and are valid until the object is Release()'d.
	// unset strings are set to NULL.
	uint32_t      m_id;
	uint32_t      m_fromId; // 0 = self
	time_t        m_timestamp; // unix time the message was sended
	MrMsgType     m_type;
	MrMsgState    m_state;
	char*         m_msg;  // meaning dedpends on m_type

private:
	// the mailbox, the message belongs to
	MrMailbox*    m_mailbox;
	void          Empty          ();
};


class MrMsgList
{
public:
	             MrMsgList   ();
	             ~MrMsgList  ();
	carray*      m_msgs; // contains MrMsg objects
};

#endif // __MRMSG_H__

