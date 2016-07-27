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


#include "mrmsg.h"

class MrMsgList;
class MrMailbox;


enum MrChatType
{
	 MR_CHAT_UNDEFINED =   0
	,MR_CHAT_NORMAL    = 100 // a normal chat is a chat with a single contact
	,MR_CHAT_PRIVATE   = 110
	,MR_CHAT_GROUP     = 120
	,MR_CHAT_FEED      = 130
};


class MrChat
{
public:
	                MrChat               (MrMailbox*);
	                ~MrChat              ();
	bool            LoadFromDb           (const char* name, uint32_t id);

	static size_t   GetChatCnt           (MrMailbox*);
	static uint32_t ChatExists           (MrMailbox*, MrChatType, uint32_t contact_id); // returns chat_id or 0
	static uint32_t CreateChatRecord     (MrMailbox*, uint32_t contact_id);
	static uint32_t FindOutChatId        (MrMailbox*, carray* contact_ids_from, carray* contact_ids_to);

	// the data should be read only and are valid until the object is delete'd.
	// unset strings are set to NULL.
	int             m_id;
	MrChatType      m_type;
	char*           m_name;
	MrMsg*          m_lastMsg;

	// list messages
	MrMsgList*      ListMsgs             (); // the caller must delete the result

	// send a message
	void            SendMsg              (const char* text);

private:
	// the mailbox, the chat belongs to
	#define         MR_CHAT_FIELDS " c.id,c.type,c.name "
	#define         MR_GET_CHATS_PREFIX "SELECT " MR_CHAT_FIELDS "," MR_MSG_FIELDS " FROM chats c " \
	                    "LEFT JOIN msg m ON (c.id=m.chat_id AND m.timestamp=(SELECT MIN(timestamp) FROM msg WHERE chat_id=c.id)) "
	bool            SetChatFromStmt      (sqlite3_stmt* row);
	void            Empty                ();
	MrMailbox*      m_mailbox;

	friend class    MrChatList;
};


class MrChatList
{
public:
	                MrChatList  (MrMailbox*);
	                ~MrChatList ();
	bool            LoadFromDb  ();

	// data
	carray*         m_chats; // contains MrChat objects

private:
	MrMailbox*      m_mailbox;
	void            Empty       ();
};


#endif // __MRCHAT_H__

