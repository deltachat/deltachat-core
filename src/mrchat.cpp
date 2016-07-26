/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any laterMrChat
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
 * File:    mrchat.cpp
 * Authors: Björn Petersen
 * Purpose: MrChat represents a single chat, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrchat.h"


MrChat::MrChat(MrMailbox* mailbox)
{
	m_mailbox        = mailbox;
	m_type           = MR_CHAT_UNDEFINED;
	m_name           = NULL;
	m_last_timestamp = 0;
	m_last_msg_type  = MR_MSG_UNDEFINED;
	m_last_msg       = NULL;
}


MrChat::~MrChat()
{
	free(m_name);
	free(m_last_msg);
}


void MrChat::SendMsg(const char* text)
{
}


/*******************************************************************************
 * Chat lists
 ******************************************************************************/


MrChatList::MrChatList()
{
	m_chats = carray_new(128);
}


MrChatList::~MrChatList()
{
	if( m_chats )
	{
		int cnt = carray_count(m_chats);
		for( int i = 0; i < cnt; i++ )
		{
			MrChat* chat = (MrChat*)carray_get(m_chats, i);
			if( chat )
			{
				delete chat;
			}
		}

		carray_free(m_chats);
		m_chats = NULL;
	}
}
