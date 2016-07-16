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
	 MR_MSG_UNDEFINED =  0
	,MR_MSG_TEXT      = 10
	,MR_MSG_IMAGE     = 20
	,MR_MSG_STICKER   = 30
	,MR_MSG_AUDIO     = 40
	,MR_MSG_VIDEO     = 50
	,MR_MSG_FILE      = 60
	,MR_MSG_CONTACT   = 70
	,MR_MSG_LOCATION  = 80
};


class MrMsg
{
public:
	// if an object is no longer needed, it should be Release()'d, to destroy a message physically,
	// call Destroy() (an additional Release() is needed even in this case)
	void          Release     () { delete this; }
	void          Destroy     ();

	// the data should be read only and are valid until the object is Release()'d.
	// unset strings are set to NULL.
	MrMsgType m_type;
	char*         m_msg; // meaning dedpends on m_type

private:
	// as message objects are only constructed by MrMailbox, we declare the constructor as private and MrMailbox as a friend
	              MrMsg       (MrMailbox*);
	              ~MrMsg      ();
	friend class  MrMailbox;

	// the mailbox, the message belongs to
	MrMailbox*    m_mailbox;
};


#endif // __MRMSG_H__

