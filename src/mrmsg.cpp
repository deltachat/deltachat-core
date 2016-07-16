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
 * File:    mrmsg.cpp
 * Authors: Björn Petersen
 * Purpose: MrMsg represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrmsg.h"


MrMsg::MrMsg(MrMailbox* mailbox)
{
	m_mailbox = mailbox;
	m_type    = MR_MSG_UNDEFINED;
	m_msg     = NULL;
}


MrMsg::~MrMsg()
{
	#define FREE_(a) if((a)) { free((a)); (a)=NULL; }
	FREE_(m_msg)
}

