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
 * File:    mrmsglist.c
 * Authors: Björn Petersen
 * Purpose: List of messages
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrmsglist_t* mrmsglist_new(mrchat_t* chat)
{
	mrmsglist_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrmsglist_t)))==NULL ) {
		exit(21); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_chat = chat;
	ths->m_msgs = carray_new(128);

	return ths;
}


void mrmsglist_unref(mrmsglist_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrmsglist_empty(ths);
	if( ths->m_msgs ) {
		carray_free(ths->m_msgs);
	}

	free(ths);
}


void mrmsglist_empty(mrmsglist_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	if( ths->m_msgs )
	{
		int i, cnt = carray_count(ths->m_msgs);
		for( i = 0; i < cnt; i++ )
		{
			mrmsg_t* msg = (mrmsg_t*)carray_get(ths->m_msgs, i);
			mrmsg_unref(msg);
		}
		carray_set_size(ths->m_msgs, 0);
	}
}


size_t mrmsglist_get_cnt(mrmsglist_t* ths)
{
	if( ths == NULL || ths->m_msgs == NULL ) {
		return 0;
	}

	return (size_t)carray_count(ths->m_msgs);
}


mrmsg_t* mrmsglist_get_msg_by_index (mrmsglist_t* ths, size_t index)
{
	if( ths == NULL || ths->m_msgs == NULL || index >= (size_t)carray_count(ths->m_msgs) ) {
		return 0;
	}

	return mrmsg_ref((mrmsg_t*)carray_get(ths->m_msgs, index));
}

