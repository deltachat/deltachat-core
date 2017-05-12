/*******************************************************************************
 *
 *                             Messenger Backend
 *                      Copyright (C) 2017 Björn Petersen
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
 * File:    mrapeerstate.c
 * Purpose: mrapeerstate_t represents the state of an Autocrypt peer
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrapeerstate.h"

#define CLASS_MAGIC 1494527374


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrapeerstate_t* mrapeerstate_new()
{
	mrapeerstate_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrapeerstate_t)))==NULL ) {
		exit(15); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	return ths;
}


void mrapeerstate_unref(mrapeerstate_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrapeerstate_empty(ths);
	free(ths);
}


void mrapeerstate_empty(mrapeerstate_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	ths->m_changed          = 0;
	ths->m_last_seen        = 0;
	ths->m_prefer_encrypted = 0;

	free(ths->m_addr);
	ths->m_addr = NULL;

	free(ths->m_public_key);
	ths->m_public_key = NULL;
}


int mrapeerstate_apply_header(mrapeerstate_t* ths, const mraheader_t* header)
{
	return 0;
}


int mrapeerstate_load_from_db__(mrapeerstate_t* ths, mrsqlite3_t* sql, const char* addr)
{
	mrapeerstate_empty(ths);
	return 0;
}


int mrapeerstate_save_to_db__(const mrapeerstate_t* ths, mrsqlite3_t* sql)
{
	return 0;
}
