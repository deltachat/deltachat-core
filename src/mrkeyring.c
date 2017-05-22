/*******************************************************************************
 *
 *                              Delta Chat Core
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
 * File:    mrkeyring.c
 * Purpose: Handle keys
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrkey.h"
#include "mrkeyring.h"
#include "mrtools.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mrkeyring_init(mrkeyring_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	memset(ths, 0, sizeof(mrkeyring_t));
}


void mrkeyring_empty(mrkeyring_t* ths)
{
	int i;
	if( ths == NULL ) {
		return;
	}

	free(ths->m_keys);
	memset(ths, 0, sizeof(mrkeyring_t));
}


void mrkeyring_add(mrkeyring_t* ths, const mrkey_t* to_add)
{
	if( ths==NULL || to_add==NULL ) {
		return;
	}

	/* expand array, if needed */
	if( ths->m_count == ths->m_allocated ) {
		int newsize = (ths->m_allocated * 2) + 10;
		if( (ths->m_keys=realloc(ths->m_keys, newsize*sizeof(mrkey_t*)))==NULL ) {
			exit(41);
		}
		ths->m_allocated = newsize;
	}

	ths->m_keys[ths->m_count] = to_add;
	ths->m_count++;
}




