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
 * File:    mrkey.c
 * Purpose: Handle keys
 *
 ******************************************************************************/


#include <stdlib.h>
#include <memory.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrkey.h"


void mrkey_set_from_raw(mrkey_t* ths, const unsigned char* data, int bytes)
{
    mrkey_empty(ths);
    if( data==NULL || bytes <= 0 ) {
		return;
    }
    ths->m_binary = malloc(bytes);
    if( ths->m_binary == NULL ) {
		exit(40);
    }
    memcpy(ths->m_binary, data, bytes);
    ths->m_bytes = bytes;
}


void mrkey_set_from_key(mrkey_t* ths, const mrkey_t* o)
{
	mrkey_empty(ths);
	if( ths && o ) {
		mrkey_set_from_raw(ths, o->m_binary, o->m_bytes);
	}
}


void mrkey_set_from_stmt(mrkey_t* ths, sqlite3_stmt* stmt, int index)
{
	mrkey_empty(ths);
	if( ths && stmt ) {
		mrkey_set_from_raw(ths, (unsigned char*)sqlite3_column_blob(stmt, index), sqlite3_column_bytes(stmt, index));
	}
}


void mrkey_empty(mrkey_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	free(ths->m_binary);
	ths->m_binary = NULL;
	ths->m_bytes = 0;
}


int mrkey_equals(const mrkey_t* ths, const mrkey_t* o)
{
	if( ths==NULL || o==NULL
	 || ths->m_binary==NULL || ths->m_bytes<=0 || o->m_binary==NULL || o->m_bytes<=0 ) {
		return 0; /*error*/
	}

	if( ths->m_bytes != o->m_bytes ) {
		return 0; /*different size -> the keys cannot be equal*/
	}

	return memcmp(ths->m_binary, o->m_binary, o->m_bytes)==0? 1 : 0;
}

