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
 * File:    mracpeerstate.h
 * Purpose: mracpeerstate_t represents the state of an Autocrypt peer
 *
 ******************************************************************************/


#ifndef __MRACPEERSTATE_H__
#define __MRACPEERSTATE_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mracheader_t mracheader_t;


#define MRAC_PE_NO           0 /* prefer-encrypted states */
#define MRAC_PE_YES          1
#define MRAC_PE_NOPREFERENCE 2
#define MRAC_PE_RESET        3


typedef struct mracpeerstate_t
{
	uint32_t       m_magic;
	char*          m_addr;
	time_t         m_changed;
	time_t         m_last_seen;
	unsigned char* m_pah_key;
	int            m_pah_prefer_encrypted;
} mracpeerstate_t;


mracpeerstate_t* mracpeerstate_new             (); /* the returned pointer is ref'd and must be unref'd after usage */
void             mracpeerstate_unref           (mracpeerstate_t*);
void             mracpeerstate_empty           (mracpeerstate_t*);

void             mracpeerstate_apply_header    (mracpeerstate_t*, const mracheader_t*);

int              mracpeerstate_load_from_db__  (mracpeerstate_t*, mrsqlite3_t*, const char* addr);
int              mracpeerstate_save_to_db__    (const mracpeerstate_t*, mrsqlite3_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRACPEERSTATE_H__ */

