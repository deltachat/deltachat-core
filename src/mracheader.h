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
 * File:    mracheader.h
 * Purpose: Handle Autocrypt:-headers
 *
 ******************************************************************************/


#ifndef __MRACHEADER_H__
#define __MRACHEADER_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mracheader_t
{
	uint32_t       m_magic;
	char*          m_to;
	unsigned char* m_pah_key;
	int            m_pah_prefer_encrypted;
} mracheader_t;


mracheader_t* mracheader_new             (); /* the returned pointer is ref'd and must be unref'd after usage */
void          mracheader_unref           (mracheader_t*);
void          mracheader_empty           (mracheader_t*);

int           mracheader_set_from_message(mracheader_t*, const struct mailmime* mime);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRACHEADER_H__ */
