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
 * File:    mraheader.h
 * Purpose: Handle Autocrypt:-headers
 *
 ******************************************************************************/


#ifndef __MRAHEADER_H__
#define __MRAHEADER_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mraheader_t
{
	uint32_t       m_magic;
	char*          m_to;
	unsigned char* m_pah_key;
	int            m_pah_prefer_encrypted;
} mraheader_t;


mraheader_t* mraheader_new               (); /* the returned pointer is ref'd and must be unref'd after usage */
void         mraheader_unref             (mraheader_t*);
void         mraheader_empty             (mraheader_t*);

int          mraheader_set_from_imffields(mraheader_t*, const struct mailimf_fields* mime);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRAHEADER_H__ */
