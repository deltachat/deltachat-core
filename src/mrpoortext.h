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
 * File:    mrpoortext.h
 * Authors: Björn Petersen
 * Purpose: A line of text that describes eg. the last chat state as
 *          "Draft: Foo" or "Me: Foobar" (not really _richtext_, therefore
 *          _poortext_)
 *
 ******************************************************************************/


#ifndef __MRPOORTEXT_H__
#define __MRPOORTEXT_H__
#ifdef __cplusplus
extern "C" {
#endif


/* additional, emphasized text */
#define MR_TITLE_NORMAL    0 /* the values must not be changes as used directly in the frontend */
#define MR_TITLE_DRAFT     1
#define MR_TITLE_USERNAME  2
#define MR_TITLE_SELF      3


typedef struct mrpoortext_t
{
	uint32_t m_magic;
	char*    m_title;         /* may be NULL */
	int      m_title_meaning; /* one of MR_TITLE_* */
	char*    m_text;          /* may be NULL */
	time_t   m_timestamp;     /* may be 0 */
	int      m_state;         /* may be 0 */
} mrpoortext_t;


mrpoortext_t* mrpoortext_new       ();
void          mrpoortext_unref     (mrpoortext_t*);

void          mrpoortext_empty     (mrpoortext_t*);


/*** library-private **********************************************************/


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRPOORTEXT_H__ */

