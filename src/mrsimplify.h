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
 * File:    mrsimplify.h
 * Authors: Björn Petersen
 * Purpose: Simplify and normalise text: Remove quotes, signatures, unnecessary
 *          lineends etc.
 *
 ******************************************************************************/


#ifndef __MRSIMPLIFY_H__
#define __MRSIMPLIFY_H__


typedef struct mrsimplify_t
{
	int dummy;
} mrsimplify_t;

mrsimplify_t* mrsimplify_new           ();
void          mrsimplify_delete        (mrsimplify_t*);

/* The data returned from Simplify() must be free()'d when no longer used */
char*         mrsimplify_simplify      (mrsimplify_t*, const char* txt_unterminated, int txt_bytes, int mimetype /*eg. MR_MIMETYPE_TEXT_HTML*/);


#endif /* __MRSIMPLIFY_H__ */

