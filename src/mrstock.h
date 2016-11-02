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
 * File:    mrstock.h
 * Authors: Björn Petersen
 * Purpose: Add translated strings that are used by the messager backend
 *
 ******************************************************************************/


#ifndef __MRSTOCK_H__
#define __MRSTOCK_H__
#ifdef __cplusplus
extern "C" {
#endif


#define MR_STR_FREE_            0 /* the IDs must not change! No gaps, please. */
#define MR_STR_NO_MESSAGES      1
#define MR_STR_YOU              2
#define MR_STR_DRAFT            3
#define MR_STR_MEMBER           4
#define MR_STR_MEMBERS          5 /* must be MR_STR_MEMBERS+1 */
#define MR_STR_CONTACT          6
#define MR_STR_CONTACTS         7 /* must be MR_STR_CONTACT+1 */
#define MR_STR_STRANGERS        8
#define MR_STR_IMAGE            9
#define MR_STR_VIDEO            10
#define MR_STR_AUDIO            11
#define MR_STR_FILE             12
#define MR_STR_STATUSLINE       13
#define MR_STR_SUBJECTPREFIX    14
#define MR_STR_COUNT_           15


/* mrstock_set_str() adds a string to the repository. A copy of the given string
is made. Usually, this is used to pass translated strings to the backend. */
void         mrstock_add_str (int id, const char*);

/* frees all strings allocated by mrstock_set_str().  Usually, there is no need
to call this function - when the program terminates, usually all strings are
free automatically.  However, this function may be handy if you watch the memory
for leaks using some special tools. */
void         mrstock_exit    (void);


/*** library-private **********************************************************/

char*  mrstock_str             (int id);             /* the result must be free()'d! */
char*  mrstock_str_repl_number (int id, int number); /* replaces the first ? by the given number, the result must be free()'d! */
char*  mrstock_str_pl          (int id, int cnt);    /* id+0 should be singular, id+1 should be plural, replaces the first ? by the given number, the result must be free()'d! */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRSTOCKSTR_H__ */

