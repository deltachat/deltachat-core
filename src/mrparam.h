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
 * File:    mrparam.h
 * Authors: Björn Petersen
 * Purpose: Handle parameter lists as follows:
 *          - the list is stored in a string as "a=value\nb=value"
 *          - values can contain all characters but "\n"
 *          - for efficiency, keys are limited to one character
 *          - we expect the packed string to be well formatted and do not
 *            allow spaces around the key; spaces right of the value are trimmed
 *
 *******************************************************************************
 *
 * Known keys:
 * 'f'ile
 * 'o'riginal filename
 * 'w'idth
 * 'h'eight
 * 'd'uration in milliseconds
 * 'm'ime
 * 't'imstamp to try a job again
 *
 ******************************************************************************/


#ifndef __MRPARAM_H__
#define __MRPARAM_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct mrparam_t
{
	char*    m_packed;    /* != NULL */
	int      m_refcnt;
} mrparam_t;


mrparam_t*    mrparam_new          ();
mrparam_t*    mrparam_ref          (mrparam_t*);
void          mrparam_unref        (mrparam_t*);

void          mrparam_empty        (mrparam_t*);
void          mrparam_set_packed   (mrparam_t*, const char*); /* overwrites all existing parameters */

char*         mrparam_get          (mrparam_t*, int key, const char* def); /* the value may be an empty string, "def" is returned only if the value unset.  The result must be free()'d in any case. */
int32_t       mrparam_get_int      (mrparam_t*, int key, int32_t def);
void          mrparam_set          (mrparam_t*, int key, const char* value);
void          mrparam_set_int      (mrparam_t*, int key, int32_t value);


/*** library-private **********************************************************/

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRPARAM_H__ */

