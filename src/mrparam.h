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
 * File:    mrparam.h
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
 * 'a' forwarded from this email-address
 * 'A' forwarded from this name
 * 'c'rypted in original/guarantee E2EE or the message is not send
 * 'v'alidation errors on decryption
 * 'f'ile
 * 'w'idth
 * 'h'eight
 * 'd'uration in milliseconds
 * 'n'ame of track
 * 'N'ame of author or artist
 * 'm'ime
 * 't'imes a job was tried
 * 'T'imes a job was tried, used for increation
 *
 * 'G'host-CC, parameter is the original msg_id
 * 'U'npromoted group
 * 'S'ystem command
 * 'E'xtra parameter for system command
 * 'P'hysically delete group after message sending
 * 'r'ead receipt wanted
 * 'R'eferences header last used for a chat
 *
 ******************************************************************************/


#ifndef __MRPARAM_H__
#define __MRPARAM_H__
#ifdef __cplusplus
extern "C" {
#endif


#define MRP_GUARANTEE_E2EE    'c'  /* 'c'rypted in original/guarantee E2EE or the message is not send */
#define MRP_ERRONEOUS_E2EE    'e'  /* decrypted with validation errors, if neither 'c' nor 'v' are preset, the messages is only transport encrypted */
#define MRP_WANTS_MDN         'r'  /* an incoming message which requestes a MDN (aka read receipt) */


typedef struct mrparam_t
{
	char*    m_packed;    /* != NULL */
} mrparam_t;


mrparam_t*    mrparam_new          ();
void          mrparam_unref        (mrparam_t*);

void          mrparam_empty        (mrparam_t*);
void          mrparam_set_packed   (mrparam_t*, const char*); /* overwrites all existing parameters */

int           mrparam_exists       (mrparam_t*, int key);
char*         mrparam_get          (mrparam_t*, int key, const char* def); /* the value may be an empty string, "def" is returned only if the value unset.  The result must be free()'d in any case. */
int32_t       mrparam_get_int      (mrparam_t*, int key, int32_t def);
void          mrparam_set          (mrparam_t*, int key, const char* value);
void          mrparam_set_int      (mrparam_t*, int key, int32_t value);


/*** library-private **********************************************************/

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRPARAM_H__ */

