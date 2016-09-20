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
 * File:    mrtools.h
 * Authors: Björn Petersen
 * Purpose: Some tools and enhancements to the used libraries
 *
 ******************************************************************************/


#ifndef __MRTOOLS_H__
#define __MRTOOLS_H__
#ifdef __cplusplus
extern "C" {
#endif


/* public */
char*  mr_timestamp_to_str(time_t); /* the return values must be free()'d */


/* private string pools */
char*  safe_strdup                (const char*); /* returns empty string if NULL is given, else same as strdup() */
char*  mr_strlower                (const char*); /* the result must be free()'d */
char*  mr_decode_header_string    (const char* in); /* the result must be free()'d */
void   mr_unwrap_str              (char*); /* unwrap lines in the given buffer */
void   mr_remove_cr_chars         (char*); /* remove all \r characters from string */
char*  imap_modified_utf7_to_utf8 (const char *mbox, int change_spaces);
char*  imap_utf8_to_modified_utf7 (const char *src, int change_spaces);


/* private misc tools */
#define MR_INVALID_TIMESTAMP    (-1)
time_t mr_timestamp_from_date(struct mailimf_date_time * date_time); /* the result is UTC or MR_INVALID_TIMESTAMP */
int    carray_search              (carray*, void* needle, unsigned int* indx); /* returns 1/0 and the index if `indx` is not NULL */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRTOOLS_H__ */
