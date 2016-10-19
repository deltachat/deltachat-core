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


#define MR_VERSION_MAJOR    0
#define MR_VERSION_MINOR    1
#define MR_VERSION_REVISION 2


char*   mr_get_version_str         (void);   /* the return value must be free()'d */
char*   mr_timestamp_to_str        (time_t); /* the return value must be free()'d */


/*** library-private **********************************************************/

char*   mr_strlower                (const char*); /* the result must be free()'d */
char*   mr_decode_header_string    (const char* in); /* the result must be free()'d */
void    mr_unwrap_str              (char*, int approx_bytes); /* unwrap lines in the given buffer */
void    mr_remove_cr_chars         (char*); /* remove all \r characters from string */
void    mr_ltrim                   (char*);
void    mr_rtrim                   (char*);
void    mr_trim                    (char*);
carray* mr_split_into_lines        (const char* buf_terminated);
void    mr_free_splitted_lines     (carray* lines);

/* safe_strdup() returns empty string if NULL is given, else same as strdup(),
never returns NULL (exists on errors) */
char*   safe_strdup                (const char*);

/* A wrapper around sqlite3_mprintf() - the result must be free()'d, maybe by the user.
Internally, it's faster to call sqlite3_mprintf()/sqlite3_free() directly. */
char*   mr_mprintf                 (const char* format, ...);

char*   imap_modified_utf7_to_utf8 (const char *mbox, int change_spaces);
char*   imap_utf8_to_modified_utf7 (const char *src, int change_spaces);

#define MR_INVALID_TIMESTAMP       (-1)
time_t  mr_timestamp_from_date     (struct mailimf_date_time * date_time); /* the result is UTC or MR_INVALID_TIMESTAMP */
int     carray_search              (carray*, void* needle, unsigned int* indx); /* returns 1/0 and the index if `indx` is not NULL */

#define MR_INIT_REFERENCE \
	if( ths == NULL ) { return NULL; } \
	ths->m_refcnt = 1;

#define MR_INC_REFERENCE \
	if( ths == NULL ) { return NULL; } \
	ths->m_refcnt++; \
	return ths;

#define MR_DEC_REFERENCE_AND_CONTINUE_ON_0 \
	if( ths == NULL ) { return; } \
	ths->m_refcnt--; \
	if( ths->m_refcnt > 0 ) { return; }


#define MR_QUOTEHELPER(name) #name
#define MR_STRINGIFY(macro) MR_QUOTEHELPER(macro)
#define MR_MIN(X, Y) (((X) < (Y))? (X) : (Y))
#define MR_MAX(X, Y) (((X) > (Y))? (X) : (Y))


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRTOOLS_H__ */
