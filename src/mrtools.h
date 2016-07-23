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


// string tools
char* mr_strlower(const char*); // the result must be free()'d
char* imap_modified_utf7_to_utf8(const char *mbox, bool change_spaces);
char* imap_utf8_to_modified_utf7(const char *src, bool change_spaces);

// carray tools
bool carray_search     (carray*, void* needle, unsigned int* indx); // returns true/false and the index if `indx` is not NULL

// date/time tools
#define INVALID_TIMESTAMP    (-1)
time_t timestampFromDate(struct mailimf_date_time * date_time); // the result is UTC or INVALID_TIMESTAMP


#endif // __MRTOOLS_H__

