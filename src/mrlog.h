/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2017 Björn Petersen Software Design and Development
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
 * File:    mrlog.h
 * Authors: Björn Petersen
 * Purpose: Error handling
 *
 ******************************************************************************/


#ifndef __MRLOG_H__
#define __MRLOG_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef void (*mrlogcb_t) (int type, const char* msg);


/* Set a handler to receive logfiles.  Overwrites and disables the default handler
which uses printf().
Note, that the given handler may be called from any thread! */
void mrlog_set_handler (mrlogcb_t);


/*** library-private **********************************************************/

void mrlog_error            (const char* msg, ...);
void mrlog_warning          (const char* msg, ...);
void mrlog_info             (const char* msg, ...);
int  mrlog_get_thread_index (void);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRLOG_H__ */

