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
 * File:    mrlog.c
 * Authors: Björn Petersen
 * Purpose: Error handling, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "mrmailbox.h"
#include "mrlog.h"



static void mr_log(char type, const char* msg_format_str, va_list argp)
{
	const char *type_str;
	char* msg_full_str, *log_entry_str;

	switch( type ) {
		case 'i': type_str = "Information"; break;
		case 'w': type_str = "Warning";     break;
		default:  type_str = "ERROR";       break;
	}

	msg_full_str = sqlite3_vmprintf(msg_format_str, argp); if( msg_full_str == NULL ) { exit(18); }
		log_entry_str = sqlite3_mprintf("[%s] %s", type_str, msg_full_str); if( log_entry_str == NULL ) { exit(19); }
			printf("%s\n", log_entry_str);
		sqlite3_free(log_entry_str);
	sqlite3_free(msg_full_str);
}


void mr_log_info(const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		mr_log('i', msg, va);
	va_end(va);
}



void mr_log_warning(const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		mr_log('w', msg, va);
	va_end(va);
}


void mr_log_error(const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		mr_log('e', msg, va);
	va_end(va);
}


