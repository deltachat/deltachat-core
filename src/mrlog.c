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


/*******************************************************************************
 * The default logging handler
 ******************************************************************************/


void mrlog_default_handler_(int type, const char* msg)
{
	const char* type_str;
	char*       log_entry_str;

	switch( type ) {
		case 'i': type_str = "";          break;
		case 'w': type_str = "[Warning]"; break;
		default:  type_str = "[ERROR]";   break;
	}

	log_entry_str = sqlite3_mprintf("%s[%s]", type_str, msg); if( log_entry_str == NULL ) { exit(18); }
		printf("%s\n", log_entry_str);
	sqlite3_free(log_entry_str);
}


/*******************************************************************************
 * Call/set the logging handler
 ******************************************************************************/


mrlogcallback_t mrlog_callback_ptr_ = mrlog_default_handler_;


static void mrlog_print(int type, const char* msg)
{
	mrlog_callback_ptr_(type, msg);
}


void mrlog_set_handler(mrlogcallback_t cb)
{
	if( cb ) {
		mrlog_callback_ptr_ = cb;
	}
}


/*******************************************************************************
 * High-level logging functions
 ******************************************************************************/


static void mrlog_vprintf(int type, const char* msg_format, va_list va)
{
	char* msg;

	if( type != 'e' && type != 'w' && type != 'i' ) {
		mrlog_print('e', "Bad log type.");
		return;
	}

	if( msg_format == NULL ) {
		mrlog_print('e', "Log format string missing.");
		return;
	}

	msg = sqlite3_vmprintf(msg_format, va); if( msg == NULL ) { mrlog_print('e', "Bad log format string."); }
		mrlog_print(type, msg);
	sqlite3_free(msg);
}


void mrlog_info(const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		mrlog_vprintf('i', msg, va);
	va_end(va);
}



void mrlog_warning(const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		mrlog_vprintf('w', msg, va);
	va_end(va);
}


void mrlog_error(const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		mrlog_vprintf('e', msg, va);
	va_end(va);
}

