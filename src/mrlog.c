/*******************************************************************************
 *
 *                             Messenger Backend
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
 * File:    mrlog.c
 * Purpose: Error handling, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mrlog.h"


/*******************************************************************************
 * Get a unique thread ID to recognize log output from different threads
 ******************************************************************************/


int mrlog_get_thread_index(void)
{
	#define          MR_MAX_THREADS 32 /* if more threads are started, the full ID is printed (this may happen eg. on many failed connections so that we try to start a working thread several times) */
	static pthread_t s_threadIds[MR_MAX_THREADS];
	static int       s_threadIdsCnt = 0;

	int       i;
	pthread_t self = pthread_self();

	if( s_threadIdsCnt==0 ) {
		for( i = 0; i < MR_MAX_THREADS; i++ ) {
			s_threadIds[i] = 0;
		}
	}

	for( i = 0; i < s_threadIdsCnt; i++ ) {
		if( s_threadIds[i] == self ) {
			return i+1;
		}
	}

	if( s_threadIdsCnt >= MR_MAX_THREADS ) {
		return (int)(self); /* Fallback, this may happen, see comment above */
	}

	s_threadIds[s_threadIdsCnt] = self;
	s_threadIdsCnt++;
	return s_threadIdsCnt;
}


/*******************************************************************************
 * The default logging handler
 ******************************************************************************/


static void mrlog_default_handler_(int type, const char* msg)
{
	const char* type_str;

	switch( type ) {
		case 'd': type_str = "[Debug] ";   break;
		case 'i': type_str = "";           break;
		case 'w': type_str = "[Warning] "; break;
		default:  type_str = "[ERROR] ";   break;
	}

	printf("%s%s\n", type_str, msg);
}


/*******************************************************************************
 * Call/set the logging handler
 ******************************************************************************/


static mrlogcb_t mrlog_cb_ = mrlog_default_handler_;


void mrlog_set_handler(mrlogcb_t cb)
{
	if( cb ) {
		mrlog_cb_ = cb;
	}
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


static void mrlog_vprintf(int type, const char* msg_format, va_list va)
{
	#define BUFSIZE 1024
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int  thread_index = mrlog_get_thread_index();

	if( type != 'e' && type != 'w' && type != 'i' ) {
		mrlog_cb_('e', "Bad log type.");
		return;
	}

	if( msg_format == NULL ) {
		mrlog_cb_('e', "Log format string missing.");
		return;
	}

	vsnprintf(buf1, BUFSIZE, msg_format, va);
	if( thread_index==1 ) {
		snprintf(buf2, BUFSIZE, "%s", buf1);
	}
	else {
		snprintf(buf2, BUFSIZE, "T%i: %s", mrlog_get_thread_index(), buf1);
	}
	mrlog_cb_(type, buf2);
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

