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
 ******************************************************************************/


/* Asynchronous "Thread-errors" are reported by the dc_log_error()
function.  These errors must be shown to the user by a bubble or so.

"Normal" errors are usually returned by a special value (null or so) and are
usually not reported using dc_log_error() - its up to the caller to
decide, what should be reported or done.  However, these "Normal" errors
are usually logged by dc_log_warning(). */


#include <stdarg.h>
#include <memory.h>
#include "dc_context.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


static void log_vprintf(dc_context_t* mailbox, int event, int code, const char* msg_format, va_list va)
{
	char* msg = NULL;

	if( mailbox==NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	/* format message from variable parameters or translate very comming errors */
	if( code == DC_ERROR_SELF_NOT_IN_GROUP )
	{
		msg = mrstock_str(MR_STR_SELFNOTINGRP);
	}
	else if( code == DC_ERROR_NO_NETWORK )
	{
		msg = mrstock_str(MR_STR_NONETWORK);
	}
	else if( msg_format )
	{
		#define BUFSIZE 1024
		char tempbuf[BUFSIZE+1];
		vsnprintf(tempbuf, BUFSIZE, msg_format, va);
		msg = safe_strdup(tempbuf);
	}

	/* if we have still no message, create one based upon  the code */
	if( msg == NULL ) {
		     if( event == DC_EVENT_INFO )    { msg = mr_mprintf("Info: %i",    (int)code); }
		else if( event == DC_EVENT_WARNING ) { msg = mr_mprintf("Warning: %i", (int)code); }
		else                                 { msg = mr_mprintf("Error: %i",   (int)code); }
	}

	/* finally, log */
	mailbox->m_cb(mailbox, event, (uintptr_t)code, (uintptr_t)msg);

	/* remember the last N log entries */
	pthread_mutex_lock(&mailbox->m_log_ringbuf_critical);
		free(mailbox->m_log_ringbuf[mailbox->m_log_ringbuf_pos]);
		mailbox->m_log_ringbuf[mailbox->m_log_ringbuf_pos] = msg;
		mailbox->m_log_ringbuf_times[mailbox->m_log_ringbuf_pos] = time(NULL);
		mailbox->m_log_ringbuf_pos = (mailbox->m_log_ringbuf_pos+1) % MR_LOG_RINGBUF_SIZE;
	pthread_mutex_unlock(&mailbox->m_log_ringbuf_critical);
}


void dc_log_info(dc_context_t* mailbox, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		log_vprintf(mailbox, DC_EVENT_INFO, code, msg, va);
	va_end(va);
}



void dc_log_warning(dc_context_t* mailbox, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		log_vprintf(mailbox, DC_EVENT_WARNING, code, msg, va);
	va_end(va);
}


void dc_log_error(dc_context_t* mailbox, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		log_vprintf(mailbox, DC_EVENT_ERROR, code, msg, va);
	va_end(va);
}


void dc_log_error_if(int* condition, dc_context_t* mailbox, int code, const char* msg, ...)
{
	if( condition == NULL || mailbox==NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	va_list va;
	va_start(va, msg);
		if( *condition ) {
			/* pop-up error, if we're offline, force a "not connected" error (the function is not used for other cases) */
			if( mailbox->m_cb(mailbox, DC_EVENT_IS_OFFLINE, 0, 0)!=0 ) {
				log_vprintf(mailbox, DC_EVENT_ERROR, DC_ERROR_NO_NETWORK, NULL, va);
			}
			else {
				log_vprintf(mailbox, DC_EVENT_ERROR, code, msg, va);
			}
			*condition = 0;
		}
		else {
			/* log a warning only (eg. for subsequent connection errors) */
			log_vprintf(mailbox, DC_EVENT_WARNING, code, msg, va);
		}
	va_end(va);
}


