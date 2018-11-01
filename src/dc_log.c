/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

/* Asynchronous "Thread-errors" are reported by the dc_log_error()
function.  These errors must be shown to the user by a bubble or so.

"Normal" errors are usually returned by a special value (null or so) and are
usually not reported using dc_log_error() - its up to the caller to
decide, what should be reported or done.  However, these "Normal" errors
are usually logged by dc_log_warning(). */


#include <stdarg.h>
#include <memory.h>
#include "dc_context.h"


static void log_vprintf(dc_context_t* context, int event, int code, const char* msg_format, va_list va)
{
	char* msg = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	/* format message from variable parameters or translate very comming errors */
	if (code==DC_ERROR_SELF_NOT_IN_GROUP)
	{
		msg = dc_stock_str(context, DC_STR_SELFNOTINGRP);
	}
	else if (code==DC_ERROR_NO_NETWORK)
	{
		msg = dc_stock_str(context, DC_STR_NONETWORK);
	}
	else if (msg_format)
	{
		#define BUFSIZE 1024
		char tempbuf[BUFSIZE+1];
		vsnprintf(tempbuf, BUFSIZE, msg_format, va);
		msg = dc_strdup(tempbuf);
	}

	/* if we have still no message, create one based upon  the code */
	if (msg==NULL) {
		     if (event==DC_EVENT_INFO)    { msg = dc_mprintf("Info: %i",    (int)code); }
		else if (event==DC_EVENT_WARNING) { msg = dc_mprintf("Warning: %i", (int)code); }
		else                                 { msg = dc_mprintf("Error: %i",   (int)code); }
	}

	/* finally, log */
	context->cb(context, event, (uintptr_t)code, (uintptr_t)msg);
}


void dc_log_info(dc_context_t* context, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		log_vprintf(context, DC_EVENT_INFO, code, msg, va);
	va_end(va);
}

void dc_log_event(dc_context_t* context, int event_code, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		log_vprintf(context, event_code, code, msg, va);
	va_end(va);
}


void dc_log_warning(dc_context_t* context, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg); /* va_start() expects the last non-variable argument as the second parameter */
		log_vprintf(context, DC_EVENT_WARNING, code, msg, va);
	va_end(va);
}


void dc_log_error(dc_context_t* context, int code, const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
		log_vprintf(context, DC_EVENT_ERROR, code, msg, va);
	va_end(va);
}


void dc_log_error_if(int* condition, dc_context_t* context, int code, const char* msg, ...)
{
	if (condition==NULL || context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	va_list va;
	va_start(va, msg);
		if (*condition) {
			/* pop-up error, if we're offline, force a "not connected" error (the function is not used for other cases) */
			if (context->cb(context, DC_EVENT_IS_OFFLINE, 0, 0)!=0) {
				log_vprintf(context, DC_EVENT_ERROR, DC_ERROR_NO_NETWORK, NULL, va);
			}
			else {
				log_vprintf(context, DC_EVENT_ERROR, code, msg, va);
			}
			*condition = 0;
		}
		else {
			/* log a warning only (eg. for subsequent connection errors) */
			log_vprintf(context, DC_EVENT_WARNING, code, msg, va);
		}
	va_end(va);
}


