/*******************************************************************************
 *
 *                              Delta Chat Core
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


#ifndef __MREVENT_H__
#define __MREVENT_H__
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 *
 * The following constants are used as events reported to the callback given to mrmailbox_new().
 */


/**
 * The user may write an informational string to the log.
 * Passed to the callback given to mrmailbox_new().
 * This event should not be reported using a popup or something like that.
 * @param data1 0
 * @param data2 Info string
 * @return 0
 */
#define MR_EVENT_INFO                     100


/**
 * The user should write an warning string to the log.
 * Passed to the callback given to mrmailbox_new().
 * This event should not be reported using a popup or something like that.
 * @param data1 0
 * @param data2 Info string
 * @return 0
 */
#define MR_EVENT_WARNING                  300


/**
 * The user should show an error.
 * The error must be reported to the user by a non-disturbing bubble or so.
 * @param data1 0
 * @param data2 Error string
 * @return 0
 */
#define MR_EVENT_ERROR                    400


/** one or more messages changed for some reasons in the database - added or
removed.  For added messages: data1=chat_id, data2=msg_id */
#define MR_EVENT_MSGS_CHANGED             2000


/** For fresh messages from the INBOX, MR_EVENT_INCOMING_MSG is send;
data1=chat_id, data2=msg_id */
#define MR_EVENT_INCOMING_MSG             2005


/** a single message is send successfully (state changed from PENDING/SENDING to
DELIVERED); data1=chat_id, data2=msg_id */
#define MR_EVENT_MSG_DELIVERED            2010


/** a single message is read by the receiver (state changed from DELIVERED to
READ); data1=chat_id, data2=msg_id */
#define MR_EVENT_MSG_READ                 2015


/** group name/image changed or members added/removed */
#define MR_EVENT_CHAT_MODIFIED            2020


/** contact(s) created, renamed, blocked or deleted */
#define MR_EVENT_CONTACTS_CHANGED         2030


/** connection state changed,
data1=0:failed-not-connected, 1:configured-and-connected */
#define MR_EVENT_CONFIGURE_ENDED          2040


/** data1=percent */
#define MR_EVENT_CONFIGURE_PROGRESS       2041


/** mrmailbox_imex() done:
data1=0:failed, 1=success */
#define MR_EVENT_IMEX_ENDED               2050


/** data1=permille */
#define MR_EVENT_IMEX_PROGRESS            2051


/** file written, event may be needed to make the file public to some system
services. data1=file name, data2=mime type */
#define MR_EVENT_IMEX_FILE_WRITTEN        2052


/* The following events are functions that should be provided by the frontends */


/** check, if the system is online currently
ret=0: not online, ret=1: online */
#define MR_EVENT_IS_ONLINE                2080


/** get a string from the frontend, data1=MR_STR_*, ret=string which will be
free()'d by the backend */
#define MR_EVENT_GET_STRING               2091


/** synchronous http/https(!) call, data1=url, ret=content which will be
free()'d by the backend, 0 on errors */
#define MR_EVENT_GET_QUANTITY_STRING      2092


/** synchronous http/https(!) call, data1=url, ret=content which will be free()'d
by the backend, 0 on errors */
#define MR_EVENT_HTTP_GET                 2100

/** acquire wakeLock (data1=1) or release it (data1=0), the backend does not make
nested or unsynchronized calls */
#define MR_EVENT_WAKE_LOCK                2110


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MREVENT_H__ */

