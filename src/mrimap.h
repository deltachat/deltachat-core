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
 * File:    mrimap.h
 * Authors: Björn Petersen
 * Purpose: Reading from IMAP servers
 *
 ******************************************************************************/


#ifndef __MRIMAP_H__
#define __MRIMAP_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mrloginparam_t mrloginparam_t;


typedef struct mrimap_t
{
	mrmailbox_t*          m_mailbox;

	mailimap*             m_hEtpan;

	pthread_t             m_thread;
	int                   m_threadState; /* set by the working thread, the main thread can read this, one of MR_THREAD_* */
	int                   m_threadCmd;   /* set by the main thread, read and reset by the working thread, one of MR_THREAD_* */
	pthread_cond_t        m_cond;
	pthread_mutex_t       m_condmutex;

	char*                 m_imap_server;
	int                   m_imap_port;
	char*                 m_imap_user;
	char*                 m_imap_pw;

	char*                 m_debugDir;
} mrimap_t;


mrimap_t* mrimap_new               (mrmailbox_t*); /* the mailbox object is needed to store IMAP folder states and to call the user callback. We may decide to use separate parameters instead of the mailbox object some time. */
void      mrimap_unref             (mrimap_t*);

int       mrimap_is_connected      (mrimap_t*);
int       mrimap_connect           (mrimap_t*, const mrloginparam_t*);
void      mrimap_disconnect        (mrimap_t*);
int       mrimap_fetch             (mrimap_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRIMAP_H__ */

