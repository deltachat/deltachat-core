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


#define MR_THREAD_NOTALLOCATED  0
#define MR_THREAD_INIT         10
#define MR_THREAD_CONNECT      20
#define MR_THREAD_WAIT         30
#define MR_THREAD_FETCH        40
#define MR_THREAD_EXIT         50


typedef struct mrimapthreadval_t
{
	mailimap*    m_imap;
} mrimapthreadval_t;


typedef struct mrimap_t
{
	mrmailbox_t*          m_mailbox;
	mrloginparam_t*       m_loginParam;

	pthread_t             m_thread;
	int                   m_threadState; /* set by the working thread, the main thread can read this, one of MR_THREAD_* */
	int                   m_threadCmd;   /* set by the main thread, read and reset by the working thread, one of MR_THREAD_* */
	pthread_cond_t        m_cond;
	pthread_mutex_t       m_condmutex;

	char*                 m_debugDir;
} mrimap_t;


mrimap_t* mrimap_new               (mrmailbox_t*);
void      mrimap_unref             (mrimap_t*);

int       mrimap_is_connected      (mrimap_t*);
int       mrimap_connect           (mrimap_t*, mrloginparam_t*); /* mrimap_connect() takes ownership of the mrloginparam_t-object */
void      mrimap_disconnect        (mrimap_t*);
int       mrimap_fetch             (mrimap_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRIMAP_H__ */

