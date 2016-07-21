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


#include "mrloginparam.h"
class MrMailbox;


enum MrImapThreadCmd
{
	 MR_THREAD_NOTALLOCATED = 0
	,MR_THREAD_INIT
	,MR_THREAD_CONNECT
	,MR_THREAD_WAIT
	,MR_THREAD_FETCH
	,MR_THREAD_EXIT
};


class MrImapThreadVal
{
public:
	MrImapThreadVal()
	{
		m_imap = NULL;
	}

	mailimap*    m_imap;
};


class MrImap
{
public:
	                    MrImap               (MrMailbox* mailbox);
	                    ~MrImap              ();

	bool                IsConnected          () { return (m_threadState!=MR_THREAD_NOTALLOCATED); }
	bool                Connect              (const MrLoginParam*);
	void                Disconnect           ();
	bool                Fetch                ();

private:
	MrMailbox*          m_mailbox;
	const MrLoginParam* m_loginParam;

	pthread_t           m_thread;
	MrImapThreadCmd     m_threadState; // set by the working thread, the main thread can read this
	MrImapThreadCmd     m_threadCmd;   // set by the main thread, read and reset by the working thread
	pthread_cond_t      m_cond;
	pthread_mutex_t     m_condmutex;

	static void         StartupHelper       (MrImap*);
	void                WorkingThread       ();

	void                FetchFromFolder     (MrImapThreadVal&, const char* folder);
	void                FetchSingleMsg      (MrImapThreadVal&, const char* folder, uint32_t uid);
};


#endif // __MRIMAP_H__

