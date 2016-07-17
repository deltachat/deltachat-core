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


class MrImap
{
public:
	                    MrImap               (MrMailbox* mailbox);
	                    ~MrImap              ();

	bool                IsConnected          () { return m_threadRunning; }
	bool                Connect              (const MrLoginParam*);
	void                Disconnect           ();
	bool                Fetch                ();

private:
	MrMailbox*          m_mailbox;
	const MrLoginParam* m_loginParam;

	pthread_t           m_thread;
	bool                m_threadRunning;
	pthread_cond_t      m_cond;
	pthread_mutex_t     m_condmutex;

	#define             DO_FETCH 1
	#define             DO_EXIT  2
	int                 m_dowhat;

	static void         StartupHelper       (MrImap* imap) { imap->WorkingThread(); }
	void                WorkingThread       ();
};


#endif // __MRIMAP_H__

