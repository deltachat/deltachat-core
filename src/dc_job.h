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


#ifndef __MRJOB_H__
#define __MRJOB_H__
#ifdef __cplusplus
extern "C" {
#endif


// thread IDs
#define MR_IMAP_THREAD             100
#define MR_SMTP_THREAD            5000


// jobs in the IMAP-thread
#define MRJ_DELETE_MSG_ON_IMAP     110    // low priority ...
#define MRJ_MARKSEEN_MDN_ON_IMAP   120
#define MRJ_MARKSEEN_MSG_ON_IMAP   130
#define MRJ_SEND_MSG_TO_IMAP       700
#define MRJ_CONFIGURE_IMAP         900    // ... high priority


// jobs in the SMTP-thread
#define MRJ_SEND_MDN              5010    // low priority ...
#define MRJ_SEND_MSG_TO_SMTP      5900    // ... high priority


// timeouts until actions are aborted.
// this may also affects IDLE to return, so a re-connect may take this time.
// mailcore2 uses 30 seconds, k-9 uses 10 seconds
#define MR_IMAP_TIMEOUT_SEC       10
#define MR_SMTP_TIMEOUT_SEC       10


// this is the timeout after which dc_perform_smtp_idle() returns at latest.
// this timeout should not be too large as this might be the only option to perform
// jobs that failed on the first execution.
#define MR_SMTP_IDLE_SEC          60


/**
 * Library-internal.
 */
typedef struct mrjob_t
{
	/** @privatesection */

	uint32_t   m_job_id;
	int        m_action;
	uint32_t   m_foreign_id;
	mrparam_t* m_param;
	int        m_try_again;
} mrjob_t;


void     mrjob_add                   (mrmailbox_t*, int action, int foreign_id, const char* param, int delay);
void     mrjob_kill_actions          (mrmailbox_t*, int action1, int action2); /* delete all pending jobs with the given actions */

#define  MR_DONT_TRY_AGAIN           0
#define  MR_AT_ONCE                 -1
#define  MR_INCREATION_POLL          2 // this value does not increase the number of tries
#define  MR_STANDARD_DELAY           3
void     mrjob_try_again_later       (mrjob_t*, int try_again);


// the other mrjob_do_MRJ_*() functions are declared static in the c-file
void     mrjob_do_MRJ_CONFIGURE_IMAP (mrmailbox_t*, mrjob_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRJOB_H__ */

