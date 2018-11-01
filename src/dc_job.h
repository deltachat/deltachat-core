/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

#ifndef __DC_JOB_H__
#define __DC_JOB_H__
#ifdef __cplusplus
extern "C" {
#endif


// thread IDs
#define DC_IMAP_THREAD             100
#define DC_SMTP_THREAD            5000


// jobs in the IMAP-thread
#define DC_JOB_DELETE_MSG_ON_IMAP     110    // low priority ...
#define DC_JOB_MARKSEEN_MDN_ON_IMAP   120
#define DC_JOB_MARKSEEN_MSG_ON_IMAP   130
#define DC_JOB_SEND_MSG_TO_IMAP       700
#define DC_JOB_CONFIGURE_IMAP         900
#define DC_JOB_IMEX_IMAP              910    // ... high priority


// jobs in the SMTP-thread
#define DC_JOB_SEND_MDN              5010    // low priority ...
#define DC_JOB_SEND_MSG_TO_SMTP      5900    // ... high priority


// timeouts until actions are aborted.
// this may also affects IDLE to return, so a re-connect may take this time.
// mailcore2 uses 30 seconds, k-9 uses 10 seconds
#define DC_IMAP_TIMEOUT_SEC       10
#define DC_SMTP_TIMEOUT_SEC       10


// this is the timeout after which dc_perform_smtp_idle() returns at latest.
// this timeout should not be too large as this might be the only option to perform
// jobs that failed on the first execution.
#define DC_SMTP_IDLE_SEC          60


/**
 * Library-internal.
 */
typedef struct dc_job_t
{
	/** @privatesection */

	uint32_t    job_id;
	int         action;
	uint32_t    foreign_id;
	dc_param_t* param;

	int         try_again;
	char*       pending_error; // discarded if the retry succeeds
} dc_job_t;


void     dc_job_add                   (dc_context_t*, int action, int foreign_id, const char* param, int delay);
void     dc_job_kill_actions          (dc_context_t*, int action1, int action2); /* delete all pending jobs with the given actions */

#define  DC_DONT_TRY_AGAIN           0
#define  DC_AT_ONCE                 -1
#define  DC_INCREATION_POLL          2 // this value does not increase the number of tries
#define  DC_STANDARD_DELAY           3
void     dc_job_try_again_later       (dc_job_t*, int try_again, const char* error);


// the other dc_job_do_DC_JOB_*() functions are declared static in the c-file
void     dc_job_do_DC_JOB_CONFIGURE_IMAP (dc_context_t*, dc_job_t*);
void     dc_job_do_DC_JOB_IMEX_IMAP      (dc_context_t*, dc_job_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_JOB_H__ */

