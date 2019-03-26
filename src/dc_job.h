#ifndef __DC_JOB_H__
#define __DC_JOB_H__
#ifdef __cplusplus
extern "C" {
#endif


// thread IDs
#define DC_IMAP_THREAD             100
#define DC_SMTP_THREAD            5000


// jobs in the INBOX-thread, range from DC_IMAP_THREAD..DC_IMAP_THREAD+999
#define DC_JOB_HOUSEKEEPING           105    // low priority ...
#define DC_JOB_DELETE_MSG_ON_IMAP     110
#define DC_JOB_MARKSEEN_MDN_ON_IMAP   120
#define DC_JOB_MARKSEEN_MSG_ON_IMAP   130
#define DC_JOB_MOVE_MSG               200
#define DC_JOB_CONFIGURE_IMAP         900
#define DC_JOB_IMEX_IMAP              910    // ... high priority


// jobs in the SMTP-thread, range from DC_SMTP_THREAD..DC_SMTP_THREAD+999
#define DC_JOB_MAYBE_SEND_LOCATIONS  5005    // low priority ...
#define DC_JOB_SEND_MDN_OLD          5010
#define DC_JOB_SEND_MDN              5011
#define DC_JOB_SEND_MSG_TO_SMTP_OLD  5900
#define DC_JOB_SEND_MSG_TO_SMTP      5901    // ... high priority


// timeouts until actions are aborted.
// this may also affects IDLE to return, so a re-connect may take this time.
// mailcore2 uses 30 seconds, k-9 uses 10 seconds
#define DC_IMAP_TIMEOUT_SEC       10
#define DC_SMTP_TIMEOUT_SEC       10


typedef struct _dc_job dc_job_t;

/**
 * Library-internal.
 */
struct _dc_job
{
	/** @privatesection */

	uint32_t    job_id;
	int         action;
	uint32_t    foreign_id;
	time_t      desired_timestamp;
	time_t      added_timestamp;
	int         tries;
	dc_param_t* param;

	int         try_again;
	char*       pending_error; // discarded if the retry succeeds
};


void     dc_job_add                   (dc_context_t*, int action, int foreign_id, const char* param, int delay);
int      dc_job_action_exists         (dc_context_t*, int action);
void     dc_job_kill_action           (dc_context_t*, int action); /* delete all pending jobs with the given action */

int      dc_job_send_msg              (dc_context_t*, uint32_t msg_id); /* special case for DC_JOB_SEND_MSG_TO_SMTP */

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

