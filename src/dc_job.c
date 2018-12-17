#include <stdarg.h>
#include <unistd.h>
#include <math.h>
#include "dc_context.h"
#include "dc_loginparam.h"
#include "dc_job.h"
#include "dc_imap.h"
#include "dc_smtp.h"
#include "dc_mimefactory.h"


/*******************************************************************************
 * IMAP-jobs
 ******************************************************************************/


static int connect_to_imap(dc_imap_t* imap)
{
	#define          NOT_CONNECTED     0
	#define          ALREADY_CONNECTED 1
	#define          JUST_CONNECTED    2
	int              ret_connected = NOT_CONNECTED;
	dc_loginparam_t* param = dc_loginparam_new();

	if (imap==NULL || imap->context==NULL
	 || imap->context->magic!=DC_CONTEXT_MAGIC ) {
		dc_log_warning(imap->context, 0, "Cannot connect to IMAP: Bad parameters.");
		goto cleanup;
	}

	if (dc_imap_is_connected(imap)) {
		ret_connected = ALREADY_CONNECTED;
		goto cleanup;
	}

	if (dc_sqlite3_get_config_int(imap->context->sql, "configured", 0)==0) {
		dc_log_warning(imap->context, 0, "Not configured, cannot connect.");
		goto cleanup;
	}

	dc_loginparam_read(param, imap->context->sql,
		"configured_" /*the trailing underscore is correct*/);

	if (!dc_imap_connect(imap, param)) {
		goto cleanup;
	}

	ret_connected = JUST_CONNECTED;

cleanup:
	dc_loginparam_unref(param);
	return ret_connected;
}


static int connect_to_inbox(dc_context_t* context)
{
	int   ret_connected = NOT_CONNECTED;
	char* inbox_name = NULL;

	ret_connected = connect_to_imap(context->inbox);
	if (!ret_connected) {
		goto cleanup;
	}

	inbox_name = dc_sqlite3_get_config(context->sql, "imap_folder", "INBOX");
	dc_imap_set_watch_folder(context->inbox, inbox_name);

cleanup:
	free(inbox_name);
	return ret_connected;
}


static int connect_to_mvbox(dc_context_t* context, int* mvbox_desired)
{
	int   ret_connected = NOT_CONNECTED;
	char* mvbox_name = NULL;

	*mvbox_desired = 1;

	// a fallback to support upgrades from core 0.29.0 or older;
	// newer core versions set configured_mvbox_folder during configure.
	if (dc_sqlite3_get_config_int(context->sql, "configured_mvbox", 0)==0) {
		if (!(ret_connected=connect_to_imap(context->mvbox))) {
			goto cleanup;
		}
		dc_imap_configure_folders(context->mvbox);
	}

	mvbox_name = dc_sqlite3_get_config(context->sql, "configured_mvbox_folder", NULL);
	if (mvbox_name==NULL) {
		*mvbox_desired = 0;
		ret_connected = NOT_CONNECTED;
		goto cleanup;
	}

	if (!(ret_connected=connect_to_imap(context->mvbox))) {
		goto cleanup;
	}
	dc_imap_set_watch_folder(context->mvbox, mvbox_name);

cleanup:
	free(mvbox_name);
	return ret_connected;
}


static void dc_job_do_DC_JOB_DELETE_MSG_ON_IMAP(dc_context_t* context, dc_job_t* job)
{
	int           delete_from_server = 1;
	dc_msg_t*     msg = dc_msg_new_untyped(context);

	if (!dc_msg_load_from_db(msg, context, job->foreign_id)
	 || msg->rfc724_mid==NULL || msg->rfc724_mid[0]==0 /* eg. device messages have no Message-ID */) {
		goto cleanup;
	}

	if (dc_rfc724_mid_cnt(context, msg->rfc724_mid)!=1) {
		dc_log_info(context, 0, "The message is deleted from the server when all parts are deleted.");
		delete_from_server = 0;
	}

	/* if this is the last existing part of the message, we delete the message from the server */
	if (delete_from_server)
	{
		if (!dc_imap_is_connected(context->inbox)) {
			connect_to_inbox(context);
			if (!dc_imap_is_connected(context->inbox)) {
				dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
				goto cleanup;
			}
		}

		if (!dc_imap_delete_msg(context->inbox, msg->rfc724_mid, msg->server_folder, msg->server_uid))
		{
			dc_job_try_again_later(job, DC_AT_ONCE, NULL);
			goto cleanup;
		}
	}

	/* we delete the database entry ...
	- if the message is successfully removed from the server
	- or if there are other parts of the message in the database (in this case we have not deleted if from the server)
	(As long as the message is not removed from the IMAP-server, we need at least one database entry to avoid a re-download) */
	dc_delete_msg_from_db(context, msg->id);

cleanup:
	dc_msg_unref(msg);
}


static void dc_job_do_DC_JOB_MARKSEEN_MSG_ON_IMAP(dc_context_t* context, dc_job_t* job)
{
	dc_msg_t* msg = dc_msg_new_untyped(context);
	char*     new_server_folder = NULL;
	uint32_t  new_server_uid = 0;
	int       in_ms_flags = 0;
	int       out_ms_flags = 0;

	if (!dc_imap_is_connected(context->inbox)) {
		connect_to_inbox(context);
		if (!dc_imap_is_connected(context->inbox)) {
			dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
			goto cleanup;
		}
	}

	if (!dc_msg_load_from_db(msg, context, job->foreign_id)) {
		goto cleanup;
	}

	/* add an additional job for sending the MDN (here in a thread for fast ui resonses) (an extra job as the MDN has a lower priority) */
	if (dc_param_get_int(msg->param, DC_PARAM_WANTS_MDN, 0) /* DC_PARAM_WANTS_MDN is set only for one part of a multipart-message */
	 && dc_sqlite3_get_config_int(context->sql, "mdns_enabled", DC_MDNS_DEFAULT_ENABLED)) {
		in_ms_flags |= DC_MS_SET_MDNSent_FLAG;
	}

	if (dc_imap_markseen_msg(context->inbox, msg->server_folder, msg->server_uid,
		   in_ms_flags, &new_server_folder, &new_server_uid, &out_ms_flags)!=0)
	{
		if ((new_server_folder && new_server_uid) || out_ms_flags&DC_MS_MDNSent_JUST_SET)
		{
			if (new_server_folder && new_server_uid)
			{
				dc_update_server_uid(context, msg->rfc724_mid, new_server_folder, new_server_uid);
			}

			if (out_ms_flags&DC_MS_MDNSent_JUST_SET)
			{
				dc_job_add(context, DC_JOB_SEND_MDN, msg->id, NULL, 0);
			}
		}
	}
	else
	{
		dc_job_try_again_later(job, DC_AT_ONCE, NULL);
	}

cleanup:
	dc_msg_unref(msg);
	free(new_server_folder);
}


static void dc_job_do_DC_JOB_MARKSEEN_MDN_ON_IMAP(dc_context_t* context, dc_job_t* job)
{
	char*    server_folder = dc_param_get(job->param, DC_PARAM_SERVER_FOLDER, NULL);
	uint32_t server_uid = dc_param_get_int(job->param, DC_PARAM_SERVER_UID, 0);
	char*    new_server_folder = NULL;
	uint32_t new_server_uid = 0;
	int      out_ms_flags = 0;

	if (!dc_imap_is_connected(context->inbox)) {
		connect_to_inbox(context);
		if (!dc_imap_is_connected(context->inbox)) {
			dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
			goto cleanup;
		}
	}

	if (dc_imap_markseen_msg(context->inbox, server_folder, server_uid, 0, &new_server_folder, &new_server_uid, &out_ms_flags)==0) {
		dc_job_try_again_later(job, DC_AT_ONCE, NULL);
	}

cleanup:
	free(server_folder);
	free(new_server_folder);
}


static void dc_suspend_mvbox_thread(dc_context_t* context, int suspend)
{
	if (suspend)
	{
		dc_log_info(context, 0, "Suspending MVBOX-thread.");
		pthread_mutex_lock(&context->mvboxidle_condmutex);
			context->mvbox_suspended = 1;
		pthread_mutex_unlock(&context->mvboxidle_condmutex);

		dc_interrupt_mvbox_idle(context);

		// wait until we're out of idle,
		// after that the handle won't be in use anymore
		while (1) {
			pthread_mutex_lock(&context->mvboxidle_condmutex);
				if (context->mvbox_using_handle==0) {
					pthread_mutex_unlock(&context->mvboxidle_condmutex);
					return;
				}
			pthread_mutex_unlock(&context->mvboxidle_condmutex);
			usleep(300*1000);
		}
	}
	else
	{
		dc_log_info(context, 0, "Unsuspending MVBOX-thread.");
		pthread_mutex_lock(&context->mvboxidle_condmutex);
			context->mvbox_suspended = 0;
			context->mvboxidle_condflag = 1;
			pthread_cond_signal(&context->mvboxidle_cond);
		pthread_mutex_unlock(&context->mvboxidle_condmutex);
	}
}


/*******************************************************************************
 * SMTP-jobs
 ******************************************************************************/


static void dc_job_do_DC_JOB_SEND_MSG_TO_SMTP(dc_context_t* context, dc_job_t* job)
{
	char*            pathNfilename = NULL;
	dc_mimefactory_t mimefactory;
	dc_mimefactory_init(&mimefactory, context);

	/* connect to SMTP server, if not yet done */
	if (!dc_smtp_is_connected(context->smtp)) {
		dc_loginparam_t* loginparam = dc_loginparam_new();
			dc_loginparam_read(loginparam, context->sql, "configured_");
			int connected = dc_smtp_connect(context->smtp, loginparam);
		dc_loginparam_unref(loginparam);
		if (!connected) {
			dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
			goto cleanup;
		}
	}

	/* load message data */
	if (!dc_mimefactory_load_msg(&mimefactory, job->foreign_id)
	 || mimefactory.from_addr==NULL) {
		dc_log_warning(context, 0, "Cannot load data to send, maybe the message is deleted in between.");
		goto cleanup; // no redo, no IMAP. moreover, as the data does not exist, there is no need in calling dc_set_msg_failed()
	}

	/* check if the message is ready (normally, only video files may be delayed this way) */
	if (mimefactory.increation) {
		dc_log_info(context, 0, "File is in creation, retrying later.");
		dc_job_try_again_later(job, DC_INCREATION_POLL, NULL);
		goto cleanup;
	}

	/* set width/height of images, if not yet done */
	if (DC_MSG_NEEDS_ATTACHMENT(mimefactory.msg->type)) {
		char* pathNfilename = dc_param_get(mimefactory.msg->param, DC_PARAM_FILE, NULL);
		if (pathNfilename) {
			if ((mimefactory.msg->type==DC_MSG_IMAGE || mimefactory.msg->type==DC_MSG_GIF)
			 && !dc_param_exists(mimefactory.msg->param, DC_PARAM_WIDTH)) {
				unsigned char* buf = NULL; size_t buf_bytes; uint32_t w, h;
				dc_param_set_int(mimefactory.msg->param, DC_PARAM_WIDTH, 0);
				dc_param_set_int(mimefactory.msg->param, DC_PARAM_HEIGHT, 0);
				if (dc_read_file(context, pathNfilename, (void**)&buf, &buf_bytes)) {
					if (dc_get_filemeta(buf, buf_bytes, &w, &h)) {
						dc_param_set_int(mimefactory.msg->param, DC_PARAM_WIDTH, w);
						dc_param_set_int(mimefactory.msg->param, DC_PARAM_HEIGHT, h);
					}
				}
				free(buf);
				dc_msg_save_param_to_disk(mimefactory.msg);
			}
		}
	}

	/* send message */
	{
		if (!dc_mimefactory_render(&mimefactory)) {
			dc_set_msg_failed(context, job->foreign_id, mimefactory.error);
			goto cleanup; // no redo, no IMAP - this will also fail next time
		}

		/* have we guaranteed encryption but cannot fulfill it for any reason? Do not send the message then.*/
		if (dc_param_get_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 0) && !mimefactory.out_encrypted) {
			dc_set_msg_failed(context, job->foreign_id, "End-to-end-encryption unavailable unexpectedly.");
			goto cleanup; /* unrecoverable */
		}

		/* add SELF to the recipient list (it's no longer used elsewhere, so a copy of the whole list is needless) */
		if (clist_search_string_nocase(mimefactory.recipients_addr, mimefactory.from_addr)==0) {
			clist_append(mimefactory.recipients_names, NULL);
			clist_append(mimefactory.recipients_addr,  (void*)dc_strdup(mimefactory.from_addr));
		}

		if (!dc_smtp_send_msg(context->smtp, mimefactory.recipients_addr, mimefactory.out->str, mimefactory.out->len)) {
			if (MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION==context->smtp->error_etpan
			 || MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE==context->smtp->error_etpan) {
				dc_set_msg_failed(context, job->foreign_id, context->smtp->error);
			}
			else {
				dc_smtp_disconnect(context->smtp);
				dc_job_try_again_later(job, DC_AT_ONCE, context->smtp->error);
			}
			goto cleanup;
		}
	}

	/* done */
	dc_sqlite3_begin_transaction(context->sql);

		dc_update_msg_state(context, mimefactory.msg->id, DC_STATE_OUT_DELIVERED);
		if (mimefactory.out_encrypted && dc_param_get_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 0)==0) {
			dc_param_set_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 1); /* can upgrade to E2EE - fine! */
			dc_msg_save_param_to_disk(mimefactory.msg);
		}

		// TODO: add to keyhistory
		dc_add_to_keyhistory(context, NULL, 0, NULL, NULL);

	dc_sqlite3_commit(context->sql);

	context->cb(context, DC_EVENT_MSG_DELIVERED, mimefactory.msg->chat_id, mimefactory.msg->id);

cleanup:
	dc_mimefactory_empty(&mimefactory);
	free(pathNfilename);
}


static void dc_job_do_DC_JOB_SEND_MDN(dc_context_t* context, dc_job_t* job)
{
	dc_mimefactory_t mimefactory;
	dc_mimefactory_init(&mimefactory, context);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || job==NULL) {
		return;
	}

	/* connect to SMTP server, if not yet done */
	if (!dc_smtp_is_connected(context->smtp))
	{
		dc_loginparam_t* loginparam = dc_loginparam_new();
			dc_loginparam_read(loginparam, context->sql, "configured_");
			int connected = dc_smtp_connect(context->smtp, loginparam);
		dc_loginparam_unref(loginparam);
		if (!connected) {
			dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
			goto cleanup;
		}
	}

    if (!dc_mimefactory_load_mdn(&mimefactory, job->foreign_id)
     || !dc_mimefactory_render(&mimefactory)) {
		goto cleanup;
    }

	//char* t1=dc_null_terminate(mimefactory.out->str,mimefactory.out->len);printf("~~~~~MDN~~~~~\n%s\n~~~~~/MDN~~~~~",t1);free(t1); // DEBUG OUTPUT

	if (!dc_smtp_send_msg(context->smtp, mimefactory.recipients_addr, mimefactory.out->str, mimefactory.out->len)) {
		dc_smtp_disconnect(context->smtp);
		dc_job_try_again_later(job, DC_AT_ONCE, NULL);
		goto cleanup;
	}

cleanup:
	dc_mimefactory_empty(&mimefactory);
}


static void dc_suspend_smtp_thread(dc_context_t* context, int suspend)
{
	pthread_mutex_lock(&context->smtpidle_condmutex);
		context->smtp_suspended = suspend;
	pthread_mutex_unlock(&context->smtpidle_condmutex);

	// if the smtp-thread is currently in dc_perform_smtp_jobs(),
	// wait until the jobs are done.
	// this function is only needed during dc_configure();
	// for simplicity, we do this by polling a variable.
	if (suspend)
	{
		while (1) {
			pthread_mutex_lock(&context->smtpidle_condmutex);
				if (context->smtp_doing_jobs==0) {
					pthread_mutex_unlock(&context->smtpidle_condmutex);
					return;
				}
			pthread_mutex_unlock(&context->smtpidle_condmutex);
			usleep(300*1000);
		}
	}
}


/*******************************************************************************
 * Tools
 ******************************************************************************/


static time_t get_backoff_time_offset(int c_tries)
{
	#define MULTIPLY 60
	#define JOB_RETRIES 17 // results in ~3 weeks for the last backoff timespan

	time_t N = (time_t)pow((double)2, c_tries - 1);

	N = N * MULTIPLY;

	time_t seconds = rand() % (N+1);

	if (seconds<1) {
		seconds = 1;
	}

	return seconds;
}


static time_t get_next_wakeup_time(dc_context_t* context, int thread)
{
	time_t        wakeup_time = 0;
	sqlite3_stmt* stmt = NULL;

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT MIN(desired_timestamp)"
		" FROM jobs"
		" WHERE thread=?;");
	sqlite3_bind_int(stmt, 1, thread);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		wakeup_time = sqlite3_column_int(stmt, 0);
	}

	if (wakeup_time==0) {
		wakeup_time = time(NULL) + 10*60;
	}

	sqlite3_finalize(stmt);
	return wakeup_time;
}


void dc_job_add(dc_context_t* context, int action, int foreign_id, const char* param, int delay_seconds)
{
	time_t        timestamp = time(NULL);
	sqlite3_stmt* stmt = NULL;
	int           thread = 0;

	if (action >= DC_IMAP_THREAD && action < DC_IMAP_THREAD+1000) {
		thread = DC_IMAP_THREAD;
	}
	else if (action >= DC_SMTP_THREAD && action < DC_SMTP_THREAD+1000) {
		thread = DC_SMTP_THREAD;
	}
	else {
		return;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO jobs (added_timestamp, thread, action, foreign_id, param, desired_timestamp) VALUES (?,?,?,?,?,?);");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, thread);
	sqlite3_bind_int  (stmt, 3, action);
	sqlite3_bind_int  (stmt, 4, foreign_id);
	sqlite3_bind_text (stmt, 5, param? param : "",  -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 6, timestamp+delay_seconds);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (thread==DC_IMAP_THREAD) {
		dc_interrupt_imap_idle(context);
	}
	else {
		dc_interrupt_smtp_idle(context);
	}
}


static void dc_job_update(dc_context_t* context, const dc_job_t* job)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE jobs"
		" SET desired_timestamp=?, tries=?, param=?"
		" WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, job->desired_timestamp);
	sqlite3_bind_int64(stmt, 2, job->tries);
	sqlite3_bind_text (stmt, 3, job->param->packed, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt, 4, job->job_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


static void dc_job_delete(dc_context_t* context, const dc_job_t* job)
{
	sqlite3_stmt* delete_stmt = dc_sqlite3_prepare(context->sql,
		"DELETE FROM jobs WHERE id=?;");
	sqlite3_bind_int(delete_stmt, 1, job->job_id);
	sqlite3_step(delete_stmt);
	sqlite3_finalize(delete_stmt);
}


void dc_job_try_again_later(dc_job_t* job, int try_again, const char* pending_error)
{
	if (job==NULL) {
		return;
	}

	job->try_again = try_again;

	free(job->pending_error);
	job->pending_error = dc_strdup_keep_null(pending_error);
}


void dc_job_kill_actions(dc_context_t* context, int action1, int action2)
{
	if (context==NULL) {
		return;
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"DELETE FROM jobs WHERE action=? OR action=?;");
	sqlite3_bind_int(stmt, 1, action1);
	sqlite3_bind_int(stmt, 2, action2);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


static void dc_job_perform(dc_context_t* context, int thread, int probe_network)
{
	sqlite3_stmt* select_stmt = NULL;
	dc_job_t      job;
	#define       THREAD_STR (thread==DC_IMAP_THREAD? "INBOX" : "SMTP")
	#define       IS_EXCLUSIVE_JOB (DC_JOB_CONFIGURE_IMAP==job.action || DC_JOB_IMEX_IMAP==job.action)

	memset(&job, 0, sizeof(dc_job_t));
	job.param = dc_param_new();

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (probe_network==0) {
		// processing for first-try and after backoff-timeouts:
		// process jobs in the order they were added.
		#define FIELDS "id, action, foreign_id, param, added_timestamp, desired_timestamp, tries"
		select_stmt = dc_sqlite3_prepare(context->sql,
			"SELECT " FIELDS " FROM jobs"
			" WHERE thread=? AND desired_timestamp<=?"
			" ORDER BY action DESC, added_timestamp;");
		sqlite3_bind_int64(select_stmt, 1, thread);
		sqlite3_bind_int64(select_stmt, 2, time(NULL));
	}
	else {
		// processing after call to dc_maybe_network():
		// process _all_ pending jobs that failed before
		// in the order of their backoff-times.
		select_stmt = dc_sqlite3_prepare(context->sql,
			"SELECT " FIELDS " FROM jobs"
			" WHERE thread=? AND tries>0"
			" ORDER BY desired_timestamp, action DESC;");
		sqlite3_bind_int64(select_stmt, 1, thread);
	}

	while (sqlite3_step(select_stmt)==SQLITE_ROW)
	{
		job.job_id                          = sqlite3_column_int  (select_stmt, 0);
		job.action                          = sqlite3_column_int  (select_stmt, 1);
		job.foreign_id                      = sqlite3_column_int  (select_stmt, 2);
		dc_param_set_packed(job.param, (char*)sqlite3_column_text (select_stmt, 3));
		job.added_timestamp                 = sqlite3_column_int64(select_stmt, 4);
		job.desired_timestamp               = sqlite3_column_int64(select_stmt, 5);
		job.tries                           = sqlite3_column_int  (select_stmt, 6);

		dc_log_info(context, 0, "%s-job #%i, action %i started...", THREAD_STR, (int)job.job_id, (int)job.action);

		// some configuration jobs are "exclusive":
		// - they are always executed in the imap-thread and the smtp-thread is suspended during execution
		// - they may change the database handle change the database handle; we do not keep old pointers therefore
		// - they can be re-executed one time AT_ONCE, but they are not save in the database for later execution
		if (IS_EXCLUSIVE_JOB) {
			dc_job_kill_actions(context, job.action, 0);
			sqlite3_finalize(select_stmt);
			select_stmt = NULL;
			dc_suspend_mvbox_thread(context, 1);
			dc_suspend_smtp_thread(context, 1);
		}

		for (int tries = 0; tries <= 1; tries++)
		{
			job.try_again = DC_DONT_TRY_AGAIN; // this can be modified by a job using dc_job_try_again_later()

			switch (job.action) {
				case DC_JOB_SEND_MSG_TO_SMTP:     dc_job_do_DC_JOB_SEND_MSG_TO_SMTP     (context, &job); break;
				case DC_JOB_DELETE_MSG_ON_IMAP:   dc_job_do_DC_JOB_DELETE_MSG_ON_IMAP   (context, &job); break;
				case DC_JOB_MARKSEEN_MSG_ON_IMAP: dc_job_do_DC_JOB_MARKSEEN_MSG_ON_IMAP (context, &job); break;
				case DC_JOB_MARKSEEN_MDN_ON_IMAP: dc_job_do_DC_JOB_MARKSEEN_MDN_ON_IMAP (context, &job); break;
				case DC_JOB_SEND_MDN:             dc_job_do_DC_JOB_SEND_MDN             (context, &job); break;
				case DC_JOB_CONFIGURE_IMAP:       dc_job_do_DC_JOB_CONFIGURE_IMAP       (context, &job); break;
				case DC_JOB_IMEX_IMAP:            dc_job_do_DC_JOB_IMEX_IMAP            (context, &job); break;
			}

			if (job.try_again!=DC_AT_ONCE) {
				break;
			}
		}

		if (IS_EXCLUSIVE_JOB) {
			dc_suspend_mvbox_thread(context, 0);
			dc_suspend_smtp_thread(context, 0);
			goto cleanup;
		}
		else if (job.try_again==DC_INCREATION_POLL)
		{
			// just try over next loop unconditionally, the ui typically interrupts idle when the file (video) is ready
			dc_log_info(context, 0, "%s-job #%i not yet ready and will be delayed.", THREAD_STR, (int)job.job_id);
		}
		else if (job.try_again==DC_AT_ONCE || job.try_again==DC_STANDARD_DELAY)
		{
			int tries = job.tries + 1;

			if( tries < JOB_RETRIES ) {
				job.tries = tries;

				time_t time_offset = get_backoff_time_offset(tries);
				job.desired_timestamp = job.added_timestamp + time_offset;

				dc_job_update(context, &job);
				dc_log_info(context, 0, "%s-job #%i not succeeded on try #%i, retry in ADD_TIME+%i (in %i seconds).", THREAD_STR, (int)job.job_id,
					tries, time_offset, (job.added_timestamp+time_offset)-time(NULL));

				if (thread==DC_SMTP_THREAD && tries<(JOB_RETRIES-1)) {
					pthread_mutex_lock(&context->smtpidle_condmutex);
						context->perform_smtp_jobs_needed = DC_JOBS_NEEDED_AVOID_DOS;
					pthread_mutex_unlock(&context->smtpidle_condmutex);
				}
			}
			else {
				if (job.action==DC_JOB_SEND_MSG_TO_SMTP) { // in all other cases, the messages is already sent
					dc_set_msg_failed(context, job.foreign_id, job.pending_error);
				}
				dc_job_delete(context, &job);
			}

			if (probe_network) {
				// on dc_maybe_network() we stop trying here;
				// these jobs are already tried once.
				// otherwise, we just continue with the next job
				// to give other jobs a chance being tried at least once.
				goto cleanup;
			}
		}
		else
		{
			dc_job_delete(context, &job);
		}
	}

cleanup:
	dc_param_unref(job.param);
	free(job.pending_error);
	sqlite3_finalize(select_stmt);
}


/*******************************************************************************
 * User-functions handle IMAP-jobs from the IMAP-thread
 ******************************************************************************/


/**
 * Execute pending imap-jobs.
 * This function and dc_perform_imap_fetch() and dc_perform_imap_idle() must be called from the same thread,
 * typically in a loop.
 *
 * See dc_interrupt_imap_idle() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_imap_jobs(dc_context_t* context)
{
	dc_log_info(context, 0, "INBOX-jobs started...");

	pthread_mutex_lock(&context->inboxidle_condmutex);
		int probe_imap_network = context->probe_imap_network;
		context->probe_imap_network = 0;

		context->perform_inbox_jobs_needed = 0;
	pthread_mutex_unlock(&context->inboxidle_condmutex);

	dc_job_perform(context, DC_IMAP_THREAD, probe_imap_network);

	dc_log_info(context, 0, "INBOX-jobs ended.");
}


/**
 * Fetch new messages, if any.
 * This function and dc_perform_imap_jobs() and dc_perform_imap_idle() must be called from the same thread,
 * typically in a loop.
 *
 * See dc_interrupt_imap_idle() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_imap_fetch(dc_context_t* context)
{
	clock_t start = clock();

	if (!connect_to_inbox(context)) {
		return;
	}

	dc_log_info(context, 0, "INBOX-fetch started...");

	dc_imap_fetch(context->inbox);

	if (context->inbox->should_reconnect)
	{
		dc_log_info(context, 0, "INBOX-fetch aborted, starting over...");
		dc_imap_fetch(context->inbox);
	}

	dc_log_info(context, 0, "INBOX-fetch done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);
}


/**
 * Wait for messages or jobs.
 * This function and dc_perform_imap_jobs() and dc_perform_imap_fetch() must be called from the same thread,
 * typically in a loop.
 *
 * You should call this function directly after calling dc_perform_imap_fetch().
 *
 * See dc_interrupt_imap_idle() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_imap_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	// also idle if connection fails because of not-configured,
	// no-network, whatever. dc_imap_idle() will handle this by the fake-idle and log a warning
	connect_to_inbox(context);

	pthread_mutex_lock(&context->inboxidle_condmutex);
		if (context->perform_inbox_jobs_needed) {
			dc_log_info(context, 0, "INBOX-IDLE will not be started because of waiting jobs.");
			pthread_mutex_unlock(&context->inboxidle_condmutex);
			return;
		}
	pthread_mutex_unlock(&context->inboxidle_condmutex);

	dc_log_info(context, 0, "INBOX-IDLE started...");

	dc_imap_idle(context->inbox);

	dc_log_info(context, 0, "INBOX-IDLE ended.");
}


/**
 * Interrupt waiting for imap-jobs.
 * If dc_perform_imap_jobs(), dc_perform_imap_fetch() and dc_perform_imap_idle() are called in a loop,
 * calling this function causes imap-jobs to be executed and messages to be fetched.
 *
 * dc_interrupt_imap_idle() does _not_ interrupt dc_perform_imap_jobs() or dc_perform_imap_fetch().
 * If the imap-thread is inside one of these functions when dc_interrupt_imap_idle() is called, however,
 * the next call of the imap-thread to dc_perform_imap_idle() is interrupted immediately.
 *
 * Internally, this function is called whenever a imap-jobs should be processed (delete message, markseen etc.),
 * for the UI view it may make sense to call the function eg. on network changes to fetch messages immediately.
 *
 * Example:
 *
 *     void* imap_thread_func(void* context)
 *     {
 *         while (true) {
 *             dc_perform_imap_jobs(context);
 *             dc_perform_imap_fetch(context);
 *             dc_perform_imap_idle(context);
 *         }
 *     }
 *
 *     // start imap-thread that runs forever
 *     pthread_t imap_thread;
 *     pthread_create(&imap_thread, NULL, imap_thread_func, context);
 *
 *     ... program runs ...
 *
 *     // network becomes available again - the interrupt causes
 *     // dc_perform_imap_idle() in the thread to return so that jobs are executed
 *     // and messages are fetched.
 *     dc_interrupt_imap_idle(context);
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_interrupt_imap_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->inbox==NULL) {
		dc_log_warning(context, 0, "Interrupt IMAP-IDLE: Bad parameters.");
		return;
	}

	dc_log_info(context, 0, "Interrupting IMAP-IDLE...");

	pthread_mutex_lock(&context->inboxidle_condmutex);
		// when this function is called, it might be that the idle-thread is in
		// perform_idle_jobs() instead of idle(). if so, added jobs will be performed after the _next_ idle-jobs loop.
		// setting the flag perform_imap_jobs_needed makes sure, idle() returns immediately in this case.
		context->perform_inbox_jobs_needed = 1;
	pthread_mutex_unlock(&context->inboxidle_condmutex);

	dc_imap_interrupt_idle(context->inbox);
}


/*******************************************************************************
 * User-functions to handle IMAP-jobs in the secondary IMAP-thread
 ******************************************************************************/


void dc_perform_mvbox_fetch(dc_context_t* context)
{
	int mvbox_desired = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	pthread_mutex_lock(&context->mvboxidle_condmutex);
		if (context->mvbox_suspended) {
			pthread_mutex_unlock(&context->mvboxidle_condmutex);
			return;
		}

		context->mvbox_using_handle = 1;
	pthread_mutex_unlock(&context->mvboxidle_condmutex);

	clock_t start = clock();

	if (!connect_to_mvbox(context, &mvbox_desired)) {
		return;
	}

	dc_log_info(context, 0, "MVBOX-fetch started...");
	dc_imap_fetch(context->mvbox);

	if (context->mvbox->should_reconnect)
	{
		dc_log_info(context, 0, "MVBOX-fetch aborted, starting over...");
		dc_imap_fetch(context->mvbox);
	}

	dc_log_info(context, 0, "MVBOX-fetch done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	pthread_mutex_lock(&context->mvboxidle_condmutex);
		context->mvbox_using_handle = 0;
	pthread_mutex_unlock(&context->mvboxidle_condmutex);
}


void dc_perform_mvbox_idle(dc_context_t* context)
{
	int mvbox_desired = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	pthread_mutex_lock(&context->mvboxidle_condmutex);
		if (context->mvbox_suspended) {
			while (context->mvboxidle_condflag==0) {
				// unlock mutex -> wait -> lock mutex
				pthread_cond_wait(&context->mvboxidle_cond, &context->mvboxidle_condmutex);
			}
			context->mvboxidle_condflag = 0;
			pthread_mutex_unlock(&context->mvboxidle_condmutex);
			return;
		}

		context->mvbox_using_handle = 1;
	pthread_mutex_unlock(&context->mvboxidle_condmutex);

	connect_to_mvbox(context, &mvbox_desired);
	if (!mvbox_desired) {
		pthread_mutex_lock(&context->mvboxidle_condmutex);
			context->mvbox_using_handle = 0;
			while (context->mvboxidle_condflag==0) {
				// unlock mutex -> wait -> lock mutex
				pthread_cond_wait(&context->mvboxidle_cond, &context->mvboxidle_condmutex);
			}
			context->mvboxidle_condflag = 0;
		pthread_mutex_unlock(&context->mvboxidle_condmutex);
		return;
	}

	dc_log_info(context, 0, "MVBOX-IDLE started...");
	dc_imap_idle(context->mvbox);
	dc_log_info(context, 0, "MVBOX-IDLE ended.");

	pthread_mutex_lock(&context->mvboxidle_condmutex);
		context->mvbox_using_handle = 0;
	pthread_mutex_unlock(&context->mvboxidle_condmutex);
}


void dc_interrupt_mvbox_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->mvbox==NULL) {
		dc_log_warning(context, 0, "Interrupt MVBOX-IDLE: Bad parameters.");
		return;
	}

	dc_log_info(context, 0, "Interrupting MVBOX-IDLE...");
	dc_imap_interrupt_idle(context->mvbox);
}


/*******************************************************************************
 * User-functions handle SMTP-jobs from the SMTP-thread
 ******************************************************************************/


/**
 * Execute pending smtp-jobs.
 * This function and dc_perform_smtp_idle() must be called from the same thread,
 * typically in a loop.
 *
 * See dc_interrupt_smtp_idle() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_smtp_jobs(dc_context_t* context)
{
	pthread_mutex_lock(&context->smtpidle_condmutex);
		int probe_smtp_network = context->probe_smtp_network;
		context->probe_smtp_network = 0;

		context->perform_smtp_jobs_needed = 0;
		if (context->smtp_suspended) {
			dc_log_info(context, 0, "SMTP-jobs suspended.");
			pthread_mutex_unlock(&context->smtpidle_condmutex);
			return;
		}
		context->smtp_doing_jobs = 1;
	pthread_mutex_unlock(&context->smtpidle_condmutex);

	dc_log_info(context, 0, "SMTP-jobs started...");
	dc_job_perform(context, DC_SMTP_THREAD, probe_smtp_network);
	dc_log_info(context, 0, "SMTP-jobs ended.");

	pthread_mutex_lock(&context->smtpidle_condmutex);
		context->smtp_doing_jobs = 0;
	pthread_mutex_unlock(&context->smtpidle_condmutex);
}


/**
 * Wait for smtp-jobs.
 * This function and dc_perform_smtp_jobs() must be called from the same thread,
 * typically in a loop.
 *
 * See dc_interrupt_smtp_idle() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_smtp_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		dc_log_warning(context, 0, "Cannot perform SMTP-idle: Bad parameters.");
		return;
	}

	dc_log_info(context, 0, "SMTP-idle started...");

	pthread_mutex_lock(&context->smtpidle_condmutex);

		if (context->perform_smtp_jobs_needed==DC_JOBS_NEEDED_AT_ONCE)
		{
			dc_log_info(context, 0, "SMTP-idle will not be started because of waiting jobs.");
		}
		else
		{
			int r = 0;
			struct timespec wakeup_at;
			memset(&wakeup_at, 0, sizeof(wakeup_at));
			wakeup_at.tv_sec  = get_next_wakeup_time(context, DC_SMTP_THREAD)+1;
			while (context->smtpidle_condflag==0 && r==0) {
				r = pthread_cond_timedwait(&context->smtpidle_cond, &context->smtpidle_condmutex, &wakeup_at); // unlock mutex -> wait -> lock mutex
			}
			context->smtpidle_condflag = 0;
		}

	pthread_mutex_unlock(&context->smtpidle_condmutex);

	dc_log_info(context, 0, "SMTP-idle ended.");
}


/**
 * Interrupt waiting for smtp-jobs.
 * If dc_perform_smtp_jobs() and dc_perform_smtp_idle() are called in a loop,
 * calling this function causes jobs to be executed.
 *
 * dc_interrupt_smtp_idle() does _not_ interrupt dc_perform_smtp_jobs().
 * If the smtp-thread is inside this function when dc_interrupt_smtp_idle() is called, however,
 * the next call of the smtp-thread to dc_perform_smtp_idle() is interrupted immediately.
 *
 * Internally, this function is called whenever a message is to be send,
 * for the UI view it may make sense to call the function eg. on network changes.
 *
 * Example:
 *
 *     void* smtp_thread_func(void* context)
 *     {
 *         while (true) {
 *             dc_perform_smtp_jobs(context);
 *             dc_perform_smtp_idle(context);
 *         }
 *     }
 *
 *     // start smtp-thread that runs forever
 *     pthread_t smtp_thread;
 *     pthread_create(&smtp_thread, NULL, smtp_thread_func, context);
 *
 *     ... program runs ...
 *
 *     // network becomes available again - the interrupt causes
 *     // dc_perform_smtp_idle() in the thread to return so that jobs are executed
 *     dc_interrupt_smtp_idle(context);
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_interrupt_smtp_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		dc_log_warning(context, 0, "Interrupt SMTP-idle: Bad parameters.");
		return;
	}

	dc_log_info(context, 0, "Interrupting SMTP-idle...");

	pthread_mutex_lock(&context->smtpidle_condmutex);

		// when this function is called, it might be that the smtp-thread is in
		// perform_smtp_jobs(). if so, added jobs will be performed after the _next_ idle-jobs loop.
		// setting the flag perform_smtp_jobs_needed makes sure, idle() returns immediately in this case.
		context->perform_smtp_jobs_needed = DC_JOBS_NEEDED_AT_ONCE;

		context->smtpidle_condflag = 1;
		pthread_cond_signal(&context->smtpidle_cond);

	pthread_mutex_unlock(&context->smtpidle_condmutex);
}



/**
 * This function can be called whenever there is a hint
 * that the network is available again.
 * The library will try to send pending messages out.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_maybe_network(dc_context_t* context)
{
	// the following flags are forwarded to dc_job_perform() and make sure,
	// sending is tried independingly of retry-count or timeouts.
	// if the first messages comes through, the others are be retried as well.
	pthread_mutex_lock(&context->smtpidle_condmutex);
		context->probe_smtp_network = 1;
	pthread_mutex_unlock(&context->smtpidle_condmutex);

	pthread_mutex_lock(&context->inboxidle_condmutex);
		context->probe_imap_network = 1;
	pthread_mutex_unlock(&context->inboxidle_condmutex);

	dc_interrupt_smtp_idle(context);
	dc_interrupt_imap_idle(context);
	dc_interrupt_mvbox_idle(context);
}
