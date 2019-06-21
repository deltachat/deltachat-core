#include <stdarg.h>
#include <unistd.h>
#include <math.h>
#include "dc_context.h"
#include "dc_loginparam.h"
#include "dc_job.h"
#include "dc_imap.h"
#include "dc_smtp.h"
#include "dc_mimefactory.h"


static void dc_send_mdn(dc_context_t* context, uint32_t msg_id);


/*******************************************************************************
 * IMAP-jobs
 ******************************************************************************/


static int connect_to_inbox(dc_context_t* context)
{
	int   ret_connected = DC_NOT_CONNECTED;

	ret_connected = dc_connect_to_configured_imap(context, context->inbox);
	if (!ret_connected) {
		goto cleanup;
	}

	dc_imap_set_watch_folder(context->inbox, "INBOX");

cleanup:
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


static void dc_job_do_DC_JOB_EMPTY_SERVER(dc_context_t* context, dc_job_t* job)
{
	if (!dc_imap_is_connected(context->inbox)) {
		connect_to_inbox(context);
		if (!dc_imap_is_connected(context->inbox)) {
			goto cleanup;
		}
	}

	dc_imap_empty_folders(context->inbox, job->foreign_id);

cleanup:
	;
}


static void dc_job_do_DC_JOB_MOVE_MSG(dc_context_t* context, dc_job_t* job)
{
	dc_msg_t* msg = dc_msg_new_untyped(context);
	char*     dest_folder = NULL;
	uint32_t  dest_uid = 0;

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

	if (dc_sqlite3_get_config_int(context->sql, "folders_configured", 0)<DC_FOLDERS_CONFIGURED_VERSION) {
		dc_configure_folders(context, context->inbox, DC_CREATE_MVBOX);
	}

	dest_folder = dc_sqlite3_get_config(context->sql, "configured_mvbox_folder", NULL);

	switch (dc_imap_move(context->inbox, msg->server_folder, msg->server_uid, dest_folder, &dest_uid)) {
		case DC_FAILED:       goto cleanup;
		case DC_RETRY_LATER:  dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL); break;
		case DC_ALREADY_DONE: break;
		case DC_SUCCESS:      dc_update_server_uid(context, msg->rfc724_mid, dest_folder, dest_uid); break;
	}

cleanup:
	free(dest_folder);
	dc_msg_unref(msg);
}


static void dc_job_do_DC_JOB_MARKSEEN_MSG_ON_IMAP(dc_context_t* context, dc_job_t* job)
{
	dc_msg_t* msg = dc_msg_new_untyped(context);

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

	switch (dc_imap_set_seen(context->inbox, msg->server_folder, msg->server_uid)) {
		case DC_FAILED:      goto cleanup;
		case DC_RETRY_LATER: dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL); goto cleanup;
		default:             break;
	}

	if (dc_param_get_int(msg->param, DC_PARAM_WANTS_MDN, 0)
	 && dc_sqlite3_get_config_int(context->sql, "mdns_enabled", DC_MDNS_DEFAULT_ENABLED))
	{
		switch (dc_imap_set_mdnsent(context->inbox, msg->server_folder, msg->server_uid)) {
			case DC_FAILED:       goto cleanup;
			case DC_RETRY_LATER:  dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL); goto cleanup;
			case DC_ALREADY_DONE: break;
			case DC_SUCCESS:      dc_send_mdn(context, msg->id); break;
		}
	}

cleanup:
	dc_msg_unref(msg);
}


static void dc_job_do_DC_JOB_MARKSEEN_MDN_ON_IMAP(dc_context_t* context, dc_job_t* job)
{
	char*     folder = dc_param_get(job->param, DC_PARAM_SERVER_FOLDER, NULL);
	uint32_t  uid = dc_param_get_int(job->param, DC_PARAM_SERVER_UID, 0);
	char*     dest_folder = NULL;
	uint32_t  dest_uid = 0;

	if (!dc_imap_is_connected(context->inbox)) {
		connect_to_inbox(context);
		if (!dc_imap_is_connected(context->inbox)) {
			dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
			goto cleanup;
		}
	}

	if (dc_imap_set_seen(context->inbox, folder, uid)==0) {
		dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL);
	}

	if (dc_param_get_int(job->param, DC_PARAM_ALSO_MOVE, 0))
	{
		if (dc_sqlite3_get_config_int(context->sql, "folders_configured", 0)<DC_FOLDERS_CONFIGURED_VERSION) {
			dc_configure_folders(context, context->inbox, DC_CREATE_MVBOX);
		}

		dest_folder = dc_sqlite3_get_config(context->sql, "configured_mvbox_folder", NULL);

		switch (dc_imap_move(context->inbox, folder, uid, dest_folder, &dest_uid)) {
			case DC_FAILED:      goto cleanup;
			case DC_RETRY_LATER: dc_job_try_again_later(job, DC_STANDARD_DELAY, NULL); break;
			default:             break;
		}
	}

cleanup:
	free(folder);
	free(dest_folder);
}


/*******************************************************************************
 * SMTP-jobs
 ******************************************************************************/


/**
 * Store the MIME message in a file and send it later with a new SMTP job.
 *
 * @param context The context object as created by dc_context_new()
 * @param action One of the DC_JOB_SEND_ constants
 * @param mimefactory An instance of dc_mimefactory_t with a loaded and rendered message or MDN
 * @return 1=success, 0=error
 */
static int dc_add_smtp_job(dc_context_t* context, int action, dc_mimefactory_t* mimefactory)
{
	char*            pathNfilename = NULL;
	int              success = 0;
	char*            recipients = NULL;
	dc_param_t*      param = dc_param_new();

	// find a free file name in the blob directory
	pathNfilename = dc_get_fine_pathNfilename(context, "$BLOBDIR", mimefactory->rfc724_mid);
	if (!pathNfilename) {
		dc_log_error(context, 0, "Could not find free file name for message with ID <%s>.", mimefactory->rfc724_mid);
		goto cleanup;
	}

	// write the file
	if (!dc_write_file(context, pathNfilename, mimefactory->out->str, mimefactory->out->len)) {
		dc_log_error(context, 0, "Could not write message <%s> to \"%s\".", mimefactory->rfc724_mid, pathNfilename);
		goto cleanup;
	}

	// store recipients in job param
	recipients = dc_str_from_clist(mimefactory->recipients_addr, "\x1e");
	dc_param_set(param, DC_PARAM_FILE, pathNfilename);
	dc_param_set(param, DC_PARAM_RECIPIENTS, recipients);

	dc_job_add(context, action, mimefactory->loaded==DC_MF_MSG_LOADED ? mimefactory->msg->id : 0, param->packed, 0);

	success = 1;

cleanup:
	dc_param_unref(param);
	free(recipients);
	free(pathNfilename);
	return success;
}


/**
 * Create an SMTP job to send a message from the DB
 *
 * @param context The context object as created by dc_context_new()
 * @param msg_id The ID of the message to send
 * @return 1=success, 0=error
 */
int dc_job_send_msg(dc_context_t* context, uint32_t msg_id)
{
	int success = 0;
	dc_mimefactory_t mimefactory;
	dc_mimefactory_init(&mimefactory, context);

	/* load message data */
	if (!dc_mimefactory_load_msg(&mimefactory, msg_id)
	 || mimefactory.from_addr==NULL) {
		dc_log_warning(context, 0, "Cannot load data to send, maybe the message is deleted in between.");
		goto cleanup; // no redo, no IMAP. moreover, as the data does not exist, there is no need in calling dc_set_msg_failed()
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
		free(pathNfilename);
	}

	/* create message */
	{
		if (!dc_mimefactory_render(&mimefactory)) {
			dc_set_msg_failed(context, msg_id, mimefactory.error);
			goto cleanup; // no redo, no IMAP - this will also fail next time
		}

		/* have we guaranteed encryption but cannot fulfill it for any reason? Do not send the message then.*/
		if (dc_param_get_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 0) && !mimefactory.out_encrypted) {
			dc_set_msg_failed(context, msg_id, "End-to-end-encryption unavailable unexpectedly.");
			goto cleanup; /* unrecoverable */
		}

		/* add SELF to the recipient list (it's no longer used elsewhere, so a copy of the whole list is needless) */
		if (clist_search_string_nocase(mimefactory.recipients_addr, mimefactory.from_addr)==0) {
			clist_append(mimefactory.recipients_names, NULL);
			clist_append(mimefactory.recipients_addr,  (void*)dc_strdup(mimefactory.from_addr));
		}
	}

	dc_sqlite3_begin_transaction(context->sql);

		if (mimefactory.out_gossiped) {
			dc_set_gossiped_timestamp(context, mimefactory.msg->chat_id, time(NULL));
		}

		if (mimefactory.out_last_added_location_id) {
			dc_set_kml_sent_timestamp(context, mimefactory.msg->chat_id, time(NULL));
			if (!mimefactory.msg->hidden) {
				dc_set_msg_location_id(context, mimefactory.msg->id, mimefactory.out_last_added_location_id);
			}
		}

		if (mimefactory.out_encrypted && dc_param_get_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 0)==0) {
			dc_param_set_int(mimefactory.msg->param, DC_PARAM_GUARANTEE_E2EE, 1); /* can upgrade to E2EE - fine! */
			dc_msg_save_param_to_disk(mimefactory.msg);
		}

		// TODO: add to keyhistory
		dc_add_to_keyhistory(context, NULL, 0, NULL, NULL);

	dc_sqlite3_commit(context->sql);

	success = dc_add_smtp_job(context, DC_JOB_SEND_MSG_TO_SMTP, &mimefactory);

cleanup:
	dc_mimefactory_empty(&mimefactory);
	return success;
}


static void dc_job_do_DC_JOB_SEND(dc_context_t* context, dc_job_t* job)
{
	char*         filename = NULL;
	void*         buf = NULL;
	size_t        buf_bytes = 0;
	char*         recipients = NULL;
	clist*        recipients_list = NULL;
	sqlite3_stmt* stmt = NULL;

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
	filename = dc_param_get(job->param, DC_PARAM_FILE, NULL);
	if (!filename) {
		dc_log_warning(context, 0, "Missing file name for job %d", job->job_id);
		goto cleanup;
	}
	if (!dc_read_file(context, filename, &buf, &buf_bytes)) {
		goto cleanup;
	}

	/* get the list of recipients */
	recipients = dc_param_get(job->param, DC_PARAM_RECIPIENTS, NULL);
	if (!recipients) {
		dc_log_warning(context, 0, "Missing recipients for job %d", job->job_id);
		goto cleanup;
	}
	recipients_list = dc_str_to_clist(recipients, "\x1e");

	/* if there is a msg-id and it does not exist in the db, cancel sending.
	this happends if dc_delete_msgs() was called
	before the generated mime was sent out */
	if (job->foreign_id) {
		if(!dc_msg_exists(context, job->foreign_id)) {
			dc_log_warning(context, 0, "Message %i for job %i does not exist",
				job->foreign_id, job->job_id);
			goto cleanup;
		}
	}

	/* send message */
	{
		if (!dc_smtp_send_msg(context->smtp, recipients_list, buf, buf_bytes)) {
			if (job->foreign_id && (
			    MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION==context->smtp->error_etpan
			 || MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE==context->smtp->error_etpan)) {
				dc_set_msg_failed(context, job->foreign_id, context->smtp->error);
			}
			else {
				dc_smtp_disconnect(context->smtp);
				dc_job_try_again_later(job, DC_AT_ONCE, context->smtp->error);
			}
			goto cleanup;
		}
	}

	/* delete the stores message file */
	dc_delete_file(context, filename);
	/* an error still means the message is sent, so the rest continues */

	/* done */
	if (job->foreign_id) {
		dc_update_msg_state(context, job->foreign_id, DC_STATE_OUT_DELIVERED);

		/* find the chat ID */
		stmt = dc_sqlite3_prepare(context->sql, "SELECT chat_id FROM msgs WHERE id=?");
		sqlite3_bind_int(stmt, 1, job->foreign_id);
		/* a deleted message results in an event with chat_id==0, rather than no event at all */
		int chat_id = sqlite3_step(stmt)==SQLITE_ROW ? sqlite3_column_int(stmt, 0) : 0;

		context->cb(context, DC_EVENT_MSG_DELIVERED, chat_id, job->foreign_id);
	}

cleanup:
	sqlite3_finalize(stmt);
	if (recipients_list) {
		clist_free_content(recipients_list);
		clist_free(recipients_list);
	}
	free(recipients);
	free(buf);
	free(filename);
}


static void dc_send_mdn(dc_context_t* context, uint32_t msg_id)
{
	dc_mimefactory_t mimefactory;
	dc_mimefactory_init(&mimefactory, context);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

    if (!dc_mimefactory_load_mdn(&mimefactory, msg_id)
     || !dc_mimefactory_render(&mimefactory)) {
		goto cleanup;
    }

	//char* t1=dc_null_terminate(mimefactory.out->str,mimefactory.out->len);printf("~~~~~MDN~~~~~\n%s\n~~~~~/MDN~~~~~",t1);free(t1); // DEBUG OUTPUT

	dc_add_smtp_job(context, DC_JOB_SEND_MDN, &mimefactory);

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


int dc_job_action_exists(dc_context_t* context, int action)
{
	int           job_exists = 0;
	sqlite3_stmt* stmt = NULL;

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM jobs WHERE action=?;");
	sqlite3_bind_int  (stmt, 1, action);

	job_exists = (sqlite3_step(stmt)==SQLITE_ROW);

	sqlite3_finalize(stmt);
	return job_exists;
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


void dc_job_kill_action(dc_context_t* context, int action)
{
	if (context==NULL) {
		return;
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"DELETE FROM jobs WHERE action=?;");
	sqlite3_bind_int(stmt, 1, action);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


static void dc_job_perform(dc_context_t* context, int thread, int probe_network)
{
	sqlite3_stmt* select_stmt = NULL;
	dc_job_t      job;
	#define       THREAD_STR (thread==DC_IMAP_THREAD? "INBOX" : "SMTP")
	#define       IS_EXCLUSIVE_JOB (DC_JOB_CONFIGURE_IMAP==job.action || DC_JOB_IMEX_IMAP==job.action || DC_JOB_EMPTY_SERVER==job.action)

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
			dc_job_kill_action(context, job.action);
			sqlite3_finalize(select_stmt);
			select_stmt = NULL;
			dc_jobthread_suspend(&context->sentbox_thread, 1);
			dc_jobthread_suspend(&context->mvbox_thread, 1);
			dc_suspend_smtp_thread(context, 1);
		}

		for (int tries = 0; tries <= 1; tries++)
		{
			job.try_again = DC_DONT_TRY_AGAIN; // this can be modified by a job using dc_job_try_again_later()

			switch (job.action) {
				case DC_JOB_SEND_MSG_TO_SMTP:     dc_job_do_DC_JOB_SEND                 (context, &job); break;
				case DC_JOB_DELETE_MSG_ON_IMAP:   dc_job_do_DC_JOB_DELETE_MSG_ON_IMAP   (context, &job); break;
				case DC_JOB_MARKSEEN_MSG_ON_IMAP: dc_job_do_DC_JOB_MARKSEEN_MSG_ON_IMAP (context, &job); break;
				case DC_JOB_MARKSEEN_MDN_ON_IMAP: dc_job_do_DC_JOB_MARKSEEN_MDN_ON_IMAP (context, &job); break;
				case DC_JOB_MOVE_MSG:             dc_job_do_DC_JOB_MOVE_MSG             (context, &job); break;
				case DC_JOB_SEND_MDN:             dc_job_do_DC_JOB_SEND                 (context, &job); break;
				case DC_JOB_CONFIGURE_IMAP:       dc_job_do_DC_JOB_CONFIGURE_IMAP       (context, &job); break;
				case DC_JOB_IMEX_IMAP:            dc_job_do_DC_JOB_IMEX_IMAP            (context, &job); break;
				case DC_JOB_MAYBE_SEND_LOCATIONS: dc_job_do_DC_JOB_MAYBE_SEND_LOCATIONS (context, &job); break;
				case DC_JOB_MAYBE_SEND_LOC_ENDED: dc_job_do_DC_JOB_MAYBE_SEND_LOC_ENDED (context, &job); break;
				case DC_JOB_EMPTY_SERVER:         dc_job_do_DC_JOB_EMPTY_SERVER         (context, &job); break;
				case DC_JOB_HOUSEKEEPING:         dc_housekeeping                       (context);       break;
			}

			if (job.try_again!=DC_AT_ONCE) {
				break;
			}
		}

		if (IS_EXCLUSIVE_JOB) {
			dc_jobthread_suspend(&context->sentbox_thread, 0);
			dc_jobthread_suspend(&context->mvbox_thread, 0);
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
 * This function and dc_perform_imap_fetch() and dc_perform_imap_idle()
 * must be called from the same thread, typically in a loop.
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
 *     // network becomes available again -
 *     // the interrupt causes dc_perform_imap_idle() in the thread above
 *     // to return so that jobs are executed and messages are fetched.
 *     dc_maybe_network(context);
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
 * See dc_perform_imap_jobs() for an example.
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

	if (dc_sqlite3_get_config_int(context->sql, "inbox_watch", DC_INBOX_WATCH_DEFAULT)==0) {
		dc_log_info(context, 0, "INBOX-watch disabled.");
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
 * See dc_perform_imap_jobs() for an example.
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

	// TODO: optimisation: inbox_watch should also be regarded here to save some bytes.
	// however, the thread and the imap connection are needed even if inbox_watch is disabled
	// as the jobs are happending here.
	// anyway, the best way would be to switch this thread also to dc_jobthread_t
	// which has all the needed capabilities.

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
 * Internally, this function is called whenever a imap-jobs should be processed
 * (delete message, markseen etc.).
 *
 * When you need to call this function just because to get jobs done after network changes,
 * use dc_maybe_network() instead.
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


/**
 * Fetch new messages from the MVBOX, if any.
 * The MVBOX is a folder on the account where chat messages are moved to.
 * The moving is done to not disturb shared accounts that are used by both,
 * Delta Chat and a classical MUA.
 *
 * This function and dc_perform_mvbox_idle()
 * must be called from the same thread, typically in a loop.
 *
 * Example:
 *
 *     void* mvbox_thread_func(void* context)
 *     {
 *         while (true) {
 *             dc_perform_mvbox_fetch(context);
 *             dc_perform_mvbox_idle(context);
 *         }
 *     }
 *
 *     // start mvbox-thread that runs forever
 *     pthread_t mvbox_thread;
 *     pthread_create(&mvbox_thread, NULL, mvbox_thread_func, context);
 *
 *     ... program runs ...
 *
 *     // network becomes available again -
 *     // the interrupt causes dc_perform_mvbox_idle() in the thread above
 *     // to return so that and messages are fetched.
 *     dc_maybe_network(context);
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_mvbox_fetch(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	int use_network = dc_sqlite3_get_config_int(context->sql, "mvbox_watch", DC_MVBOX_WATCH_DEFAULT);
	dc_jobthread_fetch(&context->mvbox_thread, use_network);
}


/**
 * Wait for messages or jobs in the MVBOX-thread.
 * This function and dc_perform_mvbox_fetch().
 * must be called from the same thread, typically in a loop.
 *
 * You should call this function directly after calling dc_perform_mvbox_fetch().
 *
 * See dc_perform_mvbox_fetch() for an example.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_mvbox_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	int use_network = dc_sqlite3_get_config_int(context->sql, "mvbox_watch", DC_MVBOX_WATCH_DEFAULT);
	dc_jobthread_idle(&context->mvbox_thread, use_network);
}


/**
 * Interrupt waiting for MVBOX-fetch.
 * dc_interrupt_mvbox_idle() does _not_ interrupt dc_perform_mvbox_fetch().
 * If the MVBOX-thread is inside this function when dc_interrupt_mvbox_idle() is called, however,
 * the next call of the MVBOX-thread to dc_perform_mvbox_idle() is interrupted immediately.
 *
 * Internally, this function is called whenever a imap-jobs should be processed.
 *
 * When you need to call this function just because to get jobs done after network changes,
 * use dc_maybe_network() instead.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_interrupt_mvbox_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		dc_log_warning(context, 0, "Interrupt MVBOX-IDLE: Bad parameters.");
		return;
	}

	dc_jobthread_interrupt_idle(&context->mvbox_thread);
}


/*******************************************************************************
 * User-functions to handle IMAP-jobs in the Sendbox-IMAP-thread
 ******************************************************************************/


/**
 * Fetch new messages from the Sent folder, if any.
 * This function and dc_perform_sentbox_idle()
 * must be called from the same thread, typically in a loop.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_sentbox_fetch(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	int use_network = dc_sqlite3_get_config_int(context->sql, "sentbox_watch", DC_SENTBOX_WATCH_DEFAULT);
	dc_jobthread_fetch(&context->sentbox_thread, use_network);
}


/**
 * Wait for messages or jobs in the SENTBOX-thread.
 * This function and dc_perform_sentbox_fetch()
 * must be called from the same thread, typically in a loop.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_perform_sentbox_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	int use_network = dc_sqlite3_get_config_int(context->sql, "sentbox_watch", DC_SENTBOX_WATCH_DEFAULT);
	dc_jobthread_idle(&context->sentbox_thread, use_network);
}


/**
 * Interrupt waiting for messages or jobs in the SENTBOX-thread.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return None.
 */
void dc_interrupt_sentbox_idle(dc_context_t* context)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		dc_log_warning(context, 0, "Interrupt SENT-IDLE: Bad parameters.");
		return;
	}

	dc_jobthread_interrupt_idle(&context->sentbox_thread);
}


/*******************************************************************************
 * User-functions handle SMTP-jobs from the SMTP-thread
 ******************************************************************************/


/**
 * Execute pending smtp-jobs.
 * This function and dc_perform_smtp_idle() must be called from the same thread,
 * typically in a loop.
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
 *     // network becomes available again -
 *     // the interrupt causes dc_perform_smtp_idle() in the thread above
 *     // to return so that jobs are executed
 *     dc_maybe_network(context);
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
 * Internally, this function is called whenever a message is to be sent.
 *
 * When you need to call this function just because to get jobs done after network changes,
 * use dc_maybe_network() instead.
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
	dc_interrupt_sentbox_idle(context);
}


void dc_empty_server(dc_context_t* context, int flags)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || (flags&(DC_EMPTY_INBOX|DC_EMPTY_MVBOX))==0) {
		return;
	}

	dc_job_kill_action(context, DC_JOB_EMPTY_SERVER);
	dc_job_add(context, DC_JOB_EMPTY_SERVER, flags, NULL, 0);
}