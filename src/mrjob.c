/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
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


#include <stdarg.h>
#include <unistd.h>
#include "mrmailbox_internal.h"
#include "mrloginparam.h"
#include "mrjob.h"
#include "mrimap.h"
#include "mrsmtp.h"
#include "mrmimefactory.h"


/*******************************************************************************
 * IMAP-jobs
 ******************************************************************************/


static int connect_to_imap(mrmailbox_t* mailbox, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	#define         NOT_CONNECTED     0
	#define         ALREADY_CONNECTED 1
	#define         JUST_CONNECTED    2
	int             ret_connected = NOT_CONNECTED;
	int             is_locked = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot connect to IMAP: Bad parameters.");
		goto cleanup;
	}

	if( mrimap_is_connected(mailbox->m_imap) ) {
		ret_connected = ALREADY_CONNECTED;
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	is_locked = 1;

		if( mrsqlite3_get_config_int__(mailbox->m_sql, "configured", 0) == 0 ) {
			mrmailbox_log_warning(mailbox, 0, "Not configured, cannot connect."); // this is no error, connect() is called eg. when the screen is switched on, it's okay if the caller does not check all circumstances here
			goto cleanup;
		}

		mrloginparam_read__(param, mailbox->m_sql, "configured_" /*the trailing underscore is correct*/);

	mrsqlite3_unlock(mailbox->m_sql);
	is_locked = 0;

	if( !mrimap_connect(mailbox->m_imap, param) ) {
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
		goto cleanup;
	}

	ret_connected = JUST_CONNECTED;

cleanup:
	if( is_locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrloginparam_unref(param);
	return ret_connected;
}


static void mrjob_do_MRJ_SEND_MSG_TO_IMAP(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrmimefactory_t  mimefactory;
	char*            server_folder = NULL;
	uint32_t         server_uid = 0;

	mrmimefactory_init(&mimefactory, mailbox);

	/* connect to IMAP-server */
	if( !mrimap_is_connected(mailbox->m_imap) ) {
		connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* create message */
	if( mrmimefactory_load_msg(&mimefactory, job->m_foreign_id)==0
	 || mimefactory.m_from_addr == NULL ) {
		goto cleanup; /* should not happen as we've sent the message to the SMTP server before */
	}

	if( !mrmimefactory_render(&mimefactory) ) {
		goto cleanup; /* should not happen as we've sent the message to the SMTP server before */
	}

	if( !mrimap_append_msg(mailbox->m_imap, mimefactory.m_msg->m_timestamp, mimefactory.m_out->str, mimefactory.m_out->len, &server_folder, &server_uid) ) {
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
		goto cleanup;
	}
	else {
		mrsqlite3_lock(mailbox->m_sql);
			mrmailbox_update_server_uid__(mailbox, mimefactory.m_msg->m_rfc724_mid, server_folder, server_uid);
		mrsqlite3_unlock(mailbox->m_sql);
	}

cleanup:
	mrmimefactory_empty(&mimefactory);
	free(server_folder);
}


static void mrjob_do_MRJ_DELETE_MSG_ON_IMAP(mrmailbox_t* mailbox, mrjob_t* job)
{
	int      locked = 0, delete_from_server = 1;
	mrmsg_t* msg = mrmsg_new();

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db__(msg, mailbox, job->m_foreign_id)
		 || msg->m_rfc724_mid == NULL || msg->m_rfc724_mid[0] == 0 /* eg. device messages have no Message-ID */ ) {
			goto cleanup;
		}

		if( mrmailbox_rfc724_mid_cnt__(mailbox, msg->m_rfc724_mid) != 1 ) {
			mrmailbox_log_info(mailbox, 0, "The message is deleted from the server when all parts are deleted.");
			delete_from_server = 0;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* if this is the last existing part of the message, we delete the message from the server */
	if( delete_from_server )
	{
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			connect_to_imap(mailbox, NULL);
			if( !mrimap_is_connected(mailbox->m_imap) ) {
				mrjob_try_again_later(job, MR_STANDARD_DELAY);
				goto cleanup;
			}
		}

		if( !mrimap_delete_msg(mailbox->m_imap, msg->m_rfc724_mid, msg->m_server_folder, msg->m_server_uid) )
		{
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* we delete the database entry ...
	- if the message is successfully removed from the server
	- or if there are other parts of the message in the database (in this case we have not deleted if from the server)
	(As long as the message is not removed from the IMAP-server, we need at least one database entry to avoid a re-download) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_msgs_WHERE_id,
			"DELETE FROM msgs WHERE id=?;");
		sqlite3_bind_int(stmt, 1, msg->m_id);
		sqlite3_step(stmt);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_msgs_mdns_WHERE_m,
			"DELETE FROM msgs_mdns WHERE msg_id=?;");
		sqlite3_bind_int(stmt, 1, msg->m_id);
		sqlite3_step(stmt);

		char* pathNfilename = mrparam_get(msg->m_param, MRP_FILE, NULL);
		if( pathNfilename ) {
			if( strncmp(mailbox->m_blobdir, pathNfilename, strlen(mailbox->m_blobdir))==0 )
			{
				char* strLikeFilename = mr_mprintf("%%f=%s%%", pathNfilename);
				sqlite3_stmt* stmt2 = mrsqlite3_prepare_v2_(mailbox->m_sql, "SELECT id FROM msgs WHERE type!=? AND param LIKE ?;"); /* if this gets too slow, an index over "type" should help. */
				sqlite3_bind_int (stmt2, 1, MR_MSG_TEXT);
				sqlite3_bind_text(stmt2, 2, strLikeFilename, -1, SQLITE_STATIC);
				int file_used_by_other_msgs = (sqlite3_step(stmt2)==SQLITE_ROW)? 1 : 0;
				free(strLikeFilename);
				sqlite3_finalize(stmt2);

				if( !file_used_by_other_msgs )
				{
					mr_delete_file(pathNfilename, mailbox);

					char* increation_file = mr_mprintf("%s.increation", pathNfilename);
					mr_delete_file(increation_file, mailbox);
					free(increation_file);

					char* filenameOnly = mr_get_filename(pathNfilename);
					if( msg->m_type==MR_MSG_VOICE ) {
						char* waveform_file = mr_mprintf("%s/%s.waveform", mailbox->m_blobdir, filenameOnly);
						mr_delete_file(waveform_file, mailbox);
						free(waveform_file);
					}
					else if( msg->m_type==MR_MSG_VIDEO ) {
						char* preview_file = mr_mprintf("%s/%s-preview.jpg", mailbox->m_blobdir, filenameOnly);
						mr_delete_file(preview_file, mailbox);
						free(preview_file);
					}
					free(filenameOnly);
				}
			}
			free(pathNfilename);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrmsg_unref(msg);
}


static void mrjob_do_MRJ_MARKSEEN_MSG_ON_IMAP(mrmailbox_t* mailbox, mrjob_t* job)
{
	int      locked = 0;
	mrmsg_t* msg = mrmsg_new();
	char*    new_server_folder = NULL;
	uint32_t new_server_uid = 0;
	int      in_ms_flags = 0, out_ms_flags = 0;

	if( !mrimap_is_connected(mailbox->m_imap) ) {
		connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db__(msg, mailbox, job->m_foreign_id) ) {
			goto cleanup;
		}

		/* add an additional job for sending the MDN (here in a thread for fast ui resonses) (an extra job as the MDN has a lower priority) */
		if( mrparam_get_int(msg->m_param, MRP_WANTS_MDN, 0) /* MRP_WANTS_MDN is set only for one part of a multipart-message */
		 && mrsqlite3_get_config_int__(mailbox->m_sql, "mdns_enabled", MR_MDNS_DEFAULT_ENABLED) ) {
			in_ms_flags |= MR_MS_SET_MDNSent_FLAG;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( msg->m_is_msgrmsg ) {
		in_ms_flags |= MR_MS_ALSO_MOVE;
	}

	if( mrimap_markseen_msg(mailbox->m_imap, msg->m_server_folder, msg->m_server_uid,
		   in_ms_flags, &new_server_folder, &new_server_uid, &out_ms_flags) != 0 )
	{
		if( (new_server_folder && new_server_uid) || out_ms_flags&MR_MS_MDNSent_JUST_SET )
		{
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				if( new_server_folder && new_server_uid )
				{
					mrmailbox_update_server_uid__(mailbox, msg->m_rfc724_mid, new_server_folder, new_server_uid);
				}

				if( out_ms_flags&MR_MS_MDNSent_JUST_SET )
				{
					mrjob_add(mailbox, MRJ_SEND_MDN, msg->m_id, NULL, 0);
				}

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
	}
	else
	{
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
	}

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrmsg_unref(msg);
	free(new_server_folder);
}


static void mrjob_do_MRJ_MARKSEEN_MDN_ON_IMAP(mrmailbox_t* mailbox, mrjob_t* job)
{
	char*    server_folder = mrparam_get    (job->m_param, MRP_SERVER_FOLDER, NULL);
	uint32_t server_uid    = mrparam_get_int(job->m_param, MRP_SERVER_UID, 0);
	char*    new_server_folder = NULL;
	uint32_t new_server_uid    = 0;
	int      out_ms_flags = 0;

	if( !mrimap_is_connected(mailbox->m_imap) ) {
		connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	if( mrimap_markseen_msg(mailbox->m_imap, server_folder, server_uid, MR_MS_ALSO_MOVE, &new_server_folder, &new_server_uid, &out_ms_flags) == 0 ) {
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
	}

cleanup:
	free(server_folder);
	free(new_server_folder);
}


/*******************************************************************************
 * SMTP-jobs
 ******************************************************************************/


static void mark_as_error(mrmailbox_t* mailbox, mrmsg_t* msg)
{
	if( mailbox==NULL || msg==NULL ) {
		return;
	}

	mrsqlite3_lock(mailbox->m_sql);
		mrmailbox_update_msg_state__(mailbox, msg->m_id, MR_STATE_OUT_ERROR);
	mrsqlite3_unlock(mailbox->m_sql);
	mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, msg->m_chat_id, 0);
}


static void mrjob_do_MRJ_SEND_MSG_TO_SMTP(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrmimefactory_t mimefactory;

	mrmimefactory_init(&mimefactory, mailbox);

	/* connect to SMTP server, if not yet done */
	if( !mrsmtp_is_connected(mailbox->m_smtp) ) {
		mrloginparam_t* loginparam = mrloginparam_new();
			mrsqlite3_lock(mailbox->m_sql);
				mrloginparam_read__(loginparam, mailbox->m_sql, "configured_");
			mrsqlite3_unlock(mailbox->m_sql);
			int connected = mrsmtp_connect(mailbox->m_smtp, loginparam);
		mrloginparam_unref(loginparam);
		if( !connected ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* load message data */
	if( !mrmimefactory_load_msg(&mimefactory, job->m_foreign_id)
	 || mimefactory.m_from_addr == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot load data to send, maybe the message is deleted in between.");
		goto cleanup; /* no redo, no IMAP - there won't be more recipients next time (as the data does not exist, there is no need in calling mark_as_error()) */
	}

	/* check if the message is ready (normally, only video files may be delayed this way) */
	if( mimefactory.m_increation ) {
		mrmailbox_log_info(mailbox, 0, "File is in creation, retrying later.");
		mrjob_try_again_later(job, MR_INCREATION_POLL);
		goto cleanup;
	}

	/* send message - it's okay if there are no recipients, this is a group with only OURSELF; we only upload to IMAP in this case */
	if( clist_count(mimefactory.m_recipients_addr) > 0 ) {
		if( !mrmimefactory_render(&mimefactory) ) {
			mark_as_error(mailbox, mimefactory.m_msg);
			mrmailbox_log_error(mailbox, 0, "Empty message."); /* should not happen */
			goto cleanup; /* no redo, no IMAP - there won't be more recipients next time. */
		}

		/* have we guaranteed encryption but cannot fulfill it for any reason? Do not send the message then.*/
		if( mrparam_get_int(mimefactory.m_msg->m_param, MRP_GUARANTEE_E2EE, 0) && !mimefactory.m_out_encrypted ) {
			mark_as_error(mailbox, mimefactory.m_msg);
			mrmailbox_log_error(mailbox, 0, "End-to-end-encryption unavailable unexpectedly.");
			goto cleanup; /* unrecoverable */
		}

		if( !mrsmtp_send_msg(mailbox->m_smtp, mimefactory.m_recipients_addr, mimefactory.m_out->str, mimefactory.m_out->len) ) {
			mrsmtp_disconnect(mailbox->m_smtp);
			mrjob_try_again_later(job, MR_AT_ONCE); /* MR_AT_ONCE is only the _initial_ delay, if the second try failes, the delay gets larger */
			goto cleanup;
		}
	}

	/* done */
	mrsqlite3_lock(mailbox->m_sql);
	mrsqlite3_begin_transaction__(mailbox->m_sql);

		/* debug print? */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "save_eml", 0) ) {
			char* emlname = mr_mprintf("%s/to-smtp-%i.eml", mailbox->m_blobdir, (int)mimefactory.m_msg->m_id);
			FILE* emlfileob = fopen(emlname, "w");
			if( emlfileob ) {
				if( mimefactory.m_out ) {
					fwrite(mimefactory.m_out->str, 1, mimefactory.m_out->len, emlfileob);
				}
				fclose(emlfileob);
			}
			free(emlname);
		}

		mrmailbox_update_msg_state__(mailbox, mimefactory.m_msg->m_id, MR_STATE_OUT_DELIVERED);
		if( mimefactory.m_out_encrypted && mrparam_get_int(mimefactory.m_msg->m_param, MRP_GUARANTEE_E2EE, 0)==0 ) {
			mrparam_set_int(mimefactory.m_msg->m_param, MRP_GUARANTEE_E2EE, 1); /* can upgrade to E2EE - fine! */
			mrmsg_save_param_to_disk__(mimefactory.m_msg);
		}

		if( (mailbox->m_imap->m_server_flags&MR_NO_EXTRA_IMAP_UPLOAD)==0
		 && mrparam_get(mimefactory.m_chat->m_param, MRP_SELFTALK, 0)==0
		 && mrparam_get_int(mimefactory.m_msg->m_param, MRP_CMD, 0)!=MR_CMD_SECUREJOIN_MESSAGE ) {
			mrjob_add(mailbox, MRJ_SEND_MSG_TO_IMAP, mimefactory.m_msg->m_id, NULL, 0); /* send message to IMAP in another job */
		}

		// TODO: add to keyhistory
		mrmailbox_add_to_keyhistory__(mailbox, NULL, 0, NULL, NULL);

	mrsqlite3_commit__(mailbox->m_sql);
	mrsqlite3_unlock(mailbox->m_sql);

	mailbox->m_cb(mailbox, MR_EVENT_MSG_DELIVERED, mimefactory.m_msg->m_chat_id, mimefactory.m_msg->m_id);

cleanup:
	mrmimefactory_empty(&mimefactory);
}


static void mrjob_do_MRJ_SEND_MDN(mrmailbox_t* mailbox, mrjob_t* job)
{
	mrmimefactory_t mimefactory;
	mrmimefactory_init(&mimefactory, mailbox);

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || job == NULL ) {
		return;
	}

	/* connect to SMTP server, if not yet done */
	if( !mrsmtp_is_connected(mailbox->m_smtp) )
	{
		mrloginparam_t* loginparam = mrloginparam_new();
			mrsqlite3_lock(mailbox->m_sql);
				mrloginparam_read__(loginparam, mailbox->m_sql, "configured_");
			mrsqlite3_unlock(mailbox->m_sql);
			int connected = mrsmtp_connect(mailbox->m_smtp, loginparam);
		mrloginparam_unref(loginparam);
		if( !connected ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

    if( !mrmimefactory_load_mdn(&mimefactory, job->m_foreign_id)
     || !mrmimefactory_render(&mimefactory) ) {
		goto cleanup;
    }

	//char* t1=mr_null_terminate(mimefactory.m_out->str,mimefactory.m_out->len);printf("~~~~~MDN~~~~~\n%s\n~~~~~/MDN~~~~~",t1);free(t1); // DEBUG OUTPUT

	if( !mrsmtp_send_msg(mailbox->m_smtp, mimefactory.m_recipients_addr, mimefactory.m_out->str, mimefactory.m_out->len) ) {
		mrsmtp_disconnect(mailbox->m_smtp);
		mrjob_try_again_later(job, MR_AT_ONCE); /* MR_AT_ONCE is only the _initial_ delay, if the second try failes, the delay gets larger */
		goto cleanup;
	}

cleanup:
	mrmimefactory_empty(&mimefactory);
}


void mrmailbox_suspend_smtp_thread(mrmailbox_t* mailbox, int suspend)
{
	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);
		mailbox->m_smtpidle_suspend = suspend;
	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);

	// the smtp-thread may be in perform_jobs() when this function is called,
	// wait until we arrive in idle(). for simplicity, we do this by polling a variable
	// (in fact, this is only needed when calling configure() is called)
	if( suspend )
	{
		while( 1 ) {
			pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);
				if( mailbox->m_smtpidle_in_idleing ) {
					pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);
					return;
				}
			pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);
			usleep(300*1000);
		}
	}
}


/*******************************************************************************
 * Tools
 ******************************************************************************/


void mrjob_add(mrmailbox_t* mailbox, int action, int foreign_id, const char* param, int delay_seconds)
{
	time_t        timestamp = time(NULL);
	sqlite3_stmt* stmt;
	int           thread;

	if( action >= MR_IMAP_THREAD && action < MR_IMAP_THREAD+1000 ) {
		thread = MR_IMAP_THREAD;
	}
	else if( action >= MR_SMTP_THREAD && action < MR_SMTP_THREAD+1000 ) {
		thread = MR_SMTP_THREAD;
	}
	else {
		return;
	}

	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
		"INSERT INTO jobs (added_timestamp, thread, action, foreign_id, param, desired_timestamp) VALUES (?,?,?,?,?,?);");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, thread);
	sqlite3_bind_int  (stmt, 3, action);
	sqlite3_bind_int  (stmt, 4, foreign_id);
	sqlite3_bind_text (stmt, 5, param? param : "",  -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 6, delay_seconds>0? (timestamp+delay_seconds) : 0);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if( thread == MR_IMAP_THREAD ) {
		mrmailbox_interrupt_idle(mailbox);
	}
	else {
		mrmailbox_interrupt_smtp_idle(mailbox);
	}
}


void mrjob_try_again_later(mrjob_t* job, int try_again)
{
	if( job == NULL ) {
		return;
	}

	job->m_try_again = try_again;
}


void mrjob_kill_actions(mrmailbox_t* mailbox, int action1, int action2)
{
	if( mailbox == NULL ) {
		return;
	}

	sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
		"DELETE FROM jobs WHERE action=? OR action=?;");
	sqlite3_bind_int(stmt, 1, action1);
	sqlite3_bind_int(stmt, 2, action2);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


static void mrjob_perform(mrmailbox_t* mailbox, int thread)
{
	sqlite3_stmt* select_stmt = NULL;
	mrjob_t       job;

	memset(&job, 0, sizeof(mrjob_t));
	job.m_param = mrparam_new();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	select_stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
		"SELECT id, action, foreign_id, param FROM jobs WHERE thread=? AND desired_timestamp<=? ORDER BY action DESC, added_timestamp;");
	sqlite3_bind_int64(select_stmt, 1, thread);
	sqlite3_bind_int64(select_stmt, 2, time(NULL));
	while( sqlite3_step(select_stmt) == SQLITE_ROW )
	{
		job.m_job_id                         = sqlite3_column_int (select_stmt, 0);
		job.m_action                         = sqlite3_column_int (select_stmt, 1);
		job.m_foreign_id                     = sqlite3_column_int (select_stmt, 2);
		mrparam_set_packed(job.m_param, (char*)sqlite3_column_text(select_stmt, 3));

		mrmailbox_log_info(mailbox, 0, "Executing job #%i, action %i...", (int)job.m_job_id, (int)job.m_action);

		for( int tries = 0; tries <= 1; tries++ )
		{
			job.m_try_again = MR_DONT_TRY_AGAIN; // this can be modified by a job using mrjob_try_again_later()

			switch( job.m_action ) {
				case MRJ_SEND_MSG_TO_SMTP:     mrjob_do_MRJ_SEND_MSG_TO_SMTP     (mailbox, &job); break;
				case MRJ_SEND_MSG_TO_IMAP:     mrjob_do_MRJ_SEND_MSG_TO_IMAP     (mailbox, &job); break;
				case MRJ_DELETE_MSG_ON_IMAP:   mrjob_do_MRJ_DELETE_MSG_ON_IMAP   (mailbox, &job); break;
				case MRJ_MARKSEEN_MSG_ON_IMAP: mrjob_do_MRJ_MARKSEEN_MSG_ON_IMAP (mailbox, &job); break;
				case MRJ_MARKSEEN_MDN_ON_IMAP: mrjob_do_MRJ_MARKSEEN_MDN_ON_IMAP (mailbox, &job); break;
				case MRJ_SEND_MDN:             mrjob_do_MRJ_SEND_MDN             (mailbox, &job); break;
				case MRJ_CONFIGURE_IMAP:       mrjob_do_MRJ_CONFIGURE_IMAP       (mailbox, &job); break;
			}

			if( job.m_try_again != MR_AT_ONCE ) {
				break;
			}
		}


		if( job.m_try_again == MR_INCREATION_POLL )
		{
			// just try over next loop unconditionally, the ui typically interrupts idle when the file (video) is ready
			;
		}
		else if( job.m_try_again == MR_AT_ONCE || job.m_try_again == MR_STANDARD_DELAY )
		{
			int tries = mrparam_get_int(job.m_param, MRP_TIMES, 0) + 1;
			mrparam_set_int(job.m_param, MRP_TIMES, tries);

			sqlite3_stmt* update_stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
				"UPDATE jobs SET desired_timestamp=0, param=? WHERE id=?;");
			sqlite3_bind_text (update_stmt, 1, job.m_param->m_packed, -1, SQLITE_STATIC);
			sqlite3_bind_int  (update_stmt, 2, job.m_job_id);
			sqlite3_step(update_stmt);
			sqlite3_finalize(update_stmt);
			mrmailbox_log_info(mailbox, 0, "Job #%i not succeeded, trying again asap.", (int)job.m_job_id);
		}
		else
		{
			sqlite3_stmt* delete_stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
				"DELETE FROM jobs WHERE id=?;");
			sqlite3_bind_int(delete_stmt, 1, job.m_job_id);
			sqlite3_step(delete_stmt);
			sqlite3_finalize(delete_stmt);
			mrmailbox_log_info(mailbox, 0, "Job #%i done and deleted from database", (int)job.m_job_id);
		}
	}

cleanup:
	mrparam_unref(job.m_param);
	if( select_stmt ) { sqlite3_finalize(select_stmt); }
}


/*******************************************************************************
 * User-functions handle IMAP-jobs from the IMAP-thread
 ******************************************************************************/


/**
 * Execute pending jobs.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None
 */
void mrmailbox_perform_jobs(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, ">>>>> IMAP-jobs started.");

	pthread_mutex_lock(&mailbox->m_imapidle_condmutex);
		mailbox->m_perform_imap_jobs_needed = 0;
	pthread_mutex_unlock(&mailbox->m_imapidle_condmutex);

	mrjob_perform(mailbox, MR_IMAP_THREAD);

	mrmailbox_log_info(mailbox, 0, "<<<<< IMAP-jobs ended.");
}


/**
 * Poll for new messages.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None.
 */
void mrmailbox_fetch(mrmailbox_t* mailbox)
{
	clock_t start = clock();

	if( !connect_to_imap(mailbox, NULL) ) {
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> IMAP-fetch started.");

	mrimap_fetch(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< IMAP-fetch done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);
}


/**
 * Wait for messages.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None.
 */
void mrmailbox_idle(mrmailbox_t* mailbox)
{
	if( !connect_to_imap(mailbox, NULL) ) {
		mrmailbox_log_info(mailbox, 0, "Cannot connect, idle anyway and waiting for configure.");
		// no return!
	}

	pthread_mutex_lock(&mailbox->m_imapidle_condmutex);
		if( mailbox->m_perform_imap_jobs_needed ) {
			mrmailbox_log_info(mailbox, 0, "IMAP-IDLE skipped.");
			pthread_mutex_unlock(&mailbox->m_imapidle_condmutex);
			return;
		}
	pthread_mutex_unlock(&mailbox->m_imapidle_condmutex);

	mrmailbox_log_info(mailbox, 0, ">>>>> IMAP-IDLE started.");

	mrimap_watch_n_wait(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< IMAP-IDLE ended.");
}


/**
 * Interrupt the mrmailbox_perform_imap_idle().
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None
 */
void mrmailbox_interrupt_idle(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_error(mailbox, 0, "Cannot interrupt idle: Bad parameters.");
		return;
	}

	mrmailbox_log_info(mailbox, 0, "> > > interrupt IMAP-IDLE.");

	pthread_mutex_lock(&mailbox->m_imapidle_condmutex);
		// when this function is called, it might be that the idle-thread is in
		// perform_idle_jobs() instead of idle(). if so, added jobs will be performed after the _next_ idle-jobs loop.
		// setting the flag perform_imap_jobs_needed makes sure, idle() returns immediately in this case.
		mailbox->m_perform_imap_jobs_needed = 1;
	pthread_mutex_unlock(&mailbox->m_imapidle_condmutex);

	mrimap_interrupt_watch(mailbox->m_imap);
}


/*******************************************************************************
 * User-functions handle SMTP-jobs from the SMTP-thread
 ******************************************************************************/


void mrmailbox_perform_smtp_jobs(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, ">>>>> SMTP-jobs started.");

	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);
		mailbox->m_perform_smtp_jobs_needed = 0;
	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);

	mrjob_perform(mailbox, MR_SMTP_THREAD);

	mrmailbox_log_info(mailbox, 0, "<<<<< SMTP-jobs ended.");
}


void mrmailbox_perform_smtp_idle(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot perform SMTP-idle: Bad parameters.");
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> SMTP-idle started.");

	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);

		if( mailbox->m_perform_smtp_jobs_needed )
		{
			mrmailbox_log_info(mailbox, 0, "SMTP-idle skipped.");
		}
		else
		{
			mailbox->m_smtpidle_in_idleing = 1; // checked in suspend(), for idle-interruption the pthread-condition below is used

				int r = 0;
				struct timespec timeToWait;
				timeToWait.tv_sec  = time(NULL)+60;
				timeToWait.tv_nsec = 0;
				while( (mailbox->m_smtpidle_condflag == 0 && r == 0) || mailbox->m_smtpidle_suspend ) {
					r = pthread_cond_timedwait(&mailbox->m_smtpidle_cond, &mailbox->m_smtpidle_condmutex, &timeToWait); // unlock mutex -> wait -> lock mutex
					mrmailbox_log_info(mailbox, 0, "SMTP: m_smtpidle_condflag=%i r=%i m_smtpidle_suspend=%i", mailbox->m_smtpidle_condflag, r, mailbox->m_smtpidle_suspend);
				}
				mailbox->m_smtpidle_condflag = 0;

			mailbox->m_smtpidle_in_idleing = 0;
		}

	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);

	mrmailbox_log_info(mailbox, 0, "<<<<< SMTP-idle ended.");
}


void mrmailbox_interrupt_smtp_idle(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot interrupt SMTP-idle: Bad parameters.");
		return;
	}

	mrmailbox_log_info(mailbox, 0, "> > > interrupt SMTP-idle.");

	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);

		// when this function is called, it might be that the smtp-thread is in
		// perform_smtp_jobs(). if so, added jobs will be performed after the _next_ idle-jobs loop.
		// setting the flag perform_smtp_jobs_needed makes sure, idle() returns immediately in this case.
		mailbox->m_perform_smtp_jobs_needed = 1;

		mailbox->m_smtpidle_condflag = 1;
		pthread_cond_signal(&mailbox->m_smtpidle_cond);

	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);
}
