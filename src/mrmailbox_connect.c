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
 * High-level IMAP-thread functions
 ******************************************************************************/


int mrmailbox_ll_connect_to_imap(mrmailbox_t* mailbox, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	#define         NOT_CONNECTED     0
	#define         ALREADY_CONNECTED 1
	#define         JUST_CONNECTED    2
	int             ret_connected = NOT_CONNECTED;
	int             is_locked = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
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


/**
 * Execute pending jobs.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None
 */
void mrmailbox_perform_jobs(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, ">>>>> perform-IMAP-jobs started.");

	mrjob_perform(mailbox, MR_IMAP_THREAD);

	mrmailbox_log_info(mailbox, 0, "<<<<< perform-IMAP-jobs ended.");
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
	clock_t         start = clock();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	if( !mrmailbox_ll_connect_to_imap(mailbox, NULL) ) {
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> fetch started.");

	mrimap_fetch(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< fetch done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);
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
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot idle: Bad parameters.");
		return;
	}

	if( !mrmailbox_ll_connect_to_imap(mailbox, NULL) ) {
		mrmailbox_log_info(mailbox, 0, "Cannot connect, idle anyway and waiting for configure.");
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> IMAP-IDLE started.");

	mrimap_watch_n_wait(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< IMAP-IDLE ended.");
}


/**
 * Interrupt the mrmailbox_perform_idle().
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None
 */
void mrmailbox_interrupt_idle(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot interrupt idle: Bad parameters.");
		return;
	}

	mrmailbox_log_info(mailbox, 0, "> > > interrupt IMAP-IDLE.");

	mrimap_interrupt_watch(mailbox->m_imap);
}



/*******************************************************************************
 * High-level SMTP-thread functions
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


void mrmailbox_send_msg_to_smtp(mrmailbox_t* mailbox, mrjob_t* job)
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
			mrjob_add__(mailbox, MRJ_SEND_MSG_TO_IMAP, mimefactory.m_msg->m_id, NULL, 0); /* send message to IMAP in another job */
		}

		// TODO: add to keyhistory
		mrmailbox_add_to_keyhistory__(mailbox, NULL, 0, NULL, NULL);

	mrsqlite3_commit__(mailbox->m_sql);
	mrsqlite3_unlock(mailbox->m_sql);

	mailbox->m_cb(mailbox, MR_EVENT_MSG_DELIVERED, mimefactory.m_msg->m_chat_id, mimefactory.m_msg->m_id);

cleanup:
	mrmimefactory_empty(&mimefactory);
}


void mrmailbox_send_mdn(mrmailbox_t* mailbox, mrjob_t* job)
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


void mrmailbox_perform_smtp_jobs(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, ">>>>> perform-SMTP-jobs started.");

	mrjob_perform(mailbox, MR_SMTP_THREAD);

	mrmailbox_log_info(mailbox, 0, "<<<<< perform-SMTP-jobs ended.");
}


void mrmailbox_perform_smtp_idle(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, ">>>>> SMTP-idle started.");

	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);

		if( mailbox->m_smtpidle_condflag == 0 ) {
			struct timespec timeToWait;
			timeToWait.tv_sec  = time(NULL)+60;
			timeToWait.tv_nsec = 0;
			pthread_cond_timedwait(&mailbox->m_smtpidle_cond, &mailbox->m_smtpidle_condmutex, &timeToWait); /* unlock mutex -> wait -> lock mutex */
		}
		mailbox->m_smtpidle_condflag = 0;

	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);

	mrmailbox_log_info(mailbox, 0, "<<<<< SMTP-idle ended.");
}


void mrmailbox_interrupt_smtp_idle(mrmailbox_t* mailbox)
{
	mrmailbox_log_info(mailbox, 0, "> > > interrupt SMTP-idle.");

	pthread_mutex_lock(&mailbox->m_smtpidle_condmutex);

		mailbox->m_smtpidle_condflag = 1;
		pthread_cond_signal(&mailbox->m_smtpidle_cond);

	pthread_mutex_unlock(&mailbox->m_smtpidle_condmutex);
}
