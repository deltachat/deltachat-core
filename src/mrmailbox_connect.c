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
		mrmailbox_log_info(mailbox, 0, "IMAP already connected.");
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
 * Check for changes in the mailbox. mrmailbox_poll() connects, checks and disconnects
 * as fast as possible for this purpose. If there are new messages, you get them
 * as usual through the event handler given to mrmailbox_new().
 *
 * Typically the function takes less than 1 second, however, for various reasons
 * it may take much longer to connect-check-disconnect.  The caller should
 * call mrmailbox_poll() from a non-ui thread therefore.
 *
 * If there is already a permanent push connection to the server, mrmailbox_poll()
 * return 0 and does nothing (permanent push connections are started and ended with mrmailbox_connect()
 * and mrmailbox_disconnect()).
 *
 * See also: mrmailbox_idle()
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return If polling was done, the function returns 1.
 *     If polling was not done, eg. on errors or if there is already a permanent connection, the function returns 0.
 */
int mrmailbox_poll(mrmailbox_t* mailbox)
{
	clock_t         start = clock();
	int             polling_done = 0;
	int             connected = NOT_CONNECTED;

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	if( mailbox->m_in_idle ) {
		mrmailbox_log_info(mailbox, 0, "In idle, poll not needed.");
		goto cleanup;
	}

	if( mailbox->m_block_idle ) {
		mrmailbox_log_info(mailbox, 0, "Idle blocked, won't poll as well.");
		goto cleanup;
	}

	if( (connected=mrmailbox_ll_connect_to_imap(mailbox, NULL)) == NOT_CONNECTED ) {
		goto cleanup;
	}

	mrimap_fetch(mailbox->m_imap);

	mrimap_disconnect(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "▶⏹️ Poll done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	polling_done = 1;

cleanup:
	if( connected == JUST_CONNECTED ) { mrimap_disconnect(mailbox->m_imap); }
	return polling_done;
}


/**
 * Wait for messages.
 * mrmailbox_idle() waits until there are new messages.
 * If there are new messages, you get them as usual through the event handler given to mrmailbox_new().
 * After that, the function waits for messages again.
 * If the mailbox is not yet configured or the connection is down,
 * the function tries to reconnect as soon as changes in the environment are detected.
 *
 * So, the function may last forever; however, you can interrupt it by mrmailbox_interrupt_idle().
 *
 * Waiting for messages is typically done by IMAP-IDLE, but there may also be different approaches
 * eg. if IMAP-IDLE is not available.
 *
 * This function MUST be called in a separate thread
 * and MUST NOT run in the UI thread or in the thread that calls mrmailbox_interrupt_idle().
 * To check if mrmailbox_idle() is runninng, you can use mrmailbox_is_idle().
 *
 * See also: mrmailbox_poll()
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return 0=cannot do idle, probably, there is already an idle process running
 *     1=idle interrupted by mrmailbox_interrupt_idle()
 */
int mrmailbox_idle(mrmailbox_t* mailbox)
{
	int success = 0;

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot idle: Bad parameters.");
		goto cleanup;
	}

	if( mailbox->m_block_idle ) {
		mrmailbox_log_info(mailbox, 0, "Idle blocked.");
		goto cleanup;
	}

	pthread_mutex_lock(&mailbox->m_in_idle_critical); // the mutex makes sure, m_in_idle can only be set by one thread
		if( mailbox->m_in_idle ) {
			mrmailbox_log_info(mailbox, 0, "Already in idle.");
			pthread_mutex_unlock(&mailbox->m_in_idle_critical);
			goto cleanup;
		}
		mailbox->m_in_idle = 1;
	pthread_mutex_unlock(&mailbox->m_in_idle_critical);

	if( !mrmailbox_ll_connect_to_imap(mailbox, NULL) ) {
		mrmailbox_log_info(mailbox, 0, "Cannot idle: Cannot connect.");
		goto cleanup;
	}

	mrimap_watch_n_wait(mailbox->m_imap);

	success = 1;

cleanup:
	mailbox->m_in_idle = 0;
	return success;
}


/**
 * Check if the mrmailbox_idle() function is running.
 * Typically, mrmailbox_idle() is started in a separate thread,
 * this function may be handy to decide if a new thread should be started or not.
 *
 * Independingly of the state returned by this function, mrmailbox_idle() or mrmailbox_interrupt_idle,
 * however, may or may not succeed.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return 0=mrmailbox_idle() is not running;
 *     1=mrmailbox_idle() is running
 */
int mrmailbox_is_idle(mrmailbox_t* mailbox)
{
	return (mailbox && mailbox->m_in_idle);
}


/**
 * Interrupt the function that waits for messages.
 *
 * If you have started mrmailbox_idle() in a separate thread to wait for push messages, mrmailbox_idle() typically runs forever.
 * To stop waiting for messages, call mrmailbox_interrupt_idle().
 *
 * mrmailbox_interrupt_idle() signals mrmailbox_idle() stop and returns _immediately_.
 * You may want to wait for the idle-thread to finish; this is _not_ done by this function.
 * (waiting for a thread can be perfomed eg. by pthread_join() or Thread.join(), depending on your environment).
 * To check if the idle thread is ended, you can use mrmailbox_is_idle().
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return 0=There is no idle function to interrupt or other errors;
 *     1=mrmailbox_idle() signalled to stop
 */
int mrmailbox_interrupt_idle(mrmailbox_t* mailbox)
{
	int success = 0;

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot interrupt idle: Bad parameters.");
		goto cleanup;
	}

	if( !mailbox->m_in_idle ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot interrupt idle: Not in idle.");
		goto cleanup;
	}

	mrimap_interrupt_watch(mailbox->m_imap);

	success = 1;

cleanup:
	return success;
}


