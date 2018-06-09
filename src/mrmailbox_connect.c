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
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> perform-jobs started.");

	mrjob_perform(mailbox);

	mrmailbox_log_info(mailbox, 0, "<<<<< perform-jobs ended.");
}


/**
 * Poll for new messages.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None.
 */
void mrmailbox_perform_poll(mrmailbox_t* mailbox)
{
	clock_t         start = clock();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	if( !mrmailbox_ll_connect_to_imap(mailbox, NULL) ) {
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> perform-poll started.");

	mrimap_fetch(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< perform-poll done in %.0f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);
}


/**
 * Wait for messages.
 *
 * @memberof mrmailbox_t
 * @param mailbox The mailbox object.
 * @return None.
 */
void mrmailbox_perform_idle(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC || mailbox->m_imap == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Cannot idle: Bad parameters.");
		return;
	}

	if( !mrmailbox_ll_connect_to_imap(mailbox, NULL) ) {
		mrmailbox_log_info(mailbox, 0, "Cannot idle: Cannot connect.");
		return;
	}

	mrmailbox_log_info(mailbox, 0, ">>>>> perform-idle started.");

	mrimap_watch_n_wait(mailbox->m_imap);

	mrmailbox_log_info(mailbox, 0, "<<<<< perform-idle ended.");
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

	mrmailbox_log_info(mailbox, 0, "> > > interrupt-idle");

	mrimap_interrupt_watch(mailbox->m_imap);
}

