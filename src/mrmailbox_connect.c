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


#include "mrmailbox_internal.h"
#include "mrloginparam.h"
#include "mrjob.h"
#include "mrimap.h"
#include "mrsmtp.h"


void mrmailbox_ll_connect_to_imap(mrmailbox_t* mailbox, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	int             is_locked = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	if( mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_log_info(mailbox, 0, "Already connected or trying to connect.");
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

	mrimap_start_watch_thread(mailbox->m_imap);

cleanup:
	if( is_locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrloginparam_unref(param);
}


void mrmailbox_ll_disconnect(mrmailbox_t* mailbox, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	mrimap_disconnect(mailbox->m_imap);
	mrsmtp_disconnect(mailbox->m_smtp);
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
	int             is_locked = 0;
	int             connected_here = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	mrmailbox_log_info(mailbox, 0, "Polling...");

	if( mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_log_info(mailbox, 0, "Poll not needed, already connected or trying to connect.");
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	is_locked = 1;

		if( mrsqlite3_get_config_int__(mailbox->m_sql, "configured", 0) == 0 ) {
			mrmailbox_log_warning(mailbox, 0, "Not configured, cannot poll."); // this is no error, pull() is called eg. from a timer, it's okay if the caller does not check all circumstances here
			goto cleanup;
		}

		mrloginparam_read__(param, mailbox->m_sql, "configured_" /*the trailing underscore is correct*/);

	mrsqlite3_unlock(mailbox->m_sql);
	is_locked = 0;

	if( !mrimap_connect(mailbox->m_imap, param) ) {
		goto cleanup;
	}
	connected_here = 1;

	mrimap_fetch(mailbox->m_imap);

	mrimap_disconnect(mailbox->m_imap);
	connected_here = 0;

	mrmailbox_log_info(mailbox, 0, "Poll finished in %.3f ms.", (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	polling_done = 1;

cleanup:
	if( is_locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( connected_here ) { mrimap_disconnect(mailbox->m_imap); }
	mrloginparam_unref(param);
	return polling_done;
}


/**
 * Stay alive.
 * This function checks that eg. installed IMAP-PUSH is working and not halted
 * for any reasons. Normally, this works automatically - we have a timeout of about
 * 25 minutes and re-install push then. However, if this thread hangs it may
 * be useful on some operating systems to force a check. This can be done by this function.
 *
 * If you think, this function is required, you may want to call it about every minute.
 * The function MUST NOT be called from the UI thread and may take a moment to return.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return None.
 */
void mrmailbox_heartbeat(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	//mrmailbox_log_info(mailbox, 0, "<3 Mailbox");
	mrimap_heartbeat(mailbox->m_imap);
}


int mrmailbox_idle(mrmailbox_t* mailbox)
{
	return 0;
}


int mrmailbox_interrupt_idle(mrmailbox_t* mailbox)
{
	return 0;
}
