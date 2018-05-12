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


void mrmailbox_connect_to_imap(mrmailbox_t* ths, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	int             is_locked = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( ths == NULL || ths->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	if( mrimap_is_connected(ths->m_imap) ) {
		mrmailbox_log_info(ths, 0, "Already connected or trying to connect.");
		goto cleanup;
	}

	mrsqlite3_lock(ths->m_sql);
	is_locked = 1;

		if( mrsqlite3_get_config_int__(ths->m_sql, "configured", 0) == 0 ) {
			mrmailbox_log_error(ths, 0, "Not configured.");
			goto cleanup;
		}

		mrloginparam_read__(param, ths->m_sql, "configured_" /*the trailing underscore is correct*/);

	mrsqlite3_unlock(ths->m_sql);
	is_locked = 0;

	if( !mrimap_connect(ths->m_imap, param) ) {
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
		goto cleanup;
	}

cleanup:
	if( is_locked ) { mrsqlite3_unlock(ths->m_sql); }
	mrloginparam_unref(param);
}



/**
 * Connect to the mailbox using the configured settings.  We connect using IMAP-IDLE or, if this is not possible,
 * a using pull algorithm.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object as created by mrmailbox_new()
 *
 * @return None
 */
void mrmailbox_connect(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	mrsqlite3_lock(mailbox->m_sql);

		mailbox->m_smtp->m_log_connect_errors = 1;
		mailbox->m_imap->m_log_connect_errors = 1;

		mrjob_kill_action__(mailbox, MRJ_CONNECT_TO_IMAP);
		mrjob_add__(mailbox, MRJ_CONNECT_TO_IMAP, 0, NULL, 0);

	mrsqlite3_unlock(mailbox->m_sql);
}


/**
 * Disonnect the mailbox from the server.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object as created by mrmailbox_new()
 *
 * @return None
 */
void mrmailbox_disconnect(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		return;
	}

	mrsqlite3_lock(mailbox->m_sql);

		mrjob_kill_action__(mailbox, MRJ_CONNECT_TO_IMAP);

	mrsqlite3_unlock(mailbox->m_sql);

	mrimap_disconnect(mailbox->m_imap);
	mrsmtp_disconnect(mailbox->m_smtp);
}


/**
 * Check for changes in the mailbox. mrmailbox_pull() connects, checks and disconnects
 * as fast as possible for this purpose. If there are new messages, you get them
 * as usual through the event handler given to mrmailbox_new().
 *
 * The function may take a while until it returns, typically about 1 second
 * but if connection is not possible, it may be much longer.  The caller may
 * want to call mrmailbox_pull() from a non-ui thread therefore.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return Returns the number of seconds when this function should be called again.
 */
int mrmailbox_pull(mrmailbox_t* mailbox)
{
	if( mailbox == NULL || mailbox->m_magic != MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	// TODO: connect to IMAP and check the INBOX _without_ creating a separate thread.
	#if 0
	mrmailbox_connect_to_imap(mailbox, NULL);
	if( !mrimap_is_connected(mailbox->m_imap) ) {
		goto cleanup;
	}

	mrimap_disconnect(mailbox->m_imap);
	#endif

cleanup:
	return 30;
}


/**
 * Stay alive.
 * The library tries itself to stay alive. For this purpose there is an additional
 * "heartbeat" thread that checks if the IDLE-thread is up and working. This check is done about every minute.
 * However, depending on the operating system, this thread may be delayed or stopped, if this is the case you can
 * force additional checks manually by just calling mrmailbox_heartbeat() about every minute.
 * If in doubt, call this function too often, not too less :-)
 *
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

	//mrmailbox_log_info(ths, 0, "<3 Mailbox");
	mrimap_heartbeat(mailbox->m_imap);
}
