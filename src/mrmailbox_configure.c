/*******************************************************************************
 *
 *                             Messenger Backend
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
 *******************************************************************************
 *
 * File:    mrmailbox_configure.c
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrloginparam.h"
#include "mrimap.h"
#include "mrsmtp.h"
#include "mrosnative.h"


static pthread_t s_configure_thread;
static int       s_configure_thread_created = 0;
static int       s_configure_do_exit = 1; /* the value 1 avoids mrmailbox_configure_cancel() from stopping already stopped threads */


/*******************************************************************************
 * The configuration thread
 ******************************************************************************/


static void* configure_thread_entry_point(void* entry_arg)
{
	mrmailbox_t*    mailbox = (mrmailbox_t*)entry_arg;
	int             success = 0;
	mrloginparam_t* param = mrloginparam_new();
	#define         CHECK_EXIT if( s_configure_do_exit ) { goto exit_; }

	mrmailbox_log_info(mailbox, 0, "Configure-thread started.");
	mrosnative_setup_thread(mailbox);

	CHECK_EXIT

	mrsqlite3_lock(mailbox->m_sql);
		mrloginparam_read__(param, mailbox->m_sql, "");
	mrsqlite3_unlock(mailbox->m_sql);

	/* complete the parameters; in the future we may also try some server connections here */
	mrloginparam_complete(param, mailbox);

	/* write back the configured parameters with the "configured_" prefix. Also write the "configured"-flag */
	if( !param->m_addr
	 || !param->m_mail_server
	 || !param->m_mail_port
	 || !param->m_mail_user
	 || !param->m_mail_pw
	 || !param->m_send_server
	 || !param->m_send_port
	 || !param->m_send_user
	 || !param->m_send_pw )
	{
		mrmailbox_log_error(mailbox, 0, "Cannot get configuration.");
		goto exit_;
	}

	CHECK_EXIT

	/* try to connect */
	if( !mrimap_connect(mailbox->m_imap, param) ) {
		goto exit_;
	}

	CHECK_EXIT

	if( !mrsmtp_connect(mailbox->m_smtp, param) )  {
		goto exit_;
	}

	/* configuration success */
	mrloginparam_write__(param, mailbox->m_sql, "configured_" /*the trailing underscore is correct*/);
	mrsqlite3_set_config_int__(mailbox->m_sql, "configured", 1);
	success = 1;
	mrmailbox_log_info(mailbox, 0, "Configure-thread finished.");

exit_:
	mrloginparam_unref(param);
	s_configure_do_exit = 1; /* set this before sending MR_EVENT_CONFIGURE_ENDED, avoids mrmailbox_configure_cancel() to stop the thread */
	mailbox->m_cb(mailbox, MR_EVENT_CONFIGURE_ENDED, success, 0);
	mrosnative_unsetup_thread(mailbox);
	s_configure_thread_created = 0;
	return NULL;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mrmailbox_configure_and_connect(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	mrmailbox_log_info(mailbox, 0, "Configuring...");

	if( !mrsqlite3_is_open(mailbox->m_sql) ) {
		mrmailbox_log_error(mailbox, 0, "Database not opened.");
		s_configure_do_exit = 1;
		mailbox->m_cb(mailbox, MR_EVENT_CONFIGURE_ENDED, 0, 0);
		return;
	}

	if( s_configure_thread_created || s_configure_do_exit == 0 ) {
		mrmailbox_log_error(mailbox, 0, "Already configuring.");
		return; /* do not send a MR_EVENT_CONFIGURE_ENDED event, this is done by the already existing thread */
	}

	s_configure_thread_created = 1;
	s_configure_do_exit        = 0;

	/* disconnect */
	mrmailbox_disconnect(mailbox);
	mrsqlite3_lock(mailbox->m_sql);
		//mrsqlite3_set_config_int__(mailbox->m_sql, "configured", 0); -- NO: we do _not_ reset this flag if it was set once; otherwise the user won't get back to his chats (as an alternative, we could change the frontends)
		mailbox->m_smtp->m_log_connect_errors = 1;
		mailbox->m_imap->m_log_connect_errors = 1;
	mrsqlite3_unlock(mailbox->m_sql);

	/* start a thread for the configuration it self, when done, we'll post a MR_EVENT_CONFIGURE_ENDED event */
	pthread_create(&s_configure_thread, NULL, configure_thread_entry_point, mailbox);
}


void mrmailbox_configure_cancel(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	if( s_configure_thread_created && s_configure_do_exit==0 )
	{
		mrmailbox_log_info(mailbox, 0, "Stopping configure-thread...");
			s_configure_do_exit = 1;
			pthread_join(s_configure_thread, NULL);
		mrmailbox_log_info(mailbox, 0, "Configure-thread stopped.");
	}
}


int mrmailbox_is_configured(mrmailbox_t* mailbox)
{
	int is_configured;

	if( mailbox == NULL ) {
		return 0;
	}

	if( mrimap_is_connected(mailbox->m_imap) ) { /* if we're connected, we're also configured. this check will speed up the check as no database is involved */
		return 1;
	}

	mrsqlite3_lock(mailbox->m_sql);

		is_configured = mrsqlite3_get_config_int__(mailbox->m_sql, "configured", 0);

	mrsqlite3_unlock(mailbox->m_sql);

	return is_configured? 1 : 0;
}


