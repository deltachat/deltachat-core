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
#include <string.h>
#include "mrmailbox.h"
#include "mrloginparam.h"
#include "mrimap.h"
#include "mrsmtp.h"
#include "mrosnative.h"
#include "mrtools.h"


/*******************************************************************************
 * Configuration guessing
 ******************************************************************************/


static int exactly_one_bit_set(int v)
{
	return (v && !(v & (v - 1))); /* via http://www.graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2 */
}


static void loginparam_guess(mrloginparam_t* ths, mrmailbox_t* mailbox)
{
	/* tries to set missing parameters from at least m_addr and m_mail_pw */
	char* adr_server;

	if( ths == NULL || ths->m_addr == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Configuration failed, we need at least the email-address.");
		return; /* nothing we can do */
	}

	/* if no password is given, assume an empty password.
	(in general, unset values are NULL, not the empty string, this allows to use eg. empty user names or empty passwords) */
	if( ths->m_mail_pw == NULL ) {
		ths->m_mail_pw = safe_strdup("");
	}

	adr_server = strstr(ths->m_addr, "@");
	if( adr_server == NULL ) {
		mrmailbox_log_warning(mailbox, 0, "Configuration failed, bad email-address.");
		return; /* no "@" found in address, normally, this should not happen */
	}
	adr_server++;

	/* set servers, ports etc. for well-known and frequently used and/or privacy-aware services.
	Examples: gmail.com, gmx.net, web.de, yahoo.com, posteo.de, mailbox.org

	TODO: maybe we should support Thunderbird's Autoconfiguration
	( https://developer.mozilla.org/en-US/docs/Mozilla/Thunderbird/Autoconfiguration ,
	https://wiki.mozilla.org/Thunderbird:Autoconfiguration ).
	At a glance, this would result in HTTP-download as `https://autoconfig.thunderbird.net/v1.1/posteo.de`
	or even `http://autoconfig.posteo.de` */
	if( strcasecmp(adr_server, "gmail.com")==0
	 || strcasecmp(adr_server, "googlemail.com")==0 )
	{
		/* Google
		Checking GMail too often (<10 Minutes) may result in blocking, says https://github.com/itprojects/InboxPager/blob/HEAD/README.md#gmail-configuration
		also not https://www.google.com/settings/security/lesssecureapps - is this needed? */
		if( ths->m_mail_server == NULL )               { ths->m_mail_server = safe_strdup("imap.gmail.com"); }
		if( ths->m_mail_port == 0 )                    { ths->m_mail_port   = 993; } /* IMAPS */
		if( ths->m_mail_user == NULL )                 { ths->m_mail_user   = safe_strdup(ths->m_addr); }

		if( ths->m_send_server == NULL )               { ths->m_send_server = safe_strdup("smtp.gmail.com"); }
		if( ths->m_send_port == 0 )                    { ths->m_send_port   = 465; } /* SSMTP - difference between 465 and 587: http://stackoverflow.com/questions/15796530/what-is-the-difference-between-ports-465-and-587 */
		if( ths->m_send_user == NULL )                 { ths->m_send_user   = safe_strdup(ths->m_addr); }
		if( ths->m_send_pw == NULL && ths->m_mail_pw ) { ths->m_send_pw     = safe_strdup(ths->m_mail_pw); }
		if( ths->m_server_flags == 0 )                 { ths->m_server_flags= MR_AUTH_XOAUTH2 | MR_SMTP_SSL_TLS | MR_NO_EXTRA_IMAP_UPLOAD | MR_NO_MOVE_TO_CHATS; }
		return;
	}
	else if( strcasecmp(adr_server, "web.de")==0 )
	{
		if( ths->m_send_server == NULL && ths->m_send_port == 0 && ths->m_server_flags == 0 ) {
			ths->m_send_port = 587;
			ths->m_server_flags = MR_SMTP_STARTTLS;
		}
	}

	/* generic approach, just duplicate the servers and use the standard ports.
	works fine eg. for all-inkl */
	if( ths->m_mail_server == NULL ) {
		ths->m_mail_server = mr_mprintf("imap.%s", adr_server);
	}

	if( ths->m_mail_port == 0 ) {
		ths->m_mail_port = 993;
	}

	if( ths->m_mail_user == NULL ) {
		ths->m_mail_user = safe_strdup(ths->m_addr);
	}

	if( ths->m_send_server == NULL && ths->m_mail_server ) {
		ths->m_send_server = safe_strdup(ths->m_mail_server);
		if( strncmp(ths->m_send_server, "imap.", 5)==0 ) {
			memcpy(ths->m_send_server, "smtp", 4);
		}
	}

	if( ths->m_send_port == 0 ) {
		ths->m_send_port = 465;
	}

	if( ths->m_send_user == NULL && ths->m_mail_user ) {
		ths->m_send_user = safe_strdup(ths->m_mail_user);
	}

	if( ths->m_send_pw == NULL && ths->m_mail_pw ) {
		ths->m_send_pw = safe_strdup(ths->m_mail_pw);
	}

	if( ths->m_server_flags == 0 ) {
		ths->m_server_flags = MR_SMTP_SSL_TLS;
	}
}


/*******************************************************************************
 * The configuration thread
 ******************************************************************************/


static pthread_t s_configure_thread;
static int       s_configure_thread_created = 0;
static int       s_configure_do_exit = 1; /* the value 1 avoids mrmailbox_configure_cancel() from stopping already stopped threads */


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
	if( (param->m_server_flags&MR_NO_AUTOCONFIG)==0 )
	{
		loginparam_guess(param, mailbox);
	}

	/* set some default flags (one is always needed) */
	if( !exactly_one_bit_set(param->m_server_flags&MR_AUTH_FLAGS) )
	{
		param->m_server_flags &= ~MR_AUTH_FLAGS;
		param->m_server_flags |= MR_AUTH_NORMAL;
	}

	if( !exactly_one_bit_set(param->m_server_flags&MR_SMTP_FLAGS) )
	{
		param->m_server_flags &= ~MR_SMTP_FLAGS;
		param->m_server_flags |= MR_SMTP_SSL_TLS;
	}


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
		mrmailbox_log_error(mailbox, 0, "Configuration parameters incomplete.");
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


