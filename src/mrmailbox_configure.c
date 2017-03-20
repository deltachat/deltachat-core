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
#include "mrsaxparser.h"
#include "mrtools.h"


/*******************************************************************************
 * AutoConfigure
 ******************************************************************************/


typedef struct autoconfig_t
{
	const mrloginparam_t* m_in;
	char*                 m_in_emaildomain;
	char*                 m_in_emaillocalpart;
	mrloginparam_t*       m_out;

	/* currently, we assume there is only one emailProvider tag in the
	file, see example at https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
	moreover, we assume, the returned domains match the one queried.  I've not seen another example (bp).
	However, _if_ the assumpltions are wrong, we can add a first saxparser-pass that searches for the correct domain
	and the second pass will look for the index found. */

	#define AC_SERVER_IMAP 1
	#define AC_SERVER_SMTP 2
	int m_tag_server;

	#define AC_HOSTNAME   10
	#define AC_PORT       11
	#define AC_USERNAME   12
	#define AC_SOCKETTYPE 13
	int m_tag_config;

} autoconfig_t;


static void autoconfig_starttag_cb(void* userdata, const char* tag, char** attr)
{
	autoconfig_t* autoconfig = (autoconfig_t*)userdata;
	const char*   p1;

	if( strcmp(tag, "incomingserver")==0 ) {
		autoconfig->m_tag_server = ((p1=mrattr_find(attr, "type"))!=NULL && strcasecmp(p1, "imap")==0)? AC_SERVER_IMAP : 0;
		autoconfig->m_tag_config = 0;
	}
	else if( strcmp(tag, "outgoingserver") == 0 ) {
		autoconfig->m_tag_server = AC_SERVER_SMTP;
		autoconfig->m_tag_config = 0;
	}
	else if( strcmp(tag, "hostname") == 0 ) {
		autoconfig->m_tag_config = AC_HOSTNAME;
	}
	else if( strcmp(tag, "port") == 0 ) {
		autoconfig->m_tag_config = AC_PORT;
	}
	else if( strcmp(tag, "sockettype") == 0 ) {
		autoconfig->m_tag_config = AC_SOCKETTYPE;
	}
	else if( strcmp(tag, "username") == 0 ) {
		autoconfig->m_tag_config = AC_USERNAME;
	}
}


static void autoconfig_text_cb(void* userdata, const char* text, int len)
{
	autoconfig_t*   ac = (autoconfig_t*)userdata;

	char* val = safe_strdup(text);
	mr_trim(val);
	mr_str_replace(&val, "%EMAILADDRESS%",   ac->m_in->m_addr);
	mr_str_replace(&val, "%EMAILLOCALPART%", ac->m_in_emaillocalpart);
	mr_str_replace(&val, "%EMAILDOMAIN%",    ac->m_in_emaildomain);

	if( ac->m_tag_server == AC_SERVER_IMAP ) {
		switch( ac->m_tag_config ) {
			case AC_HOSTNAME: free(ac->m_out->m_mail_server); ac->m_out->m_mail_server = val; val = NULL; break;
			case AC_PORT:                                     ac->m_out->m_mail_port   = atoi(val);       break;
			case AC_USERNAME: free(ac->m_out->m_mail_user);   ac->m_out->m_mail_user   = val; val = NULL; break;
			case AC_SOCKETTYPE:
				if( strcasecmp(val, "ssl")==0 )      { ac->m_out->m_server_flags |=MR_IMAP_SOCKET_SSL; }
				if( strcasecmp(val, "starttls")==0 ) { ac->m_out->m_server_flags |=MR_IMAP_SOCKET_STARTTLS; }
				if( strcasecmp(val, "plain")==0 )    { ac->m_out->m_server_flags |=MR_IMAP_SOCKET_PLAIN; }
				break;
		}
	}
	else if( ac->m_tag_server == AC_SERVER_SMTP ) {
		switch( ac->m_tag_config ) {
			case AC_HOSTNAME: free(ac->m_out->m_send_server); ac->m_out->m_send_server = val; val = NULL; break;
			case AC_PORT:                                     ac->m_out->m_send_port   = atoi(val);       break;
			case AC_USERNAME: free(ac->m_out->m_send_user);   ac->m_out->m_send_user   = val; val = NULL; break;
			case AC_SOCKETTYPE:
				if( strcasecmp(val, "ssl")==0 )      { ac->m_out->m_server_flags |=MR_SMTP_SOCKET_SSL; }
				if( strcasecmp(val, "starttls")==0 ) { ac->m_out->m_server_flags |=MR_SMTP_SOCKET_STARTTLS; }
				if( strcasecmp(val, "plain")==0 )    { ac->m_out->m_server_flags |=MR_SMTP_SOCKET_PLAIN; }
				break;
		}
	}

	free(val);
}


static void autoconfig_endtag_cb(void* userdata, const char* tag)
{
	autoconfig_t* autoconfig = (autoconfig_t*)userdata;

	if( strcmp(tag, "incomingserver")==0 || strcmp(tag, "outgoingserver")==0 ) {
		autoconfig->m_tag_server = 0;
		autoconfig->m_tag_config = 0;
	}
	else {
		autoconfig->m_tag_config = 0;
	}
}


static mrloginparam_t* autoconfig_do(mrmailbox_t* mailbox, const char* url, const mrloginparam_t* param_in)
{
	char* xml_raw = NULL;
	autoconfig_t autoconfig;
	memset(&autoconfig, 0, sizeof(autoconfig_t));

	mrmailbox_log_info(mailbox, 0, "Trying autoconfig from %s ...", url);
	xml_raw = (char*)mailbox->m_cb(mailbox, MR_EVENT_HTTP_GET, (uintptr_t)url, 0);
	if( xml_raw == NULL ) {
		mrmailbox_log_info(mailbox, 0, "Can't get autoconfig file.");
		goto cleanup;
	}

	/* parse the file ... */
	autoconfig.m_in                = param_in;
	autoconfig.m_in_emaillocalpart = safe_strdup(param_in->m_addr); char* p = strchr(autoconfig.m_in_emaillocalpart, '@'); if( p == NULL ) { goto cleanup; } *p = 0;
	autoconfig.m_in_emaildomain    = safe_strdup(p+1);
	autoconfig.m_out               = mrloginparam_new();
	autoconfig.m_out->m_mail_user  = strdup_keep_null(param_in->m_mail_user);

	mrsaxparser_t                 saxparser;
	mrsaxparser_init            (&saxparser, &autoconfig);
	mrsaxparser_set_tag_handler (&saxparser, autoconfig_starttag_cb, autoconfig_endtag_cb);
	mrsaxparser_set_text_handler(&saxparser, autoconfig_text_cb);
	mrsaxparser_parse           (&saxparser, xml_raw);

	if( autoconfig.m_out->m_mail_server == NULL
	 || autoconfig.m_out->m_mail_port == 0
	 || autoconfig.m_out->m_send_server == NULL
	 || autoconfig.m_out->m_send_port == 0 )
	{
		{ char* r = mrloginparam_get_readable(autoconfig.m_out); mrmailbox_log_warning(mailbox, 0, "Bad or incomplete autoconfig: %s", r); free(r); }

		mrloginparam_unref(autoconfig.m_out); /* autoconfig failed for the given URL */
		autoconfig.m_out = NULL;
		goto cleanup;
	}

	/* success */
	if( autoconfig.m_out->m_addr == NULL )    { autoconfig.m_out->m_addr      = strdup_keep_null(autoconfig.m_in->m_addr);    }
	if( autoconfig.m_out->m_mail_pw == NULL ) { autoconfig.m_out->m_mail_pw   = strdup_keep_null(autoconfig.m_in->m_mail_pw); }

	{ char* r = mrloginparam_get_readable(autoconfig.m_out); mrmailbox_log_info(mailbox, 0, "Got autoconfig: %s", r); free(r); }

cleanup:
	free(xml_raw);
	free(autoconfig.m_in_emaildomain);
	free(autoconfig.m_in_emaillocalpart);
	return autoconfig.m_out; /* may be NULL */
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
	char*           param_domain = NULL; /* just a pointer inside param, must not be freed! */
	char*           param_addr_urlencoded = NULL;
	mrloginparam_t* param_autoconfig = NULL;

	#define         CHECK_EXIT if( s_configure_do_exit ) { goto exit_; }

	mrmailbox_log_info(mailbox, 0, "Configure-thread started.");
	mrosnative_setup_thread(mailbox);

	CHECK_EXIT

	if( mailbox->m_cb(mailbox, MR_EVENT_IS_ONLINE, 0, 0)!=1 ) {
		mrmailbox_log_error(mailbox, MR_ERR_NONETWORK, NULL);
		goto exit_;
	}

	CHECK_EXIT

	/* 1.  Load the parameters and check e-mail-address and password
	 **************************************************************************/

	mrsqlite3_lock(mailbox->m_sql);
		mrloginparam_read__(param, mailbox->m_sql, "");
	mrsqlite3_unlock(mailbox->m_sql);

	if( param->m_addr == NULL ) {
		mrmailbox_log_error(mailbox, 0, "Please enter the e-mail address.");
		goto exit_;
	}
	mr_trim(param->m_addr);

	param_domain = strchr(param->m_addr, '@');
	if( param_domain==NULL || param_domain[0]==0 ) {
		mrmailbox_log_error(mailbox, 0, "Bad email-address.");
		goto exit_;
	}
	param_domain++;

	param_addr_urlencoded = mr_url_encode(param->m_addr);

	/* if no password is given, assume an empty password.
	(in general, unset values are NULL, not the empty string, this allows to use eg. empty user names or empty passwords) */
	if( param->m_mail_pw == NULL ) {
		param->m_mail_pw = safe_strdup(NULL);
	}


	/* 2.  Autoconfig
	 **************************************************************************/

	if( param->m_mail_server  == NULL
	 && param->m_mail_port    == 0
	/*&&param->m_mail_user    == NULL -- the user can enter a loginname which is used by autoconfig then */
	 && param->m_send_server  == NULL
	 && param->m_send_port    == 0
	 && param->m_send_user    == NULL
	/*&&param->m_send_pw      == NULL -- the password cannot be auto-configured and is no criterion for autoconfig or not */
	 && param->m_server_flags == 0 )
	{
		CHECK_EXIT

		char* url = mr_mprintf("http://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", param_domain, param_addr_urlencoded);
		param_autoconfig = autoconfig_do(mailbox, url, param);
		free(url);

		CHECK_EXIT

		if( param_autoconfig==NULL )
		{
			char* url = mr_mprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", param_domain, param_addr_urlencoded);
			param_autoconfig = autoconfig_do(mailbox, url, param);
			free(url);

			if( param_autoconfig==NULL )
			{
				url = mr_mprintf("https://autoconfig.thunderbird.net/v1.1/%s", param_domain);
				param_autoconfig = autoconfig_do(mailbox, url, param);
				free(url);
			}
		}

		CHECK_EXIT

		if( param_autoconfig )
		{
			free(param->m_mail_user); param->m_mail_user = NULL; /* all other pointers are already NULL, see initial condition */

			param->m_mail_server  = strdup_keep_null(param_autoconfig->m_mail_server);
			param->m_mail_port    =                  param_autoconfig->m_mail_port;
			param->m_mail_user    = strdup_keep_null(param_autoconfig->m_mail_user);
			param->m_send_server  = strdup_keep_null(param_autoconfig->m_send_server);
			param->m_send_port    =                  param_autoconfig->m_send_port;
			param->m_send_user    = strdup_keep_null(param_autoconfig->m_send_user);
			param->m_send_pw      = strdup_keep_null(param_autoconfig->m_send_pw);
			param->m_server_flags =                  param_autoconfig->m_server_flags;
		}
	}


	/* 3.  Internal specials (eg. for uploading to chats-folder etc.)
	 **************************************************************************/

	if( strcasecmp(param_domain, "gmail.com")==0 || strcasecmp(param_domain, "googlemail.com")==0 )
	{
		/* NB: Checking GMail too often (<10 Minutes) may result in blocking, says https://github.com/itprojects/InboxPager/blob/HEAD/README.md#gmail-configuration
		Also note https://www.google.com/settings/security/lesssecureapps */
		param->m_server_flags |= MR_AUTH_XOAUTH2 | MR_NO_EXTRA_IMAP_UPLOAD | MR_NO_MOVE_TO_CHATS;
	}


	/* 2.  Fill missing fields with defaults
	 **************************************************************************/

	#define TYPICAL_IMAP_SSL_PORT       993 /* our default */
	#define TYPICAL_IMAP_STARTTLS_PORT  143 /* not used very often but eg. by posteo.de, default for PLAIN */

	#define TYPICAL_SMTP_SSL_PORT       465 /* our default */
	#define TYPICAL_SMTP_STARTTLS_PORT  587 /* also used very often, SSL:STARTTLS is maybe 50:50 */
	#define TYPICAL_SMTP_PLAIN_PORT      25

	if( param->m_mail_server == NULL ) {
		param->m_mail_server = mr_mprintf("imap.%s", param_domain);
	}

	if( param->m_mail_port == 0 ) {
		param->m_mail_port = (param->m_server_flags&(MR_IMAP_SOCKET_STARTTLS|MR_IMAP_SOCKET_PLAIN))?  TYPICAL_IMAP_STARTTLS_PORT : TYPICAL_IMAP_SSL_PORT;
	}

	if( param->m_mail_user == NULL ) {
		param->m_mail_user = safe_strdup(param->m_addr);
	}

	if( param->m_send_server == NULL && param->m_mail_server ) {
		param->m_send_server = safe_strdup(param->m_mail_server);
		if( strncmp(param->m_send_server, "imap.", 5)==0 ) {
			memcpy(param->m_send_server, "smtp", 4);
		}
	}

	if( param->m_send_port == 0 ) {
		param->m_send_port = (param->m_server_flags&MR_SMTP_SOCKET_STARTTLS)?  TYPICAL_SMTP_STARTTLS_PORT :
			((param->m_server_flags&MR_SMTP_SOCKET_PLAIN)? TYPICAL_SMTP_PLAIN_PORT : TYPICAL_SMTP_SSL_PORT);
	}

	if( param->m_send_user == NULL && param->m_mail_user ) {
		param->m_send_user = safe_strdup(param->m_mail_user);
	}

	if( param->m_send_pw == NULL && param->m_mail_pw ) {
		param->m_send_pw = safe_strdup(param->m_mail_pw);
	}

	if( !mr_exactly_one_bit_set(param->m_server_flags&MR_AUTH_FLAGS) )
	{
		param->m_server_flags &= ~MR_AUTH_FLAGS;
		param->m_server_flags |= MR_AUTH_NORMAL;
	}

	if( !mr_exactly_one_bit_set(param->m_server_flags&MR_IMAP_SOCKET_FLAGS) )
	{
		param->m_server_flags &= ~MR_IMAP_SOCKET_FLAGS;
		param->m_server_flags |= (param->m_send_port==TYPICAL_IMAP_STARTTLS_PORT?  MR_IMAP_SOCKET_STARTTLS : MR_IMAP_SOCKET_SSL);
	}

	if( !mr_exactly_one_bit_set(param->m_server_flags&MR_SMTP_SOCKET_FLAGS) )
	{
		param->m_server_flags &= ~MR_SMTP_SOCKET_FLAGS;
		param->m_server_flags |= ( param->m_send_port==TYPICAL_SMTP_STARTTLS_PORT?  MR_SMTP_SOCKET_STARTTLS :
			(param->m_send_port==TYPICAL_SMTP_PLAIN_PORT? MR_SMTP_SOCKET_PLAIN: MR_SMTP_SOCKET_SSL) );
	}


	/* write back the configured parameters with the "configured_" prefix. Also write the "configured"-flag */
	if( param->m_addr         == NULL
	 || param->m_mail_server  == NULL
	 || param->m_mail_port    == 0
	 || param->m_mail_user    == NULL
	 || param->m_mail_pw      == NULL
	 || param->m_send_server  == NULL
	 || param->m_send_port    == 0
	 || param->m_send_user    == NULL
	 || param->m_send_pw      == NULL
	 || param->m_server_flags == 0 )
	{
		mrmailbox_log_error(mailbox, 0, "Account settings incomplete.");
		goto exit_;
	}

	CHECK_EXIT

	{ char* r = mrloginparam_get_readable(param); mrmailbox_log_info(mailbox, 0, "Configure result: %s", r); free(r); }

	/* try to connect */
	if( !mrimap_connect(mailbox->m_imap, param) ) {
		goto exit_;
	}

	CHECK_EXIT

	if( !mrsmtp_connect(mailbox->m_smtp, param) )  {
		goto exit_;
	}

	CHECK_EXIT

	/* configuration success */
	mrloginparam_write__(param, mailbox->m_sql, "configured_" /*the trailing underscore is correct*/);
	mrsqlite3_set_config_int__(mailbox->m_sql, "configured", 1);
	success = 1;
	mrmailbox_log_info(mailbox, 0, "Configure-thread finished.");

exit_:
	mrloginparam_unref(param);
	mrloginparam_unref(param_autoconfig);
	free(param_addr_urlencoded);

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


