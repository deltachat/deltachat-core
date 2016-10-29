/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
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
 * File:    mrsmtp.c
 * Authors: Björn Petersen
 * Purpose: Use SMTP servers
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <libetpan/libetpan.h>
#include "mrmailbox.h"
#include "mrsmtp.h"
#include "mrlog.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrsmtp_t* mrsmtp_new()
{
	mrsmtp_t* ths;
	if( (ths=calloc(1, sizeof(mrsmtp_t)))==NULL ) {
		exit(29);
	}
	return ths;
}


void mrsmtp_unref(mrsmtp_t* ths)
{
	if( ths == NULL ) {
		return;
	}
	mrsmtp_disconnect(ths);
	free(ths);
}



/*******************************************************************************
 * Connect/Disconnect
 ******************************************************************************/


int mrsmtp_is_connected (mrsmtp_t* ths)
{
	return ths->m_hEtpan? 1 : 0;
}


int mrsmtp_connect(mrsmtp_t* ths, mrsqlite3_t* config)
{
	int         success = 0;
	char*       smtp_server = NULL;
	int         smtp_port;
	char*       smtp_user = NULL;
	char*       smtp_pw = NULL;
	int         smtp_esmtp = 1, smtp_ssl = 1, smtp_tls = 0; /* TODO: make additional configurations available */
	char*       smtp_from;
	int         ret, esmtp = 0;

	char*       rcpt = "foo@bar";
	char*       data = "just a test!";
	int         len = strlen(data);

	/* read configuration */
	mrsqlite3_lock(config);
		smtp_from   = mrsqlite3_get_config_    (config, "configured_addr", NULL);
		smtp_server = mrsqlite3_get_config_    (config, "configured_send_server", NULL);
		smtp_port   = mrsqlite3_get_config_int_(config, "configured_send_port", 0);
		smtp_user   = mrsqlite3_get_config_    (config, "configured_send_user", "");
		smtp_pw     = mrsqlite3_get_config_    (config, "configured_send_pw", "");
	mrsqlite3_unlock(config);
	if( smtp_from == NULL || smtp_server == NULL || smtp_port == 0 ) {
		goto done_;
	}

	ths->m_hEtpan = mailsmtp_new(0, NULL);
	if( ths->m_hEtpan == NULL ) {
		mrlog_error("mailsmtp_new() failed.");
	}

	/* first open the stream */
	if( smtp_ssl ) {
		/* use SMTP over SSL */
		if( (ret=mailsmtp_ssl_connect(ths->m_hEtpan, smtp_server, smtp_port)) != MAILSMTP_NO_ERROR ) {
			mrlog_error("mailsmtp_ssl_connect: %s\n", mailsmtp_strerror(ret));
			goto done_;
		}
	}
	else {
		/* use STARTTLS */
		if( (ret=mailsmtp_socket_connect(ths->m_hEtpan, smtp_server, smtp_port)) != MAILSMTP_NO_ERROR ) {
			mrlog_error("mailsmtp_socket_connect: %s\n", mailsmtp_strerror(ret));
			goto done_;
		}
	}

	/* then introduce ourselves */
	if (smtp_esmtp && (ret = mailesmtp_ehlo(ths->m_hEtpan)) == MAILSMTP_NO_ERROR) {
		esmtp = 1;
	}
	else if (!smtp_esmtp || ret == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
		ret = mailsmtp_helo(ths->m_hEtpan);
	}

	if (ret != MAILSMTP_NO_ERROR) {
		mrlog_error("mailsmtp_helo: %s\n", mailsmtp_strerror(ret));
		goto done_;
	}

	if( esmtp && smtp_tls && (ret=mailsmtp_socket_starttls(ths->m_hEtpan)) != MAILSMTP_NO_ERROR ) {
		mrlog_error("mailsmtp_starttls: %s\n", mailsmtp_strerror(ret));
		goto done_;
	}

	if (esmtp && smtp_tls) {
		/* introduce ourselves again */
		if (smtp_esmtp && (ret = mailesmtp_ehlo(ths->m_hEtpan)) == MAILSMTP_NO_ERROR) {
			esmtp = 1;
		}
		else if (!smtp_esmtp || ret == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
			ret = mailsmtp_helo(ths->m_hEtpan);
		}

		if (ret != MAILSMTP_NO_ERROR) {
			mrlog_error("mailsmtp_helo: %s\n", mailsmtp_strerror(ret));
			goto done_;
		}
	}

	if (esmtp && smtp_user != NULL && (ret = mailsmtp_auth(ths->m_hEtpan, smtp_user, smtp_pw)) != MAILSMTP_NO_ERROR) {
		mrlog_error("mailsmtp_auth: %s: %s\n", smtp_user, mailsmtp_strerror(ret));
		goto done_;
	}


  /* source */
  if ((ret = (esmtp ?
	      mailesmtp_mail(ths->m_hEtpan, smtp_from, 1, "etPanSMTPTest") :
	      mailsmtp_mail(ths->m_hEtpan, smtp_from))) != MAILSMTP_NO_ERROR) {
    mrlog_error("mailsmtp_mail: %s, %s\n", smtp_from, mailsmtp_strerror(ret));
    goto done_;
  }

  /* recipients */

    if ((ret = (esmtp ?
		mailesmtp_rcpt(ths->m_hEtpan, rcpt,
			       MAILSMTP_DSN_NOTIFY_FAILURE|MAILSMTP_DSN_NOTIFY_DELAY,
			       NULL) :
		mailsmtp_rcpt(ths->m_hEtpan, rcpt))) != MAILSMTP_NO_ERROR) {
      mrlog_error("mailsmtp_rcpt: %s: %s\n", rcpt, mailsmtp_strerror(ret));
      goto done_;
    }


  /* message */
  if ((ret = mailsmtp_data(ths->m_hEtpan)) != MAILSMTP_NO_ERROR) {
    fprintf(stderr, "mailsmtp_data: %s\n", mailsmtp_strerror(ret));
    goto done_;
  }
  if ((ret = mailsmtp_data_message(ths->m_hEtpan, data, len)) != MAILSMTP_NO_ERROR) {
    fprintf(stderr, "mailsmtp_data_message: %s\n", mailsmtp_strerror(ret));
    goto done_;
  }



done_:
	if( !success ) {
		mailsmtp_free(ths->m_hEtpan);
	}
	free(smtp_from);
	free(smtp_server);
	free(smtp_user);
	free(smtp_pw);
	return success;
}


void mrsmtp_disconnect(mrsmtp_t* ths)
{
	if( ths->m_hEtpan ) {
		//mailsmtp_quit(ths->m_hEtpan); -- ?
		mailsmtp_free(ths->m_hEtpan);
		ths->m_hEtpan = NULL;
	}
}
