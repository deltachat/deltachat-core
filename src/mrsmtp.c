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
#include "mrtools.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrsmtp_t* mrsmtp_new(mrmailbox_t* mailbox)
{
	mrsmtp_t* ths;
	if( (ths=calloc(1, sizeof(mrsmtp_t)))==NULL ) {
		exit(29);
	}
	ths->m_mailbox = mailbox;
	return ths;
}


void mrsmtp_unref(mrsmtp_t* ths)
{
	if( ths == NULL ) {
		return;
	}
	mrsmtp_disconnect(ths);
	free(ths->m_from);
	free(ths);
}


/*******************************************************************************
 * Connect/Disconnect
 ******************************************************************************/


int mrsmtp_is_connected (mrsmtp_t* ths)
{
	return ths->m_hEtpan? 1 : 0;
}


static void body_progress(size_t current, size_t maximum, void* user_data)
{
	mrlog_info("body_progress called with current=%i, maximum=%i.", (int)current, (int)maximum);
}


static void logger(mailsmtp* smtp, int log_type, const char* buffer__, size_t size, void* user_data)
{
	char* buffer = malloc(size+1);
	memcpy(buffer, buffer__, size);
	buffer[size] = 0;
	mrlog_info("SMPT: %i: %s", log_type, buffer__);
}


int mrsmtp_connect(mrsmtp_t* ths)
{
	int         success = 0;
	char*       smtp_server = NULL;
	int         smtp_port;
	char*       smtp_user = NULL;
	char*       smtp_pw = NULL;
	int         smtp_esmtp = 1, smtp_ssl = 1, smtp_tls = 0; /* TODO: make additional configurations available */
	int         ret, debug;

	if( ths == NULL ) {
		return 0;
	}

	if( ths->m_hEtpan ) {
		mrlog_warning("Already connected to SMTP server.");
		return 1;
	}

	/* read configuration */
	free(ths->m_from);
	mrsqlite3_lock(ths->m_mailbox->m_sql);
		ths->m_from = mrsqlite3_get_config_    (ths->m_mailbox->m_sql, "configured_addr", NULL);
		smtp_server = mrsqlite3_get_config_    (ths->m_mailbox->m_sql, "configured_send_server", NULL);
		smtp_port   = mrsqlite3_get_config_int_(ths->m_mailbox->m_sql, "configured_send_port", 0);
		smtp_user   = mrsqlite3_get_config_    (ths->m_mailbox->m_sql, "configured_send_user", "");
		smtp_pw     = mrsqlite3_get_config_    (ths->m_mailbox->m_sql, "configured_send_pw", "");
		debug       = mrsqlite3_get_config_int_(ths->m_mailbox->m_sql, "debug", 0);
	mrsqlite3_unlock(ths->m_mailbox->m_sql);
	if( ths->m_from == NULL || smtp_server == NULL || smtp_port == 0 ) {
		goto cleanup;
	}

	ths->m_hEtpan = mailsmtp_new(0, NULL);
	if( ths->m_hEtpan == NULL ) {
		mrlog_error("mailsmtp_new() failed.");
	}
	mailsmtp_set_progress_callback(ths->m_hEtpan, body_progress, ths);
	if( debug ) {
		mailsmtp_set_logger(ths->m_hEtpan, logger, ths);
	}

	/* first open the stream */
	if( smtp_ssl ) {
		/* use SMTP over SSL */
		if( (ret=mailsmtp_ssl_connect(ths->m_hEtpan, smtp_server, smtp_port)) != MAILSMTP_NO_ERROR ) {
			mrlog_error("mailsmtp_ssl_connect: %s\n", mailsmtp_strerror(ret));
			goto cleanup;
		}
	}
	else {
		/* use STARTTLS */
		if( (ret=mailsmtp_socket_connect(ths->m_hEtpan, smtp_server, smtp_port)) != MAILSMTP_NO_ERROR ) {
			mrlog_error("mailsmtp_socket_connect: %s\n", mailsmtp_strerror(ret));
			goto cleanup;
		}
	}

	/* then introduce ourselves */
	ths->m_esmtp = 0;
	if (smtp_esmtp && (ret = mailesmtp_ehlo(ths->m_hEtpan)) == MAILSMTP_NO_ERROR) {
		ths->m_esmtp = 1;
	}
	else if (!smtp_esmtp || ret == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
		ret = mailsmtp_helo(ths->m_hEtpan);
	}

	if (ret != MAILSMTP_NO_ERROR) {
		mrlog_error("mailsmtp_helo: %s\n", mailsmtp_strerror(ret));
		goto cleanup;
	}

	if( ths->m_esmtp && smtp_tls && (ret=mailsmtp_socket_starttls(ths->m_hEtpan)) != MAILSMTP_NO_ERROR ) {
		mrlog_error("mailsmtp_starttls: %s\n", mailsmtp_strerror(ret));
		goto cleanup;
	}

	if (ths->m_esmtp && smtp_tls) {
		/* introduce ourselves again */
		if (smtp_esmtp && (ret = mailesmtp_ehlo(ths->m_hEtpan)) == MAILSMTP_NO_ERROR) {
			ths->m_esmtp = 1;
		}
		else if (!smtp_esmtp || ret == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
			ret = mailsmtp_helo(ths->m_hEtpan);
		}

		if (ret != MAILSMTP_NO_ERROR) {
			mrlog_error("mailsmtp_helo: %s\n", mailsmtp_strerror(ret));
			goto cleanup;
		}
	}

	if (ths->m_esmtp && smtp_user != NULL && (ret = mailsmtp_auth(ths->m_hEtpan, smtp_user, smtp_pw)) != MAILSMTP_NO_ERROR) {
		mrlog_error("mailsmtp_auth: %s: %s\n", smtp_user, mailsmtp_strerror(ret));
		goto cleanup;
	}

	/* cleanup */
	success = 1;

cleanup:
	if( !success ) {
		mailsmtp_free(ths->m_hEtpan);
		ths->m_hEtpan = NULL;
	}
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


/*******************************************************************************
 * Send a message
 ******************************************************************************/


int mrsmtp_send_msg(mrsmtp_t* ths, uint32_t msg_id)
{
	int           success = 0, locked = 0, ret;
	mrmsg_t*      msg = mrmsg_new();
	clist*	      addresses = clist_new();
	clistiter*    l;
	sqlite3_stmt* stmt;

	/* load information from database */
	mrsqlite3_lock(ths->m_mailbox->m_sql);
	locked = 1;
		if( !mrmsg_load_from_db_(msg, ths->m_mailbox, msg_id) ) {
			goto cleanup;
		}
		stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_addr_FROM_contacts_WHERE_chat_id,
			"SELECT c.addr FROM chats_contacts cc LEFT JOIN contacts c ON cc.contact_id=c.id WHERE cc.chat_id=?;");
		sqlite3_bind_int(stmt, 1, msg->m_chat_id);
		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			const char* rcpt = (const char*)sqlite3_column_text(stmt, 0);
			clist_append(addresses, (void*)safe_strdup(rcpt));
		}
	mrsqlite3_unlock(ths->m_mailbox->m_sql);
	locked = 0;

	/* set source */
	if( (ret=(ths->m_esmtp?
			mailesmtp_mail(ths->m_hEtpan, ths->m_from, 1, "etPanSMTPTest") :
	         mailsmtp_mail(ths->m_hEtpan, ths->m_from))) != MAILSMTP_NO_ERROR ) {
		mrlog_error("mailsmtp_mail: %s, %s\n", ths->m_from, mailsmtp_strerror(ret));
		goto cleanup;
	}

	/* set recipients */
	for(l = clist_begin(addresses) ; l != NULL; l = clist_next(l)) {
		const char* rcpt;
		rcpt = clist_content(l);
		if( (ret = (ths->m_esmtp?
				 mailesmtp_rcpt(ths->m_hEtpan, rcpt, MAILSMTP_DSN_NOTIFY_FAILURE|MAILSMTP_DSN_NOTIFY_DELAY, NULL) :
				  mailsmtp_rcpt(ths->m_hEtpan, rcpt))) != MAILSMTP_NO_ERROR) {
			mrlog_error("mailsmtp_rcpt: %s: %s\n", rcpt, mailsmtp_strerror(ret));
			goto cleanup;
		}
	}


	/* message */
	if ((ret = mailsmtp_data(ths->m_hEtpan)) != MAILSMTP_NO_ERROR) {
		fprintf(stderr, "mailsmtp_data: %s\n", mailsmtp_strerror(ret));
		goto cleanup;
	}

	if ((ret = mailsmtp_data_message(ths->m_hEtpan, msg->m_text, strlen(msg->m_text))) != MAILSMTP_NO_ERROR) {
		fprintf(stderr, "mailsmtp_data_message: %s\n", mailsmtp_strerror(ret));
		goto cleanup;
	}

	/* done */
	success = 1;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(ths->m_mailbox->m_sql);
	}
	for(l = clist_begin(addresses) ; l != NULL; l = clist_next(l)) {
		free(clist_content(l));
	}
	clist_free(addresses);
	mrmsg_unref(msg);
	return success;
}

