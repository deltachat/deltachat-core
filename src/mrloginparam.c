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
 * File:    mrloginparam.c
 * Authors: Björn Petersen
 * Purpose: Handle IMAP/POP3/SMTP parameters, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrloginparam.h"
#include "mrtools.h"
#include "mrlog.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrloginparam_t* mrloginparam_new()
{
	mrloginparam_t* ths = NULL;

	if( (ths=malloc(sizeof(mrloginparam_t)))==NULL ) {
		exit(22); /* cannot allocate little memory, unrecoverable error */
	}

	/* init pointers (this cannot be done by mrloginparam_empty() as this function checks against NULL pointers) */
	ths->m_addr        = NULL;

	ths->m_mail_server = NULL;
	ths->m_mail_port   = 0;
	ths->m_mail_user   = NULL;
	ths->m_mail_pw     = NULL;

	ths->m_send_server = NULL;
	ths->m_send_port   = 0;
	ths->m_send_user   = NULL;
	ths->m_send_pw     = NULL;

	return ths;
}


void mrloginparam_unref(mrloginparam_t* ths)
{
	if( ths == NULL ) {
		return; /* ok, but nothing to do */
	}

	mrloginparam_empty(ths);
	free(ths);
}


void mrloginparam_empty(mrloginparam_t* ths)
{
	if( ths == NULL ) {
		return; /* ok, but nothing to do */
	}

	free(ths->m_addr);        ths->m_addr        = NULL;
	free(ths->m_mail_server); ths->m_mail_server = NULL;
	                          ths->m_mail_port   = 0;
	free(ths->m_mail_user);   ths->m_mail_user   = NULL;
	free(ths->m_mail_pw);     ths->m_mail_pw     = NULL;
	free(ths->m_send_server); ths->m_send_server = NULL;
	                          ths->m_send_port   = 0;
	free(ths->m_send_user);   ths->m_send_user   = NULL;
	free(ths->m_send_pw);     ths->m_send_pw     = NULL;
}


void mrloginparam_read_(mrloginparam_t* ths, mrsqlite3_t* sql, const char* prefix)
{
	char* key = NULL;
	#define MR_PREFIX(a) sqlite3_free(key); key=sqlite3_mprintf("%s%s", prefix, (a));

	mrloginparam_empty(ths);

	MR_PREFIX("addr");        ths->m_addr        = mrsqlite3_get_config_    (sql, key, NULL);

	MR_PREFIX("mail_server"); ths->m_mail_server = mrsqlite3_get_config_    (sql, key, NULL);
	MR_PREFIX("mail_port");   ths->m_mail_port   = mrsqlite3_get_config_int_(sql, key, 0);
	MR_PREFIX("mail_user");   ths->m_mail_user   = mrsqlite3_get_config_    (sql, key, NULL);
	MR_PREFIX("mail_pw");     ths->m_mail_pw     = mrsqlite3_get_config_    (sql, key, NULL);

	MR_PREFIX("send_server"); ths->m_send_server = mrsqlite3_get_config_    (sql, key, NULL);
	MR_PREFIX("send_port");   ths->m_send_port   = mrsqlite3_get_config_int_(sql, key, 0);
	MR_PREFIX("send_user");   ths->m_send_user   = mrsqlite3_get_config_    (sql, key, NULL);
	MR_PREFIX("send_pw");     ths->m_send_pw     = mrsqlite3_get_config_    (sql, key, NULL);

	sqlite3_free(key);
}


void mrloginparam_write_(const mrloginparam_t* ths, mrsqlite3_t* sql, const char* prefix)
{
	char* key = NULL;

	MR_PREFIX("addr");         mrsqlite3_set_config_    (sql, key, ths->m_addr);

	MR_PREFIX("mail_server");  mrsqlite3_set_config_    (sql, key, ths->m_mail_server);
	MR_PREFIX("mail_port");    mrsqlite3_set_config_int_(sql, key, ths->m_mail_port);
	MR_PREFIX("mail_user");    mrsqlite3_set_config_    (sql, key, ths->m_mail_user);
	MR_PREFIX("mail_pw");      mrsqlite3_set_config_    (sql, key, ths->m_mail_pw);

	MR_PREFIX("send_server");  mrsqlite3_set_config_    (sql, key, ths->m_send_server);
	MR_PREFIX("send_port");    mrsqlite3_set_config_int_(sql, key, ths->m_send_port);
	MR_PREFIX("send_user");    mrsqlite3_set_config_    (sql, key, ths->m_send_user);
	MR_PREFIX("send_pw");      mrsqlite3_set_config_    (sql, key, ths->m_send_pw);

	sqlite3_free(key);
}


void mrloginparam_complete(mrloginparam_t* ths)
{
	char* adr_server;

	if( ths == NULL || ths->m_addr == NULL ) {
		mrlog_error("Configuration failed, we need at least the email-address.");
		return; /* nothing we can do */
	}

	/* if no password is given, assume an empty password.
	(in general, unset values are NULL, not the empty string, this allows to use eg. empty user names or empty passwords) */
	if( ths->m_mail_pw == NULL ) {
		ths->m_mail_pw = safe_strdup("");
	}

	adr_server = strstr(ths->m_addr, "@");
	if( adr_server == NULL ) {
		mrlog_error("Configuration failed, bad email-address.");
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
	if( strcmp(adr_server, "gmail.com")==0
	 || strcmp(adr_server, "googlemail.com")==0 )
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
		return;
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
}



