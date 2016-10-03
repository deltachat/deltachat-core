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



mrloginparam_t* mrloginparam_new()
{
	mrloginparam_t* ths = NULL;

	if( (ths=malloc(sizeof(mrloginparam_t)))==NULL ) {
		return NULL; /* error */
	}

	/* init pointers (this cannot be done by mrloginparam_empty() as this function checks against NULL pointers) */
	ths->m_email      = NULL;

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
		return; /* error */
	}

	mrloginparam_empty(ths);
	free(ths);
}


void mrloginparam_empty(mrloginparam_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	#define FREE_(a) if((a)) { free((a)); (a) = NULL; }

	FREE_(ths->m_email)

	FREE_(ths->m_mail_server)
	ths->m_mail_port = 0;
	FREE_(ths->m_mail_user)
	FREE_(ths->m_mail_pw)

	FREE_(ths->m_send_server)
	ths->m_send_port = 0;
	FREE_(ths->m_send_user)
	FREE_(ths->m_send_pw)
}


void mrloginparam_complete(mrloginparam_t* ths)
{
	char* adr_server;

	if( ths == NULL || ths->m_email == NULL ) {
		return; /* nothing we can do */
	}

	adr_server = strstr(ths->m_email, "@");
	if( adr_server == NULL ) {
		return; /* no "@" found in address, normally, this should not happen */
	}
	adr_server++;

	/* set servers, ports etc. for well-known and frequently used services
	TODO: We should add values for gmx.net, web.de etc. */
	if( strcmp(adr_server, "gmail.com")==0
	 || strcmp(adr_server, "googlemail.com")==0 )
	{
		/* Google
		Checking GMail too often (<10 Minutes) may result in blocking, says https://github.com/itprojects/InboxPager/blob/HEAD/README.md#gmail-configuration
		also not https://www.google.com/settings/security/lesssecureapps - is this needed? */
		if( ths->m_mail_server == NULL )               { ths->m_mail_server = safe_strdup("imap.gmail.com"); }
		if( ths->m_mail_port == 0 )                    { ths->m_mail_port   = 993; } /* IMAPS */
		if( ths->m_mail_user == NULL )                 { ths->m_mail_user   = safe_strdup(ths->m_email); }

		if( ths->m_send_server == NULL )               { ths->m_send_server = safe_strdup("smtp.gmail.com"); }
		if( ths->m_send_port == 0 )                    { ths->m_send_port   = 465; } /* SSMTP - difference between 465 and 587: http://stackoverflow.com/questions/15796530/what-is-the-difference-between-ports-465-and-587 */
		if( ths->m_send_user == NULL )                 { ths->m_send_user   = safe_strdup(ths->m_email); }
		if( ths->m_send_pw == NULL && ths->m_mail_pw ) { ths->m_send_pw     = safe_strdup(ths->m_mail_pw); }
	}

	/* generic approach */
	if( ths->m_mail_port == 0 )                    { ths->m_mail_port = 993; }
	if( ths->m_mail_user == NULL )                 { ths->m_mail_user = safe_strdup(ths->m_email); }
	if( ths->m_send_port == 0 )                    { ths->m_send_port = 465; }
	if( ths->m_send_user == NULL )                 { ths->m_send_user = safe_strdup(ths->m_email); }
	if( ths->m_send_pw == NULL && ths->m_mail_pw ) { ths->m_send_pw   = safe_strdup(ths->m_mail_pw); }
}



