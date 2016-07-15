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
 * File:    mrloginparam.h
 * Authors: Björn Petersen
 * Purpose: Handle IMAP parameters, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrloginparam.h"


MrLoginParam::MrLoginParam(MrMailbox* mailbox)
{
	m_mailbox      = mailbox;

	// init pointers (this cannot be done by Clear() as this function checks against NULL pointers)
	m_email      = NULL;

	m_mail_server = NULL;
	m_mail_port   = 0;
	m_mail_user   = NULL;
	m_mail_pw     = NULL;

	m_send_server = NULL;
	m_send_port   = 0;
	m_send_user   = NULL;
	m_send_pw     = NULL;
}


MrLoginParam::~MrLoginParam()
{
	Clear();
}


void MrLoginParam::Clear()
{
	#define FREE_(a) if((a)) { free((a)); (a) = NULL; }

	FREE_(m_email)

	FREE_(m_mail_server)
	m_mail_port = 0;
	FREE_(m_mail_user)
	FREE_(m_mail_pw)

	FREE_(m_send_server)
	m_send_port = 0;
	FREE_(m_send_user)
	FREE_(m_send_pw)
}


void MrLoginParam::ReadFromSql()
{
	Clear();

    m_email       = m_mailbox->GetConfig   ("email",       NULL);

    m_mail_server = m_mailbox->GetConfig   ("mail_server", NULL);
    m_mail_port   = m_mailbox->GetConfigInt("mail_port",   0);
    m_mail_user   = m_mailbox->GetConfig   ("mail_user",   NULL);
    m_mail_pw     = m_mailbox->GetConfig   ("mail_pw",     NULL);

    m_send_server = m_mailbox->GetConfig   ("send_server", NULL);
    m_send_port   = m_mailbox->GetConfigInt("send_port",   0);
    m_send_user   = m_mailbox->GetConfig   ("send_user",   NULL);
    m_send_pw     = m_mailbox->GetConfig   ("send_pw",     NULL);
}


void MrLoginParam::Complete()
{
	if( m_email == NULL ) {
		return; // nothing we can do
	}

	char* adr_server = strstr(m_email, "@");
	if( adr_server == NULL ) {
		return; // no "@" found in address, normally, this should not happen
	}
	adr_server++;

	// set servers, ports etc. for well-known and frequently used services
	if( strcmp(adr_server, "gmail.com")==0
	 || strcmp(adr_server, "googlemail.com")==0 )
	{
		// GOOGLE
		if( m_mail_server == NULL )          { m_mail_server = strdup("imap.gmail.com"); }
		if( m_mail_port == 0 )               { m_mail_port   = 993; } // IMAPS
		if( m_mail_user == NULL )            { m_mail_user = strdup(m_email); }

		if( m_send_server == NULL )          { m_send_server = strdup("smtp.gmail.com"); }
		if( m_send_port == 0 )               { m_send_port   = 465; } // SSMTP - difference between 465 and 587: http://stackoverflow.com/questions/15796530/what-is-the-difference-between-ports-465-and-587
		if( m_send_user == NULL )            { m_send_user   = strdup(m_email); }
		if( m_send_pw == NULL && m_mail_pw ) { m_send_pw     = strdup(m_mail_pw); }
	}

	// generic approach
	if( m_mail_port == 0 )               { m_mail_port = 993; }
	if( m_mail_user == NULL )            { m_mail_user = strdup(m_email); }
	if( m_send_port == 0 )               { m_send_port = 465; }
	if( m_send_user == NULL )            { m_send_user = strdup(m_email); }
	if( m_send_pw == NULL && m_mail_pw ) { m_send_pw   = strdup(m_mail_pw); }
}



