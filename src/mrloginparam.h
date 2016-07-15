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
 * Purpose: Handle IMAP/POP3/SMTP parameters
 *
 ******************************************************************************/


#ifndef __MRLOGINPARAM_H__
#define __MRLOGINPARAM_H__


class MrMailbox;


class MrLoginParam
{
public:
	              MrLoginParam          (MrMailbox* mailbox);
	              ~MrLoginParam         ();

	// clears all data and frees its memory. All pointers are NULL after this function is called.
	void          Clear                 ();

	// read all data from database, unset values are still NULL after calling ReadFromSql()
	void          ReadFromSql           ();

	// tries to set missing parameters from at least m_email and m_mail_pw
	void          Complete              ();

	// IMAP/POP3 - all pointers may be NULL if unset
	char*         m_email;
	char*         m_mail_server;
	char*         m_mail_user;
	char*         m_mail_pw;
	uint16_t      m_mail_port;

	// SMTP - all pointers may be NULL if unset
	char*         m_send_server;
	char*         m_send_user;
	char*         m_send_pw;
	uint16_t      m_send_port;

private:
	MrMailbox*    m_mailbox;
};


#endif // __MRLOGINPARAM_H__

