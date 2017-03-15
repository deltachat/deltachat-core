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
 * File:    mrloginparam.h
 * Purpose: Handle IMAP/POP3/SMTP parameters
 *
 ******************************************************************************/


#ifndef __MRLOGINPARAM_H__
#define __MRLOGINPARAM_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mrloginparam_t
{
	uint32_t      m_magic;

	/* IMAP/POP3 - all pointers may be NULL if unset, public read */
	char*         m_addr;
	char*         m_mail_server;
	char*         m_mail_user;
	char*         m_mail_pw;
	uint16_t      m_mail_port;

	/* SMTP - all pointers may be NULL if unset, public read */
	char*         m_send_server;
	char*         m_send_user;
	char*         m_send_pw;
	int           m_send_port;

	/* Server options*/
	#define       MR_AUTH_TYPE             0x000000FF
	#define       MR_AUTH_NORMAL                    1
	#define       MR_AUTH_XOAUTH2                   2
	#define       MR_SMTP_STARTTLS         0x00010000
	#define       MR_SMTP_SSL_TLS          0x00020000
	#define       MR_SMTP_NO_ESMPT         0x01000000
	#define       MR_NO_EXTRA_IMAP_UPLOAD  0x02000000
	#define       MR_NO_MOVE_TO_CHATS      0x04000000
	int           m_server_flags;
} mrloginparam_t;


mrloginparam_t* mrloginparam_new      ();
void            mrloginparam_unref    (mrloginparam_t*);
void            mrloginparam_empty    (mrloginparam_t*); /* clears all data and frees its memory. All pointers are NULL after this function is called. */
void            mrloginparam_read__   (mrloginparam_t*, mrsqlite3_t*, const char* prefix);
void            mrloginparam_write__  (const mrloginparam_t*, mrsqlite3_t*, const char* prefix);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRLOGINPARAM_H__ */

