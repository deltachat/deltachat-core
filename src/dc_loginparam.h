/*******************************************************************************
 *
 *                              Delta Chat Core
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
 ******************************************************************************/


#ifndef __DC_LOGINPARAM_H__
#define __DC_LOGINPARAM_H__
#ifdef __cplusplus
extern "C" {
#endif


/**
 * Library-internal.
 */
typedef struct dc_loginparam_t
{
	/**  @privatesection */

	/* IMAP - all pointers may be NULL if unset, public read */
	char*         addr;
	char*         mail_server;
	char*         mail_user;
	char*         mail_pw;
	uint16_t      mail_port;

	/* SMTP - all pointers may be NULL if unset, public read */
	char*         send_server;
	char*         send_user;
	char*         send_pw;
	int           send_port;

	/* Server options as DC_LP_* flags */
	int           server_flags;
} dc_loginparam_t;


dc_loginparam_t* dc_loginparam_new          ();
void             dc_loginparam_unref        (dc_loginparam_t*);
void             dc_loginparam_empty        (dc_loginparam_t*); /* clears all data and frees its memory. All pointers are NULL after this function is called. */
void             dc_loginparam_read         (dc_loginparam_t*, dc_sqlite3_t*, const char* prefix);
void             dc_loginparam_write        (const dc_loginparam_t*, dc_sqlite3_t*, const char* prefix);
char*            dc_loginparam_get_readable (const dc_loginparam_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_LOGINPARAM_H__ */

