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
 * File:    mrimap.h
 * Authors: Björn Petersen
 * Purpose: Reading from IMAP servers with no dependencies to mrmailbox_t or to
 *          the database.
 *
 ******************************************************************************/


#ifndef __MRIMAP_H__
#define __MRIMAP_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/

typedef struct mrloginparam_t mrloginparam_t;
typedef struct mrimap_t mrimap_t;

#define MR_IMAP_SEEN 0x0001L

typedef int32_t  (*mr_get_config_int_t)(mrimap_t*, const char*, int32_t);
typedef void     (*mr_set_config_int_t)(mrimap_t*, const char*, int32_t);
typedef void     (*mr_receive_imf_t)   (mrimap_t*, const char* imf_raw_not_terminated, size_t imf_raw_bytes, uint32_t flags);


typedef struct mrimap_t
{
	int                   m_connected; /* initally connected and watch thread installed */
	mailimap*             m_hEtpan;    /* normally, if connected, m_hEtpan is also set; however, if a reconnection is required, we may lost this handle */

	pthread_mutex_t       m_critical;

	char*                 m_imap_server;
	int                   m_imap_port;
	char*                 m_imap_user;
	char*                 m_imap_pw;

	pthread_t             m_watch_thread;
	pthread_cond_t        m_watch_cond;
	pthread_mutex_t       m_watch_condmutex;
	int                   m_watch_do_exit;

	struct mailimap_fetch_type* m_fetch_type_uid;
	struct mailimap_fetch_type* m_fetch_type_body;

	mr_get_config_int_t   m_get_config_int;
	mr_set_config_int_t   m_set_config_int;
	mr_receive_imf_t      m_receive_imf;
	void*                 m_userData;
} mrimap_t;


mrimap_t* mrimap_new               (mr_get_config_int_t, mr_set_config_int_t, mr_receive_imf_t, void* userData);
void      mrimap_unref             (mrimap_t*);

int       mrimap_is_connected      (mrimap_t*);
int       mrimap_connect           (mrimap_t*, const mrloginparam_t*);
void      mrimap_disconnect        (mrimap_t*);
int       mrimap_fetch             (mrimap_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRIMAP_H__ */

