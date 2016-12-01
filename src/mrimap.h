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
typedef void     (*mr_receive_imf_t)   (mrimap_t*, const char* imf_raw_not_terminated, size_t imf_raw_bytes, const char* server_folder, uint32_t server_uid, uint32_t flags);


typedef struct mrimap_t
{
	char*                 m_imap_server;
	int                   m_imap_port;
	char*                 m_imap_user;
	char*                 m_imap_pw;
	int                   m_server_flags;

	int                   m_connected; /* initally connected and watch thread installed */
	mailimap*             m_hEtpan;    /* normally, if connected, m_hEtpan is also set; however, if a reconnection is required, we may lost this handle */
	pthread_mutex_t       m_hEtpanmutex;
	int                   m_idle_set_up;
	char*                 m_selected_folder;
	int                   m_should_reconnect;
	int                   m_manual_fetch;

	char*                 m_error_descr; /* != NULL, non-empty eg. on connection errors */

	int                   m_can_idle;
	int                   m_has_xlist;
	char*                 m_moveto_folder;/* Folder, where reveived chat messages should go to.  Normally "Chats" but may be NULL to leave them in the INBOX */
	char*                 m_sent_folder;  /* Folder, where send messages should go to.  Normally "Chats". */
	pthread_mutex_t       m_idlemutex;    /* set, if idle is not possible; morover, the interrupted IDLE thread waits a second before IDLEing again; this allows several jobs to be executed */
	pthread_mutex_t       m_inwait_mutex; /* only used to wait for mailstream_wait_idle()/mailimap_idle_done() to terminate. */

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

int       mrimap_connect           (mrimap_t*, const mrloginparam_t*);
void      mrimap_disconnect        (mrimap_t*);
int       mrimap_is_connected      (mrimap_t*);
int       mrimap_fetch             (mrimap_t*);

int       mrimap_append_msg        (mrimap_t*, time_t timestamp, const char* data_not_terminated, size_t data_bytes, char** ret_server_folder, uint32_t* ret_server_uid);
int       mrimap_markseen_msg      (mrimap_t*, const char* folder, uint32_t server_uid, int also_move, char** ret_server_folder, uint32_t* ret_server_uid); /* only returns 0 on connection problems; we should try later again in this case */
int       mrimap_delete_msg        (mrimap_t*, const char* rfc724_mid, const char* folder, uint32_t server_uid); /* only returns 0 on connection problems; we should try later again in this case */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRIMAP_H__ */

