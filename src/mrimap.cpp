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
 * Purpose: Reading from IMAP servers, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <libetpan/libetpan.h>
#include <sys/stat.h>

#include "mrmailbox.h"
#include "mrimap.h"
#include "mrosnative.h"


/*******************************************************************************
 * Fetching Messages
 ******************************************************************************/

static uint32_t get_uid(struct mailimap_msg_att * msg_att)
{
	clistiter * cur;

	/* iterate on each result of one given message */
	for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
		struct mailimap_msg_att_item * item;

		item = (mailimap_msg_att_item*)clist_content(cur);
		if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
			continue;
		}

		if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_UID) {
			continue;
		}

		return item->att_data.att_static->att_data.att_uid;
	}

	return 0;
}

static char * get_msg_att_msg_content(struct mailimap_msg_att * msg_att, size_t * p_msg_size)
{
	clistiter * cur;

  /* iterate on each result of one given message */
	for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
		struct mailimap_msg_att_item * item;

		item = (mailimap_msg_att_item*)clist_content(cur);
		if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
			continue;
		}

    if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
			continue;
    }

		* p_msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
		return item->att_data.att_static->att_data.att_body_section->sec_body_part;
	}

	return NULL;
}

static char * get_msg_content(clist * fetch_result, size_t * p_msg_size)
{
	clistiter * cur;

  /* for each message (there will be probably only on message) */
	for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
		struct mailimap_msg_att * msg_att;
		size_t msg_size;
		char * msg_content;

		msg_att = (mailimap_msg_att*)clist_content(cur);
		msg_content = get_msg_att_msg_content(msg_att, &msg_size);
		if (msg_content == NULL) {
			continue;
		}

		* p_msg_size = msg_size;
		return msg_content;
	}

	return NULL;
}

void MrImap::FetchSingleMsg(MrImapThreadVal& threadval, uint32_t uid)
{
	struct mailimap_set * set;
	struct mailimap_section * section;
	char filename[512];
	size_t msg_len;
	char * msg_content;
	FILE * f;
	struct mailimap_fetch_type * fetch_type;
	struct mailimap_fetch_att * fetch_att;
	int r;
	clist * fetch_result;
	struct stat stat_info;

	snprintf(filename, sizeof(filename), "/home/bpetersen/temp/%u.eml", (unsigned int) uid);
	r = stat(filename, &stat_info);
	if (r == 0) {
		// already cached
		printf("%u is already fetched\n", (unsigned int) uid);
		return;
	}

	set = mailimap_set_new_single(uid);
	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
	section = mailimap_section_new(NULL);
	fetch_att = mailimap_fetch_att_new_body_peek_section(section);
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	r = mailimap_uid_fetch(threadval.m_imap, set, fetch_type, &fetch_result);
	if( IsError(r) ) {
		MrLogError("Could not fetch");
		return;
	}
	printf("fetch %u\n", (unsigned int) uid);

	msg_content = get_msg_content(fetch_result, &msg_len);
	if (msg_content == NULL) {
		fprintf(stderr, "no content\n");
		mailimap_fetch_list_free(fetch_result);
		return;
	}

	f = fopen(filename, "w");
	if (f == NULL) {
		fprintf(stderr, "could not write\n");
		mailimap_fetch_list_free(fetch_result);
		return;
	}

	fwrite(msg_content, 1, msg_len, f);
	fclose(f);

	printf("%u has been fetched\n", (unsigned int) uid);

	mailimap_fetch_list_free(fetch_result);
}


void MrImap::FetchMessages(MrImapThreadVal& threadval)
{
	struct mailimap_set * set;
	struct mailimap_fetch_type * fetch_type;
	struct mailimap_fetch_att * fetch_att;
	clist * fetch_result;
	clistiter * cur;
	int r;

	r = mailimap_select(threadval.m_imap, "INBOX");
	if( IsError(r) ) {
		MrLogError("could not select INBOX.");
		return;
	}

	/* as improvement UIDVALIDITY should be read and the message cache should be cleaned
	   if the UIDVALIDITY is not the same */

	set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */
	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
	fetch_att = mailimap_fetch_att_new_uid();
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	r = mailimap_fetch(threadval.m_imap, set, fetch_type, &fetch_result);
	if( IsError(r) ) {
		MrLogError("could not fetch");
		return;
	}

  /* for each message */
	for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
		struct mailimap_msg_att * msg_att;
		uint32_t uid;

		msg_att = (mailimap_msg_att*)clist_content(cur);
		uid = get_uid(msg_att);
		if (uid == 0)
			continue;

		FetchSingleMsg(threadval, uid);
	}

	mailimap_fetch_list_free(fetch_result);
}

/*******************************************************************************
 * The working thread
 ******************************************************************************/


void MrImap::WorkingThread()
{
	// connect to server
	m_threadState = MR_THREAD_CONNECT;

	MrImapThreadVal threadval;

	int r;
	threadval.m_imap = mailimap_new(0, NULL);
	r = mailimap_ssl_connect(threadval.m_imap, m_loginParam->m_mail_server, m_loginParam->m_mail_port);
	if( IsError(r) ) {
		MrLogError("could not connect to server");
		goto WorkingThread_Exit;
	}

	r = mailimap_login(threadval.m_imap, m_loginParam->m_mail_user, m_loginParam->m_mail_pw);
	if( IsError(r) ) {
		MrLogError("could not login");
		goto WorkingThread_Exit;
	}

	// endless look
	while( 1 )
	{
		// wait for condition
		pthread_mutex_lock(&m_condmutex);
			m_threadState = MR_THREAD_WAIT;
			pthread_cond_wait(&m_cond, &m_condmutex); // wait unlocks the mutex and waits for signal, if it returns, the mutex is locked again
			MrImapThreadCmd cmd = m_threadCmd;
			m_threadState = cmd; // make sure state or cmd blocks eg. Fetch()
			m_threadCmd = MR_THREAD_WAIT;
		pthread_mutex_unlock(&m_condmutex);

		switch( cmd )
		{
			case MR_THREAD_FETCH:
                FetchMessages(threadval);
                break;

			case MR_THREAD_EXIT:
                goto WorkingThread_Exit;

			default:
				break; // bad command
		}

	}

WorkingThread_Exit:
	if( threadval.m_imap ) {
		mailimap_logout(threadval.m_imap);
		mailimap_free(threadval.m_imap);
		threadval.m_imap = NULL;
	}
	m_threadState = MR_THREAD_NOTALLOCATED;
}


void MrImap::StartupHelper(MrImap* imap) // static function
{
	#if defined(__ANDROID) || defined(ANDROID)
		MrAndroidSetupThread();
	#endif

	imap->WorkingThread();

	#if defined(__ANDROID) || defined(ANDROID)
		MrAndroidUnsetupThread();
	#endif
}


/*******************************************************************************
 * Connect/disconnect by start/stop the working thread
 ******************************************************************************/


MrImap::MrImap(MrMailbox* mailbox)
{
	m_mailbox       = mailbox;
	m_threadState   = MR_THREAD_NOTALLOCATED;
	m_threadCmd     = MR_THREAD_WAIT;
	m_loginParam    = NULL;

	pthread_mutex_init(&m_condmutex, NULL);
    pthread_cond_init(&m_cond, NULL);
}


MrImap::~MrImap()
{
	Disconnect();

	pthread_cond_destroy(&m_cond);
	pthread_mutex_destroy(&m_condmutex);
}


bool MrImap::Connect(const MrLoginParam* param)
{
	if( param==NULL || param->m_mail_server==NULL || param->m_mail_user==NULL || param->m_mail_pw==NULL ) {
		MrLogError("MrImap::Connect(): Bad parameter.");
		return false; // error, bad parameters
	}

	if( m_threadState!=MR_THREAD_NOTALLOCATED ) {
		return true; // already trying to connect
	}

	m_loginParam = param;
	m_threadState = MR_THREAD_INIT;
	pthread_create(&m_thread, NULL, (void * (*)(void *)) MrImap::StartupHelper, this);

	// success, so far, the real connection takes place in the working thread
	return true;
}


void MrImap::Disconnect()
{
	if( m_threadState==MR_THREAD_NOTALLOCATED ) {
		return; // already disconnected
	}

	if( m_threadState==MR_THREAD_EXIT || m_threadCmd==MR_THREAD_EXIT ) {
		return; // already exiting/about to exit
	}

	// raise exit signal
	m_threadCmd = MR_THREAD_EXIT;
	pthread_cond_signal(&m_cond);
}


bool MrImap::Fetch()
{
	if( m_threadState==MR_THREAD_NOTALLOCATED ) {
		MrLogError("MrImap::Fetch(): Working thread not ready.");
		return false; // not connected
	}

	if( m_threadState==MR_THREAD_FETCH || m_threadCmd==MR_THREAD_FETCH ) {
		return true; // already fetching/about to fetch
	}

	// raise fetch signal
	m_threadCmd = MR_THREAD_FETCH;
	pthread_cond_signal(&m_cond);

	// signal successfully raised; when and if fetching is started cannot be determinated by the return value
	return true;
}


/*******************************************************************************
 * Tools
 ******************************************************************************/


bool MrImap::IsError(int imapCode)
{
	if( imapCode == MAILIMAP_NO_ERROR
	 || imapCode == MAILIMAP_NO_ERROR_AUTHENTICATED
	 || imapCode == MAILIMAP_NO_ERROR_NON_AUTHENTICATED )
	{
		return false; // no error - success
	}

	return true; // yes, the code is an error
}
