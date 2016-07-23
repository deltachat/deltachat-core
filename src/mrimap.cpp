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
 * Tools
 ******************************************************************************/


static bool Mr_is_error(int imapCode)
{
	if( imapCode == MAILIMAP_NO_ERROR
	 || imapCode == MAILIMAP_NO_ERROR_AUTHENTICATED
	 || imapCode == MAILIMAP_NO_ERROR_NON_AUTHENTICATED )
	{
		return false; // no error - success
	}

	return true; // yes, the code is an error
}


static uint32_t Mr_get_uid(mailimap_msg_att* msg_att) // search the UID in a list of attributes
{
	for( clistiter* cur=clist_begin(msg_att->att_list); cur!=NULL; cur=clist_next(cur) )
	{
		mailimap_msg_att_item* item = (mailimap_msg_att_item*)clist_content(cur);

		if( item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC ) {
			continue;
		}

		if( item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_UID ) {
			continue;
		}

		return item->att_data.att_static->att_data.att_uid;
	}

	return 0;
}


static char* Mr_get_msg_att_msg_content(mailimap_msg_att* msg_att, size_t* p_msg_size) // search content in a list of attributes
{
	for( clistiter* cur=clist_begin(msg_att->att_list); cur!=NULL; cur=clist_next(cur) )
	{
		mailimap_msg_att_item* item = (mailimap_msg_att_item*)clist_content(cur);

		if( item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC ) {
			continue;
		}

		if( item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_BODY_SECTION ) {
			continue;
		}

		*p_msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
		return item->att_data.att_static->att_data.att_body_section->sec_body_part;
	}

	return NULL;
}


/*******************************************************************************
 * Fetching Messages
 ******************************************************************************/


bool MrImap::FetchSingleMsg(MrImapThreadVal& threadval,
							const char* folder, // only needed for statistical/debugging purposes, the correct folder is already selected when this function is called
                            uint32_t flocal_uid)
{
	// we're inside a working thread!
	// the function returns false if the caller should try over fetch message again, else true.
	size_t      msg_len;
	char*       msg_content;
	FILE*       f;
	int         r;
	clist*      fetch_result;

	// call mailimap_uid_fetch() with some options; the result goes to fetch_result
	{
		// create an object defining the set set to fetch
		mailimap_set* set = mailimap_set_new_single(flocal_uid);

		// create an object describing the type of information to be retrieved
		// - we want to retrieve the body -
		mailimap_fetch_type* type = mailimap_fetch_type_new_fetch_att_list_empty();
		{
		 mailimap_section*    section = mailimap_section_new(NULL);
		 mailimap_fetch_att*  att     = mailimap_fetch_att_new_body_peek_section(section);
		 mailimap_fetch_type_new_fetch_att_list_add(type, att);
		}

		r = mailimap_uid_fetch(threadval.m_imap,
			set,            // set of message uid, mailimap_fetch() takes ownership of the object
			type,           // type of information to be retrieved, mailimap_fetch() takes ownership of the object
			&fetch_result); // result as a clist of mailimap_msg_att*
	}

	if( Mr_is_error(r) ) {
		MrLogError("MrImap::FetchSingleMsg(): Could not fetch.");
		return false; // this is an error that should be recovered; the caller should try over later to fetch the message again
	}

	// get message content (fetch_result should be only one message)
	{
		clistiter* cur = clist_begin(fetch_result);
		if( cur == NULL ) {
			MrLogError("MrImap::FetchSingleMsg(): Empty message.");
			return true; // error, however, do not try to fetch the message again
		}

		mailimap_msg_att* msg_att = (mailimap_msg_att*)clist_content(cur);
		msg_content = Mr_get_msg_att_msg_content(msg_att, &msg_len);
		if( msg_content == NULL ) {
			MrLogWarning("MrImap::FetchSingleMsg(): No content found for a message.");
			mailimap_fetch_list_free(fetch_result);
			return true; // error, however, do not try to fetch the message again
		}
	}

	// write the mail for debugging purposes to a directory
	if( m_debugDir )
	{
		char filename[512];
		snprintf(filename, sizeof(filename), "%s/%s-%u.eml", m_debugDir, folder, (unsigned int)flocal_uid);
		f = fopen(filename, "w");
		if( f ) {
			fwrite(msg_content, 1, msg_len, f);
			fclose(f);
		}
	}

	// add to our respository
	m_mailbox->ReceiveImf(msg_content, msg_len);

	mailimap_fetch_list_free(fetch_result);

	return true; // success, message fetched
}


void MrImap::FetchFromSingleFolder(MrImapThreadVal& threadval, const char* folder)
{
	// we're inside a working thread!
	int      r;
	clist*   fetch_result = NULL;
	uint32_t in_first_uid = 0; // the first uid to fetch, if 0, get all
	uint32_t out_largetst_uid = 0;
	int      read_cnt = 0, read_errors = 0;
	char*    config_key = NULL;

	// read the last index used for the given folder
	config_key = sqlite3_mprintf("folder.%s.lastuid", folder);
	if( config_key == NULL ) {
		MrLogError("out of memory.");
		goto FetchFromFolder_Done;
	}

	{
		MrSqlite3Locker locker(m_mailbox->m_sql);
		in_first_uid = m_mailbox->m_sql.GetConfigInt(config_key, 0);
	}

	// select the folder
	r = mailimap_select(threadval.m_imap, folder);
	if( Mr_is_error(r) ) {
		MrLogError("could not select folder.", folder);
		goto FetchFromFolder_Done;
	}

	// call mailimap_fetch() with some options; the result goes to fetch_result
	{
		// create an object describing the type of information to be retrieved, mailimap_fetch() takes ownership of the object
		// - we want to retrieve the uid -
		mailimap_fetch_type* type = mailimap_fetch_type_new_fetch_att_list_empty();
		{
		 mailimap_fetch_att*  att = mailimap_fetch_att_new_uid();
		 mailimap_fetch_type_new_fetch_att_list_add(type, att);
		}

		// do fetch!
		if( in_first_uid )
		{
			// CAVE: We may get mails with uid smaller than the given one; therefore we check the uid below (this is also done in MailCore2, see "if (uid < fromUID) {..}"@IMAPSession::fetchMessageNumberUIDMapping()@MCIMAPSession.cpp)
			r = mailimap_uid_fetch(threadval.m_imap, mailimap_set_new_interval(in_first_uid+1, 0), // fetch by uid
				type, &fetch_result);
		}
		else
		{
			r = mailimap_fetch(threadval.m_imap, mailimap_set_new_interval(1, 0), // fetch by index
				type, &fetch_result);
		}
	}

	if( Mr_is_error(r) || fetch_result == NULL )
	{
		MrLogError("could not fetch");
		goto FetchFromFolder_Done;
	}

	// go through all mails in folder (this is typically _fast_ as we already have the whole list)
	for( clistiter* cur = clist_begin(fetch_result); cur != NULL ; cur = clist_next(cur) )
	{
		mailimap_msg_att* msg_att = (mailimap_msg_att*)clist_content(cur); // mailimap_msg_att is a list of attributes: list is a list of message attributes
		uint32_t cur_uid = Mr_get_uid(msg_att);
		if( cur_uid && (in_first_uid==0 || cur_uid>in_first_uid) )
		{
			if( cur_uid > out_largetst_uid ) {
				out_largetst_uid = cur_uid;
			}

			read_cnt++;
			if( !FetchSingleMsg(threadval, folder, cur_uid) ) {
				read_errors++;
			}
		}
	}

	if( !read_errors && out_largetst_uid > 0 ) {
		MrSqlite3Locker locker(m_mailbox->m_sql);
		m_mailbox->m_sql.SetConfigInt(config_key, out_largetst_uid);
	}

	// done
FetchFromFolder_Done:
    {
		char* temp = sqlite3_mprintf("Read %i mails from %s with %i errors.", read_cnt, folder, read_errors);
		if( temp ) {
			if( read_errors ) {
				MrLogError(temp, NULL);
			}
			else {
				MrLogInfo(temp, NULL);
			}
			sqlite3_free(temp);
		}
    }

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}

	if( config_key ) {
		sqlite3_free(config_key);
	}
}


void MrImap::FetchFromAllFolders(MrImapThreadVal& threadval)
{
	// we're inside a working thread!
	/*int        r;
	clist*     imap_folders = NULL;
	clistiter* cur;

	r = mailimap_list(threadval.m_imap, "", "", &imap_folders); // returns mailimap_mailbox_list
	if( Mr_is_error(r) || imap_folders==NULL ) {
		goto FetchFromAllFolders_Done;
	}

	for( cur = clist_begin(imap_folders); cur != NULL ; cur = clist_next(cur) )
	{
		mailimap_mailbox_list* folder = (mailimap_mailbox_list*)clist_content(cur);
		if( folder )
		{
            printf("%s\n", folder->mb_name);
		}
	}
	*/

	FetchFromSingleFolder(threadval, "INBOX");
	//FetchFromSingleFolder(threadval, "Gesendet");

FetchFromAllFolders_Done:
	;
}


/*******************************************************************************
 * The working thread
 ******************************************************************************/


void MrImap::WorkingThread()
{
	MrImapThreadVal threadval;
	int             r;

	// connect to server
	m_threadState = MR_THREAD_CONNECT;

	threadval.m_imap = mailimap_new(0, NULL);
	r = mailimap_ssl_connect(threadval.m_imap, m_loginParam->m_mail_server, m_loginParam->m_mail_port);
	if( Mr_is_error(r) ) {
		MrLogError("could not connect to server");
		goto WorkingThread_Exit;
	}

	r = mailimap_login(threadval.m_imap, m_loginParam->m_mail_user, m_loginParam->m_mail_pw);
	if( Mr_is_error(r) ) {
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
                FetchFromAllFolders(threadval);
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

	m_debugDir      = NULL;

	pthread_mutex_init(&m_condmutex, NULL);
    pthread_cond_init(&m_cond, NULL);
}


MrImap::~MrImap()
{
	Disconnect();

	pthread_cond_destroy(&m_cond);
	pthread_mutex_destroy(&m_condmutex);

	free(m_debugDir);
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

	// (re-)read debug directory configuration
	{
		MrSqlite3Locker locker(m_mailbox->m_sql);
		free(m_debugDir);
		m_debugDir = m_mailbox->m_sql.GetConfig("debug_dir", NULL);
	}

	// start the working thread
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

