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
 * File:    mrimap.c
 * Authors: Björn Petersen
 * Purpose: Reading from IMAP servers, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <libetpan/libetpan.h>
#include <sys/stat.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrimap.h"
#include "mrosnative.h"
#include "mrtools.h"
#include "mrlog.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int Mr_ignore_folder(const char* folder_name)
{
	int ignore_folder = 0;
	char* l = mr_strlower(folder_name);
	if( !l ) {
		goto Mr_is_void_folder_Done;
	}

	if( strcmp(l, "spam") == 0
	 || strcmp(l, "junk") == 0
	 || strcmp(l, "indésirables") == 0 /* fr */

	 || strcmp(l, "trash") == 0
	 || strcmp(l, "deleted") == 0
	 || strcmp(l, "deleted items") == 0
	 || strcmp(l, "papierkorb") == 0   /* de */
	 || strcmp(l, "corbeille") == 0    /* fr */
	 || strcmp(l, "papelera") == 0     /* es */
	 || strcmp(l, "papperskorg") == 0  /* sv */

	 || strcmp(l, "drafts") == 0
	 || strcmp(l, "entwürfe") == 0     /* de */
	 || strcmp(l, "brouillons") == 0   /* fr */
	 || strcmp(l, "borradores") == 0   /* es */
	 || strcmp(l, "utkast") == 0       /* sv */
	  )
	{
		ignore_folder = 1;
	}

Mr_is_void_folder_Done:
	if( l ) {
		free(l);
	}
	return ignore_folder;
}


static int Mr_is_error(int imapCode)
{
	if( imapCode == MAILIMAP_NO_ERROR
	 || imapCode == MAILIMAP_NO_ERROR_AUTHENTICATED
	 || imapCode == MAILIMAP_NO_ERROR_NON_AUTHENTICATED )
	{
		return 0; /* no error - success */
	}

	return 1; /* yes, the code is an error */
}


static uint32_t Mr_get_uid(struct mailimap_msg_att* msg_att) /* search the UID in a list of attributes */
{
	clistiter* cur;

	for( cur=clist_begin(msg_att->att_list); cur!=NULL; cur=clist_next(cur) )
	{
		struct mailimap_msg_att_item* item = (struct mailimap_msg_att_item*)clist_content(cur);

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


static char* Mr_get_msg_att_msg_content(struct mailimap_msg_att* msg_att, size_t* p_msg_size) /* search content in a list of attributes */
{
	clistiter* cur;

	for( cur=clist_begin(msg_att->att_list); cur!=NULL; cur=clist_next(cur) )
	{
		struct mailimap_msg_att_item* item = (struct mailimap_msg_att_item*)clist_content(cur);

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


static int mrimap_fetch_single_msg(mrimap_t* ths, mrimapthreadval_t* threadval,
							  const char* folder, /* only needed for statistical/debugging purposes, the correct folder is already selected when this function is called */
                              uint32_t flocal_uid)
{
	/* we're inside a working thread!
	the function returns 0 if the caller should try over fetch message again, else 1. */
	size_t      msg_len;
	char*       msg_content;
	FILE*       f;
	int         r;
	clist*      fetch_result;

	/* call mailimap_uid_fetch() with some options; the result goes to fetch_result */
	{
		/* create an object defining the set set to fetch */
		struct mailimap_set* set = mailimap_set_new_single(flocal_uid);

		/* create an object describing the type of information to be retrieved
		- we want to retrieve the body - */
		struct mailimap_fetch_type* type = mailimap_fetch_type_new_fetch_att_list_empty();
		{
		 struct mailimap_section*    section = mailimap_section_new(NULL);
		 struct mailimap_fetch_att*  att     = mailimap_fetch_att_new_body_peek_section(section);
		 mailimap_fetch_type_new_fetch_att_list_add(type, att);
		}

		r = mailimap_uid_fetch(threadval->m_imap,
			set,            /* set of message uid, mailimap_fetch() takes ownership of the object */
			type,           /* type of information to be retrieved, mailimap_fetch() takes ownership of the object */
			&fetch_result); /* result as a clist of mailimap_msg_att* */
	}

	if( Mr_is_error(r) ) {
		mr_log_error("mrimap_fetch_single_msg(): Could not fetch.");
		return 0; /* this is an error that should be recovered; the caller should try over later to fetch the message again */
	}

	/* get message content (fetch_result should be only one message) */
	{
		clistiter* cur = clist_begin(fetch_result);
		if( cur == NULL ) {
			mr_log_error("mrimap_fetch_single_msg(): Empty message.");
			return 1; /* error, however, do not try to fetch the message again */
		}

		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur);
		msg_content = Mr_get_msg_att_msg_content(msg_att, &msg_len);
		if( msg_content == NULL ) {
			mr_log_warning("mrimap_fetch_single_msg(): No content found for a message.");
			mailimap_fetch_list_free(fetch_result);
			return 1; /* error, however, do not try to fetch the message again */
		}
	}

	/* write the mail for debugging purposes to a directory */
	if( ths->m_debugDir )
	{
		char filename[512];
		snprintf(filename, sizeof(filename), "%s/%s-%u.eml", ths->m_debugDir, folder, (unsigned int)flocal_uid);
		f = fopen(filename, "w");
		if( f ) {
			fwrite(msg_content, 1, msg_len, f);
			fclose(f);
		}
	}

	/* add to our respository */
	mrmailbox_receive_imf__(ths->m_mailbox, msg_content, msg_len);

	mailimap_fetch_list_free(fetch_result);

	return 1; /* success, message fetched */
}


static void fetch_from_single_folder(mrimap_t* ths, mrimapthreadval_t* threadval, const char* folder)
{
	/* we're inside a working thread! */
	int        r;
	clist*     fetch_result = NULL;
	uint32_t   in_first_uid = 0; /* the first uid to fetch, if 0, get all */
	uint32_t   out_largetst_uid = 0;
	int        read_cnt = 0, read_errors = 0;
	char*      config_key = NULL;
	clistiter* cur;

	/* read the last index used for the given folder */
	config_key = sqlite3_mprintf("folder.%s.lastuid", folder);
	if( config_key == NULL ) {
		mr_log_error("MrImap::FetchFromSingleFolder(): Out of memory.");
		goto FetchFromFolder_Done;
	}

	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE! - do not forge the unlock */

			in_first_uid = mrsqlite3_get_config_int(ths->m_mailbox->m_sql, config_key, 0);

	mrsqlite3_unlock(ths->m_mailbox->m_sql); /* CAVE! - do not forge the unlock */

	/* select the folder */
	r = mailimap_select(threadval->m_imap, folder);
	if( Mr_is_error(r) ) {
		mr_log_error("MrImap::FetchFromSingleFolder(): Could not select folder.");
		goto FetchFromFolder_Done;
	}

	/* call mailimap_fetch() with some options; the result goes to fetch_result */
	{
		/* create an object describing the type of information to be retrieved, mailimap_fetch() takes ownership of the object
		- we want to retrieve the uid - */
		struct mailimap_fetch_type* type = mailimap_fetch_type_new_fetch_att_list_empty();
		{
		 struct mailimap_fetch_att*  att = mailimap_fetch_att_new_uid();
		 mailimap_fetch_type_new_fetch_att_list_add(type, att);
		}

		/* do fetch! */
		if( in_first_uid )
		{
			/* CAVE: We may get mails with uid smaller than the given one; therefore we check the uid below (this is also done in MailCore2, see "if (uid < fromUID) {..}"@IMAPSession::fetchMessageNumberUIDMapping()@MCIMAPSession.cpp) */
			r = mailimap_uid_fetch(threadval->m_imap, mailimap_set_new_interval(in_first_uid+1, 0), /* fetch by uid */
				type, &fetch_result);
		}
		else
		{
			r = mailimap_fetch(threadval->m_imap, mailimap_set_new_interval(1, 0), /* fetch by index */
				type, &fetch_result);
		}
	}

	if( Mr_is_error(r) || fetch_result == NULL )
	{
		if( r == MAILIMAP_ERROR_PROTOCOL ) {
			goto FetchFromFolder_Done; /* the folder is simply empty */
		}
		mr_log_error("MrImap::FetchFromSingleFolder(): Could not fetch");
		goto FetchFromFolder_Done;
	}

	/* go through all mails in folder (this is typically _fast_ as we already have the whole list) */
	for( cur = clist_begin(fetch_result); cur != NULL ; cur = clist_next(cur) )
	{
		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur); /* mailimap_msg_att is a list of attributes: list is a list of message attributes */
		uint32_t cur_uid = Mr_get_uid(msg_att);
		if( cur_uid && (in_first_uid==0 || cur_uid>in_first_uid) )
		{
			if( cur_uid > out_largetst_uid ) {
				out_largetst_uid = cur_uid;
			}

			read_cnt++;
			if( !mrimap_fetch_single_msg(ths, threadval, folder, cur_uid) ) {
				read_errors++;
			}
		}
	}

	if( !read_errors && out_largetst_uid > 0 )
	{
		mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE! - do not forge the unlock */

			mrsqlite3_set_config_int(ths->m_mailbox->m_sql, config_key, out_largetst_uid);

		mrsqlite3_unlock(ths->m_mailbox->m_sql); /* CAVE! - do not forge the unlock */
	}

	/* done */
FetchFromFolder_Done:
    {
		char* temp = sqlite3_mprintf("%i mails read from \"%s\" with %i errors.", read_cnt, folder, read_errors);
		if( read_errors ) {
			mr_log_error(temp);
		}
		else {
			mr_log_info(temp);
		}
		sqlite3_free(temp);
    }

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}

	if( config_key ) {
		sqlite3_free(config_key);
	}
}


static void fetch_from_all_folders(mrimap_t* ths, mrimapthreadval_t*  threadval)
{
	/* we're inside a working thread! */

	/* check INBOX */
	fetch_from_single_folder(ths, threadval, "INBOX");

	/* check other folders */
	int        r;
	clist*     imap_folders = NULL;
	clistiter* cur;

	r = mailimap_list(threadval->m_imap, "", "*", &imap_folders); /* returns mailimap_mailbox_list */
	if( Mr_is_error(r) || imap_folders==NULL ) {
		goto FetchFromAllFolders_Done;
	}

	for( cur = clist_begin(imap_folders); cur != NULL ; cur = clist_next(cur) ) /* contains eg. Gesendet, Archiv, INBOX - uninteresting: Spam, Papierkorb, Entwürfe */
	{
		struct mailimap_mailbox_list* folder = (struct mailimap_mailbox_list*)clist_content(cur);
		if( folder && strcmp(folder->mb_name, "INBOX")!=0 )
		{
			char* name_utf8 = imap_modified_utf7_to_utf8(folder->mb_name, 0);
			if( name_utf8 )
			{
				if( !Mr_ignore_folder(name_utf8) )
				{
					fetch_from_single_folder(ths, threadval, name_utf8);
				}
				else
				{
					char* p = sqlite3_mprintf("Folder \"%s\" ignored.", name_utf8);
					mr_log_info(p);
					sqlite3_free(p);
				}

				free(name_utf8);
			}
		}
	}

FetchFromAllFolders_Done:
	;
}


/*******************************************************************************
 * The working thread
 ******************************************************************************/


static void mrimap_working_thread__(mrimap_t* ths)
{
	mrimapthreadval_t threadval;
	int               r, cmd;

	mr_log_info("Entering working thread.");

	/* connect to server */
	ths->m_threadState = MR_THREAD_CONNECT;

	threadval.m_imap = mailimap_new(0, NULL);
	r = mailimap_ssl_connect(threadval.m_imap, ths->m_loginParam->m_mail_server, ths->m_loginParam->m_mail_port);
	if( Mr_is_error(r) ) {
		mr_log_error("could not connect to server");
		goto WorkingThread_Exit;
	}

	mr_log_info("Successfully connected to server.");

	r = mailimap_login(threadval.m_imap, ths->m_loginParam->m_mail_user, ths->m_loginParam->m_mail_pw);
	if( Mr_is_error(r) ) {
		mr_log_error("could not login");
		goto WorkingThread_Exit;
	}

	mr_log_info("Successfully logged in.");

	/* endless loop */
	while( 1 )
	{
		/* wait for condition */
		pthread_mutex_lock(&ths->m_condmutex);
			ths->m_threadState = MR_THREAD_WAIT;
			pthread_cond_wait(&ths->m_cond, &ths->m_condmutex); /* wait unlocks the mutex and waits for signal, if it returns, the mutex is locked again */
			cmd = ths->m_threadCmd;
			ths->m_threadState = cmd; /* make sure state or cmd blocks eg. Fetch() */
			ths->m_threadCmd = MR_THREAD_WAIT;
		pthread_mutex_unlock(&ths->m_condmutex);

		switch( cmd )
		{
			case MR_THREAD_FETCH:
                fetch_from_all_folders(ths, &threadval);
                break;

			case MR_THREAD_EXIT:
                goto WorkingThread_Exit;

			default:
				break; /* bad command */
		}

	}

WorkingThread_Exit:
	if( threadval.m_imap ) {
		mailimap_logout(threadval.m_imap);
		mailimap_free(threadval.m_imap);
		threadval.m_imap = NULL;
	}
	ths->m_threadState = MR_THREAD_NOTALLOCATED;

	mr_log_info("Exit working thread.");
}


void mrimap_startup_helper(void* param)
{
	mrimap_t* ths = (mrimap_t*)param;

	mrosnative_setup_thread();

		mrimap_working_thread__(ths);

	mrosnative_unsetup_thread();
}


/*******************************************************************************
 * Connect/disconnect by start/stop the working thread
 ******************************************************************************/


mrimap_t* mrimap_new(mrmailbox_t* mailbox)
{
	mrimap_t* ths = NULL;

	if( (ths=malloc(sizeof(mrimap_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_mailbox       = mailbox;
	ths->m_threadState   = MR_THREAD_NOTALLOCATED;
	ths->m_threadCmd     = MR_THREAD_WAIT;
	ths->m_loginParam    = NULL;

	ths->m_debugDir      = NULL;

	pthread_mutex_init(&ths->m_condmutex, NULL);
    pthread_cond_init(&ths->m_cond, NULL);

    return ths;
}


void mrimap_unref(mrimap_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	mrimap_disconnect(ths);

	pthread_cond_destroy(&ths->m_cond);
	pthread_mutex_destroy(&ths->m_condmutex);

	free(ths->m_debugDir);
	free(ths);
}


int mrimap_connect(mrimap_t* ths, const mrloginparam_t* param)
{
	if( ths == NULL || param==NULL || param->m_mail_server==NULL || param->m_mail_user==NULL || param->m_mail_pw==NULL ) {
		mr_log_error("mrimap_connect(): Bad parameter.");
		return 0; /* error, bad parameters */
	}

	if( ths->m_threadState!=MR_THREAD_NOTALLOCATED ) {
		mr_log_info("mrimap_connect(): Already trying to connect.");
		return 1; /* already trying to connect */
	}

	/* (re-)read debug directory configuration */
	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE! - do not forge the unlock */

		free(ths->m_debugDir);
		ths->m_debugDir = mrsqlite3_get_config(ths->m_mailbox->m_sql, "debug_dir", NULL);

	mrsqlite3_unlock(ths->m_mailbox->m_sql); /* /CAVE! - do not forge the unlock */

	/* start the working thread */
	ths->m_loginParam = param;
	ths->m_threadState = MR_THREAD_INIT;
	pthread_create(&ths->m_thread, NULL, (void * (*)(void *))mrimap_startup_helper, ths);

	/* success, so far, the real connection takes place in the working thread */
	return 1;
}


void mrimap_disconnect(mrimap_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_threadState==MR_THREAD_NOTALLOCATED ) {
		return; /* already disconnected */
	}

	if( ths->m_threadState==MR_THREAD_EXIT || ths->m_threadCmd==MR_THREAD_EXIT ) {
		return; /* already exiting/about to exit */
	}

	/* raise exit signal */
	ths->m_threadCmd = MR_THREAD_EXIT;
	pthread_cond_signal(&ths->m_cond);
}


int mrimap_is_connected(mrimap_t* ths)
{
	return (ths->m_threadState!=MR_THREAD_NOTALLOCATED);
}


int mrimap_fetch(mrimap_t* ths)
{
	if( ths == NULL ) {
		return 0; /* error */
	}

	if( ths->m_threadState==MR_THREAD_NOTALLOCATED ) {
		mr_log_error("mrimap_fetch(): Working thread not ready.");
		return 0; /* not connected */
	}

	if( ths->m_threadState==MR_THREAD_FETCH || ths->m_threadCmd==MR_THREAD_FETCH ) {
		return 1; /* already fetching/about to fetch */
	}

	/* raise fetch signal */
	ths->m_threadCmd = MR_THREAD_FETCH;
	pthread_cond_signal(&ths->m_cond);

	/* signal successfully raised; when and if fetching is started cannot be determinated by the return value */
	return 1;
}

