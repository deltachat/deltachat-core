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
#include "mrloginparam.h"


#define MR_THREAD_NOTALLOCATED  0
#define MR_THREAD_INIT         10
#define MR_THREAD_CONNECT      20
#define MR_THREAD_WAIT         30
#define MR_THREAD_FETCH        40
#define MR_THREAD_EXIT         50


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int ignore_folder(const char* folder_name)
{
	int ignore_folder = 0;
	char* l = mr_strlower(folder_name);

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

	free(l);
	return ignore_folder;
}


static int is_error(int imapCode)
{
	if( imapCode == MAILIMAP_NO_ERROR
	 || imapCode == MAILIMAP_NO_ERROR_AUTHENTICATED
	 || imapCode == MAILIMAP_NO_ERROR_NON_AUTHENTICATED )
	{
		return 0;
	}

	return 1;
}


static uint32_t get_uid(struct mailimap_msg_att* msg_att) /* search the UID in a list of attributes */
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


static char* get_msg_att_msg_content(struct mailimap_msg_att* msg_att, size_t* p_msg_size) /* search content in a list of attributes */
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


static int fetch_single_msg(mrimap_t* ths, const char* folder, uint32_t flocal_uid, size_t* created_db_entries)
{
	/* the function returns:
	    0  on errors; in this case, the caller should try over again later
	or  1  if the messages should be treated as received (even if no database entries are returned)

	moreover, the function copies the nubmer or really created database entries to ret_created_database_entries.

	Finally, remember, we're inside a working thread! */
	size_t      msg_len;
	char*       msg_content;
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

		r = mailimap_uid_fetch(ths->m_hEtpan,
			set,            /* set of message uid, mailimap_fetch() takes ownership of the object */
			type,           /* type of information to be retrieved, mailimap_fetch() takes ownership of the object */
			&fetch_result); /* result as a clist of mailimap_msg_att* */
	}

	if( is_error(r) ) {
		mrlog_error("mrimap_fetch_single_msg(): Could not fetch.");
		return 0; /* this is an error that should be recovered; the caller should try over later to fetch the message again */
	}

	/* get message content (fetch_result should be only one message) */
	{
		clistiter* cur = clist_begin(fetch_result);
		if( cur == NULL ) {
			mrlog_warning("mrimap_fetch_single_msg(): Empty message.");
			return 1; /* error, however, do not try to fetch the message again */
		}

		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur);
		msg_content = get_msg_att_msg_content(msg_att, &msg_len);
		if( msg_content == NULL ) {
			mrlog_warning("mrimap_fetch_single_msg(): No content found for a message.");
			mailimap_fetch_list_free(fetch_result);
			return 1; /* error, however, do not try to fetch the message again */
		}
	}

	/* add to our respository */
	*created_db_entries = ths->m_cb(ths, MR_EVENT_RECEIVE_IMF_, (uintptr_t)msg_content, msg_len, (uintptr_t)folder, (uintptr_t)flocal_uid);

	mailimap_fetch_list_free(fetch_result);

	return 1; /* Success, messages fetched. However, the amount in created_db_entries may be 0. */
}


static size_t fetch_from_single_folder(mrimap_t* ths, const char* folder)
{
	/* we're inside a working thread! */
	int        r;
	clist*     fetch_result = NULL;
	uint32_t   in_first_uid = 0; /* the first uid to fetch, if 0, get all */
	uint32_t   out_largetst_uid = 0;
	size_t     read_cnt = 0, read_errors = 0, created_db_entries = 0;
	char*      config_key = NULL;
	clistiter* cur;

	/* read the last index used for the given folder */
	config_key = sqlite3_mprintf("folder.%s.lastuid", folder);
	if( config_key == NULL ) {
		mrlog_error("MrImap::FetchFromSingleFolder(): Out of memory.");
		goto cleanup;
	}

	in_first_uid = (uint32_t)ths->m_cb(ths, MR_EVENT_GET_CONFIG_INT_, (uintptr_t)config_key, 0, 0, 0);


	/* select the folder */
	r = mailimap_select(ths->m_hEtpan, folder);
	if( is_error(r) ) {
		mrlog_error("MrImap::FetchFromSingleFolder(): Could not select folder.");
		goto cleanup;
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
			r = mailimap_uid_fetch(ths->m_hEtpan, mailimap_set_new_interval(in_first_uid+1, 0), /* fetch by uid */
				type, &fetch_result);
		}
		else
		{
			r = mailimap_fetch(ths->m_hEtpan, mailimap_set_new_interval(1, 0), /* fetch by index - TODO: check if this will fetch _all_ mails in the folder - this is undesired, we should check only say 100 the newest mails - and more if the user scrolls up */
				type, &fetch_result);
		}
	}

	if( is_error(r) || fetch_result == NULL )
	{
		if( r == MAILIMAP_ERROR_PROTOCOL ) {
			goto cleanup; /* the folder is simply empty */
		}
		mrlog_error("MrImap::FetchFromSingleFolder(): Could not fetch");
		goto cleanup;
	}

	/* go through all mails in folder (this is typically _fast_ as we already have the whole list) */
	for( cur = clist_begin(fetch_result); cur != NULL ; cur = clist_next(cur) )
	{
		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur); /* mailimap_msg_att is a list of attributes: list is a list of message attributes */
		uint32_t cur_uid = get_uid(msg_att);
		if( cur_uid && (in_first_uid==0 || cur_uid>in_first_uid) )
		{
			size_t temp_created_db_entries = 0;

			if( cur_uid > out_largetst_uid ) {
				out_largetst_uid = cur_uid;
			}

			read_cnt++;
			if( fetch_single_msg(ths, folder, cur_uid, &temp_created_db_entries) == 0 ) {
				read_errors++;
			}
			else {
				created_db_entries += temp_created_db_entries; /* may be 0 eg. for empty messages. This is NO error. */
			}
		}
	}

	if( !read_errors && out_largetst_uid > 0 )
	{
		ths->m_cb(ths, MR_EVENT_SET_CONFIG_INT_, (uintptr_t)config_key, out_largetst_uid, 0, 0);
	}

	/* done */
cleanup:
    {
		char* temp = sqlite3_mprintf("%i mails read from \"%s\" with %i errors; %i messages created.", (int)read_cnt, folder, (int)read_errors, (int)created_db_entries);
		if( read_errors ) {
			mrlog_error(temp);
		}
		else {
			mrlog_info(temp);
		}
		sqlite3_free(temp);
    }

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}

	if( config_key ) {
		sqlite3_free(config_key);
	}

	return created_db_entries;
}


static size_t fetch_from_all_folders(mrimap_t* ths)
{
	/* we're inside a working thread! */
	size_t created_db_entries = 0;

	/* check INBOX */
	created_db_entries += fetch_from_single_folder(ths, "INBOX");

	/* check other folders */
	int        r;
	clist*     imap_folders = NULL;
	clistiter* cur;

	mrlog_info("Checking other folders...");

	r = mailimap_list(ths->m_hEtpan, "", "*", &imap_folders); /* returns mailimap_mailbox_list */
	if( is_error(r) || imap_folders==NULL ) {
		mrlog_error("Cannot get folder list.");
		goto cleanup;
	}

	for( cur = clist_begin(imap_folders); cur != NULL ; cur = clist_next(cur) ) /* contains eg. Gesendet, Archiv, INBOX - uninteresting: Spam, Papierkorb, Entwürfe */
	{
		struct mailimap_mailbox_list* folder = (struct mailimap_mailbox_list*)clist_content(cur);
		if( folder && strcmp(folder->mb_name, "INBOX")!=0 )
		{
			char* name_utf8 = imap_modified_utf7_to_utf8(folder->mb_name, 0);
			if( name_utf8 )
			{
				if( !ignore_folder(name_utf8) )
				{
					created_db_entries += fetch_from_single_folder(ths, name_utf8);
				}
				else
				{
					mrlog_info("Folder \"%s\" ignored.", name_utf8);
				}

				free(name_utf8);
			}
		}
	}

cleanup:
	return created_db_entries;
}


/*******************************************************************************
 * The working thread
 ******************************************************************************/


static void imap_thread_entry_point(void* entry_arg)
{
	mrimap_t* ths = (mrimap_t*)entry_arg;
	int       r, cmd, login_done = 0;

	/* init thread */
	mrlog_info("Working thread entered.");
	mrosnative_setup_thread();

	ths->m_threadState = MR_THREAD_CONNECT;

	mrlog_info("Connecting to IMAP-server \"%s:%i\"...", ths->m_imap_server, (int)ths->m_imap_port);
		ths->m_hEtpan = mailimap_new(0, NULL);
		r = mailimap_ssl_connect(ths->m_hEtpan, ths->m_imap_server, ths->m_imap_port);
		if( is_error(r) ) {
			mrlog_error("Could not connect to IMAP-server.");
			goto exit_;
		}
	mrlog_info("Connection to IMAP-server ok.");

	mrlog_info("Login to IMAP-server as \"%s\"...", ths->m_imap_user);
		r = mailimap_login(ths->m_hEtpan, ths->m_imap_user, ths->m_imap_pw);
		if( is_error(r) ) {
			mrlog_error("Could not login.");
			goto exit_;
		}
		login_done = 1;
	mrlog_info("Login ok.");

	while( 1 )
	{
		/* wait for condition */
		pthread_mutex_lock(&ths->m_condmutex);
			ths->m_threadState = MR_THREAD_WAIT;
			pthread_cond_wait(&ths->m_cond, &ths->m_condmutex); /* wait unlocks the mutex and waits for signal; if it returns, the mutex is locked again */
			cmd = ths->m_threadCmd;
			ths->m_threadState = cmd; /* make sure state or cmd blocks eg. Fetch() */
			ths->m_threadCmd = MR_THREAD_WAIT;
		pthread_mutex_unlock(&ths->m_condmutex);

		switch( cmd )
		{
			case MR_THREAD_FETCH:
				mrlog_info("Received MR_THREAD_FETCH signal.");
				if( fetch_from_all_folders(ths) > 0 ) {
					ths->m_cb(ths, MR_EVENT_MSGS_UPDATED, 0, 0, 0, 0);
				}
				break;

			case MR_THREAD_EXIT:
				mrlog_info("Received MR_THREAD_EXIT signal.");
				goto exit_;

			default:
				break;
		}
	}

	/* exit thread */
exit_:
	if( ths->m_hEtpan ) {

		if( login_done ) {
			mrlog_info("Logout...");

			mailimap_logout(ths->m_hEtpan);

			mrlog_info("Logout done.");
		}

		mrlog_info("Disconnecting...");

		mailimap_free(ths->m_hEtpan);
		ths->m_hEtpan = NULL;

		mrlog_info("Disconnect done.");
	}
	ths->m_threadState = MR_THREAD_NOTALLOCATED;

	mrlog_info("Exit working thread.");
	mrosnative_unsetup_thread();
}


/*******************************************************************************
 * Connect/disconnect by start/stop the working thread
 ******************************************************************************/


mrimap_t* mrimap_new(mrimapcb_t cb, void* userData)
{
	mrimap_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrimap_t)))==NULL ) {
		exit(25); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_cb            = cb;
	ths->m_userData      = userData;
	ths->m_threadState   = MR_THREAD_NOTALLOCATED;
	ths->m_threadCmd     = MR_THREAD_WAIT;

	pthread_mutex_init(&ths->m_condmutex, NULL);
    pthread_cond_init(&ths->m_cond, NULL);

    return ths;
}


void mrimap_unref(mrimap_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrimap_disconnect(ths);

	pthread_cond_destroy(&ths->m_cond);
	pthread_mutex_destroy(&ths->m_condmutex);

	free(ths->m_imap_server);
	free(ths->m_imap_user);
	free(ths->m_imap_pw);
	free(ths);
}


int mrimap_connect(mrimap_t* ths, const mrloginparam_t* lp)
{
	if( ths == NULL || lp==NULL || lp->m_mail_server==NULL || lp->m_mail_user==NULL || lp->m_mail_pw==NULL ) {
		mrlog_error("mrimap_connect(): Bad parameter.");
		return 0;
	}

	if( ths->m_threadState!=MR_THREAD_NOTALLOCATED ) {
		mrlog_info("mrimap_connect(): Already trying to connect.");
		return 1; /* already trying to connect */
	}

	/* start the working thread */
	free(ths->m_imap_server); ths->m_imap_server  = safe_strdup(lp->m_mail_server);
							  ths->m_imap_port    = lp->m_mail_port;
	free(ths->m_imap_user);   ths->m_imap_user    = safe_strdup(lp->m_mail_user);
	free(ths->m_imap_pw);     ths->m_imap_pw      = safe_strdup(lp->m_mail_pw);

	ths->m_threadState = MR_THREAD_INIT;
	pthread_create(&ths->m_thread, NULL, (void * (*)(void *))imap_thread_entry_point, ths);

	/* success, so far, the real connection takes place in the working thread */
	return 1;
}


void mrimap_disconnect(mrimap_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	if( ths->m_threadState==MR_THREAD_NOTALLOCATED ) {
		return; /* already disconnected */
	}

	if( ths->m_threadState==MR_THREAD_EXIT || ths->m_threadCmd==MR_THREAD_EXIT ) {
		return; /* already exiting/about to exit */
	}

	/* raise exit signal */
	mrlog_info("Raise MR_THREAD_EXIT signal...");
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
		return 0;
	}

	if( ths->m_threadState==MR_THREAD_NOTALLOCATED ) {
		mrlog_error("Cannot fetch now, working thread not ready.");
		return 0; /* not connected */
	}

	if( ths->m_threadState==MR_THREAD_FETCH || ths->m_threadCmd==MR_THREAD_FETCH ) {
		mrlog_info("Already fetching.");
		return 1; /* already fetching/about to fetch */
	}

	/* raise fetch signal */
	mrlog_info("Raise MR_THREAD_FETCH signal...");
	ths->m_threadCmd = MR_THREAD_FETCH;
	pthread_cond_signal(&ths->m_cond);

	/* signal successfully raised; when and if fetching is started cannot be determinated by the return value */
	return 1;
}

