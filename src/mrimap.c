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


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int ignore_folder(const char* folder_name)
{
	int   ignore_folder = 0;
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


static int fetch_single_msg(mrimap_t* ths, const char* folder, uint32_t flocal_uid)
{
	/* the function returns:
	    0  on errors; in this case, the caller should try over again later
	or  1  if the messages should be treated as received (even if no database entries are returned)

	Finally, remember, we're inside a working thread! */
	size_t      msg_len;
	char*       msg_content;
	int         r;
	clist*      fetch_result;

	/* call mailimap_uid_fetch() with some options; the result goes to fetch_result */
	pthread_mutex_lock(&ths->m_critical);
		{
			struct mailimap_set* set = mailimap_set_new_single(flocal_uid);

					r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_body, &fetch_result);

			mailimap_set_free(set);
		}
	pthread_mutex_unlock(&ths->m_critical);

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

	/* let the user handle the message */
	ths->m_receive_imf(ths, msg_content, msg_len, folder, flocal_uid);

	mailimap_fetch_list_free(fetch_result);

	return 1; /* Success, messages fetched. The amount of really created db entries by m_receive_imf() may be 0. */
}


static void fetch_from_single_folder(mrimap_t* ths, const char* folder)
{
	/* we're inside a working thread! */
	int        r;
	clist*     fetch_result = NULL;
	uint32_t   in_first_uid = 0; /* the first uid to fetch, if 0, get all */
	uint32_t   out_largetst_uid = 0;
	size_t     read_cnt = 0, read_errors = 0;
	char*      config_key = NULL;
	clistiter* cur;

	/* read the last index used for the given folder */
	config_key = sqlite3_mprintf("folder.%s.lastuid", folder);
	if( config_key == NULL ) {
		mrlog_error("MrImap::FetchFromSingleFolder(): Out of memory.");
		goto cleanup;
	}

	in_first_uid = ths->m_get_config_int(ths, config_key, 0);

	/* select the folder */
	pthread_mutex_lock(&ths->m_critical);
		r = mailimap_select(ths->m_hEtpan, folder);
	pthread_mutex_unlock(&ths->m_critical);
	if( is_error(r) ) {
		mrlog_error("MrImap::FetchFromSingleFolder(): Could not select folder.");
		goto cleanup;
	}

	/* call mailimap_fetch() with some options; the result goes to fetch_result */
	pthread_mutex_lock(&ths->m_critical);
		if( in_first_uid )
		{
			/* CAVE: We may get mails with uid smaller than the given one; therefore we check the uid below (this is also done in MailCore2, see "if (uid < fromUID) {..}"@IMAPSession::fetchMessageNumberUIDMapping()@MCIMAPSession.cpp) */
			struct mailimap_set* set = mailimap_set_new_interval(in_first_uid+1, 0);
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result); /* fetch by uid */
			mailimap_set_free(set);
		}
		else
		{
			struct mailimap_set* set = mailimap_set_new_interval(1, 0);
				r = mailimap_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result); /* fetch by index - TODO: check if this will fetch _all_ mails in the folder - this is undesired, we should check only say 100 the newest mails - and more if the user scrolls up */
			mailimap_set_free(set);
		}
	pthread_mutex_unlock(&ths->m_critical);

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
			if( cur_uid > out_largetst_uid ) {
				out_largetst_uid = cur_uid;
			}

			read_cnt++;
			if( fetch_single_msg(ths, folder, cur_uid) == 0 ) {
				read_errors++;
			}
		}
	}

	if( !read_errors && out_largetst_uid > 0 )
	{
		ths->m_set_config_int(ths, config_key, out_largetst_uid);
	}

	/* done */
cleanup:
    {
		char* temp = sqlite3_mprintf("%i mails read from \"%s\" with %i errors.", (int)read_cnt, folder, (int)read_errors);
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
}


static void fetch_from_all_folders(mrimap_t* ths)
{
	/* check INBOX */
	fetch_from_single_folder(ths, "INBOX");

	/* check other folders */
	int        r;
	clist*     imap_folders = NULL;
	clistiter* cur;

	mrlog_info("Checking other folders...");

	pthread_mutex_lock(&ths->m_critical);
		r = mailimap_list(ths->m_hEtpan, "", "*", &imap_folders); /* returns mailimap_mailbox_list */
	pthread_mutex_unlock(&ths->m_critical);
	if( is_error(r) || imap_folders==NULL ) {
		mrlog_error("Cannot get folder list.");
		return;
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
					fetch_from_single_folder(ths, name_utf8);
				}
				else
				{
					mrlog_info("Folder \"%s\" ignored.", name_utf8);
				}

				free(name_utf8);
			}
		}
	}
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


static void* watch_thread_entry_point(void* entry_arg)
{
	mrimap_t*       ths = (mrimap_t*)entry_arg;
	struct timespec timeToWait;

	mrlog_info("IMAP-watch-thread started.");
	mrosnative_setup_thread();

	while( 1 )
	{
		mrlog_info("IMAP-watch-thread is checking for messages...");
			fetch_from_all_folders(ths);
		mrlog_info("Done with checking for messages.");

		/* wait 10 seconds for for manual fetch condition */
		if( ths->m_watch_do_exit ) { goto exit_; }
		pthread_mutex_lock(&ths->m_watch_condmutex);
			timeToWait.tv_sec  = time(NULL)+10;
			timeToWait.tv_nsec = 0;
			pthread_cond_timedwait(&ths->m_watch_cond, &ths->m_watch_condmutex, &timeToWait); /* wait unlocks the mutex and waits for signal; if it returns, the mutex is locked again */
		pthread_mutex_unlock(&ths->m_watch_condmutex);
		if( ths->m_watch_do_exit ) { goto exit_; }
	}

exit_:
	mrlog_info("IMAP-watch-thread ended.");
	mrosnative_unsetup_thread();
	return NULL;
}


int mrimap_connect(mrimap_t* ths, const mrloginparam_t* lp)
{
	int success = 0, locked = 0, login_done = 0, r;

	if( ths == NULL || lp==NULL || lp->m_mail_server==NULL || lp->m_mail_user==NULL || lp->m_mail_pw==NULL ) {
		return 0;
	}

	if( pthread_mutex_trylock(&ths->m_critical)!=0 ) {
		mrlog_warning("Cannot connect, IMAP-object blocked by another thread.");
		goto cleanup;
	}
	locked = 1;

		if( ths->m_connected ) {
			mrlog_warning("Already connected to IMAP-server.");
			success = 1;
			goto cleanup;
		}

		free(ths->m_imap_server); ths->m_imap_server  = safe_strdup(lp->m_mail_server);
								  ths->m_imap_port    = lp->m_mail_port;
		free(ths->m_imap_user);   ths->m_imap_user    = safe_strdup(lp->m_mail_user);
		free(ths->m_imap_pw);     ths->m_imap_pw      = safe_strdup(lp->m_mail_pw);

		mrlog_info("Connecting to IMAP-server \"%s:%i\"...", ths->m_imap_server, (int)ths->m_imap_port);
			ths->m_hEtpan = mailimap_new(0, NULL);
			r = mailimap_ssl_connect(ths->m_hEtpan, ths->m_imap_server, ths->m_imap_port);
			if( is_error(r) ) {
				mrlog_error("Could not connect to IMAP-server.");
				goto cleanup;
			}
		mrlog_info("Connection to IMAP-server ok.");

		mrlog_info("Login to IMAP-server as \"%s\"...", ths->m_imap_user);
			r = mailimap_login(ths->m_hEtpan, ths->m_imap_user, ths->m_imap_pw);
			if( is_error(r) ) {
				mrlog_error("Could not login.");
				goto cleanup;
			}
			login_done = 1;
		mrlog_info("Login ok.");

		mrlog_info("Starting IMAP-watch-thread...");
		ths->m_watch_do_exit = 0;
		pthread_create(&ths->m_watch_thread, NULL, watch_thread_entry_point, ths);

		ths->m_connected = 1;
		success = 1;

cleanup:
	if( success == 0 ) {
		if( ths->m_hEtpan ) {
			if( login_done ) {
				mailimap_logout(ths->m_hEtpan);
			}
			mailimap_free(ths->m_hEtpan);
			ths->m_hEtpan = NULL;
		}
		ths->m_connected = 0;
	}

	if( locked ) {
		pthread_mutex_unlock(&ths->m_critical);
	}
	return success;
}


void mrimap_disconnect(mrimap_t* ths)
{
	int   locked = 0;

	if( ths == NULL ) {
		return;
	}

	pthread_mutex_lock(&ths->m_critical); /* no try, wait until we get the object. */
	locked = 1;

			if( !ths->m_connected ) {
				goto cleanup;
			}

	pthread_mutex_unlock(&ths->m_critical);
	locked = 0;

	mrlog_info("Waiting for IMAP-watch-thread to terminate...");
		ths->m_watch_do_exit = 1;
		pthread_cond_signal(&ths->m_watch_cond);
		pthread_join(ths->m_watch_thread, NULL);
	mrlog_info("IMAP-watch-thread terminated.");

	pthread_mutex_lock(&ths->m_critical); /* no try, wait until we get the object. */
	locked = 1;

			mrlog_info("Logout...");
				mailimap_logout(ths->m_hEtpan);
			mrlog_info("Logout done.");

			mrlog_info("Disconnecting...");
				mailimap_free(ths->m_hEtpan);
				ths->m_hEtpan = NULL;
			mrlog_info("Disconnect done.");

			ths->m_connected = 0;

cleanup:
	if( locked ) {
		pthread_mutex_unlock(&ths->m_critical);
	}
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrimap_t* mrimap_new(mr_get_config_int_t get_config_int, mr_set_config_int_t set_config_int, mr_receive_imf_t receive_imf, void* userData)
{
	mrimap_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrimap_t)))==NULL ) {
		exit(25); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_get_config_int = get_config_int;
	ths->m_set_config_int = set_config_int;
	ths->m_receive_imf    = receive_imf;
	ths->m_userData       = userData;

    pthread_mutex_init(&ths->m_critical, NULL);
	pthread_mutex_init(&ths->m_watch_condmutex, NULL);
    pthread_cond_init(&ths->m_watch_cond, NULL);

	/* create some useful objects */
	ths->m_fetch_type_uid = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch the ID */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_uid, mailimap_fetch_att_new_uid());

	ths->m_fetch_type_body = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch the body */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_body,
		mailimap_fetch_att_new_body_peek_section(mailimap_section_new(NULL)));

    return ths;
}


void mrimap_unref(mrimap_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrimap_disconnect(ths);

	pthread_cond_destroy(&ths->m_watch_cond);
	pthread_mutex_destroy(&ths->m_watch_condmutex);
	pthread_mutex_destroy(&ths->m_critical);

	free(ths->m_imap_server);
	free(ths->m_imap_user);
	free(ths->m_imap_pw);

	if( ths->m_fetch_type_uid )  { mailimap_fetch_type_free(ths->m_fetch_type_uid);  }
	if( ths->m_fetch_type_body ) { mailimap_fetch_type_free(ths->m_fetch_type_body); }

	free(ths);
}


int mrimap_is_connected(mrimap_t* ths)
{
	return (ths && ths->m_connected); /* do not check for m_hEtpan, as we may loose this handle during reconnection */
}


int mrimap_fetch(mrimap_t* ths)
{
	if( ths == NULL ) {
		return 0;
	}

	if( !ths->m_connected ) {
		mrlog_error("Cannot fetch, not connected to IMAP-server.");
		return 0;
	}

	pthread_cond_signal(&ths->m_watch_cond);
	return 1;
}




