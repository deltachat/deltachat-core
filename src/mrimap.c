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
#include <unistd.h> /* for sleep() */
#include "mrmailbox.h"
#include "mrimap.h"
#include "mrosnative.h"
#include "mrtools.h"
#include "mrlog.h"
#include "mrloginparam.h"

#define LOCK_HANDLE   pthread_mutex_lock(&ths->m_hEtpanmutex); handle_locked = 1;
#define UNLOCK_HANDLE if( handle_locked ) { pthread_mutex_unlock(&ths->m_hEtpanmutex); handle_locked = 0; }

#define BLOCK_IDLE   pthread_mutex_lock(&ths->m_idlemutex); idle_blocked = 1;
#define UNBLOCK_IDLE if( idle_blocked ) { pthread_mutex_unlock(&ths->m_idlemutex); idle_blocked = 0; }

#define INTERRUPT_IDLE  if( ths->m_can_idle && ths->m_hEtpan->imap_stream ) { \
			mailstream_interrupt_idle(ths->m_hEtpan->imap_stream); /* make sure, mailimap_idle_done() is called - otherwise the other routines do not work */ \
			pthread_mutex_lock(&ths->m_inwait_mutex); \
			pthread_mutex_unlock(&ths->m_inwait_mutex); \
		}

static int  setup_handle_if_needed__ (mrimap_t*);
static void unsetup_handle__         (mrimap_t*);


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int is_error(mrimap_t* ths, int code)
{
	if( code == MAILIMAP_NO_ERROR
	 || code == MAILIMAP_NO_ERROR_AUTHENTICATED
	 || code == MAILIMAP_NO_ERROR_NON_AUTHENTICATED )
	{
		return 0;
	}

	if( code == MAILIMAP_ERROR_STREAM
	 || code == MAILIMAP_ERROR_PARSE )
	{
		mrlog_info("IMAP stream lost; we'll reconnect soon.");
		ths->m_should_reconnect = 1;
	}

	return 1;
}


/*******************************************************************************
 * Handle folders
 ******************************************************************************/


static int get_folder_meaning(const mrimap_t* ths, struct mailimap_mbx_list_flags* flags, const char* folder_name, bool force_fallback)
{
	#define MEANING_NORMAL       1
	#define MEANING_INBOX        2
	#define MEANING_IGNORE       3
	#define MEANING_SENT_OBJECTS 4

	char* lower = NULL;
	int   ret_meaning = MEANING_NORMAL;

	if( !force_fallback && (ths->m_has_xlist || flags != NULL) )
	{
		/* We check for flags if we get some (LIST may also return some, see https://tools.ietf.org/html/rfc6154 )
		or if m_has_xlist is set.  However, we also allow a NULL-pointer for "no flags" if m_has_xlist is true. */
		if( flags && flags->mbf_oflags )
		{
			clistiter* iter2;
			for( iter2=clist_begin(flags->mbf_oflags); iter2!=NULL; iter2=clist_next(iter2) )
			{
				struct mailimap_mbx_list_oflag* oflag = (struct mailimap_mbx_list_oflag*)clist_content(iter2);
				switch( oflag->of_type )
				{
					case MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT:
						if( strcasecmp(oflag->of_flag_ext, "spam")==0
						 || strcasecmp(oflag->of_flag_ext, "trash")==0
						 || strcasecmp(oflag->of_flag_ext, "drafts")==0
						 || strcasecmp(oflag->of_flag_ext, "junk")==0 )
						{
							ret_meaning = MEANING_IGNORE;
						}
						else if( strcasecmp(oflag->of_flag_ext, "sent")==0 )
						{
							ret_meaning = MEANING_SENT_OBJECTS;
						}
						else if( strcasecmp(oflag->of_flag_ext, "inbox")==0 )
						{
							ret_meaning = MEANING_INBOX;
						}
						break;
				}
			}
		}
	}
	else
	{
		/* we have no flag list; try some known default names */
		lower = mr_strlower(folder_name);
		if( strcmp(lower, "spam") == 0
		 || strcmp(lower, "junk") == 0
		 || strcmp(lower, "indésirables") == 0 /* fr */

		 || strcmp(lower, "trash") == 0
		 || strcmp(lower, "deleted") == 0
		 || strcmp(lower, "deleted items") == 0
		 || strcmp(lower, "papierkorb") == 0   /* de */
		 || strcmp(lower, "corbeille") == 0    /* fr */
		 || strcmp(lower, "papelera") == 0     /* es */
		 || strcmp(lower, "papperskorg") == 0  /* sv */

		 || strcmp(lower, "drafts") == 0
		 || strcmp(lower, "entwürfe") == 0     /* de */
		 || strcmp(lower, "brouillons") == 0   /* fr */
		 || strcmp(lower, "borradores") == 0   /* es */
		 || strcmp(lower, "utkast") == 0       /* sv */
		  )
		{
			ret_meaning = MEANING_IGNORE;
		}
		else if( strcmp(lower, "inbox") == 0 ) /* the "INBOX" foldername is IMAP-standard, AFAIK */
		{
			ret_meaning = MEANING_INBOX;
		}
		else if( strcmp(lower, "sent")==0 || strcmp(lower, "sent objects")==0 || strcmp(lower, "gesendet")==0 )
		{
			ret_meaning = MEANING_SENT_OBJECTS;
		}
	}

	free(lower);
	return ret_meaning;
}


typedef struct mrimapfolder_t
{
	char* m_name_to_select;
	char* m_name_utf8;
	int   m_meaning;
} mrimapfolder_t;


static clist* list_folders__(mrimap_t* ths)
{
	clist*     imap_list = NULL;
	clistiter* iter1;
	clist *    ret_list = clist_new();
	int        r, xlist_works = 0;

	/* the "*" not only gives us the folders from the main directory, but also all subdirectories; so the resulting foldernames may contain
	delimiters as "folder/subdir/subsubdir" etc.  However, as we do not really use folders, this is just fine (otherwise we'd implement this
	functinon recursively. */
	if( ths->m_has_xlist )  {
		r = mailimap_xlist(ths->m_hEtpan, "", "*", &imap_list);
	}
	else {
		r = mailimap_list(ths->m_hEtpan, "", "*", &imap_list);
	}
	if( is_error(ths, r) ) {
		mrlog_error("Cannot get folder list.");
		goto cleanup;
	}

	for( iter1 = clist_begin(imap_list); iter1 != NULL ; iter1 = clist_next(iter1) )
	{
		struct mailimap_mailbox_list* imap_folder = (struct mailimap_mailbox_list*)clist_content(iter1);
		mrimapfolder_t* ret_folder = calloc(1, sizeof(mrimapfolder_t));
		ret_folder->m_name_to_select = safe_strdup(imap_folder->mb_name);
		ret_folder->m_name_utf8      = imap_modified_utf7_to_utf8(imap_folder->mb_name, 0);
		ret_folder->m_meaning        = get_folder_meaning(ths, imap_folder->mb_flag, ret_folder->m_name_utf8, false);
		if( ret_folder->m_meaning != MEANING_NORMAL ) {
			xlist_works = 1;
		}
		clist_append(ret_list, (void*)ret_folder);
	}

	/* at least my own server claims that it support XLIST but does not return folder flags. So, if we did not get a single
	flag, fall back to the default behaviour */
	if( !xlist_works ) {
		for( iter1 = clist_begin(ret_list); iter1 != NULL ; iter1 = clist_next(iter1) )
		{
			mrimapfolder_t* ret_folder = (struct mrimapfolder_t*)clist_content(iter1);
			ret_folder->m_meaning = get_folder_meaning(ths, NULL, ret_folder->m_name_utf8, true);
		}
	}

cleanup:
	if( imap_list ) {
		mailimap_list_result_free(imap_list);
	}
	return ret_list;
}


static void free_folders__(clist* folders)
{
	if( folders ) {
		clistiter* iter1;
		for( iter1 = clist_begin(folders); iter1 != NULL ; iter1 = clist_next(iter1) ) {
			mrimapfolder_t* ret_folder = (struct mrimapfolder_t*)clist_content(iter1);
			free(ret_folder->m_name_to_select);
			free(ret_folder->m_name_utf8);
			free(ret_folder);
		}
		clist_free(folders);
	}
}


static int init_chat_folders__(mrimap_t* ths)
{
	int        success = 0;
	clist*     folder_list = NULL;
	clistiter* iter1;
	char       *normal_folder = NULL, *sent_folder = NULL, *chats_folder = NULL;

	if( ths->m_sent_folder && ths->m_sent_folder[0] ) {
		success = 1;
		goto cleanup;
	}

	free(ths->m_sent_folder);
	ths->m_sent_folder = NULL;

	free(ths->m_moveto_folder);
	ths->m_moveto_folder = NULL;

	folder_list = list_folders__(ths);
	for( iter1 = clist_begin(folder_list); iter1 != NULL ; iter1 = clist_next(iter1) ) {
		mrimapfolder_t* folder = (struct mrimapfolder_t*)clist_content(iter1);
		if( strcmp(folder->m_name_utf8, MR_CHATS_FOLDER)==0 ) {
			chats_folder = safe_strdup(folder->m_name_to_select);
			break;
		}
		else if( folder->m_meaning == MEANING_SENT_OBJECTS ) {
			sent_folder = safe_strdup(folder->m_name_to_select);
		}
		else if( folder->m_meaning == MEANING_NORMAL && normal_folder == NULL ) {
			normal_folder = safe_strdup(folder->m_name_to_select);
		}
	}

	if( chats_folder == NULL ) {
		mrlog_info("Creating IMAP-folder \"%s\"...", MR_CHATS_FOLDER);
		int r = mailimap_create(ths->m_hEtpan, MR_CHATS_FOLDER);
		if( is_error(ths, r) ) {
			/* continue on errors, we'll just use a different folder then */
			mrlog_error("Cannot create IMAP-folder, using default.");
		}
		else {
			chats_folder = safe_strdup(MR_CHATS_FOLDER);
			mrlog_info("IMAP-folder created.");
		}
	}

	if( chats_folder ) {
		ths->m_moveto_folder = safe_strdup(chats_folder);
		ths->m_sent_folder   = safe_strdup(chats_folder);
		success = 1;
	}
	else if( sent_folder ) {
		ths->m_sent_folder = safe_strdup(sent_folder);
		success = 1;
	}
	else if( normal_folder ) {
		ths->m_sent_folder = safe_strdup(normal_folder);
		success = 1;
	}

cleanup:
	free_folders__(folder_list);
	free(chats_folder);
	free(sent_folder);
	free(normal_folder);
	return success;
}


static int select_folder__(mrimap_t* ths, const char* folder)
{
	if( strcmp(ths->m_selected_folder, folder)==0 ) {
		return 1;
	}

	int r = mailimap_select(ths->m_hEtpan, folder);
	if( is_error(ths, r) || ths->m_hEtpan->imap_selection_info == NULL ) {
		ths->m_selected_folder[0] = 0;
		return 0;
	}
	else {
		free(ths->m_selected_folder);
		ths->m_selected_folder = safe_strdup(folder);
		return 1;
	}
}


/*******************************************************************************
 * Fetch Messages
 ******************************************************************************/


static uint32_t peek_uid(struct mailimap_msg_att* msg_att)
{
	/* search the UID in a list of attributes returned by a FETCH command */
	clistiter* iter1;
	for( iter1=clist_begin(msg_att->att_list); iter1!=NULL; iter1=clist_next(iter1) )
	{
		struct mailimap_msg_att_item* item = (struct mailimap_msg_att_item*)clist_content(iter1);
		if( item )
		{
			if( item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC )
			{
				if( item->att_data.att_static->att_type == MAILIMAP_MSG_ATT_UID )
				{
					return item->att_data.att_static->att_data.att_uid;
				}
			}
		}
	}

	return 0;
}


static void peek_body(struct mailimap_msg_att* msg_att, char** p_msg, size_t* p_msg_bytes, uint32_t* flags, int* deleted)
{
	/* search body & Co. in a list of attributes returned by a FETCH command */
	clistiter *iter1, *iter2;
	for( iter1=clist_begin(msg_att->att_list); iter1!=NULL; iter1=clist_next(iter1) )
	{
		struct mailimap_msg_att_item* item = (struct mailimap_msg_att_item*)clist_content(iter1);
		if( item )
		{
			if( item->att_type == MAILIMAP_MSG_ATT_ITEM_DYNAMIC )
			{
				if( item->att_data.att_dyn->att_list /*I've seen NULL here ...*/ )
				{
					for( iter2=clist_begin(item->att_data.att_dyn->att_list); iter2!=NULL ; iter2=clist_next(iter2))
					{
						struct mailimap_flag_fetch* flag_fetch =(struct mailimap_flag_fetch*) clist_content(iter2);
						if( flag_fetch && flag_fetch->fl_type==MAILIMAP_FLAG_FETCH_OTHER )
						{
							struct mailimap_flag* flag = flag_fetch->fl_flag;
							if( flag )
							{
								if( flag->fl_type == MAILIMAP_FLAG_SEEN ) {
									*flags |= MR_IMAP_SEEN;
								}
								else if( flag->fl_type == MAILIMAP_FLAG_DELETED ) {
									*deleted = 1;
								}
							}
						}
					}
				}
			}
			else if( item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC )
			{
				if( item->att_data.att_static->att_type == MAILIMAP_MSG_ATT_BODY_SECTION )
				{
					*p_msg = item->att_data.att_static->att_data.att_body_section->sec_body_part;
					*p_msg_bytes = item->att_data.att_static->att_data.att_body_section->sec_length;
				}
			}
		}
	}
}


static int fetch_single_msg(mrimap_t* ths, const char* folder, uint32_t server_uid)
{
	/* the function returns:
	    0  the caller should try over again later
	or  1  if the messages should be treated as received, the caller should not try to read the message again (even if no database entries are returned) */
	char*       msg_content;
	size_t      msg_bytes;
	int         r, retry_later = 0, deleted = 0, handle_locked = 0;
	uint32_t    flags = 0;
	clist*      fetch_result = NULL;
	clistiter*  cur;

	LOCK_HANDLE

		{
			struct mailimap_set* set = mailimap_set_new_single(server_uid);
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_body, &fetch_result);
			mailimap_set_free(set);
		}

	UNLOCK_HANDLE

	if( is_error(ths, r) ) {
		mrlog_error("Problem on fetching message #%i from folder \"%s\".  Try again later.", (int)server_uid, folder);
		retry_later = 1;
		goto cleanup; /* this is an error that should be recovered; the caller should try over later to fetch the message again (if there is no such message, we simply get an empty result) */
	}

	if( (cur=clist_begin(fetch_result)) == NULL ) {
		mrlog_warning("Message #%i does not exist in folder \"%s\".", (int)server_uid, folder);
		goto cleanup; /* server response is fine, however, there is no such message, do not try to fetch the message again */
	}

	struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur);
	peek_body(msg_att, &msg_content, &msg_bytes, &flags, &deleted);
	if( msg_content == NULL  || msg_bytes <= 0 || deleted ) {
		/* mrlog_warning("Message #%i in folder \"%s\" is empty or deleted.", (int)server_uid, folder); -- this is a quite usual situation, do not print a warning */
		goto cleanup;
	}

	ths->m_receive_imf(ths, msg_content, msg_bytes, folder, server_uid, flags);

cleanup:
	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}
	return retry_later? 0 : 1;
}


static int fetch_from_single_folder(mrimap_t* ths, const char* folder, uint32_t uidvalidity)
{
	int        r, handle_locked = 0;
	clist*     fetch_result = NULL;
	uint32_t   out_largetst_uid = 0;
	size_t     read_cnt = 0, read_errors = 0;
	clistiter* cur;

	uint32_t   lastuid = 0; /* The last uid fetched, we fetch from lastuid+1. If 0, we get some of the newest ones. */
	char*      lastuid_config_key = NULL;

	LOCK_HANDLE

		if( uidvalidity )
		{
			lastuid_config_key = mr_mprintf("imap.lastuid.%lu.%s",
				(unsigned long)uidvalidity, folder); /* RFC3501: UID are unique and should grow only, for mailbox recreation etc. UIDVALIDITY changes. */
			lastuid = ths->m_get_config_int(ths, lastuid_config_key, 0);

			struct mailimap_set* set = mailimap_set_new_interval(lastuid+1, 0);
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result); /* execute UID FETCH from:to command, result includes the given UIDs */
			mailimap_set_free(set);
		}
		else
		{
			if( select_folder__(ths, folder)==0 ) {
				mrlog_error("Cannot select folder \"%s\".", folder);
				goto cleanup;
			}

			lastuid_config_key = mr_mprintf("imap.lastuid.%lu.%s",
				(unsigned long)ths->m_hEtpan->imap_selection_info->sel_uidvalidity, folder); /* RFC3501: UID are unique and should grow only, for mailbox recreation etc. UIDVALIDITY changes. */
			lastuid = ths->m_get_config_int(ths, lastuid_config_key, 0);

			if( lastuid > 0 )
			{
				/* Get messages with an ID larger than the one we got last time */
				if( ths->m_hEtpan->imap_selection_info->sel_uidnext == lastuid+1 ) {
					goto cleanup; /* the predicted "next uid on insert" is equal to the one we start for fetching - no new messages (this check only works for the folder with the last message, however, most times this is INBOX - and the check is cheap) */
				}

				struct mailimap_set* set = mailimap_set_new_interval(lastuid+1, 0);
					r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result); /* execute UID FETCH from:to command, result includes the given UIDs */
				mailimap_set_free(set);
			}
			else
			{
				/* fetch the last 200 messages by one-based-index.  Maybe we shoud implement a method to fetch more older ones if the user scrolls up. */
				int32_t i_first = 1, i_last = 200; /* if we cannot get the count, we start with the oldest messages; normally, this should not happen */
				if( ths->m_hEtpan->imap_selection_info->sel_has_exists ) {
					i_last  = ths->m_hEtpan->imap_selection_info->sel_exists;
					i_first = MR_MAX(i_last-200, 1);
				}

				struct mailimap_set* set = mailimap_set_new_interval(i_first, i_last);
					r = mailimap_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result); /* execute FETCH from:to command, result includes the given index */
				mailimap_set_free(set);
			}
		}

	UNLOCK_HANDLE

	if( is_error(ths, r) || fetch_result == NULL )
	{
		if( r == MAILIMAP_ERROR_PROTOCOL ) {
			goto cleanup; /* the folder is simply empty, this is no error */
		}
		mrlog_error("Cannot fetch message list from folder \"%s\".", folder);
		goto cleanup;
	}

	/* go through all mails in folder (this is typically _fast_ as we already have the whole list) */
	for( cur = clist_begin(fetch_result); cur != NULL ; cur = clist_next(cur) )
	{
		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur); /* mailimap_msg_att is a list of attributes: list is a list of message attributes */
		uint32_t cur_uid = peek_uid(msg_att);
		if( cur_uid && (lastuid==0 || cur_uid>lastuid) ) /* normally, the "cur_uid>lastuid" is not needed, however, some server return some smaller IDs under some curcumstances. Mailcore2 does the same check, see see "if (uid < fromUID) {..}"@IMAPSession::fetchMessageNumberUIDMapping()@MCIMAPSession.cpp */
		{
			read_cnt++;
			if( fetch_single_msg(ths, folder, cur_uid) == 0 ) {
				read_errors++;
			}
			else if( cur_uid > out_largetst_uid ) {
				out_largetst_uid = cur_uid;
			}
		}
	}

	if( !read_errors && out_largetst_uid > 0 ) {
		ths->m_set_config_int(ths, lastuid_config_key, out_largetst_uid);
	}

	/* done */
cleanup:
	UNLOCK_HANDLE

    {
		char* temp = mr_mprintf("%i mails read from \"%s\" with %i errors.", (int)read_cnt, folder, (int)read_errors);
		if( read_errors ) {
			mrlog_error(temp);
		}
		else {
			mrlog_info(temp);
		}
		free(temp);
    }

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}

	if( lastuid_config_key ) {
		free(lastuid_config_key);
	}

	return read_cnt;
}


static int fetch_from_all_folders(mrimap_t* ths)
{
	int        handle_locked = 0;
	clist*     folder_list = NULL;
	clistiter* cur;
	int        total_cnt = 0;

	LOCK_HANDLE
		folder_list = list_folders__(ths);
	UNLOCK_HANDLE

	/* first, read the INBOX, this looks much better on the initial load as the INBOX
	has the most recent mails.  Moreover, this is for speed reasons, as the other folders only have few new messages. */
	for( cur = clist_begin(folder_list); cur != NULL ; cur = clist_next(cur) )
	{
		mrimapfolder_t* folder = (mrimapfolder_t*)clist_content(cur);
		if( folder->m_meaning == MEANING_INBOX ) {
			total_cnt += fetch_from_single_folder(ths, folder->m_name_to_select, 0);
		}
	}

	for( cur = clist_begin(folder_list); cur != NULL ; cur = clist_next(cur) )
	{
		mrimapfolder_t* folder = (mrimapfolder_t*)clist_content(cur);
		if( folder->m_meaning == MEANING_IGNORE ) {
			mrlog_info("Folder \"%s\" ignored.", folder->m_name_utf8);
		}
		else if( folder->m_meaning != MEANING_INBOX ) {
			total_cnt += fetch_from_single_folder(ths, folder->m_name_to_select, 0);
		}
	}

	free_folders__(folder_list);

	return total_cnt;
}


/*******************************************************************************
 * Watch thread
 ******************************************************************************/


static void* watch_thread_entry_point(void* entry_arg)
{
	mrimap_t*       ths = (mrimap_t*)entry_arg;
	int             handle_locked = 0, idle_blocked = 0, unsetup_idle = 0, force_sleep = 0, do_fetch = 0;
	#define         SLEEP_ON_ERROR_SECONDS     10
	#define         SLEEP_ON_INTERRUPT_SECONDS  2      /* let the job thread a little bit time before we IDLE again, otherweise there will be many idle-interrupt sequences */
	#define         IDLE_DELAY_SECONDS         (28*60) /* 28 minutes is a typical maximum, most servers do not allow more. if the delay is reached, we also check _all_ folders. */

	mrlog_info("IMAP-watch-thread started.");
	mrosnative_setup_thread();

	if( ths->m_can_idle )
	{
		/* watch using IDLE
		 **********************************************************************/

		int      r, r2;
		uint32_t uidvaliditiy;

		fetch_from_all_folders(ths); /* the initial fetch from all folders is needed as this will init the folder UIDs (see fetch_from_single_folder() if lastuid is unset) */

		LOCK_HANDLE
			mailstream_setup_idle(ths->m_hEtpan->imap_stream);
			unsetup_idle = 1;
		UNLOCK_HANDLE

		while( 1 )
		{
			if( ths->m_watch_do_exit ) { goto exit_; }

			BLOCK_IDLE /* must be done before LOCK_HANDLE; this allows other threads to block IDLE */
			LOCK_HANDLE

				do_fetch = 0;
				force_sleep = SLEEP_ON_ERROR_SECONDS;
				uidvaliditiy = 0;
				setup_handle_if_needed__(ths);
				if( select_folder__(ths, "INBOX") )
				{
					uidvaliditiy = ths->m_hEtpan->imap_selection_info->sel_uidvalidity;
					r = mailimap_idle(ths->m_hEtpan);
					if( !is_error(ths, r) )
					{
						mrlog_info("IDLE start...");

						UNLOCK_HANDLE
						UNBLOCK_IDLE

							pthread_mutex_lock(&ths->m_inwait_mutex);
								r = mailstream_wait_idle(ths->m_hEtpan->imap_stream, IDLE_DELAY_SECONDS);
								r2 = mailimap_idle_done(ths->m_hEtpan); /* it's okay to use the handle without locking as we're inwait */
							pthread_mutex_unlock(&ths->m_inwait_mutex);
							force_sleep = 0;

							if( r == MAILSTREAM_IDLE_ERROR || r==MAILSTREAM_IDLE_CANCELLED ) {
								mrlog_info("IDLE wait cancelled, r=%i; we'll reconnect soon.", (int)r);
								force_sleep = SLEEP_ON_ERROR_SECONDS;
								ths->m_should_reconnect = 1;
							}
							else if( r == MAILSTREAM_IDLE_INTERRUPTED ) {
								mrlog_info("IDLE interrupted.");
								if( !ths->m_watch_do_exit ) {
									force_sleep = SLEEP_ON_INTERRUPT_SECONDS;
								}
							}
							else if( r == MAILSTREAM_IDLE_TIMEOUT ) {
								mrlog_info("IDLE timeout.");
								do_fetch = 2; /* fetch from all folders */
							}
							else if( r ==  MAILSTREAM_IDLE_HASDATA ) {
								mrlog_info("IDLE got data.");
								do_fetch = 1; /* fetch from currently selected folder, the INBOX */
							}
							else if( is_error(ths, r) ) {
								; /* this check is needed and should be last as is_error() also sets m_should_reconnect */
							}

							if( is_error(ths, r2) ) {
								do_fetch = 0;
							}

							if( ths->m_watch_do_exit ) { goto exit_; }

						BLOCK_IDLE
						LOCK_HANDLE
					}
				}

			UNLOCK_HANDLE
			UNBLOCK_IDLE

			if( do_fetch == 1 ) {
				fetch_from_single_folder(ths, "INBOX", uidvaliditiy);
			}
			else if( do_fetch == 2 ) {
				fetch_from_all_folders(ths);
			}
			else if( force_sleep ) {
				sleep(force_sleep);
			}
		}
	}
	else
	{
		/* watch using POLL
		 **********************************************************************/

		mrlog_info("IMAP-watch-thread will poll for messages.");
		time_t last_message_time=time(NULL), last_fullread_time=0, now, seconds_to_wait;
		struct timespec timeToWait;
		while( 1 )
		{
			/* get the latest messages */
			now = time(NULL);
			do_fetch = 1;
			if( now-last_fullread_time > IDLE_DELAY_SECONDS ) {
				do_fetch = 2;
			}

			LOCK_HANDLE
				setup_handle_if_needed__(ths);
			UNLOCK_HANDLE


			if( do_fetch == 1 ) {
				if( fetch_from_single_folder(ths, "INBOX", 0) > 0 ) {
					last_message_time = now;
				}
			}
			else if( do_fetch == 2 ) {
				if( fetch_from_all_folders(ths) > 0 ) {
					last_message_time = now;
				}
				last_fullread_time = now;
			}

			/* calculate the wait time: every 10 seconds in the first 2 minutes after a new message, after that growing up to 5 minutes */
			if( now-last_message_time < 2*60 ) {
				seconds_to_wait = 10;
			}
			else {
				seconds_to_wait = (now-last_message_time)/6;
				if( seconds_to_wait > 5*60 ) {
					seconds_to_wait = 5*60;
				}
			}

			/* wait */
			mrlog_info("IMAP-watch-thread waits %i seconds.", (int)seconds_to_wait);
			if( ths->m_watch_do_exit ) { goto exit_; }
			pthread_mutex_lock(&ths->m_watch_condmutex);
				timeToWait.tv_sec  = time(NULL)+seconds_to_wait;
				timeToWait.tv_nsec = 0;
				pthread_cond_timedwait(&ths->m_watch_cond, &ths->m_watch_condmutex, &timeToWait);
			pthread_mutex_unlock(&ths->m_watch_condmutex);
			if( ths->m_watch_do_exit ) { goto exit_; }
		}
	}

exit_:
	UNLOCK_HANDLE
	UNBLOCK_IDLE
	if( unsetup_idle ) {
		LOCK_HANDLE
			mailstream_unsetup_idle(ths->m_hEtpan->imap_stream);
		UNLOCK_HANDLE
	}
	mrosnative_unsetup_thread();
	return NULL;
}


/*******************************************************************************
 * Setup handle
 ******************************************************************************/


static int setup_handle_if_needed__(mrimap_t* ths)
{
	int r, success = 0;

    if( ths->m_should_reconnect ) {
		unsetup_handle__(ths);
    }

    if( ths->m_hEtpan ) {
		success = 1;
		goto cleanup;
    }

	mrlog_info("Connecting to IMAP-server \"%s:%i\"...", ths->m_imap_server, (int)ths->m_imap_port);
		ths->m_hEtpan = mailimap_new(0, NULL);
		r = mailimap_ssl_connect(ths->m_hEtpan, ths->m_imap_server, ths->m_imap_port);
		if( is_error(ths, r) ) {
			mrlog_error("Could not connect to IMAP-server.");
			goto cleanup;
		}
	mrlog_info("Connection to IMAP-server ok.");

	mrlog_info("Login to IMAP-server as \"%s\"...", ths->m_imap_user);
		r = mailimap_login(ths->m_hEtpan, ths->m_imap_user, ths->m_imap_pw);
		if( is_error(ths, r) ) {
			mrlog_error("Could not login.");
			goto cleanup;
		}
	mrlog_info("Login ok.");

	success = 1;

cleanup:
	if( success == 0 ) {
		unsetup_handle__(ths);
	}

	ths->m_should_reconnect = 0;
	return success;
}


static void unsetup_handle__(mrimap_t* ths)
{
	if( ths->m_hEtpan )
	{
		mrlog_info("Disconnecting...");
			if( ths->m_hEtpan->imap_stream != NULL ) {
				mailstream_close(ths->m_hEtpan->imap_stream); /* not sure, if this is really needed, however, mailcore2 does the same */
				ths->m_hEtpan->imap_stream = NULL;
			}

			mailimap_free(ths->m_hEtpan);
			ths->m_hEtpan = NULL;
		mrlog_info("Disconnect done.");
	}

	ths->m_selected_folder[0] = 0;

	/* we leave m_sent_folder set; normally this does not change in a normal reconnect; we'll update this folder if we get errors */
}


/*******************************************************************************
 * Connect/Disconnect
 ******************************************************************************/


int mrimap_connect(mrimap_t* ths, const mrloginparam_t* lp)
{
	int success = 0, handle_locked = 0;

	if( ths == NULL || lp==NULL || lp->m_mail_server==NULL || lp->m_mail_user==NULL || lp->m_mail_pw==NULL ) {
		return 0;
	}

	if( pthread_mutex_trylock(&ths->m_hEtpanmutex)!=0 ) {
		goto cleanup;
	}
	handle_locked = 1;

		if( ths->m_connected ) {
			success = 1;
			goto cleanup;
		}

		free(ths->m_imap_server); ths->m_imap_server  = safe_strdup(lp->m_mail_server);
								  ths->m_imap_port    = lp->m_mail_port;
		free(ths->m_imap_user);   ths->m_imap_user    = safe_strdup(lp->m_mail_user);
		free(ths->m_imap_pw);     ths->m_imap_pw      = safe_strdup(lp->m_mail_pw);

		if( !setup_handle_if_needed__(ths) ) {
			goto cleanup;
		}

		ths->m_connected = 1;

		/* we set the following flags here and not in setup_handle_if_needed__() as they must not change during connection */
		ths->m_can_idle = mailimap_has_idle(ths->m_hEtpan);
		mrlog_info("Can Idle? %s", ths->m_can_idle? "Yes" : "No");

		ths->m_has_xlist = mailimap_has_xlist(ths->m_hEtpan);
		mrlog_info("Has Xlist? %s", ths->m_has_xlist? "Yes" : "No");

		mrlog_info("Starting IMAP-watch-thread...");
		ths->m_watch_do_exit = 0;

	UNLOCK_HANDLE

	pthread_create(&ths->m_watch_thread, NULL, watch_thread_entry_point, ths);

	success = 1;

cleanup:
	if( success == 0 ) {
		unsetup_handle__(ths);
	}

	return success;
}


void mrimap_disconnect(mrimap_t* ths)
{
	int handle_locked = 0, connected;

	if( ths == NULL ) {
		return;
	}

	LOCK_HANDLE
		connected = ths->m_connected;
	UNLOCK_HANDLE

	if( connected )
	{
		mrlog_info("Stopping IMAP-watch-thread...");
			ths->m_watch_do_exit = 1;
			if( ths->m_can_idle && ths->m_hEtpan->imap_stream )
			{
				LOCK_HANDLE
					mailstream_interrupt_idle(ths->m_hEtpan->imap_stream);
				UNLOCK_HANDLE
				pthread_join(ths->m_watch_thread, NULL);
			}
			else
			{
				pthread_cond_signal(&ths->m_watch_cond);
				pthread_join(ths->m_watch_thread, NULL);
			}
		mrlog_info("IMAP-watch-thread stopped.");

		LOCK_HANDLE
			unsetup_handle__(ths);
			ths->m_can_idle  = 0;
			ths->m_has_xlist = 0;
			ths->m_connected = 0;
		UNLOCK_HANDLE
	}
}


int mrimap_is_connected(mrimap_t* ths)
{
	return (ths && ths->m_connected); /* we do not use a LOCK - otherwise, the check may take seconds and is not sufficient for some GUI state updates. */
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

	pthread_mutex_init(&ths->m_hEtpanmutex, NULL);
	pthread_mutex_init(&ths->m_idlemutex, NULL);
	pthread_mutex_init(&ths->m_inwait_mutex, NULL);
	pthread_mutex_init(&ths->m_watch_condmutex, NULL);
	pthread_cond_init(&ths->m_watch_cond, NULL);

	ths->m_selected_folder = calloc(1, 1);
	ths->m_moveto_folder   = NULL;
	ths->m_sent_folder     = NULL;

	/* create some useful objects */
	ths->m_fetch_type_uid = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch the ID */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_uid, mailimap_fetch_att_new_uid());

	ths->m_fetch_type_body = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch flags+body */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_body, mailimap_fetch_att_new_flags());
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_body, mailimap_fetch_att_new_body_peek_section(mailimap_section_new(NULL)));

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
	pthread_mutex_destroy(&ths->m_inwait_mutex);
	pthread_mutex_destroy(&ths->m_idlemutex);
	pthread_mutex_destroy(&ths->m_hEtpanmutex);

	free(ths->m_imap_server);
	free(ths->m_imap_user);
	free(ths->m_imap_pw);
	free(ths->m_selected_folder);
	free(ths->m_moveto_folder);
	free(ths->m_sent_folder);


	if( ths->m_fetch_type_uid )  { mailimap_fetch_type_free(ths->m_fetch_type_uid);  }
	if( ths->m_fetch_type_body ) { mailimap_fetch_type_free(ths->m_fetch_type_body); }

	free(ths);
}


int mrimap_fetch(mrimap_t* ths)
{
	if( ths == NULL || !ths->m_connected ) {
		return 0;
	}

	ths->m_manual_fetch = 1;
	pthread_cond_signal(&ths->m_watch_cond);
	return 1;
}


int mrimap_append_msg(mrimap_t* ths, time_t timestamp, const char* data_not_terminated, size_t data_bytes, char** ret_server_folder, uint32_t* ret_server_uid)
{
	int                        success = 0, handle_locked = 0, idle_blocked = 0, r;
	uint32_t                   ret_uidvalidity = 0;
	struct mailimap_flag_list* flag_list = NULL;
	struct mailimap_date_time* imap_date = NULL;

	*ret_server_folder = NULL;

	LOCK_HANDLE
	BLOCK_IDLE

		INTERRUPT_IDLE

		mrlog_info("Appending message IMAP-server...");

		if( !init_chat_folders__(ths) ) {
			mrlog_error("Cannot find out IMAP-sent-folder.");
			goto cleanup;
		}

		if( !select_folder__(ths, ths->m_sent_folder) ) {
			mrlog_error("Cannot select IMAP-folder \"%s\".", ths->m_sent_folder);
			ths->m_sent_folder[0] = 0; /* force re-init */
			goto cleanup;
		}

		flag_list = mailimap_flag_list_new_empty();
		mailimap_flag_list_add(flag_list, mailimap_flag_new_seen());

		imap_date = mr_timestamp_to_mailimap_date_time(timestamp);
		if( imap_date == NULL ) {
			mrlog_error("Bad date.");
			goto cleanup;
		}

		r = mailimap_uidplus_append(ths->m_hEtpan, ths->m_sent_folder, flag_list, imap_date, data_not_terminated, data_bytes, &ret_uidvalidity, ret_server_uid);
		if( is_error(ths, r) ) {
			mrlog_error("Cannot append message to \"%s\", error #%i.", ths->m_sent_folder, (int)r);
			goto cleanup;
		}

		*ret_server_folder = safe_strdup(ths->m_sent_folder);

		mrlog_info("Message appended to \"%s\".", ths->m_sent_folder);

		success = 1;

cleanup:
	UNBLOCK_IDLE
	UNLOCK_HANDLE

    if( imap_date ) {
        mailimap_date_time_free(imap_date);
    }

    if( flag_list ) {
		mailimap_flag_list_free(flag_list);
    }

	return success;
}


static int add_flag__(mrimap_t* ths, const char* folder, uint32_t server_uid, struct mailimap_flag* flag)
{
	int                              r;
	struct mailimap_flag_list*       flag_list = NULL;
	struct mailimap_store_att_flags* store_att_flags = NULL;
	struct mailimap_set*             set = mailimap_set_new_single(server_uid);

	if( select_folder__(ths, folder)==0 ) {
		goto cleanup;
	}

	flag_list = mailimap_flag_list_new_empty();
	mailimap_flag_list_add(flag_list, flag);

	store_att_flags = mailimap_store_att_flags_new_add_flags(flag_list); /* FLAGS.SILENT does not return the new value */

	r = mailimap_uid_store(ths->m_hEtpan, set, store_att_flags);
	if( is_error(ths, r) ) {
		goto cleanup;
	}

cleanup:
	mailimap_store_att_flags_free(store_att_flags);
	mailimap_set_free(set);
	return ths->m_should_reconnect? 0 : 1; /* all non-connection states are treated as success - the mail may already be deleted or moved away on the server */
}


int mrimap_markseen_msg(mrimap_t* ths, const char* folder, uint32_t server_uid, int also_move, char** ret_server_folder, uint32_t* ret_server_uid)
{
	// when marking as seen, there is no real need to check against the rfc724_mid - in the worst case, when the UID validity or the mailbox has changed, we mark the wrong message as "seen" - as the very most messages are seen, this is no big thing.
	// command would be "STORE 123,456,678 +FLAGS (\Seen)"
	int                  handle_locked = 0, idle_blocked = 0, r;
	struct mailimap_set* set = NULL;

	if( ths==NULL || folder==NULL || server_uid==0 ) {
		return 1; /* job done */
	}

	*ret_server_folder = NULL;
	*ret_server_uid = 0;

	LOCK_HANDLE
	BLOCK_IDLE

		INTERRUPT_IDLE

		mrlog_info("Marking message %s/%i as seen...", folder, (int)server_uid);

		if( add_flag__(ths, folder, server_uid, mailimap_flag_new_seen())==0 ) {
			mrlog_error("Cannot mark message as seen.");
			goto cleanup;
		}

		mrlog_info("Message marked as seen.");

		if( also_move )
		{
			init_chat_folders__(ths);
			if( ths->m_moveto_folder )
			{
				mrlog_info("Moving message %s/%i to %s...", folder, (int)server_uid, ths->m_moveto_folder);
				set = mailimap_set_new_single(server_uid);

				/* TODO/TOCHECK: MOVE may not be supported on servers, if this is often the case, we should fallback to a COPY/DELETE implementation.
				Same for the UIDPLUS extension (if in doubt, we can find out the resulting UID using "imap_selection_info->sel_uidnext" then). */
				uint32_t             res_uid = 0;
				struct mailimap_set* res_setsrc = NULL;
				struct mailimap_set* res_setdest = NULL;
				r = mailimap_uidplus_uid_move(ths->m_hEtpan, set, ths->m_moveto_folder, &res_uid, &res_setsrc, &res_setdest); /* the correct folder is already selected in add_flag__() above */
				if( is_error(ths, r) ) {
					mrlog_info("Cannot move message.");
					goto cleanup;
				}

				if( res_setsrc ) {
					mailimap_set_free(res_setsrc);
				}

				if( res_setdest ) {
					clistiter* cur = clist_begin(res_setdest->set_list);
					if (cur != NULL) {
						struct mailimap_set_item* item;
						item = clist_content(cur);
						*ret_server_uid = item->set_first;
						*ret_server_folder = safe_strdup(ths->m_moveto_folder);
					}
					mailimap_set_free(res_setdest);
				}

				mrlog_info("Message moved.");
			}
		}

cleanup:
	UNBLOCK_IDLE
	UNLOCK_HANDLE
	if( set ) {
		mailimap_set_free(set);
	}
	return ths->m_should_reconnect? 0 : 1;
}


int mrimap_delete_msg(mrimap_t* ths, const char* rfc724_mid, const char* folder, uint32_t server_uid)
{
	// when deleting using server_uid, we have to check against rfc724_mid first - the UID validity or the mailbox may have change
	int success = 0, handle_locked = 0, idle_blocked = 0;

	if( ths==NULL || rfc724_mid==NULL || folder==NULL || folder[0]==0 || server_uid==0 ) {
		return 1; /* job done */
	}

	LOCK_HANDLE
	BLOCK_IDLE

		INTERRUPT_IDLE

		mrlog_info("Deleting message \"%s\", server_folder=%s, server_uid=%i...", rfc724_mid, folder, (int)server_uid);

		if( add_flag__(ths, folder, server_uid, mailimap_flag_new_deleted())==0 ) {
			mrlog_error("Cannot delete message.");
			goto cleanup;
		}

		mrlog_info("Message deleted.");

		success = 1;

cleanup:
	UNBLOCK_IDLE
	UNLOCK_HANDLE

	return success;
}

