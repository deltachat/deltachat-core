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


#include <stdlib.h>
#include <libetpan/libetpan.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h> /* for sleep() */
#include "mrmailbox_internal.h"
#include "mrimap.h"
#include "mrosnative.h"
#include "mrloginparam.h"

#define LOCK_HANDLE   pthread_mutex_lock(&ths->m_hEtpanmutex); mrmailbox_wake_lock(ths->m_mailbox); handle_locked = 1;
#define UNLOCK_HANDLE if( handle_locked ) { mrmailbox_wake_unlock(ths->m_mailbox); pthread_mutex_unlock(&ths->m_hEtpanmutex); handle_locked = 0; }

#define BLOCK_IDLE   pthread_mutex_lock(&ths->m_idlemutex); idle_blocked = 1;
#define UNBLOCK_IDLE if( idle_blocked ) { pthread_mutex_unlock(&ths->m_idlemutex); idle_blocked = 0; }
#define INTERRUPT_IDLE  \
	if( ths && ths->m_can_idle && ths->m_hEtpan && ths->m_hEtpan->imap_stream ) { \
		if( pthread_mutex_trylock(&ths->m_inwait_mutex)!=0 ) { \
			mrmailbox_log_info(ths->m_mailbox, 0, "Interrupting IDLE..."); \
			mailstream_interrupt_idle(ths->m_hEtpan->imap_stream); \
			pthread_mutex_lock(&ths->m_inwait_mutex); /* make sure, mailimap_idle_done() is called - otherwise the other routines do not work */ \
		} \
		pthread_mutex_unlock(&ths->m_inwait_mutex); \
	}

static int  setup_handle_if_needed__ (mrimap_t*);
static void unsetup_handle__         (mrimap_t*);


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int is_error(mrimap_t* ths, int code)
{
	if( code == MAILIMAP_NO_ERROR /*0*/
	 || code == MAILIMAP_NO_ERROR_AUTHENTICATED /*1*/
	 || code == MAILIMAP_NO_ERROR_NON_AUTHENTICATED /*2*/ )
	{
		return 0;
	}

	if( code == MAILIMAP_ERROR_STREAM /*4*/
	 || code == MAILIMAP_ERROR_PARSE /*5*/ )
	{
		mrmailbox_log_info(ths->m_mailbox, 0, "IMAP stream lost; we'll reconnect soon.");
		ths->m_should_reconnect = 1;
	}

	return 1;
}


static void get_config_lastseenuid(mrimap_t* imap, const char* folder, uint32_t* uidvalidity, uint32_t* lastseenuid)
{
	*uidvalidity = 0;
	*lastseenuid = 0;

	char* key = mr_mprintf("imap.mailbox.%s", folder);
	char* val1 = imap->m_get_config(imap, key, NULL), *val2 = NULL, *val3 = NULL;
	if( val1 )
	{
		/* the entry has the format `imap.mailbox.<folder>=<uidvalidity>:<lastseenuid>` */
		val2 = strchr(val1, ':');
		if( val2 )
		{
			*val2 = 0;
			val2++;

			val3 = strchr(val2, ':');
			if( val3 ) { *val3 = 0; /* ignore everything bethind an optional second colon to allow future enhancements */ }

			*uidvalidity = atol(val1);
			*lastseenuid = atol(val2);
		}
	}
	free(val1); /* val2 and val3 are only pointers inside val1 and MUST NOT be free()'d */
	free(key);
}


static void set_config_lastseenuid(mrimap_t* imap, const char* folder, uint32_t uidvalidity, uint32_t lastseenuid)
{
	char* key = mr_mprintf("imap.mailbox.%s", folder);
	char* val = mr_mprintf("%lu:%lu", uidvalidity, lastseenuid);
	imap->m_set_config(imap, key, val);
	free(val);
	free(key);
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
		else if( strcmp(lower, "inbox") == 0 ) /* the "INBOX" foldername is IMAP-standard */
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

	if( ths==NULL || ths->m_hEtpan==NULL ) {
		goto cleanup;
	}

	/* the "*" not only gives us the folders from the main directory, but also all subdirectories; so the resulting foldernames may contain
	delimiters as "folder/subdir/subsubdir" etc.  However, as we do not really use folders, this is just fine (otherwise we'd implement this
	functinon recursively. */
	if( ths->m_has_xlist )  {
		r = mailimap_xlist(ths->m_hEtpan, "", "*", &imap_list);
	}
	else {
		r = mailimap_list(ths->m_hEtpan, "", "*", &imap_list);
	}
	if( is_error(ths, r) || imap_list==NULL ) {
		imap_list = NULL;
		mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot get folder list.");
		goto cleanup;
	}
	//default IMAP delimiter if none is returned by the list command
	ths->m_imap_delimiter = '.';
	for( iter1 = clist_begin(imap_list); iter1 != NULL ; iter1 = clist_next(iter1) )
	{
		struct mailimap_mailbox_list* imap_folder = (struct mailimap_mailbox_list*)clist_content(iter1);
		if (imap_folder->mb_delimiter) {
			/* Set IMAP delimiter */
			ths->m_imap_delimiter = imap_folder->mb_delimiter;
		}

		mrimapfolder_t* ret_folder = calloc(1, sizeof(mrimapfolder_t));

		if( strcasecmp(imap_folder->mb_name, "INBOX")==0 ) {
			/* Force upper case INBOX as we also use it directly this way; a unified name is needed as we use the folder name to remember the last uid.
			Servers may return any case, however, all variants MUST lead to the same INBOX, see RFC 3501 5.1 */
			ret_folder->m_name_to_select = safe_strdup("INBOX");
		}
		else {
			ret_folder->m_name_to_select = safe_strdup(imap_folder->mb_name);
		}

		ret_folder->m_name_utf8      = mr_decode_modified_utf7(imap_folder->mb_name, 0);
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


static void free_folders(clist* folders)
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
	char       *normal_folder = NULL, *sent_folder = NULL, *chats_folder = NULL, *chats_folder_legacy = NULL;

	if( ths==NULL || ths->m_hEtpan==NULL ) {
		goto cleanup;
	}

	if( ths->m_sent_folder && ths->m_sent_folder[0] ) {
		success = 1;
		goto cleanup;
	}

	free(ths->m_sent_folder);
	ths->m_sent_folder = NULL;

	free(ths->m_moveto_folder);
	ths->m_moveto_folder = NULL;
	//this sets ths->m_imap_delimiter as side-effect
	folder_list = list_folders__(ths);

	//as a fallback, the chats_folder is created under INBOX as required e.g. for DomainFactory
	char fallback_folder[64];
	snprintf(fallback_folder, sizeof(fallback_folder), "INBOX%c%s", ths->m_imap_delimiter, MR_CHATS_FOLDER);
        char fallback_folder_legacy[64];
        snprintf(fallback_folder_legacy, sizeof(fallback_folder_legacy), "INBOX%c%s", ths->m_imap_delimiter, MR_CHATS_FOLDER_LEGACY);
        
	for( iter1 = clist_begin(folder_list); iter1 != NULL ; iter1 = clist_next(iter1) ) {
		mrimapfolder_t* folder = (struct mrimapfolder_t*)clist_content(iter1);
		if( strcmp(folder->m_name_utf8, MR_CHATS_FOLDER)==0 || strcmp(folder->m_name_utf8, fallback_folder)==0 ) {
			chats_folder = safe_strdup(folder->m_name_to_select);
			break;
		}
                else if( strcmp(folder->m_name_utf8, MR_CHATS_FOLDER_LEGACY)==0 || strcmp(folder->m_name_utf8, fallback_folder_legacy)==0 ) {
			chats_folder_legacy = safe_strdup(folder->m_name_to_select);
			break;
		}
		else if( folder->m_meaning == MEANING_SENT_OBJECTS ) {
			sent_folder = safe_strdup(folder->m_name_to_select);
		}
		else if( folder->m_meaning == MEANING_NORMAL && normal_folder == NULL ) {
			normal_folder = safe_strdup(folder->m_name_to_select);
		}
	}

	if (chats_folder == NULL && (ths->m_server_flags & MR_NO_MOVE_TO_CHATS) == 0) {
		if (chats_folder_legacy != NULL) {
			//we found an old Chats-Folder, so rename
			mrmailbox_log_info(ths->m_mailbox, 0, "Found Legacy IMAP-folder \"%s\", trying to rename...", chats_folder_legacy);
			char* new_name = MR_CHATS_FOLDER;
			if (strcmp(chats_folder_legacy, fallback_folder_legacy) == 0) {
				//previous folder was under INBOX so the new folder should be also
				new_name = fallback_folder;
			}
			int r = mailimap_rename(ths->m_hEtpan, chats_folder_legacy, new_name);
			if (is_error(ths, r)) {
				/* continue on errors, we'll just use the old folder then */
				chats_folder = safe_strdup(chats_folder_legacy);
				mrmailbox_log_warning(ths->m_mailbox, 0, "Failed to rename IMAP-folder, using legacy.");
			} else {
				chats_folder = safe_strdup(new_name);
				mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-folder renamed.");
			}
		} 
		else{ //no old chats folder, so create a new one
			mrmailbox_log_info(ths->m_mailbox, 0, "Creating IMAP-folder \"%s\"...", MR_CHATS_FOLDER);
			int r = mailimap_create(ths->m_hEtpan, MR_CHATS_FOLDER);
			if( is_error(ths, r) ) {
				mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot create IMAP-folder, using trying INBOX subfolder.");
				r = mailimap_create(ths->m_hEtpan, fallback_folder);
				if( is_error(ths, r) ) {
					/* continue on errors, we'll just use a different folder then */
					mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot create IMAP-folder, using default.");
				}
				else {
					chats_folder = safe_strdup(fallback_folder);
					mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-folder created (inbox subfolder).");
				}
			}
			else {
				chats_folder = safe_strdup(MR_CHATS_FOLDER);
				mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-folder created.");
			}
		}
	}

	/* Subscribe to the created folder.  Otherwise, although a top-level folder, if clients use LSUB for listing, the created folder may be hidden.
	(we could also do this directly after creation, however, we forgot this in versions <v0.1.19 */
	if( chats_folder && ths->m_get_config(ths, "imap.subscribedToChats", NULL)==NULL ) {
		mailimap_subscribe(ths->m_hEtpan, chats_folder);
		ths->m_set_config(ths, "imap.subscribedToChats", "1");
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
	free_folders(folder_list);
	free(chats_folder);
	free(sent_folder);
	free(normal_folder);
	return success;
}


static int select_folder__(mrimap_t* ths, const char* folder /*may be NULL*/)
{
	if( ths == NULL ) {
		return 0;
	}

	if( ths->m_hEtpan==NULL ) {
		ths->m_selected_folder[0] = 0;
		ths->m_selected_folder_needs_expunge = 0;
		return 0;
	}

	/* if there is a new folder and the new folder is equal to the selected one, there's nothing to do.
	if there is _no_ new folder, we continue as we might want to expunge below.  */
	if( folder && strcmp(ths->m_selected_folder, folder)==0 ) {
		return 1;
	}

	/* deselect existing folder, if needed (it's also done implicitly by SELECT, however, without EXPUNGE then) */
	if( ths->m_selected_folder_needs_expunge ) {
		if( ths->m_selected_folder[0] ) {
			mrmailbox_log_info(ths->m_mailbox, 0, "Expunge messages in \"%s\".", ths->m_selected_folder);
			mailimap_close(ths->m_hEtpan); /* a CLOSE-SELECT is considerably faster than an EXPUNGE-SELECT, see https://tools.ietf.org/html/rfc3501#section-6.4.2 */
		}
		ths->m_selected_folder_needs_expunge = 0;
	}

	/* select new folder */
	if( folder ) {
		int r = mailimap_select(ths->m_hEtpan, folder);
		if( is_error(ths, r) || ths->m_hEtpan->imap_selection_info == NULL ) {
			ths->m_selected_folder[0] = 0;
			return 0;
		}
	}

	free(ths->m_selected_folder);
	ths->m_selected_folder = safe_strdup(folder);
	return 1;
}


static void forget_folder_selection__(mrimap_t* ths)
{
	select_folder__(ths, NULL);
}


static uint32_t search_uid__(mrimap_t* imap, const char* message_id)
{
	/* Search Message-ID in all folders.
	On success, the folder containing the message is selected and the UID is returned.
	On failure, 0 is returned and any or none folder is selected. */
	clist                       *folders = list_folders__(imap), *search_result = NULL;
	clistiter                   *cur, *cur2;
	struct mailimap_search_key  *key = mailimap_search_key_new_header(strdup("Message-ID"), mr_mprintf("<%s>", message_id));
	uint32_t                    uid = 0;
	for( cur = clist_begin(folders); cur != NULL ; cur = clist_next(cur) )
	{
		mrimapfolder_t* folder = (mrimapfolder_t*)clist_content(cur);
		if( select_folder__(imap, folder->m_name_to_select) )
		{
			int r = mailimap_uid_search(imap->m_hEtpan, "utf-8", key, &search_result);
			if( !is_error(imap, r) && search_result ) {
				if( (cur2=clist_begin(search_result)) != NULL ) {
					uint32_t* ptr_uid = (uint32_t *)clist_content(cur2);
					if( ptr_uid ) {
						uid = *ptr_uid;
					}
				}
				mailimap_search_result_free(search_result);
				search_result = NULL;
				if( uid ) {
					goto cleanup;
				}
			}
		}
	}

cleanup:
	if( search_result ) { mailimap_search_result_free(search_result); }
	if( key ) { mailimap_search_key_free(key); }
	free_folders(folders);
	return uid;
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


static char* unquote_rfc724_mid(const char* in)
{
	/* remove < and > from the given message id */
	char* out = safe_strdup(in);
	int out_len = strlen(out);
	if( out_len > 2 ) {
		if( out[0]         == '<' ) { out[0]         = ' '; }
		if( out[out_len-1] == '>' ) { out[out_len-1] = ' '; }
		mr_trim(out);
	}
	return out;
}


static const char* peek_rfc724_mid(struct mailimap_msg_att* msg_att)
{
	if( msg_att == NULL ) {
		return NULL;
	}

	/* search the UID in a list of attributes returned by a FETCH command */
	clistiter* iter1;
	for( iter1=clist_begin(msg_att->att_list); iter1!=NULL; iter1=clist_next(iter1) )
	{
		struct mailimap_msg_att_item* item = (struct mailimap_msg_att_item*)clist_content(iter1);
		if( item )
		{
			if( item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC )
			{
				if( item->att_data.att_static->att_type == MAILIMAP_MSG_ATT_ENVELOPE )
				{
					struct mailimap_envelope* env = item->att_data.att_static->att_data.att_env;
					if( env && env->env_message_id ) {
						return env->env_message_id;
					}
				}
			}
		}
	}

	return NULL;
}


static int peek_flag_keyword(struct mailimap_msg_att* msg_att, const char* flag_keyword)
{
	/* search $MDNSent in a list of attributes returned by a FETCH command */
	if( msg_att == NULL || msg_att->att_list==NULL || flag_keyword == NULL ) {
		return 0;
	}

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
								if( flag->fl_type == MAILIMAP_FLAG_KEYWORD && flag->fl_data.fl_keyword!=NULL
								 && strcmp(flag->fl_data.fl_keyword, flag_keyword)==0 ) {
									return 1; /* flag found */
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}


static void peek_body(struct mailimap_msg_att* msg_att, char** p_msg, size_t* p_msg_bytes, uint32_t* flags, int* deleted)
{
	if( msg_att == NULL ) {
		return;
	}
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


static int fetch_single_msg(mrimap_t* ths, const char* folder, uint32_t server_uid, int block_idle)
{
	/* the function returns:
	    0  the caller should try over again later
	or  1  if the messages should be treated as received, the caller should not try to read the message again (even if no database entries are returned) */
	char*       msg_content = NULL;
	size_t      msg_bytes = 0;
	int         r, retry_later = 0, deleted = 0, handle_locked = 0, idle_blocked = 0;
	uint32_t    flags = 0;
	clist*      fetch_result = NULL;
	clistiter*  cur;

	if( ths==NULL ) {
		goto cleanup;
	}

	LOCK_HANDLE

		if( ths->m_hEtpan==NULL ) {
			goto cleanup;
		}

		if( block_idle ) {
			BLOCK_IDLE
			INTERRUPT_IDLE
			setup_handle_if_needed__(ths);
			forget_folder_selection__(ths);
			select_folder__(ths, folder); /* if we need to block IDLE, we'll also need to select the folder as it may have changed by IDLE */
		}

		{
			struct mailimap_set* set = mailimap_set_new_single(server_uid);
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_body, &fetch_result);
			mailimap_set_free(set);
		}

		if( block_idle ) {
			UNBLOCK_IDLE
		}

	UNLOCK_HANDLE

	if( is_error(ths, r) || fetch_result == NULL ) {
		fetch_result = NULL;
		mrmailbox_log_warning(ths->m_mailbox, 0, "Error #%i on fetching message #%i from folder \"%s\"; retry=%i.", (int)r, (int)server_uid, folder, (int)ths->m_should_reconnect);
		if( ths->m_should_reconnect ) {
			retry_later = 1; /* maybe we should also retry on other errors, however, we should check this carefully, as this may result in a dead lock! */
		}
		goto cleanup; /* this is an error that should be recovered; the caller should try over later to fetch the message again (if there is no such message, we simply get an empty result) */
	}

	if( (cur=clist_begin(fetch_result)) == NULL ) {
		mrmailbox_log_warning(ths->m_mailbox, 0, "Message #%i does not exist in folder \"%s\".", (int)server_uid, folder);
		goto cleanup; /* server response is fine, however, there is no such message, do not try to fetch the message again */
	}

	struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur);
	peek_body(msg_att, &msg_content, &msg_bytes, &flags, &deleted);
	if( msg_content == NULL  || msg_bytes <= 0 || deleted ) {
		/* mrmailbox_log_warning(ths->m_mailbox, 0, "Message #%i in folder \"%s\" is empty or deleted.", (int)server_uid, folder); -- this is a quite usual situation, do not print a warning */
		goto cleanup;
	}

	ths->m_receive_imf(ths, msg_content, msg_bytes, folder, server_uid, flags);

cleanup:
	if( block_idle ) {
		UNBLOCK_IDLE
	}
	UNLOCK_HANDLE

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}
	return retry_later? 0 : 1;
}


static int fetch_from_single_folder(mrimap_t* ths, const char* folder)
{
	int                  r, handle_locked = 0;
	uint32_t             uidvalidity = 0;
	uint32_t             lastseenuid = 0, new_lastseenuid = 0;
	clist*               fetch_result = NULL;
	size_t               read_cnt = 0, read_errors = 0;
	clistiter*           cur;
	struct mailimap_set* set;

	if( ths==NULL ) {
		goto cleanup;
	}

	LOCK_HANDLE

		if( ths->m_hEtpan==NULL ) {
			mrmailbox_log_info(ths->m_mailbox, 0, "Cannot fetch from \"%s\" - not connected.", folder);
			goto cleanup;
		}

		if( select_folder__(ths, folder)==0 ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot select folder \"%s\".", folder);
			goto cleanup;
		}

		/* compare last seen UIDVALIDITY against the current one */
		get_config_lastseenuid(ths, folder, &uidvalidity, &lastseenuid);
		if( uidvalidity != ths->m_hEtpan->imap_selection_info->sel_uidvalidity )
		{
			/* first time this folder is selected or UIDVALIDITY has changed, init lastseenuid and save it to config */
			mrmailbox_log_info(ths->m_mailbox, 0, "Init lastseenuid and attach it to UIDVALIDITY for folder \"%s\".", folder);
			if( ths->m_hEtpan->imap_selection_info->sel_uidvalidity <= 0 ) {
				mrmailbox_log_error(ths->m_mailbox, 0, "Cannot get UIDVALIDITY for folder \"%s\".", folder);
				goto cleanup;
			}

			if( ths->m_hEtpan->imap_selection_info->sel_has_exists ) {
				if( ths->m_hEtpan->imap_selection_info->sel_exists <= 0 ) {
					mrmailbox_log_info(ths->m_mailbox, 0, "Folder \"%s\" is empty.", folder);
					goto cleanup;
				}
				/* `FETCH <message sequence number> (UID)` */
				set = mailimap_set_new_single(ths->m_hEtpan->imap_selection_info->sel_exists);
			}
			else {
				/* `FETCH * (UID)` - according to RFC 3501, `*` represents the largest message sequence number; if the mailbox is empty,
				an error resp. an empty list is returned. */
                mrmailbox_log_info(ths->m_mailbox, 0, "EXISTS is missing for folder \"%s\", using fallback.", folder);
				set = mailimap_set_new_single(0);
			}
			r = mailimap_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result);
			mailimap_set_free(set);

			if( is_error(ths, r) || fetch_result==NULL || (cur=clist_begin(fetch_result))==NULL ) {
				mrmailbox_log_info(ths->m_mailbox, 0, "Empty result returned for folder \"%s\".", folder);
				goto cleanup; /* this might happen if the mailbox is empty an EXISTS does not work */
			}

			struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur);
			lastseenuid = peek_uid(msg_att);
			mailimap_fetch_list_free(fetch_result);
			fetch_result = NULL;
			if( lastseenuid <= 0 ) {
				mrmailbox_log_error(ths->m_mailbox, 0, "Cannot get largest UID for folder \"%s\"", folder);
				goto cleanup;
			}

			/* if the UIDVALIDITY has _changed_, decrease lastseenuid by one to avoid gaps (well add 1 below) */
			if( uidvalidity > 0 && lastseenuid > 1 ) {
				lastseenuid -= 1;
			}

			/* store calculated uidvalidity/lastseenuid */
			uidvalidity = ths->m_hEtpan->imap_selection_info->sel_uidvalidity;
			set_config_lastseenuid(ths, folder, uidvalidity, lastseenuid);
		}

		/* fetch messages with larger UID than the last one seen (`UID FETCH lastseenuid+1:*)`, see RFC 4549 */
		set = mailimap_set_new_interval(lastseenuid+1, 0);
			r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_uid, &fetch_result);
		mailimap_set_free(set);

	UNLOCK_HANDLE

	if( is_error(ths, r) || fetch_result == NULL )
	{
		fetch_result = NULL;
		if( r == MAILIMAP_ERROR_PROTOCOL ) {
			mrmailbox_log_info(ths->m_mailbox, 0, "Folder \"%s\" is empty", folder);
			goto cleanup; /* the folder is simply empty, this is no error */
		}
		mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot fetch message list from folder \"%s\".", folder);
		goto cleanup;
	}

	/* go through all mails in folder (this is typically _fast_ as we already have the whole list) */
	for( cur = clist_begin(fetch_result); cur != NULL ; cur = clist_next(cur) )
	{
		struct mailimap_msg_att* msg_att = (struct mailimap_msg_att*)clist_content(cur); /* mailimap_msg_att is a list of attributes: list is a list of message attributes */
		uint32_t cur_uid = peek_uid(msg_att);
		if( cur_uid > 0
		 && cur_uid!=lastseenuid /* `UID FETCH <lastseenuid+1>:*` may include lastseenuid if "*" == lastseenuid */ )
		{
			read_cnt++;
			if( fetch_single_msg(ths, folder, cur_uid, 0) == 0/* 0=try again later*/ ) {
				read_errors++;
			}
			else if( cur_uid > new_lastseenuid ) {
				new_lastseenuid = cur_uid;
			}

		}
	}

	if( !read_errors && new_lastseenuid > 0 ) {
		set_config_lastseenuid(ths, folder, uidvalidity, new_lastseenuid);
	}

	/* done */
cleanup:
	UNLOCK_HANDLE

	{
		char* temp = mr_mprintf("%i mails read from \"%s\" with %i errors.", (int)read_cnt, folder, (int)read_errors);
		if( read_errors ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, temp);
		}
		else {
			mrmailbox_log_info(ths->m_mailbox, 0, temp);
		}
		free(temp);
	}

	if( fetch_result ) {
		mailimap_fetch_list_free(fetch_result);
	}

	return read_cnt;
}


static int fetch_from_all_folders(mrimap_t* ths)
{
	int        handle_locked = 0;
	clist*     folder_list = NULL;
	clistiter* cur;
	int        total_cnt = 0;

	mrmailbox_log_info(ths->m_mailbox, 0, "Fetching from all folders.");

	LOCK_HANDLE
		folder_list = list_folders__(ths);
	UNLOCK_HANDLE

	/* first, read the INBOX, this looks much better on the initial load as the INBOX
	has the most recent mails.  Moreover, this is for speed reasons, as the other folders only have few new messages. */
	for( cur = clist_begin(folder_list); cur != NULL ; cur = clist_next(cur) )
	{
		mrimapfolder_t* folder = (mrimapfolder_t*)clist_content(cur);
		if( folder->m_meaning == MEANING_INBOX ) {
			total_cnt += fetch_from_single_folder(ths, folder->m_name_to_select);
		}
	}

	for( cur = clist_begin(folder_list); cur != NULL ; cur = clist_next(cur) )
	{
		mrimapfolder_t* folder = (mrimapfolder_t*)clist_content(cur);
		if( folder->m_meaning == MEANING_IGNORE ) {
			mrmailbox_log_info(ths->m_mailbox, 0, "Folder \"%s\" ignored.", folder->m_name_utf8);
		}
		else if( folder->m_meaning != MEANING_INBOX ) {
			total_cnt += fetch_from_single_folder(ths, folder->m_name_to_select);
		}
	}

	free_folders(folder_list);

	return total_cnt;
}


/*******************************************************************************
 * Watch thread
 ******************************************************************************/


static void* watch_thread_entry_point(void* entry_arg)
{
	mrimap_t*       ths = (mrimap_t*)entry_arg;
	mrosnative_setup_thread(ths->m_mailbox); /* must be very first */

	int             handle_locked = 0, idle_blocked = 0, force_sleep = 0, do_fetch = 0;
	#define         SLEEP_ON_ERROR_SECONDS     10
	#define         SLEEP_ON_INTERRUPT_SECONDS  2      /* give the job thread a little time before we IDLE again, otherwise there will be many idle-interrupt sequences */
	#define         IDLE_DELAY_SECONDS         (28*60) /* 28 minutes is a typical maximum, most servers do not allow more. if the delay is reached, we also check _all_ folders. */
	#define         FULL_FETCH_EVERY_SECONDS   (27*60) /* force a full fetch every 27 minutes (typically together with the IDLE delay break) */

	time_t          last_fullread_time = 0;

	mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-watch-thread started.");

	if( ths->m_can_idle )
	{
		/* watch using IDLE
		 **********************************************************************/

		int      r, r2;

		fetch_from_all_folders(ths); /* the initial fetch from all folders is needed as this will init the folder UIDs (see fetch_from_single_folder() if lastuid is unset) */
		last_fullread_time = time(NULL);

		while( 1 )
		{
			if( ths->m_watch_do_exit ) {
				goto exit_;
			}

			BLOCK_IDLE /* must be done before LOCK_HANDLE; this allows other threads to block IDLE */
			LOCK_HANDLE

				do_fetch = 0;
				force_sleep = SLEEP_ON_ERROR_SECONDS;

				setup_handle_if_needed__(ths);
				if( ths->m_idle_set_up==0 && ths->m_hEtpan && ths->m_hEtpan->imap_stream ) {
					if( time(NULL)-last_fullread_time > FULL_FETCH_EVERY_SECONDS ) {
						/* we go here only if we get MAILSTREAM_IDLE_ERROR or MAILSTREAM_IDLE_CANCELLED instead or a proper timeout */
						UNLOCK_HANDLE
						UNBLOCK_IDLE
							fetch_from_all_folders(ths);
						BLOCK_IDLE
						LOCK_HANDLE
						last_fullread_time = time(NULL);
					}
					mailstream_setup_idle(ths->m_hEtpan->imap_stream);
					ths->m_idle_set_up = 1;
				}

				if( select_folder__(ths, "INBOX") )
				{
					r = mailimap_idle(ths->m_hEtpan);
					if( !is_error(ths, r) )
					{
						mrmailbox_log_info(ths->m_mailbox, 0, "IDLE start...");

						ths->m_enter_watch_wait_time = time(NULL);

						UNLOCK_HANDLE
						UNBLOCK_IDLE

							pthread_mutex_lock(&ths->m_inwait_mutex);
								r = 0; r2 = 0;
								if( ths->m_hEtpan ) {
									r = mailstream_wait_idle(ths->m_hEtpan->imap_stream, IDLE_DELAY_SECONDS);
									r2 = mailimap_idle_done(ths->m_hEtpan); /* it's okay to use the handle without locking as we're inwait */
								}
							pthread_mutex_unlock(&ths->m_inwait_mutex);
							force_sleep = 0;

							if( r == MAILSTREAM_IDLE_ERROR /*0*/ || r==MAILSTREAM_IDLE_CANCELLED /*4*/ ) {
								mrmailbox_log_info(ths->m_mailbox, 0, "IDLE wait cancelled, r=%i, r2=%i; we'll reconnect soon.", (int)r, (int)r2);
								force_sleep = SLEEP_ON_ERROR_SECONDS;
								ths->m_should_reconnect = 1;
							}
							else if( r == MAILSTREAM_IDLE_INTERRUPTED /*1*/ ) {
								mrmailbox_log_info(ths->m_mailbox, 0, "IDLE interrupted.");
								force_sleep = SLEEP_ON_INTERRUPT_SECONDS;
							}
							else if( r ==  MAILSTREAM_IDLE_HASDATA /*2*/ ) {
								mrmailbox_log_info(ths->m_mailbox, 0, "IDLE has data.");
								do_fetch = 1;
							}
							else if( r == MAILSTREAM_IDLE_TIMEOUT /*3*/ ) {
								mrmailbox_log_info(ths->m_mailbox, 0, "IDLE timeout.");
								do_fetch = 1;
							}

							if( is_error(ths, r2) ) {
								do_fetch = 0;
							}

							if( ths->m_watch_do_exit ) { /* check after is_error() to allow reconnections on errors */
								goto exit_;
							}

						BLOCK_IDLE
						LOCK_HANDLE

						ths->m_enter_watch_wait_time = 0;
					}
				}

			UNLOCK_HANDLE
			UNBLOCK_IDLE

			if( do_fetch == 1 && time(NULL)-last_fullread_time > FULL_FETCH_EVERY_SECONDS ) {
				do_fetch = 2;
			}

			if( do_fetch == 1 ) {
				fetch_from_single_folder(ths, "INBOX");
			}
			else if( do_fetch == 2 ) {
				fetch_from_all_folders(ths);
				last_fullread_time = time(NULL);
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

		mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-watch-thread will poll for messages.");
		time_t last_message_time=time(NULL), now, seconds_to_wait;
		while( 1 )
		{
			/* get the latest messages */
			now = time(NULL);

			do_fetch = 1;
			if( now-last_fullread_time > FULL_FETCH_EVERY_SECONDS ) {
				do_fetch = 2;
			}

			LOCK_HANDLE
				setup_handle_if_needed__(ths);
				forget_folder_selection__(ths); /* seems to be needed - otherwise, we'll get a new message only every _twice_ polls. WTF? */
			UNLOCK_HANDLE

			if( do_fetch == 1 ) {
				if( fetch_from_single_folder(ths, "INBOX") > 0 ) {
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

			#ifdef __APPLE__
			seconds_to_wait = 10; // HACK to force iOS not to work IMAP-IDLE which does not work for now, see also (*)
			#endif

			/* wait */
			mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-watch-thread waits %i seconds.", (int)seconds_to_wait);
			pthread_mutex_lock(&ths->m_watch_condmutex);

				if( ths->m_watch_condflag == 0 ) {
					struct timespec timeToWait;
					timeToWait.tv_sec  = time(NULL)+seconds_to_wait;
					timeToWait.tv_nsec = 0;

					LOCK_HANDLE
						ths->m_enter_watch_wait_time = time(NULL);
					UNLOCK_HANDLE

					pthread_cond_timedwait(&ths->m_watch_cond, &ths->m_watch_condmutex, &timeToWait); /* unlock mutex -> wait -> lock mutex */

					LOCK_HANDLE
						ths->m_enter_watch_wait_time = 0;
					UNLOCK_HANDLE
				}
				ths->m_watch_condflag = 0;

				if( ths->m_watch_do_exit ) {
					pthread_mutex_unlock(&ths->m_watch_condmutex);
					goto exit_;
				}

			pthread_mutex_unlock(&ths->m_watch_condmutex);
		}
	}

exit_:
	ths->m_enter_watch_wait_time = 0;

	UNLOCK_HANDLE
	UNBLOCK_IDLE

	mrosnative_unsetup_thread(ths->m_mailbox); /* must be very last */
	return NULL;
}


void mrimap_heartbeat(mrimap_t* ths)
{
	/* the function */
	int handle_locked = 0, idle_blocked = 0;

	if( ths == NULL ) {
		return;
	}

	LOCK_HANDLE

		if( ths->m_hEtpan == NULL || ths->m_should_reconnect == 1 ) {
			goto cleanup;
		}

		if( ths->m_enter_watch_wait_time != 0
		 && time(NULL)-ths->m_enter_watch_wait_time > (IDLE_DELAY_SECONDS+60) )
		{
			/* force reconnect if the IDLE timeout does not arrive */
			mrmailbox_log_info(ths->m_mailbox, 0, "Reconnect forced from the heartbeat thread.");
			ths->m_should_reconnect = 1;
			ths->m_enter_watch_wait_time = 0;
			if( ths->m_can_idle )
			{
				/* the handle must be LOCKED when calling BLOCK_IDLE */
				BLOCK_IDLE
					INTERRUPT_IDLE
				UNBLOCK_IDLE
			}
			else
			{
				UNLOCK_HANDLE

				pthread_mutex_lock(&ths->m_watch_condmutex);
					ths->m_watch_condflag = 1;
					pthread_cond_signal(&ths->m_watch_cond);
				pthread_mutex_unlock(&ths->m_watch_condmutex);
			}
		}

cleanup:
	UNLOCK_HANDLE
}


/*******************************************************************************
 * Setup handle
 ******************************************************************************/


static int setup_handle_if_needed__(mrimap_t* ths)
{
	int r, success = 0;

	if( ths==NULL ) {
		goto cleanup;
	}

    if( ths->m_should_reconnect ) {
		unsetup_handle__(ths);
    }

    if( ths->m_hEtpan ) {
		success = 1;
		goto cleanup;
    }

	if( ths->m_mailbox->m_cb(ths->m_mailbox, MR_EVENT_IS_OFFLINE, 0, 0)!=0 ) {
		mrmailbox_log_error_if(&ths->m_log_connect_errors, ths->m_mailbox, MR_ERR_NONETWORK, NULL);
		goto cleanup;
	}

	ths->m_hEtpan = mailimap_new(0, NULL);

	mailimap_set_timeout(ths->m_hEtpan, 30); /* 30 seconds until actions are aborted, this is also used in mailcore2 */

	if( ths->m_server_flags&(MR_IMAP_SOCKET_STARTTLS|MR_IMAP_SOCKET_PLAIN) )
	{
		mrmailbox_log_info(ths->m_mailbox, 0, "Connecting to IMAP-server \"%s:%i\"...", ths->m_imap_server, (int)ths->m_imap_port);
		r = mailimap_socket_connect(ths->m_hEtpan, ths->m_imap_server, ths->m_imap_port);
		if( is_error(ths, r) ) {
			mrmailbox_log_error_if(&ths->m_log_connect_errors, ths->m_mailbox, 0, "Could not connect to IMAP-server \"%s:%i\". (Error #%i)", ths->m_imap_server, (int)ths->m_imap_port, (int)r);
			goto cleanup;
		}

		if( ths->m_server_flags&MR_IMAP_SOCKET_STARTTLS )
		{
			mrmailbox_log_info(ths->m_mailbox, 0, "Switching to IMAP-STARTTLS.", ths->m_imap_server, (int)ths->m_imap_port);
			r = mailimap_socket_starttls(ths->m_hEtpan);
			if( is_error(ths, r) ) {
				mrmailbox_log_error_if(&ths->m_log_connect_errors, ths->m_mailbox, 0, "Could not connect to IMAP-server \"%s:%i\" using STARTTLS. (Error #%i)", ths->m_imap_server, (int)ths->m_imap_port, (int)r);
				goto cleanup;
			}
		}
	}
	else
	{
		mrmailbox_log_info(ths->m_mailbox, 0, "Connecting to IMAP-server \"%s:%i\" via SSL...", ths->m_imap_server, (int)ths->m_imap_port);
		r = mailimap_ssl_connect(ths->m_hEtpan, ths->m_imap_server, ths->m_imap_port);
		if( is_error(ths, r) ) {
			mrmailbox_log_error_if(&ths->m_log_connect_errors, ths->m_mailbox, 0, "Could not connect to IMAP-server \"%s:%i\" using SSL. (Error #%i)", ths->m_imap_server, (int)ths->m_imap_port, (int)r);
			goto cleanup;
		}
	}
	mrmailbox_log_info(ths->m_mailbox, 0, "Connection to IMAP-server ok.");

	mrmailbox_log_info(ths->m_mailbox, 0, "Login to IMAP-server as \"%s\"...", ths->m_imap_user);

		/* TODO: There are more authorisation types, see mailcore2/MCIMAPSession.cpp, however, I'm not sure of they are really all needed */
		/*if( ths->m_server_flags&MR_AUTH_XOAUTH2 )
		{
			//TODO: Support XOAUTH2, we "just" need to get the token someway. If we do so, there is no more need for the user to enable
			//https://www.google.com/settings/security/lesssecureapps - however, maybe this is also not needed if the user had enabled 2-factor-authorisation.
			if (mOAuth2Token == NULL) {
				r = MAILIMAP_ERROR_STREAM;
			}
			else {
				r = mailimap_oauth2_authenticate(ths->m_hEtpan, ths->m_imap_use, mOAuth2Token);
			}
		}
		else*/
		{
			/* MR_AUTH_NORMAL or no auth flag set */
			r = mailimap_login(ths->m_hEtpan, ths->m_imap_user, ths->m_imap_pw);
		}

		if( is_error(ths, r) ) {
			mrmailbox_log_error_if(&ths->m_log_connect_errors, ths->m_mailbox, 0, "Could not login: %s (Error #%i)", ths->m_hEtpan->imap_response? ths->m_hEtpan->imap_response : "Unknown error.", (int)r);
			goto cleanup;
		}

	mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-Login ok.");

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
	if( ths==NULL ) {
		return;
	}

	if( ths->m_hEtpan )
	{
		mrmailbox_log_info(ths->m_mailbox, 0, "Disconnecting...");

			if( ths->m_idle_set_up ) {
				mailstream_unsetup_idle(ths->m_hEtpan->imap_stream);
				ths->m_idle_set_up = 0;
			}

			if( ths->m_hEtpan->imap_stream != NULL ) {
				mailstream_close(ths->m_hEtpan->imap_stream); /* not sure, if this is really needed, however, mailcore2 does the same */
				ths->m_hEtpan->imap_stream = NULL;
			}

			mailimap_free(ths->m_hEtpan);
			ths->m_hEtpan = NULL;

		mrmailbox_log_info(ths->m_mailbox, 0, "Disconnect done.");
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

	if( ths==NULL || lp==NULL || lp->m_mail_server==NULL || lp->m_mail_user==NULL || lp->m_mail_pw==NULL ) {
		return 0;
	}

	LOCK_HANDLE

		if( ths->m_connected ) {
			success = 1;
			goto cleanup;
		}

		free(ths->m_imap_server); ths->m_imap_server  = safe_strdup(lp->m_mail_server);
		                          ths->m_imap_port    = lp->m_mail_port;
		free(ths->m_imap_user);   ths->m_imap_user    = safe_strdup(lp->m_mail_user);
		free(ths->m_imap_pw);     ths->m_imap_pw      = safe_strdup(lp->m_mail_pw);
		                          ths->m_server_flags = lp->m_server_flags;

		if( !setup_handle_if_needed__(ths) ) {
			goto cleanup;
		}

		ths->m_connected = 1;

		/* we set the following flags here and not in setup_handle_if_needed__() as they must not change during connection */
		ths->m_can_idle = mailimap_has_idle(ths->m_hEtpan);
		ths->m_has_xlist = mailimap_has_xlist(ths->m_hEtpan);

		#ifdef __APPLE__
		ths->m_can_idle = 0; // HACK to force iOS not to work IMAP-IDLE which does not work for now, see also (*)
		#endif


		if( ths->m_hEtpan->imap_connection_info && ths->m_hEtpan->imap_connection_info->imap_capability ) {
			/* just log the whole capabilities list (the mailimap_has_*() function also use this list, so this is a good overview on problems) */
			mrstrbuilder_t capinfostr;
			mrstrbuilder_init(&capinfostr, 0);
			clist* list = ths->m_hEtpan->imap_connection_info->imap_capability->cap_list;
			if( list ) {
				clistiter* cur;
				for(cur = clist_begin(list) ; cur != NULL ; cur = clist_next(cur)) {
					struct mailimap_capability * cap = clist_content(cur);
					if( cap && cap->cap_type == MAILIMAP_CAPABILITY_NAME ) {
						mrstrbuilder_cat(&capinfostr, " ");
						mrstrbuilder_cat(&capinfostr, cap->cap_data.cap_name);
					}
				}
			}
			mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-Capabilities:%s", capinfostr.m_buf);
			free(capinfostr.m_buf);
		}

	UNLOCK_HANDLE

	success = 1;

cleanup:
	if( success == 0 ) {
		unsetup_handle__(ths);
	}
	UNLOCK_HANDLE
	return success;
}


void mrimap_start_watch_thread(mrimap_t* ths)
{
	int handle_locked = 0;

	if( ths == NULL ) {
		goto cleanup;
	}

	mrmailbox_log_info(ths->m_mailbox, 0, "Starting IMAP-watch-thread...");

	LOCK_HANDLE
		if( !ths->m_connected || ths->m_watch_thread_started ) {
			goto cleanup;
		}
		ths->m_watch_thread_started = 1;
		ths->m_watch_do_exit        = 0;
	UNLOCK_HANDLE

	pthread_create(&ths->m_watch_thread, NULL, watch_thread_entry_point, ths);

cleanup:
	UNLOCK_HANDLE
}


void mrimap_disconnect(mrimap_t* ths)
{
	int handle_locked = 0, connected = 0, watch_thread_started = 0;

	if( ths==NULL ) {
		return;
	}

	LOCK_HANDLE
		connected = (ths->m_hEtpan && ths->m_connected);
		watch_thread_started = (ths->m_hEtpan && ths->m_watch_thread_started);
	UNLOCK_HANDLE

	if( watch_thread_started )
	{
		mrmailbox_log_info(ths->m_mailbox, 0, "Stopping IMAP-watch-thread...");

			/* prepare for exit */
			if( ths->m_can_idle && ths->m_hEtpan->imap_stream )
			{
				ths->m_watch_do_exit = 1;

				LOCK_HANDLE
					mrmailbox_log_info(ths->m_mailbox, 0, "Interrupting IDLE for disconnecting...");
					mailstream_interrupt_idle(ths->m_hEtpan->imap_stream);
				UNLOCK_HANDLE
			}
			else
			{
				pthread_mutex_lock(&ths->m_watch_condmutex);
					ths->m_watch_condflag = 1;
					ths->m_watch_do_exit  = 1;
					pthread_cond_signal(&ths->m_watch_cond);
				pthread_mutex_unlock(&ths->m_watch_condmutex);
			}

			/* wait for the threads to terminate */
			pthread_join(ths->m_watch_thread, NULL);

			LOCK_HANDLE
				ths->m_watch_thread_started = 0;
			UNLOCK_HANDLE

		mrmailbox_log_info(ths->m_mailbox, 0, "IMAP-watch-thread stopped.");
	}

	if( connected )
	{
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


mrimap_t* mrimap_new(mr_get_config_t get_config, mr_set_config_t set_config, mr_receive_imf_t receive_imf, void* userData, mrmailbox_t* mailbox)
{
	mrimap_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrimap_t)))==NULL ) {
		exit(25); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_log_connect_errors = 1;

	ths->m_mailbox        = mailbox;
	ths->m_get_config     = get_config;
	ths->m_set_config     = set_config;
	ths->m_receive_imf    = receive_imf;
	ths->m_userData       = userData;

	pthread_mutex_init(&ths->m_hEtpanmutex, NULL);
	pthread_mutex_init(&ths->m_idlemutex, NULL);
	pthread_mutex_init(&ths->m_inwait_mutex, NULL);
	pthread_mutex_init(&ths->m_watch_condmutex, NULL);
	pthread_cond_init(&ths->m_watch_cond, NULL);

	ths->m_enter_watch_wait_time = 0;

	ths->m_selected_folder = calloc(1, 1);
	ths->m_moveto_folder   = NULL;
	ths->m_sent_folder     = NULL;

	/* create some useful objects */
	ths->m_fetch_type_uid = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch the ID */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_uid, mailimap_fetch_att_new_uid());


	ths->m_fetch_type_message_id = mailimap_fetch_type_new_fetch_att_list_empty();
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_message_id, mailimap_fetch_att_new_envelope());
	/*clist* hdrlist = clist_new();
	clist_append(hdrlist, strdup("Message-ID"));
	struct mailimap_header_list* imap_hdrlist = mailimap_header_list_new(hdrlist);
	struct mailimap_section* section = mailimap_section_new_header_fields(imap_hdrlist);
	struct mailimap_fetch_att* fetch_att = mailimap_fetch_att_new_body_peek_section(section);
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_message_id, fetch_att);*/


	ths->m_fetch_type_body = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch flags+body */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_body, mailimap_fetch_att_new_flags());
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_body, mailimap_fetch_att_new_body_peek_section(mailimap_section_new(NULL)));

	ths->m_fetch_type_flags = mailimap_fetch_type_new_fetch_att_list_empty(); /* object to fetch flags only */
	mailimap_fetch_type_new_fetch_att_list_add(ths->m_fetch_type_flags, mailimap_fetch_att_new_flags());

    return ths;
}


void mrimap_unref(mrimap_t* ths)
{
	if( ths==NULL ) {
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
	if( ths->m_fetch_type_flags ){ mailimap_fetch_type_free(ths->m_fetch_type_flags);}

	free(ths);
}


int mrimap_fetch(mrimap_t* ths)
{
	if( ths==NULL || !ths->m_connected ) {
		return 0;
	}

	fetch_from_single_folder(ths, "INBOX");

	return 1;
}


int mrimap_append_msg(mrimap_t* ths, time_t timestamp, const char* data_not_terminated, size_t data_bytes, char** ret_server_folder, uint32_t* ret_server_uid)
{
	int                        success = 0, handle_locked = 0, idle_blocked = 0, r;
	uint32_t                   ret_uidvalidity = 0;
	struct mailimap_flag_list* flag_list = NULL;
	struct mailimap_date_time* imap_date = NULL;

	*ret_server_folder = NULL;

	if( ths==NULL ) {
		goto cleanup;
	}

	LOCK_HANDLE

	if( ths->m_hEtpan==NULL ) {
		goto cleanup;
	}

	BLOCK_IDLE

		INTERRUPT_IDLE

		mrmailbox_log_info(ths->m_mailbox, 0, "Appending message to IMAP-server...");

		if( !init_chat_folders__(ths) ) {
			mrmailbox_log_error(ths->m_mailbox, 0, "Cannot find out IMAP-sent-folder.");
			goto cleanup;
		}

		if( !select_folder__(ths, ths->m_sent_folder) ) {
			mrmailbox_log_error(ths->m_mailbox, 0, "Cannot select IMAP-folder \"%s\".", ths->m_sent_folder);
			ths->m_sent_folder[0] = 0; /* force re-init */
			goto cleanup;
		}

		flag_list = mailimap_flag_list_new_empty();
		mailimap_flag_list_add(flag_list, mailimap_flag_new_seen());

		imap_date = mr_timestamp_to_mailimap_date_time(timestamp);
		if( imap_date == NULL ) {
			mrmailbox_log_error(ths->m_mailbox, 0, "Bad date.");
			goto cleanup;
		}

		r = mailimap_uidplus_append(ths->m_hEtpan, ths->m_sent_folder, flag_list, imap_date, data_not_terminated, data_bytes, &ret_uidvalidity, ret_server_uid);
		if( is_error(ths, r) ) {
			mrmailbox_log_error(ths->m_mailbox, 0, "Cannot append message to \"%s\", error #%i.", ths->m_sent_folder, (int)r);
			goto cleanup;
		}

		*ret_server_folder = safe_strdup(ths->m_sent_folder);

		mrmailbox_log_info(ths->m_mailbox, 0, "Message appended to \"%s\".", ths->m_sent_folder);

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


static int add_flag__(mrimap_t* ths, uint32_t server_uid, struct mailimap_flag* flag)
{
	int                              r;
	struct mailimap_flag_list*       flag_list = NULL;
	struct mailimap_store_att_flags* store_att_flags = NULL;
	struct mailimap_set*             set = mailimap_set_new_single(server_uid);

	if( ths==NULL || ths->m_hEtpan==NULL ) {
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
	if( store_att_flags ) {
		mailimap_store_att_flags_free(store_att_flags);
	}
	if( set ) {
		mailimap_set_free(set);
	}
	return ths->m_should_reconnect? 0 : 1; /* all non-connection states are treated as success - the mail may already be deleted or moved away on the server */
}


int mrimap_markseen_msg(mrimap_t* ths, const char* folder, uint32_t server_uid, int ms_flags,
                        char** ret_server_folder, uint32_t* ret_server_uid, int* ret_ms_flags)
{
	// when marking as seen, there is no real need to check against the rfc724_mid - in the worst case, when the UID validity or the mailbox has changed, we mark the wrong message as "seen" - as the very most messages are seen, this is no big thing.
	// command would be "STORE 123,456,678 +FLAGS (\Seen)"
	int                  handle_locked = 0, idle_blocked = 0, r;
	struct mailimap_set* set = NULL;

	if( ths==NULL || folder==NULL || server_uid==0 || ret_server_folder==NULL || ret_server_uid==NULL || ret_ms_flags==NULL
	 || *ret_server_folder!=NULL || *ret_server_uid!=0 || *ret_ms_flags!=0 ) {
		return 1; /* job done */
	}

	if( (set=mailimap_set_new_single(server_uid))==NULL ) {
		goto cleanup;
	}

	LOCK_HANDLE

	if( ths->m_hEtpan==NULL ) {
		goto cleanup;
	}

	BLOCK_IDLE

		INTERRUPT_IDLE

		mrmailbox_log_info(ths->m_mailbox, 0, "Marking message %s/%i as seen...", folder, (int)server_uid);

		if( select_folder__(ths, folder)==0 ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot select folder.");
			goto cleanup;
		}

		if( add_flag__(ths, server_uid, mailimap_flag_new_seen())==0 ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot mark message as seen.");
			goto cleanup;
		}

		mrmailbox_log_info(ths->m_mailbox, 0, "Message marked as seen.");

		if( (ms_flags&MR_MS_SET_MDNSent_FLAG)
		 && ths->m_hEtpan->imap_selection_info!=NULL && ths->m_hEtpan->imap_selection_info->sel_perm_flags!=NULL )
		{
			/* Check if the folder can handle the `$MDNSent` flag (see RFC 3503).  If so, and not set: set the flags and return this information.
			If the folder cannot handle the `$MDNSent` flag, we risk duplicated MDNs; it's up to the receiving MUA to handle this then (eg. Delta Chat has no problem with this). */
			int can_create_flag = 0;
			clistiter* iter;
			for( iter=clist_begin(ths->m_hEtpan->imap_selection_info->sel_perm_flags); iter!=NULL; iter=clist_next(iter) )
			{
				struct mailimap_flag_perm* fp = (struct mailimap_flag_perm*)clist_content(iter);
				if( fp ) {
					if( fp->fl_type==MAILIMAP_FLAG_PERM_ALL ) {
						can_create_flag = 1;
						break;
					}
					else if( fp->fl_type==MAILIMAP_FLAG_PERM_FLAG && fp->fl_flag ) {
						struct mailimap_flag* fl = (struct mailimap_flag*)fp->fl_flag;
						if( fl->fl_type==MAILIMAP_FLAG_KEYWORD && fl->fl_data.fl_keyword && strcmp(fl->fl_data.fl_keyword, "$MDNSent")==0 ) {
							can_create_flag = 1;
							break;
						}
					}
				}
			}

			if( can_create_flag )
			{
				clist* fetch_result = NULL;
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_flags, &fetch_result);
				if( !is_error(ths, r) && fetch_result ) {
					clistiter* cur=clist_begin(fetch_result);
					if( cur ) {
						if( !peek_flag_keyword((struct mailimap_msg_att*)clist_content(cur), "$MDNSent") ) {
							add_flag__(ths, server_uid, mailimap_flag_new_flag_keyword(safe_strdup("$MDNSent")));
							*ret_ms_flags |= MR_MS_MDNSent_JUST_SET;
						}
					}
					mailimap_fetch_list_free(fetch_result);
				}
				mrmailbox_log_info(ths->m_mailbox, 0, ((*ret_ms_flags)&MR_MS_MDNSent_JUST_SET)? "$MDNSent just set and MDN will be sent." : "$MDNSent already set and MDN already sent.");
			}
			else
			{
				*ret_ms_flags |= MR_MS_MDNSent_JUST_SET;
				mrmailbox_log_info(ths->m_mailbox, 0, "Cannot store $MDNSent flags, risk sending duplicate MDN.");
			}
		}

		if( (ms_flags&MR_MS_ALSO_MOVE) && (ths->m_server_flags&MR_NO_MOVE_TO_CHATS)==0 )
		{
			init_chat_folders__(ths);
			if( ths->m_moveto_folder && strcmp(folder, ths->m_moveto_folder)==0 )
			{
				mrmailbox_log_info(ths->m_mailbox, 0, "Message %s/%i is already in %s...", folder, (int)server_uid, ths->m_moveto_folder);
				/* avoid deadlocks as moving messages in the same folder may be result in a new server_uid and the state "fresh" -
				we will catch these messages again on the next poll, try to move them away and so on, see also (***) in mrmailbox.c */
			}
			else if( ths->m_moveto_folder )
			{
				mrmailbox_log_info(ths->m_mailbox, 0, "Moving message %s/%i to %s...", folder, (int)server_uid, ths->m_moveto_folder);

				/* TODO/TOCHECK: MOVE may not be supported on servers, if this is often the case, we should fallback to a COPY/DELETE implementation.
				Same for the UIDPLUS extension (if in doubt, we can find out the resulting UID using "imap_selection_info->sel_uidnext" then). */
				uint32_t             res_uid = 0;
				struct mailimap_set* res_setsrc = NULL;
				struct mailimap_set* res_setdest = NULL;
				r = mailimap_uidplus_uid_move(ths->m_hEtpan, set, ths->m_moveto_folder, &res_uid, &res_setsrc, &res_setdest); /* the correct folder is already selected in add_flag__() above */
				if( is_error(ths, r) ) {
					mrmailbox_log_info(ths->m_mailbox, 0, "Cannot move message.");
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

				// TODO: If the new UID is equal to lastuid.Chats, we should increase lastuid.Chats by one
				// (otherwise, we'll download the mail in moment again from the chats folder ...)

				mrmailbox_log_info(ths->m_mailbox, 0, "Message moved.");
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
	int    success = 0, handle_locked = 0, idle_blocked = 0, r = 0;
	clist* fetch_result = NULL;
	char*  is_rfc724_mid = NULL;
	char*  new_folder = NULL;

	if( ths==NULL || rfc724_mid==NULL || folder==NULL || folder[0]==0 ) {
		success = 1; /* job done, do not try over */
		goto cleanup;
	}

	LOCK_HANDLE
	BLOCK_IDLE

		INTERRUPT_IDLE

		mrmailbox_log_info(ths->m_mailbox, 0, "Marking message \"%s\", %s/%i for deletion...", rfc724_mid, folder, (int)server_uid);

		if( select_folder__(ths, folder)==0 ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot select folder \"%s\".", folder); /* maybe the folder does no longer exist */
			goto cleanup;
		}

		/* check if Folder+UID matches the Message-ID (to detect if the messages
		was moved around by other MUAs and in place of an UIDVALIDITY check)
		(we also detect messages moved around when we do a fetch-all, see
		mrmailbox_update_server_uid__() in receive_imf(), however this may take a while) */
		if( server_uid )
		{
			clistiter* cur = NULL;
			const char* is_quoted_rfc724_mid = NULL;
			struct mailimap_set* set = mailimap_set_new_single(server_uid);
				r = mailimap_uid_fetch(ths->m_hEtpan, set, ths->m_fetch_type_message_id, &fetch_result);
			mailimap_set_free(set);
			if( is_error(ths, r) || fetch_result == NULL
			 || (cur=clist_begin(fetch_result)) == NULL
			 || (is_quoted_rfc724_mid=peek_rfc724_mid((struct mailimap_msg_att*)clist_content(cur)))==NULL
			 || (is_rfc724_mid=unquote_rfc724_mid(is_quoted_rfc724_mid))==NULL
			 || strcmp(is_rfc724_mid, rfc724_mid)!=0 )
			{
				mrmailbox_log_warning(ths->m_mailbox, 0, "UID not found in the given folder or does not match Message-ID.");
				server_uid = 0;
			}
		}

		/* server_uid is 0 now if it was not given or if it does not match the given message id;
		try to search for it in all folders (the message may be moved by another MUA to a folder we do not sync or the sync is a moment ago) */
		if( server_uid == 0 ) {
			mrmailbox_log_info(ths->m_mailbox, 0, "Searching UID by Message-ID \"%s\"...", rfc724_mid);
			if( (server_uid=search_uid__(ths, rfc724_mid))==0 ) {
				mrmailbox_log_warning(ths->m_mailbox, 0, "Message-ID \"%s\" not found in any folder, cannot delete message.", rfc724_mid);
				goto cleanup;
			}
			mrmailbox_log_info(ths->m_mailbox, 0, "Message-ID \"%s\" found in %s/%i", rfc724_mid, ths->m_selected_folder, server_uid);
		}


		/* mark the message for deletion */
		if( add_flag__(ths, server_uid, mailimap_flag_new_deleted())==0 ) {
			mrmailbox_log_warning(ths->m_mailbox, 0, "Cannot mark message as \"Deleted\"."); /* maybe the message is already deleted */
			goto cleanup;
		}

		/* force an EXPUNGE resp. CLOSE for the selected folder */
		ths->m_selected_folder_needs_expunge = 1;

		success = 1;

cleanup:
	UNBLOCK_IDLE
	UNLOCK_HANDLE

	if( fetch_result ) { mailimap_fetch_list_free(fetch_result); }
	free(is_rfc724_mid);
	free(new_folder);

	return success? 1 : mrimap_is_connected(ths); /* only return 0 on connection problems; we should try later again in this case */

}

