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
 *******************************************************************************
 *
 * File:    mrmsg.c
 * Purpose: mrmsg_t represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrimap.h"
#include "mrsmtp.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrjob.h"

#define CLASS_MAGIC 1333334140


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrmsg_set_from_stmt__(mrmsg_t* ths, sqlite3_stmt* row, int row_offset) /* field order must be MR_MSG_FIELDS */
{
	mrmsg_empty(ths);

	ths->m_id           =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_rfc724_mid   =  safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_server_folder=  safe_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_server_uid   =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_chat_id      =           (uint32_t)sqlite3_column_int  (row, row_offset++);

	ths->m_from_id      =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_to_id        =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_timestamp    =             (time_t)sqlite3_column_int64(row, row_offset++);

	ths->m_type         =                     sqlite3_column_int  (row, row_offset++);
	ths->m_state        =                     sqlite3_column_int  (row, row_offset++);
	ths->m_is_msgrmsg   =                     sqlite3_column_int  (row, row_offset++);
	ths->m_text         =  safe_strdup((char*)sqlite3_column_text (row, row_offset++));

	mrparam_set_packed(  ths->m_param, (char*)sqlite3_column_text (row, row_offset++));

	if( ths->m_chat_id == MR_CHAT_ID_DEADDROP ) {
		mr_truncate_n_unwrap_str(ths->m_text, 256, 0); /* 256 characters is about a half screen on a 5" smartphone display */
	}

	return 1;
}


int mrmsg_load_from_db__(mrmsg_t* ths, mrmailbox_t* mailbox, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || mailbox==NULL || mailbox->m_sql==NULL ) {
		return 0;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_ircftttstpb_FROM_msg_WHERE_i,
		"SELECT " MR_MSG_FIELDS " FROM msgs m WHERE m.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	if( !mrmsg_set_from_stmt__(ths, stmt, 0) ) { /* also calls mrmsg_empty() */
		return 0;
	}

	ths->m_mailbox = mailbox;

	return 1;
}


void mrmailbox_update_msg_chat_id__(mrmailbox_t* mailbox, uint32_t msg_id, uint32_t chat_id)
{
    sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_msgs_SET_chat_id_WHERE_id,
		"UPDATE msgs SET chat_id=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
}


void mrmailbox_update_msg_state__(mrmailbox_t* mailbox, uint32_t msg_id, int state)
{
    sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_msgs_SET_state_WHERE_id,
		"UPDATE msgs SET state=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, state);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
}


static int mrmailbox_update_msg_state_conditional__(mrmailbox_t* mailbox, uint32_t msg_id, int old_state, int new_state)
{
	/* updates the message state only if the message has an given old state, returns the number of affected rows */
    sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_msgs_SET_state_WHERE_id_AND_state,
		"UPDATE msgs SET state=? WHERE id=? AND state=?;");
	sqlite3_bind_int(stmt, 1, new_state);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_bind_int(stmt, 3, old_state);
	sqlite3_step(stmt);
	return sqlite3_changes(mailbox->m_sql->m_cobj);
}


size_t mrmailbox_get_real_msg_cnt__(mrmailbox_t* mailbox)
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_assigned,
		"SELECT COUNT(*) FROM msgs WHERE id>? AND chat_id>?;");
	sqlite3_bind_int(stmt, 1, MR_MSG_ID_LAST_SPECIAL);
	sqlite3_bind_int(stmt, 2, MR_CHAT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_assigned_msg_cnt_() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


size_t mrmailbox_get_deaddrop_msg_cnt__(mrmailbox_t* mailbox)
{
	if( mailbox==NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_unassigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_DEADDROP);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


int mrmailbox_rfc724_mid_cnt__(mrmailbox_t* mailbox, const char* rfc724_mid)
{
	if( mailbox==NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	/* check the number of messages with the same rfc724_mid */
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_rfc724_mid,
		"SELECT COUNT(*) FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


int mrmailbox_rfc724_mid_exists__(mrmailbox_t* mailbox, const char* rfc724_mid, char** ret_server_folder, uint32_t* ret_server_uid)
{
	/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space) */
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_ss_FROM_msgs_WHERE_m,
		"SELECT server_folder, server_uid FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		*ret_server_folder = NULL;
		*ret_server_uid = 0;
		return 0;
	}

	*ret_server_folder = safe_strdup((char*)sqlite3_column_text(stmt, 0));
	*ret_server_uid = sqlite3_column_int(stmt, 1); /* may be 0 */
	return 1;
}


void mrmailbox_update_server_uid__(mrmailbox_t* mailbox, const char* rfc724_mid, const char* server_folder, uint32_t server_uid)
{
	sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_msgs_SET_ss_WHERE_rfc724_mid,
		"UPDATE msgs SET server_folder=?, server_uid=? WHERE rfc724_mid=?;"); /* we update by "rfc724_mid" instead "id" as there may be several db-entries refering to the same "rfc724_mid" */
	sqlite3_bind_text(stmt, 1, server_folder, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, server_uid);
	sqlite3_bind_text(stmt, 3, rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
}


void mr_guess_msgtype_from_suffix(const char* pathNfilename, int* ret_msgtype, char** ret_mime)
{
	if( pathNfilename == NULL || ret_msgtype == NULL || ret_mime == NULL) {
		return;
	}

	*ret_msgtype = MR_MSG_UNDEFINED;
	*ret_mime = NULL;

	char* s = mr_get_filesuffix_lc(pathNfilename);
	if( s == NULL ) {
		goto cleanup;
	}

	if( strcmp(s, "mp3")==0 ) {
		*ret_msgtype = MR_MSG_AUDIO;
		*ret_mime = safe_strdup("audio/mpeg");
	}
	else if( strcmp(s, "mp4")==0 ) {
		*ret_msgtype = MR_MSG_VIDEO;
		*ret_mime = safe_strdup("video/mp4");
	}
	else if( strcmp(s, "jpg")==0 || strcmp(s, "jpeg")==0 ) {
		*ret_msgtype = MR_MSG_IMAGE;
		*ret_mime = safe_strdup("image/jpeg");
	}
	else if( strcmp(s, "png")==0 ) {
		*ret_msgtype = MR_MSG_IMAGE;
		*ret_mime = safe_strdup("image/png");
	}
	else if( strcmp(s, "gif")==0 ) {
		*ret_msgtype = MR_MSG_GIF;
		*ret_mime = safe_strdup("image/gif");
	}

cleanup:
	free(s);
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrmsg_t* mrmsg_new()
{
	mrmsg_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrmsg_t)))==NULL ) {
		exit(15); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_type      = MR_MSG_UNDEFINED;
	ths->m_state     = MR_STATE_UNDEFINED;
	ths->m_param     = mrparam_new();

	return ths;
}


void mrmsg_unref(mrmsg_t* ths)
{
	if( ths==NULL ) {
		return;
	}

	mrmsg_empty(ths);
	mrparam_unref(ths->m_param);
	free(ths);
}


void mrmsg_empty(mrmsg_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	free(ths->m_text);
	ths->m_text = NULL;

	free(ths->m_rfc724_mid);
	ths->m_rfc724_mid = NULL;

	free(ths->m_server_folder);
	ths->m_server_folder = NULL;

	mrparam_set_packed(ths->m_param, NULL);

	ths->m_mailbox = NULL;
}


mrmsg_t* mrmailbox_get_msg(mrmailbox_t* ths, uint32_t id)
{
	int success = 0;
	int db_locked = 0;
	mrmsg_t* obj = mrmsg_new();

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

		if( !mrmsg_load_from_db__(obj, ths, id) ) {
			goto cleanup;
		}

		success = 1;

cleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( success ) {
		return obj;
	}
	else {
		mrmsg_unref(obj);
		return NULL;
	}
}


char* mrmailbox_get_msg_info(mrmailbox_t* mailbox, uint32_t msg_id)
{
	char*         ret = NULL, *rawtxt = NULL, *timestr = NULL, *file = NULL, *metadata = NULL;
	int           locked = 0;
	sqlite3_stmt* stmt;
	mrmsg_t*      msg = mrmsg_new();

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		mrmsg_load_from_db__(msg, mailbox, msg_id);
		msg_id = mrparam_get_int(msg->m_param, 'G', msg_id);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_txt_raw_FROM_msgs_WHERE_id,
			"SELECT txt_raw FROM msgs WHERE id=?;");
		sqlite3_bind_int(stmt, 1, msg_id);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			ret = mr_mprintf("Cannot load message #%i.", (int)msg_id);
			goto cleanup;
		}

		rawtxt = safe_strdup((char*)sqlite3_column_text(stmt, 0));

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	timestr = mr_timestamp_to_str(msg->m_timestamp);

	file = mrparam_get(msg->m_param, 'f', NULL);
	if( file ) {
		int bytes = mr_get_filebytes(file);
		metadata = mr_mprintf("\nFile: %s\nBytes: %i\nWidth: %i\nHeight: %i\nDuration: %i ms\nType: %i", file? file : "",
			(int)bytes,
			mrparam_get_int(msg->m_param, 'w', 0), mrparam_get_int(msg->m_param, 'h', 0), mrparam_get_int(msg->m_param, 'd', 0), (int)msg->m_type);
	}

	ret = mr_mprintf("Date: %s%s\n\n%s",
		timestr,
		metadata? metadata : "",
		rawtxt);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrmsg_unref(msg);
	free(timestr);
	free(rawtxt);
	free(file);
	free(metadata);
	return ret? ret : safe_strdup(NULL);
}


mrpoortext_t* mrmsg_get_summary(mrmsg_t* msg, const mrchat_t* chat)
{
	mrpoortext_t* ret = mrpoortext_new();
	mrcontact_t*  contact = NULL;

	if( msg==NULL || chat==NULL ) {
		goto cleanup;
	}

	if( msg->m_from_id != MR_CONTACT_ID_SELF  &&  chat->m_type == MR_CHAT_GROUP ) {
		contact = mrmailbox_get_contact(chat->m_mailbox, msg->m_from_id);
	}

	mrpoortext_fill(ret, msg, chat, contact);

cleanup:
	mrcontact_unref(contact);
	return ret;
}


void mr_get_authorNtitle_from_filename(const char* pathNfilename, char** ret_author, char** ret_title)
{
	/* function extracts AUTHOR and TITLE from a path given as `/path/other folder/AUTHOR - TITLE.mp3`
	if the mark ` - ` is not preset, the whole name (without suffix) is used as the title and the author is NULL. */
	char *author = NULL, *title = NULL, *p;
	mr_split_filename(pathNfilename, &title, NULL);
	p = strstr(title, " - ");
	if( p ) {
		*p = 0;
		author = title;
		title  = safe_strdup(&p[3]);
	}

	if( ret_author ) { *ret_author = author; } else { free(author); }
	if( ret_title  ) { *ret_title  = title;  } else { free(title);  }
}


char* mrmsg_get_summarytext(mrmsg_t* msg, int approx_characters)
{
	if( msg==NULL ) {
		return safe_strdup(NULL);
	}

	return mrmsg_get_summarytext_by_raw(msg->m_type, msg->m_text, msg->m_param, approx_characters);
}


char* mrmsg_get_summarytext_by_raw(int type, const char* text, mrparam_t* param, int approx_characters)
{
	char* ret = NULL;
	char* pathNfilename = NULL, *label = NULL, *value = NULL;

	switch( type ) {
		case MR_MSG_IMAGE:
			ret = mrstock_str(MR_STR_IMAGE);
			break;

		case MR_MSG_GIF:
			ret = mrstock_str(MR_STR_GIF);
			break;

		case MR_MSG_VIDEO:
			ret = mrstock_str(MR_STR_VIDEO);
			break;

		case MR_MSG_VOICE:
			ret = mrstock_str(MR_STR_VOICEMESSAGE);
			break;

		case MR_MSG_AUDIO:
			if( (value=mrparam_get(param, 'n', NULL))==NULL ) { /* although we send files with "author - title" in the filename, existing files may follow other conventions, so this lookup is neccessary */
				pathNfilename = mrparam_get(param, 'f', "ErrFilename");
				mr_get_authorNtitle_from_filename(pathNfilename, NULL, &value);
			}
			label = mrstock_str(MR_STR_AUDIO);
			ret = mr_mprintf("%s: %s", label, value);
			break;

		case MR_MSG_FILE:
			pathNfilename = mrparam_get(param, 'f', "ErrFilename");
			value = mr_get_filename(pathNfilename);
			label = mrstock_str(MR_STR_FILE);
			ret = mr_mprintf("%s: %s", label, value);
			break;

		default:
			if( text ) {
				ret = safe_strdup(text);
				mr_truncate_n_unwrap_str(ret, approx_characters, 1);
			}
			break;
	}

	/* cleanup */
	free(pathNfilename);
	free(label);
	free(value);
	if( ret == NULL ) {
		ret = safe_strdup(NULL);
	}
	return ret;
}


char* mrmsg_get_filename(mrmsg_t* msg)
{
	char* ret = NULL, *pathNfilename = NULL;

	if( msg == NULL ) {
		goto cleanup;
	}

	pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
	if( pathNfilename == NULL ) {
		goto cleanup;
	}

	ret = mr_get_filename(pathNfilename);

cleanup:
	free(pathNfilename);
	return ret? ret : safe_strdup(NULL);
}


mrpoortext_t* mrmsg_get_mediainfo(mrmsg_t* msg)
{
	/* Get authorname and trackname of a message.
	- for voice messages, the author the sender and the trackname is the sending time
	- for music messages,
	  - read the information from the filename
	  - for security reasons, we DO NOT read ID3 and such at this stage, the needed libraries may be buggy
		and the whole stuff is way to complicated.
		However, this is not a great disadvantage, as the sender usually sets the filename in a way we expect it -
		if not, we simply print the whole filename as we do it for documents.  All fine in any case :-) */
	mrpoortext_t* ret = mrpoortext_new();
	char *pathNfilename = NULL;
	mrcontact_t* contact = NULL;

	if( msg == NULL || msg->m_mailbox == NULL ) {
		goto cleanup;
	}

	if( msg->m_type == MR_MSG_VOICE )
	{
		if( (contact = mrmailbox_get_contact(msg->m_mailbox, msg->m_from_id))==NULL ) {
			goto cleanup;
		}
		ret->m_text1 = safe_strdup((contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_addr);
		ret->m_text2 = mrstock_str(MR_STR_VOICEMESSAGE);
	}
	else
	{
		ret->m_text1 = mrparam_get(msg->m_param, 'N', NULL);
		ret->m_text2 = mrparam_get(msg->m_param, 'n', NULL);
		if( ret->m_text1 && ret->m_text1[0] && ret->m_text2 && ret->m_text2[0] ) {
			goto cleanup;
		}
		free(ret->m_text1); ret->m_text1 = NULL;
		free(ret->m_text2); ret->m_text2 = NULL;

		pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
		if( pathNfilename == NULL ) {
			goto cleanup;
		}
		mr_get_authorNtitle_from_filename(pathNfilename, &ret->m_text1, &ret->m_text2);
		if( ret->m_text1 == NULL && ret->m_text2 != NULL ) {
			ret->m_text1 = mrstock_str(MR_STR_AUDIO);
		}
	}

cleanup:
	free(pathNfilename);
	mrcontact_unref(contact);
	return ret;
}


int mrmsg_is_increation__(const mrmsg_t* msg)
{
	int is_increation = 0;
	if( MR_MSG_NEEDS_ATTACHMENT(msg->m_type) )
	{
		char* pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
		if( pathNfilename ) {
			char* totest = mr_mprintf("%s.increation", pathNfilename);
			if( mr_file_exist(totest) ) {
				is_increation = 1;
			}
			free(totest);
			free(pathNfilename);
		}
	}
	return is_increation;
}


int mrmsg_is_increation(mrmsg_t* msg) /* surrounds mrmsg_is_increation__() with locking and error checking */
{
	int is_increation = 0;
	if( msg && msg->m_mailbox && MR_MSG_NEEDS_ATTACHMENT(msg->m_type) /*additional check for speed reasons*/ )
	{
		mrsqlite3_lock(msg->m_mailbox->m_sql);
			is_increation = mrmsg_is_increation__(msg);
		mrsqlite3_unlock(msg->m_mailbox->m_sql);
	}
	return is_increation;
}


void mrmsg_save_param_to_disk(mrmsg_t* msg)
{
	if( msg == NULL || msg->m_mailbox == NULL || msg->m_mailbox->m_sql == NULL ) {
		return;
	}

	mrsqlite3_lock(msg->m_mailbox->m_sql);

		sqlite3_stmt* stmt = mrsqlite3_predefine__(msg->m_mailbox->m_sql, UPDATE_msgs_SET_param_WHERE_id,
			"UPDATE msgs SET param=? WHERE id=?;");
		sqlite3_bind_text(stmt, 1, msg->m_param->m_packed, -1, SQLITE_STATIC);
		sqlite3_bind_int (stmt, 2, msg->m_id);
		sqlite3_step(stmt);

	mrsqlite3_unlock(msg->m_mailbox->m_sql);
}


/*******************************************************************************
 * Delete messages
 ******************************************************************************/


void mrmailbox_delete_msg_on_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
	int      locked = 0, delete_from_server = 1;
	mrmsg_t* msg = mrmsg_new();

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db__(msg, mailbox, job->m_foreign_id) ) {
			goto cleanup;
		}

		if( mrmailbox_rfc724_mid_cnt__(mailbox, msg->m_rfc724_mid) != 1 ) {
			mrmailbox_log_info(mailbox, 0, "The message is deleted from the server when all message are deleted.");
			delete_from_server = 0;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* if this is the last existing part of the message (ghost messages not counted), we delete the message from the server */
	if( delete_from_server )
	{
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrmailbox_connect_to_imap(mailbox, NULL);
			if( !mrimap_is_connected(mailbox->m_imap) ) {
				mrjob_try_again_later(job, MR_STANDARD_DELAY);
				goto cleanup;
			}
		}

		if( !mrimap_delete_msg(mailbox->m_imap, msg->m_rfc724_mid, msg->m_server_folder, msg->m_server_uid) )
		{
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	/* we delete the database entry ...
	- if the message is successfully removed from the server
	- or if there are other parts of the messages in the database (in this case we have not deleted if from the server)
	(As long as the message is not removed from the IMAP-server, we need at least one database entry to avoid a re-download) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		sqlite3_stmt* stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_msgs_WHERE_id, "DELETE FROM msgs WHERE id=?;");
		sqlite3_bind_int(stmt, 1, msg->m_id);
		sqlite3_step(stmt);

		char* pathNfilename = mrparam_get(msg->m_param, 'f', NULL);
		if( pathNfilename ) {
			if( strncmp(mailbox->m_blobdir, pathNfilename, strlen(mailbox->m_blobdir))==0 )
			{
				char* strLikeFilename = mr_mprintf("%%f=%s%%", pathNfilename);
				sqlite3_stmt* stmt2 = mrsqlite3_prepare_v2_(mailbox->m_sql, "SELECT id FROM msgs WHERE type!=? AND param LIKE ?;"); /* if this gets too slow, an index over "type" should help. */
				sqlite3_bind_int (stmt2, 1, MR_MSG_TEXT);
				sqlite3_bind_text(stmt2, 2, strLikeFilename, -1, SQLITE_STATIC);
				int file_used_by_other_msgs = (sqlite3_step(stmt2)==SQLITE_ROW)? 1 : 0;
				free(strLikeFilename);
				sqlite3_finalize(stmt2);

				if( !file_used_by_other_msgs )
				{
					mr_delete_file(pathNfilename, mailbox);

					char* increation_file = mr_mprintf("%s.increation", pathNfilename);
					mr_delete_file(increation_file, mailbox);
					free(increation_file);

					char* filenameOnly = mr_get_filename(pathNfilename);
					if( msg->m_type==MR_MSG_VOICE ) {
						char* waveform_file = mr_mprintf("%s/%s.waveform", mailbox->m_blobdir, filenameOnly);
						mr_delete_file(waveform_file, mailbox);
						free(waveform_file);
					}
					else if( msg->m_type==MR_MSG_VIDEO ) {
						char* preview_file = mr_mprintf("%s/%s-preview.jpg", mailbox->m_blobdir, filenameOnly);
						mr_delete_file(preview_file, mailbox);
						free(preview_file);
					}
					free(filenameOnly);
				}
			}
			free(pathNfilename);
		}

		char* ghost_rfc724_mid_str = mr_mprintf(MR_GHOST_ID_FORMAT, msg->m_id);
		stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_msgs_WHERE_rfc724_mid, "DELETE FROM msgs WHERE rfc724_mid=?;");
		sqlite3_bind_text(stmt, 1, ghost_rfc724_mid_str, -1, SQLITE_STATIC);
		sqlite3_step(stmt);
		free(ghost_rfc724_mid_str);

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	mrmsg_unref(msg);
}


int mrmailbox_delete_msgs(mrmailbox_t* ths, const uint32_t* msg_ids, int msg_cnt)
{
	int i;

	if( ths == NULL || msg_ids == NULL || msg_cnt <= 0 ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	mrsqlite3_begin_transaction__(ths->m_sql);

		for( i = 0; i < msg_cnt; i++ )
		{
			mrmailbox_update_msg_chat_id__(ths, msg_ids[i], MR_CHAT_ID_TRASH);
			mrjob_add__(ths, MRJ_DELETE_MSG_ON_IMAP, msg_ids[i], NULL); /* results in a call to mrmailbox_delete_msg_on_imap() */
		}

	mrsqlite3_commit__(ths->m_sql);
	mrsqlite3_unlock(ths->m_sql);

	return 1;
}


int mrmailbox_forward_msgs(mrmailbox_t* mailbox, const uint32_t* msg_ids_unsorted, int msg_cnt, uint32_t chat_id)
{
	mrmsg_t*      msg = mrmsg_new();
	mrchat_t*     chat = mrchat_new(mailbox);
	mrcontact_t*  contact = mrcontact_new();
	int           success = 0, locked = 0, transaction_pending = 0;
	carray*       created_db_entries = carray_new(16);
	char*         idsstr = NULL, *q3 = NULL;
	sqlite3_stmt* stmt = NULL;
	time_t        curr_timestamp;

	if( mailbox == NULL || msg_ids_unsorted==NULL || msg_cnt <= 0 || chat_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;
	mrsqlite3_begin_transaction__(mailbox->m_sql);
	transaction_pending = 1;

		mailbox->m_smtp->m_log_connect_errors = 1;

		if( !mrchat_load_from_db__(chat, chat_id) ) {
			goto cleanup;
		}

		curr_timestamp = mr_create_smeared_timestamps__(msg_cnt);

		idsstr = mr_arr_to_string(msg_ids_unsorted, msg_cnt);
		q3 = sqlite3_mprintf("SELECT id FROM msgs WHERE id IN(%s) ORDER BY timestamp,id", idsstr);
		stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, q3);
		while( sqlite3_step(stmt)==SQLITE_ROW )
		{
			int src_msg_id = sqlite3_column_int(stmt, 0);
			if( !mrmsg_load_from_db__(msg, mailbox, src_msg_id) ) {
				goto cleanup;
			}

			if( mrparam_exists(msg->m_param, 'a') ) {
				/* forwarding already forwarded mails: keep the original name and mail */
				;
			}
			else if( msg->m_from_id == MR_CONTACT_ID_SELF ) {
				/* forwarding our own mails: also show the forward state in this case - the mail may be address to another person and
				without the forwarding hint it may look strange.  Moreover, when forwarding a list of mails, it may feel like an
				error if the forwarding-headline is missing for some mails.  KISS. */
				char* addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
				char* name = mrsqlite3_get_config__(mailbox->m_sql, "displayname", NULL);
					mrparam_set(msg->m_param, 'a', addr);
					if( name ) {
						mrparam_set(msg->m_param, 'A', name);
					}
				free(name);
				free(addr);
			}
			else {
				/* forward mails received from other persons: add the original author */
				if( !mrcontact_load_from_db__(contact, mailbox->m_sql, msg->m_from_id) ) {
					goto cleanup;
				}
				mrparam_set(msg->m_param, 'a', contact->m_addr);
				if( contact->m_authname&&contact->m_authname[0] ) {
					mrparam_set(msg->m_param, 'A', contact->m_authname);
				}
			}

			uint32_t new_msg_id = mrchat_send_msg__(chat, msg, curr_timestamp++);
			carray_add(created_db_entries, (void*)(uintptr_t)chat_id, NULL);
			carray_add(created_db_entries, (void*)(uintptr_t)new_msg_id, NULL);
		}

	mrsqlite3_commit__(mailbox->m_sql);
	transaction_pending = 0;

	success = 1;

cleanup:
	if( transaction_pending ) { mrsqlite3_rollback__(mailbox->m_sql); }
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( created_db_entries ) {
		size_t i, icnt = carray_count(created_db_entries);
		for( i = 0; i < icnt; i += 2 ) {
			mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, (uintptr_t)carray_get(created_db_entries, i), (uintptr_t)carray_get(created_db_entries, i+1));
		}
		carray_free(created_db_entries);
	}
	mrcontact_unref(contact);
	mrmsg_unref(msg);
	mrchat_unref(chat);
	if( stmt ) { sqlite3_finalize(stmt); }
	free(idsstr);
	if( q3 ) { sqlite3_free(q3); }
	return success;
}


/*******************************************************************************
 * mark message as seen
 ******************************************************************************/


void mrmailbox_markseen_msg_on_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
	int      locked = 0;
	mrmsg_t* msg = mrmsg_new();
	char*    new_server_folder = NULL;
	uint32_t new_server_uid = 0;

	if( !mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job, MR_STANDARD_DELAY);
			goto cleanup;
		}
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db__(msg, mailbox, job->m_foreign_id) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( mrimap_markseen_msg(mailbox->m_imap, msg->m_server_folder, msg->m_server_uid,
		  msg->m_is_msgrmsg /*move to chats folder?*/, &new_server_folder, &new_server_uid) != 0 )
	{
		if( new_server_folder && new_server_uid )
		{
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				mrmailbox_update_server_uid__(mailbox, msg->m_rfc724_mid, new_server_folder, new_server_uid);

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
	}
	else
	{
		mrjob_try_again_later(job, MR_STANDARD_DELAY);
	}

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	mrmsg_unref(msg);
	free(new_server_folder);
}


int mrmailbox_markseen_msg(mrmailbox_t* ths, uint32_t msg_id)
{
	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);

		if( mrmailbox_update_msg_state_conditional__(ths, msg_id, MR_IN_UNSEEN, MR_IN_SEEN) ) { /* avoid converting outgoing messages to incoming ones and protect against double calls */
			mrjob_add__(ths, MRJ_MARKSEEN_MSG_ON_IMAP, msg_id, NULL); /* results in a call to mrmailbox_markseen_msg_on_imap() */
		}

	mrsqlite3_unlock(ths->m_sql);

	return 1;
}

