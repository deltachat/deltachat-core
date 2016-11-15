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
 * File:    mrmsg.c
 * Authors: Björn Petersen
 * Purpose: mrmsg_t represents a single message, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrimap.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"
#include "mrjob.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


int mrmsg_set_from_stmt_(mrmsg_t* ths, sqlite3_stmt* row, int row_offset) /* field order must be MR_MSG_FIELDS */
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
	ths->m_text         =  safe_strdup((char*)sqlite3_column_text (row, row_offset++));

	mrparam_set_packed(  ths->m_param, (char*)sqlite3_column_text (row, row_offset++));
	ths->m_bytes        =                     sqlite3_column_int  (row, row_offset++);

	if( ths->m_chat_id == MR_CHAT_ID_STRANGERS ) {
		mr_truncate_n_unwrap_str(ths->m_text, 256, 0); /* 256 characters is about a half screen on a 5" smartphone display */
	}

	return 1;
}


int mrmsg_load_from_db_(mrmsg_t* ths, mrsqlite3_t* sql, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || sql == NULL ) {
		return 0;
	}

	mrmsg_empty(ths);

	stmt = mrsqlite3_predefine_(sql, SELECT_ircftttstpb_FROM_msg_WHERE_i,
		"SELECT " MR_MSG_FIELDS " FROM msgs m WHERE m.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	if( !mrmsg_set_from_stmt_(ths, stmt, 0) ) {
		return 0;
	}

	return 1;
}


void mrmailbox_update_msg_chat_id_(mrmailbox_t* mailbox, uint32_t msg_id, uint32_t chat_id)
{
    sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, UPDATE_msgs_SET_chat_id_WHERE_id,
		"UPDATE msgs SET chat_id=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
}


void mrmailbox_update_msg_state_(mrmailbox_t* mailbox, uint32_t msg_id, int state)
{
    sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, UPDATE_msgs_SET_state_WHERE_id,
		"UPDATE msgs SET state=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, state);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
}


static int mrmailbox_update_msg_state_conditional_(mrmailbox_t* mailbox, uint32_t msg_id, int old_state, int new_state)
{
	/* updates the message state only if the message has an given old state, returns the number of affected rows */
    sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, UPDATE_msgs_SET_state_WHERE_id_AND_state,
		"UPDATE msgs SET state=? WHERE id=? AND state=?;");
	sqlite3_bind_int(stmt, 1, new_state);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_bind_int(stmt, 3, old_state);
	sqlite3_step(stmt);
	return sqlite3_changes(mailbox->m_sql->m_cobj);
}


size_t mrmailbox_get_real_msg_cnt_(mrmailbox_t* mailbox)
{
	if( mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_assigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id>?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_assigned_msg_cnt_() failed.");
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


size_t mrmailbox_get_strangers_msg_cnt_(mrmailbox_t* mailbox)
{
	if( mailbox==NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_unassigned,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, MR_CHAT_ID_STRANGERS);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


int mrmailbox_rfc724_mid_cnt_(mrmailbox_t* mailbox, const char* rfc724_mid)
{
	if( mailbox==NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	/* check the number of messages with the same rfc724_mid */
	sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_rfc724_mid,
		"SELECT COUNT(*) FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


int mrmailbox_rfc724_mid_exists_(mrmailbox_t* mailbox, const char* rfc724_mid, char** ret_server_folder, uint32_t* ret_server_uid)
{
	/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
	so, we should even keep unuseful messages in the database (we can leave the other fields empty to safe space) */
	sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, SELECT_ss_FROM_msgs_WHERE_m,
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


void mrmailbox_update_server_uid_(mrmailbox_t* mailbox, const char* rfc724_mid, const char* server_folder, uint32_t server_uid)
{
	sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, UPDATE_msgs_SET_ss_WHERE_rfc724_mid,
		"UPDATE msgs SET server_folder=?, server_uid=? WHERE rfc724_mid=?;"); /* we update by "rfc724_mid" instead "id" as there may be several db-entries refering to the same "rfc724_mid" */
	sqlite3_bind_text(stmt, 1, server_folder, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, server_uid);
	sqlite3_bind_text(stmt, 3, rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
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

	MR_INIT_REFERENCE

	ths->m_type      = MR_MSG_UNDEFINED;
	ths->m_state     = MR_STATE_UNDEFINED;
	ths->m_param     = mrparam_new();

	return ths;
}


mrmsg_t* mrmsg_ref(mrmsg_t* ths)
{
	MR_INC_REFERENCE
}


void mrmsg_unref(mrmsg_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

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
}


mrmsg_t* mrmailbox_get_msg(mrmailbox_t* ths, uint32_t id)
{
	int success = 0;
	int db_locked = 0;
	mrmsg_t* obj = mrmsg_new();

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

		if( !mrmsg_load_from_db_(obj, ths->m_sql, id) ) {
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
	char*         ret = NULL;
	int           locked = 0;
	sqlite3_stmt* stmt;
	mrmsg_t*      msg = mrmsg_new();

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		mrmsg_load_from_db_(msg, mailbox->m_sql, msg_id);
		msg_id = mrparam_get_int(msg->m_param, 'G', msg_id);

		stmt = mrsqlite3_predefine_(mailbox->m_sql, SELECT_txt_raw_FROM_msgs_WHERE_id,
			"SELECT txt_raw FROM msgs WHERE id=?;");
		sqlite3_bind_int(stmt, 1, msg_id);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			goto cleanup;
		}

		ret = safe_strdup((char*)sqlite3_column_text(stmt, 0));

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	mrmsg_unref(msg);
	return ret? ret : safe_strdup(NULL);
}


char* mrmsg_get_summary(int type, const char* text, int approx_characters)
{
	char* ret = NULL;

	switch( type ) {
		case MR_MSG_IMAGE: ret = mrstock_str(MR_STR_IMAGE); break;
		case MR_MSG_VIDEO: ret = mrstock_str(MR_STR_VIDEO); break;
		case MR_MSG_AUDIO: ret = mrstock_str(MR_STR_AUDIO); break;
		case MR_MSG_FILE:  ret = mrstock_str(MR_STR_FILE);  break;
		default:
			if( text ) {
				ret = safe_strdup(text);
				mr_truncate_n_unwrap_str(ret, approx_characters, 1);
			}
			break;
	}

	if( ret == NULL ) {
		ret = safe_strdup(NULL);
	}

	return ret;
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

		if( !mrmsg_load_from_db_(msg, mailbox->m_sql, job->m_foreign_id) ) {
			goto cleanup;
		}

		if( mrmailbox_rfc724_mid_cnt_(mailbox, msg->m_rfc724_mid) != 1 ) {
			mrlog_info("The message is deleted from the server when all message are deleted.");
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
				mrjob_try_again_later(job);
				goto cleanup;
			}
		}

		if( !mrimap_delete_msg(mailbox->m_imap, msg->m_rfc724_mid, msg->m_server_folder, msg->m_server_uid) )
		{
			mrjob_try_again_later(job);
			goto cleanup;
		}
	}

	/* we delete the database entry ...
	- if the message is successfully removed from the server
	- or if there are other parts of the messages in the database (in this case we have not deleted if from the server)
	(As long as the message is not removed from the IMAP-server, we need at least one database entry to avoid a re-download) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		sqlite3_stmt* stmt = mrsqlite3_predefine_(mailbox->m_sql, DELETE_FROM_msgs_WHERE_id, "DELETE FROM msgs WHERE id=?;");
		sqlite3_bind_int(stmt, 1, msg->m_id);
		sqlite3_step(stmt);

		char* pathNfilename = mrparam_get(job->m_param, 'f', NULL);
		if( pathNfilename ) {
			mr_delete_file(pathNfilename);
			free(pathNfilename);
		}

		char* ghost_rfc724_mid_str = mr_mprintf(MR_GHOST_ID_FORMAT, msg->m_id);
		stmt = mrsqlite3_predefine_(mailbox->m_sql, DELETE_FROM_msgs_WHERE_rfc724_mid, "DELETE FROM msgs WHERE rfc724_mid=?;");
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


int mrmailbox_delete_msg(mrmailbox_t* ths, uint32_t msg_id)
{
	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	mrsqlite3_begin_transaction_(ths->m_sql);

		mrmailbox_update_msg_chat_id_(ths, msg_id, MR_CHAT_ID_TRASH);
		mrjob_add_(ths, MRJ_DELETE_MSG_ON_IMAP, msg_id, NULL); /* results in a call to mrmailbox_delete_msg_on_imap() */

	mrsqlite3_commit_(ths->m_sql);
	mrsqlite3_unlock(ths->m_sql);

	return 1;
}


/*******************************************************************************
 * mark message as seen
 ******************************************************************************/


void mrmailbox_markseen_msg_on_imap(mrmailbox_t* mailbox, mrjob_t* job)
{
	int      locked = 0;
	mrmsg_t* msg = mrmsg_new();

	if( !mrimap_is_connected(mailbox->m_imap) ) {
		mrmailbox_connect_to_imap(mailbox, NULL);
		if( !mrimap_is_connected(mailbox->m_imap) ) {
			mrjob_try_again_later(job);
			goto cleanup;
		}
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( !mrmsg_load_from_db_(msg, mailbox->m_sql, job->m_foreign_id) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( mrimap_markseen_msg(mailbox->m_imap, msg->m_server_folder, msg->m_server_uid)==0 ) {
		mrjob_try_again_later(job);
	}

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	mrmsg_unref(msg);
}


int mrmailbox_markseen_msg(mrmailbox_t* ths, uint32_t msg_id)
{
	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
	mrsqlite3_begin_transaction_(ths->m_sql);

		if( mrmailbox_update_msg_state_conditional_(ths, msg_id, MR_IN_UNSEEN, MR_IN_SEEN) ) { /* avoid converting outgoing messages to incoming ones and protect against double calls */
			mrjob_add_(ths, MRJ_MARKSEEN_MSG_ON_IMAP, msg_id, NULL); /* results in a call to mrmailbox_markseen_msg_on_imap() */
		}

	mrsqlite3_commit_(ths->m_sql);
	mrsqlite3_unlock(ths->m_sql);

	return 1;
}

