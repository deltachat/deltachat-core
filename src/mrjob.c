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


#include "mrmailbox_internal.h"
#include "mrjob.h"
#include "mrosnative.h"


void mrjob_perform(mrmailbox_t* mailbox, int thread)
{
	sqlite3_stmt* stmt;
	mrjob_t       job;

	memset(&job, 0, sizeof(mrjob_t));
	job.m_param = mrparam_new();

		while( 1 )
		{
			/* get next waiting job */
			job.m_job_id = 0;
			stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
				"SELECT id, action, foreign_id, param FROM jobs WHERE thread=? AND desired_timestamp<=? ORDER BY action DESC, id LIMIT 1;");
			sqlite3_bind_int64(stmt, 1, thread);
			sqlite3_bind_int64(stmt, 2, time(NULL));
			if( sqlite3_step(stmt) == SQLITE_ROW ) {
				job.m_job_id                         = sqlite3_column_int (stmt, 0);
				job.m_action                         = sqlite3_column_int (stmt, 1);
				job.m_foreign_id                     = sqlite3_column_int (stmt, 2);
				mrparam_set_packed(job.m_param, (char*)sqlite3_column_text(stmt, 3));
			}
			sqlite3_finalize(stmt);

			if( job.m_job_id == 0 ) {
				break;
			}

			/* execute job */
			mrmailbox_log_info(mailbox, 0, "Executing job #%i, action %i...", (int)job.m_job_id, (int)job.m_action);
			job.m_start_again_at = 0;
			switch( job.m_action ) {
                case MRJ_SEND_MSG_TO_SMTP:     mrmailbox_send_msg_to_smtp     (mailbox, &job); break;
                case MRJ_SEND_MSG_TO_IMAP:     mrmailbox_send_msg_to_imap     (mailbox, &job); break;
                case MRJ_DELETE_MSG_ON_IMAP:   mrmailbox_delete_msg_on_imap   (mailbox, &job); break;
                case MRJ_MARKSEEN_MSG_ON_IMAP: mrmailbox_markseen_msg_on_imap (mailbox, &job); break;
                case MRJ_MARKSEEN_MDN_ON_IMAP: mrmailbox_markseen_mdn_on_imap (mailbox, &job); break;
                case MRJ_SEND_MDN:             mrmailbox_send_mdn             (mailbox, &job); break;
                case MRJ_CONFIGURE_IMAP:       mrmailbox_configure_imap       (mailbox, &job); break;
			}

			/* delete job or execute job later again */
			if( job.m_start_again_at ) {
				stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
					"UPDATE jobs SET desired_timestamp=?, param=? WHERE id=?;");
				sqlite3_bind_int64(stmt, 1, job.m_start_again_at);
				sqlite3_bind_text (stmt, 2, job.m_param->m_packed, -1, SQLITE_STATIC);
				sqlite3_bind_int  (stmt, 3, job.m_job_id);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
				mrmailbox_log_info(mailbox, 0, "Job #%i delayed for %i seconds", (int)job.m_job_id, (int)(job.m_start_again_at-time(NULL)));
			}
			else {
				stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
					"DELETE FROM jobs WHERE id=?;");
				sqlite3_bind_int(stmt, 1, job.m_job_id);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
				mrmailbox_log_info(mailbox, 0, "Job #%i done and deleted from database", (int)job.m_job_id);
			}
		}


	mrparam_unref(job.m_param);
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


uint32_t mrjob_add__(mrmailbox_t* mailbox, int action, int foreign_id, const char* param, int delay_seconds)
{
	time_t        timestamp = time(NULL);
	sqlite3_stmt* stmt;
	uint32_t      job_id = 0;
	int           thread;

	if( action >= MR_IMAP_THREAD && action < MR_IMAP_THREAD+1000 ) {
		thread = MR_IMAP_THREAD;
	}
	else if( action >= MR_SMTP_THREAD && action < MR_SMTP_THREAD+1000 ) {
		thread = MR_SMTP_THREAD;
	}
	else {
		return 0;
	}

	stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
		"INSERT INTO jobs (added_timestamp, thread, action, foreign_id, param, desired_timestamp) VALUES (?,?,?,?,?,?);");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, thread);
	sqlite3_bind_int  (stmt, 3, action);
	sqlite3_bind_int  (stmt, 4, foreign_id);
	sqlite3_bind_text (stmt, 5, param? param : "",  -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 6, delay_seconds>0? (timestamp+delay_seconds) : 0);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	job_id = sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj);

    mrmailbox_interrupt_idle(mailbox);

	return job_id;
}


void mrjob_try_again_later(mrjob_t* ths, int initial_delay_seconds)
{
	if( ths == NULL ) {
		return;
	}

	if( initial_delay_seconds == MR_INCREATION_POLL )
	{
		int tries = mrparam_get_int(ths->m_param, MRP_TIMES_INCREATION, 0) + 1;
		mrparam_set_int(ths->m_param, MRP_TIMES_INCREATION, tries);

		if( tries < 120/MR_INCREATION_POLL ) {
			ths->m_start_again_at = time(NULL)+MR_INCREATION_POLL;
		}
		else {
			ths->m_start_again_at = time(NULL)+10; /* after two minutes of waiting, try less often */
		}
	}
	else
	{
		int tries = mrparam_get_int(ths->m_param, MRP_TIMES, 0) + 1;
		mrparam_set_int(ths->m_param, MRP_TIMES, tries);

		if( tries == 1 ) {
			ths->m_start_again_at = time(NULL)+initial_delay_seconds;
		}
		else if( tries < 5 ) {
			ths->m_start_again_at = time(NULL)+60;
		}
		else {
			ths->m_start_again_at = time(NULL)+600;
		}
	}
}


void mrjob_kill_actions__(mrmailbox_t* mailbox, int action1, int action2)
{
	if( mailbox == NULL ) {
		return;
	}

	sqlite3_stmt* stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
		"DELETE FROM jobs WHERE action=? OR action=?;");
	sqlite3_bind_int(stmt, 1, action1);
	sqlite3_bind_int(stmt, 2, action2);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}

