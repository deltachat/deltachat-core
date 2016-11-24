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
 * File:    mrjob.c
 * Authors: Björn Petersen
 * Purpose: Handle jobs
 *
 ******************************************************************************/


#include <stdlib.h>
#include <memory.h>
#include "mrmailbox.h"
#include "mrjob.h"
#include "mrlog.h"
#include "mrchat.h"
#include "mrmsg.h"
#include "mrosnative.h"


/*******************************************************************************
 * The job thread
 ******************************************************************************/


static void* job_thread_entry_point(void* entry_arg)
{
	mrmailbox_t*  mailbox = (mrmailbox_t*)entry_arg;
	sqlite3_stmt* stmt;
	mrjob_t       job;

	memset(&job, 0, sizeof(mrjob_t));
	job.m_param = mrparam_new();

	/* init thread */
	mrlog_info("Job thread entered.");
	mrosnative_setup_thread();

	while( 1 )
	{
		/* wait for condition */
		mrlog_info("Job thread waiting...");

		if( mailbox->m_job_do_exit ) { goto exit_; }
		pthread_mutex_lock(&mailbox->m_job_condmutex);
			pthread_cond_wait(&mailbox->m_job_cond, &mailbox->m_job_condmutex); /* wait unlocks the mutex and waits for signal; if it returns, the mutex is locked again */
		pthread_mutex_unlock(&mailbox->m_job_condmutex);
		if( mailbox->m_job_do_exit ) { goto exit_; }

		mrlog_info("Job thread waked up.");

		/* do all waiting jobs */
		while( 1 )
		{
			/* get next waiting job */
			job.m_job_id = 0;
			mrsqlite3_lock(mailbox->m_sql);
				stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_iafp_FROM_jobs,
					"SELECT id, action, foreign_id, param FROM jobs WHERE desired_timestamp<=? ORDER BY action DESC, id LIMIT 1;");
				sqlite3_bind_int64(stmt, 1, time(NULL));
				if( sqlite3_step(stmt) == SQLITE_ROW ) {
					job.m_job_id                         = sqlite3_column_int (stmt, 0);
					job.m_action                         = sqlite3_column_int (stmt, 1);
					job.m_foreign_id                     = sqlite3_column_int (stmt, 2);
					mrparam_set_packed(job.m_param, (char*)sqlite3_column_text(stmt, 3));
				}
			mrsqlite3_unlock(mailbox->m_sql);

			if( job.m_job_id == 0 ) {
				break;
			}
			else if( mailbox->m_job_do_exit ) {
				goto exit_;
			}

			/* execute job */
			mrlog_info("Executing job #%i, action %i...", (int)job.m_job_id, (int)job.m_action);
			job.m_start_again_at = 0;
			switch( job.m_action ) {
				case MRJ_CONNECT_TO_IMAP:      mrmailbox_connect_to_imap      (mailbox, &job); break;
                case MRJ_SEND_MSG_TO_SMTP:     mrmailbox_send_msg_to_smtp     (mailbox, &job); break;
                case MRJ_SEND_MSG_TO_IMAP:     mrmailbox_send_msg_to_imap     (mailbox, &job); break;
                case MRJ_DELETE_MSG_ON_IMAP:   mrmailbox_delete_msg_on_imap   (mailbox, &job); break;
                case MRJ_MARKSEEN_MSG_ON_IMAP: mrmailbox_markseen_msg_on_imap (mailbox, &job); break;
			}

			/* delete job or execute job later again */
			if( job.m_start_again_at ) {
				mrsqlite3_lock(mailbox->m_sql);
					stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_jobs_SET_dp_WHERE_id,
						"UPDATE jobs SET desired_timestamp=?, param=? WHERE id=?;");
					sqlite3_bind_int64(stmt, 1, job.m_start_again_at);
					sqlite3_bind_text (stmt, 2, job.m_param->m_packed, -1, SQLITE_STATIC);
					sqlite3_bind_int  (stmt, 3, job.m_job_id);
					sqlite3_step(stmt);
				mrsqlite3_unlock(mailbox->m_sql);
				mrlog_info("Job #%i delayed for %i seconds", (int)job.m_job_id, (int)(job.m_start_again_at-time(NULL)));
			}
			else {
				mrsqlite3_lock(mailbox->m_sql);
					stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_jobs_WHERE_id,
						"DELETE FROM jobs WHERE id=?;");
					sqlite3_bind_int(stmt, 1, job.m_job_id);
					sqlite3_step(stmt);
				mrsqlite3_unlock(mailbox->m_sql);
				mrlog_info("Job #%i done and deleted from database", (int)job.m_job_id);
			}
		}

	}

	/* exit thread */
exit_:
	mrparam_unref(job.m_param);
	mrlog_info("Exit job thread.");
	mrosnative_unsetup_thread();
	return NULL;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mrjob_init_thread(mrmailbox_t* mailbox)
{
	pthread_mutex_init(&mailbox->m_job_condmutex, NULL);
    pthread_cond_init(&mailbox->m_job_cond, NULL);
    pthread_create(&mailbox->m_job_thread, NULL, job_thread_entry_point, mailbox);
}


void mrjob_exit_thread(mrmailbox_t* mailbox)
{
	mailbox->m_job_do_exit = 1;
	pthread_cond_signal(&mailbox->m_job_cond);
	pthread_join(mailbox->m_job_thread, NULL);
	pthread_cond_destroy(&mailbox->m_job_cond);
	pthread_mutex_destroy(&mailbox->m_job_condmutex);
}


uint32_t mrjob_add__(mrmailbox_t* mailbox, int action, int foreign_id, const char* param)
{
	time_t        timestamp = time(NULL);
	sqlite3_stmt* stmt;
	uint32_t      job_id = 0;

	stmt = mrsqlite3_predefine__(mailbox->m_sql, INSERT_INTO_jobs_aafp,
		"INSERT INTO jobs (added_timestamp, action, foreign_id, param) VALUES (?,?,?,?);");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, action);
	sqlite3_bind_int  (stmt, 3, foreign_id);
	sqlite3_bind_text (stmt, 4, param? param : "",  -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		return 0;
	}

	job_id = sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj);

	if( !mailbox->m_job_do_exit ) {
		mrlog_info("Signal job thread to wake up...");
		pthread_mutex_lock(&mailbox->m_job_condmutex);
			pthread_cond_signal(&mailbox->m_job_cond);
		pthread_mutex_unlock(&mailbox->m_job_condmutex);
	}

	return job_id;
}


void mrjob_ping__(mrmailbox_t* mailbox)
{
	sqlite3_stmt* stmt;
	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_i_FROM_jobs,
		"SELECT id FROM jobs WHERE desired_timestamp<=? LIMIT 1;");
	sqlite3_bind_int64(stmt, 1, time(NULL));
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		mrlog_info("Ping does signal job thread to wake up...");
		pthread_cond_signal(&mailbox->m_job_cond);
	}
}


void mrjob_try_again_later(mrjob_t* ths)
{
	int tries = mrparam_get_int(ths->m_param, 't', 0) + 1;
	mrparam_set_int(ths->m_param, 't', tries);

	if( tries == 1 ) {
		ths->m_start_again_at = time(NULL)+3;
	}
	else if( tries < 5 ) {
		ths->m_start_again_at = time(NULL)+60;
	}
	else {
		ths->m_start_again_at = time(NULL)+600;
	}
}

