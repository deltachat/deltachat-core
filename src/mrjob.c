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
#include "mrmailbox.h"
#include "mrjob.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


int mrjob_add_(mrmailbox_t* mailbox, int action, int foreign_id, const char* param)
{
	time_t        timestamp = time(NULL);
	sqlite3_stmt* stmt;

	stmt = mrsqlite3_predefine(mailbox->m_sql, INSERT_INTO_jobs_tafp,
		"INSERT INTO jobs (timestamp, action, foreign_id, param) VALUES (?,?,?,?);");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, action);
	sqlite3_bind_int  (stmt, 3, foreign_id);
	sqlite3_bind_text (stmt, 4, param? param : "",  -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		return 0;
	}

	return sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj);
}

