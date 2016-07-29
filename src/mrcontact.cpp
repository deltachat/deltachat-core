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
 * File:    mrcontact.cpp
 * Authors: Björn Petersen
 * Purpose: MrContactrepresents a single contact, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrtools.h"


MrContact::MrContact(MrMailbox* mailbox)
{
	m_mailbox = mailbox;
	m_name    = NULL;
	m_email   = NULL;
}


MrContact::~MrContact()
{
	Empty();
}


void MrContact::Empty()
{
	if( m_name ) {
		free(m_name);
		m_name = NULL;
	}

	if( m_email ) {
		free(m_email);
		m_email = NULL;
	}
}


bool MrContact::LoadFromDb(uint32_t contact_id)
{
	bool          success = false;
	char*         q;
	sqlite3_stmt* stmt;

	Empty();

	q=sqlite3_mprintf("SELECT id, name, email FROM contacts WHERE id=%i;", contact_id);
	stmt = m_mailbox->m_sql.sqlite3_prepare_v2_(q);
	if( stmt == NULL ) {
		goto LoadFromDb_Cleanup;
	}

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto LoadFromDb_Cleanup;
	}

	m_id    = contact_id;
	m_name  = save_strdup((char*)sqlite3_column_text(stmt, 1));
	m_email = save_strdup((char*)sqlite3_column_text(stmt, 2));
	if( m_name == NULL || m_email == NULL ) {
		goto LoadFromDb_Cleanup; // out of memory, should not happen
	}

	// success
	success = true;

	// cleanup
LoadFromDb_Cleanup:
	if( q ) {
		sqlite3_free(q);
	}

	if( stmt ) {
		sqlite3_finalize(stmt);
	}

	return success;
}


/*******************************************************************************
 * Static funcions
 ******************************************************************************/


size_t MrContact::GetContactCnt(MrMailbox* mailbox) // static function
{
	if( mailbox->m_sql.m_cobj==NULL ) {
		return 0; // no database, no contacts - this is no error (needed eg. for information)
	}

	sqlite3_stmt* s = mailbox->m_sql.m_pd[SELECT_COUNT_FROM_contacts];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		MrLogSqliteError(mailbox->m_sql.m_cobj);
		MrLogError("MrSqlite3::GetContactCnt() failed.");
		return 0; // error
	}

	return sqlite3_column_int(s, 0); // success
}


