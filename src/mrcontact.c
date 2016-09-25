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
 * File:    mrcontact.c
 * Authors: Björn Petersen
 * Purpose: mrcontact_t represents a single contact, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"


mrcontact_t* mrcontact_new(mrmailbox_t* mailbox)
{
	mrcontact_t* ths = NULL;

	if( (ths=malloc(sizeof(mrcontact_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_mailbox = mailbox;
	ths->m_name    = NULL;
	ths->m_email   = NULL;

	return ths;
}


void mrcontact_unref(mrcontact_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	mrcontact_empty(ths);
	free(ths);
}


void mrcontact_empty(mrcontact_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_name ) {
		free(ths->m_name);
		ths->m_name = NULL;
	}

	if( ths->m_email ) {
		free(ths->m_email);
		ths->m_email = NULL;
	}
}


int mrcontact_load_from_db(mrcontact_t* ths, uint32_t contact_id)
{
	int           success = 0;
	char*         q;
	sqlite3_stmt* stmt;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		return 0; /* error */
	}

	mrcontact_empty(ths);

	q=sqlite3_mprintf("SELECT id, name, email FROM contacts WHERE id=%i;", contact_id);
	stmt = mrsqlite3_prepare_v2_(ths->m_mailbox->m_sql, q);
	if( stmt == NULL ) {
		goto LoadFromDb_Cleanup;
	}

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto LoadFromDb_Cleanup;
	}

	ths->m_id    = contact_id;
	ths->m_name  = safe_strdup((char*)sqlite3_column_text(stmt, 1));
	ths->m_email = safe_strdup((char*)sqlite3_column_text(stmt, 2));
	if( ths->m_name == NULL || ths->m_email == NULL ) {
		goto LoadFromDb_Cleanup; /* out of memory, should not happen */
	}

	/* success */
	success = 1;

	/* cleanup */
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


size_t mr_get_contact_cnt_(mrmailbox_t* mailbox) /* static function */
{
	if( mailbox == NULL || mailbox->m_sql == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no contacts - this is no error (needed eg. for information) */
	}

	sqlite3_stmt* s = mailbox->m_sql->m_pd[SELECT_COUNT_FROM_contacts];
	sqlite3_reset (s);
	if( sqlite3_step(s) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql);
		mr_log_error("mr_get_contact_cnt() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(s, 0); /* success */
}
