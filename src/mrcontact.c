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
#include <string.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"


mrcontact_t* mrcontact_new(mrmailbox_t* mailbox)
{
	mrcontact_t* ths = NULL;

	if( (ths=malloc(sizeof(mrcontact_t)))==NULL ) {
		exit(19); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_mailbox = mailbox;
	ths->m_name    = NULL;
	ths->m_addr    = NULL;

	return ths;
}


mrcontact_t* mrcontact_ref(mrcontact_t* ths)
{
	MR_INC_REFERENCE
}


void mrcontact_unref(mrcontact_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrcontact_empty(ths);
	free(ths);
}


void mrcontact_empty(mrcontact_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	free(ths->m_name); /* it is safe to call free(NULL) */
	ths->m_name = NULL;

	free(ths->m_addr);
	ths->m_addr = NULL;
}


int mrcontact_load_from_db_(mrcontact_t* ths, uint32_t contact_id)
{
	int           success = 0;
	sqlite3_stmt* stmt;

	if( ths == NULL || ths->m_mailbox == NULL ) {
		return 0; /* error */
	}

	mrcontact_empty(ths);

	stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, SELECT_ine_FROM_contacts_i,
		"SELECT id, name, addr FROM contacts WHERE id=?;");
	if( stmt == NULL ) {
		goto LoadFromDb_Cleanup;
	}
	sqlite3_bind_int(stmt, 1, contact_id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto LoadFromDb_Cleanup;
	}

	ths->m_id    = contact_id;
	ths->m_name  = safe_strdup((char*)sqlite3_column_text(stmt, 1));
	ths->m_addr  = safe_strdup((char*)sqlite3_column_text(stmt, 2));
	if( ths->m_name == NULL || ths->m_addr == NULL ) {
		goto LoadFromDb_Cleanup; /* out of memory, should not happen */
	}

	/* success */
	success = 1;

	/* cleanup */
LoadFromDb_Cleanup:

	return success;
}


/*******************************************************************************
 * Static funcions
 ******************************************************************************/


size_t mr_get_contact_cnt_(mrmailbox_t* mailbox) /* static function */
{
	sqlite3_stmt* stmt;

	if( mailbox == NULL || mailbox->m_sql == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0; /* no database, no contacts - this is no error (needed eg. for information) */
	}

	if( (stmt=mrsqlite3_predefine(mailbox->m_sql, SELECT_COUNT_FROM_contacts, "SELECT COUNT(*) FROM contacts WHERE id>?;"))==NULL ) {
		return 0;
	}
	sqlite3_bind_int(stmt, 1, MRSCID_LAST);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		mrsqlite3_log_error(mailbox->m_sql, "mr_get_contact_cnt() failed.");
		return 0; /* error */
	}

	return sqlite3_column_int(stmt, 0); /* success */
}


void mr_normalize_name(char* full_name)
{
	/* function ...
	- converts names as "Petersen, Björn" to "Björn Petersen"
	- trims the resulting string
	- modifies the given buffer; so the resulting string must not be longer than the original string. */

	if( full_name == NULL ) {
		return; /* error, however, this can be treated as documented behaviour */
	}

	char* p1 = strchr(full_name, ',');
	if( p1 ) {
		*p1 = 0;
		char* last_name  = safe_strdup(full_name);
		char* first_name = safe_strdup(p1+1);
		mr_trim(last_name);
		mr_trim(first_name);
		strcpy(full_name, first_name);
		strcat(full_name, " ");
		strcat(full_name, last_name);
	}
	else {
		mr_trim(full_name);
	}
}


char* mr_get_first_name(const char* full_name)
{
	/* check for the name before the first space */
	char* first_name = safe_strdup(full_name);
	char* p1 = strchr(first_name, ' ');
	if( p1 ) {
		*p1 = 0;
		mr_rtrim(first_name);
		if( first_name[0]  == 0 ) { /*empty result? use the original string in this case */
			free(first_name);
			first_name = safe_strdup(full_name);
		}
	}

	return first_name; /* the result must be free()'d */
}
