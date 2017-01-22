/*******************************************************************************
 *
 *                             Messenger Backend
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
 * File:    mre2ee.c
 * Purpose: Handle End-To-End-Encryption
 *
 ******************************************************************************/


#include <string.h>
#include "mrmailbox.h"
#include "mre2ee.h"


void mre2ee_execute_gnupg_block_command__(mrmailbox_t* mailbox, uint32_t contact_id, time_t timestamp, const char* gnupg_block)
{
	mrcontact_t*  contact = mrcontact_new();
	sqlite3_stmt* stmt;

	if( mailbox == NULL || contact_id<=MR_CONTACT_ID_LAST_SPECIAL || gnupg_block == NULL ) {
		goto cleanup;
	}

	if( mrcontact_load_from_db__(contact, mailbox->m_sql, contact_id) == 0 ) {
		goto cleanup;
	}

	if( timestamp < contact->m_pubkey_timestamp
	 || strcmp(contact->m_pubkey,  gnupg_block)==0 ) {
		goto cleanup;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_contacts_SET_pubkey,
		"UPDATE contacts SET pubkey=?, pubkey_timestamp=? WHERE id=?;");
	sqlite3_bind_text (stmt, 1, gnupg_block, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, timestamp);
	sqlite3_bind_int  (stmt, 3, contact_id);
	if( sqlite3_step(stmt)!=SQLITE_DONE ) {
		goto cleanup;
	}

cleanup:
	mrcontact_unref(contact);
}

