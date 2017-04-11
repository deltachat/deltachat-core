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


#ifdef USE_E2EE /* this is a temporary define, E2EE will be always enabled, when implemented */


#include <string.h>
#include <gcrypt.h>
#include "mrmailbox.h"
#include "mre2ee.h"


static const char* s_version = NULL;


static void mr_gcry_log_handler(void* user_data, int level, const char* msg, va_list va)
{
	int event;
	switch( level ) {
		case GCRY_LOG_INFO:  event = MR_EVENT_INFO;    break;
		case GCRY_LOG_CONT:  event = MR_EVENT_INFO;    break;
		case GCRY_LOG_DEBUG: event = MR_EVENT_INFO;    break;
		case GCRY_LOG_WARN:  event = MR_EVENT_WARNING; break;
		default:             event = MR_EVENT_ERROR;   break;
	}
	mrmailbox_log_vprintf((mrmailbox_t*)user_data, event, 0, msg, va);
}


void mre2ee_init(mrmailbox_t* mailbox)
{
	if( s_version ) {
		return; /* already initialized */
	}

	/* set logging handler (must be done before gcry_check_version()) */
	gcry_set_log_handler(mr_gcry_log_handler, mailbox);

	/* init libgcrypt; the call to gcry_check_version() is important for this */
	if( !(s_version=gcry_check_version(GCRYPT_VERSION)) ) {
		exit(37); /* should not happen, we could also handle this by disabling encryption and logging and error */
	}

	/* configuration to be done after gcry_check_version() is called */
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	//gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 1/*debug cipher functions*/ | 2/*debug multi-precision-integers*/, 0);
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}


const char* mre2ee_get_version(mrmailbox_t* mailbox)
{
	return s_version? s_version : "0.0.0";
}


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


#endif /* USE_E2EE */
