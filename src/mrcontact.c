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
 * File:    mrcontact.c
 * Purpose: mrcontact_t represents a single contact, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"

#define CLASS_MAGIC 1170070140


/*******************************************************************************
 * Tools
 ******************************************************************************/


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


int mrmailbox_real_contact_exists__(mrmailbox_t* mailbox, uint32_t contact_id)
{
	sqlite3_stmt* stmt;
	int           ret = 0;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL
	 || contact_id <= MR_CONTACT_ID_LAST_SPECIAL ) {
		return 0;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_contacts_WHERE_id,
		"SELECT id FROM contacts WHERE id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);

	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = 1;
	}

	return ret;
}


size_t mrmailbox_get_real_contact_cnt__(mrmailbox_t* mailbox)
{
	sqlite3_stmt* stmt;

	if( mailbox == NULL || mailbox->m_sql->m_cobj==NULL ) {
		return 0;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_contacts, "SELECT COUNT(*) FROM contacts WHERE id>?;");
	sqlite3_bind_int(stmt, 1, MR_CONTACT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	return sqlite3_column_int(stmt, 0);
}


uint32_t mrmailbox_add_or_lookup_contact__( mrmailbox_t* mailbox,
                                           const char*  name /*can be NULL, the caller may use mr_normalize_name() before*/,
                                           const char*  addr,
                                           int          origin,
                                           int*         sth_modified )
{
	sqlite3_stmt* stmt;
	uint32_t      row_id = 0;
	int           dummy;

	if( sth_modified == NULL ) {
		sth_modified = &dummy;
	}

	*sth_modified = 0;

	if( mailbox == NULL || addr == NULL || origin <= 0 ) {
		return 0;
	}

	if( strlen(addr) < 3 || strchr(addr, '@')==NULL || strchr(addr, '.')==NULL ) {
		mrlog_warning("Bad address \"%s\" for contact \"%s\".", addr, name?name:"<unset>");
		return 0;
	}

	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_inao_FROM_contacts_a,
		"SELECT id, name, addr, origin FROM contacts WHERE addr=? COLLATE NOCASE;");
	sqlite3_bind_text(stmt, 1, (const char*)addr, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) == SQLITE_ROW )
	{
		const char  *row_name, *row_addr;
		int         row_origin, update_addr = 0, update_name = 0;

		row_id       = sqlite3_column_int(stmt, 0);
		row_name     = (const char*)sqlite3_column_text(stmt, 1); if( row_name == NULL ) { row_name = ""; }
		row_addr     = (const char*)sqlite3_column_text(stmt, 2); if( row_addr == NULL ) { row_addr = addr; }
		row_origin   = sqlite3_column_int(stmt, 3);

		if( name && name[0] ) {
			if( row_name && row_name[0] ) {
				if( origin>=row_origin && strcmp(name, row_name)!=0 ) {
					update_name = 1;
				}
			}
			else {
				update_name = 1;
			}
		}

		if( origin>=row_origin && strcmp(addr, row_addr)!=0 /*really compare case-sensitive here*/ ) {
			update_addr = 1;
		}

		if( update_name || update_addr || origin>row_origin )
		{
			stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_contacts_nao_WHERE_i,
				"UPDATE contacts SET name=?, addr=?, origin=? WHERE id=?;");
			sqlite3_bind_text(stmt, 1, update_name?       name   : row_name, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, update_addr?       addr   : row_addr, -1, SQLITE_STATIC);
			sqlite3_bind_int (stmt, 3, origin>row_origin? origin : row_origin);
			sqlite3_bind_int (stmt, 4, row_id);
			sqlite3_step     (stmt);

			if( update_name )
			{
				/* Update the contact name also if it is used as a group name.
				This is one of the few duplicated data, however, getting the chat list is much faster this way.*/
				stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_chats_SET_n_WHERE_c,
					"UPDATE chats SET name=? WHERE type=? AND id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?);");
				sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
				sqlite3_bind_int (stmt, 2, MR_CHAT_NORMAL);
				sqlite3_bind_int (stmt, 3, row_id);
				sqlite3_step     (stmt);
			}
		}

		*sth_modified = 1;
	}
	else
	{
		stmt = mrsqlite3_predefine__(mailbox->m_sql, INSERT_INTO_contacts_neo,
			"INSERT INTO contacts (name, addr, origin) VALUES(?, ?, ?);");
		sqlite3_bind_text(stmt, 1, name? name : "", -1, SQLITE_STATIC); /* avoid NULL-fields in column */
		sqlite3_bind_text(stmt, 2, addr,    -1, SQLITE_STATIC);
		sqlite3_bind_int (stmt, 3, origin);
		if( sqlite3_step(stmt) == SQLITE_DONE )
		{
			row_id = sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj);
			*sth_modified = 1;
		}
		else
		{
			mrlog_error("Cannot add contact.");
		}
	}

	return row_id; /*success*/
}


int mrmailbox_is_contact_blocked__(mrmailbox_t* mailbox, uint32_t contact_id)
{
	int          is_blocked = 0;
	mrcontact_t* ths = mrcontact_new();

	if( mrcontact_load_from_db__(ths, mailbox->m_sql, contact_id) ) { /* we could optimize this by loading only the needed fields */
		if( ths->m_blocked ) {
			is_blocked = 1;
		}
	}

	mrcontact_unref(ths);
	return is_blocked;
}


int mrmailbox_is_known_contact__(mrmailbox_t* mailbox, uint32_t contact_id, int* ret_blocked)
{
	int          is_known = 0;
	int          dummy; if( ret_blocked==NULL ) { ret_blocked = &dummy; }
	mrcontact_t* ths = mrcontact_new();

	*ret_blocked = 0;

	if( !mrcontact_load_from_db__(ths, mailbox->m_sql, contact_id) ) { /* we could optimize this by loading only the needed fields */
		goto cleanup;
	}

	if( ths->m_blocked ) {
		*ret_blocked = 1;
		goto cleanup;
	}

	if( ths->m_origin > MR_ORIGIN_INCOMING_UNKNOWN_FROM ) {
		is_known = 1;
		goto cleanup;
	}

cleanup:
	mrcontact_unref(ths);
	return is_known;
}


int mrcontact_load_from_db__(mrcontact_t* ths, mrsqlite3_t* sql, uint32_t contact_id)
{
	int           success = 0;
	sqlite3_stmt* stmt;

	if( ths == NULL || sql == NULL ) {
		return 0;
	}

	mrcontact_empty(ths);

	stmt = mrsqlite3_predefine__(sql, SELECT_naob_FROM_contacts_i,
		"SELECT name, addr, origin, blocked, pubkey, pubkey_timestamp FROM contacts WHERE id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ths->m_id               = contact_id;
	ths->m_name             = safe_strdup((char*)sqlite3_column_text (stmt, 0));
	ths->m_addr             = safe_strdup((char*)sqlite3_column_text (stmt, 1));
	ths->m_origin           =                    sqlite3_column_int  (stmt, 2);
	ths->m_blocked          =                    sqlite3_column_int  (stmt, 3);
	ths->m_pubkey           = safe_strdup((char*)sqlite3_column_text (stmt, 4));
	ths->m_pubkey_timestamp =                    sqlite3_column_int64(stmt, 5);

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	return success;
}


char* mr_get_headerlike_name(const char* addr, const char* name)
{
	if( name ) {
		return mr_mprintf("%s <%s>", name, addr);
	}
	else {
		return safe_strdup(addr);
	}
}



/*******************************************************************************
 * Main interface
 ******************************************************************************/


uint32_t mrmailbox_create_contact(mrmailbox_t* mailbox, const char* name, const char* addr)
{
	uint32_t contact_id = 0;

	if( mailbox == NULL || addr == NULL || addr[0]==0 ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);

		contact_id = mrmailbox_add_or_lookup_contact__(mailbox, name, addr, MR_ORIGIN_MANUALLY_CREATED, NULL);

	mrsqlite3_unlock(mailbox->m_sql);

	mailbox->m_cb(mailbox, MR_EVENT_CONTACTS_CHANGED, 0, 0);

cleanup:
	return contact_id;
}


int mrmailbox_add_address_book(mrmailbox_t* ths, const char* adr_book) /* format: Name one\nAddress one\nName two\Address two */
{
	carray* lines = NULL;
	size_t  i, iCnt;
	int     sth_modified, modify_cnt = 0;

	if( ths == NULL || adr_book == NULL ) {
		goto cleanup;
	}

	if( (lines=mr_split_into_lines(adr_book))==NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(ths->m_sql);

		mrsqlite3_begin_transaction__(ths->m_sql);

		iCnt = carray_count(lines);
		for( i = 0; i+1 < iCnt; i += 2 ) {
			char* name = (char*)carray_get(lines, i);
			char* addr = (char*)carray_get(lines, i+1);
			mr_normalize_name(name);
			mr_trim(addr);
			mrmailbox_add_or_lookup_contact__(ths, name, addr, MR_ORIGIN_ADRESS_BOOK, &sth_modified);
			if( sth_modified ) {
				modify_cnt++;
			}
		}

		mrsqlite3_commit__(ths->m_sql);

	mrsqlite3_unlock(ths->m_sql);

cleanup:
	mr_free_splitted_lines(lines);

	return modify_cnt;
}


carray* mrmailbox_get_known_contacts(mrmailbox_t* mailbox, const char* query)
{
	int           locked = 0;
	carray*       ret = carray_new(100);
	char*         s3strLikeCmd = NULL;
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( query ) {
			if( (s3strLikeCmd=sqlite3_mprintf("%%%s%%", query))==NULL ) {
				goto cleanup;
			}
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_contacts_WHERE_query_ORDER_BY,
				"SELECT id FROM contacts"
					" WHERE id>? AND origin>=? AND blocked=0 AND (name LIKE ? OR addr LIKE ?)" /* see comments in mrmailbox_search_msgs() about the LIKE operator */
					" ORDER BY LOWER(name||addr),id;");
			sqlite3_bind_int (stmt, 1, MR_CONTACT_ID_LAST_SPECIAL);
			sqlite3_bind_int (stmt, 2, MR_ORIGIN_INCOMING_REPLY_TO);
			sqlite3_bind_text(stmt, 3, s3strLikeCmd, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 4, s3strLikeCmd, -1, SQLITE_STATIC);
		}
		else {
			stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_contacts_ORDER_BY,
				"SELECT id FROM contacts"
					" WHERE id>? AND origin>=? AND blocked=0"
					" ORDER BY LOWER(name||addr),id;");
			sqlite3_bind_int(stmt, 1, MR_CONTACT_ID_LAST_SPECIAL);
			sqlite3_bind_int(stmt, 2, MR_ORIGIN_INCOMING_REPLY_TO);
		}

		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	if( s3strLikeCmd ) {
		sqlite3_free(s3strLikeCmd);
	}
	return ret;
}


carray* mrmailbox_get_blocked_contacts(mrmailbox_t* mailbox)
{
	carray*       ret = carray_new(100);
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_contacts_WHERE_blocked,
			"SELECT id FROM contacts"
				" WHERE id>? AND blocked!=0"
				" ORDER BY LOWER(name||addr),id;");
		sqlite3_bind_int(stmt, 1, MR_CONTACT_ID_LAST_SPECIAL);
		while( sqlite3_step(stmt) == SQLITE_ROW ) {
			carray_add(ret, (void*)(uintptr_t)sqlite3_column_int(stmt, 0), NULL);
		}

	mrsqlite3_unlock(mailbox->m_sql);

cleanup:
	return ret;
}


int mrmailbox_get_blocked_count(mrmailbox_t* mailbox)
{
	int           ret = 0;
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_contacts_WHERE_blocked,
			"SELECT COUNT(*) FROM contacts"
				" WHERE id>? AND blocked!=0");
		sqlite3_bind_int(stmt, 1, MR_CONTACT_ID_LAST_SPECIAL);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			goto cleanup;
		}
		ret = sqlite3_column_int(stmt, 0);

	mrsqlite3_unlock(mailbox->m_sql);

cleanup:
	return ret;
}


mrcontact_t* mrmailbox_get_contact(mrmailbox_t* ths, uint32_t contact_id)
{
	mrcontact_t* ret = mrcontact_new();

	mrsqlite3_lock(ths->m_sql);

		if( contact_id == MR_CONTACT_ID_SELF )
		{
			ret->m_id   = contact_id;
			ret->m_name = mrstock_str(MR_STR_SELF);
			ret->m_addr = mrsqlite3_get_config__(ths->m_sql, "configured_addr", NULL);
		}
		else
		{
			if( !mrcontact_load_from_db__(ret, ths->m_sql, contact_id) ) {
				mrcontact_unref(ret);
				ret = NULL;
			}
		}

	mrsqlite3_unlock(ths->m_sql);

	return ret; /* may be NULL */
}


int mrmailbox_block_contact(mrmailbox_t* mailbox, uint32_t contact_id, int new_blocking)
{
	int success = 0, locked = 0, send_event = 0, transaction_pending = 0;
	mrcontact_t*  contact = mrcontact_new();
	sqlite3_stmt* stmt;

	if( mailbox == NULL ) {
		return 0;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( mrcontact_load_from_db__(contact, mailbox->m_sql, contact_id)
		 && contact->m_blocked != new_blocking )
		{
			mrsqlite3_begin_transaction__(mailbox->m_sql);
			transaction_pending = 1;

				stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_contacts_SET_b_WHERE_i,
					"UPDATE contacts SET blocked=? WHERE id=?;");
				sqlite3_bind_int(stmt, 1, new_blocking);
				sqlite3_bind_int(stmt, 2, contact_id);
				if( sqlite3_step(stmt)!=SQLITE_DONE ) {
					goto cleanup;
				}

				/* also (un)block all chats with _only_ this contact - we do not delete them to allow a non-destructive blocking->unblocking.
				(Maybe, beside normal chats (type=100) we should also block group chats with only this user.
				However, I'm not sure about this point; it may be confusing if the user wants to add other people;
				this would result in recreating the same group...) */
				stmt = mrsqlite3_predefine__(mailbox->m_sql, UPDATE_chats_SET_blocked,
					"UPDATE chats SET blocked=? WHERE type=? AND id IN (SELECT chat_id FROM chats_contacts WHERE contact_id=?);");
				sqlite3_bind_int(stmt, 1, new_blocking);
				sqlite3_bind_int(stmt, 2, MR_CHAT_NORMAL);
				sqlite3_bind_int(stmt, 3, contact_id);
				if( sqlite3_step(stmt)!=SQLITE_DONE ) {
					goto cleanup;
				}

			mrsqlite3_commit__(mailbox->m_sql);
			transaction_pending = 0;

			send_event = 1;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( send_event ) {
		mailbox->m_cb(mailbox, MR_EVENT_CONTACTS_CHANGED, 0, 0);
	}

	success = 1;

cleanup:
	if( transaction_pending ) {
		mrsqlite3_rollback__(mailbox->m_sql);
	}

	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}

	mrcontact_unref(contact);
	return success;
}


int mrmailbox_delete_contact(mrmailbox_t* mailbox, uint32_t contact_id)
{
	int           locked = 0, success = 0;
	sqlite3_stmt* stmt;

	if( mailbox == NULL || contact_id <= MR_CONTACT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* we can only delete contacts that are not in use anywhere; this function is mainly for the user who has just
		created an contact manually and wants to delete it a moment later */
		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_chats_contacts_WHERE_contact_id,
			"SELECT COUNT(*) FROM chats_contacts WHERE contact_id=?;");
		sqlite3_bind_int(stmt, 1, contact_id);
		if( sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) >= 1 ) {
			goto cleanup;
		}

		stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_COUNT_FROM_msgs_WHERE_ft,
			"SELECT COUNT(*) FROM msgs WHERE from_id=? OR to_id=?;");
		sqlite3_bind_int(stmt, 1, contact_id);
		sqlite3_bind_int(stmt, 2, contact_id);
		if( sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) >= 1 ) {
			goto cleanup;
		}

		stmt = mrsqlite3_predefine__(mailbox->m_sql, DELETE_FROM_contacts_WHERE_id,
			"DELETE FROM contacts WHERE id=?;");
		sqlite3_bind_int(stmt, 1, contact_id);
		if( sqlite3_step(stmt) != SQLITE_DONE ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	mailbox->m_cb(mailbox, MR_EVENT_CONTACTS_CHANGED, 0, 0);

	success = 1;

cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
	}
	return success;
}


int mrmailbox_contact_addr_equals__(mrmailbox_t* mailbox, uint32_t contact_id, const char* other_addr)
{
	int addr_are_equal = 0;
	if( other_addr ) {
		mrcontact_t* contact = mrcontact_new();
		if( mrcontact_load_from_db__(contact, mailbox->m_sql, contact_id) ) {
			if( contact->m_addr ) {
				if( strcasecmp(contact->m_addr, other_addr)==0 ) {
					addr_are_equal = 1;
				}
			}
		}
		mrcontact_unref(contact);
	}
	return addr_are_equal;
}


mrcontact_t* mrcontact_new()
{
	mrcontact_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrcontact_t)))==NULL ) {
		exit(19); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	return ths;
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
		return;
	}

	ths->m_id = 0;

	free(ths->m_name); /* it is safe to call free(NULL) */
	ths->m_name = NULL;

	free(ths->m_addr);
	ths->m_addr = NULL;

	ths->m_origin = 0;
	ths->m_blocked = 0;

	free(ths->m_pubkey);
	ths->m_pubkey = NULL;

	ths->m_pubkey_timestamp = 0;
}

