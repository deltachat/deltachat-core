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
#include "mrcontact.h"


/**
 * Create a new contact object in memory.
 * Typically the user does not call this function directly but gets contact
 * objects using mrmailbox_get_contact().
 *
 * @private @memberof mrcontact_t
 *
 * @return The contact object. Must be freed using mrcontact_unref() when done.
 */
mrcontact_t* mrcontact_new()
{
	mrcontact_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrcontact_t)))==NULL ) {
		exit(19); /* cannot allocate little memory, unrecoverable error */
	}

	return ths;
}


/**
 * Free a contact object.
 *
 * @memberof mrcontact_t
 *
 * @param contact The contact object as created eg. by mrmailbox_get_contact().
 *
 * @return None.
 */
void mrcontact_unref(mrcontact_t* contact)
{
	if( contact==NULL ) {
		return;
	}

	mrcontact_empty(contact);
	free(contact);
}


/**
 * Empty a contact object.
 * Typically not needed by the user of the library. To free a contact object,
 * use mrcontact_unref().
 *
 * @private @memberof mrcontact_t
 *
 * @param contact The contact object to free.
 *
 * @return None.
 */
void mrcontact_empty(mrcontact_t* contact)
{
	if( contact == NULL ) {
		return;
	}

	contact->m_id = 0;

	free(contact->m_name); /* it is safe to call free(NULL) */
	contact->m_name = NULL;

	free(contact->m_authname);
	contact->m_authname = NULL;

	free(contact->m_addr);
	contact->m_addr = NULL;

	contact->m_origin = 0;
	contact->m_blocked = 0;
}


/**
 * Get the first name.
 *
 * In a string, get the part before the first space.
 * If there is no space in the string, the whole string is returned.
 *
 * @memberof mrcontact_t
 *
 * @param full_name Full name of the contct.
 *
 * @return String with the first name, must be free()'d after usage.
 */
char* mrcontact_get_first_name(const char* full_name)
{
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

	return first_name;
}


/**
 * Normalize a name in-place.
 *
 * - Remove quotes (come from some bad MUA implementations)
 * - Convert names as "Petersen, Björn" to "Björn Petersen"
 * - Trims the resulting string
 *
 * @memberof mrcontact_t
 *
 * @param full_name Buffer with the name, is modified during processing; the
 *     resulting string may be shorter but never longer.
 *
 * @return None. But the given buffer may be modified.
 */
void mrcontact_normalize_name(char* full_name)
{
	if( full_name == NULL ) {
		return; /* error, however, this can be treated as documented behaviour */
	}

	mr_trim(full_name); /* remove spaces around possible quotes */
	int len = strlen(full_name);
	if( len > 0 ) {
		char firstchar = full_name[0], lastchar = full_name[len-1];
		if( (firstchar=='\'' && lastchar=='\'')
		 || (firstchar=='"'  && lastchar=='"' )
		 || (firstchar=='<'  && lastchar=='>' ) ) {
			full_name[0]     = ' ';
			full_name[len-1] = ' '; /* the string is trimmed later again */
		}
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
		free(last_name);
		free(first_name);
	}
	else {
		mr_trim(full_name);
	}
}


/**
 * Library-internal.
 *
 * Calling this function is not thread-safe, locking is up to the caller.
 *
 * @private @memberof mrcontact_t
 */
int mrcontact_load_from_db__(mrcontact_t* ths, mrsqlite3_t* sql, uint32_t contact_id)
{
	int           success = 0;
	sqlite3_stmt* stmt;

	if( ths == NULL || sql == NULL ) {
		return 0;
	}

	mrcontact_empty(ths);

	stmt = mrsqlite3_predefine__(sql, SELECT_naob_FROM_contacts_i,
		"SELECT name, addr, origin, blocked, authname FROM contacts WHERE id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ths->m_id               = contact_id;
	ths->m_name             = safe_strdup((char*)sqlite3_column_text (stmt, 0));
	ths->m_addr             = safe_strdup((char*)sqlite3_column_text (stmt, 1));
	ths->m_origin           =                    sqlite3_column_int  (stmt, 2);
	ths->m_blocked          =                    sqlite3_column_int  (stmt, 3);
	ths->m_authname         = safe_strdup((char*)sqlite3_column_text (stmt, 4));

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	return success;
}
