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


#include "dc_context.h"
#include "dc_contact.h"
#include "dc_apeerstate.h"


#define DC_CONTACT_MAGIC 0x0c047ac7


/**
 * Create a new contact object in memory.
 * Typically the user does not call this function directly but gets contact
 * objects using dc_get_contact().
 *
 * @private @memberof dc_contact_t
 *
 * @return The contact object. Must be freed using dc_contact_unref() when done.
 */
dc_contact_t* dc_contact_new(dc_context_t* context)
{
	dc_contact_t* contact = NULL;

	if( (contact=calloc(1, sizeof(dc_contact_t)))==NULL ) {
		exit(19); /* cannot allocate little memory, unrecoverable error */
	}

	contact->m_magic   = DC_CONTACT_MAGIC;
	contact->m_context = context;

	return contact;
}


/**
 * Free a contact object.
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object as created eg. by dc_get_contact().
 *
 * @return None.
 */
void dc_contact_unref(dc_contact_t* contact)
{
	if( contact==NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return;
	}

	dc_contact_empty(contact);
	contact->m_magic = 0;
	free(contact);
}


/**
 * Empty a contact object.
 * Typically not needed by the user of the library. To free a contact object,
 * use dc_contact_unref().
 *
 * @private @memberof dc_contact_t
 *
 * @param contact The contact object to free.
 *
 * @return None.
 */
void dc_contact_empty(dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
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


/*******************************************************************************
 * Getters
 ******************************************************************************/


/**
 * Get the ID of the contact.
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return the ID of the contact, 0 on errors.
 */
uint32_t dc_contact_get_id(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return 0;
	}
	return contact->m_id;
}


/**
 * Get email address.  The email address is always set for a contact.
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return String with the email address, must be free()'d. Never returns NULL.
 */
char* dc_contact_get_addr(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return dc_strdup(NULL);
	}

	return dc_strdup(contact->m_addr);
}


/**
 * Get name. This is the name as defined the the contact himself or
 * modified by the user.  May be an empty string.
 *
 * This name is typically used in a form where the user can edit the name of a contact.
 * This name must not be spreaded via mail (To:, CC: ...) as it as it may be sth. like "Daddy".
 * To get a fine name to display in lists etc., use dc_contact_get_display_name() or dc_contact_get_name_n_addr().
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return String with the name to display, must be free()'d. Empty string if unset, never returns NULL.
 */
char* dc_contact_get_name(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return dc_strdup(NULL);
	}

	return dc_strdup(contact->m_name);
}


/**
 * Get display name. This is the name as defined the the contact himself,
 * modified by the user or, if both are unset, the email address.
 *
 * This name is typically used in lists and must not be speaded via mail (To:, CC: ...).
 * To get the name editable in a formular, use dc_contact_get_name().
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return String with the name to display, must be free()'d. Never returns NULL.
 */
char* dc_contact_get_display_name(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return dc_strdup(NULL);
	}

	if( contact->m_name && contact->m_name[0] ) {
		return dc_strdup(contact->m_name);
	}

	return dc_strdup(contact->m_addr);
}


/**
 * Get a summary of name and address.
 *
 * The returned string is either "Name (email@domain.com)" or just
 * "email@domain.com" if the name is unset.
 *
 * The summary is typically used when asking the user something about the contact.
 * The attached email address makes the question unique, eg. "Chat with Alan Miller (am@uniquedomain.com)?"
 *
 * The summary must not be spreaded via mail (To:, CC: ...) as it as it may contain sth. like "Daddy".
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return Summary string, must be free()'d. Never returns NULL.
 */
char* dc_contact_get_name_n_addr(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return dc_strdup(NULL);
	}

	if( contact->m_name && contact->m_name[0] ) {
		return dc_mprintf("%s (%s)", contact->m_name, contact->m_addr);
	}

	return dc_strdup(contact->m_addr);
}


/**
 * Get the part of the name before the first space. In most languages, this seems to be
 * the prename. If there is no space, the full display name is returned.
 * If the display name is not set, the e-mail address is returned.
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return String with the name to display, must be free()'d. Never returns NULL.
 */
char* dc_contact_get_first_name(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return dc_strdup(NULL);
	}

	if( contact->m_name && contact->m_name[0] ) {
		return dc_get_first_name(contact->m_name);
	}

	return dc_strdup(contact->m_addr);
}


/**
 * Check if a contact is blocked.
 *
 * To block or unblock a contact, use dc_block_contact().
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return 1=contact is blocked, 0=contact is not blocked.
 */
int dc_contact_is_blocked(const dc_contact_t* contact)
{
	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		return 0;
	}
	return contact->m_blocked;
}


int dc_contact_n_peerstate_are_verified(const dc_contact_t* contact, const dc_apeerstate_t* peerstate)
{
	int             contact_verified = DC_NOT_VERIFIED;

	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		goto cleanup;
	}

	if( contact->m_id == DC_CONTACT_ID_SELF ) {
		contact_verified = DC_BIDIRECT_VERIFIED;
		goto cleanup; // we're always sort of secured-verified as we could verify the key on this device any time with the key on this device
	}

	contact_verified = peerstate->m_verified_key? DC_BIDIRECT_VERIFIED : 0;

cleanup:
	return contact_verified;
}


/**
 * Check if a contact was verified eg. by a secure-join QR code scan
 * and if the key has not changed since this verification.
 *
 * The UI may draw a checkbox or sth. like that beside verified contacts.
 *
 * @memberof dc_contact_t
 *
 * @param contact The contact object.
 *
 * @return 0: contact is not verified.
 *    2: SELF and contact have verified their fingerprints in both directions; in the UI typically checkmarks are shown.
 */
int dc_contact_is_verified(const dc_contact_t* contact)
{
	int              contact_verified = DC_NOT_VERIFIED;
	dc_apeerstate_t* peerstate        = NULL;

	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC ) {
		goto cleanup;
	}

	peerstate = dc_apeerstate_new(contact->m_context);

	if( !dc_apeerstate_load_by_addr(peerstate, contact->m_context->m_sql, contact->m_addr) ) {
		goto cleanup;
	}

	contact_verified = dc_contact_n_peerstate_are_verified(contact, peerstate);

cleanup:
	dc_apeerstate_unref(peerstate);
	return contact_verified;
}


/**
 * Get the first name.
 *
 * In a string, get the part before the first space.
 * If there is no space in the string, the whole string is returned.
 *
 * @private @memberof dc_contact_t
 *
 * @param full_name Full name of the contact.
 *
 * @return String with the first name, must be free()'d after usage.
 */
char* dc_get_first_name(const char* full_name)
{
	char* first_name = dc_strdup(full_name);
	char* p1 = strchr(first_name, ' ');
	if( p1 ) {
		*p1 = 0;
		dc_rtrim(first_name);
		if( first_name[0]  == 0 ) { /*empty result? use the original string in this case */
			free(first_name);
			first_name = dc_strdup(full_name);
		}
	}

	return first_name;
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


/**
 * Normalize a name in-place.
 *
 * - Remove quotes (come from some bad MUA implementations)
 * - Convert names as "Petersen, Björn" to "Björn Petersen"
 * - Trims the resulting string
 *
 * Typically, this function is not needed as it is called implicitly by dc_add_address_book()
 *
 * @private @memberof dc_contact_t
 *
 * @param full_name Buffer with the name, is modified during processing; the
 *     resulting string may be shorter but never longer.
 *
 * @return None. But the given buffer may be modified.
 */
void dc_normalize_name(char* full_name)
{
	if( full_name == NULL ) {
		return; /* error, however, this can be treated as documented behaviour */
	}

	dc_trim(full_name); /* remove spaces around possible quotes */
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
		char* last_name  = dc_strdup(full_name);
		char* first_name = dc_strdup(p1+1);
		dc_trim(last_name);
		dc_trim(first_name);
		strcpy(full_name, first_name);
		strcat(full_name, " ");
		strcat(full_name, last_name);
		free(last_name);
		free(first_name);
	}
	else {
		dc_trim(full_name);
	}
}


/**
 * Normalize an email address.
 *
 * Normalization includes:
 * - removing `mailto:` prefix
 *
 * Not sure if we should also unifiy international characters before the @,
 * see also https://autocrypt.readthedocs.io/en/latest/address-canonicalization.html
 *
 * @private @memberof dc_contact_t
 *
 * @param email_addr__ The email address to normalize.
 *
 * @return The normalized email address, must be free()'d. NULL is never returned.
 */
char* dc_normalize_addr(const char* email_addr__)
{
	char* addr = dc_strdup(email_addr__);
	dc_trim(addr);
	if( strncmp(addr, "mailto:", 7)==0 ) {
		char* old = addr;
		addr = dc_strdup(&old[7]);
		free(old);
		dc_trim(addr);
	}
	return addr;
}


/**
 * Library-internal.
 *
 * Calling this function is not thread-safe, locking is up to the caller.
 *
 * @private @memberof dc_contact_t
 */
int dc_contact_load_from_db(dc_contact_t* contact, dc_sqlite3_t* sql, uint32_t contact_id)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;

	if( contact == NULL || contact->m_magic != DC_CONTACT_MAGIC || sql == NULL ) {
		goto cleanup;
	}

	dc_contact_empty(contact);

	if( contact_id == DC_CONTACT_ID_SELF )
	{
		contact->m_id   = contact_id;
		contact->m_name = dc_stock_str(contact->m_context, DC_STR_SELF);
		contact->m_addr = dc_sqlite3_get_config(sql, "configured_addr", "");
	}
	else
	{
		stmt = dc_sqlite3_prepare(sql,
			"SELECT c.name, c.addr, c.origin, c.blocked, c.authname "
			" FROM contacts c "
			" WHERE c.id=?;");
		sqlite3_bind_int(stmt, 1, contact_id);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			goto cleanup;
		}

		contact->m_id               = contact_id;
		contact->m_name             = dc_strdup((char*)sqlite3_column_text (stmt, 0));
		contact->m_addr             = dc_strdup((char*)sqlite3_column_text (stmt, 1));
		contact->m_origin           =                  sqlite3_column_int  (stmt, 2);
		contact->m_blocked          =                  sqlite3_column_int  (stmt, 3);
		contact->m_authname         = dc_strdup((char*)sqlite3_column_text (stmt, 4));
	}

	success = 1;

cleanup:
	sqlite3_finalize(stmt);
	return success;
}
