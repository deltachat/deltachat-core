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


#include <memory.h>
#include "dc_context.h"
#include "dc_key.h"
#include "dc_keyring.h"
#include "dc_tools.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


dc_keyring_t* dc_keyring_new()
{
	dc_keyring_t* keyring;

	if( (keyring=calloc(1, sizeof(dc_keyring_t)))==NULL ) {
		exit(42); /* cannot allocate little memory, unrecoverable error */
	}
	return keyring;
}


void dc_keyring_unref(dc_keyring_t* keyring)
{
	int i;
	if( keyring == NULL ) {
		return;
	}

	for( i = 0; i < keyring->m_count; i++ ) {
		dc_key_unref(keyring->m_keys[i]);
	}
	free(keyring->m_keys);
	free(keyring);
}


void dc_keyring_add(dc_keyring_t* keyring, dc_key_t* to_add)
{
	if( keyring==NULL || to_add==NULL ) {
		return;
	}

	/* expand array, if needed */
	if( keyring->m_count == keyring->m_allocated ) {
		int newsize = (keyring->m_allocated * 2) + 10;
		if( (keyring->m_keys=realloc(keyring->m_keys, newsize*sizeof(dc_key_t*)))==NULL ) {
			exit(41);
		}
		keyring->m_allocated = newsize;
	}

	keyring->m_keys[keyring->m_count] = dc_key_ref(to_add);
	keyring->m_count++;
}


int dc_keyring_load_self_private_for_decrypting(dc_keyring_t* keyring, const char* self_addr, dc_sqlite3_t* sql)
{
	if( keyring==NULL || self_addr==NULL || sql==NULL ) {
		return 0;
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(sql,
		"SELECT private_key FROM keypairs ORDER BY addr=? DESC, is_default DESC;");
	sqlite3_bind_text (stmt, 1, self_addr, -1, SQLITE_STATIC);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_key_t* key = dc_key_new();
			if( dc_key_set_from_stmt(key, stmt, 0, DC_KEY_PRIVATE) ) {
				dc_keyring_add(keyring, key);
			}
		dc_key_unref(key); /* unref in any case, dc_keyring_add() adds its own reference */
	}
	sqlite3_finalize(stmt);

	return 1;
}

