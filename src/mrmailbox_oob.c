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


#include <stdarg.h>
#include "mrmailbox_internal.h"
#include "mrkey.h"
#include "mrapeerstate.h"


char* mrmailbox_get_qr(mrmailbox_t* mailbox)
{
	int      locked               = 0;
	char*    qr                   = NULL;
	char*    self_addr            = NULL;
	char*    self_addr_urlencoded = NULL;
	char*    self_name            = NULL;
	char*    self_name_urlencoded = NULL;
	mrkey_t* self_key             = mrkey_new();
	char*    fingerprint          = NULL;

	if( mailbox == NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( (self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL)) == NULL
		 || !mrkey_load_self_public__(self_key, self_addr, mailbox->m_sql) ) {
			mrmailbox_log_error(mailbox, 0, "Cannot get QR-code for unconfigured mailbox.");
			goto cleanup;
		}

		self_name = mrsqlite3_get_config__(mailbox->m_sql, "displayname", "");

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( (fingerprint=mrkey_get_fingerprint(self_key)) == NULL ) {
		goto cleanup;
	}

	#define OPENPGP4FPR_SCHEME "OPENPGP4FPR:"
	self_addr_urlencoded = mr_url_encode(self_addr);
	self_name_urlencoded = mr_url_encode(self_name);
	qr = mr_mprintf(OPENPGP4FPR_SCHEME "%s#v=%s&n=%s", fingerprint, self_addr_urlencoded, self_name_urlencoded);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrkey_unref(self_key);
	free(self_addr_urlencoded);
	free(self_addr);
	free(self_name);
	free(self_name_urlencoded);
	free(fingerprint);
	return qr? qr : safe_strdup(NULL);
}


/**
 * Check a scanned QR code.
 * The function should be called after a QR-code is scanned.
 * The function takes the raw text scanned and checks what can be done with it.
 */
mrlot_t* mrmailbox_check_scanned_qr(mrmailbox_t* mailbox, const char* qr)
{
	int             locked      = 0;
	char*           addr        = NULL; /* must be normalized, if set */
	char*           fingerprint = NULL; /* must be normalized, if set */
	char*           name        = NULL;
	mrapeerstate_t* peerstate   = mrapeerstate_new();
	mrlot_t*        ret         = mrlot_new();

	ret->m_state = 0;

	if( mailbox==NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC || qr==NULL ) {
		goto cleanup;
	}

	mrmailbox_log_info(mailbox, 0, "Scanned QR code: %s", qr);

	/* split parameters from the qr code */
	if( strncasecmp(qr, OPENPGP4FPR_SCHEME, strlen(OPENPGP4FPR_SCHEME)) == 0 )
	{
		/* scheme: OPENPGP4FPR:1234567890123456789012345678901234567890#v=mail%40domain.de&n=Name */
		char* payload  = safe_strdup(&qr[strlen(OPENPGP4FPR_SCHEME)]);
		char* fragment = strchr(payload, '#'); /* must not be freed, only a pointer inside payload */
		if( fragment )
		{
			*fragment = 0;
			fragment++;

			mrparam_t* param = mrparam_new();
			mrparam_set_urlencoded(param, fragment);

			char* addr_urlencoded = mrparam_get(param, 'v', NULL);
			if( addr_urlencoded ) {
				char* addr_unnormalized = mr_url_decode(addr_urlencoded);
					addr = mr_normalize_addr(addr_unnormalized);
				free(addr_unnormalized);
				free(addr_urlencoded);

				char* name_urlencoded = mrparam_get(param, 'n', NULL);
				if( name_urlencoded ) {
					name = mr_url_decode(name_urlencoded);
					mr_normalize_name(name);
					free(name_urlencoded);
				}
			}

			mrparam_unref(param);
		}

		fingerprint = mr_normalize_fingerprint(payload);
		free(payload);
	}

	/* check some paramters */
	if( addr ) {
		if( strlen(addr) < 3 || strchr(addr, '@')==NULL || strchr(addr, '.')==NULL ) {
			ret->m_state = MR_QR_ERROR;
			ret->m_text1 = safe_strdup("Bad e-mail address.");
			goto cleanup;
		}
	}

	if( fingerprint ) {
		if( strlen(fingerprint) != 40 ) {
			ret->m_state = MR_QR_ERROR;
			ret->m_text1 = safe_strdup("Bad fingerprint length in QR code.");
			goto cleanup;
		}
	}

	/* let's see what we can do with the parameters */
	if( fingerprint )
	{
		/* fingerprint set ... */

		ret->m_text1 = safe_strdup(fingerprint);
		ret->m_text2 = mr_format_fingerprint(fingerprint);

		if( addr == NULL )
		{
			/* _only_ fingerprint set ... */
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				if( mrapeerstate_load_by_fingerprint__(peerstate, mailbox->m_sql, fingerprint) ) {
					ret->m_state = MR_QR_ASK_CMP_FINGERPRINT;
					ret->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, NULL, peerstate->m_addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
				}
				else {
					ret->m_state = MR_QR_FINGERPRINT_WITHOUT_ADDR;
				}

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
		else
		{
			/* fingerprint and addr set ... */
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				ret->m_state = MR_QR_ASK_CMP_FINGERPRINT;
				ret->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
	}
	else if( addr )
	{
        ret->m_state = MR_QR_ADDR;
		ret->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
	}
	else
	{
        ret->m_state = MR_QR_TEXT;
		ret->m_text1 = safe_strdup(qr);
	}

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	free(addr);
	free(fingerprint);
	mrapeerstate_unref(peerstate);
	return ret;
}
