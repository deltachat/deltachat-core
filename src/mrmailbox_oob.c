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
	char*    qr                   = NULL;
	char*    self_addr            = NULL;
	char*    self_addr_urlencoded = NULL;
	mrkey_t* self_key             = mrkey_new();
	char*    fingerprint          = NULL;

	if( mailbox == NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	if( (self_addr=mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL))==NULL ) {
		mrmailbox_log_error(mailbox, 0, "Cannot get QR-code for unconfigured mailbox.");
		goto cleanup;
	}

	if( !mrkey_load_self_public__(self_key, self_addr, mailbox->m_sql)
	 || (fingerprint=mrkey_get_fingerprint(self_key)) == NULL ) {
		goto cleanup;
	}

	#define OPENPGP4FPR_SCHEME "OPENPGP4FPR:"
	self_addr_urlencoded = mr_url_encode(self_addr);
	qr = mr_mprintf(OPENPGP4FPR_SCHEME "%s#v=%s", fingerprint, self_addr_urlencoded);

cleanup:
	mrkey_unref(self_key);
	free(self_addr_urlencoded);
	free(self_addr);
	free(fingerprint);
	return qr? qr : safe_strdup(NULL);
}


mrlot_t* mrmailbox_check_scanned_qr(mrmailbox_t* mailbox, const char* qr)
{
	char*      addr        = NULL; /* must be normalized, if set */
	char*      fingerprint = NULL; /* must be normalized, if set */
	mrlot_t*   ret         = mrlot_new();

	ret->m_state = MR_QR_UNKNOWN;

	if( mailbox==NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC || qr==NULL ) {
		goto cleanup;
	}

	mrmailbox_log_info(mailbox, 0, "Scanned QR code: %s", qr);

	/* split parameters from the qr code */
	if( strncasecmp(qr, OPENPGP4FPR_SCHEME, strlen(OPENPGP4FPR_SCHEME)) == 0 )
	{
		/* scheme: OPENPGP4FPR:1234567890123456789012345678901234567890#v=mail%40domain.de */
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
			}

			mrparam_unref(param);
		}

		fingerprint = mr_normalize_fingerprint(payload);
		free(payload);
	}

	/* let's see what we can do with the parameters */
	if( fingerprint )
	{
		if( strlen(fingerprint) != 40 ) {
			ret->m_state = MR_QR_FINGERPRINT_SYNTAX_ERR;
			goto cleanup;
		}

		ret->m_state = MR_QR_FINGERPRINT_NOT_FOUND;
		ret->m_text1 = safe_strdup(fingerprint);
		ret->m_text2 = strdup_keep_null(addr);

		mrapeerstate_t* peerstate = mrapeerstate_new();
		if( mrapeerstate_load_by_fingerprint__(peerstate, mailbox->m_sql, fingerprint) ) {
			if( addr == NULL ) {
				ret->m_state = MR_QR_FINGERPRINT_FOUND;
			}
			else {
				if( strcasecmp(addr, peerstate->m_addr)==0 ) {
					ret->m_state = MR_QR_FINGERPRINT_FOUND;
				}
			}
		}
		mrapeerstate_unref(peerstate);
	}
	else if( addr )
	{
        ret->m_state = MR_QR_ADDR_FOUND;
		ret->m_text2 = safe_strdup(addr);
	}

cleanup:
	free(addr);
	free(fingerprint);
	if( ret->m_state >= 400 && ret->m_state <= 499 ) {
		free(ret->m_text1);
		free(ret->m_text2);
		ret->m_text1 = safe_strdup(qr);
		ret->m_text2 = NULL;
	}
	return ret;
}
