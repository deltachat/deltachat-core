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


char* mrmailbox_get_qr(mrmailbox_t* mailbox)
{
	char*    qr          = NULL;
	char*    self_addr   = NULL;
	mrkey_t* self_key    = mrkey_new();
	char*    fingerprint = NULL;

	if( mailbox == NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	if( (self_addr=mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL))==NULL ) {
		mrmailbox_log_error(mailbox, 0, "Cannot get QR-code for unconfigured mailbox.");
		goto cleanup;
	}

	if( !mrkey_load_self_public__(self_key, self_addr, mailbox->m_sql)
	 || (fingerprint=mrkey_get_fingerprint(self_key, mailbox)) == NULL ) {
		goto cleanup;
	}

	qr = mr_mprintf("OPENPGP4FPR:%s#v=%s", fingerprint, self_addr);

cleanup:
	mrkey_unref(self_key);
	free(self_addr);
	free(fingerprint);
	return qr? qr : safe_strdup(NULL);
}


mrlot_t* mrmailbox_check_scanned_qr(mrmailbox_t* mailbox, const char* qr)
{
	mrlot_t* ret = mrlot_new();

	if( mailbox==NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC || qr==NULL ) {
		goto cleanup;
	}

	mrmailbox_log_info(mailbox, 0, "Scanned QR code: %s", qr);

cleanup:
	return ret;
}
