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


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mre2ee.h"
#include "mre2ee_driver.h"
#include "mrapeerstate.h"
#include "mraheader.h"
#include "mrmimeparser.h"
#include "mrtools.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mre2ee_init(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	mre2ee_driver_init(mailbox);
}


void mre2ee_exit(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	mre2ee_driver_exit(mailbox);
}


void mre2ee_encrypt(mrmailbox_t* mailbox, const clist* recipients_addr, struct mailmime** in_out_message)
{
	int              locked = 0;
	//struct mailmime* in_message = NULL;

	if( mailbox == NULL || recipients_addr == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	//in_message = *in_out_message;

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* add Autocrypt:-header */
		//mr_print_mime(in_message);

		/* encrypt, if possible */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", 1 /*default is "on"*/) == 0 ) {
			goto cleanup;
		}

		mre2ee_driver_encrypt__(mailbox, recipients_addr, in_out_message);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
}


void mre2ee_decrypt(mrmailbox_t* mailbox, struct mailmime** in_out_message)
{
	struct mailmime*             in_message = NULL;
	const struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mraheader_t*                 autocryptheader = NULL;
	int                          autocryptheader_fine = 0;
	time_t                       message_time = 0;
	mrapeerstate_t*              peerstate = NULL;
	int                          locked = 0;
	char*                        from = NULL;

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	peerstate = mrapeerstate_new();
	autocryptheader = mraheader_new();
	in_message = *in_out_message;
	imffields = mr_find_mailimf_fields(in_message);

	/* get From: and Date: */
	{
		const struct mailimf_field* field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_FROM);
		if( field && field->fld_data.fld_from ) {
			from = mr_find_first_addr(field->fld_data.fld_from->frm_mb_list);
		}

		field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_ORIG_DATE);
		if( field && field->fld_data.fld_orig_date ) {
			struct mailimf_orig_date* orig_date = field->fld_data.fld_orig_date;
			if( orig_date ) {
				message_time = mr_timestamp_from_date(orig_date->dt_date_time); /* is not yet checked against bad times! */
				if( message_time != MR_INVALID_TIMESTAMP && message_time > time(NULL) ) {
					message_time = time(NULL);
				}
			}
		}

		if( message_time <= 0 ) {
			goto cleanup; /* from checked later, may be set by Autocrypt:-header */
		}
	}

	/* check the autocrypt header, if any */
	autocryptheader_fine = mraheader_set_from_imffields(autocryptheader, imffields);
	if( autocryptheader_fine ) {
		if( from == NULL ) {
			from = safe_strdup(autocryptheader->m_to);
		}
		else if( strcasecmp(autocryptheader->m_to, from /*SIC! compare to= against From: - the key is for answering!*/)!=0 ) {
			autocryptheader_fine = 0;
		}
	}

	if( from == NULL ) {
		goto cleanup;
	}

	/* modify the peerstate (eg. if there is a peer but not autocrypt header, stop encryption) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, from) ) {
			if( autocryptheader_fine ) {
				mrapeerstate_apply_header(peerstate, autocryptheader, message_time);
				mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0/*no not create*/);
			}
			else {
				if( message_time > peerstate->m_last_seen ) {
					mrapeerstate_degrade_encryption(peerstate, message_time);
					mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0/*no not create*/);
				}
			}
		}
		else if( autocryptheader_fine ) {
			mrapeerstate_init_from_header(peerstate, autocryptheader, message_time);
			mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 1/*create*/);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* finally, decrypt */
	mre2ee_driver_decrypt__(mailbox, in_out_message);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mraheader_unref(autocryptheader);
	mrapeerstate_unref(peerstate);
	free(from);
}

