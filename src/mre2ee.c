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
 * Tools
 ******************************************************************************/


static int load_or_generate_public_key__(mrmailbox_t* mailbox, mrkey_t* public_key, const char* self_addr)
{
	static int s_in_key_creation = 0; /* avoid double creation (we unlock the database during creation) */
	int        key_created = 0;
	int        success = 0, key_creation_here = 0;

	if( mailbox == NULL || public_key == NULL ) {
		goto cleanup;
	}

	if( !mrkey_load_public__(public_key, mailbox->m_sql) )
	{
		/* create the keypair - this may take a moment, however, as this is in a thread, this is no big deal */
		if( s_in_key_creation ) { goto cleanup; }
		key_creation_here = 1;
		s_in_key_creation = 1;

		{
			mrkey_t private_key;
			mrkey_init(&private_key);

			mrmailbox_log_info(mailbox, 0, "Generating keypair ...");

			mrsqlite3_unlock(mailbox->m_sql); /* SIC! unlock database during creation - otherwise the GUI may hang */

				key_created = mre2ee_driver_create_keypair(mailbox, self_addr, public_key, &private_key);

			mrsqlite3_lock(mailbox->m_sql);

			if( !key_created ) {
				mrmailbox_log_warning(mailbox, 0, "Cannot create keypair.");
				goto cleanup;
			}

			if( !mrkey_save_keypair__(public_key, &private_key, self_addr, mailbox->m_sql) ) {
				mrmailbox_log_warning(mailbox, 0, "Cannot save keypair.");
				goto cleanup;
			}

			mrmailbox_log_info(mailbox, 0, "Keypair generated.");

			mrkey_empty(&private_key);
		}
	}

	success = 1;

cleanup:
	if( key_creation_here ) { s_in_key_creation = 0; }
	return success;
}


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
	int                    locked = 0;
	mrapeerstate_t*        peerstate = NULL;
	mraheader_t*           autocryptheader = NULL;
	struct mailmime*       in_message = NULL;
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	clistiter*             iter1;
	const char*            recipient_addr; /* just a pointer inside recipients_addr, must not be freed */

	if( mailbox == NULL || recipients_addr == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* encryption enabled? */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", MR_E2EE_DEFAULT_ENABLED) == 0 ) {
			goto cleanup;
		}

		/* add Autocrypt:-header to allow the recipient to send us encrypted messages back */
		autocryptheader = mraheader_new();
		autocryptheader->m_prefer_encrypted = MRA_PE_YES;

		autocryptheader->m_to = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
		if( autocryptheader->m_to == NULL ) {
			goto cleanup;
		}

		if( !load_or_generate_public_key__(mailbox, &autocryptheader->m_public_key, autocryptheader->m_to) ) {
			goto cleanup;
		}

		in_message = *in_out_message;
		imffields = mr_find_mailimf_fields(in_message);
		char* p = mraheader_render(autocryptheader);
		if( p == NULL ) {
			goto cleanup;
		}
		mailimf_fields_add(imffields, mailimf_field_new_custom(strdup("Autocrypt"), p/*takes ownership of pointer*/));

		/* encrypt messasge, if possible */
		if( clist_count(recipients_addr)!=1 ) {
			goto cleanup;
		}

		iter1 = clist_begin(recipients_addr);
		recipient_addr = clist_content(iter1);

		peerstate = mrapeerstate_new();
		if( !mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, recipient_addr)
		 || peerstate->m_prefer_encrypted==MRA_PE_NO ) {
			goto cleanup;
		}

		mre2ee_driver_encrypt__(mailbox, in_out_message, &peerstate->m_public_key);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrapeerstate_unref(peerstate);
	mraheader_unref(autocryptheader);
}


void mre2ee_decrypt(mrmailbox_t* mailbox, struct mailmime** in_out_message)
{
	struct mailmime*       in_message = NULL;
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mraheader_t*           autocryptheader = NULL;
	int                    autocryptheader_fine = 0;
	time_t                 message_time = 0;
	mrapeerstate_t*        peerstate = NULL;
	int                    locked = 0;
	char*                  from = NULL;
	mrkey_t                private_key;
	mrkey_init(&private_key);

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	peerstate = mrapeerstate_new();
	autocryptheader = mraheader_new();
	in_message = *in_out_message;
	imffields = mr_find_mailimf_fields(in_message);

	/* get From: and Date: */
	{
		struct mailimf_field* field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_FROM);
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

		/* apply Autocrypt:-header only if encryption is enabled (if we're out of beta, we should do this always to track the correct state; now we want no bugs spread widely to the databases :-) */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", MR_E2EE_DEFAULT_ENABLED) != 0 )
		{
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
		}

		/* load private key for decryption */
		if( !mrkey_load_private__(&private_key, mailbox->m_sql) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* finally, decrypt */
	mre2ee_driver_decrypt__(mailbox, in_out_message, &private_key);

	mrkey_empty(&private_key); /* this also wipes the key */

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mraheader_unref(autocryptheader);
	mrapeerstate_unref(peerstate);
	free(from);
}

