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
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
		locked = 0;
	}
}


void mre2ee_decrypt(mrmailbox_t* mailbox, struct mailmime** in_out_message)
{
	struct mailmime*             in_message = NULL;
	const struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mraheader_t*                 autocryptheader = NULL;
	mrapeerstate_t*              peerstate = NULL;
	int                          locked = 0;
	char*                        from = NULL;

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	autocryptheader = mraheader_new();
	in_message = *in_out_message;
	imffields = mr_find_mailimf_fields(in_message);

	if( mraheader_set_from_imffields(autocryptheader, imffields) )
	{
		const struct mailimf_field* field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_FROM);
		if( field && field->fld_data.fld_from )
		{
			from = mr_find_first_addr(field->fld_data.fld_from->frm_mb_list);
			if( strcasecmp(autocryptheader->m_to, from /*SIC! compare to= against From: - the key is for answering!*/)==0 )
			{
				peerstate = mrapeerstate_new();
				mrsqlite3_lock(mailbox->m_sql);
				locked = 1;
					if( mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, autocryptheader->m_to) ) {
						if( mrapeerstate_apply_header(peerstate, autocryptheader) ) {
							mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0/*no not create*/);
						}
					}
					else {
						mrapeerstate_init_from_header(peerstate, autocryptheader);
						mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 1/*create*/);
					}
				mrsqlite3_unlock(mailbox->m_sql);
				locked = 0;
			}
		}
	}

/*cleanup:*/
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mraheader_unref(autocryptheader);
	mrapeerstate_unref(peerstate);
	free(from);
}

