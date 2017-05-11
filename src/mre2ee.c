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
#include "mracpeerstate.h"
#include "mracheader.h"


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
	struct mailmime* in_message = NULL;

	if( mailbox == NULL || recipients_addr == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	in_message = *in_out_message;

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
	struct mailmime*  in_message = NULL;
	mracheader_t*     ach = mracheader_new();
	mracpeerstate_t*  acps = NULL;
	int               locked = 0;

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	in_message = *in_out_message;
	//mr_print_mime(in_message);

	if( mracheader_set_from_message(ach, in_message) ) {
		// TODO: check against To:-header
		acps = mracpeerstate_new();
		mrsqlite3_lock(mailbox->m_sql);
		locked = 1;
			if( mracpeerstate_load_from_db__(acps, mailbox->m_sql, ach->m_to) ) {
				mracpeerstate_apply_header(acps, ach);
				// TODO: save peer state back to db
			}
		mrsqlite3_lock(mailbox->m_sql);
		locked = 0;

	}


cleanup:
	if( locked ) {
		mrsqlite3_unlock(mailbox->m_sql);
		locked = 0;
	}
	mracheader_unref(ach);
	mracpeerstate_unref(acps);
}

