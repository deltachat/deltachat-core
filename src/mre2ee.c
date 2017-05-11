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


#include <string.h>
#include "mrmailbox.h"
#include "mre2ee.h"
#include "mre2ee_driver.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


static struct mailimf_fields* find_imf_header(const struct mailmime* mime)
{
	clistiter* cur;
	switch (mime->mm_type) {
		case MAILMIME_MULTIPLE:
			for(cur = clist_begin(mime->mm_data.mm_multipart.mm_mp_list) ; cur != NULL ; cur = clist_next(cur)) {
				struct mailimf_fields* header = find_imf_header(clist_content(cur));
				if( header ) {
					return header;
				}
			}
			break;

		case MAILMIME_MESSAGE:
			return mime->mm_data.mm_message.mm_fields;
	}
	return NULL;
}


static const char* find_autocrypt_header(const struct mailimf_fields* header)
{
	clistiter* cur;
	for( cur = clist_begin(header->fld_list); cur!=NULL ; cur=clist_next(cur) )
	{
		struct mailimf_field* field = (struct mailimf_field*)clist_content(cur);
		if( field )
		{
			if( field->fld_type == MAILIMF_FIELD_OPTIONAL_FIELD )
			{
				struct mailimf_optional_field* optional_field = field->fld_data.fld_optional_field;
				if( optional_field && optional_field->fld_name ) {
					if( strcasecmp(optional_field->fld_name, "Autocrypt")==0 ) {
						return optional_field->fld_value;
					}
				}
			}
		}
	}
	return NULL;
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
	struct mailmime* in_message = NULL;

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL ) {
		return;
	}

	in_message = *in_out_message;
	//mr_print_mime(in_message);

	struct mailimf_fields* header = find_imf_header(in_message);
	if( header == NULL ) {
		goto cleanup;
	}

	const char* autocrypt_header = find_autocrypt_header(header);
	if( autocrypt_header == NULL ) {
		goto cleanup;
	}

cleanup:
	;
}

