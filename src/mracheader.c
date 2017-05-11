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
 * File:    mracheader.c
 * Purpose: Handle Autocrypt:-headers
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mracheader.h"

#define CLASS_MAGIC 1494527378


/*******************************************************************************
 * Parse Header
 ******************************************************************************/


static int mracheader_set_from_string(mracheader_t* ths, const char* header_str)
{
	return 0;
}


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


static const char* find_ac_header_string(const struct mailimf_fields* header)
{
	clistiter*  cur;
	const char* header_str = NULL;

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
						if( header_str ) {
							return NULL; /* if there are multiple Autocrypt:-headers, skip all;  see https://autocrypt.readthedocs.io/en/latest/level0.html#deriving-a-parsed-autocrypt-header-from-a-message  */
						}
						header_str = optional_field->fld_value;
					}
				}
			}
		}
	}

	return header_str;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mracheader_t* mracheader_new()
{
	mracheader_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mracheader_t)))==NULL ) {
		exit(37); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	return ths;
}


void mracheader_unref(mracheader_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mracheader_empty(ths);
	free(ths);
}


void mracheader_empty(mracheader_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	ths->m_pah_prefer_encrypted = 0;

	free(ths->m_to);
	ths->m_to = NULL;

	free(ths->m_pah_key);
	ths->m_pah_key = NULL;
}


int mracheader_set_from_message(mracheader_t* ths, const struct mailmime* mime)
{
	if( ths == NULL || mime == NULL ) {
		return 0;
	}

	struct mailimf_fields* header = find_imf_header(mime);
	if( header == NULL ) {
		return 0;
	}

	return mracheader_set_from_string(ths, find_ac_header_string(header));
}

