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
 * File:    mraheader.c
 * Purpose: Handle Autocrypt:-headers
 *
 *******************************************************************************
 *
 * Delta Chat aims to implement Autocrypt-Level0, see
 * https://autocrypt.readthedocs.io/en/latest/level0.html for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <base64.h>
#include "mrmailbox.h"
#include "mrtools.h"
#include "mraheader.h"
#include "mrapeerstate.h"
#include "mrmimeparser.h"

#define CLASS_MAGIC 1494527378


/*******************************************************************************
 * Parse Header
 ******************************************************************************/


char* mraheader_render(const mraheader_t* ths)
{
	int            success = 0;
	char*          keybase64 = NULL;
	char*          keybase64_wrapped = NULL;
	mrstrbuilder_t ret;
	mrstrbuilder_init(&ret);

	if( ths==NULL || ths->m_to==NULL || ths->m_public_key.m_binary==NULL || ths->m_public_key.m_type!=MR_PUBLIC ) {
		goto cleanup;
	}

	mrstrbuilder_cat(&ret, "to=");
	mrstrbuilder_cat(&ret, ths->m_to);
	mrstrbuilder_cat(&ret, "; ");

	if( ths->m_prefer_encrypted==MRA_PE_YES ) {
		mrstrbuilder_cat(&ret, "prefer-encrypted=yes; ");
	}
	else if( ths->m_prefer_encrypted==MRA_PE_NO ) {
		mrstrbuilder_cat(&ret, "prefer-encrypted=no; ");
	}

	mrstrbuilder_cat(&ret, "key= "); /* the trailing space together with mr_insert_spaces() allows a proper transport */

	if( (keybase64 = encode_base64((const char*)ths->m_public_key.m_binary, ths->m_public_key.m_bytes))==NULL ) {
		goto cleanup;
	}

	/* adds a whitespace every 78 characters, this allows libEtPan to wrap the lines according to RFC 5322
	(which may insert a linebreak before every whitespace) */
	if( (keybase64_wrapped = mr_insert_spaces(keybase64, 78)) == NULL ) {
		goto cleanup;
	}

	mrstrbuilder_cat(&ret, keybase64_wrapped);

	success = 1;

cleanup:
	if( !success ) { mrstrbuilder_empty(&ret); }
	free(keybase64);
	free(keybase64_wrapped);
	return ret.m_buf;
}


/*******************************************************************************
 * Parse Header
 ******************************************************************************/


static int add_attribute(mraheader_t* ths, const char* name, const char* value /*may be NULL*/)
{
	/* returns 0 if the attribute will result in an invalid header, 1 if the attribute is okay */
	if( strcasecmp(name, "to")==0 )
	{
		if( value == NULL
		 || strlen(value) < 3 || strchr(value, '@')==NULL || strchr(value, '.')==NULL /* rough check if email-address is valid */
		 || ths->m_to /* email already given */ ) {
			return 0;
		}
		ths->m_to = mr_normalize_addr(value);
		return 1;
	}
	else if( strcasecmp(name, "type")==0 )
	{
		if( value == NULL
		 || strcasecmp(value, "p")!=0) {
			return 0; /* we do not support any types but "p" (=PGP), if the type is ommited, this is okay and we assume "p" */
		}
		return 1;
	}
	else if( strcasecmp(name, "prefer-encrypted")==0 )
	{
		if( value == NULL ) { return 0; }
        if( strcasecmp(value, "no")==0 ) { ths->m_prefer_encrypted = MRA_PE_NO; return 1; }
        if( strcasecmp(value, "yes")==0 ) { ths->m_prefer_encrypted = MRA_PE_YES; return 1; }
		return 0; /* Autocrypt-Level0: If prefer-encrypted is set, but neither yes nor no, the MUA must skip the header as invalid. */
	}
	else if( strcasecmp(name, "key")==0 )
	{
		if( value == NULL
		 || ths->m_public_key.m_binary || ths->m_public_key.m_bytes ) {
			return 0; /* there is already a k*/
		}
		size_t indx = 0, result_len = 0;
		char* result = NULL;
		if( mailmime_base64_body_parse(value, strlen(value), &indx, &result/*must be freed using mmap_string_unref()*/, &result_len)!=MAILIMF_NO_ERROR
		 || result == NULL || result_len == 0 ) {
			return 0; /* bad key */
		}
		mrkey_set_from_raw(&ths->m_public_key, (unsigned char*)result, result_len, MR_PUBLIC);
		mmap_string_unref(result);
		return 1;
	}
	else if( name[0]=='_' )
	{
		/* Autocrypt-Level0: unknown attributes starting with an underscore can be safely ignored */
		return 1;
	}

	/* Autocrypt-Level0: unknown attribute, treat the header as invalid */
	return 0;
}


int mraheader_set_from_string(mraheader_t* ths, const char* header_str__)
{
	/* according to RFC 5322 (Internet Message Format), the given string may contain `\r\n` before any whitespace.
	we can ignore this issue as
	(a) no key or value is expected to contain spaces,
	(b) for the key, non-base64-characters are ignored and
	(c) for parsing, we ignore `\r\n` as well as tabs for spaces */
	#define AHEADER_WS "\t\r\n "
	char    *header_str = NULL;
	char    *p, *beg_attr_name, *after_attr_name, *beg_attr_value;
	int     success = 0;

	mraheader_empty(ths);
	ths->m_prefer_encrypted = MRA_PE_NOPREFERENCE; /* value to use if the prefer-encrypted header is missing */

	if( ths == NULL || header_str__ == NULL ) {
		goto cleanup;
	}

	header_str = safe_strdup(header_str__);
	p = header_str;
	while( *p )
	{
		p += strspn(p, AHEADER_WS "=;"); /* forward to first attribute name beginning */
		beg_attr_name = p;
		beg_attr_value = NULL;
		p += strcspn(p, AHEADER_WS "=;"); /* get end of attribute name (an attribute may have no value) */
		if( p != beg_attr_name )
		{
			/* attribute found */
			after_attr_name = p;
			p += strspn(p, AHEADER_WS); /* skip whitespace between attribute name and possible `=` */
			if( *p == '=' )
			{
				p += strspn(p, AHEADER_WS "="); /* skip spaces and equal signs */

				/* read unquoted attribute value until the first semicolon */
				beg_attr_value = p;
				p += strcspn(p, ";");
				if( *p != '\0' ) {
					*p = '\0';
					p++;
				}
				mr_trim(beg_attr_value);
			}
			else
			{
				p += strspn(p, AHEADER_WS ";");
			}
			*after_attr_name = '\0';
			if( !add_attribute(ths, beg_attr_name, beg_attr_value) ) {
				goto cleanup; /* a bad attribute makes the whole header invalid */
			}
		}
	}

	/* all needed data found? */
	if( ths->m_to && ths->m_public_key.m_binary ) {
		success = 1;
	}

cleanup:
	free(header_str);
	if( !success ) { mraheader_empty(ths); }
	return success;
}


static const char* find_aheader_string(const struct mailimf_fields* header)
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
							return NULL; /* Autocrypt-Level0: if there are multiple Autocrypt:-headers  */
						}
						header_str = optional_field->fld_value;
					}
				}
			}
		}
	}

	return header_str; /* may be NULL */
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mraheader_t* mraheader_new()
{
	mraheader_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mraheader_t)))==NULL ) {
		exit(37); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	return ths;
}


void mraheader_unref(mraheader_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mraheader_empty(ths);
	free(ths);
}


void mraheader_empty(mraheader_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	ths->m_prefer_encrypted = 0;

	free(ths->m_to);
	ths->m_to = NULL;

	mrkey_empty(&ths->m_public_key);
}


int mraheader_set_from_imffields(mraheader_t* ths, const struct mailimf_fields* header)
{
	if( ths == NULL || header == NULL ) {
		return 0;
	}

	return mraheader_set_from_string(ths, find_aheader_string(header));
}

