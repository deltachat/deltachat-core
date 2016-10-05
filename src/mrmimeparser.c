/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
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
 * File:    mrmimeparser.c
 * Authors: Björn Petersen
 * Purpose: Parse MIME body, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrmimeparser.h"
#include "mrsimplify.h"
#include "mrtools.h"
#include "mrlog.h"


/*******************************************************************************
 * debug output
 ******************************************************************************/


#define DEBUG_MIME_OUTPUT 0


#if DEBUG_MIME_OUTPUT


static void display_mime_content(struct mailmime_content * content_type);

static void display_mime_data(struct mailmime_data * data)
{
  switch (data->dt_type) {
  case MAILMIME_DATA_TEXT:
    printf("data : %u bytes\n", (unsigned int) data->dt_data.dt_text.dt_length);
    break;
  case MAILMIME_DATA_FILE:
    printf("data (file) : %s\n", data->dt_data.dt_filename);
    break;
  }
}

static void display_mime_dsp_parm(struct mailmime_disposition_parm * param)
{
  switch (param->pa_type) {
  case MAILMIME_DISPOSITION_PARM_FILENAME:
    printf("filename: %s\n", param->pa_data.pa_filename);
    break;
  }
}

static void display_mime_disposition(struct mailmime_disposition * disposition)
{
  clistiter * cur;

  for(cur = clist_begin(disposition->dsp_parms) ;
    cur != NULL ; cur = clist_next(cur)) {
    struct mailmime_disposition_parm * param;

    param = (mailmime_disposition_parm*)clist_content(cur);
    display_mime_dsp_parm(param);
  }
}

static void display_mime_field(struct mailmime_field * field)
{
	switch (field->fld_type) {
		case MAILMIME_FIELD_TYPE:
		printf("content-type: ");
		display_mime_content(field->fld_data.fld_content);
	  printf("\n");
		break;
		case MAILMIME_FIELD_DISPOSITION:
		display_mime_disposition(field->fld_data.fld_disposition);
		break;
	}
}

static void display_mime_fields(struct mailmime_fields * fields)
{
	clistiter * cur;

	for(cur = clist_begin(fields->fld_list) ; cur != NULL ; cur = clist_next(cur)) {
		struct mailmime_field * field;

		field = (mailmime_field*)clist_content(cur);
		display_mime_field(field);
	}
}

static void display_date_time(struct mailimf_date_time * d)
{
  printf("%02i/%02i/%i %02i:%02i:%02i %+04i",
    d->dt_day, d->dt_month, d->dt_year,
    d->dt_hour, d->dt_min, d->dt_sec, d->dt_zone);
}

static void display_orig_date(struct mailimf_orig_date * orig_date)
{
  display_date_time(orig_date->dt_date_time);
}

static void display_mailbox(struct mailimf_mailbox * mb)
{
  if (mb->mb_display_name != NULL)
    printf("%s ", mb->mb_display_name);
  printf("<%s>", mb->mb_addr_spec);
}

static void display_mailbox_list(struct mailimf_mailbox_list * mb_list)
{
  clistiter * cur;

  for(cur = clist_begin(mb_list->mb_list) ; cur != NULL ;
    cur = clist_next(cur)) {
    struct mailimf_mailbox * mb;

    mb = (mailimf_mailbox*)clist_content(cur);

    display_mailbox(mb);
		if (clist_next(cur) != NULL) {
			printf(", ");
		}
  }
}

static void display_group(struct mailimf_group * group)
{
	clistiter * cur;

  printf("%s: ", group->grp_display_name);
  for(cur = clist_begin(group->grp_mb_list->mb_list) ; cur != NULL ; cur = clist_next(cur)) {
    struct mailimf_mailbox * mb;

    mb = (mailimf_mailbox*)clist_content(cur);
    display_mailbox(mb);
  }
	printf("; ");
}

static void display_address(struct mailimf_address * a)
{
  switch (a->ad_type) {
    case MAILIMF_ADDRESS_GROUP:
      display_group(a->ad_data.ad_group);
      break;

    case MAILIMF_ADDRESS_MAILBOX:
      display_mailbox(a->ad_data.ad_mailbox);
      break;
  }
}

static void display_address_list(struct mailimf_address_list * addr_list)
{
  clistiter * cur;

  for(cur = clist_begin(addr_list->ad_list) ; cur != NULL ;
    cur = clist_next(cur)) {
    struct mailimf_address * addr;

    addr = (mailimf_address*)clist_content(cur);

    display_address(addr);

		if (clist_next(cur) != NULL) {
			printf(", ");
		}
  }
}

static void display_from(struct mailimf_from * from)
{
  display_mailbox_list(from->frm_mb_list);
}

static void display_to(struct mailimf_to * to)
{
  display_address_list(to->to_addr_list);
}

static void display_cc(struct mailimf_cc * cc)
{
  display_address_list(cc->cc_addr_list);
}

static void display_subject(struct mailimf_subject * subject)
{
  printf("%s", subject->sbj_value);
}

static void display_field(struct mailimf_field * field)
{
  switch (field->fld_type) {
  case MAILIMF_FIELD_ORIG_DATE:
    printf("Date: ");
    display_orig_date(field->fld_data.fld_orig_date);
		printf("\n");
    break;
  case MAILIMF_FIELD_FROM:
    printf("From: ");
    display_from(field->fld_data.fld_from);
		printf("\n");
    break;
  case MAILIMF_FIELD_TO:
    printf("To: ");
    display_to(field->fld_data.fld_to);
		printf("\n");
    break;
  case MAILIMF_FIELD_CC:
    printf("Cc: ");
    display_cc(field->fld_data.fld_cc);
		printf("\n");
    break;
  case MAILIMF_FIELD_SUBJECT:
    printf("Subject: ");
    display_subject(field->fld_data.fld_subject);
		printf("\n");
    break;
  case MAILIMF_FIELD_MESSAGE_ID:
    printf("Message-ID: %s\n", field->fld_data.fld_message_id->mid_value);
    break;
  }
}

static void display_fields(struct mailimf_fields * fields)
{
  clistiter * cur;

  for(cur = clist_begin(fields->fld_list) ; cur != NULL ;
    cur = clist_next(cur)) {
    struct mailimf_field * f;

    f = (mailimf_field*)clist_content(cur);

    display_field(f);
  }
}

static void display_mime_discrete_type(struct mailmime_discrete_type * discrete_type)
{
  switch (discrete_type->dt_type) {
  case MAILMIME_DISCRETE_TYPE_TEXT:
    printf("text");
    break;
  case MAILMIME_DISCRETE_TYPE_IMAGE:
    printf("image");
    break;
  case MAILMIME_DISCRETE_TYPE_AUDIO:
    printf("audio");
    break;
  case MAILMIME_DISCRETE_TYPE_VIDEO:
    printf("video");
    break;
  case MAILMIME_DISCRETE_TYPE_APPLICATION:
    printf("application");
    break;
  case MAILMIME_DISCRETE_TYPE_EXTENSION:
    printf("%s", discrete_type->dt_extension);
    break;
  }
}

static void display_mime_composite_type(struct mailmime_composite_type * ct)
{
  switch (ct->ct_type) {
  case MAILMIME_COMPOSITE_TYPE_MESSAGE:
    printf("message");
    break;
  case MAILMIME_COMPOSITE_TYPE_MULTIPART:
    printf("multipart");
    break;
  case MAILMIME_COMPOSITE_TYPE_EXTENSION:
    printf("%s", ct->ct_token);
    break;
  }
}

static void display_mime_type(struct mailmime_type * type)
{
  switch (type->tp_type) {
  case MAILMIME_TYPE_DISCRETE_TYPE:
    display_mime_discrete_type(type->tp_data.tp_discrete_type);
    break;
  case MAILMIME_TYPE_COMPOSITE_TYPE:
    display_mime_composite_type(type->tp_data.tp_composite_type);
    break;
  }
}

static void display_mime_content(struct mailmime_content * content_type)
{
  printf("type: ");
  display_mime_type(content_type->ct_type);
  printf("/%s\n", content_type->ct_subtype);
}

static void display_mime(struct mailmime * mime)
{
	clistiter * cur;

	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			printf("single part\n");
			break;
		case MAILMIME_MULTIPLE:
			printf("multipart\n");
			break;
		case MAILMIME_MESSAGE:
			printf("message\n");
			break;
	}

	if (mime->mm_mime_fields != NULL) {
		if (clist_begin(mime->mm_mime_fields->fld_list) != NULL) {
			printf("+++ MIME headers begin\n");
			display_mime_fields(mime->mm_mime_fields);
			printf("+++ MIME headers end\n");
		}
	}

	display_mime_content(mime->mm_content_type);

	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			display_mime_data(mime->mm_data.mm_single);
			break;

		case MAILMIME_MULTIPLE:
			for(cur = clist_begin(mime->mm_data.mm_multipart.mm_mp_list) ; cur != NULL ; cur = clist_next(cur)) {
				display_mime((mailmime*)clist_content(cur));
			}
			break;

		case MAILMIME_MESSAGE:
			if (mime->mm_data.mm_message.mm_fields) {
				if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list) != NULL) {
					printf("E-Mail headers begin\n");
					display_fields(mime->mm_data.mm_message.mm_fields);
					printf("E-Mail headers end\n");
				}

				if (mime->mm_data.mm_message.mm_msg_mime != NULL) {
					display_mime(mime->mm_data.mm_message.mm_msg_mime);
				}
			}
			break;
	}
}

#endif /* DEBUG_MIME_OUTPUT */



/*******************************************************************************
 * a MIME part
 ******************************************************************************/


mrmimepart_t* mrmimepart_new()
{
	mrmimepart_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmimepart_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_type    = MR_MSG_UNDEFINED;
	ths->m_msg     = NULL;
	ths->m_msg_raw = NULL;

	return ths;
}


void mrmimepart_unref(mrmimepart_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_msg ) {
		free(ths->m_msg);
		ths->m_msg = NULL;
	}

	if( ths->m_msg_raw ) {
		free(ths->m_msg_raw);
		ths->m_msg_raw = NULL;
	}

	free(ths);
}


/*******************************************************************************
 * MIME parser
 ******************************************************************************/


mrmimeparser_t* mrmimeparser_new_()
{
	mrmimeparser_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmimeparser_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_parts          = carray_new(16);
	ths->m_header         = NULL;
	ths->m_subjectEncoded = NULL;
	ths->m_mimeroot       = NULL;

	return ths;
}


void mrmimeparser_unref_(mrmimeparser_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	mrmimeparser_empty_(ths);
	if( ths->m_parts ) {
		carray_free(ths->m_parts);
	}
	free(ths);
}


void mrmimeparser_empty_(mrmimeparser_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	if( ths->m_parts )
	{
		int i, cnt = carray_count(ths->m_parts);
		for( i = 0; i < cnt; i++ ) {
			mrmimepart_t* part = (mrmimepart_t*)carray_get(ths->m_parts, i);
			if( part ) {
				mrmimepart_unref(part);
			}
		}
		carray_set_size(ths->m_parts, 0);
	}

	ths->m_header         = NULL; /* a pointer somewhere to the MIME data, must not be freed */
	ths->m_subjectEncoded = NULL; /* a pointer somewhere to the MIME data, must not be freed */

	if( ths->m_mimeroot )
	{
		mailmime_free(ths->m_mimeroot);
		ths->m_mimeroot = NULL;
	}
}


int mrmimeparser_get_mime_type_(struct mailmime_content* c)
{
	if( c == NULL || c->ct_type == NULL ) {
		return 0; /* error */
	}

	switch( c->ct_type->tp_type )
	{
		case MAILMIME_TYPE_DISCRETE_TYPE:
			switch( c->ct_type->tp_data.tp_discrete_type->dt_type )
			{
				case MAILMIME_DISCRETE_TYPE_TEXT:
					if( strcmp(c->ct_subtype, "plain")==0 ) {
						return MR_MIMETYPE_TEXT_PLAIN;
                    }
					else if( strcmp(c->ct_subtype, "html")==0 ) {
						return MR_MIMETYPE_TEXT_HTML;
                    }
                    else {
						return MR_MIMETYPE_TEXT;
                    }

				case MAILMIME_DISCRETE_TYPE_IMAGE:
					return MR_MIMETYPE_IMAGE;

				case MAILMIME_DISCRETE_TYPE_AUDIO:
					return MR_MIMETYPE_AUDIO;

				case MAILMIME_DISCRETE_TYPE_VIDEO:
					return MR_MIMETYPE_VIDEO;

				default:
					return MR_MIMETYPE_FILE;
			}
			break;

		case MAILMIME_TYPE_COMPOSITE_TYPE:
			if( c->ct_type->tp_data.tp_composite_type->ct_type == MAILMIME_COMPOSITE_TYPE_MULTIPART )
			{
				if( strcmp(c->ct_subtype, "alternative")==0 ) {
					return MR_MIMETYPE_MP_ALTERNATIVE;
				}
				else if( strcmp(c->ct_subtype, "related")==0 ) {
					return MR_MIMETYPE_MP_RELATED;
				}
				else { /* eg. "mixed" */
					return MR_MIMETYPE_MP;
				}
			}
			break;

		default:
			break;
	}

	return 0; /* unknown */
}


static int mrmimeparser_add_single_part_if_known_(mrmimeparser_t* ths, struct mailmime* mime)
{
	mrmimepart_t*  part = mrmimepart_new();
	int            do_add_part = 0;

	int            mime_type;
	struct mailmime_data* mime_data;
	int            mime_transfer_encoding = MAILMIME_MECHANISM_BINARY;

	char*          transfer_decoding_buffer = NULL; /* mmap_string_unref()'d if set */
	char*          charset_buffer = NULL; /* charconv_buffer_free()'d if set (just calls mmap_string_unref()) */

	const char*    decoded_data = NULL; /* must not be free()'d */
	size_t         decoded_data_bytes = 0;

	mrsimplify_t*  simplifier = NULL;

	if( mime == NULL || mime->mm_data.mm_single == NULL || part == NULL ) {
		goto AddSinglePart_Cleanup; /* error */
	}

	/* get mime type from `mime` */
	mime_type = mrmimeparser_get_mime_type_(mime->mm_content_type);

	/* get data pointer from `mime` */
	mime_data = mime->mm_data.mm_single;
	if( mime_data->dt_type != MAILMIME_DATA_TEXT   /* MAILMIME_DATA_FILE indicates, the data is in a file; AFAIK this is not used on parsing */
	 || mime_data->dt_data.dt_text.dt_data == NULL
	 || mime_data->dt_data.dt_text.dt_length <= 0 ) {
		goto AddSinglePart_Cleanup; /* error */
	}

	/* check headers in `mime` */
	if( mime->mm_mime_fields != NULL ) {
		clistiter* cur;
		for( cur = clist_begin(mime->mm_mime_fields->fld_list); cur != NULL; cur = clist_next(cur) ) {
			struct mailmime_field* field = (struct mailmime_field*)clist_content(cur);
			if( field ) {
				if( field->fld_type == MAILMIME_FIELD_TRANSFER_ENCODING && field->fld_data.fld_encoding ) {
					mime_transfer_encoding = field->fld_data.fld_encoding->enc_type;
				}
			}
		}
	}

	/* regard `Content-Transfer-Encoding:` */
	if( mime_transfer_encoding == MAILMIME_MECHANISM_7BIT
	 || mime_transfer_encoding == MAILMIME_MECHANISM_8BIT
	 || mime_transfer_encoding == MAILMIME_MECHANISM_BINARY )
	{
		decoded_data       = mime_data->dt_data.dt_text.dt_data;
		decoded_data_bytes = mime_data->dt_data.dt_text.dt_length;
		if( decoded_data == NULL || decoded_data_bytes <= 0 ) {
			goto AddSinglePart_Cleanup; /* no error - but no data */
		}
	}
	else
	{
		int r;
		size_t current_index = 0;
		r = mailmime_part_parse(mime_data->dt_data.dt_text.dt_data, mime_data->dt_data.dt_text.dt_length,
			&current_index, mime_transfer_encoding,
			&transfer_decoding_buffer, &decoded_data_bytes);
		if( r != MAILIMF_NO_ERROR || transfer_decoding_buffer == NULL || decoded_data_bytes <= 0 ) {
			goto AddSinglePart_Cleanup; /* error */
		}
		decoded_data = transfer_decoding_buffer;
	}

	switch( mime_type )
	{
		case MR_MIMETYPE_TEXT_PLAIN:
		case MR_MIMETYPE_TEXT_HTML:
			{
				if( simplifier==NULL ) {
					simplifier = mrsimplify_new();
					if( simplifier==NULL ) {
						goto AddSinglePart_Cleanup; /* error */
					}
				}

				const char* charset = mailmime_content_charset_get(mime->mm_content_type); /* get from `Content-Type: text/...; charset=utf-8`; must not be free()'d */
				if( charset!=NULL && strcmp(charset, "utf-8")!=0 && strcmp(charset, "UTF-8")!=0 ) {
					size_t ret_bytes = 0;
					int r = charconv_buffer("utf-8", charset, decoded_data, decoded_data_bytes, &charset_buffer, &ret_bytes);
					if( r != MAIL_CHARCONV_NO_ERROR ) {
						mrlog_warning("Cannot convert character set."); /* continue, however */
					}
					else if( charset_buffer==NULL || ret_bytes <= 0 ) {
						goto AddSinglePart_Cleanup; /* no error - but nothing to add */
					}
					else  {
						decoded_data = charset_buffer;
						decoded_data_bytes = ret_bytes;
					}
				}

				part->m_type = MR_MSG_TEXT;
				part->m_msg_raw = strndup(decoded_data, decoded_data_bytes);
				part->m_msg = mrsimplify_simplify(simplifier, decoded_data, decoded_data_bytes, mime_type);
				if( part->m_msg && part->m_msg[0] ) {
					do_add_part = 1;
				}
			}
			break;

		case MR_MIMETYPE_IMAGE:
			part->m_type = MR_MSG_IMAGE;
			part->m_msg  = safe_strdup("IMAGE");
			do_add_part = 1;
			break;

		default:
			break;
	}

	/* add object? (we do not add all objetcs, eg. signatures etc. are ignored) */
AddSinglePart_Cleanup:
	if( simplifier ) {
		mrsimplify_unref(simplifier);
	}

	if( charset_buffer ) {
		charconv_buffer_free(charset_buffer);
	}

	if( transfer_decoding_buffer ) {
		mmap_string_unref(transfer_decoding_buffer);
	}

	if( do_add_part ) {
		carray_add(ths->m_parts, (void*)part, NULL);
		return 1; /* part used */
	}
	else {
		mrmimepart_unref(part);
		return 0;
	}
}


int mrmimeparser_parse_mime_recursive__(mrmimeparser_t* ths, struct mailmime* mime)
{
	int        sth_added = 0;
	clistiter* cur;

	switch( mime->mm_type )
	{
		case MAILMIME_SINGLE:
			sth_added = mrmimeparser_add_single_part_if_known_(ths, mime);
			break;

		case MAILMIME_MULTIPLE:
			switch( mrmimeparser_get_mime_type_(mime->mm_content_type) )
			{
				case MR_MIMETYPE_MP_ALTERNATIVE: /* add "best" part - this is either `text/plain` or the first part */
					{
						for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
							struct mailmime* childmime = (struct mailmime*)clist_content(cur);
							if( mrmimeparser_get_mime_type_(childmime->mm_content_type) == MR_MIMETYPE_TEXT_PLAIN ) {
								sth_added = mrmimeparser_parse_mime_recursive__(ths, childmime);
								break;
							}
						}

						if( !sth_added ) { /* `text/plain` not found - use the first part */
							for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
								if( mrmimeparser_parse_mime_recursive__(ths, (struct mailmime*)clist_content(cur)) ) {
									sth_added = 1;
									break; /* out of for() */
								}
							}
						}
					}
					break;

				case MR_MIMETYPE_MP_RELATED: /* add the "root part" - the other parts may be referenced which is not interesting for us (eg. embedded images) */
				                             /* we assume he "root part" being the first one, which may not be always true ... however, most times it seems okay. */
					cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list);
					if( cur ) {
						mrmimeparser_parse_mime_recursive__(ths, (struct mailmime*)clist_content(cur));
					}
					break;

				default: /* eg. MR_MIME_MP_MIXED - add all parts (in fact, AddSinglePartIfKnown() later check if the parts are really supported) */
					for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
						if( mrmimeparser_parse_mime_recursive__(ths, (struct mailmime*)clist_content(cur)) ) {
							sth_added = 1;
						}
					}
					break;
			}
			break;

		case MAILMIME_MESSAGE:
			if( ths->m_header == NULL && mime->mm_data.mm_message.mm_fields )
			{
				ths->m_header = mime->mm_data.mm_message.mm_fields;
				for( cur = clist_begin(ths->m_header->fld_list); cur!=NULL ; cur=clist_next(cur) ) {
					struct mailimf_field* field = (struct mailimf_field*)clist_content(cur);
					if( field->fld_type == MAILIMF_FIELD_SUBJECT ) {
						if( ths->m_subjectEncoded == NULL && field->fld_data.fld_subject ) {
							ths->m_subjectEncoded = field->fld_data.fld_subject->sbj_value;
						}
						break; /* we're not interested in the other fields */
					}
				}
			}

			if( mime->mm_data.mm_message.mm_msg_mime )
			{
				sth_added = mrmimeparser_parse_mime_recursive__(ths, mime->mm_data.mm_message.mm_msg_mime);
			}
			break;
	}

	return sth_added;
}


void mrmimeparser_parse_(mrmimeparser_t* ths, const char* body_not_terminated, size_t body_bytes)
{
	int r;
	size_t index = 0;


	mrmimeparser_empty_(ths);

	/* parse body */
	r = mailmime_parse(body_not_terminated, body_bytes, &index, &ths->m_mimeroot);
	if(r != MAILIMF_NO_ERROR || ths->m_mimeroot == NULL ) {
		goto Parse_Cleanup;
	}

	#if DEBUG_MIME_OUTPUT
		printf("-----------------------------------------------------------------------\n");
		display_mime(m_mimeroot);
		printf("-----------------------------------------------------------------------\n");
	#endif

	/* recursively check, whats parsed */
	mrmimeparser_parse_mime_recursive__(ths, ths->m_mimeroot);

	/* Cleanup - and try to create at least an empty part if there are no parts yet */
Parse_Cleanup:
	if( carray_count(ths->m_parts)==0 ) {
		mrmimepart_t* part = mrmimepart_new();
		if( part!=NULL ) {
			char* subject_decoded = mr_decode_header_string(ths->m_subjectEncoded); /* may be NULL */
			part->m_type = MR_MSG_TEXT;
			part->m_msg = safe_strdup((char*)(subject_decoded? subject_decoded : "Empty message"));
			carray_add(ths->m_parts, (void*)part, NULL);
			free(subject_decoded);
		}
	}
}
