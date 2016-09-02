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
 * File:    mrmimeparser.cpp
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

#endif // DEBUG_MIME_OUTPUT



/*******************************************************************************
 * a MIME part
 ******************************************************************************/


MrMimePart::MrMimePart()
{
	m_type    = MR_MSG_UNDEFINED;
	m_msg     = NULL;
	m_msg_raw = NULL;
}


MrMimePart::~MrMimePart()
{
	if( m_msg ) {
		free((void*)m_msg);
		m_msg = NULL;
	}

	if( m_msg_raw ) {
		free((void*)m_msg_raw);
		m_msg_raw = NULL;
	}
}


/*******************************************************************************
 * MIME parser
 ******************************************************************************/


MrMimeParser::MrMimeParser()
{
	m_parts          = carray_new(16);
	m_header         = NULL;
	m_subjectEncoded = NULL;
	m_mimeroot       = NULL;
}


MrMimeParser::~MrMimeParser()
{
	Empty();
	carray_free(m_parts);
}


void MrMimeParser::Empty()
{
	if( m_parts )
	{
		int i, cnt = carray_count(m_parts);
		for( i = 0; i < cnt; i++ ) {
			MrMimePart* part = (MrMimePart*)carray_get(m_parts, i);
			if( part ) {
				delete part;
			}
		}
		carray_set_size(m_parts, 0);
	}

	m_header         = NULL; // a pointer somewhere to the MIME data, must not be freed
	m_subjectEncoded = NULL; // a pointer somewhere to the MIME data, must not be freed

	if( m_mimeroot )
	{
		mailmime_free(m_mimeroot);
		m_mimeroot = NULL;
	}
}


int MrMimeParser::GetMimeType(mailmime_content* c)
{
	if( c == NULL || c->ct_type == NULL ) {
		return 0; // error
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
				else { // eg. "mixed"
					return MR_MIMETYPE_MP;
				}
			}
			break;

		default:
			break;
	}

	return 0; // unknown
}


bool MrMimeParser::AddSinglePartIfKnown(mailmime* mime)
{
	MrMimePart*    part = new MrMimePart();
	bool           do_add_part = false;

	int            mime_type;
	mailmime_data* mime_data;
	int            mime_transfer_encoding = MAILMIME_MECHANISM_BINARY;

	char*          transfer_decoding_buffer = NULL; // mmap_string_unref()'d if set
	char*          charset_buffer = NULL; // charconv_buffer_free()'d if set (just calls mmap_string_unref())

	const char*    decoded_data = NULL; // must not be free()'d
	size_t         decoded_data_bytes = 0;

	if( mime == NULL || mime->mm_data.mm_single == NULL || part == NULL ) {
		goto AddSinglePart_Cleanup; // error
	}

	// get mime type from `mime`
	mime_type = GetMimeType(mime->mm_content_type);

	// get data pointer from `mime`
	mime_data = mime->mm_data.mm_single;
	if( mime_data->dt_type != MAILMIME_DATA_TEXT   // MAILMIME_DATA_FILE indicates, the data is in a file; AFAIK this is not used on parsing
	 || mime_data->dt_data.dt_text.dt_data == NULL
	 || mime_data->dt_data.dt_text.dt_length <= 0 ) {
		goto AddSinglePart_Cleanup; // error
	}

	// check headers in `mime`
	if( mime->mm_mime_fields != NULL ) {
		for( clistiter* cur = clist_begin(mime->mm_mime_fields->fld_list); cur != NULL; cur = clist_next(cur) ) {
			mailmime_field* field = (mailmime_field*)clist_content(cur);
			if( field ) {
				if( field->fld_type == MAILMIME_FIELD_TRANSFER_ENCODING && field->fld_data.fld_encoding ) {
					mime_transfer_encoding = field->fld_data.fld_encoding->enc_type;
				}
			}
		}
	}

	// regard `Content-Transfer-Encoding:`
	if( mime_transfer_encoding == MAILMIME_MECHANISM_7BIT
	 || mime_transfer_encoding == MAILMIME_MECHANISM_8BIT
	 || mime_transfer_encoding == MAILMIME_MECHANISM_BINARY )
	{
		decoded_data       = mime_data->dt_data.dt_text.dt_data;
		decoded_data_bytes = mime_data->dt_data.dt_text.dt_length;
		if( decoded_data == NULL || decoded_data_bytes <= 0 ) {
			goto AddSinglePart_Cleanup; // no error - but no data
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
			goto AddSinglePart_Cleanup; // error
		}
		decoded_data = transfer_decoding_buffer;
	}

	switch( mime_type )
	{
		case MR_MIMETYPE_TEXT_PLAIN:
		case MR_MIMETYPE_TEXT_HTML:
			{
				MrSimplify simplifier;

				const char* charset = mailmime_content_charset_get(mime->mm_content_type); // get from `Content-Type: text/...; charset=utf-8`; must not be free()'d
				if( charset!=NULL && strcmp(charset, "utf-8")!=0 && strcmp(charset, "UTF-8")!=0 ) {
					size_t ret_bytes = 0;
					int r = charconv_buffer("utf-8", charset, decoded_data, decoded_data_bytes, &charset_buffer, &ret_bytes);
					if( r != MAIL_CHARCONV_NO_ERROR ) {
						MrLogWarning("Cannot convert character set."); // continue, however
					}
					else if( charset_buffer==NULL || ret_bytes <= 0 ) {
						goto AddSinglePart_Cleanup; // no error - but nothing to add
					}
					else  {
						decoded_data = charset_buffer;
						decoded_data_bytes = ret_bytes;
					}
				}

				part->m_type = MR_MSG_TEXT;
				part->m_msg_raw = strndup(decoded_data, decoded_data_bytes);
				part->m_msg = simplifier.Simplify(decoded_data, decoded_data_bytes, mime_type);
				if( part->m_msg && part->m_msg[0] ) {
					do_add_part = true;
				}
			}
			break;

		case MR_MIMETYPE_IMAGE:
			part->m_type = MR_MSG_IMAGE;
			part->m_msg  = strdup("IMAGE");
			do_add_part = true;
			break;

		default:
			break;
	}

	// add object?
	// (we do not add all objetcs, eg. signatures etc. are ignored)
AddSinglePart_Cleanup:
	if( charset_buffer ) {
		charconv_buffer_free(charset_buffer);
	}

	if( transfer_decoding_buffer ) {
		mmap_string_unref(transfer_decoding_buffer);
	}

	if( do_add_part ) {
		carray_add(m_parts, (void*)part, NULL);
		return true; // part used
	}
	else {
		delete part;
		return false;
	}
}


bool MrMimeParser::ParseMimeRecursive(mailmime* mime)
{
	bool       sth_added = false;
	clistiter* cur;

	switch( mime->mm_type )
	{
		case MAILMIME_SINGLE:
			sth_added = AddSinglePartIfKnown(mime);
			break;

		case MAILMIME_MULTIPLE:
			switch( GetMimeType(mime->mm_content_type) )
			{
				case MR_MIMETYPE_MP_ALTERNATIVE: // add "best" part - this is either `text/plain` or the first part
					{
						for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
							mailmime* childmime = (mailmime*)clist_content(cur);
							if( GetMimeType(childmime->mm_content_type) == MR_MIMETYPE_TEXT_PLAIN ) {
								sth_added = ParseMimeRecursive(childmime);
								break;
							}
						}

						if( !sth_added ) { // `text/plain` not found - use the first part
							for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
								if( ParseMimeRecursive((mailmime*)clist_content(cur)) ) {
									sth_added = true;
									break; // out of for()
								}
							}
						}
					}
					break;

				case MR_MIMETYPE_MP_RELATED: // add the "root part" - the other parts may be referenced which is not interesting for us (eg. embedded images)
				                             // we assume he "root part" being the first one, which may not be always true ... however, most times it seems okay.
					cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list);
					if( cur ) {
						ParseMimeRecursive((mailmime*)clist_content(cur));
					}
					break;

				default: // eg. MR_MIME_MP_MIXED - add all parts (in fact, AddSinglePartIfKnown() later check if the parts are really supported)
					for( cur=clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) {
						if( ParseMimeRecursive((mailmime*)clist_content(cur)) ) {
							sth_added = true;
						}
					}
					break;
			}
			break;

		case MAILMIME_MESSAGE:
			if( m_header == NULL && mime->mm_data.mm_message.mm_fields )
			{
				m_header = mime->mm_data.mm_message.mm_fields;
				for( cur = clist_begin(m_header->fld_list); cur!=NULL ; cur=clist_next(cur) ) {
					mailimf_field* field = (mailimf_field*)clist_content(cur);
					if( field->fld_type == MAILIMF_FIELD_SUBJECT ) {
						if( m_subjectEncoded == NULL && field->fld_data.fld_subject ) {
							m_subjectEncoded = field->fld_data.fld_subject->sbj_value;
						}
						break; // we're not interested in the other fields
					}
				}
			}

			if( mime->mm_data.mm_message.mm_msg_mime )
			{
				sth_added = ParseMimeRecursive(mime->mm_data.mm_message.mm_msg_mime);
			}
			break;
	}

	return sth_added;
}


void MrMimeParser::Parse(const char* body_not_terminated, size_t body_bytes)
{
	int r;
	size_t index = 0;


	Empty();

	// parse body
	r = mailmime_parse(body_not_terminated, body_bytes, &index, &m_mimeroot);
	if(r != MAILIMF_NO_ERROR || m_mimeroot == NULL ) {
		goto Parse_Cleanup;
	}

	#if DEBUG_MIME_OUTPUT
		printf("-----------------------------------------------------------------------\n");
		display_mime(m_mimeroot);
		printf("-----------------------------------------------------------------------\n");
	#endif

	// recursively check, whats parsed
	ParseMimeRecursive(m_mimeroot);

	// Cleanup - and try to create at least an empty part if there are no parts yet
Parse_Cleanup:
	if( carray_count(m_parts)==0 ) {
		MrMimePart* part = new MrMimePart();
		if( part!=NULL ) {
			char* subject_decoded = mr_decode_header_string(m_subjectEncoded); // may be NULL
			part->m_type = MR_MSG_TEXT;
			part->m_msg = save_strdup((char*)(subject_decoded? subject_decoded : "Empty message"));
			carray_add(m_parts, (void*)part, NULL);
			free(subject_decoded);
		}
	}
}
