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
 * File:    mrimfparser.c
 * Authors: Björn Petersen
 * Purpose: Parse IMF, see header for details.
 *
 *******************************************************************************

 Common types:

 mailimf_address_list {
     clist* ad_list;                        // list of (mailimf_address *), != NULL
 };

 mailimf_address {
     int ad_type;
     union {
         mailimf_mailbox* ad_mailbox;       // can be NULL
         mailimf_group*   ad_group;         // can be NULL
     } ad_data;
 }

 mailimf_group {
     char*                 grp_display_name; // != NULL
     mailimf_mailbox_list* grp_mb_list {     // can be NULL
        clist * mb_list;                     // list of (struct mailimf_mailbox *), != NULL
     }
 };

 mailimf_mailbox {
     char* mb_display_name; // can be NULL
     char* mb_addr_spec;    // != NULL
 }

 NB: What, if a mail has a Reply-To:-Header? Shouldn't we treat this as the real
 sender? So prefer this header to From:?
 However, before creating something here, we whould check how this is used in
 practice.  At least for mailing lists, the Reply-To: is used differently and
 contains a thread ID - such stuff is not desired.  Maybe the best approach for
 the moment is just to ignore the header - at least until we have more
 information.

 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <libetpan/libetpan.h>
#include "mrmailbox.h"
#include "mrimfparser.h"
#include "mrmimeparser.h"
#include "mrtools.h"
#include "mrlog.h"


/*******************************************************************************
 * Decoder MIME header
 ******************************************************************************/


static char* create_stub_message_id_(time_t message_timestamp, uint32_t contact_id_from, carray* contact_ids_to)
{
	if( message_timestamp == MR_INVALID_TIMESTAMP || contact_ids_to == NULL || carray_count(contact_ids_to)==0 ) {
		return NULL; /* cannot create a unique timestamp */
	}

	/* find out the largets receiver ID (we could also take the smallest, but it should be unique) */
	size_t   i, icnt = carray_count(contact_ids_to);
	uint32_t largest_id = contact_id_from;
	for( i = 0; i < icnt; i++ ) {
		uint32_t cur_id = (uint32_t)(uintptr_t)carray_get(contact_ids_to, i);
		if( cur_id > largest_id ) {
			largest_id = cur_id;
		}
	}


	/* build a more or less unique string based on the timestamp and one receiver -
	for our purposes, this seems "good enough" for the moment, esp. as clients may a Message-ID on sent. */
	char* ret = mr_mprintf("%u-%i@stub", (unsigned int)message_timestamp, (int)largest_id);

	return ret; /* must be free()'d by the caller */
}


static void add_or_lookup_contact2_( mrmailbox_t* mailbox,
                                     const char*  display_name_enc /*can be NULL*/,
                                     const char*  addr_spec,
                                     int          origin,
                                     carray*      ids )
{
	char* display_name_dec = NULL;
	if( display_name_enc ) {
		display_name_dec = mr_decode_header_string(display_name_enc);
		mr_normalize_name(display_name_dec);
	}

	uint32_t row_id = mrmailbox_add_or_lookup_contact_(mailbox, display_name_dec /*can be NULL*/, addr_spec, origin);

	free(display_name_dec);

	if( row_id )
	{
		if( !carray_search(ids, (void*)(uintptr_t)row_id, NULL) ) {
			carray_add(ids, (void*)(uintptr_t)row_id, NULL);
		}
	}
}


static void mrimfparser_add_or_lookup_contacts_by_mailbox_list(
				mrimfparser_t*               ths,
				struct mailimf_mailbox_list* mb_list,
				int                          origin,
				carray*                      ids )
{
	clistiter* cur;
	for( cur = clist_begin(mb_list->mb_list); cur!=NULL ; cur=clist_next(cur) ) {
		struct mailimf_mailbox* mb = (struct mailimf_mailbox*)clist_content(cur);
		if( mb ) {
			add_or_lookup_contact2_(ths->m_mailbox, mb->mb_display_name, mb->mb_addr_spec, origin, ids);
		}
	}
}


static void mrimfparser_add_or_lookup_contacts_by_address_list(
				mrimfparser_t*               ths,
				struct mailimf_address_list* adr_list, /* an address is a mailbox or a group */
				int                          origin,
				carray*                      ids )
{
	clistiter* cur;
	for( cur = clist_begin(adr_list->ad_list); cur!=NULL ; cur=clist_next(cur) ) {
		struct mailimf_address* adr = (struct mailimf_address*)clist_content(cur);
		if( adr ) {
			if( adr->ad_type == MAILIMF_ADDRESS_MAILBOX ) {
				struct mailimf_mailbox* mb = adr->ad_data.ad_mailbox; /* can be NULL */
				if( mb ) {
					add_or_lookup_contact2_(ths->m_mailbox, mb->mb_display_name, mb->mb_addr_spec, origin, ids);
				}
			}
			else if( adr->ad_type == MAILIMF_ADDRESS_GROUP ) {
				struct mailimf_group* group = adr->ad_data.ad_group; /* can be NULL */
				if( group && group->grp_mb_list /*can be NULL*/ ) {
					mrimfparser_add_or_lookup_contacts_by_mailbox_list(ths, group->grp_mb_list, origin, ids);
				}
			}
		}
	}
}


static struct mailimf_field* find_field(mrmimeparser_t* mime_parser, int wanted_fld_type)
{
	clistiter* cur1;
	for( cur1 = clist_begin(mime_parser->m_header->fld_list); cur1!=NULL ; cur1=clist_next(cur1) )
	{
		struct mailimf_field* field = (struct mailimf_field*)clist_content(cur1);
		if( field )
		{
			if( field->fld_type == wanted_fld_type ) {
				return field;
			}
		}
	}

	return NULL;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


mrimfparser_t* mrimfparser_new_(mrmailbox_t* mailbox)
{
	mrimfparser_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrimfparser_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_mailbox = mailbox;

	return ths;
}


void mrimfparser_unref_(mrimfparser_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	free(ths);
}


/*******************************************************************************
 * Parse entry point
 ******************************************************************************/


size_t mrimfparser_imf2msg_(mrimfparser_t* ths, const char* imf_raw_not_terminated, size_t imf_raw_bytes)
{
	/* the function returns the number of created messages in the database */
	int              incoming = 0;
	int              incoming_from_known_sender = 0;
	#define          outgoing (!incoming)

	carray*          to_list = NULL;

	uint32_t         from_id = 0;
	uint32_t         to_id   = 0;
	uint32_t         chat_id = 0;
	int              state   = MR_STATE_UNDEFINED;

	sqlite3_stmt*    stmt;
	size_t           i, icnt;
	uint32_t         first_dblocal_id = 0;
	char*            rfc724_mid = NULL; /* Message-ID from the header */
	time_t           message_timestamp = MR_INVALID_TIMESTAMP;
	mrmimeparser_t*  mime_parser = mrmimeparser_new_();
	int              db_locked = 0;
	int              transaction_pending = 0;
	clistiter*       cur1;
	struct mailimf_field* field;
	size_t           created_db_entries = 0;
	int              has_return_path = 0;

	/* create arrays that will hold from: and to: lists */
	to_list = carray_new(16);
	if( to_list==NULL || mime_parser == NULL ) {
		goto Imf2Msg_Done; /* out of memory */
	}

	/* parse the imf to mailimf_message {
	        mailimf_fields* msg_fields {
	          clist* fld_list; // list of mailimf_field
	        }
	        mailimf_body* msg_body { // != NULL
                const char * bd_text; // != NULL
                size_t bd_size;
	        }
	   };
	normally, this is done by mailimf_message_parse(), however, as we also need the MIME data,
	we use mailmime_parse() through MrMimeParser (both call mailimf_struct_multiple_parse() somewhen, I did not found out anything
	that speaks against this approach yet) */
	mrmimeparser_parse_(mime_parser, imf_raw_not_terminated, imf_raw_bytes);
	if( mime_parser->m_header == NULL ) {
		goto Imf2Msg_Done; /* Error - even adding an empty record won't help as we do not know the message ID */
	}

	/* lock database */
	mrsqlite3_lock(ths->m_mailbox->m_sql); /* CAVE: No return until unlock! */
	db_locked = 1;

	/* start transaction */
	mrsqlite3_begin_transaction(ths->m_mailbox->m_sql);
	transaction_pending = 1;


		/* Check, if the mail comes from extern, resp. is not send by us.  This is a _really_ important step
		as messages send by us are used to validate other mail senders and receivers.
		For this purpose, we assume, the `Return-Path:`-header is never present if the message is send by us.
		The `Received:`-header may be another idea, however, this is also set if mails are transfered from other accounts via IMAP. */
		for( cur1 = clist_begin(mime_parser->m_header->fld_list); cur1!=NULL ; cur1=clist_next(cur1) )
		{
			field = (struct mailimf_field*)clist_content(cur1);
			if( field )
			{
				if( field->fld_type == MAILIMF_FIELD_RETURN_PATH )
				{
					has_return_path = 1;
				}
				else if( field->fld_type == MAILIMF_FIELD_OPTIONAL_FIELD )
				{
					struct mailimf_optional_field* optional_field = field->fld_data.fld_optional_field;
					if( optional_field && strcasecmp(optional_field->fld_name, "Return-Path")==0 )
					{
						has_return_path = 1; /* "MAILIMF_FIELD_OPTIONAL_FIELD.Return-Path" should be "MAILIMF_FIELD_RETURN_PATH", however, this is not always the case */
					}
				}
			}

		} /* for */

		if( has_return_path ) {
			incoming = 1;
		}


		/* for incoming messages, get From: and check if it is known (for known From:'s we add the other To:/Cc:/Bcc: in the 3rd pass) */
		if( incoming
		 && (field=find_field(mime_parser,  MAILIMF_FIELD_FROM  ))!=NULL )
		{
			struct mailimf_from* fld_from = field->fld_data.fld_from;
			if( fld_from )
			{
				carray* from_list = carray_new(16);
				mrimfparser_add_or_lookup_contacts_by_mailbox_list(ths, fld_from->frm_mb_list,
					MR_ORIGIN_INCOMING_UNKNOWN_FROM, from_list);
				if( carray_count(from_list)>=1 )
				{
					from_id = (uint32_t)(uintptr_t)carray_get(from_list, 0);
					if( mrmailbox_is_known_contact_(ths->m_mailbox, from_id) ) { /* currently, this checks if the contact is known by any reason, we could be more strict and allow eg. only contacts already used for sending. However, as a first idea, the current approach seems okay. */
						incoming_from_known_sender = 1;
					}
				}
				carray_free(from_list);
			}
		}

		/* Make sure, to_list starts with the first To:-address (Cc: and Bcc: are added in the loop below pass) */
		if( (outgoing || incoming_from_known_sender)
		 && (field=find_field(mime_parser,  MAILIMF_FIELD_TO  ))!=NULL )
		{
			struct mailimf_to* fld_to = field->fld_data.fld_to; /* can be NULL */
			if( fld_to )
			{
				mrimfparser_add_or_lookup_contacts_by_address_list(ths, fld_to->to_addr_list /*!= NULL*/,
					outgoing? MR_ORIGIN_OUTGOING_TO : MR_ORIGIN_INCOMING_TO, to_list);
			}
		}


		/* collect the rest information */
		for( cur1 = clist_begin(mime_parser->m_header->fld_list); cur1!=NULL ; cur1=clist_next(cur1) )
		{
			field = (struct mailimf_field*)clist_content(cur1);
			if( field )
			{
				if( field->fld_type == MAILIMF_FIELD_MESSAGE_ID )
				{
					struct mailimf_message_id* fld_message_id = field->fld_data.fld_message_id;
					if( fld_message_id ) {
						rfc724_mid = safe_strdup(fld_message_id->mid_value);
					}
				}
				else if( field->fld_type == MAILIMF_FIELD_CC )
				{
					struct mailimf_cc* fld_cc = field->fld_data.fld_cc;
					if( fld_cc ) {
						mrimfparser_add_or_lookup_contacts_by_address_list(ths, fld_cc->cc_addr_list,
							outgoing? MR_ORIGIN_OUTGOING_CC : MR_ORIGIN_INCOMING_CC, to_list);
					}
				}
				else if( field->fld_type == MAILIMF_FIELD_BCC )
				{
					struct mailimf_bcc* fld_bcc = field->fld_data.fld_bcc;
					if( outgoing && fld_bcc ) {
						mrimfparser_add_or_lookup_contacts_by_address_list(ths, fld_bcc->bcc_addr_list,
							MR_ORIGIN_OUTGOING_BCC, to_list);
					}
				}
				else if( field->fld_type == MAILIMF_FIELD_ORIG_DATE )
				{
					struct mailimf_orig_date* orig_date = field->fld_data.fld_orig_date;
					if( orig_date ) {
						message_timestamp = mr_timestamp_from_date(orig_date->dt_date_time);
					}
				}
			}

		} /* for */


		/* check if the message introduces a new chat:
		- outgoing messages introduce a chat with the first to: address
		- incoming messages introduce a chat only for known contacts (eg. used for outgoing cc: before or in the system''s address book)
		only these messages reflect the will of the sender IMHO (of course, the user can add other chats manually) */
		if( incoming )
		{
			state = MR_IN_READ; /* TODO: New messages should ge tthe state MR_IN_UNREAD here */
			to_id = MR_CONTACT_ID_SELF;
			chat_id = mrmailbox_real_chat_exists_(ths->m_mailbox, MR_CHAT_NORMAL, from_id);
			if( chat_id == 0 && incoming_from_known_sender ) {
				chat_id = mrmailbox_create_or_lookup_chat_record_(ths->m_mailbox, from_id);
			}
		}
		else /* outgoing */
		{
			state = MR_OUT_DELIVERED; /* the mail is on the IMAP server, probably it is also deliverd.  We cannot recreate other states (read, error). */
			from_id = MR_CONTACT_ID_SELF;
			if( carray_count(to_list) >= 1 ) {
				to_id   = (uint32_t)(uintptr_t)carray_get(to_list, 0);
				chat_id = mrmailbox_create_or_lookup_chat_record_(ths->m_mailbox, to_id);
			}
		}

		if( chat_id == 0 ) {
			chat_id = MR_CHAT_ID_STRANGERS;
		}

		/* check, if the mail is already in our database - if so, there's nothing more to do
		(we may get a mail twice eg. it it is moved between folders) */
		if( rfc724_mid == NULL ) {
			/* header is lacking a Message-ID - this may be the case, if the message was sent from this account and the mail client
			the the SMTP-server set the ID (true eg. for the Webmailer used in all-inkl-KAS)
			in these cases, we build a message ID based on some useful header fields that do never change (date, to)
			we do not use the folder-local id, as this will change if the mail is moved to another folder. */
			rfc724_mid = create_stub_message_id_(message_timestamp, from_id, to_list);
			if( rfc724_mid == NULL ) {
				goto Imf2Msg_Done;
			}
		}

		if( mrmailbox_message_id_exists_(ths->m_mailbox, rfc724_mid) ) {
			goto Imf2Msg_Done; /* success - the message is already added to our database  (this also implies the contacts - so we can do a ROLLBACK) */
		}

		/* fine, so far.  now, split the message into simple parts usable as "short messages"
		and add them to the database (mails send by other messenger clients should result
		into only one message; mails send by other clients may result in several messages (eg. one per attachment)) */
		icnt = carray_count(mime_parser->m_parts); /* should be at least one - maybe empty - part */
		for( i = 0; i < icnt; i++ )
		{
			mrmimepart_t* part = (mrmimepart_t*)carray_get(mime_parser->m_parts, i);

			stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, INSERT_INTO_msgs_mcftttstp,
				"INSERT INTO msgs (rfc724_mid,chat_id,from_id, to_id,timestamp,type, state,txt,param) VALUES (?,?,?, ?,?,?, ?,?,?);");
			sqlite3_bind_text (stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
			sqlite3_bind_int  (stmt, 2, chat_id);
			sqlite3_bind_int  (stmt, 3, from_id);
			sqlite3_bind_int  (stmt, 4, to_id);
			sqlite3_bind_int64(stmt, 5, message_timestamp);
			sqlite3_bind_int  (stmt, 6, part->m_type);
			sqlite3_bind_int  (stmt, 7, state);
			sqlite3_bind_text (stmt, 8, part->m_msg, -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt, 9, "", -1, SQLITE_STATIC);
			if( sqlite3_step(stmt) != SQLITE_DONE ) {
				goto Imf2Msg_Done; /* i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record */
			}

			if( first_dblocal_id == 0 ) {
				first_dblocal_id = sqlite3_last_insert_rowid(ths->m_mailbox->m_sql->m_cobj);
			}

			created_db_entries++;
		}

		/* finally, create "ghost messages" for additional to:, cc: bcc: receivers
		(just to be more compatibe to standard email-programs, the flow in the Messanger would not need this) */
		if( outgoing && carray_count(to_list)>1 && first_dblocal_id != 0 )
		{
			char* param = sqlite3_mprintf("omi=%i", (int)first_dblocal_id); /*omi=Original Message Id*/
			icnt = carray_count(to_list);
			for( i = 1/*the first one is added in detail above*/; i < icnt; i++ )
			{
				uint32_t ghost_to_id   = (uint32_t)(uintptr_t)carray_get(to_list, i);
				uint32_t ghost_chat_id = mrmailbox_real_chat_exists_(ths->m_mailbox, MR_CHAT_NORMAL, ghost_to_id);
				if(ghost_chat_id==0) {
					ghost_chat_id = MR_CHAT_ID_STRANGERS;
				}

				stmt = mrsqlite3_predefine(ths->m_mailbox->m_sql, INSERT_INTO_msgs_mcftttstp, NULL /*the first_dblocal_id-check above makes sure, the query is really created*/);
				sqlite3_bind_text (stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
				sqlite3_bind_int  (stmt, 2, ghost_chat_id);
				sqlite3_bind_int  (stmt, 3, from_id);
				sqlite3_bind_int  (stmt, 4, ghost_to_id);
				sqlite3_bind_int64(stmt, 5, message_timestamp);
				sqlite3_bind_int  (stmt, 6, MR_MSG_TEXT);
				sqlite3_bind_int  (stmt, 7, MR_STATE_UNDEFINED); /* state */
				sqlite3_bind_text (stmt, 8, "cc", -1, SQLITE_STATIC);
				sqlite3_bind_text (stmt, 9, param, -1, SQLITE_STATIC);
				if( sqlite3_step(stmt) != SQLITE_DONE ) {
					goto Imf2Msg_Done; /* i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record */
				}

				created_db_entries++;
			}
			sqlite3_free(param);
		}

	/* end sql-transaction */
	mrsqlite3_commit(ths->m_mailbox->m_sql);
	transaction_pending = 0;

	/* done */
Imf2Msg_Done:
	if( transaction_pending ) {
		mrsqlite3_rollback(ths->m_mailbox->m_sql);
	}

	if( db_locked ) {
		mrsqlite3_unlock(ths->m_mailbox->m_sql); /* /CAVE: No return until unlock! */
	}

	if( mime_parser ) {
		mrmimeparser_unref_(mime_parser);
	}

	if( rfc724_mid ) {
		free(rfc724_mid);
	}

	if( to_list ) {
		carray_free(to_list);
	}

	return created_db_entries;
}
