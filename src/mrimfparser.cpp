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
 * File:    mrimfparser.cpp
 * Authors: Björn Petersen
 * Purpose: Parse IMF, see header for details.
 *
 *******************************************************************************

 Common types:

 mailimf_address_list {
     clist* ad_list;                        // list of (struct mailimf_address *), != NULL
 };

 mailimf_address {
     int ad_type;
     union {
         mailimf_mailbox* ad_mailbox;       // can be NULL
         mailimf_group*   ad_group;         // can be NULL
     } ad_data;
 }

 struct mailimf_group {
     char*                 grp_display_name; // != NULL
     mailimf_mailbox_list* grp_mb_list {     // can be NULL
        clist * mb_list;                     // list of (struct mailimf_mailbox *), != NULL
     }
 };

 mailimf_mailbox {
     char* mb_display_name; // can be NULL
     char* mb_addr_spec;    // != NULL
 }

 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrimfparser.h"
#include "mrmimeparser.h"
#include "mrtools.h"
#include "mrmsg.h"


MrImfParser::MrImfParser(MrMailbox* mailbox)
{
	m_mailbox = mailbox;
}


MrImfParser::~MrImfParser()
{
}


/*******************************************************************************
 * Decoder MIME header
 ******************************************************************************/


char* MrImfParser::CreateStubMessageId(time_t message_timestamp, carray* contact_ids_to)
{
	if( message_timestamp == INVALID_TIMESTAMP || contact_ids_to == NULL || carray_count(contact_ids_to)==0 ) {
		return NULL; // cannot create a unique timestamp
	}

	// find out the largets receiver ID (we could also take the smallest, but it should be unique)
	int icnt = carray_count(contact_ids_to), largest_id = 0;
	for( int i = 0; i < icnt; i++ ) {
		int cur_id = (int)(uintptr_t)carray_get(contact_ids_to, i);
		if( cur_id > largest_id ) {
			largest_id = cur_id;
		}
	}


	// build a more or less unique string based on the timestamp and one receiver -
	// for our purposes, this seems "good enough" for the moment, esp. as clients may a Message-ID on sent.
	char* ret = NULL;
	char* buf = sqlite3_mprintf("%u-%i@stub", (unsigned int)message_timestamp, (int)largest_id);
	if( buf ) {
		ret = strdup(buf);
		sqlite3_free(buf);
	}

	return ret; // must be free()'d by the caller
}


void MrImfParser::AddOrLookupContact(const char* display_name_enc /*can be NULL*/, const char* addr_spec, carray* ids)
{
	uint32_t row_id = 0;

	sqlite3_stmt* s = m_mailbox->m_sql.m_pd[SELECT_FROM_contacts_e];
	sqlite3_reset(s);
	sqlite3_bind_text(s, 1, (const char*)addr_spec, -1, SQLITE_STATIC);
	if( sqlite3_step(s) == SQLITE_ROW )
	{
		row_id   = sqlite3_column_int(s, 0);
		const char* row_name = (const char*)sqlite3_column_text(s, 1);
		if( display_name_enc && display_name_enc[0] && (row_name==NULL || row_name[0]==0) )
		{
			// update the display name ONLY if it was unset before (otherwise, we can assume, the name is fine and maybe already edited by the user)
			char* display_name_dec = mr_decode_header_string(display_name_enc);
			if( display_name_dec )
			{
				sqlite3_stmt* s = m_mailbox->m_sql.m_pd[UPDATE_contacts_ni];
				sqlite3_bind_text(s, 1, display_name_dec, -1, SQLITE_STATIC);
				sqlite3_bind_int (s, 2, row_id);
				sqlite3_step     (s);

				free(display_name_dec);
			}
		}
	}
	else
	{
		char* display_name_dec = mr_decode_header_string(display_name_enc); // may be NULL (if display_name_enc is NULL)

		sqlite3_stmt* s = m_mailbox->m_sql.m_pd[INSERT_INTO_contacts_ne];
		sqlite3_reset(s);
		sqlite3_bind_text(s, 1, display_name_dec? display_name_dec : "", -1, SQLITE_STATIC); // avoid NULL-fields in column
		sqlite3_bind_text(s, 2, addr_spec,    -1, SQLITE_STATIC);
		if( sqlite3_step(s) == SQLITE_DONE )
		{
			row_id = sqlite3_last_insert_rowid(m_mailbox->m_sql.m_cobj);
		}
		else
		{
			MrLogError("Cannot add contact.");
		}

		free(display_name_dec);
	}

	if( row_id )
	{
		if( !carray_search(ids, (void*)(uintptr_t)row_id, NULL) ) {
			carray_add(ids, (void*)(uintptr_t)row_id, NULL);
		}
	}
}


void MrImfParser::AddOrLookupContacts(mailimf_mailbox_list* mb_list, carray* ids)
{
	for( clistiter* cur = clist_begin(mb_list->mb_list); cur!=NULL ; cur=clist_next(cur) ) {
		mailimf_mailbox* mb = (mailimf_mailbox*)clist_content(cur);
		if( mb ) {
			AddOrLookupContact(mb->mb_display_name, mb->mb_addr_spec, ids);
		}
	}
}


void MrImfParser::AddOrLookupContacts(mailimf_address_list* adr_list, carray* ids) // an address is a mailbox or a group
{
	for( clistiter* cur = clist_begin(adr_list->ad_list); cur!=NULL ; cur=clist_next(cur) ) {
		mailimf_address* adr = (mailimf_address*)clist_content(cur);
		if( adr ) {
			if( adr->ad_type == MAILIMF_ADDRESS_MAILBOX ) {
				mailimf_mailbox* mb = adr->ad_data.ad_mailbox; // can be NULL
				if( mb ) {
					AddOrLookupContact(mb->mb_display_name, mb->mb_addr_spec, ids);
				}
			}
			else if( adr->ad_type == MAILIMF_ADDRESS_GROUP ) {
				mailimf_group* group = adr->ad_data.ad_group; // can be NULL
				if( group && group->grp_mb_list /*can be NULL*/ ) {
					AddOrLookupContacts(group->grp_mb_list, ids);
				}
			}
		}
	}
}


/*******************************************************************************
 * Parse entry point
 ******************************************************************************/


int32_t MrImfParser::Imf2Msg(const char* imf_raw_not_terminated, size_t imf_raw_bytes)
{
	carray*          contact_ids_from = NULL;
	carray*          contact_ids_to = NULL;
	uint32_t         contact_id_from = 0; // 0=self
	sqlite3_stmt*    s;
	int              i, icnt, part_i, part_cnt;
	uint32_t         dblocal_id = 0;    // databaselocal message id
	char*            rfc724_mid = NULL; // Message-ID from the header
	time_t           message_timestamp = INVALID_TIMESTAMP;
	uint32_t         chat_id = 0;
	bool             comes_from_extern = false; // indicates, if the mail was send by us or was received from outside
	MrMimeParser     mime_parser;

	// create arrays that will hold from: and to: lists
	contact_ids_from = carray_new(16);
	contact_ids_to = carray_new(16);
	if( contact_ids_from==NULL || contact_ids_to==NULL ) {
		goto Imf2Msg_Done; // out of memory
	}

	// parse the imf to mailimf_message {
	//		mailimf_fields* msg_fields {
	//          clist* fld_list; // list of mailimf_field
	//      }
	//		mailimf_body* msg_body { // != NULL
    //          const char * bd_text; /* != NULL */
    //          size_t bd_size;
	//      }
	// };
	// normally, this is done by mailimf_message_parse(), however, as we also need the MIME data,
	// we use mailmime_parse() through MrMimeParser (both call mailimf_struct_multiple_parse() somewhen, I did not found out anything
	// that speaks against this approach yet)
	mime_parser.Parse(imf_raw_not_terminated, imf_raw_bytes);
	if( mime_parser.m_header == NULL ) {
		goto Imf2Msg_Done; // Error - even adding an empty record won't help as we do not know the message ID
	}

	// iterate through the parsed fields
	{
		MrSqlite3Locker locker(m_mailbox->m_sql); // lock database (parsing should be done outside the lock)
		{
			MrSqlite3Transaction transaction(m_mailbox->m_sql);

			for( clistiter* cur1 = clist_begin(mime_parser.m_header->fld_list); cur1!=NULL ; cur1=clist_next(cur1) )
			{
				mailimf_field* field = (mailimf_field*)clist_content(cur1);
				if( field )
				{
					if( field->fld_type == MAILIMF_FIELD_MESSAGE_ID )
					{
						mailimf_message_id* fld_message_id = field->fld_data.fld_message_id; // can be NULL
						if( fld_message_id ) {
							rfc724_mid = strdup(fld_message_id->mid_value); // != NULL
						}
					}
					else if( field->fld_type == MAILIMF_FIELD_FROM )
					{
						mailimf_from* fld_from = field->fld_data.fld_from; // can be NULL
						if( fld_from ) {
							AddOrLookupContacts(fld_from->frm_mb_list /*!= NULL*/, contact_ids_from);
						}
					}
					else if( field->fld_type == MAILIMF_FIELD_TO )
					{
						mailimf_to* fld_to = field->fld_data.fld_to; // can be NULL
						if( fld_to ) {
							AddOrLookupContacts(fld_to->to_addr_list /*!= NULL*/, contact_ids_to);
						}
					}
					else if( field->fld_type == MAILIMF_FIELD_CC )
					{
						mailimf_cc* fld_cc = field->fld_data.fld_cc; // can be NULL;
						if( fld_cc ) {
							AddOrLookupContacts(fld_cc->cc_addr_list /*!= NULL*/, contact_ids_to);
						}
					}
					else if( field->fld_type == MAILIMF_FIELD_ORIG_DATE )
					{
						mailimf_orig_date* orig_date = field->fld_data.fld_orig_date;
						if( orig_date ) {
							message_timestamp =timestampFromDate(orig_date->dt_date_time /*!= NULL*/);
						}
					}
					else if( field->fld_type == MAILIMF_FIELD_RETURN_PATH )
					{
						comes_from_extern = true; // we assume, the `Return-Path:`-header is never present if the message is send by us
												  // (messages send by us are used to validate other mail senders and receivers)
												  // maybe, the `Received:`-header is a better choice, however, I don't know how to get it with libEtPan.
					}
				}

			} // for

			// check, if the given message is send by _us_ to only _one_ receiver --
			// only these messages introduce an automatic chat with the receiver; only these messages reflect the will of the sender IMHO
			// (of course, the user can add other chats manually)
			if( !comes_from_extern && carray_count(contact_ids_to)==1 )
			{
				chat_id = MrChat::CreateChatRecord(m_mailbox, (uint32_t)(uintptr_t)carray_get(contact_ids_to, 0));
			}

			if( chat_id == 0 )
			{
				chat_id = MrChat::FindOutChatId(m_mailbox, contact_ids_from, contact_ids_to);
			}

			// check, if the mail is already in our database - if so, there's nothing more to do
			// (we may get a mail twice eg. it it is moved between folders)
			if( rfc724_mid == NULL ) {
				// header is lacking a Message-ID - this may be the case, if the message was sent from this account and the mail clien
				// the the SMTP-server set the ID (true eg. for the Webmailer used in all-inkl-KAS)
				// in these cases, we build a message ID based on some useful header fields that do never change (date, to)
				// we do not use the folder-local id, as this will change if the mail is moved to another folder.
				rfc724_mid = CreateStubMessageId(message_timestamp, contact_ids_to);
				if( rfc724_mid == NULL ) {
					goto Imf2Msg_Done;
				}
			}

			if( MrMsg::MessageIdExists(m_mailbox, rfc724_mid) ) {
				goto Imf2Msg_Done; // success - the message is already added to our database  (this also implies the contacts - so we can do a ROLLBACK)
			}

			// set the sender (contact_id_from, 0=self)
			if( comes_from_extern ) {
				if( carray_count(contact_ids_from) == 0 ) {
					AddOrLookupContact(NULL, "no@ddress", contact_ids_from);
					if( carray_count(contact_ids_from) == 0 ) {
						goto Imf2Msg_Done;
					}
				}
				contact_id_from = (int)(uintptr_t)carray_get(contact_ids_from, 0);
			}
			else {
				contact_id_from = 0; // send by ourself
			}

			// fine, so far.  now, split the message into simple parts usable as "short messages"
			// and add them to the database (mails send by other LibreChat clients should result
			// into only one message; mails send by other clients may result in several messages (eg. one per attachment))
			part_cnt = carray_count(mime_parser.m_parts); // should be at least one - maybe empty - part
			for( part_i = 0; part_i < part_cnt; part_i++ )
			{
				MrMimePart* part = (MrMimePart*)carray_get(mime_parser.m_parts, part_i);

				s = m_mailbox->m_sql.m_pd[INSERT_INTO_msg_mcfttsm];
				sqlite3_reset(s);
				sqlite3_bind_text (s, 1, rfc724_mid, -1, SQLITE_STATIC);
				sqlite3_bind_int  (s, 2, chat_id);
				sqlite3_bind_int  (s, 3, contact_id_from);
				sqlite3_bind_int64(s, 4, message_timestamp);
				sqlite3_bind_int  (s, 5, part->m_type);
				sqlite3_bind_int  (s, 6, MR_STATE_UNDEFINED); // state
				sqlite3_bind_text (s, 7, part->m_msg, -1, SQLITE_STATIC);
				if( sqlite3_step(s) != SQLITE_DONE ) {
					goto Imf2Msg_Done; // i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record
				}

				dblocal_id = sqlite3_last_insert_rowid(m_mailbox->m_sql.m_cobj);

				if( contact_ids_to ) {
					s = m_mailbox->m_sql.m_pd[INSERT_INTO_msg_to_mc];
					icnt = carray_count(contact_ids_to);
					for( i = 0; i < icnt; i++ ) {
						sqlite3_reset(s);
						sqlite3_bind_int(s, 1, dblocal_id);
						sqlite3_bind_int(s, 2, (int)(uintptr_t)carray_get(contact_ids_to, i));
						if( sqlite3_step(s) != SQLITE_DONE ) {
							goto Imf2Msg_Done; // i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record
						}
					}
				}
			}

			transaction.Commit();

		} // end sql-transaction

	} // end sql-lock

	// done
Imf2Msg_Done:
	if( rfc724_mid ) {
		free(rfc724_mid);
	}

	if( contact_ids_from ) {
		carray_free(contact_ids_from);
	}

	if( contact_ids_to ) {
		carray_free(contact_ids_to);
	}

	return 0;
}
