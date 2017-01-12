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
 * File:    mrmailbox.c
 * Purpose: mrmailbox_t represents a single mailbox, see header for details.
 *
 *******************************************************************************
 *
 * For memory checking, use eg.
 * $ valgrind --leak-check=full --tool=memcheck ./messenger-backend <db>
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrimap.h"
#include "mrsmtp.h"
#include "mrmimeparser.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"
#include "mrjob.h"
#include "mrloginparam.h"

#define CLASS_MAGIC 1479776513


/*******************************************************************************
 * Handle Groups
 ******************************************************************************/


static char* extract_grpid_from_messageid(const char* mid)
{
	/* extract our group ID from Message-IDs as `Gr.12345678.morerandom.user@domain.de`; "12345678" is the wanted ID in this example. */
	int success = 0;
	char* ret = NULL, *p1;

    if( mid == NULL || strlen(mid)<8 || mid[0]!='G' || mid[1]!='r' || mid[2]!='.' ) {
		goto cleanup;
    }

	ret = safe_strdup(&mid[3]);

	p1 = strchr(ret, '.');
	if( p1 == NULL ) {
		goto cleanup;
	}
	*p1 = 0;

	if( strlen(ret)!=MR_VALID_ID_LEN ) {
		goto cleanup;
	}

	success = 1;

cleanup:
	if( success == 0 ) { free(ret); ret = NULL; }
    return success? ret : NULL;
}


static char* get_first_grpid_from_char_clist(const clist* list)
{
	clistiter* cur;
	if( list ) {
		for( cur = clist_begin(list); cur!=NULL ; cur=clist_next(cur) ) {
			const char* mid = clist_content(cur);
			char* grpid = extract_grpid_from_messageid(mid);
			if( grpid ) {
				return grpid;
			}
		}
	}
	return NULL;
}


static uint32_t lookup_group_by_grpid__(mrmailbox_t* mailbox, mrmimeparser_t* mime_parser, int create_as_needed,
                                        uint32_t from_id, carray* to_list)
{
	/* search the grpid in the header */
	uint32_t              chat_id = 0;
	clistiter*            cur;
	struct mailimf_field* field;
	char*                 grpid1 = NULL, *grpid2 = NULL, *grpid3 = NULL, *grpid4 = NULL;
	const char*           grpid = NULL; /* must not be freed, just one of the others */
	char*                 grpname = NULL;
	sqlite3_stmt*         stmt;
	int                   i, to_list_cnt = 0;
	char*                 self_addr = NULL;

	for( cur = clist_begin(mime_parser->m_header->fld_list); cur!=NULL ; cur=clist_next(cur) )
	{
		field = (struct mailimf_field*)clist_content(cur);
		if( field )
		{
			if( field->fld_type == MAILIMF_FIELD_OPTIONAL_FIELD )
			{
				struct mailimf_optional_field* optional_field = field->fld_data.fld_optional_field;
				if( optional_field ) {
					if( strcasecmp(optional_field->fld_name, "X-MrGrpId")==0 ) {
						grpid1 = safe_strdup(optional_field->fld_value);
					}
					else if( strcasecmp(optional_field->fld_name, "X-MrGrpName")==0 ) {
						grpname = mr_decode_header_string(optional_field->fld_value);
					}
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_MESSAGE_ID )
			{
				struct mailimf_message_id* fld_message_id = field->fld_data.fld_message_id;
				if( fld_message_id ) {
					grpid2 = extract_grpid_from_messageid(fld_message_id->mid_value);
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_IN_REPLY_TO )
			{
				struct mailimf_in_reply_to* fld_in_reply_to = field->fld_data.fld_in_reply_to;
				if( fld_in_reply_to ) {
					grpid3 = get_first_grpid_from_char_clist(fld_in_reply_to->mid_list);
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_REFERENCES )
			{
				struct mailimf_references* fld_references = field->fld_data.fld_references;
				if( fld_references ) {
					grpid4 = get_first_grpid_from_char_clist(fld_references->mid_list);
				}
			}

		}
	}

	grpid = grpid1? grpid1 : (grpid2? grpid2 : (grpid3? grpid3 : grpid4));
	if( grpid == NULL ) {
		goto cleanup;
	}

	/* check, if we have a chat with this group ID */
	stmt = mrsqlite3_predefine__(mailbox->m_sql, SELECT_id_FROM_CHATS_WHERE_grpid,
		"SELECT id FROM chats WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt)==SQLITE_ROW ) {
		chat_id = sqlite3_column_int(stmt, 0);
		goto cleanup;
	}

	/* check the number of receivers -
	the only critical situation is if the user hits "Reply" instead of "Reply all" in a non-messenger-client  */
	to_list_cnt = carray_count(to_list);
	if( to_list_cnt == 1 && mime_parser->m_is_send_by_messenger==0 ) {
		int is_contact_cnt = mrmailbox_get_chat_contact_count__(mailbox, chat_id);
		if( is_contact_cnt > 2 ) {
			goto cleanup;
		}
	}

	/* create a new chat, if wanted */
	if( create_as_needed && grpname )
	{
		stmt = mrsqlite3_prepare_v2_(mailbox->m_sql,
			"INSERT INTO chats (type, name, grpid) VALUES(?, ?, ?);");
		sqlite3_bind_int (stmt, 1, MR_CHAT_GROUP);
		sqlite3_bind_text(stmt, 2, grpname, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, grpid, -1, SQLITE_STATIC);
		if( sqlite3_step(stmt)!=SQLITE_DONE ) {
			goto cleanup;
		}
		sqlite3_finalize(stmt);
		if( (chat_id=sqlite3_last_insert_rowid(mailbox->m_sql->m_cobj)) == 0 ) {
			goto cleanup;
		}

		/* add all contacts to group*/
		self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", "");

		mrmailbox_add_contact_to_chat__(mailbox, chat_id, MR_CONTACT_ID_SELF);
		if( from_id > MR_CONTACT_ID_LAST_SPECIAL ) {
			if( mrmailbox_contact_addr_equals__(mailbox, from_id, self_addr) == 0 ) {
				mrmailbox_add_contact_to_chat__(mailbox, chat_id, from_id);
			}
		}

		for( i = 0; i < to_list_cnt; i++ )
		{
			uint32_t to_id = (uint32_t)(uintptr_t)carray_get(to_list, i); /* to_id is only once in to_list and is non-special */
			if( mrmailbox_contact_addr_equals__(mailbox, to_id, self_addr) == 0 ) {
				mrmailbox_add_contact_to_chat__(mailbox, chat_id, to_id);
			}
		}
	}

cleanup:
	free(grpid1);
	free(grpid2);
	free(grpid3);
	free(grpid4);
	free(grpname);
	free(self_addr);
	return chat_id;
}


/*******************************************************************************
 * Receive a message and add it to the database
 ******************************************************************************/


static void add_or_lookup_contact_by_addr__(mrmailbox_t* ths, const char* display_name_enc, const char* addr_spec, int origin, carray* ids, int* check_self)
{
	if( check_self )
	{
		*check_self = 0;

		char* self_addr = mrsqlite3_get_config__(ths->m_sql, "configured_addr", "");
			if( strcmp(self_addr, addr_spec)==0 ) {
				*check_self = 1;
			}
		free(self_addr);

		if( *check_self ) {
			return;
		}
	}

	char* display_name_dec = NULL;
	if( display_name_enc ) {
		display_name_dec = mr_decode_header_string(display_name_enc);
		mr_normalize_name(display_name_dec);
	}

	uint32_t row_id = mrmailbox_add_or_lookup_contact__(ths, display_name_dec /*can be NULL*/, addr_spec, origin, NULL);

	free(display_name_dec);

	if( row_id ) {
		if( !carray_search(ids, (void*)(uintptr_t)row_id, NULL) ) {
			carray_add(ids, (void*)(uintptr_t)row_id, NULL);
		}
	}
}


static void add_or_lookup_contacts_by_mailbox_list__(mrmailbox_t* ths, struct mailimf_mailbox_list* mb_list, int origin, carray* ids, int* check_self)
{
	clistiter* cur;
	for( cur = clist_begin(mb_list->mb_list); cur!=NULL ; cur=clist_next(cur) ) {
		struct mailimf_mailbox* mb = (struct mailimf_mailbox*)clist_content(cur);
		if( mb ) {
			add_or_lookup_contact_by_addr__(ths, mb->mb_display_name, mb->mb_addr_spec, origin, ids, check_self);
		}
	}
}


static void add_or_lookup_contacts_by_address_list__(mrmailbox_t* ths, struct mailimf_address_list* adr_list, int origin, carray* ids, int* check_self)
{
	clistiter* cur;
	for( cur = clist_begin(adr_list->ad_list); cur!=NULL ; cur=clist_next(cur) ) {
		struct mailimf_address* adr = (struct mailimf_address*)clist_content(cur);
		if( adr ) {
			if( adr->ad_type == MAILIMF_ADDRESS_MAILBOX ) {
				struct mailimf_mailbox* mb = adr->ad_data.ad_mailbox; /* can be NULL */
				if( mb ) {
					add_or_lookup_contact_by_addr__(ths, mb->mb_display_name, mb->mb_addr_spec, origin, ids, check_self);
				}
			}
			else if( adr->ad_type == MAILIMF_ADDRESS_GROUP ) {
				struct mailimf_group* group = adr->ad_data.ad_group; /* can be NULL */
				if( group && group->grp_mb_list /*can be NULL*/ ) {
					add_or_lookup_contacts_by_mailbox_list__(ths, group->grp_mb_list, origin, ids, check_self);
				}
			}
		}
	}
}


static void receive_imf(mrmailbox_t* ths, const char* imf_raw_not_terminated, size_t imf_raw_bytes,
                          const char* server_folder, uint32_t server_uid, uint32_t flags)
{
	/* the function returns the number of created messages in the database */
	int              incoming = 0;
	int              incoming_from_known_sender = 0;
	#define          outgoing (!incoming)
	int              is_group = 0;

	carray*          to_list = NULL;

	uint32_t         from_id = 0;
	int              from_id_blocked = 0;
	uint32_t         to_id   = 0;
	uint32_t         chat_id = 0;
	int              state   = MR_STATE_UNDEFINED;
	int              event_to_send = MR_EVENT_MSGS_CHANGED;

	sqlite3_stmt*    stmt;
	size_t           i, icnt;
	uint32_t         first_dblocal_id = 0;
	char*            rfc724_mid = NULL; /* Message-ID from the header */
	time_t           message_timestamp = MR_INVALID_TIMESTAMP;
	mrmimeparser_t*  mime_parser = mrmimeparser_new(ths->m_blobdir);
	int              db_locked = 0;
	int              transaction_pending = 0;
	clistiter*       cur1;
	struct mailimf_field* field;
	carray*          created_db_entries = carray_new(16);
	int              has_return_path = 0;
	char*            txt_raw = NULL;

	to_list = carray_new(16);
	if( to_list==NULL || created_db_entries==NULL || mime_parser == NULL ) {
		goto cleanup;
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
	mrmimeparser_parse(mime_parser, imf_raw_not_terminated, imf_raw_bytes);
	if( mime_parser->m_header == NULL ) {
		goto cleanup; /* Error - even adding an empty record won't help as we do not know the message ID */
	}

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

	mrsqlite3_begin_transaction__(ths->m_sql);
	transaction_pending = 1;


		/* Check, if the mail comes from extern, resp. is not send by us.  This is a _really_ important step
		as messages send by us are used to validate other mail senders and receivers.
		For this purpose, we assume, the `Return-Path:`-header is never present if the message is send by us.
		The `Received:`-header may be another idea, however, this is also set if mails are transfered from other accounts via IMAP.
		Using `From:` alone is no good idea, as mailboxes may use different sending-addresses - moreover, they may change over the years.
		However, we use `From:` as an additional hint below. */
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
		}

		if( has_return_path ) {
			incoming = 1;
		}


		/* for incoming messages, get From: and check if it is known (for known From:'s we add the other To:/Cc:/Bcc: in the 3rd pass) */
		if( incoming
		 && (field=mrmimeparser_find_field(mime_parser,  MAILIMF_FIELD_FROM  ))!=NULL )
		{
			struct mailimf_from* fld_from = field->fld_data.fld_from;
			if( fld_from )
			{
				int check_self;
				carray* from_list = carray_new(16);
				add_or_lookup_contacts_by_mailbox_list__(ths, fld_from->frm_mb_list, MR_ORIGIN_INCOMING_UNKNOWN_FROM, from_list, &check_self);
				if( check_self )
				{
					incoming = 0; /* The `Return-Path:`-approach above works well, however, there may be messages outgoing messages which we also receive -
					              for these messages, the `Return-Path:` is set although we're the sender.  To correct these cases, we add an
					              additional From: check - which, however, will not work for older From:-addresses used on the mailbox. */
				}
				else
				{
					if( carray_count(from_list)>=1 ) /* if there is no from given, from_id stays 0 which is just fine.  These messages are very rare, however, we have to add the to the database (they to to the "deaddrop" chat) to avoid a re-download from the server. See also [**] */
					{
						from_id = (uint32_t)(uintptr_t)carray_get(from_list, 0);
						if( mrmailbox_is_known_contact__(ths, from_id, &from_id_blocked) ) { /* currently, this checks if the contact is non-blocked and is known by any reason, we could be more strict and allow eg. only contacts already used for sending. However, as a first idea, the current approach seems okay. */
							incoming_from_known_sender = 1;
						}
					}
				}
				carray_free(from_list);
			}
		}

		/* Make sure, to_list starts with the first To:-address (Cc: and Bcc: are added in the loop below pass) */
		if( (outgoing || incoming_from_known_sender)
		 && (field=mrmimeparser_find_field(mime_parser,  MAILIMF_FIELD_TO  ))!=NULL )
		{
			struct mailimf_to* fld_to = field->fld_data.fld_to; /* can be NULL */
			if( fld_to )
			{
				add_or_lookup_contacts_by_address_list__(ths, fld_to->to_addr_list /*!= NULL*/,
					outgoing? MR_ORIGIN_OUTGOING_TO : MR_ORIGIN_INCOMING_TO, to_list, NULL);
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
						add_or_lookup_contacts_by_address_list__(ths, fld_cc->cc_addr_list,
							outgoing? MR_ORIGIN_OUTGOING_CC : MR_ORIGIN_INCOMING_CC, to_list, NULL);
					}
				}
				else if( field->fld_type == MAILIMF_FIELD_BCC )
				{
					struct mailimf_bcc* fld_bcc = field->fld_data.fld_bcc;
					if( outgoing && fld_bcc ) {
						add_or_lookup_contacts_by_address_list__(ths, fld_bcc->bcc_addr_list,
							MR_ORIGIN_OUTGOING_BCC, to_list, NULL);
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
		- outgoing messages introduce a chat with the first to: address if they are send by a messenger
		- incoming messages introduce a chat only for known contacts if they are send by a messenger
		(of course, the user can add other chats manually later) */
		if( incoming )
		{
			state = (flags&MR_IMAP_SEEN)? MR_IN_SEEN : MR_IN_UNSEEN;
			to_id = MR_CONTACT_ID_SELF;

			chat_id = lookup_group_by_grpid__(ths, mime_parser,
				(incoming_from_known_sender && mime_parser->m_is_send_by_messenger)/*create as needed?*/, from_id, to_list);
			if( chat_id )
			{
				is_group = 1;
			}
			else
			{
				chat_id = mrmailbox_lookup_real_nchat_by_contact_id__(ths, from_id);
				if( chat_id == 0 && incoming_from_known_sender && mime_parser->m_is_send_by_messenger ) {
					chat_id = mrmailbox_create_or_lookup_nchat_by_contact_id__(ths, from_id);
				}

				if( chat_id == 0 ) {
					chat_id = MR_CHAT_ID_DEADDROP;
				}
			}
		}
		else /* outgoing */
		{
			state = MR_OUT_DELIVERED; /* the mail is on the IMAP server, probably it is also deliverd.  We cannot recreate other states (read, error). */
			from_id = MR_CONTACT_ID_SELF;
			if( carray_count(to_list) >= 1 ) {
				to_id   = (uint32_t)(uintptr_t)carray_get(to_list, 0);

				chat_id = lookup_group_by_grpid__(ths, mime_parser, true/*create as needed*/, 0, to_list);
				if( chat_id )
				{
					is_group = 1;
				}
				else
				{
					chat_id = mrmailbox_lookup_real_nchat_by_contact_id__(ths, to_id);
					if( chat_id == 0 && mime_parser->m_is_send_by_messenger && !mrmailbox_is_contact_blocked__(ths, to_id) ) {
						chat_id = mrmailbox_create_or_lookup_nchat_by_contact_id__(ths, to_id);
					}
				}
			}

			if( chat_id == 0 ) {
				chat_id = MR_CHAT_ID_TO_DEADDROP;
			}
		}

		/* check, if the mail is already in our database - if so, there's nothing more to do
		(we may get a mail twice eg. it it is moved between folders) */
		if( rfc724_mid == NULL ) {
			/* header is lacking a Message-ID - this may be the case, if the message was sent from this account and the mail client
			the the SMTP-server set the ID (true eg. for the Webmailer used in all-inkl-KAS)
			in these cases, we build a message ID based on some useful header fields that do never change (date, to)
			we do not use the folder-local id, as this will change if the mail is moved to another folder. */
			rfc724_mid = mr_create_incoming_rfc724_mid(message_timestamp, from_id, to_list);
			if( rfc724_mid == NULL ) {
				goto cleanup;
			}
		}

		{
			char*    old_server_folder = NULL;
			uint32_t old_server_uid = 0;
			if( mrmailbox_rfc724_mid_exists__(ths, rfc724_mid, &old_server_folder, &old_server_uid) ) {
				/* The message is already added to our database; rollback.  If needed update the server_uid which may have changed if the message was moved around on the server. */
				if( strcmp(old_server_folder, server_folder)!=0 || old_server_uid!=server_uid ) {
					mrsqlite3_rollback__(ths->m_sql);
					transaction_pending = 0;
					mrmailbox_update_server_uid__(ths, rfc724_mid, server_folder, server_uid);
				}
				free(old_server_folder);
				goto cleanup;
			}
		}

		/* fine, so far.  now, split the message into simple parts usable as "short messages"
		and add them to the database (mails send by other messenger clients should result
		into only one message; mails send by other clients may result in several messages (eg. one per attachment)) */
		icnt = carray_count(mime_parser->m_parts); /* should be at least one - maybe empty - part */
		for( i = 0; i < icnt; i++ )
		{
			mrmimepart_t* part = (mrmimepart_t*)carray_get(mime_parser->m_parts, i);

			if( part->m_type == MR_MSG_TEXT ) {
				txt_raw = mr_mprintf("%s\n\n%s", mime_parser->m_subject? mime_parser->m_subject : "", part->m_msg_raw);
			}

			stmt = mrsqlite3_predefine__(ths->m_sql, INSERT_INTO_msgs_msscftttsmttp,
				"INSERT INTO msgs (rfc724_mid,server_folder,server_uid,chat_id,from_id, to_id,timestamp,type, state,msgrmsg,txt,txt_raw,param)"
				" VALUES (?,?,?,?,?, ?,?,?, ?,?,?,?,?);");
			sqlite3_bind_text (stmt,  1, rfc724_mid, -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt,  2, server_folder, -1, SQLITE_STATIC);
			sqlite3_bind_int  (stmt,  3, server_uid);
			sqlite3_bind_int  (stmt,  4, chat_id);
			sqlite3_bind_int  (stmt,  5, from_id);
			sqlite3_bind_int  (stmt,  6, to_id);
			sqlite3_bind_int64(stmt,  7, message_timestamp);
			sqlite3_bind_int  (stmt,  8, part->m_type);
			sqlite3_bind_int  (stmt,  9, state);
			sqlite3_bind_int  (stmt, 10, mime_parser->m_is_send_by_messenger);
			sqlite3_bind_text (stmt, 11, part->m_msg? part->m_msg : "", -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt, 12, txt_raw? txt_raw : "", -1, SQLITE_STATIC);
			sqlite3_bind_text (stmt, 13, part->m_param->m_packed, -1, SQLITE_STATIC);
			if( sqlite3_step(stmt) != SQLITE_DONE ) {
				goto cleanup; /* i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record */
			}

			free(txt_raw);
			txt_raw = NULL;

			if( first_dblocal_id == 0 ) {
				first_dblocal_id = sqlite3_last_insert_rowid(ths->m_sql->m_cobj);
			}

			carray_add(created_db_entries, (void*)(uintptr_t)chat_id, NULL);
			carray_add(created_db_entries, (void*)(uintptr_t)first_dblocal_id, NULL);
		}

		/* finally, create "ghost messages" for additional to:, cc: bcc: receivers
		(just to be more compatibe to standard email-programs, the flow in the Messanger would not need this) */
		if( outgoing && is_group == 0 && carray_count(to_list)>1 && first_dblocal_id != 0 )
		{
			char* ghost_rfc724_mid_str = mr_mprintf(MR_GHOST_ID_FORMAT, first_dblocal_id); /* G@id is used to find the message if the original is deleted */
			char* ghost_param = mr_mprintf("G=%lu", first_dblocal_id);                    /* G=Ghost message flag with the original message ID */
			char* ghost_txt = NULL;
			{
				mrmimepart_t* part = (mrmimepart_t*)carray_get(mime_parser->m_parts, 0);
				ghost_txt = mrmsg_get_summarytext_by_raw(part->m_type, part->m_msg, APPROX_SUBJECT_CHARS);
			}

			icnt = carray_count(to_list);
			for( i = 1/*the first one is added in detail above*/; i < icnt; i++ )
			{
				uint32_t ghost_to_id   = (uint32_t)(uintptr_t)carray_get(to_list, i);
				uint32_t ghost_chat_id = mrmailbox_lookup_real_nchat_by_contact_id__(ths, ghost_to_id);
				uint32_t ghost_dblocal_id;
				if( ghost_chat_id==0 ) {
					ghost_chat_id = MR_CHAT_ID_TO_DEADDROP;
				}

				stmt = mrsqlite3_predefine__(ths->m_sql, INSERT_INTO_msgs_msscftttsmttp, NULL /*the first_dblocal_id-check above makes sure, the query is really created*/);
				sqlite3_bind_text (stmt,  1, ghost_rfc724_mid_str, -1, SQLITE_STATIC);
				sqlite3_bind_text (stmt,  2, "", -1, SQLITE_STATIC);
				sqlite3_bind_int  (stmt,  3, 0);
				sqlite3_bind_int  (stmt,  4, ghost_chat_id);
				sqlite3_bind_int  (stmt,  5, from_id);
				sqlite3_bind_int  (stmt,  6, ghost_to_id);
				sqlite3_bind_int64(stmt,  7, message_timestamp);
				sqlite3_bind_int  (stmt,  8, MR_MSG_TEXT);
				sqlite3_bind_int  (stmt,  9, state);
				sqlite3_bind_int  (stmt, 10, mime_parser->m_is_send_by_messenger);
				sqlite3_bind_text (stmt, 11, ghost_txt, -1, SQLITE_STATIC);
				sqlite3_bind_text (stmt, 12, "", -1, SQLITE_STATIC);
				sqlite3_bind_text (stmt, 13, ghost_param, -1, SQLITE_STATIC);
				if( sqlite3_step(stmt) != SQLITE_DONE ) {
					goto cleanup; /* i/o error - there is nothing more we can do - in other cases, we try to write at least an empty record */
				}

				ghost_dblocal_id = sqlite3_last_insert_rowid(ths->m_sql->m_cobj);

				carray_add(created_db_entries, (void*)(uintptr_t)ghost_chat_id, NULL);
				carray_add(created_db_entries, (void*)(uintptr_t)ghost_dblocal_id, NULL);
			}
			free(ghost_txt);
			free(ghost_param);
			free(ghost_rfc724_mid_str);
		}

		/* check event to send */
		if( incoming && state==MR_IN_UNSEEN )
		{
			if( from_id_blocked ) {
				event_to_send = 0;
			}
			else if( chat_id == MR_CHAT_ID_DEADDROP ) {
				if( mrsqlite3_get_config_int__(ths->m_sql, "show_deaddrop", 0)!=0 ) {
					event_to_send = MR_EVENT_INCOMING_MSG;
				}
			}
			else {
				event_to_send = MR_EVENT_INCOMING_MSG;
			}
		}

	/* end sql-transaction */
	mrsqlite3_commit__(ths->m_sql);
	transaction_pending = 0;

	#if 0
	{
		mrsqlite3_lock(ths->m_sql);
			char* debugDir = mrsqlite3_get_config_(ths->m_sql, "debug_dir", NULL);
			if( debugDir ) {
				char filename[512];
				snprintf(filename, sizeof(filename), "%s/%s-%i.eml", debugDir, server_folder, (int)first_dblocal_id);
				FILE* f = fopen(filename, "w");
				if( f ) {
					fwrite(imf_raw_not_terminated, 1, imf_raw_bytes, f);
					fclose(f);
				}
				free(debugDir);
			}
		mrsqlite3_unlock(ths->m_sql);
	}
	#endif

	/* done */
cleanup:
	if( transaction_pending ) {
		mrsqlite3_rollback__(ths->m_sql);
	}

	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	if( mime_parser ) {
		mrmimeparser_unref(mime_parser);
	}

	if( rfc724_mid ) {
		free(rfc724_mid);
	}

	if( to_list ) {
		carray_free(to_list);
	}

	if( created_db_entries && event_to_send ) {
		size_t i, icnt = carray_count(created_db_entries);
		for( i = 0; i < icnt; i += 2 ) {
			ths->m_cb(ths, event_to_send, (uintptr_t)carray_get(created_db_entries, i), (uintptr_t)carray_get(created_db_entries, i+1));
		}
		carray_free(created_db_entries);
	}

	free(txt_raw);
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


static uintptr_t cb_dummy(mrmailbox_t* mailbox, int event, uintptr_t data1, uintptr_t data2)
{
	return 0;
}
static int32_t cb_get_config_int(mrimap_t* imap, const char* key, int32_t value)
{
	mrmailbox_t* mailbox = (mrmailbox_t*)imap->m_userData;
	mrsqlite3_lock(mailbox->m_sql);
		int32_t ret = mrsqlite3_get_config_int__(mailbox->m_sql, key, value);
	mrsqlite3_unlock(mailbox->m_sql);
	return ret;
}
static void cb_set_config_int(mrimap_t* imap, const char* key, int32_t def)
{
	mrmailbox_t* mailbox = (mrmailbox_t*)imap->m_userData;
	mrsqlite3_lock(mailbox->m_sql);
		mrsqlite3_set_config_int__(mailbox->m_sql, key, def);
	mrsqlite3_unlock(mailbox->m_sql);
}
static void cb_receive_imf(mrimap_t* imap, const char* imf_raw_not_terminated, size_t imf_raw_bytes, const char* server_folder, uint32_t server_uid, uint32_t flags)
{
	mrmailbox_t* mailbox = (mrmailbox_t*)imap->m_userData;
	receive_imf(mailbox, imf_raw_not_terminated, imf_raw_bytes, server_folder, server_uid, flags);
}


mrmailbox_t* mrmailbox_new(mrmailboxcb_t cb, void* userData)
{
	mrlog_get_thread_index(); /* make sure, the main thread has the index #1, only for a nicer look of the logs */

	mrmailbox_t* ths = NULL;

	if( (ths=calloc(1, sizeof(mrmailbox_t)))==NULL ) {
		exit(23); /* cannot allocate little memory, unrecoverable error */
	}

	MR_INIT_REFERENCE

	ths->m_sql      = mrsqlite3_new(ths);
	ths->m_cb       = cb? cb : cb_dummy;
	ths->m_userData = userData;
	ths->m_imap     = mrimap_new(cb_get_config_int, cb_set_config_int, cb_receive_imf, (void*)ths);
	ths->m_smtp     = mrsmtp_new();

	mrjob_init_thread(ths);

	return ths;
}


void mrmailbox_unref(mrmailbox_t* ths)
{
	MR_DEC_REFERENCE_AND_CONTINUE_ON_0

	mrjob_exit_thread(ths);

	if( mrmailbox_is_open(ths) ) {
		mrmailbox_close(ths);
	}

	mrimap_unref(ths->m_imap);
	mrsmtp_unref(ths->m_smtp);
	mrsqlite3_unref(ths->m_sql);
	free(ths);
}


int mrmailbox_open(mrmailbox_t* ths, const char* dbfile, const char* blobdir)
{
	int success = 0;
	int db_locked = 0;

	if( ths == NULL || dbfile == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(ths->m_sql);
	db_locked = 1;

	/* Open() sets up the object and connects to the given database
	from which all configuration is read/written to. */

	/* Create/open sqlite database */
	if( !mrsqlite3_open__(ths->m_sql, dbfile) ) {
		goto cleanup;
	}

	/* backup dbfile name */
	ths->m_dbfile = safe_strdup(dbfile);

	/* set blob-directory
	(to avoid double slashed, the given directory should not end with an slash) */
	if( blobdir && blobdir[0] ) {
		ths->m_blobdir = safe_strdup(blobdir);
	}
	else {
		ths->m_blobdir = mr_mprintf("%s-blobs", dbfile);
		mr_create_folder(ths->m_blobdir);
	}

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	if( !success ) {
		if( mrsqlite3_is_open(ths->m_sql) ) {
			mrsqlite3_close__(ths->m_sql);
		}
	}

	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	return success;
}


void mrmailbox_close(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrimap_disconnect(ths->m_imap);
	mrsmtp_disconnect(ths->m_smtp);

	mrsqlite3_lock(ths->m_sql);

		if( mrsqlite3_is_open(ths->m_sql) ) {
			mrsqlite3_close__(ths->m_sql);
		}

		free(ths->m_dbfile);
		ths->m_dbfile = NULL;

		free(ths->m_blobdir);
		ths->m_blobdir = NULL;

	mrsqlite3_unlock(ths->m_sql);
}


int mrmailbox_is_open(const mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return 0; /* error - database not opened */
	}

	return mrsqlite3_is_open(ths->m_sql);
}


/*******************************************************************************
 * Import EML-files
 ******************************************************************************/


int mrmailbox_import_file(mrmailbox_t* ths, const char* filename)
{
	int     success = 0;
	char*   data = NULL;
	size_t  data_bytes;

	if( ths == NULL ) {
		return 0;
	}

	if( mr_read_file(filename, (void**)&data, &data_bytes) == 0 ) {
		goto cleanup;
	}

	receive_imf(ths, data, data_bytes, "import", 0, 0);
	success = 1;

cleanup:
	free(data);

	return success;
}


int mrmailbox_import_spec(mrmailbox_t* ths, const char* spec) /* spec is a file, a directory or NULL for the last import */
{
	int            success = 0;
	char*          spec_memory = NULL;
	DIR*           dir = NULL;
	struct dirent* dir_entry;
	int            read_cnt = 0;
	char*          name;

	if( ths == NULL ) {
		return 0;
	}

	if( !mrsqlite3_is_open(ths->m_sql) ) {
        mrlog_error("Import: Database not opened.");
		goto cleanup;
	}

	/* if `spec` is given, remember it for later usage; if it is not given, try to use the last one */
	if( spec )
	{
		mrsqlite3_lock(ths->m_sql);
			mrsqlite3_set_config__(ths->m_sql, "import_spec", spec);
		mrsqlite3_unlock(ths->m_sql);
	}
	else {
		mrsqlite3_lock(ths->m_sql);
			spec_memory = mrsqlite3_get_config__(ths->m_sql, "import_spec", NULL);
		mrsqlite3_unlock(ths->m_sql);

		spec = spec_memory; /* may still  be NULL */
		if( spec == NULL ) {
			mrlog_error("Import: No file or folder given.");
			goto cleanup;
		}
	}

	if( strlen(spec)>=4 && strcmp(&spec[strlen(spec)-4], ".eml")==0 ) {
		/* import a single file */
		if( mrmailbox_import_file(ths, spec) ) { /* errors are logged in any case */
			read_cnt++;
		}
	}
	else {
		/* import a directory */
		if( (dir=opendir(spec))==NULL ) {
			mrlog_error("Import: Cannot open directory \"%s\".", spec);
			goto cleanup;
		}

		while( (dir_entry=readdir(dir))!=NULL ) {
			name = dir_entry->d_name; /* name without path; may also be `.` or `..` */
            if( strlen(name)>=4 && strcmp(&name[strlen(name)-4], ".eml")==0 ) {
				char* path_plus_name = sqlite3_mprintf("%s/%s", spec, name);
				mrlog_info("Import: %s", path_plus_name);
				if( path_plus_name ) {
					if( mrmailbox_import_file(ths, path_plus_name) ) { /* no abort on single errors errors are logged in any case */
						read_cnt++;
					}
					sqlite3_free(path_plus_name);
				}
            }
		}
	}

	mrlog_info("Import: %i mails read from \"%s\".", read_cnt, spec);
	if( read_cnt > 0 ) {
		ths->m_cb(ths, MR_EVENT_MSGS_CHANGED, 0, 0); /* even if read_cnt>0, the number of messages added to the database may be 0. While we regard this issue using IMAP, we ignore it here. */
	}

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	if( dir ) {
		closedir(dir);
	}
	free(spec_memory);
	return success;
}


/*******************************************************************************
 * Configuration
 ******************************************************************************/


int mrmailbox_set_config(mrmailbox_t* ths, const char* key, const char* value)
{
	int ret;

	if( ths == NULL || key == NULL ) { /* "value" may be NULL */
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
		ret = mrsqlite3_set_config__(ths->m_sql, key, value);
	mrsqlite3_unlock(ths->m_sql);

	return ret;
}


char* mrmailbox_get_config(mrmailbox_t* ths, const char* key, const char* def)
{
	char* ret;

	if( ths == NULL || key == NULL ) { /* "def" may be NULL */
		return safe_strdup(def);
	}

	mrsqlite3_lock(ths->m_sql);
		ret = mrsqlite3_get_config__(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql);

	return ret; /* the returned string must be free()'d, returns NULL on errors */
}


int mrmailbox_set_config_int(mrmailbox_t* ths, const char* key, int32_t value)
{
	int ret;

	if( ths == NULL || key == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
		ret = mrsqlite3_set_config_int__(ths->m_sql, key, value);
	mrsqlite3_unlock(ths->m_sql);

	return ret;
}


int32_t mrmailbox_get_config_int(mrmailbox_t* ths, const char* key, int32_t def)
{
	int32_t ret;

	if( ths == NULL || key == NULL ) {
		return def;
	}

	mrsqlite3_lock(ths->m_sql);
		ret = mrsqlite3_get_config_int__(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql);

	return ret;
}


int mrmailbox_configure(mrmailbox_t* ths)
{
	mrloginparam_t* param;

	mrlog_info("Configuring...");

	if( ths == NULL || !mrsqlite3_is_open(ths->m_sql) ) {
		mrlog_error("Database not opened.");
		return 0;
	}

	/* read the original parameters */
	param = mrloginparam_new();

	mrsqlite3_lock(ths->m_sql);
		mrloginparam_read__(param, ths->m_sql, "");
	mrsqlite3_unlock(ths->m_sql);

	/* complete the parameters; in the future we may also try some server connections here */
	mrloginparam_complete(param);

	/* write back the configured parameters with the "configured_" prefix. Also write the "configured"-flag */
	mrsqlite3_lock(ths->m_sql);
		if( param->m_addr
		 && param->m_mail_server
		 && param->m_mail_port
		 && param->m_mail_user
		 && param->m_mail_pw
		 && param->m_send_server
		 && param->m_send_port
		 && param->m_send_user
		 && param->m_send_pw )
		{
			mrloginparam_write__(param, ths->m_sql, "configured_" /*the trailing underscore is correct*/);
			mrsqlite3_set_config_int__(ths->m_sql, "configured", 1);
		}
		else
		{
			mrsqlite3_set_config_int__(ths->m_sql, "configured", 0);
		}
	mrsqlite3_unlock(ths->m_sql);

	mrloginparam_unref(param);
	param = NULL;

	mrlog_info("Configure ok.");

	return 1;
}


int mrmailbox_is_configured(mrmailbox_t* ths)
{
	int is_configured;

	if( ths == NULL ) {
		return 0;
	}

	if( mrimap_is_connected(ths->m_imap) ) { /* if we're connected, we're also configured. this check will speed up the check as no database is involved */
		return 1;
	}

	mrsqlite3_lock(ths->m_sql);

		is_configured = mrsqlite3_get_config_int__(ths->m_sql, "configured", 0);

	mrsqlite3_unlock(ths->m_sql);

	return is_configured? 1 : 0;
}


char* mrmailbox_get_info(mrmailbox_t* ths)
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	char *displayname = NULL, *info = NULL;
	mrloginparam_t *l = NULL, *l2 = NULL;
	int contacts, chats, real_msgs, deaddrop_msgs, is_configured;

	if( ths == NULL ) {
		return safe_strdup("ErrBadPtr");
	}

	/* read data (all pointers may be NULL!) */
	l = mrloginparam_new();
	l2 = mrloginparam_new();

	mrsqlite3_lock(ths->m_sql);

		mrloginparam_read__(l, ths->m_sql, "");
		mrloginparam_read__(l2, ths->m_sql, "configured_" /*the trailing underscore is correct*/);

		displayname     = mrsqlite3_get_config__(ths->m_sql, "displayname", NULL);

		chats           = mrmailbox_get_chat_cnt__(ths);
		real_msgs       = mrmailbox_get_real_msg_cnt__(ths);
		deaddrop_msgs   = mrmailbox_get_deaddrop_msg_cnt__(ths);
		contacts        = mrmailbox_get_real_contact_cnt__(ths);

		is_configured   = mrsqlite3_get_config_int__(ths->m_sql, "configured", 0);

	mrsqlite3_unlock(ths->m_sql);

	/* create info
	- some keys are display lower case - these can be changed using the `set`-command
	- we do not display the password here; in the cli-utility, you can see it using `get mail_pw`
	- use neutral speach; the messenger backend is not directly related to any front end or end-product
	- contributors: You're welcome to add your names here */
	info = mr_mprintf(
		"Messenger Backend %i.%i.%i - (C) Björn Petersen and contributors\n"
		"\n"
		"%i chats with %i messages, %i messages in mailbox, %i contacts\n"
		"Database file: %s, blob directory: %s\n"
		"\n"
		"displayname=%s\n"
		"configured=%i\n"
		"addr=%s (%s)\n"
		"mail_server=%s (%s)\n"
		"mail_port=%i (%i)\n"
		"mail_user=%s (%s)\n"
		"mail_pw=%s (%s)\n"
		"send_server=%s (%s)\n"
		"send_port=%i (%i)\n"
		"send_user=%s (%s)\n"
		"send_pw=%s (%s)\n"
		"server_flags=%i (%i)\n"
		"\n"
		"Using SQLite %s-ts%i and libEtPan %i.%i. Compiled " __DATE__ ", " __TIME__ " for %i bit usage."
		/* In the frontends, additional software hints may follow here. */

		, MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION

		, chats, real_msgs, deaddrop_msgs, contacts
		, ths->m_dbfile? ths->m_dbfile : unset   ,  ths->m_blobdir? ths->m_blobdir : unset

        , displayname? displayname : unset
		, is_configured
		, l->m_addr? l->m_addr : unset                 , l2->m_addr? l2->m_addr : unset
		, l->m_mail_server? l->m_mail_server : unset   , l2->m_mail_server? l2->m_mail_server : unset
		, l->m_mail_port? l->m_mail_port : 0           , l2->m_mail_port? l2->m_mail_port : 0
		, l->m_mail_user? l->m_mail_user : unset       , l2->m_mail_user? l2->m_mail_user : unset
		, l->m_mail_pw? set : unset,                     l2->m_mail_pw? set : unset
		, l->m_send_server? l->m_send_server : unset   , l2->m_send_server? l2->m_send_server : unset
		, l->m_send_port? l->m_send_port : 0           , l2->m_send_port? l2->m_send_port : 0
		, l->m_send_user? l->m_send_user : unset       , l2->m_send_user? l2->m_send_user : unset
		, l->m_send_pw? set : unset                    , l2->m_send_pw? set : unset
		, l->m_server_flags? l->m_server_flags : 0     , l2->m_server_flags? l2->m_server_flags : 0

		, SQLITE_VERSION, sqlite3_threadsafe()   ,  libetpan_get_version_major(), libetpan_get_version_minor(), sizeof(void*)*8

		);

	/* free data */
	mrloginparam_unref(l);
	mrloginparam_unref(l2);
	free(displayname);

	return info; /* must be freed by the caller */
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


int mrmailbox_empty_tables(mrmailbox_t* ths)
{
	mrlog_info("Emptying all tables...");

	mrsqlite3_lock(ths->m_sql);

		mrsqlite3_execute__(ths->m_sql, "DELETE FROM contacts WHERE id>" MR_STRINGIFY(MR_CONTACT_ID_LAST_SPECIAL) ";"); /* the other IDs are reserved - leave these rows to make sure, the IDs are not used by normal contacts*/
		mrsqlite3_execute__(ths->m_sql, "DELETE FROM chats WHERE id>" MR_STRINGIFY(MR_CHAT_ID_LAST_SPECIAL) ";");
		mrsqlite3_execute__(ths->m_sql, "DELETE FROM chats_contacts;");
		mrsqlite3_execute__(ths->m_sql, "DELETE FROM msgs WHERE id>" MR_STRINGIFY(MR_MSG_ID_LAST_SPECIAL) ";");
		mrsqlite3_execute__(ths->m_sql, "DELETE FROM config WHERE keyname LIKE 'imap.%' OR keyname LIKE 'configured%';");
		mrsqlite3_execute__(ths->m_sql, "DELETE FROM jobs;");

	mrsqlite3_unlock(ths->m_sql);

	mrlog_info("Tables emptied.");

	ths->m_cb(ths, MR_EVENT_MSGS_CHANGED, 0, 0);

	return 1;
}


char* mrmailbox_get_version_str(void)
{
	return mr_mprintf("%i.%i.%i", (int)MR_VERSION_MAJOR, (int)MR_VERSION_MINOR, (int)MR_VERSION_REVISION);
}


char* mrmailbox_execute(mrmailbox_t* ths, const char* cmd)
{
	#define COMMAND_FAILED    ((char*)1)
	#define COMMAND_SUCCEEDED ((char*)2)
	char*   ret = NULL;

	if( ths == NULL || cmd == NULL || cmd[0]==0 ) {
		goto done;
	}

	if( strncmp(cmd, "open", 4)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			mrmailbox_close(ths);
			ret = mrmailbox_open(ths, arg1, NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <file> missing.");
		}
	}
	else if( strcmp(cmd, "close")==0 )
	{
		mrmailbox_close(ths);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strncmp(cmd, "import", 6)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		ret = mrmailbox_import_spec(ths, arg1? ++arg1 : NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "configure")==0 )
	{
		ret = mrmailbox_configure(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "connect")==0 )
	{
		ret = mrmailbox_connect(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "disconnect")==0 )
	{
		mrmailbox_disconnect(ths);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strcmp(cmd, "fetch")==0 )
	{
		ret = mrmailbox_fetch(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strncmp(cmd, "restore", 7)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int days = atoi(arg1);
			ret = mrmailbox_restore(ths, days*24*60*60)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <days> missing.");
		}
	}
	else if( strncmp(cmd, "set", 3)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			char* arg2 = strstr(arg1, " ");
			if( arg2 ) {
				*arg2 = 0;
				arg2++;
			}
			ret = mrmailbox_set_config(ths, arg1, arg2)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strncmp(cmd, "get", 3)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			char* val = mrmailbox_get_config(ths, arg1, "<unset>");
			if( val ) {
				ret = mr_mprintf("%s=%s", arg1, val);
				free(val);
			}
			else {
				ret = COMMAND_FAILED;
			}
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strncmp(cmd, "delmsg ", 7)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_delete_msg(ths, id)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}
	else if( strncmp(cmd, "msginfo ", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_get_msg_info(ths, id);
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}
	else if( strncmp(cmd, "markseen ", 9)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int id = atoi(arg1);
			ret = mrmailbox_markseen_msg(ths, id)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <message-id> missing.");
		}
	}
	else if( strcmp(cmd, "info")==0 )
	{
		ret = mrmailbox_get_info(ths);
		if( ret == NULL ) {
			ret = COMMAND_FAILED;
		}
	}
	else if( strcmp(cmd, "empty")==0 )
	{
		ret = mrmailbox_empty_tables(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strncmp(cmd, "event", 5)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int event = atoi(arg1);
			uintptr_t r = ths->m_cb(ths, event, 0, 0);
			ret = mr_mprintf("Sending event %i, received value %i.", (int)event, (int)r);
		}
		else {
			ret = safe_strdup("ERROR: Argument <id> missing.");
		}
	}
	else if( strncmp(cmd, "createchat ", 11)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int contact_id = atoi(arg1);
			ret = mrmailbox_create_chat_by_contact_id(ths, contact_id)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <contact-id> missing.");
		}
	}
	else if( strncmp(cmd, "creategroup ", 12)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;;
			ret = mrmailbox_create_group_chat(ths, arg1)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <name> missing.");
		}
	}
	else if( strncmp(cmd, "delchat ", 8)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			int chat_id = atoi(arg1);
			ret = mrmailbox_delete_chat(ths, chat_id)!=0? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <chat-id> missing.");
		}
	}
	else if( strncmp(cmd, "adr", 3)==0 )
	{
		char *arg1 = (char*)strstr(cmd, " "), *arg2 = NULL;
		if( arg1 ) { arg1++; arg2 = strstr(arg1, ";"); }
		if( arg1 && arg2 ) {
			*arg2 = 0; arg2++;
			char* book = mr_mprintf("%s\n%s", arg1, arg2);
				mrmailbox_add_address_book(ths, book);
				ret = COMMAND_SUCCEEDED;
			free(book);
		}
		else {
			ret = safe_strdup("ERROR: Argument <name>;<addr> expected.");
		}
	}

done:
	if( ret == COMMAND_FAILED ) {
		ret = safe_strdup("ERROR: Command failed.");
	}
	else if( ret == COMMAND_SUCCEEDED ) {
		ret = safe_strdup("Command executed successfully.");
	}
	return ret;
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


void mrmailbox_connect_to_imap(mrmailbox_t* ths, mrjob_t* job /*may be NULL if the function is called directly!*/)
{
	int             is_locked = 0, success = 0;
	mrloginparam_t* param = mrloginparam_new();

	if( mrimap_is_connected(ths->m_imap) ) {
		mrlog_error("Already connected or trying to connect.");
		goto cleanup; /* this is no success */
	}

	mrsqlite3_lock(ths->m_sql);
	is_locked = 1;

		if( mrsqlite3_get_config_int__(ths->m_sql, "configured", 0) == 0 ) {
			mrlog_error("Not configured.");
			goto cleanup;
		}

		mrloginparam_read__(param, ths->m_sql, "configured_" /*the trailing underscore is correct*/);

	mrsqlite3_unlock(ths->m_sql);
	is_locked = 0;

	if( !mrimap_connect(ths->m_imap, param) ) {
		goto cleanup;
	}

	success = 1;

cleanup:
	if( param ) {
		mrloginparam_unref(param);
	}

	if( is_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}

	ths->m_cb(ths, MR_EVENT_CONNECTION_STATE_CHANGED, success, 0);
}


int mrmailbox_connect(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql);
		mrjob_add__(ths, MRJ_CONNECT_TO_IMAP, 0, NULL);
	mrsqlite3_unlock(ths->m_sql);
	return 1;
}


void mrmailbox_disconnect(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrimap_disconnect(ths->m_imap);
	mrsmtp_disconnect(ths->m_smtp);
}


int mrmailbox_fetch(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return 0;
	}

	return mrimap_fetch(ths->m_imap);
}


int mrmailbox_restore(mrmailbox_t* ths, time_t seconds_to_restore)
{
	if( ths == NULL ) {
		return 0;
	}

	return mrimap_restore(ths->m_imap, seconds_to_restore);
}


char* mrmailbox_get_error_descr(mrmailbox_t* ths)
{
	if( ths == NULL || ths->m_imap == NULL || ths->m_imap->m_error_descr == NULL ) {
		return safe_strdup("");
	}
	return safe_strdup(ths->m_imap->m_error_descr);
}
