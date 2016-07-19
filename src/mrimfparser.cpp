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
#include "mrmailbox.h"
#include "mrimfparser.h"


MrImfParser::MrImfParser(MrMailbox* mailbox)
{
	m_mailbox = mailbox;
}


MrImfParser::~MrImfParser()
{
}


void MrImfParser::AddOrLookupContact(const char* display_name /*can be NULL*/, const char* addr_spec)
{
	printf("%s - %s\n", display_name, addr_spec);
}


void MrImfParser::AddOrLookupContacts(mailimf_mailbox_list* mb_list)
{
	for( clistiter* cur = clist_begin(mb_list->mb_list); cur!=NULL ; cur=clist_next(cur) ) {
		mailimf_mailbox* mb = (mailimf_mailbox*)clist_content(cur);
		if( mb ) {
			AddOrLookupContact(mb->mb_display_name, mb->mb_addr_spec);
		}
	}
}


void MrImfParser::AddOrLookupContacts(mailimf_address_list* adr_list) // an address is a mailbox or a group
{
	for( clistiter* cur = clist_begin(adr_list->ad_list); cur!=NULL ; cur=clist_next(cur) ) {
		mailimf_address* adr = (mailimf_address*)clist_content(cur);
		if( adr ) {
			if( adr->ad_type == MAILIMF_ADDRESS_MAILBOX ) {
				mailimf_mailbox* mb = adr->ad_data.ad_mailbox; // can be NULL
				if( mb ) {
					AddOrLookupContact(mb->mb_display_name, mb->mb_addr_spec);
				}
			}
			else if( adr->ad_type == MAILIMF_ADDRESS_GROUP ) {
				mailimf_group* group = adr->ad_data.ad_group; // can be NULL
				if( group && group->grp_mb_list /*can be NULL*/ ) {
					AddOrLookupContacts(group->grp_mb_list);
				}
			}
		}
	}
}


int32_t MrImfParser::Imf2Msg(uint32_t uid, const char* imf_raw, size_t imf_len)
{
	size_t imf_start = 0; // in/out: pointer to the current/next message; we assume, we only get one IMF at once.
	mailimf_message* imf;

	// parse the imf to mailimf_message {
	//		mailimf_fields* msg_fields {
	//          clist* fld_list; // list of mailimf_field
	//      }
	//		mailimf_body* msg_body;
	// };
	int r = mailimf_message_parse(imf_raw, imf_len, &imf_start, &imf);
	if( r!=MAILIMF_NO_ERROR ) {
		return 0; // error
	}

	// iterate through the parsed fields
	for( clistiter* cur1 = clist_begin(imf->msg_fields->fld_list); cur1!=NULL ; cur1=clist_next(cur1) )
	{
		mailimf_field* field = (mailimf_field*)clist_content(cur1);
		if( field )
		{
			if( field->fld_type == MAILIMF_FIELD_FROM )
			{
				mailimf_from* fld_from = field->fld_data.fld_from; // can be NULL
				if( fld_from ) {
					AddOrLookupContacts(fld_from->frm_mb_list /*!= NULL*/);
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_TO )
			{
				mailimf_to* fld_to = field->fld_data.fld_to; // can be NULL
				if( fld_to ) {
					AddOrLookupContacts(fld_to->to_addr_list /*!= NULL*/);
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_CC )
			{
				mailimf_cc* fld_cc = field->fld_data.fld_cc; // can be NULL;
				if( fld_cc ) {
					AddOrLookupContacts(fld_cc->cc_addr_list /*!= NULL*/);
				}
			}
			else if( field->fld_type == MAILIMF_FIELD_ORIG_DATE )
			{
				mailimf_orig_date* orig_date = field->fld_data.fld_orig_date;
				if( orig_date ) {
					mailimf_date_time* dt = orig_date->dt_date_time;
				}
			}
		}
    }

	mailimf_message_free(imf);
	return 0;
}
