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
 * File:    mrcontact.h
 * Authors: Björn Petersen
 * Purpose: mrcontact_t represents a single contact - if in doubt a contact is
 *          every (email-)adresses the user has _send_ a mail to (only receiving
 *          is not sufficient).
 *          For the future, we plan to use the systems address books and/or a
 *          CardDAV server, too.
 *
 ******************************************************************************/


#ifndef __MRCONTACT_H__
#define __MRCONTACT_H__
#ifdef __cplusplus
extern "C" {
#endif


/* specical contact IDs */
#define MR_CONTACT_ID_SELF         1
#define MR_CONTACT_ID_SYSTEM       2
#define MR_CONTACT_ID_LAST_SPECIAL 9


/* contact origins */
#define MR_ORIGIN_UNSET                         0
#define MR_ORIGIN_INCOMING_UNKNOWN_FROM      0x10 /* From: of incoming messages of unknown sender */
#define MR_ORIGIN_INCOMING_REPLY_TO         0x100 /* Reply-To: of incoming message of known sender (TODO) */
#define MR_ORIGIN_INCOMING_CC               0x200 /* Cc: of incoming message of known sender */
#define MR_ORIGIN_INCOMING_TO               0x400 /* additional To:'s of incoming message of known sender */
#define MR_ORIGIN_CREATE_CHAT               0x800 /* a chat was manually created for this user, but no message yet sent */
#define MR_ORIGIN_OUTGOING_BCC             0x1000 /* message send by us */
#define MR_ORIGIN_OUTGOING_CC              0x2000 /* message send by us */
#define MR_ORIGIN_OUTGOING_TO              0x4000 /* message send by us */
#define MR_ORIGIN_INTERNAL                0x40000 /* internal use */
#define MR_ORIGIN_ADRESS_BOOK             0x80000 /* address is in out address book */


typedef struct mrcontact_t
{
	uint32_t            m_id;
	char*               m_name;  /* may be NULL or empty */
	char*               m_addr;
	int                 m_origin;
	int                 m_blocked;
	mrmailbox_t*        m_mailbox;
	int                 m_refcnt;
} mrcontact_t;


void         mrcontact_unref           (mrcontact_t*);


/*** library-private **********************************************************/

mrcontact_t* mrcontact_new             (mrmailbox_t*); /* the returned pointer is ref'd and must be unref'd after usage */
void         mrcontact_empty           (mrcontact_t*);
mrcontact_t* mrcontact_ref             (mrcontact_t*);
int          mrcontact_load_from_db_   (mrcontact_t*, uint32_t id);
size_t       mr_get_real_contact_cnt_  (mrmailbox_t*);
void         mr_normalize_name         (char* full_name);
char*        mr_get_first_name         (const char* full_name); /* returns part before the space or after a comma; the result must be free()'d */
uint32_t     mr_add_or_lookup_contact_ (mrmailbox_t*, const char* display_name /*can be NULL*/, const char* addr_spec, int origin);
int          mr_is_known_contact_      (mrmailbox_t*, uint32_t id);
int          mr_real_contact_exists_   (mrmailbox_t*, uint32_t id);

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCONTACT_H__ */

