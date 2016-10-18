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


typedef struct mrcontact_t
{
	uint32_t            m_id;
	char*               m_name;  /* != NULL, however, may be empty */
	char*               m_addr;  /* != NULL */
	mrmailbox_t*        m_mailbox;
	int                 m_refcnt;
} mrcontact_t;


void         mrcontact_unref           (mrcontact_t*);


/*** library-private **********************************************************/

mrcontact_t* mrcontact_new             (mrmailbox_t*); /* the returned pointer is ref'd and must be unref'd after usage */
void         mrcontact_empty           (mrcontact_t*);
mrcontact_t* mrcontact_ref             (mrcontact_t*);
int          mrcontact_load_from_db_   (mrcontact_t*, uint32_t id);
size_t       mr_get_contact_cnt_       (mrmailbox_t*);
void         mr_normalize_name         (char* full_name);
char*        mr_get_first_name         (const char* full_name); /* returns part before the space or after a comma; the result must be free()'d */
uint32_t     mr_add_or_lookup_contact  (mrmailbox_t*, const char* display_name_enc /*can be NULL*/, const char* addr_spec, int verified);
void         mr_add_or_lookup_contact2 (mrmailbox_t*, const char* display_name_enc /*can be NULL*/, const char* addr_spec, int verified, carray* ids);

#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCONTACT_H__ */

