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
 * File:    mrcontactlist.h
 * Authors: Björn Petersen
 * Purpose: List of contacts
 *
 ******************************************************************************/


#ifndef __MRCONTACTLIST_H__
#define __MRCONTACTLIST_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct mrcontactlist_t
{
	carray*      m_contacts; /* contains mrcontact_t objects */
	mrmailbox_t* m_mailbox;
} mrcontactlist_t;


mrcontactlist_t* mrcontactlist_new                  (mrmailbox_t*);
void             mrcontactlist_unref                (mrcontactlist_t*);
void             mrcontactlist_empty                (mrcontactlist_t*);
size_t           mrcontactlist_get_cnt              (mrcontactlist_t*);
mrcontact_t*     mrcontactlist_get_contact_by_index (mrcontactlist_t*, size_t index); /* result must be unref'd, you can also use m_contacts directly */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCONTACTLIST_H__ */

