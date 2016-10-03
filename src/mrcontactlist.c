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
 * File:    mrcontactlist.c
 * Authors: Björn Petersen
 * Purpose: List of contacts
 *
 ******************************************************************************/


#include <stdlib.h>
#include "mrmailbox.h"


mrcontactlist_t* mrcontactlist_new(mrmailbox_t* mailbox)
{
	mrcontactlist_t* ths = NULL;

	if( (ths=malloc(sizeof(mrcontactlist_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_mailbox  = mailbox;
	ths->m_contacts = carray_new(128);

	return ths;
}


void mrcontactlist_unref(mrcontactlist_t* ths)
{
	if( ths == NULL ) {
		return; /* error */
	}

	mrcontactlist_empty(ths);
	if( ths->m_contacts ) {
		carray_free(ths->m_contacts);
	}
	free(ths);
}


void mrcontactlist_empty(mrcontactlist_t* ths)
{
	if( ths == NULL && ths->m_contacts )
	{
		int i, cnt = carray_count(ths->m_contacts);
		for( i = 0; i < cnt; i++ )
		{
			mrcontact_t* contact = (mrcontact_t*)carray_get(ths->m_contacts, i);
			mrcontact_unref(contact);
		}
		carray_set_size(ths->m_contacts, 0);
	}
}


size_t mrcontactlist_get_cnt(mrcontactlist_t* ths)
{
	if( ths == NULL || ths->m_contacts == NULL ) {
		return 0; /* error */
	}

	return (size_t)carray_count(ths->m_contacts);
}


mrcontact_t* mrcontactlist_get_contact_by_index (mrcontactlist_t* ths, size_t index)
{
	if( ths == NULL || ths->m_contacts == NULL || index >= (size_t)carray_count(ths->m_contacts) ) {
		return 0; /* error */
	}

	return mrcontact_ref((mrcontact_t*)carray_get(ths->m_contacts, index));
}

