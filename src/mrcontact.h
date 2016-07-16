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
 * Purpose: MrContact represents a single contact - if in doubt a contact is
 *          every email-adresses the user has _send_ a mail to (only receiving
 *          is not sufficient).
 *          For the future, we plan to use the systems address books and/or a
 *          CardDAV server, too.
 *
 ******************************************************************************/


#ifndef __MRCONTACT_H__
#define __MRCONTACT_H__


class MrContact
{
public:
	// if a contact object is no longer needed, they should be Release()'d, to destroy a contact physically,
	// call Destroy() (an additional Release() is needed even in this case)
	void         Release     () { delete this; }
	void         Destroy     ();

	// the data should be read only and are valid until the object is Release()'d.
	// unset strings are set to NULL.
	char*        m_name;
	char*        m_email;

private:
	// as contact objects are only constructed by MrMailbox, we declare the constructor as private and MrMailbox as a friend
	             MrContact   (MrMailbox*);
	             ~MrContact     ();
	friend class MrMailbox;

	// the mailbox, the contact belongs to
	MrMailbox*   m_mailbox;
};


#endif // __MRCONTACT_H__

