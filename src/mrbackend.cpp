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
 * File:    mrbackend.cpp
 * Authors: Björn Petersen
 * Purpose: Main Backend Class
 *
 ******************************************************************************/


#include <iostream>
#include <string.h>
#include <libetpan/libetpan.h>
#include <sqlite3.h>
#include "mrbackend.h"


void MrBackend::Init()
{
	// test LibEtPan
	struct mailimf_mailbox * mb;
	char * display_name;
	char * address;

	display_name = strdup("DINH =?iso-8859-1?Q?Vi=EAt_Ho=E0?=");
	address = strdup("dinh.viet.hoa@free.fr");
	mb = mailimf_mailbox_new(display_name, address); // mailimf_mailbox_new() takes ownership of the given strings!
	mailimf_mailbox_free(mb);

	// test sqlite
	if( sqlite3_open("~/temp/foobar.db", &m_sqlite) == SQLITE_OK ) {
		sqlite3_close(m_sqlite);
	}
}



