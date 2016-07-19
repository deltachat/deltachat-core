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
 * File:    mrimfparser.h
 * Authors: Björn Petersen
 * Purpose: Parse IMF (Internet Message Format) as stored eg in .eml files,
 *          see https://tools.ietf.org/html/rfc5322
 *
 ******************************************************************************/


#ifndef __MRIMFPARSER_H__
#define __MRIMFPARSER_H__


class MrImfParser
{
public:
	                    MrImfParser          (MrMailbox* mailbox);
	                    ~MrImfParser         ();

	// Imf2Msg() takes an IMF, convers into one or more messages and stores them in the database.
	// the function returns the number of new created messages.
	int32_t             Imf2Msg              (uint32_t server_id, const char* imf);

private:
	MrMailbox*          m_mailbox;
};


#endif // __MRIMFPARSER_H__

