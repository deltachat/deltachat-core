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


int32_t MrImfParser::Imf2Msg(uint32_t uid, const char* imf_raw, size_t imf_len)
{
	size_t imf_start = 0; // in/out: pointer to the current/next message
	mailimf_message* imf;

	int r = mailimf_message_parse(imf_raw, imf_len, &imf_start, &imf);
	if( r!=MAILIMF_NO_ERROR ) {
		return 0; // error
	}

	mailimf_message_free(imf);
	return 0;
}
