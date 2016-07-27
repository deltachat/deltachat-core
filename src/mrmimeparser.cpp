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
 * File:    mrmimeparser.h
 * Authors: Björn Petersen
 * Purpose: Parse MIME body, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrmimeparser.h"
#include "mrtools.h"


/*******************************************************************************
 * a MIME part
 ******************************************************************************/


MrMimePart::MrMimePart()
{
	m_type = MR_MSG_UNDEFINED;
	m_txt  = NULL;
}


MrMimePart::~MrMimePart()
{
	if( m_txt ) {
		free((void*)m_txt);
		m_txt = NULL;
	}
}


/*******************************************************************************
 * MIME parser
 ******************************************************************************/


MrMimeParser::MrMimeParser()
{
	m_parts = carray_new(16);
}


MrMimeParser::~MrMimeParser()
{
	Empty();
	carray_free(m_parts);
}


void MrMimeParser::Empty()
{
	if( m_parts )
	{
		int i, cnt = carray_count(m_parts);
		for( i = 0; i < cnt; i++ ) {
			MrMimePart* part = (MrMimePart*)carray_get(m_parts, i);
			if( part ) {
				delete part;
			}
		}
		carray_set_size(m_parts, 0);
	}
}


carray* MrMimeParser::Parse(const char* subject, const char* body)
{
	int r;
	size_t index = 0;
	mailmime* mime = NULL;
	MrMimePart* part;

	Empty();

	// parse body
	r = mailmime_parse(body, strlen(body), &index, &mime);
	if(r != MAILIMF_NO_ERROR || mime == NULL ) {
		goto Parse_Cleanup;
	}

	// check parsing result
	if( (part=new MrMimePart())==NULL ) {
		goto Parse_Cleanup;
	}
	part->m_type = MR_MSG_TEXT;
	part->m_txt  = save_strdup((char*)body);
	carray_add(m_parts, (void*)part, NULL);

	// Cleanup
Parse_Cleanup:
	if( carray_count(m_parts)==0 ) {
		if( (part=new MrMimePart())!=NULL ) {
			part->m_type = MR_MSG_TEXT;
			part->m_txt  = save_strdup((char*)(subject? subject : "Empty message"));
			carray_add(m_parts, (void*)part, NULL);
		}
	}

	if( mime ) {
		mailmime_free(mime);
		mime = NULL;
	}

	return m_parts;
}
