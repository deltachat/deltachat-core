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
 * File:    mrsimplify.cpp
 * Authors: Björn Petersen
 * Purpose: Simplify text, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrsimplify.h"
#include "mrtools.h"
#include "mrmimeparser.h"


MrSimplify::MrSimplify()
{
}


MrSimplify::~MrSimplify()
{
}


carray* MrSimplify::SplitIntoLines(const char* buf_terminated)
{
	carray* lines = carray_new(1024);

	size_t line_chars = 0;
	const char* p1 = buf_terminated;
	const char* line_start = p1;
	unsigned int l_indx;
	while( *p1 ) {
		if( *p1  == '\n' ) {
			carray_add(lines, (void*)strndup(line_start, line_chars), &l_indx);
			p1++;
			line_start = p1;
			line_chars = 0;
		}
		else {
			p1++;
			line_chars++;
		}
	}
	carray_add(lines, (void*)strndup(line_start, line_chars), &l_indx);

	return lines; // should be freed using FreeSplittedLines()
}


void MrSimplify::FreeSplittedLines(carray* lines)
{
	int cnt = carray_count(lines);
	for( int i = 0; i < cnt; i++ )
	{
		free(carray_get(lines, i));
	}
	carray_free(lines);
}


void MrSimplify::RemoveCrChars(char* buf)
{
	// remove all carriage return characters (`\r`) from the null-terminated buffer;
	// the buffer itself is modified for this purpose

	const char* p1 = buf; // search for first `\r`
	while( *p1 ) {
		if( *p1 == '\r' ) {
			break;
		}
		p1++;
	}

	char* p2 = (char*)p1; // p1 is `\r` or null-byte; start removing `\r`
	while( *p1 ) {
		if( *p1 != '\r' ) {
			*p2 = *p1;
			p2++;
		}
		p1++;
	}

	// add trailing null-byte
	*p2 = 0;
}


char* MrSimplify::Simplify(const char* in_unterminated, int in_bytes, int mimetype /*eg. MR_MIMETYPE_TEXT_HTML*/)
{
	// create a copy of the given buffer
	char* out = NULL;

	if( in_unterminated == NULL || in_bytes <= 0 ) {
		return strdup(""); // error
	}

	out = strndup((char*)in_unterminated, in_bytes); // strndup() makes sure, the string is null-terminated
	if( out == NULL ) {
		return strdup(""); // error
	}

	// simplify the text in the buffer (characters to removed may be marked by `\r`)
	if( mimetype == MR_MIMETYPE_TEXT_HTML ) {
		SimplifyHtml(out);
	}
	else {
		RemoveCrChars(out); // make comparisons easier, eg. for line `-- `
		SimplifyPlainText(out);
	}

	// remove all `\r` from string
	RemoveCrChars(out);

	// done
	return out;
}


/*******************************************************************************
 * Simplify HTML
 ******************************************************************************/


void MrSimplify::SimplifyHtml(char* buf_terminated)
{
}


/*******************************************************************************
 * Simplify Plain Text
 ******************************************************************************/


void MrSimplify::SimplifyPlainText(char* buf_terminated)
{
	// This function ...
	// ... removes all text after the line `-- ` (footer mark)
	// ... removes full quotes at the beginning and at the end of the text -
	//     these are all lines starting with the character `>`
	// ... remove a non-empty line before the removed quote (contains sth. like "On 2.9.2016, Bjoern wrote:" in different formats and lanugages)


	// split the given buffer into lines
	carray* lines = SplitIntoLines(buf_terminated);

	// search for the line `-- ` and ignore this and all following lines
	unsigned int l_indx, l_cnt = carray_count(lines);
	for( l_indx = 0; l_indx < l_cnt; l_indx++ )
	{
		char* line = (char*)carray_get(lines, l_indx);
		if( strcmp(line, "-- ")==0 )
		{
			l_cnt = l_indx;
			break; // done
		}
	}

	// re-create buffer from lines
	char* p1 = buf_terminated;
	for( l_indx = 0; l_indx < l_cnt; l_indx++ )
	{
		char* line = (char*)carray_get(lines, l_indx);
		size_t line_len = strlen(line);

		strcpy(p1, line);

		if( l_indx!=l_cnt-1 ) {
			p1[line_len] = '\n';
			line_len++;
		}

		p1[line_len] = 0;
		p1 = &p1[line_len]; // points to the current terminating nullcharacters which is overwritten with the next line
	}

	FreeSplittedLines(lines);
}

