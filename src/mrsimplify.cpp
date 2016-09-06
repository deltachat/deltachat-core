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


bool MrSimplify::IsEmpty(const char* buf)
{
	const unsigned char* p1 = (const unsigned char*)buf; // force unsigned - otherwise the `> ' '` comparison will fail
	while( *p1 ) {
		if( *p1 > ' ' ) {
			return false; // at least one character found - buffer is not empty
		}
		p1++;
	}
	return true; // buffer is empty or contains only spaces, tabs, lineends etc.
}


bool MrSimplify::IsPlainQuote(const char* buf)
{
	if( buf[0] == '>' ) {
		return true;
	}
	return false;
}


bool MrSimplify::IsQuoteHeadline(const char* buf)
{
	// This function may be called for the line _directly_ before a quote.
	// The function checks if the line contains sth. like "On 01.02.2016, xy@z wrote:" in various languages.
	// Currently, we simply check if the last character is a ':'.
	// (we could also check for the existance of several digits or for the existance of `@` (however, the may be headlines not mentioning the address)

	int buf_len = strlen(buf);
	if( buf_len > 0 && buf[buf_len-1] == ':' ) {
		return true; // the buffer is a quoting headline in the meaning described above)
	}

	return false;
}


char* MrSimplify::Simplify(const char* in_unterminated, int in_bytes, int mimetype /*eg. MR_MIMETYPE_TEXT_HTML*/)
{
	// create a copy of the given buffer
	char* out = NULL;

	if( in_unterminated == NULL || in_bytes <= 0 ) {
		return safe_strdup(""); // error
	}

	out = strndup((char*)in_unterminated, in_bytes); // strndup() makes sure, the string is null-terminated
	if( out == NULL ) {
		return safe_strdup(""); // error
	}

	// simplify the text in the buffer (characters to removed may be marked by `\r`)
	if( mimetype == MR_MIMETYPE_TEXT_HTML ) {
		SimplifyHtml(out);
	}
	else {
		mr_remove_cr_chars(out); // make comparisons easier, eg. for line `-- `
		SimplifyPlainText(out);
	}

	// remove all `\r` from string
	mr_remove_cr_chars(out);

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
	int l, l_first = 0, l_last = carray_count(lines)-1; // if l_last is -1, there are no lines
	char* line;
	for( l = l_first; l <= l_last; l++ )
	{
		line = (char*)carray_get(lines, l);
		if( strcmp(line, "-- ")==0 )
		{
			l_last = l - 1; // if l_last is -1, there are no lines
			break; // done
		}
	}

	// remove full quotes at the end of the text
	{
		int l_lastQuotedLine = -1;

		for( l = l_last; l >= l_first; l-- ) {
			line = (char*)carray_get(lines, l);
			if( IsPlainQuote(line) ) {
				l_lastQuotedLine = l;
			}
			else if( !IsEmpty(line) ) {
				break;
			}
		}

		if( l_lastQuotedLine != -1 )
		{
			l_last = l_lastQuotedLine-1; // if l_last is -1, there are no lines
			if( l_last > 0 ) {
				line = (char*)carray_get(lines, l_last);
				if( IsQuoteHeadline(line) ) {
					l_last--;
				}
			}
		}
	}

	// remove full quotes at the beginning of the text
	{
		int l_lastQuotedLine = -1;
		bool hasQuotedHeadline = false;

		for( l = l_first; l <= l_last; l++ ) {
			line = (char*)carray_get(lines, l);
			if( IsPlainQuote(line) ) {
				l_lastQuotedLine = l;
			}
			else if( !IsEmpty(line) ) {
				if( IsQuoteHeadline(line) && !hasQuotedHeadline && l_lastQuotedLine == -1 ) {
					hasQuotedHeadline = true; // continue, the line may be a headline
				}
				else {
					break; // non-quoting line found
				}
			}
		}

		if( l_lastQuotedLine != -1 )
		{
			l_first = l_lastQuotedLine + 1;
		}
	}

	// re-create buffer from the remaining lines
	char* p1 = buf_terminated;
	*p1 = 0; // make sure, the string is terminated if there are no lines (l_last==-1)

	int add_nl = 0; // we write empty lines only in case and non-empty line follows

	for( l = l_first; l <= l_last; l++ )
	{
		line = (char*)carray_get(lines, l);

		if( IsEmpty(line) )
		{
			add_nl++;
		}
		else
		{
			if( p1 != buf_terminated ) // flush empty lines - except if we're at the start of the buffer
			{
				if( add_nl > 2 ) { add_nl = 2; } // ignore more than one empty line (however, regard normal line ends)
				while( add_nl ) {
					*p1 = '\n';
					p1++;
					add_nl--;
				}
			}

			size_t line_len = strlen(line);

			strcpy(p1, line);

			p1 = &p1[line_len]; // points to the current terminating nullcharacters which is overwritten with the next line
			add_nl = 1;
		}
	}

	FreeSplittedLines(lines);
}

