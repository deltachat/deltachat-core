/*******************************************************************************
 *
 *                             Messenger Backend
 *                      Copyright (C) 2017 Björn Petersen
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
 * File:    stress.c
 * Purpose: Stress some functions for testing; if used as a lib, this file is
 *          obsolete.
 *
 *******************************************************************************
 *
 * For memory checking, use eg.
 * $ valgrind --leak-check=full --tool=memcheck ./deltachat-core <db>
 *
 ******************************************************************************/


#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "mrmailbox.h"
#include "mrsimplify.h"
#include "mrapeerstate.h"
#include "mraheader.h"
#include "mrtools.h"


void stress_functions(mrmailbox_t* mailbox)
{
	/* test mrsimplify and mrsaxparser (indirectly used by mrsimplify)
	 **************************************************************************/

	{
		mrsimplify_t* simplify = mrsimplify_new();

		const char* html = "\r\r\nline1<br>\r\n\r\n\r\rline2\n\r"; /* check, that `<br>\ntext` does not result in `\n text` */
		char* plain = mrsimplify_simplify(simplify, html, strlen(html), 1);
		assert( strcmp(plain, "line1\nline2")==0 );
		free(plain);

		html = "<a href=url>text</a"; /* check unquoted attribute and unclosed end-tag */
		plain = mrsimplify_simplify(simplify, html, strlen(html), 1);
		assert( strcmp(plain, "[text](url)")==0 );
		free(plain);

		html = "<!DOCTYPE name [<!DOCTYPE ...>]><!-- comment -->text <b><?php echo ... ?>bold</b><![CDATA[<>]]>";
		plain = mrsimplify_simplify(simplify, html, strlen(html), 1);
		assert( strcmp(plain, "text *bold*<>")==0 );
		free(plain);

		mrsimplify_unref(simplify);
	}

	/* test some string functions
	 **************************************************************************/

	{
		char* str = strdup("aaa");
		int replacements = mr_str_replace(&str, "a", "ab"); /* no endless recursion here! */
		assert( strcmp(str, "ababab")==0 );
		assert( replacements == 3 );
		free(str);
	}

	/* test Autocrypt header parsing functions
	 **************************************************************************/

	{
		mraheader_t* ah = mraheader_new();
		int          ah_ok;

		ah_ok = mraheader_set_from_string(ah, "to=a@b.example.org; type=p; prefer-encrypted=yes; key=RGVsdGEgQ2hhdA==");
		assert( ah_ok == 1 );
		assert( ah->m_to && strcmp(ah->m_to, "a@b.example.org")==0 );
		assert( ah->m_public_key.m_bytes==10 && strncmp((char*)ah->m_public_key.m_binary, "Delta Chat", 10)==0 );
		assert( ah->m_prefer_encrypted==MRA_PE_YES );

		ah_ok = mraheader_set_from_string(ah, " _foo; __FOO=BAR ;;; to = a@b.example.org ;\n\r type = p ; prefer-encrypted = yes ; key = RG VsdGEgQ\n\r2hhdA==");
		assert( ah_ok == 1 );
		assert( ah->m_to && strcmp(ah->m_to, "a@b.example.org")==0 );
		assert( ah->m_public_key.m_bytes==10 && strncmp((char*)ah->m_public_key.m_binary, "Delta Chat", 10)==0 );
		assert( ah->m_prefer_encrypted==MRA_PE_YES );

		ah_ok = mraheader_set_from_string(ah, "");
		assert( ah_ok == 0 );

		ah_ok = mraheader_set_from_string(ah, ";");
		assert( ah_ok == 0 );

		ah_ok = mraheader_set_from_string(ah, "foo");
		assert( ah_ok == 0 );

		ah_ok = mraheader_set_from_string(ah, "\n\n\n");
		assert( ah_ok == 0 );

		ah_ok = mraheader_set_from_string(ah, " ;;");
		assert( ah_ok == 0 );

		ah_ok = mraheader_set_from_string(ah, "to=a@t.de; unknwon=1; key=jau"); /* unknwon non-underscore attributes result in invalid headers */
		assert( ah_ok == 0 );

		mraheader_unref(ah);
	}
}
