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
 * $ valgrind --leak-check=full --tool=memcheck ./messenger-backend <db>
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mrmailbox.h"
#include "mrsimplify.h"
#include "mrtools.h"


void stress_functions(void)
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
}
