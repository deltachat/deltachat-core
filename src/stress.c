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
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <gcrypt.h>
#include "mrmailbox.h"
#include "mrsimplify.h"
#include "mrtools.h"


static void generate_key(mrmailbox_t* mailbox)
{
	gcry_error_t err      = GPG_ERR_NO_ERROR;
	gcry_sexp_t  key_spec = NULL;
	gcry_sexp_t  key_pair = NULL;

	err = gcry_sexp_build(&key_spec, NULL, "(genkey (rsa (nbits 4:2048)))");
	if( err ) {
		return;
	}

	err = gcry_pk_genkey(&key_pair, key_spec);
	if( err ) {
		return;
    }

	gcry_sexp_t pub_key = gcry_sexp_find_token(key_pair, "public-key", 0);
	if( !pub_key ) {
		return;
	}

	gcry_sexp_t prv_key = gcry_sexp_find_token (key_pair, "private-key", 0);
	if( !prv_key ) {
		return;
	}

    {
		size_t key_pair_buffer_size = gcry_sexp_sprint(key_pair, GCRYSEXP_FMT_ADVANCED, NULL, 0);
		char* key_pair_buffer = gcry_xmalloc (key_pair_buffer_size);

		gcry_sexp_sprint (key_pair, GCRYSEXP_FMT_ADVANCED, key_pair_buffer, key_pair_buffer_size);

		printf ("%.*s", (int)key_pair_buffer_size, key_pair_buffer);
		gcry_free (key_pair_buffer);
	}

	gcry_sexp_release(pub_key);
	gcry_sexp_release(prv_key);
	gcry_sexp_release(key_pair);
	gcry_sexp_release(key_spec);
}


void stress_functions(mrmailbox_t* mailbox)
{
	/* test end-to-end-encryption (mre2ee_init() is called on mailbox creation)
	 **************************************************************************/

	{
		generate_key(mailbox);
	}


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
}
