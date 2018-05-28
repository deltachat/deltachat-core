/*******************************************************************************
 *
 *                              Delta Chat Core
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
 ******************************************************************************/


#include <ctype.h>
#include <libetpan/libetpan.h>
#include "mrmailbox_internal.h"
#include "mrstrencode.h"


/*******************************************************************************
 * URL encoding and decoding, RFC 3986
 ******************************************************************************/


static char int_2_uppercase_hex(char code)
{
	static const char hex[] = "0123456789ABCDEF";
	return hex[code & 15];
}


static char hex_2_int(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}


/**
 * Url-encodes a string.
 * All characters but A-Z, a-z, 0-9 and -_. are encoded by a percent sign followed by two hexadecimal digits.
 *
 * The space in encoded as `+` - this is correct for parts in the url _after_ the `?` and saves some bytes when used in QR codes.
 * (in the URL _before_ the `?` or elsewhere, the space should be encoded as `%20`)
 *
 * Belongs to RFC 3986: https://tools.ietf.org/html/rfc3986#section-2
 *
 * Example: The string `Björn Petersen` will be encoded as `"Bj%C3%B6rn+Petersen`.
 *
 * @param to_encode Null-terminated UTF-8 string to encode.
 *
 * @return Returns a null-terminated url-encoded strings. The result must be free()'d when no longer needed.
 *     On memory allocation errors the program halts.
 *     On other errors, an empty string is returned.
 */
char* mr_urlencode(const char *to_encode)
{
	const char *pstr = to_encode;

	if( to_encode == NULL ) {
		return safe_strdup("");
	}

	char *buf = malloc(strlen(to_encode) * 3 + 1), *pbuf = buf;
	if( buf == NULL ) {
		exit(46);
	}

	while (*pstr)
	{
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
			*pbuf++ = *pstr;
		}
		else if (*pstr == ' ') {
			*pbuf++ = '+';
		}
		else {
			*pbuf++ = '%', *pbuf++ = int_2_uppercase_hex(*pstr >> 4), *pbuf++ = int_2_uppercase_hex(*pstr & 15);
		}

		pstr++;
	}

	*pbuf = '\0';

	return buf;
}


/**
 * Returns a url-decoded version of the given string.
 * The string may be encoded eg. by mr_urlencode().
 * Belongs to RFC 3986: https://tools.ietf.org/html/rfc3986#section-2
 *
 * @param to_decode Null-terminated string to decode.
 *
 * @return The function returns a null-terminated UTF-8 string.
 *     The return value must be free() when no longer used.
 *     On memory allocation errors the program halts.
 *     On other errors, an empty string is returned.
 */
char* mr_urldecode(const char* to_decode)
{
	const char *pstr = to_decode;

	if( to_decode == NULL ) {
		return safe_strdup("");
	}

	char *buf = malloc(strlen(to_decode) + 1), *pbuf = buf;
	if( buf == NULL ) {
		exit(50);
	}

	while (*pstr)
	{
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pbuf++ = hex_2_int(pstr[1]) << 4 | hex_2_int(pstr[2]);
				pstr += 2;
			}
		}
		else if (*pstr == '+') {
			*pbuf++ = ' ';
		}
		else {
			*pbuf++ = *pstr;
		}

		pstr++;
	}

	*pbuf = '\0';

	return buf;
}


/*******************************************************************************
 * Encode header words, RFC 2047
 ******************************************************************************/


#define DEF_INCOMING_CHARSET "iso-8859-1"
#define DEF_DISPLAY_CHARSET  "utf-8"
#define MAX_IMF_LINE         666 /* see comment below */


static int to_be_quoted(const char * word, size_t size)
{
	const char* cur = word;
	size_t      i;

	for( i = 0; i < size; i++ )
	{
		switch( *cur )
		{
			case ',':
			case ':':
			case '!':
			case '"':
			case '#':
			case '$':
			case '@':
			case '[':
			case '\\':
			case ']':
			case '^':
			case '`':
			case '{':
			case '|':
			case '}':
			case '~':
			case '=':
			case '?':
			case '_':
				return 1;

			default:
				if( ((unsigned char)*cur) >= 128 ) {
					return 1;
				}
				break;
		}

		cur++;
	}

	return 0;
}


static int quote_word(const char* display_charset, MMAPString* mmapstr, const char* word, size_t size)
{
	const char * cur;
	size_t i;
	char hex[4];
	int col;

	if (mmap_string_append(mmapstr, "=?") == NULL) {
		return 0;
	}

	if (mmap_string_append(mmapstr, display_charset) == NULL) {
		return 0;
	}

	if (mmap_string_append(mmapstr, "?Q?") == NULL) {
		return 0;
	}

	col = mmapstr->len;

	cur = word;
	for(i = 0 ; i < size ; i ++)
	{
		int do_quote_char;

		#if MAX_IMF_LINE != 666
		if (col + 2 /* size of "?=" */
			+ 3 /* max size of newly added character */
			+ 1 /* minimum column of string in a
				   folded header */ >= MAX_IMF_LINE)
		{
			/* adds a concatened encoded word */
			int old_pos;

			if (mmap_string_append(mmapstr, "?=") == NULL) {
				return 0;
			}

			if (mmap_string_append(mmapstr, " ") == NULL) {
				return 0;
			}

			old_pos = mmapstr->len;

			if (mmap_string_append(mmapstr, "=?") == NULL) {
				return 0;
			}

			if (mmap_string_append(mmapstr, display_charset) == NULL) {
				return 0;
			}

			if (mmap_string_append(mmapstr, "?Q?") == NULL) {
				return 0;
			}

			col = mmapstr->len - old_pos;
		}
		#endif

		do_quote_char = 0;
		switch( *cur )
		{
			case ',':
			case ':':
			case '!':
			case '"':
			case '#':
			case '$':
			case '@':
			case '[':
			case '\\':
			case ']':
			case '^':
			case '`':
			case '{':
			case '|':
			case '}':
			case '~':
			case '=':
			case '?':
			case '_':
				do_quote_char = 1;
				break;

			default:
				if (((unsigned char) * cur) >= 128) {
					do_quote_char = 1;
				}
				break;
		}

		if (do_quote_char)
		{
			snprintf(hex, 4, "=%2.2X", (unsigned char) * cur);
			if (mmap_string_append(mmapstr, hex) == NULL) {
				return 0;
			}
			col += 3;
		}
		else
		{
			if (* cur == ' ') {
				if (mmap_string_append_c(mmapstr, '_') == NULL) {
					return 0;
				}
			}
			else {
				if (mmap_string_append_c(mmapstr, * cur) == NULL) {
					return 0;
				}
			}
			col += 3;
		}

		cur++;
	}

	if (mmap_string_append(mmapstr, "?=") == NULL) {
		return 0;
	}

	return 1;
}


static void get_word(const char* begin, const char** pend, int* pto_be_quoted)
{
	const char* cur = begin;

	while ((* cur != ' ') && (* cur != '\t') && (* cur != '\0')) {
		cur ++;
	}

	#if MAX_IMF_LINE != 666
	if (cur - begin +
      1  /* minimum column of string in a
            folded header */ > MAX_IMF_LINE)
		*pto_be_quoted = 1;
	else
	#endif
		*pto_be_quoted = to_be_quoted(begin, cur - begin);

	*pend = cur;
}


/**
 * Encode non-ascii-strings as `=?UTF-8?Q?Bj=c3=b6rn_Petersen?=`.
 * Belongs to RFC 2047: https://tools.ietf.org/html/rfc2047
 *
 * We do not fold at position 72; this would result in empty words as `=?utf-8?Q??=` which are correct,
 * but cannot be displayed by some mail programs (eg. Android Stock Mail).
 * however, this is not needed, as long as _one_ word is not longer than 72 characters.
 * _if_ it is, the display may get weired.  This affects the subject only.
 * the best solution wor all this would be if libetpan encodes the line as only libetpan knowns when a header line is full.
 *
 * @param to_encode Null-terminated UTF-8-string to encode.
 *
 * @return Returns the encoded string which must be free()'d when no longed needed.
 *     On errors, NULL is returned.
 */
char* mr_encode_header_words(const char* to_encode)
{
	char*       ret_str = NULL;
	const char* cur = to_encode;
	MMAPString* mmapstr = mmap_string_new("");

	if( to_encode == NULL || mmapstr == NULL ) {
		goto cleanup;
	}

	while (* cur != '\0')
	{
		const char * begin;
		const char * end;
		int do_quote;
		int quote_words;

		begin = cur;
		end = begin;
		quote_words = 0;
		do_quote = 1;

		while (* cur != '\0')
		{
			get_word(cur, &cur, &do_quote);
			if (do_quote) {
				quote_words = 1;
				end = cur;
			}
			else {
				break;
			}

			if (* cur != '\0') {
				cur ++;
			}
		}

		if (quote_words)
		{
			if ( !quote_word(DEF_DISPLAY_CHARSET, mmapstr, begin, end - begin) ) {
				goto cleanup;
			}

			if ((* end == ' ') || (* end == '\t')) {
				if (mmap_string_append_c(mmapstr, * end) == 0) {
					goto cleanup;
				}
				end ++;
			}

			if (* end != '\0') {
				if (mmap_string_append_len(mmapstr, end, cur - end) == NULL) {
					goto cleanup;
				}
			}
		}
		else
		{
			if (mmap_string_append_len(mmapstr, begin, cur - begin) == NULL) {
				goto cleanup;
			}
		}

		if ((* cur == ' ') || (* cur == '\t')) {
			if (mmap_string_append_c(mmapstr, * cur) == 0) {
				goto cleanup;
			}
			cur ++;
		}
	}

	ret_str = strdup(mmapstr->str);

cleanup:
	if( mmapstr ) {
		mmap_string_free(mmapstr);
	}
	return ret_str;
}



/*******************************************************************************
 * Decode header words, RFC 2047
 ******************************************************************************/


/**
 * Decode non-ascii-strings as `=?UTF-8?Q?Bj=c3=b6rn_Petersen?=`.
 * Belongs to RFC 2047: https://tools.ietf.org/html/rfc2047
 *
 * @param to_encode String to decode.
 *
 * @return Returns the null-terminated decoded string as UTF-8. Must be free()'d when no longed needed.
 *     On errors, NULL is returned.
 */
char* mr_decode_header_words(const char* in)
{
	/* decode strings as. `=?UTF-8?Q?Bj=c3=b6rn_Petersen?=`)
	if `in` is NULL, `out` is NULL as well; also returns NULL on errors */

	if( in == NULL ) {
		return NULL; /* no string given */
	}

	char* out = NULL;
	size_t cur_token = 0;
	int r = mailmime_encoded_phrase_parse(DEF_INCOMING_CHARSET, in, strlen(in), &cur_token, DEF_DISPLAY_CHARSET, &out);
	if( r != MAILIMF_NO_ERROR || out == NULL ) {
		out = safe_strdup(in); /* error, make a copy of the original string (as we free it later) */
	}

	return out; /* must be free()'d by the caller */
}


/*******************************************************************************
 * Encode international header, RFC 2231, RFC 5987
 ******************************************************************************/


char* mr_encode_ext_header(const char* to_encode)
{
	#define PREFIX "utf-8''"
	const char *pstr = to_encode;

	if( to_encode == NULL ) {
		return safe_strdup("");
	}

	char *buf = malloc(strlen(PREFIX) + strlen(to_encode) * 3 + 1);
	if( buf == NULL ) {
		exit(46);
	}

	char* pbuf = buf;
	strcpy(pbuf, PREFIX);
	pbuf += strlen(pbuf);

	while (*pstr)
	{
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
			*pbuf++ = *pstr;
		}
		else {
			*pbuf++ = '%', *pbuf++ = int_2_uppercase_hex(*pstr >> 4), *pbuf++ = int_2_uppercase_hex(*pstr & 15);
		}

		pstr++;
	}

	*pbuf = '\0';

	return buf;
}
