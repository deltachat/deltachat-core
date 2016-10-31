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
 * File:    mrtools.c
 * Authors: Björn Petersen
 * Purpose: Some tools, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <libetpan/libetpan.h>
#include "mrtools.h"


/*******************************************************************************
 * String tools
 ******************************************************************************/


char* safe_strdup(const char* s) /* strdup(NULL) is undefined, save_strdup(NULL) returns an empty string in this case */
{
	char* ret;
	if( s ) {
		if( (ret=strdup(s)) == NULL ) {
			exit(16); /* cannot allocate (little) memory, unrecoverable error */
		}
	}
	else {
		if( (ret=(char*)calloc(1, 1)) == NULL ) {
			exit(17); /* cannot allocate little memory, unrecoverable error */
		}
	}
	return ret;
}


void mr_ltrim(char* buf)
{
	size_t len;
	const unsigned char* cur;

	if( buf && *buf ) {
		len = strlen(buf);
		cur = (const unsigned char*)buf;

		while( *cur && isspace(*cur) ) {
			cur++; len--;
		}

		if( (const unsigned char*)buf != cur ) {
			memmove(buf, cur, len + 1);
		}
	}
}


void mr_rtrim(char* buf)
{
	size_t len;
	unsigned char* cur;

	if( buf && *buf ) {
		len = strlen(buf);
		cur = (unsigned char*)buf + len - 1;

		while( cur != (unsigned char*)buf && isspace(*cur) ) {
			--cur, --len;
		}

		cur[isspace(*cur) ? 0 : 1] = '\0';
	}
}


void mr_trim(char* buf)
{
	mr_ltrim(buf);
	mr_rtrim(buf);
}


char* mr_strlower(const char* in) /* the result must be free()'d */
{
	char* out = safe_strdup(in);
	if( out == NULL ) {
		return NULL;
	}

	char* p = out;
	for ( ; *p; p++) {
		*p = tolower(*p);
	}

	return out;
}


char* mr_mprintf(const char* format, ...)
{
	char *sqlite_str, *c_string;

	va_list argp;
	va_start(argp, format); /* expects the last non-variable argument as the second parameter */
		sqlite_str = sqlite3_vmprintf(format, argp);
	va_end(argp);

	if( sqlite_str == NULL ) {
		return safe_strdup("ErrFmt"); /* error - the result must be free()'d */
	}

	/* as sqlite-strings must be freed using sqlite3_free() instead of a simple free(), convert it to a normal c-string */
	c_string = safe_strdup(sqlite_str); /* exists on errors */
	sqlite3_free(sqlite_str);
	return c_string; /* success - the result must be free()'d */
}


void mr_remove_cr_chars(char* buf)
{
	/* remove all carriage return characters (`\r`) from the null-terminated buffer;
	the buffer itself is modified for this purpose */

	const char* p1 = buf; /* search for first `\r` */
	while( *p1 ) {
		if( *p1 == '\r' ) {
			break;
		}
		p1++;
	}

	char* p2 = (char*)p1; /* p1 is `\r` or null-byte; start removing `\r` */
	while( *p1 ) {
		if( *p1 != '\r' ) {
			*p2 = *p1;
			p2++;
		}
		p1++;
	}

	/* add trailing null-byte */
	*p2 = 0;
}


void mr_unwrap_str(char* buf, int approx_bytes)
{
	/* Function unwraps the given string and removes unnecessary whitespace.
	Function stops processing after approx_bytes are processed.
	(as we're using UTF-8, this is not always the lenght! Moreover, we cannot split the string at any place for the same reason).
	*/

	int lastIsCharacter = 0;
	unsigned char* p1 = (unsigned char*)buf; /* force unsigned - otherwise the `> ' '` comparison will fail */
	while( *p1 ) {
		if( *p1 > ' ' ) {
			lastIsCharacter = 1;
		}
		else {
			if( lastIsCharacter ) {
				if( ((uintptr_t)p1 - (uintptr_t)buf) > (uintptr_t)approx_bytes ) {
					*p1 = 0; /* approx_len approximately reached (take care when wraping at non-spaces - we're using UTF-8 characters)*/
					break;
				}
				lastIsCharacter = 0;
				*p1 = ' ';
			}
			else {
				*p1 = '\r'; /* removed below */
			}
		}

		p1++;
	}

	mr_remove_cr_chars(buf);
}


carray* mr_split_into_lines(const char* buf_terminated)
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

	return lines; /* should be freed using mr_free_splitted_lines() */
}


void mr_free_splitted_lines(carray* lines)
{
	if( lines ) {
		int i, cnt = carray_count(lines);
		for( i = 0; i < cnt; i++ ) {
			free(carray_get(lines, i));
		}
		carray_free(lines);
	}
}


char* mr_decode_header_string(const char* in)
{
	/* decode strings as. `=?UTF-8?Q?Bj=c3=b6rn_Petersen?=`)
	if `in` is NULL, `out` is NULL as well; also returns NULL on errors */

	if( in == NULL ) {
		return NULL; /* no string given */
	}

	#define DEF_INCOMING_CHARSET "iso-8859-1"
	#define DEF_DISPLAY_CHARSET "utf-8"
	char* out = NULL;
	size_t cur_token = 0;
	int r = mailmime_encoded_phrase_parse(DEF_INCOMING_CHARSET, in, strlen(in), &cur_token, DEF_DISPLAY_CHARSET, &out);
	if( r != MAILIMF_NO_ERROR || out == NULL ) {
		out = safe_strdup(in); /* error, make a copy of the original string (as we free it later) */
	}

	return out; /* must be free()'d by the caller */
}


/* ===================================================================
 * UTF-7 conversion routines as in RFC 2192
 * ===================================================================
 * These two functions from:
 * libimap library.
 * Copyright (C) 2003-2004 Pawel Salek. */

/* UTF7 modified base64 alphabet */
static char base64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
#define UNDEFINED 64

/* UTF16 definitions */
#define UTF16MASK       0x03FFUL
#define UTF16SHIFT      10
#define UTF16BASE       0x10000UL
#define UTF16HIGHSTART  0xD800UL
#define UTF16HIGHEND    0xDBFFUL
#define UTF16LOSTART    0xDC00UL
#define UTF16LOEND      0xDFFFUL


 /* Convert an IMAP mailbox to a UTF-8 string.
 *  dst needs to have roughly 4 times the storage space of src
 *    Hex encoding can triple the size of the input
 *    UTF-7 can be slightly denser than UTF-8
 *     (worst case: 8 octets UTF-7 becomes 9 octets UTF-8)
 */
char* imap_modified_utf7_to_utf8(const char *mbox, int change_spaces)
{
  unsigned c, i, bitcount;
  unsigned long ucs4, utf16, bitbuf;
  unsigned char base64[256];
  const char *src;
  char *dst, *res  = (char*)malloc(2*strlen(mbox)+1);

  dst = res;
  src = mbox;
  if(!dst) return NULL;
  /* initialize modified base64 decoding table */
  memset(base64, UNDEFINED, sizeof (base64));
  for (i = 0; i < sizeof (base64chars); ++i) {
    base64[(unsigned)base64chars[i]] = i;
  }

  /* loop until end of string */
  while (*src != '\0') {
    c = *src++;
    /* deal with literal characters and &- */
    if (c != '&' || *src == '-') {
      /* encode literally */
      if (change_spaces && c == '_')
	*dst++ = ' ';
      else
        *dst++ = c;
      /* skip over the '-' if this is an &- sequence */
      if (c == '&') ++src;
    } else {
      /* convert modified UTF-7 -> UTF-16 -> UCS-4 -> UTF-8 -> HEX */
      bitbuf = 0;
      bitcount = 0;
      ucs4 = 0;
      while ((c = base64[(unsigned char) *src]) != UNDEFINED) {
        ++src;
        bitbuf = (bitbuf << 6) | c;
        bitcount += 6;
        /* enough bits for a UTF-16 character? */
        if (bitcount >= 16) {
          bitcount -= 16;
          utf16 = (bitcount ? bitbuf >> bitcount
                   : bitbuf) & 0xffff;
          /* convert UTF16 to UCS4 */
          if
            (utf16 >= UTF16HIGHSTART && utf16 <= UTF16HIGHEND) {
            ucs4 = (utf16 - UTF16HIGHSTART) << UTF16SHIFT;
            continue;
          } else if
            (utf16 >= UTF16LOSTART && utf16 <= UTF16LOEND) {
            ucs4 += utf16 - UTF16LOSTART + UTF16BASE;
          } else {
            ucs4 = utf16;
          }

          /* convert UTF-16 range of UCS4 to UTF-8 */
          if (ucs4 <= 0x7fUL) {
            dst[0] = ucs4;
            dst += 1;
          } else if (ucs4 <= 0x7ffUL) {
            dst[0] = 0xc0 | (ucs4 >> 6);
            dst[1] = 0x80 | (ucs4 & 0x3f);
            dst += 2;
          } else if (ucs4 <= 0xffffUL) {
            dst[0] = 0xe0 | (ucs4 >> 12);
            dst[1] = 0x80 | ((ucs4 >> 6) & 0x3f);
            dst[2] = 0x80 | (ucs4 & 0x3f);
            dst += 3;
          } else {
            dst[0] = 0xf0 | (ucs4 >> 18);
            dst[1] = 0x80 | ((ucs4 >> 12) & 0x3f);
            dst[2] = 0x80 | ((ucs4 >> 6) & 0x3f);
            dst[3] = 0x80 | (ucs4 & 0x3f);
            dst += 4;
          }
        }
      }
      /* skip over trailing '-' in modified UTF-7 encoding */
      if (*src == '-') ++src;
    }
  }
  /* terminate destination string */
  *dst = '\0';
  return res;
}

/* Convert hex coded UTF-8 string to modified UTF-7 IMAP mailbox
 *  dst should be about twice the length of src to deal with non-hex
 *  coded URLs
 */
char* imap_utf8_to_modified_utf7(const char *src, int change_spaces)
{
  unsigned int utf8pos, utf8total, c, utf7mode, bitstogo, utf16flag;
  unsigned long ucs4 = 0, bitbuf = 0;

  /* initialize hex lookup table */
  char *dst, *res;

  if (!src) return NULL;

  res = (char*)malloc(2*strlen(src)+1);
  dst = res;
  if(!dst) return NULL;

  utf7mode = 0;
  utf8total = 0;
  bitstogo = 0;
  utf8pos = 0;
  while ((c = (unsigned char)*src) != '\0') {
    ++src;
    /* normal character? */
    if (c >= ' ' && c <= '~' && (c != '_' || !change_spaces)) {
      /* switch out of UTF-7 mode */
      if (utf7mode) {
        if (bitstogo) {
          *dst++ = base64chars[(bitbuf << (6 - bitstogo)) & 0x3F];
        }
        *dst++ = '-';
        utf7mode = 0;
        utf8pos  = 0;
        bitstogo = 0;
        utf8total= 0;
      }
      if (change_spaces && c == ' ')
        *dst++ = '_';
      else
	*dst++ = c;
      /* encode '&' as '&-' */
      if (c == '&') {
        *dst++ = '-';
      }
      continue;
    }
    /* switch to UTF-7 mode */
    if (!utf7mode) {
      *dst++ = '&';
      utf7mode = 1;
    }
    /* Encode US-ASCII characters as themselves */
    if (c < 0x80) {
      ucs4 = c;
    } else if (utf8total) {
      /* save UTF8 bits into UCS4 */
      ucs4 = (ucs4 << 6) | (c & 0x3FUL);
      if (++utf8pos < utf8total) {
        continue;
      }
    } else {
      utf8pos = 1;
      if (c < 0xE0) {
        utf8total = 2;
        ucs4 = c & 0x1F;
      } else if (c < 0xF0) {
        utf8total = 3;
        ucs4 = c & 0x0F;
      } else {
        /* NOTE: can't convert UTF8 sequences longer than 4 */
        utf8total = 4;
        ucs4 = c & 0x03;
      }
      continue;
    }
    /* loop to split ucs4 into two utf16 chars if necessary */
    utf8total = 0;
    do {
      if (ucs4 >= UTF16BASE) {
        ucs4 -= UTF16BASE;
        bitbuf = (bitbuf << 16) | ((ucs4 >> UTF16SHIFT)
                                   + UTF16HIGHSTART);
        ucs4 = (ucs4 & UTF16MASK) + UTF16LOSTART;
        utf16flag = 1;
      } else {
        bitbuf = (bitbuf << 16) | ucs4;
        utf16flag = 0;
      }
      bitstogo += 16;
      /* spew out base64 */
      while (bitstogo >= 6) {
        bitstogo -= 6;
        *dst++ = base64chars[(bitstogo ? (bitbuf >> bitstogo)
                              : bitbuf)
                             & 0x3F];
      }
    } while (utf16flag);
  }
  /* if in UTF-7 mode, finish in ASCII */
  if (utf7mode) {
    if (bitstogo) {
      *dst++ = base64chars[(bitbuf << (6 - bitstogo)) & 0x3F];
    }
    *dst++ = '-';
  }
  /* tie off string */
  *dst = '\0';
  return res;
}


/*******************************************************************************
 * carray/clist tools
 ******************************************************************************/


int carray_search(carray* haystack, void* needle, unsigned int* indx)
{
	void** data = carray_data(haystack);
	unsigned int i, cnt = carray_count(haystack);
	for( i=0; i<cnt; i++ )
	{
		if( data[i] == needle ) {
			if( indx ) {
				*indx = i;
			}
			return 1;
		}
	}

	return 0;
}


void clist_free_content(const clist* haystack)
{
	clistiter* iter;
	for( iter=clist_begin(haystack); iter!=NULL; iter=clist_next(iter) ) {
		free(iter->data);
		iter->data = NULL;
	}
}


/*******************************************************************************
 * date/time tools
 ******************************************************************************/


static int tmcomp(struct tm * atmp, struct tm * btmp) /* from mailcore2 */
{
    int    result;

    if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
        (result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
        (result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
        (result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
        (result = (atmp->tm_min - btmp->tm_min)) == 0)
        result = atmp->tm_sec - btmp->tm_sec;
    return result;
}


static time_t mkgmtime(struct tm * tmp) /* from mailcore2 */
{
    int            dir;
    int            bits;
    int            saved_seconds;
    time_t         t;
    struct tm      yourtm, mytm;

    yourtm = *tmp;
    saved_seconds = yourtm.tm_sec;
    yourtm.tm_sec = 0;
    /*
     ** Calculate the number of magnitude bits in a time_t
     ** (this works regardless of whether time_t is
     ** signed or unsigned, though lint complains if unsigned).
     */
    for (bits = 0, t = 1; t > 0; ++bits, t <<= 1)
        ;
    /*
     ** If time_t is signed, then 0 is the median value,
     ** if time_t is unsigned, then 1 << bits is median.
     */
    if(bits > 40) bits = 40;
    t = (t < 0) ? 0 : ((time_t) 1 << bits);
    for ( ; ; ) {
        gmtime_r(&t, &mytm);
        dir = tmcomp(&mytm, &yourtm);
        if (dir != 0) {
            if (bits-- < 0) {
                return MR_INVALID_TIMESTAMP;
            }
            if (bits < 0)
                --t;
            else if (dir > 0)
                t -= (time_t) 1 << bits;
            else    t += (time_t) 1 << bits;
            continue;
        }
        break;
    }
    t += saved_seconds;
    return t;
}


time_t mr_timestamp_from_date(struct mailimf_date_time * date_time) /* from mailcore2 */
{
    struct tm tmval;
    time_t timeval;
    int zone_min;
    int zone_hour;

    tmval.tm_sec  = date_time->dt_sec;
    tmval.tm_min  = date_time->dt_min;
    tmval.tm_hour = date_time->dt_hour;
    tmval.tm_mday = date_time->dt_day;
    tmval.tm_mon  = date_time->dt_month - 1;
    if (date_time->dt_year < 1000) {
        /* workaround when century is not given in year */
        tmval.tm_year = date_time->dt_year + 2000 - 1900;
    }
    else {
        tmval.tm_year = date_time->dt_year - 1900;
    }

    timeval = mkgmtime(&tmval);

    if (date_time->dt_zone >= 0) {
        zone_hour = date_time->dt_zone / 100;
        zone_min = date_time->dt_zone % 100;
    }
    else {
        zone_hour = -((- date_time->dt_zone) / 100);
        zone_min = -((- date_time->dt_zone) % 100);
    }
    timeval -= zone_hour * 3600 + zone_min * 60;

    return timeval;
}


char* mr_timestamp_to_str(time_t wanted)
{
	struct tm wanted_struct;
	memcpy(&wanted_struct, localtime(&wanted), sizeof(struct tm));

	/* if you need the current time for relative dates, use the following lines:
	time_t curr;
	struct tm curr_struct;
	time(&curr);
	memcpy(&curr_struct, localtime(&curr), sizeof(struct tm));
	*/

	return mr_mprintf("%02i.%02i.%04i %02i:%02i:%02i",
		(int)wanted_struct.tm_mday, (int)wanted_struct.tm_mon+1, (int)wanted_struct.tm_year+1900,
		(int)wanted_struct.tm_hour, (int)wanted_struct.tm_min, (int)wanted_struct.tm_sec);
}


/*******************************************************************************
 * file tools
 ******************************************************************************/


size_t mr_filebytes(const char* filename)
{
	struct stat st;
	stat(filename, &st);
	return (size_t)st.st_size;
}

