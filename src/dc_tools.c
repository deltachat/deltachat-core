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


#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h> /* for getpid() */
#include <unistd.h>    /* for getpid() */
#include <openssl/rand.h>
#include <libetpan/libetpan.h>
#include <libetpan/mailimap_types.h>
#include "dc_context.h"


/*******************************************************************************
 * Math tools
 ******************************************************************************/


int mr_exactly_one_bit_set(int v)
{
	return (v && !(v & (v - 1))); /* via http://www.graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2 */
}


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


char* strdup_keep_null(const char* s) /* strdup(NULL) is undefined, safe_strdup_keep_null(NULL) returns NULL in this case */
{
	return s? safe_strdup(s) : NULL;
}


int atoi_null_is_0(const char* s)
{
	return s? atoi(s) : 0;
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


void mr_strlower_in_place(char* in)
{
	char* p = in;
	for ( ; *p; p++) {
		*p = tolower(*p);
	}
}


char* mr_strlower(const char* in) /* the result must be free()'d */
{
	char* out = safe_strdup(in);

	char* p = out;
	for ( ; *p; p++) {
		*p = tolower(*p);
	}

	return out;
}


/*
 * haystack may be realloc()'d, returns the number of replacements.
 */
int mr_str_replace(char** haystack, const char* needle, const char* replacement)
{
	int replacements = 0, start_search_pos = 0, needle_len, replacement_len;

	if( haystack==NULL || *haystack==NULL || needle == NULL || needle[0]==0 ) {
		return 0;
	}

	needle_len = strlen(needle);
	replacement_len = replacement? strlen(replacement) : 0;
	while( 1 )
	{
		char* p2 = strstr((*haystack)+start_search_pos, needle);
		if( p2==NULL ) { break; }
		start_search_pos = (p2-(*haystack))+replacement_len; /* avoid recursion and skip the replaced part */

		*p2 = 0;
		p2 += needle_len;
		char* new_string = mr_mprintf("%s%s%s", *haystack, replacement? replacement : "", p2);
		free(*haystack);
		*haystack = new_string;
		replacements++;
	}

	return replacements;
}


int mr_str_contains(const char* haystack, const const char* needle)
{
	/* case-insensitive search of needle in haystack, return 1 if found, 0 if not */
	if( haystack==NULL || needle == NULL ) {
		return 0;
	}

	if( strstr(haystack, needle)!=NULL ) {
		return 1;
	}

	char* haystack_lower = mr_strlower(haystack);
	char* needle_lower = mr_strlower(needle);

		int ret = strstr(haystack_lower, needle_lower)? 1 : 0;

	free(haystack_lower);
	free(needle_lower);

	return ret;
}


/**
 * Creates a null-terminated string from a buffer.
 * Similar to strndup() but allows bad parameters and just halts the program
 * on memory allocation errors.
 *
 * @param in The start of the string.
 * @param bytes The number of bytes to take from the string.
 *
 * @return The null-terminates string, must be free()'d by the caller.
 *     On memory-allocation errors, the program halts.
 *     On other errors, an empty string is returned.
 */
char* mr_null_terminate(const char* in, int bytes) /* the result must be free()'d */
{
	char* out = malloc(bytes+1);
	if( out==NULL ) {
		exit(45);
	}

	if( in && bytes > 0 ) {
		strncpy(out, in, bytes);
	}
	out[bytes] = 0;
	return out;
}


/**
 * Converts a byte-buffer to a string with hexadecimal,
 * upper-case digits.
 *
 * This function is used eg. to create readable fingerprints, however, it may
 * be used for other purposes as well.
 *
 * @param buf The buffer to convert to an hexadecimal string. If this is NULL,
 *     the functions returns NULL.
 *
 * @param bytes The number of bytes in buf. buf may or may not be null-terminated
 *     If this is <=0, the function returns NULL.
 *
 * @return Returns a null-terminated string, must be free()'d when no longer
 *     needed. For errors, NULL is returned.
 */
char* mr_binary_to_uc_hex(const uint8_t* buf, size_t bytes)
{
	char* hex = NULL;
	int   i;

	if( buf == NULL || bytes <= 0 ) {
		goto cleanup;
	}

	if( (hex=calloc(sizeof(char), bytes*2+1))==NULL ) {
		goto cleanup;
	}

	for( i = 0; i < bytes; i++ ) {
		snprintf(&hex[i*2], 3, "%02X", (int)buf[i]);
	}

cleanup:
	return hex;
}


char* mr_mprintf(const char* format, ...)
{
	char  testbuf[1];
	char* buf;
	int   char_cnt_without_zero;

	va_list argp;
	va_list argp_copy;
	va_start(argp, format);
	va_copy(argp_copy, argp);

	char_cnt_without_zero = vsnprintf(testbuf, 0, format, argp);
	va_end(argp);
	if( char_cnt_without_zero < 0) {
		va_end(argp_copy);
		return safe_strdup("ErrFmt");
	}

	buf = malloc(char_cnt_without_zero+2 /* +1 would be enough, however, protect against off-by-one-errors */);
	if( buf == NULL ) {
		va_end(argp_copy);
		return safe_strdup("ErrMem");
	}

	vsnprintf(buf, char_cnt_without_zero+1, format, argp_copy);
	va_end(argp_copy);
	return buf;

	#if 0 /* old implementation based upon sqlite3 */
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
	#endif /* /old implementation based upon sqlite3 */
}


/**
 * Remove all `\r` characters from the given buffer.
 * This function will not convert anything else in the future, so it can be used
 * safely for marking thinks to remove by `\r` and call this function afterwards.
 *
 * @param buf The buffer to convert.
 *
 * @return None.
 */
void mr_remove_cr_chars(char* buf)
{
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


/**
 * Unify the lineends in the given null-terminated buffer to a simple `\n` (LF, ^J).
 * Carriage return characters (`\r`, CR, ^M) are removed.
 *
 * This function does _not_ convert only-CR linefeeds; AFAIK, they only came from
 * Mac OS 9 and before and should not be in use  for nearly 20 year, so maybe this
 * is no issue.  However, this could be easily added to the function as needed
 * by converting all `\r` to `\n` if there is no single `\n` in the original buffer.
 *
 * @param buf The buffer to convert.
 *
 * @return None.
 */
void mr_unify_lineends(char* buf)
{
	// this function may be extended to do more linefeed unification, do not mess up
	// with mr_remove_cr_chars() which does only exactly removing CR.
	mr_remove_cr_chars(buf);
}


void mr_replace_bad_utf8_chars(char* buf)
{
	if( buf==NULL ) {
		return;
	}

	unsigned char* p1 = (unsigned char*)buf; /* force unsigned - otherwise the `> ' '` comparison will fail */
	int            p1len = strlen(buf);
	int            c, i, ix, n, j;
	for( i=0, ix=p1len; i < ix; i++ )
	{
		c = p1[i];
		     if( c > 0 && c <= 0x7f )                           { n=0; }        /* 0bbbbbbb */
		else if( (c & 0xE0) == 0xC0 )                           { n=1; }        /* 110bbbbb */
		else if( c==0xed && i<(ix-1) && (p1[i+1] & 0xa0)==0xa0) { goto error; } /* U+d800 to U+dfff */
		else if( (c & 0xF0) == 0xE0 )                           { n=2; }        /* 1110bbbb */
		else if( (c & 0xF8) == 0xF0)                            { n=3; }        /* 11110bbb */
		//else if( (c & 0xFC) == 0xF8)                          { n=4; }        /* 111110bb - not valid in https://tools.ietf.org/html/rfc3629 */
		//else if( (c & 0xFE) == 0xFC)                          { n=5; }        /* 1111110b - not valid in https://tools.ietf.org/html/rfc3629 */
		else                                                    { goto error; }

		for( j = 0; j < n && i < ix; j++ ) { /* n bytes matching 10bbbbbb follow ? */
			if( (++i == ix) || (( p1[i] & 0xC0) != 0x80) ) {
				goto error;
			}
		}
	}

    /* everything is fine */
    return;

error:
	/* there are errors in the string -> replace potential errors by the character `_`
	(to avoid problems in filenames, we do not use eg. `?`) */
	while( *p1 ) {
		if( *p1 > 0x7f ) {
			*p1 = '_';
		}
		p1++;
	}
}


#if 0 /* not needed at the moment */
static size_t mr_utf8_strlen(const char* s)
{
	size_t i = 0, j = 0;
	while( s[i] ) {
		if( (s[i]&0xC0) != 0x80 )
			j++;
		i++;
	}
	return j;
}
#endif


static size_t mr_utf8_strnlen(const char* s, size_t n)
{
	size_t i = 0, j = 0;
	while( i < n ) {
		if( (s[i]&0xC0) != 0x80 )
			j++;
		i++;
	}
	return j;
}


void mr_truncate_n_unwrap_str(char* buf, int approx_characters, int do_unwrap)
{
	/* Function unwraps the given string and removes unnecessary whitespace.
	Function stops processing after approx_characters are processed.
	(as we're using UTF-8, for simplicity, we cut the string only at whitespaces). */
	const char* ellipse_utf8 = do_unwrap? " ..." : " " MR_EDITORIAL_ELLIPSE; /* a single line is truncated `...` instead of `[...]` (the former is typically also used by the UI to fit strings in a rectangle) */
	int lastIsCharacter = 0;
	unsigned char* p1 = (unsigned char*)buf; /* force unsigned - otherwise the `> ' '` comparison will fail */
	while( *p1 ) {
		if( *p1 > ' ' ) {
			lastIsCharacter = 1;
		}
		else {
			if( lastIsCharacter ) {
				size_t used_bytes = (size_t)((uintptr_t)p1 - (uintptr_t)buf);
				if( mr_utf8_strnlen(buf, used_bytes) >= approx_characters ) {
					size_t      buf_bytes = strlen(buf);
					if( buf_bytes-used_bytes >= strlen(ellipse_utf8) /* check if we have room for the ellipse */ ) {
						strcpy((char*)p1, ellipse_utf8);
					}
					break;
				}
				lastIsCharacter = 0;
				if( do_unwrap ) {
					*p1 = ' ';
				}
			}
			else {
				if( do_unwrap ) {
					*p1 = '\r'; /* removed below */
				}
			}
		}

		p1++;
	}

	if( do_unwrap ) {
		mr_remove_cr_chars(buf);
	}
}


void mr_truncate_str(char* buf, int approx_chars)
{
	if( approx_chars > 0 && strlen(buf) > approx_chars+strlen(MR_EDITORIAL_ELLIPSE) )
	{
		char* p = &buf[approx_chars]; /* null-terminate string at the desired length */
		*p = 0;

		if( strchr(buf, ' ')!=NULL ) {
			while( p[-1] != ' ' && p[-1] != '\n' ) { /* rewind to the previous space, avoid half utf-8 characters */
				p--;
				*p = 0;
			}
		}

		strcat(p, MR_EDITORIAL_ELLIPSE);
	}
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


char* mr_insert_breaks(const char* in, int break_every, const char* break_chars)
{
	/* insert a space every n characters, the return must be free()'d.
	this is useful to allow lines being wrapped according to RFC 5322 (adds linebreaks before spaces) */

	if( in == NULL || break_every <= 0 || break_chars == NULL ) {
		return safe_strdup(in);
	}

	int out_len = strlen(in), chars_added = 0;
	int break_chars_len = strlen(break_chars);
	out_len += (out_len/break_every+1)*break_chars_len + 1/*nullbyte*/;

	char* out = malloc(out_len);
	if( out == NULL ) { return NULL; }

	const char* i = in;
	char* o = out;
	while( *i ) {
		*o++ = *i++;
		chars_added++;
		if( chars_added==break_every && *i ) {
			strcpy(o, break_chars);
			o+=break_chars_len;
			chars_added = 0;
		}
	}
	*o = 0;
	return out;
}


/*******************************************************************************
 * clist tools
 ******************************************************************************/


void clist_free_content(const clist* haystack)
{
	clistiter* iter;
	for( iter=clist_begin(haystack); iter!=NULL; iter=clist_next(iter) ) {
		free(iter->data);
		iter->data = NULL;
	}
}


int clist_search_string_nocase(const clist* haystack, const char* needle)
{
	clistiter* iter;
	for( iter=clist_begin(haystack); iter!=NULL; iter=clist_next(iter) ) {
		if( strcasecmp((const char*)iter->data, needle)==0 ) {
			return 1;
		}
	}
	return 0;
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


long mr_gm2local_offset(void)
{
	/* returns the offset that must be _added_ to an UTC/GMT-time to create the localtime.
	the function may return nagative values. */
	time_t gmtime = time(NULL);
	struct tm timeinfo = {0};
	localtime_r(&gmtime, &timeinfo);
    return timeinfo.tm_gmtoff;
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


struct mailimap_date_time* mr_timestamp_to_mailimap_date_time(time_t timeval)
{
    struct tm gmt;
    struct tm lt;
    int off;
    struct mailimap_date_time * date_time;
    int sign;
    int hour;
    int min;

    gmtime_r(&timeval, &gmt);
    localtime_r(&timeval, &lt);

    off = (int) ((mkgmtime(&lt) - mkgmtime(&gmt)) / 60);
    if (off < 0) {
        sign = -1;
    }
    else {
        sign = 1;
    }
    off = off * sign;
    min = off % 60;
    hour = off / 60;
    off = hour * 100 + min;
    off = off * sign;

    date_time = mailimap_date_time_new(lt.tm_mday, lt.tm_mon + 1,
                                       lt.tm_year + 1900,
                                       lt.tm_hour, lt.tm_min, lt.tm_sec,
                                       off);

    return date_time;
}


/*******************************************************************************
 * Time smearing
 ******************************************************************************/


static time_t s_last_smeared_timestamp = 0;
#define MR_MAX_SECONDS_TO_LEND_FROM_FUTURE   5


time_t mr_create_smeared_timestamp__(void)
{
	time_t now = time(NULL);
	time_t ret = now;
	if( ret <= s_last_smeared_timestamp ) {
		ret = s_last_smeared_timestamp+1;
		if( (ret-now) > MR_MAX_SECONDS_TO_LEND_FROM_FUTURE ) {
			ret = now + MR_MAX_SECONDS_TO_LEND_FROM_FUTURE;
		}
	}
	s_last_smeared_timestamp = ret;
	return ret;
}


time_t mr_create_smeared_timestamps__(int count)
{
	/* get a range to timestamps that can be used uniquely */
	time_t now = time(NULL);
	time_t start = now + MR_MIN(count, MR_MAX_SECONDS_TO_LEND_FROM_FUTURE) - count;
	start = MR_MAX(s_last_smeared_timestamp+1, start);

	s_last_smeared_timestamp = start+(count-1);
	return start;
}


time_t mr_smeared_time__(void)
{
	/* function returns a corrected time(NULL) */
	time_t now = time(NULL);
	if( s_last_smeared_timestamp >= now ) {
		now = s_last_smeared_timestamp+1;
	}
	return now;
}


/*******************************************************************************
 * generate Message-IDs
 ******************************************************************************/


static char* encode_66bits_as_base64(uint32_t v1, uint32_t v2, uint32_t fill /*only the lower 2 bits are used*/)
{
	/* encode 66 bits as a base64 string. This is useful for ID generating with short strings as
	we save 5 character in each id compared to 64 bit hex encoding, for a typical group ID, these are 10 characters (grpid+msgid):
	hex:    64 bit, 4 bits/character, length = 64/4 = 16 characters
	base64: 64 bit, 6 bits/character, length = 64/6 = 11 characters (plus 2 additional bits) */
	char* ret = malloc(12); if( ret==NULL ) { exit(34); }
	static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	ret[ 0] = chars[   (v1>>26) & 0x3F  ];
	ret[ 1] = chars[   (v1>>20) & 0x3F  ];
	ret[ 2] = chars[   (v1>>14) & 0x3F  ];
	ret[ 3] = chars[   (v1>> 8) & 0x3F  ];
	ret[ 4] = chars[   (v1>> 2) & 0x3F  ];
	ret[ 5] = chars[ ( (v1<< 4) & 0x30 ) | ( (v2>>28) & 0x0F ) ];
	ret[ 6] = chars[                         (v2>>22) & 0x3F   ];
	ret[ 7] = chars[                         (v2>>16) & 0x3F   ];
	ret[ 8] = chars[                         (v2>>10) & 0x3F   ];
	ret[ 9] = chars[                         (v2>> 4) & 0x3F   ];
	ret[10] = chars[                       ( (v2<< 2) & 0x3C ) | (fill & 0x03) ];
	ret[11] = 0;
	return ret;
}


char* mr_create_id(void)
{
	/* generate an id. the generated ID should be as short and as unique as possible:
	- short, because it may also used as part of Message-ID headers or in QR codes
	- unique as two IDs generated on two devices should not be the same. However, collisions are not world-wide but only by the few contacts.
	IDs generated by this function are 66 bit wide and are returned as 11 base64 characters.
	If possible, RNG of OpenSSL is used.

	Additional information when used as a message-id or group-id:
	- for OUTGOING messages this ID is written to the header as `Chat-Group-ID:` and is added to the message ID as Gr.<grpid>.<random>@<random>
	- for INCOMING messages, the ID is taken from the Chat-Group-ID-header or from the Message-ID in the In-Reply-To: or References:-Header
	- the group-id should be a string with the characters [a-zA-Z0-9\-_] */
	uint32_t buf[3];
	if( !RAND_bytes((unsigned char*)&buf, sizeof(uint32_t)*3) ) {
		RAND_pseudo_bytes((unsigned char*)&buf, sizeof(uint32_t)*3);
	}
	return encode_66bits_as_base64(buf[0], buf[1], buf[2]/*only the lower 2 bits are taken from this value*/);
}


char* mr_create_dummy_references_mid()
{
	char* msgid = mr_create_id(), *ret = NULL;
	ret = mr_mprintf("Rf.%s@mr.thread", msgid);
	free(msgid);
	return ret;
}


char* mr_create_outgoing_rfc724_mid(const char* grpid, const char* from_addr)
{
	/* Function generates a Message-ID that can be used for a new outgoing message.
	- this function is called for all outgoing messages.
	- the message ID should be globally unique
	- do not add a counter or any private data as as this may give unneeded information to the receiver	*/

	char*       rand1 = NULL;
	char*       rand2 = mr_create_id();
	char*       ret = NULL;
	const char* at_hostname = strchr(from_addr, '@');

	if( at_hostname == NULL ) {
		at_hostname = "@nohost";
	}

	if( grpid ) {
		ret = mr_mprintf("Gr.%s.%s%s", grpid, rand2, at_hostname);
		               /* ^^^ `Gr.` must never change as this is used to identify group messages in normal-clients-replies. The dot is choosen as this is normally not used for random ID creation. */
	}
	else {
		rand1 = mr_create_id();
		ret = mr_mprintf("Mr.%s.%s%s", rand1, rand2, at_hostname);
		               /* ^^^ `Mr.` is currently not used, however, this may change in future */
	}

	free(rand2);
	return ret;
}


char* mr_create_incoming_rfc724_mid(time_t message_timestamp, uint32_t contact_id_from, dc_array_t* contact_ids_to)
{
	/* Function generates a Message-ID for incoming messages that lacks one.
	- normally, this function is not needed as incoming messages already have an ID
	- the generated ID is only for internal use; it should be database-unique
	- when fetching the same message again, this function should generate the same Message-ID
	*/

	if( message_timestamp == MR_INVALID_TIMESTAMP || contact_ids_to == NULL || dc_array_get_cnt(contact_ids_to)==0 ) {
		return NULL;
	}

	/* find out the largest receiver ID (we could also take the smallest, but it should be unique) */
	size_t   i, icnt = dc_array_get_cnt(contact_ids_to);
	uint32_t largest_id_to = 0;
	for( i = 0; i < icnt; i++ ) {
		uint32_t cur_id = dc_array_get_id(contact_ids_to, i);
		if( cur_id > largest_id_to ) {
			largest_id_to = cur_id;
		}
	}

	/* build a more or less unique string based on the timestamp and one receiver -
	for our purposes, this seems "good enough" for the moment, esp. as clients normally set Message-ID on sent. */
	return mr_mprintf("%lu-%lu-%lu@stub", (unsigned long)message_timestamp, (unsigned long)contact_id_from, (unsigned long)largest_id_to);
}


char* mr_extract_grpid_from_rfc724_mid(const char* mid)
{
	/* extract our group ID from Message-IDs as `Gr.12345678901.morerandom@domain.de`; "12345678901" is the wanted ID in this example. */
	int   success = 0;
	char* grpid = NULL, *p1;
	int   grpid_len;

	if( mid == NULL || strlen(mid)<8 || mid[0]!='G' || mid[1]!='r' || mid[2]!='.' ) {
		goto cleanup;
	}

	grpid = safe_strdup(&mid[3]);

	p1 = strchr(grpid, '.');
	if( p1 == NULL ) {
		goto cleanup;
	}
	*p1 = 0;

	#define MR_ALSO_VALID_ID_LEN  16 /* length returned by create_adhoc_grp_id__() */
	grpid_len = strlen(grpid);
	if( grpid_len!=MR_CREATE_ID_LEN && grpid_len!=MR_ALSO_VALID_ID_LEN ) { /* strict length comparison, the 'Gr.' magic is weak enough */
		goto cleanup;
	}

	success = 1;

cleanup:
	if( success == 0 ) { free(grpid); grpid = NULL; }
	return success? grpid : NULL;
}


char* mr_extract_grpid_from_rfc724_mid_list(const clist* list)
{
	clistiter* cur;
	if( list ) {
		for( cur = clist_begin(list); cur!=NULL ; cur=clist_next(cur) ) {
			const char* mid = clist_content(cur);
			char* grpid = mr_extract_grpid_from_rfc724_mid(mid);
			if( grpid ) {
				return grpid;
			}
		}
	}
	return NULL;
}



/*******************************************************************************
 * file tools
 ******************************************************************************/


int mr_file_exist(const char* pathNfilename)
{
	struct stat st;
	if( stat(pathNfilename, &st) == 0 ) {
		return 1; /* the size, however, may be 0 */
	}
	else {
		return 0;
	}
}


uint64_t mr_get_filebytes(const char* pathNfilename)
{
	struct stat st;
	if( stat(pathNfilename, &st) == 0 ) {
		return (uint64_t)st.st_size;
	}
	else {
		return 0;
	}
}


char* mr_get_filename(const char* pathNfilename)
{
	const char* p = strrchr(pathNfilename, '/');
	if( p==NULL ) {
		p = strrchr(pathNfilename, '\\');
	}

	if( p ) {
		p++;
		return safe_strdup(p);
	}
	else {
		return safe_strdup(pathNfilename);
	}
}


int mr_delete_file(const char* pathNfilename, dc_context_t* log/*may be NULL*/)
{
	if( pathNfilename==NULL ) {
		return 0;
	}

	if( remove(pathNfilename)!=0 ) {
		dc_log_warning(log, 0, "Cannot delete \"%s\".", pathNfilename);
		return 0;
	}

	return 1;
}


int mr_copy_file(const char* src, const char* dest, dc_context_t* log/*may be NULL*/)
{
    int     success = 0, fd_src = -1, fd_dest = -1;
    #define MR_COPY_BUF_SIZE 4096
    char    buf[MR_COPY_BUF_SIZE];
    size_t  bytes_read;
    int     anything_copied = 0;

	if( src==NULL || dest==NULL ) {
		return 0;
	}

    if( (fd_src=open(src, O_RDONLY)) < 0 ) {
		dc_log_error(log, 0, "Cannot open source file \"%s\".", src);
        goto cleanup;
	}

    if( (fd_dest=open(dest, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0 ) {
		dc_log_error(log, 0, "Cannot open destination file \"%s\".", dest);
        goto cleanup;
	}

    while( (bytes_read=read(fd_src, buf, MR_COPY_BUF_SIZE)) > 0 ) {
        if (write(fd_dest, buf, bytes_read) != bytes_read) {
            dc_log_error(log, 0, "Cannot write %i bytes to \"%s\".", bytes_read, dest);
		}
		anything_copied = 1;
    }

    if( !anything_copied ) {
		/* not a single byte copied -> check if the source is empty, too */
		close(fd_src);
		fd_src = -1;
		if( mr_get_filebytes(src)!=0 ) {
			dc_log_error(log, 0, "Different size information for \"%s\".", bytes_read, dest);
			goto cleanup;
		}
    }

    success = 1;

cleanup:
	if( fd_src >= 0 ) { close(fd_src); }
	if( fd_dest >= 0 ) { close(fd_dest); }
	return success;
}


int mr_create_folder(const char* pathNfilename, dc_context_t* log)
{
	struct stat st;
	if (stat(pathNfilename, &st) == -1) {
		if( mkdir(pathNfilename, 0755) != 0 ) {
			dc_log_warning(log, 0, "Cannot create directory \"%s\".", pathNfilename);
			return 0;
		}
	}
	return 1;
}


char* mr_get_filesuffix_lc(const char* pathNfilename)
{
	if( pathNfilename ) {
		const char* p = strrchr(pathNfilename, '.'); /* use the last point, we're interesting the "main" type */
		if( p ) {
			p++;
			return mr_strlower(p); /* in contrast to mr_split_filename() we return the lowercase suffix */
		}
	}
	return NULL;
}


void mr_split_filename(const char* pathNfilename, char** ret_basename, char** ret_all_suffixes_incl_dot)
{
	/* splits a filename into basename and all suffixes, eg. "/path/foo.tar.gz" is split into "foo.tar" and ".gz",
	(we use the _last_ dot which allows the usage inside the filename which are very usual;
	maybe the detection could be more intelligent, however, for the moment, it is just file)
	- if there is no suffix, the returned suffix string is empty, eg. "/path/foobar" is split into "foobar" and ""
	- the case of the returned suffix is preserved; this is to allow reconstruction of (similar) names */
	char* basename = mr_get_filename(pathNfilename), *suffix;
	char* p1 = strrchr(basename, '.');
	if( p1 ) {
		suffix = safe_strdup(p1);
		*p1 = 0;
	}
	else {
		suffix = safe_strdup(NULL);
	}

	/* return the given values */
	if( ret_basename              ) { *ret_basename              = basename; } else { free(basename); }
	if( ret_all_suffixes_incl_dot ) { *ret_all_suffixes_incl_dot = suffix;   } else { free(suffix);   }
}



void mr_validate_filename(char* filename)
{
	/* function modifies the given buffer and replaces all characters not valid in filenames by a "-" */
	char* p1 = filename;
	while( *p1 ) {
		if( *p1=='/' || *p1=='\\' || *p1==':' ) {
			*p1 = '-';
		}
		p1++;
	}
}


char* mr_get_fine_pathNfilename(const char* folder, const char* desired_filenameNsuffix__)
{
	char*       ret = NULL, *filenameNsuffix, *basename = NULL, *dotNSuffix = NULL;
	time_t      now = time(NULL);
	struct stat st;
	int         i;

	filenameNsuffix = safe_strdup(desired_filenameNsuffix__);
	mr_validate_filename(filenameNsuffix);
	mr_split_filename(filenameNsuffix, &basename, &dotNSuffix);

	for( i = 0; i < 1000 /*no deadlocks, please*/; i++ ) {
		if( i ) {
			time_t idx = i<100? i : now+i;
			ret = mr_mprintf("%s/%s-%lu%s", folder, basename, (unsigned long)idx, dotNSuffix);
		}
		else {
			ret = mr_mprintf("%s/%s%s", folder, basename, dotNSuffix);
		}
		if (stat(ret, &st) == -1) {
			goto cleanup; /* fine filename found */
		}
		free(ret); /* try over with the next index */
		ret = NULL;
	}

cleanup:
	free(filenameNsuffix);
	free(basename);
	free(dotNSuffix);
	return ret;
}


int mr_write_file(const char* pathNfilename, const void* buf, size_t buf_bytes, dc_context_t* log)
{
	int success = 0;

	FILE* f = fopen(pathNfilename, "wb");
	if( f ) {
		if( fwrite(buf, 1, buf_bytes, f) == buf_bytes ) {
			success = 1;
		}
		else {
			dc_log_warning(log, 0, "Cannot write %lu bytes to \"%s\".", (unsigned long)buf_bytes, pathNfilename);
		}
		fclose(f);
	}
	else {
		dc_log_warning(log, 0, "Cannot open \"%s\" for writing.", pathNfilename);
	}

	return success;
}


int mr_read_file(const char* pathNfilename, void** buf, size_t* buf_bytes, dc_context_t* log)
{
	int success = 0;

	if( pathNfilename==NULL || buf==NULL || buf_bytes==NULL ) {
		return 0; /* do not go to cleanup as this would dereference "buf" and "buf_bytes" */
	}

	*buf = NULL;
	*buf_bytes = 0;
	FILE* f = fopen(pathNfilename, "rb");
	if( f==NULL ) { goto cleanup; }

	fseek(f, 0, SEEK_END);
	*buf_bytes = ftell(f);
	fseek(f, 0, SEEK_SET);
	if( *buf_bytes <= 0 ) { goto cleanup; }

	*buf = malloc( (*buf_bytes) + 1 /*be pragmatic and terminate all files by a null - fine for texts and does not hurt for the rest */ );
	if( *buf==NULL ) { goto cleanup; }

	((char*)*buf)[*buf_bytes /*we allocated one extra byte above*/] = 0;

	if( fread(*buf, 1, *buf_bytes, f)!=*buf_bytes ) { goto cleanup; }

	success = 1;

cleanup:
	if( f ) {
		fclose(f);
	}
	if( success==0 ) {
		free(*buf);
		*buf = NULL;
		*buf_bytes = 0;
		dc_log_warning(log, 0, "Cannot read \"%s\" or file is empty.", pathNfilename);
	}
	return success; /* buf must be free()'d by the caller */
}


int mr_get_filemeta(const void* buf_start, size_t buf_bytes, uint32_t* ret_width, uint32_t *ret_height)
{
	/* Strategy:
	reading GIF dimensions requires the first 10 bytes of the file
	reading PNG dimensions requires the first 24 bytes of the file
	reading JPEG dimensions requires scanning through jpeg chunks
	In all formats, the file is at least 24 bytes big, so we'll read that always
	inspired by http://www.cplusplus.com/forum/beginner/45217/ */
	const unsigned char* buf = buf_start;
	if (buf_bytes<24) {
		return 0;
	}

	/* For JPEGs, we need to check the first bytes of each DCT chunk. */
	if( buf[0]==0xFF && buf[1]==0xD8 && buf[2]==0xFF )
	{
		long pos = 2;
		while( buf[pos]==0xFF )
		{
			if (buf[pos+1]==0xC0 || buf[pos+1]==0xC1 || buf[pos+1]==0xC2 || buf[pos+1]==0xC3 || buf[pos+1]==0xC9 || buf[pos+1]==0xCA || buf[pos+1]==0xCB) {
				*ret_height = (buf[pos+5]<<8) + buf[pos+6]; /* sic! height is first */
				*ret_width  = (buf[pos+7]<<8) + buf[pos+8];
				return 1;
			}
			pos += 2+(buf[pos+2]<<8)+buf[pos+3];
			if (pos+12>buf_bytes) { break; }
		}
	}

	/* GIF: first three bytes say "GIF", next three give version number. Then dimensions */
	if( buf[0]=='G' && buf[1]=='I' && buf[2]=='F' )
	{
		*ret_width  = buf[6] + (buf[7]<<8);
		*ret_height = buf[8] + (buf[9]<<8);
		return 1;
	}

	/* PNG: the first frame is by definition an IHDR frame, which gives dimensions */
	if( buf[0]==0x89 && buf[1]=='P' && buf[2]=='N' && buf[3]=='G' && buf[4]==0x0D && buf[5]==0x0A && buf[6]==0x1A && buf[7]==0x0A
	 && buf[12]=='I' && buf[13]=='H' && buf[14]=='D' && buf[15]=='R' )
	{
		*ret_width  = (buf[16]<<24) + (buf[17]<<16) + (buf[18]<<8) + (buf[19]<<0);
		*ret_height = (buf[20]<<24) + (buf[21]<<16) + (buf[22]<<8) + (buf[23]<<0);
		return 1;
	}

	return 0;
}
