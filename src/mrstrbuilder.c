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


#include "mrmailbox_internal.h"


/**
 * Init a string-builder-object.
 * A string-builder-object is placed typically on the stack and contains a string-buffer
 * which is initially empty.
 *
 * You can add data to the string-buffer using eg. mrstrbuilder_cat() or
 * mrstrbuilder_catf() - the buffer is reallocated as needed.
 *
 * When you're done with string building, the ready-to-use, null-terminates
 * string can be found at mrstrbuilder_t::m_buf, you can do whatever you like
 * with this buffer, however, never forget to call free() when done.
 * 
 * @param strbuilder The object to initialze.
 *
 * @param init_bytes The number of bytes to reserve for the string. If you have an 
 *     idea about how long the resulting string will be, you can give this as a hint here;
 *     this avoids some reallocations; if the string gets longer, reallocation is done.
 *     If you do not know how larget the string will be, give 0 here.
 *
 * @return None.
 */
void mrstrbuilder_init(mrstrbuilder_t* strbuilder, int init_bytes)
{
	if( strbuilder==NULL ) {
		return;
	}

	strbuilder->m_allocated    = MR_MAX(init_bytes, 128); /* use a small default minimum, we may use _many_ of these objects at the same time */
	strbuilder->m_buf          = malloc(strbuilder->m_allocated); 
    
    if( strbuilder->m_buf==NULL ) {
		exit(38);
	}
	
	strbuilder->m_buf[0]       = 0;
	strbuilder->m_free         = strbuilder->m_allocated - 1 /*the nullbyte! */;
	strbuilder->m_eos          = strbuilder->m_buf;
}


/**
 * Add a string to the end of the current string in a string-builder-object.
 * The internal buffer is reallocated as needed.
 * If reallocation fails, the program halts.
 *
 * @param strbuilder The object to initialze. Must be initialized with
 *      mrstrbuilder_init().
 *
 * @param text Null-terminated string to add to the end of the string-builder-string.
 *
 * @return Returns a pointer to the copy of the given text.
 *     The returned pointer is a pointer inside mrstrbuilder_t::m_buf and MUST NOT
 *     be freed.  If the string-builder was empty before, the returned
 *     pointer is equal to mrstrbuilder_t::m_buf.  
 *     If the given text is NULL, NULL is returned and the string-builder-object is not modified.
 */
char* mrstrbuilder_cat(mrstrbuilder_t* strbuilder, const char* text)
{
	// this function MUST NOT call logging functions as it is used to output the log
	if( strbuilder==NULL || text==NULL ) {
		return NULL;
	}

	int len = strlen(text);

	if( len > strbuilder->m_free ) {
		int add_bytes  = MR_MAX(len, strbuilder->m_allocated);
		int old_offset = (int)(strbuilder->m_eos - strbuilder->m_buf);

		strbuilder->m_allocated = strbuilder->m_allocated + add_bytes;
		strbuilder->m_buf       = realloc(strbuilder->m_buf, strbuilder->m_allocated+add_bytes);
        
        if( strbuilder->m_buf==NULL ) {
			exit(39);
		}
		
		strbuilder->m_free      = strbuilder->m_free + add_bytes;
		strbuilder->m_eos       = strbuilder->m_buf + old_offset;
	}

	char* ret = strbuilder->m_eos;

	strcpy(strbuilder->m_eos, text);
	strbuilder->m_eos += len;
	strbuilder->m_free -= len;

	return ret;
}


/**
 * Add a formatted string to a string-builder-object.
 * This function is similar to mrstrbuilder_cat() but allows the same
 * formatting options as eg. printf()
 *
 * @param strbuilder The object to initialze. Must be initialized with
 *      mrstrbuilder_init().
 *
 * @param format The formatting string to add to the string-builder-object.
 *      This parameter may be followed by data to be inserted into the
 *      formatting string, see eg. printf()
 *
 * @return None.
 */
void mrstrbuilder_catf(mrstrbuilder_t* strbuilder, const char* format, ...)
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
		mrstrbuilder_cat(strbuilder, "ErrFmt");
		return;
	}

	buf = malloc(char_cnt_without_zero+2 /* +1 would be enough, however, protect against off-by-one-errors */);
	if( buf == NULL ) {
		va_end(argp_copy);
		mrstrbuilder_cat(strbuilder, "ErrMem");
		return;
	}

	vsnprintf(buf, char_cnt_without_zero+1, format, argp_copy);
	va_end(argp_copy);

	mrstrbuilder_cat(strbuilder, buf);
	free(buf);
}


/**
 * Set the string to a lenght of 0. This does not free the buffer;
 * if you want to free the buffer, you have to call free() on mrstrbuilder_t::m_buf.
 *
 * @param strbuilder The object to initialze. Must be initialized with
 *      mrstrbuilder_init().
 *
 * @return None
 */
void mrstrbuilder_empty(mrstrbuilder_t* strbuilder)
{
	strbuilder->m_buf[0] = 0;
	strbuilder->m_free   = strbuilder->m_allocated - 1 /*the nullbyte! */;
	strbuilder->m_eos    = strbuilder->m_buf;
}
