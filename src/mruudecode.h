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


#ifndef __MRUUDECODE_H__
#define __MRUUDECODE_H__
#ifdef __cplusplus
extern "C" {
#endif


char* mruudecode_do(const char* text, char** ret_binary, size_t* ret_binary_bytes, char** ret_filename);



/**
 *  From here new code from: Christian Schneider <schneider17@gmx.de>  
 */


/* return hex representation of a string*/
char* mr_print_hex(char* s);

/* delivers one line from a string */
int   mr_getline (char** line, char* source, char** nextchar);

/* CR or CRLF or LF */
char* mr_detect_line_end (const char* txt);

/* checks if line matches uuencoded rules */
int   mr_uu_check_line(int n, int line_len);

/* find uuencoded part in msgtxt and returns it's position */
char* mr_find_uuencoded_part (const char* msgtxt);

/* extract uuencoded part and make it for next func available */
char* mr_handle_uuencoded_part (const char*   msgtxt,
                                 char*         uu_msg_start_pos,
                                 char**        ret_binary,
                                 size_t*       ret_binary_bytes,
                                 char**        ret_filename);

/* decode uuencoded part and provide it, used in mr_handle_uuencoded_part() */
int   mr_uudecode(char** ret_binary, size_t uudecoding_buffer_len, const char* uu_body_start);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRUUDECODE_H__ */

