/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2018 Christian Schneider
 *                          Contact: schneider17@gmx.de
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


/* 
 * 
 * Some functions and extensions to find, decode and store uuencoded parts from
 * Mail text string.
 * 
 * 
 */

#ifndef __MRUUDECODE_H__
#define __MRUUDECODE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* for mr_detect_line_end */
#define CRLF "\r\n" //1310 dez
#define CR   "\r"   //13
#define LF   "\n"   //10

/* CR or CRLF or LF */
char* mr_detect_line_end (char* txt);

/* delivers one line from a string */
int   mr_getline (char** line, char* source, char* lineendpattern, char** nextchar);

/* return hex representation of a string*/
char* mr_print_hex(char* s);


/* find uuencoded part in msgtxt & locate position */
char* mr_find_uuencoded_part (char* msgtxt, char* lineend);

/* extract uupart and make if for next func available */
char* mr_handle_uuencoded_part (char* msgtxt, char* uu_msg_start_pos, char* lineend);      

/* decode uupart and provide it, used in mr_handle_uuencoded_part() */
void  mr_uudecode (char* uuencoded_txt, int uuencoded_txt_len, char* filename, char* lineend);

/* checks if line matches uuencoded rules */
int mr_uu_check_line(int n, int line_len);

#ifdef __cplusplus
} /* /extern "C" */
#endif

#endif /* __MRUUDECODE_H__ */
