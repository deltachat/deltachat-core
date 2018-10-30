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


#ifndef __DC_STOCK_H__
#define __DC_STOCK_H__
#ifdef __cplusplus
extern "C" {
#endif


#include <stdlib.h>
#include <string.h>


/* Return the string with the given ID by calling DC_EVENT_GET_STRING.
The result must be free()'d! */
char* dc_stock_str (dc_context_t*, int id);


/* Replaces the first `%1$s` in the given String-ID by the given value.
The result must be free()'d! */
char* dc_stock_str_repl_string (dc_context_t*, int id, const char* value);
char* dc_stock_str_repl_int    (dc_context_t*, int id, int value);


/* Replaces the first `%1$s` and `%2$s` in the given String-ID by the two given strings.
The result must be free()'d! */
char* dc_stock_str_repl_string2 (dc_context_t*, int id, const char*, const char*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_STOCK_H__ */

