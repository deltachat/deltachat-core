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


#ifndef __MRSTRBUILDER_H__
#define __MRSTRBUILDER_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct mrstrbuilder_t
{
	char* m_buf;
	int   m_allocated;
	int   m_free;
	char* m_eos;
} mrstrbuilder_t;


void  mrstrbuilder_init    (mrstrbuilder_t* ths, int init_bytes);
char* mrstrbuilder_cat     (mrstrbuilder_t* ths, const char* text);
void  mrstrbuilder_catf    (mrstrbuilder_t* ths, const char* format, ...);
void  mrstrbuilder_empty   (mrstrbuilder_t* ths);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRSTRBUILDER_H__ */

