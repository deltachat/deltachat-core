/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

#ifndef __DC_STRBUILDER_H__
#define __DC_STRBUILDER_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct dc_strbuilder_t
{
	char* buf;
	int   allocated;
	int   free;
	char* eos;
} dc_strbuilder_t;


void  dc_strbuilder_init    (dc_strbuilder_t*, int init_bytes);
char* dc_strbuilder_cat     (dc_strbuilder_t*, const char* text);
void  dc_strbuilder_catf    (dc_strbuilder_t*, const char* format, ...);
void  dc_strbuilder_empty   (dc_strbuilder_t*);


#ifdef __cplusplus
} // /extern "C"
#endif
#endif // __DC_STRBUILDER_H__

