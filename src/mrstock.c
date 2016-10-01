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
 * File:    mrstock.h
 * Authors: Björn Petersen
 * Purpose: Add translated strings that are used by the messager backend
 *
 ******************************************************************************/


#include <stdlib.h>
#include <memory.h>
#include "mrmailbox.h"
#include "mrtools.h"


static char** s_obj = NULL;
static int    s_def_strings_added = 0;


static void mrstock_init_array_()
{
	if( s_obj ) {
		return; /* already initialized*/
	}

	size_t bytes_needed = sizeof(char*) * MR_STR_COUNT_;
	if( (s_obj=malloc(bytes_needed)) == NULL ) {
		exit(13); /* cannot allocate little memory, unrecoverable error */
	}
    memset(s_obj, 0, bytes_needed);
    s_def_strings_added = 0;
}


void mrstock_exit(void)
{
	if( s_obj ) {
		size_t i;
		for( i = 0; i < MR_STR_COUNT_; i++ ) {
			if( s_obj[i] ) {
				free(s_obj[i]);
			}
		}
		free(s_obj);
		s_obj = NULL;
	}
	s_def_strings_added = 0;
}


void mrstock_add_str(int id, const char* str)
{
	if( id < 0 || id >= MR_STR_COUNT_ || str == NULL ) {
		return; /* error */
	}

	mrstock_init_array_();

	if( s_obj[id] ) {
		free(s_obj[id]);
	}

	s_obj[id] = strdup(str);
}


const char* mrstock_str(int id)
{
	/* init array */
	mrstock_init_array_();

	if( s_obj[id] == NULL && !s_def_strings_added ) {
		/* init strings */
		s_def_strings_added = 1;
		mrstock_add_str(MR_STR_NO_MESSAGES, "No messages.");
		mrstock_add_str(MR_STR_YOU,         "You");
	}

	return s_obj[id]? s_obj[id] : "Err"; /* the result must not be freed! */
}

