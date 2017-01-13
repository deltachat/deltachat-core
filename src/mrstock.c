/*******************************************************************************
 *
 *                             Messenger Backend
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
 *******************************************************************************
 *
 * File:    mrstock.h
 * Purpose: Add translated strings that are used by the messager backend
 *
 ******************************************************************************/


#include <stdlib.h>
#include <memory.h>
#include "mrmailbox.h"
#include "mrtools.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


static char** s_obj = NULL;
static int    s_def_strings_added = 0;


static void mrstock_init_array()
{
	if( s_obj ) {
		return; /* already initialized*/
	}

	size_t bytes_needed = sizeof(char*) * MR_STR_COUNT_;
	if( (s_obj=calloc(1, bytes_needed)) == NULL ) {
		exit(13); /* cannot allocate little memory, unrecoverable error */
	}
    s_def_strings_added = 0;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


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
		return;
	}

	mrstock_init_array();

	if( s_obj[id] ) {
		free(s_obj[id]);
	}

	s_obj[id] = strdup(str);
}


char* mrstock_str(int id) /* get the string with the given ID, the result must be free()'d! */
{
	/* init array */
	mrstock_init_array();

	if( id < 0 || id >= MR_STR_COUNT_ ) {
		return safe_strdup("StockRangeErr");
	}

	if( s_obj[id] == NULL && !s_def_strings_added ) {
		/* init strings */
		s_def_strings_added = 1;
		mrstock_add_str(MR_STR_NO_MESSAGES,  "No messages.");
		mrstock_add_str(MR_STR_SELF,         "Me");
		mrstock_add_str(MR_STR_DRAFT,        "Draft");
		mrstock_add_str(MR_STR_MEMBER,       "## member");
		mrstock_add_str(MR_STR_MEMBERS,      "## members");
		mrstock_add_str(MR_STR_CONTACT,      "## contact");
		mrstock_add_str(MR_STR_CONTACTS,     "## contacts");
		mrstock_add_str(MR_STR_DEADDROP,     "Mailbox");
		mrstock_add_str(MR_STR_IMAGE,        "Image");
		mrstock_add_str(MR_STR_VIDEO,        "Video");
		mrstock_add_str(MR_STR_AUDIO,        "Voice message");
		mrstock_add_str(MR_STR_FILE,         "File");
		mrstock_add_str(MR_STR_STATUSLINE,   "Sent with my Delta Chat Messenger");
		mrstock_add_str(MR_STR_NEWGROUPDRAFT,"Hello, I've just created the group \"##\" for us.");
		mrstock_add_str(MR_STR_MSGGRPNAME,   "Group name changed from \"##\" to \"##\".");
		mrstock_add_str(MR_STR_MSGGRPIMAGE,  "Group image changed.");
		mrstock_add_str(MR_STR_MSGADDMEMBER, "Member ## added.");
		mrstock_add_str(MR_STR_MSGDELMEMBER, "Member ## removed.");
		mrstock_add_str(MR_STR_MSGGROUPLEFT, "Group left.");
	}

	return safe_strdup(s_obj[id]? s_obj[id] : "StockMissing");
}


static char* repl_string(char* p1 /*string will be modified!*/, const char* to_insert)
{
	/* replace `##` by given string, the input string will be modified, the result must be free()'d */
	char* p2 = strstr(p1, "##");
	if( p2==NULL ) { return strdup(p1); }
	*p2 = 0;
	p2 += 2;
	return mr_mprintf("%s%s%s", p1, to_insert? to_insert : "", p2);
}


char* mrstock_str_repl_string(int id, const char* to_insert)
{
	char* p1 = mrstock_str(id);
	char* p2 = repl_string(p1, to_insert);
	free(p1);
	return p2;
}


char* mrstock_str_repl_string2(int id, const char* to_insert, const char* to_insert2)
{
	char* p1 = mrstock_str(id);
	char* p2 = repl_string(p1, to_insert);
	free(p1);
	p1 = repl_string(p2, to_insert2);
	free(p2);
	return p1;
}


char* mrstock_str_repl_number(int id, int cnt)
{
	char* p1 = mrstock_str(id);
	char* p2 = strstr(p1, "##"), *ret;
	if( p2==NULL ) { return p1; }
	*p2 = 0;
	p2 += 2;
	ret = mr_mprintf("%s%i%s", p1, cnt, p2);
	free(p1);
	return ret;
}


char* mrstock_str_repl_pl(int id, int cnt)
{
	if( cnt != 1 ) {
		id++; /* the provided ID should be singular, plural is plus one. */
	}

	return mrstock_str_repl_number(id, cnt);
}
