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
 * File:    mrmailbox.c
 * Authors: Björn Petersen
 * Purpose: mrmailbox_t represents a single mailbox, see header for details.
 *
 *******************************************************************************
 *
 * For memory checking, use eg.
 * $ valgrind --leak-check=full --tool=memcheck ./messenger-backend <db>
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sqlite3.h>
#include "mrmailbox.h"
#include "mrimfparser.h"
#include "mrcontact.h"
#include "mrtools.h"
#include "mrlog.h"
#include "mrloginparam.h"


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


mrmailbox_t* mrmailbox_new(mrmailboxcb_t cb, void* userData)
{
	mrmailbox_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmailbox_t)))==NULL ) {
		exit(23); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_sql      = mrsqlite3_new(ths);
	ths->m_imap     = mrimap_new(ths);
	ths->m_dbfile   = NULL;
	ths->m_blobdir  = NULL;
	ths->m_cb       = cb;
	ths->m_userData = userData;

	return ths;
}


void mrmailbox_unref(mrmailbox_t* ths)
{
	if( ths==NULL ) {
		return; /* error */
	}

	if( mrmailbox_is_open(ths) ) {
		mrmailbox_close(ths);
	}

	mrimap_unref(ths->m_imap);
	mrsqlite3_unref(ths->m_sql);
	free(ths);
}


int mrmailbox_open(mrmailbox_t* ths, const char* dbfile, const char* blobdir)
{
	int success = 0;
	int db_locked = 0;

	if( ths == NULL || dbfile == NULL ) {
		goto Open_Done;
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
	db_locked = 1;

	/* Open() sets up the object and connects to the given database
	from which all configuration is read/written to. */

	/* Create/open sqlite database */
	if( !mrsqlite3_open_(ths->m_sql, dbfile) ) {
		goto Open_Done; /* error already logged */
	}

	/* backup dbfile name */
	ths->m_dbfile = safe_strdup(dbfile);

	/* set blob-directory
	(the directory may or may not end with an slash, we check this later) */
	if( blobdir && blobdir[0] ) {
		ths->m_blobdir = safe_strdup(blobdir);
	}
	else {
		ths->m_blobdir = mr_mprintf("%s-blobs", dbfile);
	}

	/* success */
	success = 1;

	/* cleanup */
Open_Done:
	if( !success ) {
		if( mrsqlite3_is_open(ths->m_sql) ) {
			mrsqlite3_close_(ths->m_sql); /* note, unlocking is done before */
		}
	}

	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}

	return success;
}


void mrmailbox_close(mrmailbox_t* ths)
{
	if( ths == NULL || ths->m_sql == NULL ) {
		return;
	}

	if( mrimap_is_connected(ths->m_imap) ) {
		mrimap_disconnect(ths->m_imap);
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		if( mrsqlite3_is_open(ths->m_sql) ) {
			mrsqlite3_close_(ths->m_sql);
		}

		free(ths->m_dbfile);
		ths->m_dbfile = NULL;

		free(ths->m_blobdir);
		ths->m_blobdir = NULL;

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
}


int mrmailbox_is_open(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return 0; /* error - database not opened */
	}

	return mrsqlite3_is_open(ths->m_sql);
}


/*******************************************************************************
 * Import EML-files
 ******************************************************************************/


int mrmailbox_import_file(mrmailbox_t* ths, const char* filename)
{
	int         success = 0;
	FILE*       f = NULL;
	struct stat stat_info;
	char*       data = NULL;

	if( ths == NULL ) {
		return 0;
	}

	/* read file content to `data` */
	if( (f=fopen(filename, "r")) == NULL ) {
		mrlog_error("Import: Cannot open \"%s\".", filename);
		goto ImportFile_Cleanup;
	}

	if( stat(filename, &stat_info) != 0 || stat_info.st_size == 0 ) {
		mrlog_error("Import: Cannot find out file size or file is empty for \"%s\".", filename);
		goto ImportFile_Cleanup;
	}

	if( (data=(char*)malloc(stat_info.st_size))==NULL ) {
		exit(26); /* cannot allocate little memory, unrecoverable error */
	}

	if( fread(data, 1, stat_info.st_size, f)!=(size_t)stat_info.st_size ) {
		mrlog_error("Import: Read error in \"%s\".", filename);
		goto ImportFile_Cleanup;
	}

	fclose(f);
	f = NULL;

	/* import `data` */
	mrmailbox_receive_imf_(ths, data, stat_info.st_size);

	/* success */
	success = 1;

	/* cleanup: */
ImportFile_Cleanup:
	free(data);
	if( f ) {
		fclose(f);
	}
	return success;
}


int mrmailbox_import_spec(mrmailbox_t* ths, const char* spec) /* spec is a file, a directory or NULL for the last import */
{
	int            success = 0;
	char*          spec_memory = NULL;
	DIR*           dir = NULL;
	struct dirent* dir_entry;
	int            read_cnt = 0;
	char*          name;

	if( ths == NULL ) {
		return 0;
	}

	if( !mrsqlite3_is_open(ths->m_sql) ) {
        mrlog_error("Import: Database not opened.");
		goto ImportSpec_Cleanup;
	}

	/* if `spec` is given, remember it for later usage; if it is not given, try to use the last one */
	if( spec )
	{
		mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
			mrsqlite3_set_config_(ths->m_sql, "import_spec", spec);
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}
	else {
		mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
			spec_memory = mrsqlite3_get_config_(ths->m_sql, "import_spec", NULL);
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

		spec = spec_memory; /* may still  be NULL */
		if( spec == NULL ) {
			mrlog_error("Import: No file or folder given.");
			goto ImportSpec_Cleanup;
		}
	}

	if( strlen(spec)>=4 && strcmp(&spec[strlen(spec)-4], ".eml")==0 ) {
		/* import a single file */
		if( mrmailbox_import_file(ths, spec) ) { /* errors are logged in any case */
			read_cnt++;
		}
	}
	else {
		/* import a directory */
		if( (dir=opendir(spec))==NULL ) {
			mrlog_error("Import: Cannot open directory \"%s\".", spec);
			goto ImportSpec_Cleanup;
		}

		while( (dir_entry=readdir(dir))!=NULL ) {
			name = dir_entry->d_name; /* name without path; may also be `.` or `..` */
            if( strlen(name)>=4 && strcmp(&name[strlen(name)-4], ".eml")==0 ) {
				char* path_plus_name = sqlite3_mprintf("%s/%s", spec, name);
				mrlog_info("Import: %s", path_plus_name);
				if( path_plus_name ) {
					if( mrmailbox_import_file(ths, path_plus_name) ) { /* no abort on single errors errors are logged in any case */
						read_cnt++;
					}
					sqlite3_free(path_plus_name);
				}
            }
		}
	}

	mrlog_info("Import: %i mails read from \"%s\".", read_cnt, spec);

	/* success */
	success = 1;

	/* cleanup */
ImportSpec_Cleanup:
	if( dir ) {
		closedir(dir);
	}
	free(spec_memory);
	return success;
}


/*******************************************************************************
 * Connect
 ******************************************************************************/


int mrmailbox_connect(mrmailbox_t* ths)
{
	mrloginparam_t* param = NULL;
	int             is_locked = 0;
	int             is_configured = 0;

	if( ths == NULL || ths->m_sql == NULL ) {
		return 0;
	}

	if( mrimap_is_connected(ths->m_imap) ) {
		mrlog_info("Already connected or trying to connect.");
		return 1;
	}

	/* read parameter, unset parameters are still NULL afterwards */
	param = mrloginparam_new();

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
	is_locked = 1;

		mrloginparam_read_(param, ths->m_sql, "configured_" /*the trailing underscore is correct*/);
		is_configured = mrsqlite3_get_config_int_(ths->m_sql, "configured", 0)? 1 : 0;
		if( is_configured == 0 ) {
			mrlog_error("Not configured.");
			goto Error;
		}

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	is_locked = 0;

	/* connect */
	return mrimap_connect(ths->m_imap, param /*ownership of loginParam is taken by mrimap_connect() */);

	/* error */
Error:
	if( param ) {
		mrloginparam_unref(param);
	}

	if( is_locked ) {
		mrsqlite3_unlock(ths->m_sql);
	}
	return 0;
}


void mrmailbox_disconnect(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return;
	}

	mrimap_disconnect(ths->m_imap);
}


int mrmailbox_fetch(mrmailbox_t* ths)
{
	if( ths == NULL ) {
		return 0;
	}

	return mrimap_fetch(ths->m_imap);
}


/*******************************************************************************
 * Receive an IMF as an result to calling Fetch() or Import*()
 * the new IMF may be old or new and should be parsed, contacts created etc.
 * However, the caller should make sure, it does not exist in the database.
 ******************************************************************************/


void mrmailbox_receive_imf_(mrmailbox_t* ths, const char* imf_raw_not_terminated, size_t imf_raw_bytes)
{
	mrimfparser_t* parser = mrimfparser_new_(ths);

	if( !mrimfparser_imf2msg_(parser, imf_raw_not_terminated, imf_raw_bytes) ) {
		goto ReceiveCleanup; /* error already logged */
	}

	/* Cleanup */
ReceiveCleanup:
	if( parser ) {
		mrimfparser_unref_(parser);
	}
}


/*******************************************************************************
 * Handle contacts
 ******************************************************************************/


mrcontactlist_t* mrmailbox_get_contactlist(mrmailbox_t* ths)
{
	return mrcontactlist_new(ths);
}


mrcontact_t* mrmailbox_get_contact_by_id(mrmailbox_t* ths, uint32_t contact_id)
{
	mrcontact_t* ret = mrcontact_new(ths);

	if( contact_id == MRSCID_SELF )
	{
		ret->m_id   = contact_id;
		ret->m_name = safe_strdup(mrstock_str(MR_STR_YOU));
	}
	else
	{
		mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

			if( !mrcontact_load_from_db_(ret, contact_id) ) {
				mrcontact_unref(ret);
				ret = NULL;
			}

		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}

	return ret; /* may be NULL */
}


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


mrchatlist_t* mrmailbox_get_chatlist(mrmailbox_t* ths)
{
	int success = 0;
	int db_locked = 0;
	mrchatlist_t* obj = mrchatlist_new(ths);

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
	db_locked = 1;

	if( !mrchatlist_load_from_db_(obj) ) {
		goto GetChatsCleanup;
	}

	/* success */
	success = 1;

	/* cleanup */
GetChatsCleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}

	if( success ) {
		return obj;
	}
	else {
		mrchatlist_unref(obj);
		return NULL;
	}
}


mrchat_t* mrmailbox_get_chat_by_id(mrmailbox_t* ths, uint32_t id)
{
	int success = 0;
	int db_locked = 0;
	mrchat_t* obj = mrchat_new(ths);

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
	db_locked = 1;

	if( !mrchat_load_from_db_(obj, id) ) {
		goto cleanup;
	}

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}

	if( success ) {
		return obj;
	}
	else {
		mrchat_unref(obj);
		return NULL;
	}
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


int mrmailbox_set_config(mrmailbox_t* ths, const char* key, const char* value)
{
	int ret;

	if( ths == NULL || key == NULL ) { /* "value" may be NULL */
		return 0;
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_set_config_(ths->m_sql, key, value);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return ret;
}


char* mrmailbox_get_config(mrmailbox_t* ths, const char* key, const char* def)
{
	char* ret;

	if( ths == NULL || key == NULL ) { /* "def" may be NULL */
		return safe_strdup(def);
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_get_config_(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return ret; /* the returned string must be free()'d, returns NULL on errors */
}


int mrmailbox_set_config_int(mrmailbox_t* ths, const char* key, int32_t value)
{
	int ret;

	if( ths == NULL || key == NULL ) {
		return 0;
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_set_config_int_(ths->m_sql, key, value);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return ret;
}


int32_t mrmailbox_get_config_int(mrmailbox_t* ths, const char* key, int32_t def)
{
	int32_t ret;

	if( ths == NULL || key == NULL ) {
		return def;
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_get_config_int_(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return ret;
}


int mrmailbox_configure(mrmailbox_t* ths)
{
	mrloginparam_t* param;

	mrlog_info("Configuring...");

	if( ths == NULL || !mrsqlite3_is_open(ths->m_sql) ) {
		mrlog_error("Database not opened.");
		return 0;
	}

	/* read the original parameters */
	param = mrloginparam_new();

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		mrloginparam_read_(param, ths->m_sql, "");
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	/* complete the parameters; in the future we may also try some server connections here */
	mrloginparam_complete(param);

	/* write back the configured parameters with the "configured_" prefix. Also write the "configured"-flag */
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		if( param->m_addr
		 && param->m_mail_server
		 && param->m_mail_port
		 && param->m_mail_user
		 && param->m_mail_pw
		 && param->m_send_server
		 && param->m_send_port
		 && param->m_send_user
		 && param->m_send_pw )
		{
			mrloginparam_write_(param, ths->m_sql, "configured_" /*the trailing underscore is correct*/);
			mrsqlite3_set_config_int_(ths->m_sql, "configured", 1);
		}
		else
		{
			mrsqlite3_set_config_int_(ths->m_sql, "configured", 0);
		}
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	mrloginparam_unref(param);
	param = NULL;

	mrlog_info("Configure ok.");

	return 1;
}


int mrmailbox_is_configured(mrmailbox_t* ths)
{
	int is_configured;

	if( ths == NULL || ths->m_sql == NULL ) {
		return 0;
	}

	if( mrimap_is_connected(ths->m_imap) ) { /* if we're connected, we're also configured. this check will speed up the check as no database is involved */
		return 1;
	}

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		is_configured = mrsqlite3_get_config_int_(ths->m_sql, "configured", 0);

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return is_configured? 1 : 0;
}


char* mrmailbox_get_info(mrmailbox_t* ths)
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	char *debug_dir, *name, *info;
	mrloginparam_t *l, *l2;
	int contacts, chats, assigned_msgs, unassigned_msgs, is_configured;

	if( ths == NULL ) {
		return safe_strdup("ErrBadPtr");
	}

	/* read data (all pointers may be NULL!) */
	l = mrloginparam_new();
	l2 = mrloginparam_new();

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		mrloginparam_read_(l, ths->m_sql, "");
		mrloginparam_read_(l2, ths->m_sql, "configured_" /*the trailing underscore is correct*/);

		debug_dir   = mrsqlite3_get_config_(ths->m_sql, "debug_dir", NULL);
		name        = mrsqlite3_get_config_(ths->m_sql, "displayname", NULL);

		chats           = mr_get_chat_cnt_(ths);
		assigned_msgs   = mr_get_assigned_msg_cnt_(ths);
		unassigned_msgs = mr_get_unassigned_msg_cnt_(ths);
		contacts        = mr_get_contact_cnt_(ths);

		is_configured   = mrsqlite3_get_config_int_(ths->m_sql, "configured", 0);

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	/* create info
	- some keys are display lower case - these can be changed using the `set`-command
	- we do not display the password here; in the cli-utility, you can see it using `get mail_pw` */
	info = mr_mprintf(
		"Messenger Backend %i.%i.%i - (C) Björn Petersen Software Design and Development and contributors\n" /* use neutral speach here, the messenger backend is not directly related to any front end or end-product. */
		"\n"
		"%i chats with %i messages, %i unassigned messages, %i contacts\n"
		"Database file: %s, blob directory: %s\n"
		"\n"
		"displayname=%s\n"
		"configured=%i\n"
		"addr=%s (%s)\n"
		"mail_server=%s (%s)\n"
		"mail_port=%i (%i)\n"
		"mail_user=%s (%s)\n"
		"mail_pw=%s (%s)\n"
		"send_server=%s (%s)\n"
		"send_port=%i (%i)\n"
		"send_user=%s (%s)\n"
		"send_pw=%s (%s)\n"
		"debug_dir=%s\n"
		"\n"
		"Using SQLite %s-ts%i and libEtPan %i.%i. Compiled " __DATE__ ", " __TIME__ " for %i bit usage."
		/* In the frontends, additional software hints may follow here. */

		, MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION

		, chats, assigned_msgs, unassigned_msgs, contacts
		, ths->m_dbfile? ths->m_dbfile : unset   ,  ths->m_blobdir? ths->m_blobdir : unset

        , name? name : unset
		, is_configured
		, l->m_addr? l->m_addr : unset                 , l2->m_addr? l2->m_addr : unset
		, l->m_mail_server? l->m_mail_server : unset   , l2->m_mail_server? l2->m_mail_server : unset
		, l->m_mail_port? l->m_mail_port : 0           , l2->m_mail_port? l2->m_mail_port : 0
		, l->m_mail_user? l->m_mail_user : unset       , l2->m_mail_user? l2->m_mail_user : unset
		, l->m_mail_pw? set : unset,                     l2->m_mail_pw? set : unset
		, l->m_send_server? l->m_send_server : unset   , l2->m_send_server? l2->m_send_server : unset
		, l->m_send_port? l->m_send_port : 0           , l2->m_send_port? l2->m_send_port : 0
		, l->m_send_user? l->m_send_user : unset       , l2->m_send_user? l2->m_send_user : unset
		, l->m_send_pw? set : unset                    , l2->m_send_pw? set : unset
		, debug_dir? debug_dir : unset

		, SQLITE_VERSION, sqlite3_threadsafe()   ,  libetpan_get_version_major(), libetpan_get_version_minor(), sizeof(void*)*8

		);

	/* free data */
	mrloginparam_unref(l);
	mrloginparam_unref(l2);
	free(debug_dir);
	free(name);

	return info; /* must be freed by the caller */
}


int mrmailbox_empty_tables(mrmailbox_t* ths)
{
	mrlog_info("Emptying all tables...");

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		mrsqlite3_execute(ths->m_sql, "DELETE FROM contacts WHERE id>" MR_STRINGIFY(MRSCID_LAST) ";"); /* the other IDs are reserved - leave these rows to make sure, the IDs are not used by normal contacts*/
		mrsqlite3_execute(ths->m_sql, "DELETE FROM chats;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM chats_contacts;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM msgs;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM msgs_to;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM config WHERE keyname LIKE 'folder.%' OR keyname LIKE 'configured%';");

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	mrlog_info("Tables emptied.");

	return 1;
}


char* mrmailbox_execute(mrmailbox_t* ths, const char* cmd)
{
	#define COMMAND_FAILED    ((char*)1)
	#define COMMAND_SUCCEEDED ((char*)2)
	char*   ret = NULL;

	if( ths == NULL || cmd == NULL || cmd[0]==0 ) {
		goto Done;
	}

	if( strncmp(cmd, "open", 4)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			mrmailbox_close(ths);
			ret = mrmailbox_open(ths, arg1, NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <file> missing.");
		}
	}
	else if( strcmp(cmd, "close")==0 )
	{
		mrmailbox_close(ths);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strncmp(cmd, "import", 6)==0 )
	{
		const char* arg1 = strstr(cmd, " ");
		ret = mrmailbox_import_spec(ths, arg1? ++arg1 : NULL)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "configure")==0 )
	{
		ret = mrmailbox_configure(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "connect")==0 )
	{
		ret = mrmailbox_connect(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strcmp(cmd, "disconnect")==0 )
	{
		mrmailbox_disconnect(ths);
		ret = COMMAND_SUCCEEDED;
	}
	else if( strcmp(cmd, "fetch")==0 )
	{
		ret = mrmailbox_fetch(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}
	else if( strncmp(cmd, "set", 3)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			char* arg2 = strstr(arg1, " ");
			if( arg2 ) {
				*arg2 = 0;
				arg2++;
			}
			ret = mrmailbox_set_config(ths, arg1, arg2)? COMMAND_SUCCEEDED : COMMAND_FAILED;
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strncmp(cmd, "get", 3)==0 )
	{
		char* arg1 = (char*)strstr(cmd, " ");
		if( arg1 ) {
			arg1++;
			char* val = mrmailbox_get_config(ths, arg1, "<unset>");
			if( val ) {
				ret = mr_mprintf("%s=%s", arg1, val);
				free(val);
			}
			else {
				ret = COMMAND_FAILED;
			}
		}
		else {
			ret = safe_strdup("ERROR: Argument <key> missing.");
		}
	}
	else if( strcmp(cmd, "info")==0 )
	{
		ret = mrmailbox_get_info(ths);
		if( ret == NULL ) {
			ret = COMMAND_FAILED;
		}
	}
	else if( strcmp(cmd, "empty")==0 )
	{
		ret = mrmailbox_empty_tables(ths)? COMMAND_SUCCEEDED : COMMAND_FAILED;
	}

Done:
	if( ret == COMMAND_FAILED ) {
		ret = safe_strdup("ERROR: Command failed.");
	}
	else if( ret == COMMAND_SUCCEEDED ) {
		ret = safe_strdup("Command executed successfully.");
	}
	return ret;
}
