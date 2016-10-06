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


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


mrmailbox_t* mrmailbox_new()
{
	mrmailbox_t* ths = NULL;

	if( (ths=malloc(sizeof(mrmailbox_t)))==NULL ) {
		return NULL; /* error */
	}

	ths->m_loginParam = mrloginparam_new();
	ths->m_sql = mrsqlite3_new(ths);
	ths->m_imap = mrimap_new(ths);
	ths->m_dbfile = NULL;
	ths->m_blobdir = NULL;

	return ths;
}


void mrmailbox_unref(mrmailbox_t* ths)
{
	if( ths==NULL ) {
		return; /* error */
	}

	mrmailbox_close(ths);
	mrimap_unref(ths->m_imap);
	mrsqlite3_unref(ths->m_sql);
	mrloginparam_unref(ths->m_loginParam);
	free(ths);
}


int mrmailbox_open(mrmailbox_t* ths, const char* dbfile, const char* blobdir)
{
	int success = 0;
	int db_locked = 0;

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
	db_locked = 1;

	/* Open() sets up the object and connects to the given database
	from which all configuration is read/written to. */

	/* Create/open sqlite database */
	if( !mrsqlite3_open(ths->m_sql, dbfile) ) {
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
		mrsqlite3_close(ths->m_sql); /* note, unlocking is done before */
	}

	if( db_locked ) {
		mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	}

	return success;
}


void mrmailbox_close(mrmailbox_t* ths)
{
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		mrsqlite3_close(ths->m_sql);

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

	/* read file content to `data` */
	if( (f=fopen(filename, "r")) == NULL ) {
		mrlog_error("mrmailbox_import_file(): Cannot open file.");
		goto ImportFile_Cleanup;
	}

	if( stat(filename, &stat_info) != 0 || stat_info.st_size == 0 ) {
		mrlog_error("mrmailbox_import_file(): Cannot find out file size or file is empty.");
		goto ImportFile_Cleanup;
	}

	if( (data=(char*)malloc(stat_info.st_size))==NULL ) {
		mrlog_error("mrmailbox_import_file(): Out of memory.");
		goto ImportFile_Cleanup;
	}

	if( fread(data, 1, stat_info.st_size, f)!=(size_t)stat_info.st_size ) {
		mrlog_error("mrmailbox_import_file(): Read error.");
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

	if( !mrsqlite3_is_open(ths->m_sql) ) {
        mrlog_error("mrmailbox_import_spec(): Datebase not opened.");
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
			mrlog_error("mrmailbox_import_spec(): No file or folder given.");
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
			mrlog_error("mrmailbox_import_spec(): Cannot open directory.");
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

	mrlog_info("Import: %i mails read from %s.", read_cnt, spec);

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
	if( mrimap_is_connected(ths->m_imap) ) {
		mrlog_info("mrmailbox_connect(): Already connected or trying to connect.");
		return 1;
	}

	/* read parameter, unset parameters are still NULL afterwards */
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		mrloginparam_empty(ths->m_loginParam);

		ths->m_loginParam->m_addr        = mrsqlite3_get_config_    (ths->m_sql, "addr",        NULL);

		ths->m_loginParam->m_mail_server = mrsqlite3_get_config_    (ths->m_sql, "mail_server", NULL);
		ths->m_loginParam->m_mail_port   = mrsqlite3_get_config_int_(ths->m_sql, "mail_port",   0);
		ths->m_loginParam->m_mail_user   = mrsqlite3_get_config_    (ths->m_sql, "mail_user",   NULL);
		ths->m_loginParam->m_mail_pw     = mrsqlite3_get_config_    (ths->m_sql, "mail_pw",     NULL);

		ths->m_loginParam->m_send_server = mrsqlite3_get_config_    (ths->m_sql, "send_server", NULL);
		ths->m_loginParam->m_send_port   = mrsqlite3_get_config_int_(ths->m_sql, "send_port",   0);
		ths->m_loginParam->m_send_user   = mrsqlite3_get_config_    (ths->m_sql, "send_user",   NULL);
		ths->m_loginParam->m_send_pw     = mrsqlite3_get_config_    (ths->m_sql, "send_pw",     NULL);

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	/* try to suggest unset parameters */
	mrloginparam_complete(ths->m_loginParam);

	/* connect */
	return mrimap_connect(ths->m_imap, ths->m_loginParam);
}


void mrmailbox_disconnect(mrmailbox_t* ths)
{
	mrimap_disconnect(ths->m_imap);
}


int mrmailbox_fetch(mrmailbox_t* ths)
{
	return 	mrimap_fetch(ths->m_imap);
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
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_set_config_(ths->m_sql, key, value);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	return ret;
}


char* mrmailbox_get_config(mrmailbox_t* ths, const char* key, const char* def)
{
	char* ret;
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_get_config_(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	return ret; /* the returned string must be free()'d, returns NULL on errors */
}


int32_t mrmailbox_get_config_int(mrmailbox_t* ths, const char* key, int32_t def)
{
	int32_t ret;
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */
		ret = mrsqlite3_get_config_int_(ths->m_sql, key, def);
	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */
	return ret;
}


char* mrmailbox_get_info(mrmailbox_t* ths)
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	#define BUF_BYTES 10000
	char* buf = (char*)malloc(BUF_BYTES+1);
	if( buf == NULL ) {
		mrlog_error("mrmailbox_get_info(): Out of memory.");
		return NULL; /* error */
	}

	/* read data (all pointers may be NULL!) */
	char *addr, *mail_server, *mail_port, *mail_user, *mail_pw, *send_server, *send_port, *send_user, *send_pw, *debug_dir;
	int contacts, chats, assigned_msgs, unassigned_msgs;

	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		addr        = mrsqlite3_get_config_(ths->m_sql, "addr", NULL);

		mail_server = mrsqlite3_get_config_(ths->m_sql, "mail_server", NULL);
		mail_port   = mrsqlite3_get_config_(ths->m_sql, "mail_port", NULL);
		mail_user   = mrsqlite3_get_config_(ths->m_sql, "mail_user", NULL);
		mail_pw     = mrsqlite3_get_config_(ths->m_sql, "mail_pw", NULL);

		send_server = mrsqlite3_get_config_(ths->m_sql, "send_server", NULL);
		send_port   = mrsqlite3_get_config_(ths->m_sql, "send_port", NULL);
		send_user   = mrsqlite3_get_config_(ths->m_sql, "send_user", NULL);
		send_pw     = mrsqlite3_get_config_(ths->m_sql, "send_pw", NULL);

		debug_dir   = mrsqlite3_get_config_(ths->m_sql, "debug_dir", NULL);

		chats           = mr_get_chat_cnt_(ths);
		assigned_msgs   = mr_get_assigned_msg_cnt_(ths);
		unassigned_msgs = mr_get_unassigned_msg_cnt_(ths);
		contacts        = mr_get_contact_cnt_(ths);

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	/* create info */
    snprintf(buf, BUF_BYTES,
		"Backend version  %i.%i.%i\n"
		"SQLite version   %s, threadsafe=%i\n"
		"libEtPan version %i.%i\n"
		"Database file    %s\n"
		"BLOB directory   %s\n"
		"Chats            %i chats with %i messages, %i unassigned messages\n"
		"Contacts         %i\n"

		"addr             %s\n"
		"mail_server      %s\n"
		"mail_port        %s\n"
		"mail_user        %s\n"
		"mail_pw          %s\n"

		"send_server      %s\n"
		"send_port        %s\n"
		"send_user        %s\n"
		"send_pw          %s\n"

		"debug_dir        %s\n"
		"If possible, unset values are filled by the program with typical values.\n"

		, MR_VERSION_MAJOR, MR_VERSION_MINOR, MR_VERSION_REVISION
		, SQLITE_VERSION, sqlite3_threadsafe()
		, libetpan_get_version_major(), libetpan_get_version_minor()
		, ths->m_dbfile? ths->m_dbfile : unset
		, ths->m_blobdir? ths->m_blobdir : unset

		, chats, assigned_msgs, unassigned_msgs
		, contacts

		, addr? addr : unset
		, mail_server? mail_server : unset
		, mail_port? mail_port : unset
		, mail_user? mail_user : unset
		, mail_pw? set : unset /* we do not display the password here; in the cli-utility, you can see it using `get mail_pw` */

		, send_server? send_server : unset
		, send_port? send_port : unset
		, send_user? send_user : unset
		, send_pw? set : unset /* we do not display the password here; in the cli-utility, you can see it using `get send_pw` */

		, debug_dir? debug_dir : unset
		);

	/* free data */
	free(addr);

	free(mail_server);
	free(mail_port);
	free(mail_user);
	free(mail_pw);

	free(send_server);
	free(send_port);
	free(send_user);
	free(send_pw);

	return buf; /* must be freed by the caller */
}


int mrmailbox_empty_tables(mrmailbox_t* ths)
{
	mrsqlite3_lock(ths->m_sql); /* CAVE: No return until unlock! */

		mrsqlite3_execute(ths->m_sql, "DELETE FROM contacts WHERE id>" MR_STRINGIFY(MRSCID_LAST) ";"); /* the other IDs are reserved - leave these rows to make sure, the IDs are not used by normal contacts*/
		mrsqlite3_execute(ths->m_sql, "DELETE FROM chats;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM chats_contacts;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM msg;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM msg_to;");
		mrsqlite3_execute(ths->m_sql, "DELETE FROM config WHERE keyname LIKE 'folder.%';");

	mrsqlite3_unlock(ths->m_sql); /* /CAVE: No return until unlock! */

	return 1;
}
