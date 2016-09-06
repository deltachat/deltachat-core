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
 * File:    mrmailbox.cpp
 * Authors: Björn Petersen
 * Purpose: MrMailbox represents a single mailbox, see header for details.
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
#include "mrmsg.h"
#include "mrtools.h"


/*******************************************************************************
 * Init/Exit
 ******************************************************************************/


MrMailbox::MrMailbox()
	: m_sql(this), m_imap(this)
{
}


MrMailbox::~MrMailbox()
{
	Close();
}


bool MrMailbox::Open(const char* dbfile)
{
	{
		MrSqlite3Locker locker(m_sql);

		// Open() sets up the object and connects to the given database
		// from which all configuration is read/written to.

		// Create/open sqlite database
		if( !m_sql.Open(dbfile) ) {
			goto Open_Error; // error already logged
		}
	}

	// success
	return true;

	// error
Open_Error:
	Close();
	return false;
}


void MrMailbox::Close()
{
	MrSqlite3Locker locker(m_sql);

	m_sql.Close();
}


/*******************************************************************************
 * Import EML-files
 ******************************************************************************/


bool MrMailbox::ImportFile(const char* filename)
{
	bool        success = false;
	FILE*       f = NULL;
	struct stat stat_info;
	char*       data = NULL;

	// read file content to `data`
	if( (f=fopen(filename, "r")) == NULL ) {
		MrLogError("MrMailbox::ImportFile(): Cannot open file.");
		goto ImportFile_Cleanup;
	}

	if( stat(filename, &stat_info) != 0 || stat_info.st_size == 0 ) {
		MrLogError("MrMailbox::ImportFile(): Cannot find out file size or file is empty.");
		goto ImportFile_Cleanup;
	}

	if( (data=(char*)malloc(stat_info.st_size))==NULL ) {
		MrLogError("MrMailbox::ImportFile(): Out of memory.");
		goto ImportFile_Cleanup;
	}

	if( fread(data, 1, stat_info.st_size, f)!=(size_t)stat_info.st_size ) {
		MrLogError("MrMailbox::ImportFile(): Read error.");
		goto ImportFile_Cleanup;
	}

	fclose(f);
	f = NULL;

	// import `data`
	ReceiveImf(data, stat_info.st_size);

	// success
	success = true;

	// cleanup:
ImportFile_Cleanup:
	free(data);
	if( f ) {
		fclose(f);
	}
	return success;
}


bool MrMailbox::ImportSpec(const char* spec) // spec is a file, a directory or NULL for the last import
{
	bool           success = false;
	char*          spec_memory = NULL;
	DIR*           dir = NULL;
	struct dirent* dir_entry;
	int            read_cnt = 0;
	char*          name;

	if( !m_sql.Ok() ) {
        MrLogError("MrMailbox::ImportSpec(): Datebase not opened.");
		goto ImportSpec_Cleanup;
	}

	// if `spec` is given, remember it for later usage; if it is not given, try to use the last one
	if( spec ) {
		MrSqlite3Locker locker(m_sql);
		m_sql.SetConfig("import_spec", spec);
	}
	else {
		MrSqlite3Locker locker(m_sql);
        spec_memory = m_sql.GetConfig("import_spec", NULL);
		spec = spec_memory; // may still  be NULL
		if( spec == NULL ) {
			MrLogError("MrMailbox::ImportSpec(): No file or folder given.");
			goto ImportSpec_Cleanup;
		}
	}

	if( strlen(spec)>=4 && strcmp(&spec[strlen(spec)-4], ".eml")==0 ) {
		// import a single file
		if( ImportFile(spec) ) { // errors are logged in any case
			read_cnt++;
		}
	}
	else {
		// import a directory
		if( (dir=opendir(spec))==NULL ) {
			MrLogError("MrMailbox::ImportSpec(): Cannot open directory.");
			goto ImportSpec_Cleanup;
		}

		while( (dir_entry=readdir(dir))!=NULL ) {
			name = dir_entry->d_name; // name without path; may also be `.` or `..`
            if( strlen(name)>=4 && strcmp(&name[strlen(name)-4], ".eml")==0 ) {
				char* path_plus_name = sqlite3_mprintf("%s/%s", spec, name);
				if( path_plus_name ) {
					if( ImportFile(path_plus_name) ) { // no abort on single errors errors are logged in any case
						read_cnt++;
					}
					sqlite3_free(path_plus_name);
				}
            }
		}
	}

	{
		char* p = sqlite3_mprintf("%i mails read from %s.", read_cnt, spec);
		if( p ) {
			MrLogInfo(p);
			sqlite3_free(p);
		}
	}

	// success
	success = true;

	// cleanup
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


bool MrMailbox::Connect()
{
	if( m_imap.IsConnected() ) {
		MrLogInfo("MrMailbox::Connect(): Already connected or trying to connect.");
		return true;
	}

	// read parameter, unset parameters are still NULL afterwards
	{
		MrSqlite3Locker locker(m_sql);

		m_loginParam.Clear();

		m_loginParam.m_email       = m_sql.GetConfig   ("email",       NULL);

		m_loginParam.m_mail_server = m_sql.GetConfig   ("mail_server", NULL);
		m_loginParam.m_mail_port   = m_sql.GetConfigInt("mail_port",   0);
		m_loginParam.m_mail_user   = m_sql.GetConfig   ("mail_user",   NULL);
		m_loginParam.m_mail_pw     = m_sql.GetConfig   ("mail_pw",     NULL);

		m_loginParam.m_send_server = m_sql.GetConfig   ("send_server", NULL);
		m_loginParam.m_send_port   = m_sql.GetConfigInt("send_port",   0);
		m_loginParam.m_send_user   = m_sql.GetConfig   ("send_user",   NULL);
		m_loginParam.m_send_pw     = m_sql.GetConfig   ("send_pw",     NULL);
	}

	// try to suggest unset parameters
	m_loginParam.Complete();

	// connect
	return m_imap.Connect(&m_loginParam);
}


void MrMailbox::Disconnect()
{
	m_imap.Disconnect();
}


bool MrMailbox::Fetch()
{
	return m_imap.Fetch();
}


/*******************************************************************************
 * Receive an IMF as an result to calling Fetch() or Import*()
 * the new IMF may be old or new and should be parsed, contacts created etc.
 * However, the caller should make sure, it does not exist in the database.
 ******************************************************************************/


void MrMailbox::ReceiveImf(const char* imf_raw_not_terminated, size_t imf_raw_bytes)
{
	MrImfParser parser(this);

	if( !parser.Imf2Msg(imf_raw_not_terminated, imf_raw_bytes) ) {
		return; // error already logged
	}
}


/*******************************************************************************
 * Handle contacts
 ******************************************************************************/


size_t MrMailbox::GetContactCnt()
{
	MrSqlite3Locker locker(m_sql);

	return MrContact::GetContactCnt(this);
}


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


size_t MrMailbox::GetChatCnt()
{
	MrSqlite3Locker locker(m_sql);

	return MrChat::GetChatCnt(this);
}


MrChatList* MrMailbox::GetChats()
{
	MrSqlite3Locker locker(m_sql);

	MrChatList* obj = new MrChatList(this);
	if( obj->LoadFromDb() ) {
		return obj;
	}
	else {
		delete obj;
		return NULL;
	}
}


MrChat* MrMailbox::GetChat(const char* name)
{
	MrSqlite3Locker locker(m_sql);

	MrChat* obj = new MrChat(this);
	if( obj->LoadFromDb(name, 0) ) {
		return obj;
	}
	else {
		delete obj;
		return NULL;
	}
}


MrChat* MrMailbox::GetChat(uint32_t id)
{
	MrSqlite3Locker locker(m_sql);

	MrChat* obj = new MrChat(this);
	if( obj->LoadFromDb(NULL, id) ) {
		return obj;
	}
	else {
		delete obj;
		return NULL;
	}
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


char* MrMailbox::GetDbFile()
{
	if( m_sql.m_dbfile == NULL ) {
		return NULL; // database not opened
	}

	return safe_strdup(m_sql.m_dbfile); // must be freed by the caller
}


char* MrMailbox::GetInfo()
{
	const char  unset[] = "<unset>";
	const char  set[] = "<set>";
	#define BUF_BYTES 10000
	char* buf = (char*)malloc(BUF_BYTES+1);
	if( buf == NULL ) {
		MrLogError("MrMailbox::GetInfo(): Out of memory.");
		return NULL; // error
	}

	// read data (all pointers may be NULL!)
	char *email, *mail_server, *mail_port, *mail_user, *mail_pw, *send_server, *send_port, *send_user, *send_pw, *debug_dir;
	int contacts, chats, messages;
	{
		MrSqlite3Locker locker(m_sql);

		email       = m_sql.GetConfig("email", NULL);

		mail_server = m_sql.GetConfig("mail_server", NULL);
		mail_port   = m_sql.GetConfig("mail_port", NULL);
		mail_user   = m_sql.GetConfig("mail_user", NULL);
		mail_pw     = m_sql.GetConfig("mail_pw", NULL);

		send_server = m_sql.GetConfig("send_server", NULL);
		send_port   = m_sql.GetConfig("send_port", NULL);
		send_user   = m_sql.GetConfig("send_user", NULL);
		send_pw     = m_sql.GetConfig("send_pw", NULL);

		debug_dir   = m_sql.GetConfig("debug_dir", NULL);

		contacts    = MrContact::GetContactCnt(this);
		chats       = MrChat::GetChatCnt(this);
		messages    = MrMsg::GetMsgCnt(this);
	}

	// create info
    snprintf(buf, BUF_BYTES,
		"Backend version  %i.%i.%i\n"
		"SQLite version   %s, threadsafe=%i\n"
		"libEtPan version %i.%i\n"
		"Database file    %s\n"
		"Contacts         %i\n"
		"Chats/Messages   %i/%i\n"

		"email            %s\n"
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
		, m_sql.m_dbfile? m_sql.m_dbfile : unset

		, contacts
		, chats, messages

		, email? email : unset
		, mail_server? mail_server : unset
		, mail_port? mail_port : unset
		, mail_user? mail_user : unset
		, mail_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get mail_pw`

		, send_server? send_server : unset
		, send_port? send_port : unset
		, send_user? send_user : unset
		, send_pw? set : unset // we do not display the password here; in the cli-utility, you can see it using `get send_pw`

		, debug_dir? debug_dir : unset
		);

	// free data
	#define GI_FREE_(a) if((a)) { free((a)); }
	GI_FREE_(email);

	GI_FREE_(mail_server);
	GI_FREE_(mail_port);
	GI_FREE_(mail_user);
	GI_FREE_(mail_pw);

	GI_FREE_(send_server);
	GI_FREE_(send_port);
	GI_FREE_(send_user);
	GI_FREE_(send_pw);
	return buf; // must be freed by the caller
}


bool MrMailbox::Empty()
{
	MrSqlite3Locker locker(m_sql);

	m_sql.sqlite3_execute_("DELETE FROM contacts;");
	m_sql.sqlite3_execute_("DELETE FROM chats;");
	m_sql.sqlite3_execute_("DELETE FROM chats_contacts;");
	m_sql.sqlite3_execute_("DELETE FROM msg;");
	m_sql.sqlite3_execute_("DELETE FROM msg_to;");
	m_sql.sqlite3_execute_("DELETE FROM config WHERE keyname LIKE 'folder.%';");

	return true;
}
