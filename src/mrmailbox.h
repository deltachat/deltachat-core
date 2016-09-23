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
 * File:    mrmailbox.h
 * Authors: Björn Petersen
 * Purpose: MrMailbox represents a single mailbox, normally, typically is only
 *          one instance of this class present.
 *          Each mailbox is linked to an IMAP/POP3 account and uses a separate
 *          SQLite database for offline functionality and for mailbox-related
 *          settings.
 *
 ******************************************************************************/


#ifndef __MRMAILBOX_H__
#define __MRMAILBOX_H__
#ifdef __cplusplus
extern "C" {
#endif


#include <libetpan/libetpan.h> /* defines uint16_t etc. */
#include "mrsqlite3.h"
#include "mrchat.h"
#include "mrmsg.h"
#include "mrloginparam.h"
#include "mrimap.h"
#include "mrcontact.h"


typedef struct mrmailbox_t
{
	/* public read */
	mrloginparam_t* m_loginParam;

	/* private */
	mrimap_t*       m_imap;
	mrsqlite3_t*    m_sql;

} mrmailbox_t;


/* public */
mrmailbox_t*         mrmailbox_new                  ();
void                 mrmailbox_unref                (mrmailbox_t*);

/* public open/close a mailbox object, if the given file does not exist, it is created
and can be set up using SetConfig() and Connect() afterwards.
sth. like "~/file" won't work on all systems, if in doubt, use absolute paths for dbfile. */
int                  mrmailbox_open                 (mrmailbox_t*, const char* dbfile);
void                 mrmailbox_close                (mrmailbox_t*);

/* ImportSpec() imports data from EML-files. if `spec` is a folder, all EML-files are imported, if `spec` is a file,
a single EML-file is imported, if `spec` is NULL, the last import is done again (you may want to call Empty() before)
ImportFile() always imports a single file, publiuc */
int                  mrmailbox_import_spec          (mrmailbox_t*, const char* spec);
int                  mrmailbox_import_file          (mrmailbox_t*, const char* file);

/* empty all tables but leaves server configuration, public */
int                  mrmailbox_empty_tables         (mrmailbox_t*);

/* connect to the mailbox: errors are received asynchronously. public. */
int                  mrmailbox_connect              (mrmailbox_t*);
void                 mrmailbox_disconnect           (mrmailbox_t*);
int                  mrmailbox_fetch                (mrmailbox_t*);

/* iterate contacts. Public. */
size_t               mrmailbox_get_contact_cnt      (mrmailbox_t*);
mrcontact_t*         mrmailbox_get_contact_by_index (mrmailbox_t*, size_t i);

/* iterate chats. Public. */
size_t               mrmailbox_get_chat_cnt         (mrmailbox_t*);
mrchatlist_t*        mrmailbox_get_chats            (mrmailbox_t*); /* the result must be unref'd */
mrchat_t*            mrmailbox_get_chat_by_name     (mrmailbox_t*, const char* name); /* the result must be unref'd */
mrchat_t*            mrmailbox_get_chat_by_id       (mrmailbox_t*, uint32_t id); /* the result must be unref'd */

/* get messages (aka updates) in a given timestamp */
mrmsglist_t*         mrmailbox_get_messages         (mrmailbox_t*, time_t, time_t); /* the result must be unref'd */

/* handle configurations. Public. */
int                  mrmailbox_set_config           (mrmailbox_t*, const char* key, const char* value);
char*                mrmailbox_get_config           (mrmailbox_t*, const char* key, const char* def);
int32_t              mrmailbox_get_config_int       (mrmailbox_t*, const char* key, int32_t def);

/* Misc. Public. */
char*                mrmailbox_get_db_file          (mrmailbox_t*); /* the returned string must be free()'d, returns NULL on errors or if no database is open */
char*                mrmailbox_get_info             (mrmailbox_t*); /* multi-line output; the returned string must be free()'d, returns NULL on errors */

/* private */
void                 mrmailbox_receive_imf__        (mrmailbox_t*, const char* imf, size_t imf_len); /* when fetching messages, this normally results in calls to ReceiveImf(). CAVE: ReceiveImf() may be called from within a working thread! */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMAILBOX_H__ */

