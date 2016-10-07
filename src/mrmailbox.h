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
 * Purpose: mrmailbox_t represents a single mailbox, normally, typically only
 *          one instance of this class is present.
 *          Each mailbox is linked to an IMAP/POP3 account and uses a separate
 *          SQLite database for offline functionality and for mailbox-related
 *          settings.
 *
 *******************************************************************************
 *
 * NB: Objects returned by mrmailbox_t (or other classes) typically reflect
 * the state of the system when the objects are _created_ - treat them as if
 * they're strings. Eg. mrmsg_get_state() does _always_ return the state of the
 * time the objects is created.
 * If you want an _updated state_, you have to recreate the object reflecting
 * the message - or use methods that explcitly force reloading.
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
#include "mrchatlist.h"
#include "mrmsg.h"
#include "mrmsglist.h"
#include "mrcontact.h"
#include "mrcontactlist.h"
#include "mrloginparam.h"
#include "mrimap.h"
#include "mrpoortext.h"
#include "mrstock.h"


typedef struct mrmailbox_t
{
	/* members should be treated as library private */
	mrloginparam_t* m_loginParam;
	mrimap_t*       m_imap;
	mrsqlite3_t*    m_sql;
	char*           m_dbfile;
	char*           m_blobdir;
} mrmailbox_t;


/* mrmailbox_new() creates a new mailbox object.  After creation it is usually
opened, connected and mails are fetched; the the corresponding functions below.
After usage, the mailbox object must be freed using mrmailbox_unref(). */
mrmailbox_t*         mrmailbox_new                  ();
void                 mrmailbox_unref                (mrmailbox_t*);

/* open/close a mailbox object, if the given file does not exist, it is created
and can be set up using mrmailbox_set_config() afterwards.
sth. like "~/file" won't work on all systems, if in doubt, use absolute paths for dbfile.
for blobdir: the trailing slash is added by us, so if you want to avoid double slashes, do not add one. */
int                  mrmailbox_open                 (mrmailbox_t*, const char* dbfile, const char* blobdir);
void                 mrmailbox_close                (mrmailbox_t*);
int                  mrmailbox_is_open              (mrmailbox_t*);

/* ImportSpec() imports data from EML-files. if `spec` is a folder, all EML-files are imported, if `spec` is a file,
a single EML-file is imported, if `spec` is NULL, the last import is done again (you may want to call Empty() before)
ImportFile() always imports a single file, publiuc */
int                  mrmailbox_import_spec          (mrmailbox_t*, const char* spec);
int                  mrmailbox_import_file          (mrmailbox_t*, const char* file);

/* empty all tables but leaves server configuration. */
int                  mrmailbox_empty_tables         (mrmailbox_t*);

/* connect to the mailbox.  usually, at least here, mrmailbox will create a working thread. */
int                  mrmailbox_connect              (mrmailbox_t*);
void                 mrmailbox_disconnect           (mrmailbox_t*);
int                  mrmailbox_fetch                (mrmailbox_t*);

/* Get contacts. */
mrcontactlist_t*     mrmailbox_get_contactlist      (mrmailbox_t*);
mrcontact_t*         mrmailbox_get_contact_by_id    (mrmailbox_t*, uint32_t id);

/* Get chats. */
mrchatlist_t*        mrmailbox_get_chatlist         (mrmailbox_t*); /* the result must be unref'd */
mrchat_t*            mrmailbox_get_chat_by_id       (mrmailbox_t*, uint32_t id); /* the result must be unref'd */

/* Get messages - for a list, see mrchat_get_msglist() */
mrmsg_t*             mrmailbox_get_msg_by_id        (mrmailbox_t*, uint32_t id); /* the result must be unref'd */

/* Handle configurations. */
int                  mrmailbox_set_config           (mrmailbox_t*, const char* key, const char* value);
char*                mrmailbox_get_config           (mrmailbox_t*, const char* key, const char* def);
int32_t              mrmailbox_get_config_int       (mrmailbox_t*, const char* key, int32_t def);
mrloginparam_t*      mrmailbox_suggest_config       (mrmailbox_t*); /* the result must be unref'd */
int                  mrmailbox_is_configured        (mrmailbox_t*); /* just checks if at least e-mail and password are given, does not check if the connection works */

/* Misc. */
char*                mrmailbox_get_info             (mrmailbox_t*); /* multi-line output; the returned string must be free()'d, returns NULL on errors */


/*** library-private **********************************************************/

void                 mrmailbox_receive_imf_         (mrmailbox_t*, const char* imf, size_t imf_len); /* when fetching messages, this normally results in calls to ReceiveImf(). CAVE: ReceiveImf() may be called from within a working thread! */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMAILBOX_H__ */

