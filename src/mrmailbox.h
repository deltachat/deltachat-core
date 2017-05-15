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
 *******************************************************************************
 *
 * File:    mrmailbox.h
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
#include "mrcontact.h"
#include "mrpoortext.h"
#include "mrstock.h"
typedef struct mrmailbox_t mrmailbox_t;
typedef struct mrimap_t mrimap_t;
typedef struct mrsmtp_t mrsmtp_t;
typedef struct mre2ee_t mre2ee_t;
typedef struct mre2ee_driver_t mre2ee_driver_t;


#define MR_VERSION_MAJOR    0
#define MR_VERSION_MINOR    1
#define MR_VERSION_REVISION 38


/* Callback function that is called on updates, state changes etc. with one of the MR_EVENT_* codes
- The callback MAY be called from _any_ thread, not only the main/GUI thread!
- The callback MUST NOT call any mrmailbox_* and related functions unless stated otherwise!
- The callback SHOULD return _fast_, for GUI updates etc. you should
  post yourself an asynchronous message to your GUI thread.
- If not mentioned otherweise, the callback should return 0. */
typedef uintptr_t (*mrmailboxcb_t) (mrmailbox_t*, int event, uintptr_t data1, uintptr_t data2);

#define MR_EVENT_INFO                     100  /* Information, should not be reported, can be logged */
#define MR_EVENT_WARNING                  300  /* Warning, should not be reported, should be logged */
#define MR_EVENT_ERROR                    400  /* Error, must be reported to the user by a non-disturbing bubble or so. */

#define MR_EVENT_MSGS_CHANGED             2000 /* one or more messages changed for some reasons in the database - added or removed.  For added messages: data1=chat_id, data2=msg_id */
#define MR_EVENT_INCOMING_MSG             2005 /* For fresh messages from the INBOX, MR_EVENT_INCOMING_MSG is send; data1=chat_id, data2=msg_id */
#define MR_EVENT_MSG_DELIVERED            2010 /* a single message is send successfully (state changed from PENDING/SENDING to DELIVERED); data1=chat_id, data2=msg_id */
#define MR_EVENT_MSG_READ                 2015 /* a single message is read by the receiver (state changed from DELIVERED to READ); data1=chat_id, data2=msg_id */

#define MR_EVENT_CHAT_MODIFIED            2020 /* group name/image changed or members added/removed */

#define MR_EVENT_CONTACTS_CHANGED         2030 /* contact(s) created, renamed, blocked or deleted */

#define MR_EVENT_CONFIGURE_ENDED          2040 /* connection state changed, data1=0:failed-not-connected, 1:configured-and-connected */
#define MR_EVENT_CONFIGURE_PROGRESS       2041

/* Functions that should be provided by the frontends */
#define MR_EVENT_IS_ONLINE                2080
#define MR_EVENT_GET_STRING               2091 /* get a string from the frontend, data1=MR_STR_*, ret=string which will be free()'d by the backend */
#define MR_EVENT_GET_QUANTITY_STRING      2092 /* get a string from the frontend, data1=MR_STR_*, data2=quantity, ret=string which will free()'d by the backend */
#define MR_EVENT_HTTP_GET                 2100 /* synchronous http/https(!) call, data1=url, ret=content which will be free()'d by the backend, 0 on errors */
#define MR_EVENT_WAKE_LOCK                2110 /* acquire wakeLock (data1=1) or release it (data1=0), the backend does not make nested or unsynchronized calls */

/* Error codes */
#define MR_ERR_SELF_NOT_IN_GROUP  1
#define MR_ERR_NONETWORK          2


typedef struct mrmailbox_t
{
	uint32_t         m_magic; /* must be first*/

	/* the following members should be treated as library private */
	mrsqlite3_t*     m_sql;      /* != NULL */
	char*            m_dbfile;
	char*            m_blobdir;

	mrimap_t*        m_imap;     /* != NULL */
	mrsmtp_t*        m_smtp;     /* != NULL */

	pthread_t        m_job_thread;
	pthread_cond_t   m_job_cond;
	pthread_mutex_t  m_job_condmutex;
	int              m_job_condflag;
	int              m_job_do_exit;

	mre2ee_t*        m_e2ee;        /* may or may not be NULL, completely owned by mre2ee */
	mre2ee_driver_t* m_e2ee_driver; /* may or may not be NULL, completely owned by mre2ee_driver */

	mrmailboxcb_t    m_cb;
	void*            m_userData;

	uint32_t         m_cmdline_sel_chat_id;

	int              m_wake_lock;
	pthread_mutex_t  m_wake_lock_critical;

} mrmailbox_t;


/* mrmailbox_new() creates a new mailbox object.  After creation it is usually
opened, connected and mails are fetched; see the corresponding functions below.
After usage, the mailbox object must be freed using mrmailbox_unref(). */
mrmailbox_t*         mrmailbox_new                  (mrmailboxcb_t, void* userData);
void                 mrmailbox_unref                (mrmailbox_t*);


/* Open/close a mailbox database, if the given file does not exist, it is created
and can be set up using mrmailbox_set_config() afterwards.
sth. like "~/file" won't work on all systems, if in doubt, use absolute paths for dbfile.
for blobdir: the trailing slash is added by us, so if you want to avoid double slashes, do not add one.
If you give NULL as blobdir, "dbfile-blobs" is used. */
int                  mrmailbox_open                 (mrmailbox_t*, const char* dbfile, const char* blobdir);
void                 mrmailbox_close                (mrmailbox_t*);
int                  mrmailbox_is_open              (const mrmailbox_t*);


/* mrmailbox_configure_and_connect() configures and connects a mailbox.
- Before your call this function, you should set at least `addr` and `mail_pw`
  using mrmailbox_set_config().
- mrmailbox_configure_and_connect() returns immediately, configuration is done
  in another thread; when done, the event MR_EVENT_CONFIGURE_ENDED ist posted
- There is no need to call this every program start, the result is saved in the
  database.
- mrmailbox_configure_and_connect() should be called after any settings change. */
void                 mrmailbox_configure_and_connect(mrmailbox_t*);
void                 mrmailbox_configure_cancel     (mrmailbox_t*);
int                  mrmailbox_is_configured        (mrmailbox_t*);


/* Connect to the mailbox using the configured settings. normally, there is no
need to call mrmailbox_fetch() manually as we get push events from the IMAP server;
if this fails, we fallback to a smart pull-mode. */
void                 mrmailbox_connect              (mrmailbox_t*);
void                 mrmailbox_disconnect           (mrmailbox_t*);
int                  mrmailbox_fetch                (mrmailbox_t*);


/* restore old data from the IMAP server, not really implemented. */
int                  mrmailbox_restore              (mrmailbox_t*, time_t seconds_to_restore);


/* Handle chats. */
mrchatlist_t*        mrmailbox_get_chatlist              (mrmailbox_t*, const char* query); /* the result must be unref'd */
mrchat_t*            mrmailbox_get_chat                  (mrmailbox_t*, uint32_t chat_id); /* the result must be unref'd */
uint32_t             mrmailbox_get_chat_id_by_contact_id (mrmailbox_t*, uint32_t contact_id); /* does a chat with a given single user exist? */
uint32_t             mrmailbox_create_chat_by_contact_id (mrmailbox_t*, uint32_t contact_id); /* create a normal chat with a single user */
carray*              mrmailbox_get_chat_media            (mrmailbox_t*, uint32_t chat_id, int msg_type, int or_msg_type); /* returns message IDs, the result must be carray_free()'d */
carray*              mrmailbox_get_unseen_msgs           (mrmailbox_t*); /* returns message IDs, typically used for implementing notification summaries, the result must be free()'d */
int                  mrmailbox_delete_chat               (mrmailbox_t*, uint32_t chat_id); /* deletes the chat object, no messages are deleted (we do not so as we cannot distinguish between chat messages and normal mails) */


/* Get previous/next media of a given media message (imaging eg. a virtual playlist of all audio tracks in a chat).
If there is no previous/next media, 0 is returned. */
uint32_t             mrmailbox_get_next_media            (mrmailbox_t*, uint32_t curr_msg_id, int dir);


/* mrmailbox_get_chat_contacts() returns contact IDs, the result must be carray_free()'d.
- for normal chats, the function always returns exactly one contact MR_CONTACT_ID_SELF is _not_ returned.
- for group chats all members are returned, MR_CONTACT_ID_SELF is returned explicitly as it may happen that oneself gets removed from a still existing group
- for the deaddrop, all contacts are returned, MR_CONTACT_ID_SELF is not added */
carray*              mrmailbox_get_chat_contacts         (mrmailbox_t*, uint32_t chat_id);


/* Handle group chats. */
uint32_t             mrmailbox_create_group_chat         (mrmailbox_t*, const char* name);
int                  mrmailbox_is_contact_in_chat        (mrmailbox_t*, uint32_t chat_id, uint32_t contact_id);
int                  mrmailbox_add_contact_to_chat       (mrmailbox_t*, uint32_t chat_id, uint32_t contact_id);
int                  mrmailbox_remove_contact_from_chat  (mrmailbox_t*, uint32_t chat_id, uint32_t contact_id);
int                  mrmailbox_set_chat_name             (mrmailbox_t*, uint32_t chat_id, const char* name);


/* mrmailbox_get_chat_msgs() returns a view on a chat.
The function returns an array of message IDs, which must be carray_free()'d by the caller.
Optionally, some special markers added to the ID-array may help to implement virtual lists:
- If you add the flag MR_GCM_ADD_DAY_MARKER, the marker MR_MSG_ID_DAYMARKER will be added before each day (regarding the local timezone)
- If you specify marker1before, the id MR_MSG_ID_MARKER1 will be added just before the given ID.*/
#define MR_GCM_ADDDAYMARKER 0x01
carray* mrmailbox_get_chat_msgs (mrmailbox_t*, uint32_t chat_id, uint32_t flags, uint32_t marker1before);


/* Search messages containing the given query string.
Searching can be done globally (chat_id=0) or in a specified chat only (chat_id set).
- The function returns an array of messages IDs which must be carray_free()'d by the caller.
- If nothing can be found, the function returns NULL.  */
carray*  mrmailbox_search_msgs (mrmailbox_t*, uint32_t chat_id, const char* query);


/* Get messages - for a list, see mrchat_get_msglist() */
mrmsg_t*             mrmailbox_get_msg              (mrmailbox_t*, uint32_t msg_id); /* the result must be unref'd */
char*                mrmailbox_get_msg_info         (mrmailbox_t*, uint32_t msg_id); /* the result must be free()'d */
int                  mrmailbox_delete_msgs          (mrmailbox_t*, const uint32_t* msg_ids, int msg_cnt);
int                  mrmailbox_forward_msgs         (mrmailbox_t*, const uint32_t* msg_ids, int msg_cnt, uint32_t chat_id);
int                  mrmailbox_markseen_msg         (mrmailbox_t*, uint32_t msg_id);
int                  mrmailbox_markseen_chat        (mrmailbox_t*, uint32_t chat_id);


/* handle contacts. */
carray*              mrmailbox_get_known_contacts   (mrmailbox_t*, const char* query); /* returns known and unblocked contacts, the result must be carray_free()'d */
mrcontact_t*         mrmailbox_get_contact          (mrmailbox_t*, uint32_t contact_id);
uint32_t             mrmailbox_create_contact       (mrmailbox_t*, const char* name, const char* addr);
int                  mrmailbox_get_blocked_count    (mrmailbox_t*);
carray*              mrmailbox_get_blocked_contacts (mrmailbox_t*);
int                  mrmailbox_block_contact        (mrmailbox_t*, uint32_t contact_id, int block); /* may or may not result in a MR_EVENT_BLOCKING_CHANGED event */
char*                mrmailbox_get_contact_encrinfo (mrmailbox_t*, uint32_t contact_id);
int                  mrmailbox_delete_contact       (mrmailbox_t*, uint32_t contact_id);


/* Handle configurations as:
- addr
- mail_server, mail_user, mail_pw, mail_port,
- send_server, send_user, send_pw, send_port, server_flags */
int                  mrmailbox_set_config           (mrmailbox_t*, const char* key, const char* value);
char*                mrmailbox_get_config           (mrmailbox_t*, const char* key, const char* def);
int                  mrmailbox_set_config_int       (mrmailbox_t*, const char* key, int32_t value);
int32_t              mrmailbox_get_config_int       (mrmailbox_t*, const char* key, int32_t def);


/* ImportSpec() imports data from EML-files. if `spec` is a folder, all EML-files are imported, if `spec` is a file,
a single EML-file is imported, if `spec` is NULL, the last import is done again (you may want to call Empty() before)
ImportFile() always imports a single file, publiuc */
int                  mrmailbox_import_spec          (mrmailbox_t*, const char* spec);
int                  mrmailbox_import_file          (mrmailbox_t*, const char* file);


/* Misc. */
char*                mrmailbox_get_info             (mrmailbox_t*); /* multi-line output; the returned string must be free()'d, returns NULL on errors */
int                  mrmailbox_empty_tables         (mrmailbox_t*); /* empty all tables but leaves server configuration. */
int                  mrmailbox_add_address_book     (mrmailbox_t*, const char*); /* format: Name one\nAddress one\nName two\Address two */
char*                mrmailbox_get_version_str      (void); /* the return value must be free()'d */
void                 mrmailbox_kill_all_jobs        (mrmailbox_t*); /* kill all pending jobs, pending messages are cancelled. */


/* The library tries itself to stay alive. For this purpose there is an additional
"heartbeat" thread that checks if the IDLE-thread is up and working. This check is done about every minute.
However, depending on the operating system, this thread may be delayed or stopped, if this is the case you can
force additional checks manually by just calling mrmailbox_heartbeat() about every minute.
If in doubt, call this function too often, not too less :-) */
void                 mrmailbox_heartbeat            (mrmailbox_t*);

/*** library-private **********************************************************/

void                 mrmailbox_connect_to_imap      (mrmailbox_t*, mrjob_t*);
void                 mrmailbox_wake_lock            (mrmailbox_t*);
void                 mrmailbox_wake_unlock          (mrmailbox_t*);

/* logging */
void mrmailbox_log_error           (mrmailbox_t*, int code, const char* msg, ...);
void mrmailbox_log_error_if        (int* condition, mrmailbox_t*, int code, const char* msg, ...);
void mrmailbox_log_warning         (mrmailbox_t*, int code, const char* msg, ...);
void mrmailbox_log_info            (mrmailbox_t*, int code, const char* msg, ...);
void mrmailbox_log_vprintf         (mrmailbox_t*, int event, int code, const char* msg, va_list);

int  mrmailbox_get_thread_index    (void);


#define MR_CHAT_PREFIX      "Chat:"      /* you MUST NOT modify this or the following strings */
#define MR_CHATS_FOLDER     "Chats"      /* if we want to support Gma'l-labels - "Chats" is a reserved word for Gma'l */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMAILBOX_H__ */
