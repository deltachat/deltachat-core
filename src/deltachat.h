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


#ifndef __DELTACHAT_H__
#define __DELTACHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <time.h>


#define DC_VERSION_MAJOR    0
#define DC_VERSION_MINOR    18
#define DC_VERSION_REVISION 0


/**
 * @mainpage Getting started
 *
 * This document describes how to handle the Delta Chat core library.
 * For general information about Delta Chat itself, see <https://delta.chat> and <https://github.com/deltachat>.
 *
 * Let's start.
 *
 * First of all, you have to define a function that is called by the library on
 * specific events (eg. when the configuration is done or when fresh messages arrive).
 * Your function should look like the following:
 *
 * ```
 * #include <deltachat.h>
 *
 * uintptr_t my_delta_handler(dc_context_t* mailbox, int event, uintptr_t data1, uintptr_t data2)
 * {
 *     return 0; // for unhandled events, it is always safe to return 0
 * }
 * ```
 *
 * After that, you can create and configure a dc_context_t object easily as follows:
 *
 * ```
 * dc_context_t* mailbox = dc_context_new(my_delta_handler, NULL, NULL);
 *
 * dc_set_config(mailbox, "addr",    "alice@delta.chat"); // use some real test credentials here
 * dc_set_config(mailbox, "mail_pw", "***");
 *
 * dc_configure(mailbox);
 * ```
 *
 * dc_configure() may take a while and saves the result in
 * the database. On subsequent starts, calling this function is not needed.
 *
 * However, now you can send your first message:
 *
 * ```
 * uint32_t contact_id = dc_create_contact(mailbox, NULL, "bob@delta.chat"); // use a real testing address here
 * uint32_t chat_id    = dc_create_chat_by_contact_id(mailbox, contact_id);
 *
 * dc_send_text_msg(mailbox, chat_id, "Hi, here is my first message!");
 * ```
 *
 * Now, go to the testing address (bob) and you should have received a normal email.
 * Answer this email in any email program with "Got it!" and you will get the message from delta as follows:
 *
 * ```
 * dc_perform_imap_fetch();
 *
 * dc_array_t* msglist = dc_get_chat_msgs(mailbox, chat_id, 0, 0);
 * for( size_t i = 0; i < dc_array_get_cnt(msglist); i++ )
 * {
 *     uint32_t  msg_id = dc_array_get_id(msglist, i);
 *     dc_msg_t* msg    = dc_get_msg(mailbox, msg_id);
 *     char*     text   = dc_msg_get_text(msg);
 *
 *     printf("message %i: %s\n", i+1, text);
 *
 *     free(text);
 *     dc_msg_unref(msg);
 * }
 * dc_array_unref(msglist);
 * ```
 *
 * This will output the following two lines:
 *
 * ```
 * Message 1: Hi, here is my first message!
 * Message 2: Got it!
 * ```
 *
 *
 * ## Class reference
 *
 * For a class reference, see the "Classes" link atop.
 *
 *
 * ## Further hints
 *
 * Here are some additional, unsorted hints that may be useful.
 * If you need any further assistance, please do not hesitate to contact us at <r10s@b44t.com>.
 *
 * - Two underscores at the end of a function-name may be a _hint_, that this
 *   function does no resource locking. Such functions must not be used.
 *
 * - For objects, C-structures are used.  If not mentioned otherwise, you can
 *   read the members here directly.
 *
 * - For `get`-functions, you have to unref the return value in some way.
 *
 * - Strings in function arguments or return values are usually UTF-8 encoded
 *
 * - Threads are implemented using POSIX threads (`pthread_*` functions)
 *
 * - The issue-tracker for the core library is here: <https://github.com/deltachat/deltachat-core/issues>
 *
 * The following points are important mainly for the authors of the library itself:
 *
 * - For indentation, use tabs.  Alignments that are not placed at the beginning
 *   of a line should be done with spaces.
 *
 * - For padding between functions, classes etc. use 2 empty lines
 *
 * - Source files are encoded as UTF-8 with Unix line endings (a simple `LF`, `0x0A` or
 *   `\n`)
 *
 * Please keep in mind, that your derived work must be released under a
 * **GPL-compatible licence**.  For details, please have a look at the [LICENSE file](https://github.com/deltachat/deltachat-core/blob/master/LICENSE) accompanying the source code.
 *
 * See you.
 */


/**
 * @class dc_context_t
 *
 * An object representing a single mailbox.
 *
 * Each mailbox is linked to an IMAP/POP3 account and uses a separate
 * SQLite database for offline functionality and for mailbox-related
 * settings.
 */
typedef struct _dc_context  dc_context_t;
typedef struct _dc_array    dc_array_t;
typedef struct _dc_chatlist dc_chatlist_t;
typedef struct _dc_chat     dc_chat_t;
typedef struct _dc_msg      dc_msg_t;
typedef struct _dc_contact  dc_contact_t;
typedef struct _dc_lot      dc_lot_t;


/**
 * Callback function that should be given to dc_context_new().
 *
 * @memberof dc_context_t
 *
 * @param context The context object as returned by dc_context_new().
 *
 * @param event one of the DC_EVENT_* constants as defined in dc_event.h
 *
 * @param data1 depends on the event parameter
 *
 * @param data2 depends on the event parameter
 *
 * @return return 0 unless stated otherwise in the event parameter documentation
 */
typedef uintptr_t (*dc_callback_t) (dc_context_t*, int event, uintptr_t data1, uintptr_t data2);


// create/open/config/information
dc_context_t*   dc_context_new               (dc_callback_t, void* userdata, const char* os_name);
void            dc_context_unref             (dc_context_t*);
void*           dc_get_userdata              (dc_context_t*);

int             dc_open                      (dc_context_t*, const char* dbfile, const char* blobdir);
void            dc_close                     (dc_context_t*);
int             dc_is_open                   (const dc_context_t*);
char*           dc_get_blobdir               (dc_context_t*);

int             dc_set_config                (dc_context_t*, const char* key, const char* value);
char*           dc_get_config                (dc_context_t*, const char* key, const char* def);
int             dc_set_config_int            (dc_context_t*, const char* key, int32_t value);
int32_t         dc_get_config_int            (dc_context_t*, const char* key, int32_t def);
char*           dc_get_info                  (dc_context_t*);
char*           dc_get_version_str           (void);


// connect
void            dc_configure                 (dc_context_t*);
int             dc_is_configured             (dc_context_t*);

void            dc_perform_imap_jobs         (dc_context_t*);
void            dc_perform_imap_fetch        (dc_context_t*);
void            dc_perform_imap_idle         (dc_context_t*);
void            dc_interrupt_imap_idle       (dc_context_t*);

void            dc_perform_smtp_jobs         (dc_context_t*);
void            dc_perform_smtp_idle         (dc_context_t*);
void            dc_interrupt_smtp_idle       (dc_context_t*);


// handle chatlists
#define         DC_GCL_ARCHIVED_ONLY         0x01
#define         DC_GCL_NO_SPECIALS           0x02
dc_chatlist_t*  dc_get_chatlist              (dc_context_t*, int flags, const char* query_str, uint32_t query_id);


// handle chats
uint32_t        dc_create_chat_by_msg_id     (dc_context_t*, uint32_t contact_id);
uint32_t        dc_create_chat_by_contact_id (dc_context_t*, uint32_t contact_id);
uint32_t        dc_get_chat_id_by_contact_id (dc_context_t*, uint32_t contact_id);

uint32_t        dc_send_text_msg             (dc_context_t*, uint32_t chat_id, const char* text_to_send);
uint32_t        dc_send_image_msg            (dc_context_t*, uint32_t chat_id, const char* file, const char* filemime, int width, int height);
uint32_t        dc_send_video_msg            (dc_context_t*, uint32_t chat_id, const char* file, const char* filemime, int width, int height, int duration);
uint32_t        dc_send_voice_msg            (dc_context_t*, uint32_t chat_id, const char* file, const char* filemime, int duration);
uint32_t        dc_send_audio_msg            (dc_context_t*, uint32_t chat_id, const char* file, const char* filemime, int duration, const char* author, const char* trackname);
uint32_t        dc_send_file_msg             (dc_context_t*, uint32_t chat_id, const char* file, const char* filemime);
uint32_t        dc_send_vcard_msg            (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
void            dc_set_draft                 (dc_context_t*, uint32_t chat_id, const char*);

#define         DC_GCM_ADDDAYMARKER          0x01
dc_array_t*     dc_get_chat_msgs             (dc_context_t*, uint32_t chat_id, uint32_t flags, uint32_t marker1before);
int             dc_get_total_msg_count       (dc_context_t*, uint32_t chat_id);
int             dc_get_fresh_msg_count       (dc_context_t*, uint32_t chat_id);
dc_array_t*     dc_get_fresh_msgs            (dc_context_t*);
void            dc_marknoticed_chat          (dc_context_t*, uint32_t chat_id);
dc_array_t*     dc_get_chat_media            (dc_context_t*, uint32_t chat_id, int msg_type, int or_msg_type);
uint32_t        dc_get_next_media            (dc_context_t*, uint32_t curr_msg_id, int dir);

void            dc_archive_chat              (dc_context_t*, uint32_t chat_id, int archive);
void            dc_delete_chat               (dc_context_t*, uint32_t chat_id);

dc_array_t*     dc_get_chat_contacts         (dc_context_t*, uint32_t chat_id);
dc_array_t*     dc_search_msgs               (dc_context_t*, uint32_t chat_id, const char* query);

dc_chat_t*      dc_get_chat                  (dc_context_t*, uint32_t chat_id);


// handle group chats
uint32_t        dc_create_group_chat         (dc_context_t*, int verified, const char* name);
int             dc_is_contact_in_chat        (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
int             dc_add_contact_to_chat       (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
int             dc_remove_contact_from_chat  (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
int             dc_set_chat_name             (dc_context_t*, uint32_t chat_id, const char* name);
int             dc_set_chat_profile_image    (dc_context_t*, uint32_t chat_id, const char* image);


// handle messages
char*           dc_get_msg_info              (dc_context_t*, uint32_t msg_id);
void            dc_delete_msgs               (dc_context_t*, const uint32_t* msg_ids, int msg_cnt);
void            dc_forward_msgs              (dc_context_t*, const uint32_t* msg_ids, int msg_cnt, uint32_t chat_id);
void            dc_marknoticed_contact       (dc_context_t*, uint32_t contact_id);
void            dc_markseen_msgs             (dc_context_t*, const uint32_t* msg_ids, int msg_cnt);
void            dc_star_msgs                 (dc_context_t*, const uint32_t* msg_ids, int msg_cnt, int star);
dc_msg_t*       dc_get_msg                   (dc_context_t*, uint32_t msg_id);


// handle contacts
uint32_t        dc_create_contact            (dc_context_t*, const char* name, const char* addr);
int             dc_add_address_book          (dc_context_t*, const char*);

#define         DC_GCL_VERIFIED_ONLY         0x01
#define         DC_GCL_ADD_SELF              0x02
dc_array_t*     dc_get_contacts              (dc_context_t*, uint32_t flags, const char* query);

int             dc_get_blocked_count         (dc_context_t*);
dc_array_t*     dc_get_blocked_contacts      (dc_context_t*);
void            dc_block_contact             (dc_context_t*, uint32_t contact_id, int block);
char*           dc_get_contact_encrinfo      (dc_context_t*, uint32_t contact_id);
int             dc_delete_contact            (dc_context_t*, uint32_t contact_id);
dc_contact_t*   dc_get_contact               (dc_context_t*, uint32_t contact_id);


// import/export and tools
#define         DC_IMEX_EXPORT_SELF_KEYS      1 // param1 is a directory where the keys are written to
#define         DC_IMEX_IMPORT_SELF_KEYS      2 // param1 is a directory where the keys are searched in and read from
#define         DC_IMEX_EXPORT_BACKUP        11 // param1 is a directory where the backup is written to
#define         DC_IMEX_IMPORT_BACKUP        12 // param1 is the file with the backup to import
int             dc_imex                      (dc_context_t*, int what, const char* param1, const char* param2);
char*           dc_imex_has_backup           (dc_context_t*, const char* dir);
int             dc_check_password            (dc_context_t*, const char* pw);
char*           dc_initiate_key_transfer     (dc_context_t*);
int             dc_continue_key_transfer     (dc_context_t*, uint32_t msg_id, const char* setup_code);
void            dc_stop_ongoing_process      (dc_context_t*);


// out-of-band verification
#define         DC_QR_ASK_VERIFYCONTACT      200 // id=contact
#define         DC_QR_ASK_VERIFYGROUP        202 // text1=groupname
#define         DC_QR_FPR_OK                 210 // id=contact
#define         DC_QR_FPR_MISMATCH           220 // id=contact
#define         DC_QR_FPR_WITHOUT_ADDR       230 // test1=formatted fingerprint
#define         DC_QR_ADDR                   320 // id=contact
#define         DC_QR_TEXT                   330 // text1=text
#define         DC_QR_URL                    332 // text1=text
#define         DC_QR_ERROR                  400 // text1=error string
dc_lot_t*       dc_check_qr                  (dc_context_t*, const char* qr);
char*           dc_get_securejoin_qr         (dc_context_t*, uint32_t chat_id);
uint32_t        dc_join_securejoin           (dc_context_t*, const char* qr);


/**
 * @class dc_array_t
 *
 * An object containing a simple array.
 * This object is used in several placed where functions need to return an array.
 * The items of the array are typically IDs.
 * To free an array object, use dc_array_unref().
 */
typedef struct _dc_array dc_array_t;


dc_array_t*      dc_array_new                (dc_context_t*, size_t initsize);
void             dc_array_empty              (dc_array_t*);
void             dc_array_unref              (dc_array_t*);

void             dc_array_add_uint           (dc_array_t*, uintptr_t);
void             dc_array_add_id             (dc_array_t*, uint32_t);
void             dc_array_add_ptr            (dc_array_t*, void*);

size_t           dc_array_get_cnt            (const dc_array_t*);
uintptr_t        dc_array_get_uint           (const dc_array_t*, size_t index);
uint32_t         dc_array_get_id             (const dc_array_t*, size_t index);
void*            dc_array_get_ptr            (const dc_array_t*, size_t index);

int              dc_array_search_id          (const dc_array_t*, uint32_t needle, size_t* indx);
const uintptr_t* dc_array_get_raw            (const dc_array_t*);


/**
 * @class dc_chatlist_t
 *
 * An object representing a single chatlist in memory.
 * Chatlist objects contain chat IDs and, if possible, message IDs belonging to them.
 * Chatlist objects are created eg. using dc_get_chatlist().
 * The chatlist object is not updated.  If you want an update, you have to recreate
 * the object.
 */
typedef struct _dc_chatlist dc_chatlist_t;


dc_chatlist_t*   dc_chatlist_new             (dc_context_t*);
void             dc_chatlist_empty           (dc_chatlist_t*);
void             dc_chatlist_unref           (dc_chatlist_t*);
size_t           dc_chatlist_get_cnt         (dc_chatlist_t*);
uint32_t         dc_chatlist_get_chat_id     (dc_chatlist_t*, size_t index);
uint32_t         dc_chatlist_get_msg_id      (dc_chatlist_t*, size_t index);
dc_lot_t*        dc_chatlist_get_summary     (dc_chatlist_t*, size_t index, dc_chat_t*);
dc_context_t*    dc_chatlist_get_context     (dc_chatlist_t*);


/**
 * @class dc_chat_t
 *
 * An object representing a single chat in memory. Chat objects are created using eg. dc_get_chat() and
 * are not updated on database changes;  if you want an update, you have to recreate the
 * object.
 */
typedef struct _dc_chat dc_chat_t;


#define         DC_CHAT_ID_DEADDROP          1 // virtual chat showing all messages belonging to chats flagged with chats.blocked=2
#define         DC_CHAT_ID_TRASH             3 // messages that should be deleted get this chat_id; the messages are deleted from the working thread later then. This is also needed as rfc724_mid should be preset as long as the message is not deleted on the server (otherwise it is downloaded again)
#define         DC_CHAT_ID_MSGS_IN_CREATION  4 // a message is just in creation but not yet assigned to a chat (eg. we may need the message ID to set up blobs; this avoids unready message to be sent and shown)
#define         DC_CHAT_ID_STARRED           5 // virtual chat showing all messages flagged with msgs.starred=2
#define         DC_CHAT_ID_ARCHIVED_LINK     6 // only an indicator in a chatlist
#define         DC_CHAT_ID_LAST_SPECIAL      9 // larger chat IDs are "real" chats, their messages are "real" messages.


#define         DC_CHAT_TYPE_UNDEFINED       0
#define         DC_CHAT_TYPE_SINGLE          100
#define         DC_CHAT_TYPE_GROUP           120
#define         DC_CHAT_TYPE_VERIFIED_GROUP  130


dc_chat_t*      dc_chat_new                  (dc_context_t*);
void            dc_chat_empty                (dc_chat_t*);
void            dc_chat_unref                (dc_chat_t*);

uint32_t        dc_chat_get_id               (dc_chat_t*);
int             dc_chat_get_type             (dc_chat_t*);
char*           dc_chat_get_name             (dc_chat_t*);
char*           dc_chat_get_subtitle         (dc_chat_t*);
char*           dc_chat_get_profile_image    (dc_chat_t*);
char*           dc_chat_get_draft            (dc_chat_t*);
time_t          dc_chat_get_draft_timestamp  (dc_chat_t*);
int             dc_chat_get_archived         (dc_chat_t*);
int             dc_chat_is_unpromoted        (dc_chat_t*);
int             dc_chat_is_self_talk         (dc_chat_t*);
int             dc_chat_is_verified          (dc_chat_t*);


/**
 * @class dc_msg_t
 *
 * An object representing a single message in memory.  The message
 * object is not updated.  If you want an update, you have to recreate the
 * object.
 */
typedef struct _dc_msg dc_msg_t;


#define         DC_MSG_ID_MARKER1            1
#define         DC_MSG_ID_DAYMARKER          9
#define         DC_MSG_ID_LAST_SPECIAL       9


#define         DC_MSG_UNDEFINED             0
#define         DC_MSG_TEXT                  10
#define         DC_MSG_IMAGE                 20 // m_param may contain FILE, WIDTH, HEIGHT
#define         DC_MSG_GIF                   21 //   - " -
#define         DC_MSG_AUDIO                 40 // m_param may contain FILE, DURATION
#define         DC_MSG_VOICE                 41 //   - " -
#define         DC_MSG_VIDEO                 50 // m_param may contain FILE, WIDTH, HEIGHT, DURATION
#define         DC_MSG_FILE                  60 // m_param may contain FILE


#define         DC_STATE_UNDEFINED           0
#define         DC_STATE_IN_FRESH            10
#define         DC_STATE_IN_NOTICED          13
#define         DC_STATE_IN_SEEN             16
#define         DC_STATE_OUT_PENDING         20
#define         DC_STATE_OUT_ERROR           24
#define         DC_STATE_OUT_DELIVERED       26 // to check if a mail was sent, use dc_msg_is_sent()
#define         DC_STATE_OUT_MDN_RCVD        28


#define         DC_MAX_GET_TEXT_LEN          30000 // approx. max. lenght returned by dc_msg_get_text()
#define         DC_MAX_GET_INFO_LEN          100000 // approx. max. lenght returned by dc_get_msg_info()


dc_msg_t*       dc_msg_new                   ();
void            dc_msg_unref                 (dc_msg_t*);
void            dc_msg_empty                 (dc_msg_t*);
uint32_t        dc_msg_get_id                (const dc_msg_t*);
uint32_t        dc_msg_get_from_id           (const dc_msg_t*);
uint32_t        dc_msg_get_chat_id           (const dc_msg_t*);
int             dc_msg_get_type              (const dc_msg_t*);
int             dc_msg_get_state             (const dc_msg_t*);
time_t          dc_msg_get_timestamp         (const dc_msg_t*);
char*           dc_msg_get_text              (const dc_msg_t*);
char*           dc_msg_get_file              (const dc_msg_t*);
char*           dc_msg_get_filename          (const dc_msg_t*);
char*           dc_msg_get_filemime          (const dc_msg_t*);
uint64_t        dc_msg_get_filebytes         (const dc_msg_t*);
dc_lot_t*       dc_msg_get_mediainfo         (const dc_msg_t*);
int             dc_msg_get_width             (const dc_msg_t*);
int             dc_msg_get_height            (const dc_msg_t*);
int             dc_msg_get_duration          (const dc_msg_t*);
int             dc_msg_get_showpadlock       (const dc_msg_t*);
dc_lot_t*       dc_msg_get_summary           (const dc_msg_t*, const dc_chat_t*);
char*           dc_msg_get_summarytext       (const dc_msg_t*, int approx_characters);
int             dc_msg_is_sent               (const dc_msg_t*);
int             dc_msg_is_starred            (const dc_msg_t*);
int             dc_msg_is_forwarded          (const dc_msg_t*);
int             dc_msg_is_info               (const dc_msg_t*);
int             dc_msg_is_increation         (const dc_msg_t*);
int             dc_msg_is_setupmessage       (const dc_msg_t*);
char*           dc_msg_get_setupcodebegin    (const dc_msg_t*);
void            dc_msg_latefiling_mediasize  (dc_msg_t*, int width, int height, int duration);


/**
 * @class dc_contact_t
 *
 * An object representing a single contact in memory.
 * The contact object is not updated.  If you want an update, you have to recreate
 * the object.
 */
typedef struct _dc_contact dc_contact_t;

#define         DC_CONTACT_ID_SELF           1
#define         DC_CONTACT_ID_DEVICE         2
#define         DC_CONTACT_ID_LAST_SPECIAL   9


dc_contact_t*   dc_contact_new               (dc_context_t*); /* the returned pointer is ref'd and must be unref'd after usage */
void            dc_contact_empty             (dc_contact_t*);
void            dc_contact_unref             (dc_contact_t*);
uint32_t        dc_contact_get_id            (const dc_contact_t*);
char*           dc_contact_get_addr          (const dc_contact_t*);
char*           dc_contact_get_name          (const dc_contact_t*);
char*           dc_contact_get_display_name  (const dc_contact_t*);
char*           dc_contact_get_name_n_addr   (const dc_contact_t*);
char*           dc_contact_get_first_name    (const dc_contact_t*);
int             dc_contact_is_blocked        (const dc_contact_t*);
int             dc_contact_is_verified       (const dc_contact_t*);


/**
 * @class dc_lot_t
 *
 * An object containing a set of values.  The meaning of the values is defined by the function returning the set object.
 * Set objects are created eg. by dc_chatlist_get_summary(), dc_msg_get_summary() or by dc_msg_get_mediainfo().
 *
 * NB: _Lot_ is used in the meaning _heap_ here.
 */
typedef struct _dc_lot dc_lot_t;


#define         DC_TEXT1_DRAFT     1
#define         DC_TEXT1_USERNAME  2
#define         DC_TEXT1_SELF      3


dc_lot_t*       dc_lot_new               ();
void            dc_lot_empty             (dc_lot_t*);
void            dc_lot_unref             (dc_lot_t*);
char*           dc_lot_get_text1         (dc_lot_t*);
char*           dc_lot_get_text2         (dc_lot_t*);
int             dc_lot_get_text1_meaning (dc_lot_t*);
int             dc_lot_get_state         (dc_lot_t*);
uint32_t        dc_lot_get_id            (dc_lot_t*);
time_t          dc_lot_get_timestamp     (dc_lot_t*);


#include "dc_event.h"
#include "dc_error.h"


#ifdef __cplusplus
}
#endif
#endif // __DELTACHAT_H__

