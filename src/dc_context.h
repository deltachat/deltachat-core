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


#ifndef __DC_CONTEXT_H__
#define __DC_CONTEXT_H__
#ifdef __cplusplus
extern "C" {
#endif


/* Includes that are used frequently.  This file may also be used to create predefined headers. */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <libetpan/libetpan.h>
#include "deltachat.h"
#include "dc_sqlite3.h"
#include "dc_tools.h"
#include "dc_strbuilder.h"
#include "dc_strencode.h"
#include "dc_param.h"
#include "dc_stock.h"
#include "dc_array.h"
#include "dc_chat.h"
#include "dc_chatlist.h"
#include "dc_lot.h"
#include "dc_msg.h"
#include "dc_contact.h"


typedef struct dc_imap_t       dc_imap_t;
typedef struct dc_smtp_t       dc_smtp_t;
typedef struct dc_sqlite3_t    dc_sqlite3_t;
typedef struct dc_job_t        dc_job_t;
typedef struct dc_mimeparser_t dc_mimeparser_t;
typedef struct dc_hash_t       dc_hash_t;


/** Structure behind dc_context_t */
struct _dc_context
{
	/** @privatesection */
	#define          DC_CONTEXT_MAGIC         0x11a11807
	uint32_t         m_magic;                 /**< @private */

	void*            m_userdata;              /**< Use data, may be used for any purpose. The same pointer as given to dc_context_new(), may be used by the caller for any purpose. */

	char*            m_dbfile;                /**< The database file. This is the file given to dc_context_new(). */
	char*            m_blobdir;               /**< Full path of the blob directory. This is the directory given to dc_context_new() or a directory in the same directory as dc_context_t::m_dbfile. */

	dc_sqlite3_t*    m_sql;                   /**< Internal SQL object, never NULL */

	dc_imap_t*       m_imap;                  /**< Internal IMAP object, never NULL */
	pthread_mutex_t  m_imapidle_condmutex;
	int              m_perform_imap_jobs_needed;

	dc_smtp_t*       m_smtp;                  /**< Internal SMTP object, never NULL */
	pthread_cond_t   m_smtpidle_cond;
	pthread_mutex_t  m_smtpidle_condmutex;
	int              m_smtpidle_condflag;
	int              m_smtpidle_suspend;
	int              m_smtpidle_in_idleing;
	#define          DC_JOBS_NEEDED_AT_ONCE   1
	#define          DC_JOBS_NEEDED_AVOID_DOS 2
	int              m_perform_smtp_jobs_needed;

	dc_callback_t    m_cb;                    /**< Internal */

	char*            m_os_name;               /**< Internal, may be NULL */

	uint32_t         m_cmdline_sel_chat_id;   /**< Internal */

	int              m_e2ee_enabled;          /**< Internal */

	#define          DC_LOG_RINGBUF_SIZE 200
	pthread_mutex_t  m_log_ringbuf_critical;  /**< Internal */
	char*            m_log_ringbuf[DC_LOG_RINGBUF_SIZE];
	                                          /**< Internal */
	time_t           m_log_ringbuf_times[DC_LOG_RINGBUF_SIZE];
	                                          /**< Internal */
	int              m_log_ringbuf_pos;       /**< Internal. The oldest position resp. the position that is overwritten next */

	// QR code scanning (view from Bob, the joiner)
	#define         DC_VC_AUTH_REQUIRED     2
	#define         DC_VC_CONTACT_CONFIRM   6
	int             m_bob_expects;
	#define         DC_BOB_ERROR       0
	#define         DC_BOB_SUCCESS     1
	int             m_bobs_status;
	dc_lot_t*       m_bobs_qr_scan;
	pthread_mutex_t m_bobs_qr_critical;

	// time smearing - to keep messages in order, we may modify the time by some seconds
	time_t          m_last_smeared_timestamp;
	pthread_mutex_t m_smear_critical;

	// handling ongoing processes initiated by the user
	int             m_ongoing_running;
	int             m_shall_stop_ongoing;
};


/* logging and error handling */
void            dc_log_error         (dc_context_t*, int code, const char* msg, ...);
void            dc_log_error_if      (int* condition, dc_context_t*, int code, const char* msg, ...);
void            dc_log_warning       (dc_context_t*, int code, const char* msg, ...);
void            dc_log_info          (dc_context_t*, int code, const char* msg, ...);


/* misc.*/
void            dc_receive_imf                             (dc_context_t*, const char* imf_raw_not_terminated, size_t imf_raw_bytes, const char* server_folder, uint32_t server_uid, uint32_t flags);
uint32_t        dc_send_msg_object                         (dc_context_t*, uint32_t chat_id, dc_msg_t*);
int             dc_get_archived_count                      (dc_context_t*);
size_t          dc_get_real_contact_cnt                    (dc_context_t*);
uint32_t        dc_add_or_lookup_contact                   (dc_context_t*, const char* display_name /*can be NULL*/, const char* addr_spec, int origin, int* sth_modified);
int             dc_get_contact_origin                      (dc_context_t*, uint32_t id, int* ret_blocked);
int             dc_is_contact_blocked                      (dc_context_t*, uint32_t id);
int             dc_real_contact_exists                     (dc_context_t*, uint32_t id);
int             dc_contact_addr_equals                     (dc_context_t*, uint32_t contact_id, const char* other_addr);
void            dc_scaleup_contact_origin                  (dc_context_t*, uint32_t contact_id, int origin);
void            dc_unarchive_chat                          (dc_context_t*, uint32_t chat_id);
size_t          dc_get_chat_cnt                            (dc_context_t*);
void            dc_block_chat                              (dc_context_t*, uint32_t chat_id, int new_blocking);
void            dc_unblock_chat                            (dc_context_t*, uint32_t chat_id);
void            dc_create_or_lookup_nchat_by_contact_id    (dc_context_t*, uint32_t contact_id, int create_blocked, uint32_t* ret_chat_id, int* ret_chat_blocked);
void            dc_lookup_real_nchat_by_contact_id         (dc_context_t*, uint32_t contact_id, uint32_t* ret_chat_id, int* ret_chat_blocked);
uint32_t        dc_get_last_deaddrop_fresh_msg             (dc_context_t*);
int             dc_add_to_chat_contacts_table              (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
int             dc_is_contact_in_chat                      (dc_context_t*, uint32_t chat_id, uint32_t contact_id);
int             dc_get_chat_contact_count                  (dc_context_t*, uint32_t chat_id);
int             dc_is_group_explicitly_left                (dc_context_t*, const char* grpid);
void            dc_set_group_explicitly_left               (dc_context_t*, const char* grpid);
size_t          dc_get_real_msg_cnt                        (dc_context_t*); /* the number of messages assigned to real chat (!=deaddrop, !=trash) */
size_t          dc_get_deaddrop_msg_cnt                    (dc_context_t*);
int             dc_rfc724_mid_cnt                          (dc_context_t*, const char* rfc724_mid);
uint32_t        dc_rfc724_mid_exists__                     (dc_context_t*, const char* rfc724_mid, char** ret_server_folder, uint32_t* ret_server_uid);
void            dc_update_server_uid                       (dc_context_t*, const char* rfc724_mid, const char* server_folder, uint32_t server_uid);
void            dc_update_msg_chat_id                      (dc_context_t*, uint32_t msg_id, uint32_t chat_id);
void            dc_update_msg_state                        (dc_context_t*, uint32_t msg_id, int state);
int             dc_mdn_from_ext                            (dc_context_t*, uint32_t from_id, const char* rfc724_mid, time_t, uint32_t* ret_chat_id, uint32_t* ret_msg_id); /* returns 1 if an event should be send */
void            dc_add_device_msg                          (dc_context_t*, uint32_t chat_id, const char* text);

#define         DC_FROM_HANDSHAKE                          0x01
int             dc_add_contact_to_chat_ex                  (dc_context_t*, uint32_t chat_id, uint32_t contact_id, int flags);

uint32_t        dc_get_chat_id_by_grpid                    (dc_context_t*, const char* grpid, int* ret_blocked, int* ret_verified);

#define         DC_BAK_PREFIX                "delta-chat"
#define         DC_BAK_SUFFIX                "bak"


/* library private: end-to-end-encryption */
#define DC_E2EE_DEFAULT_ENABLED  1
#define DC_MDNS_DEFAULT_ENABLED  1

typedef struct dc_e2ee_helper_t {
	// encryption
	int   m_encryption_successfull;
	void* m_cdata_to_free;

	// decryption
	int        m_encrypted;  // encrypted without problems
	dc_hash_t* m_signatures; // fingerprints of valid signatures
	dc_hash_t* m_gossipped_addr;

} dc_e2ee_helper_t;

void            dc_e2ee_encrypt      (dc_context_t*, const clist* recipients_addr, int force_plaintext, int e2ee_guaranteed, int min_verified, struct mailmime* in_out_message, dc_e2ee_helper_t*);
void            dc_e2ee_decrypt      (dc_context_t*, struct mailmime* in_out_message, dc_e2ee_helper_t*); /* returns 1 if sth. was decrypted, 0 in other cases */
void            dc_e2ee_thanks       (dc_e2ee_helper_t*); /* frees data referenced by "mailmime" but not freed by mailmime_free(). After calling this function, in_out_message cannot be used any longer! */
int             dc_ensure_secret_key_exists (dc_context_t*); /* makes sure, the private key exists, needed only for exporting keys and the case no message was sent before */
char*           dc_create_setup_code (dc_context_t*);
char*           dc_normalize_setup_code(dc_context_t*, const char* passphrase);
char*           dc_render_setup_file (dc_context_t*, const char* passphrase);
char*           dc_decrypt_setup_file(dc_context_t*, const char* passphrase, const char* filecontent);

extern int      dc_shall_stop_ongoing;
int             dc_alloc_ongoing     (dc_context_t*);
void            dc_free_ongoing      (dc_context_t*);

#define         dc_is_online(m)             ((m)->m_cb((m), DC_EVENT_IS_OFFLINE, 0, 0)==0)
#define         dc_is_offline(m)            ((m)->m_cb((m), DC_EVENT_IS_OFFLINE, 0, 0)!=0)


/* library private: secure-join */
#define         DC_IS_HANDSHAKE_CONTINUE_NORMAL_PROCESSING 1
#define         DC_IS_HANDSHAKE_STOP_NORMAL_PROCESSING     2
int             dc_handle_securejoin_handshake(dc_context_t*, dc_mimeparser_t*, uint32_t contact_id);
void            dc_handle_degrade_event       (dc_context_t*, dc_apeerstate_t*);


#define DC_OPENPGP4FPR_SCHEME "OPENPGP4FPR:" /* yes: uppercase */


/* library private: key-history */
void            dc_add_to_keyhistory__(dc_context_t*, const char* rfc724_mid, time_t, const char* addr, const char* fingerprint);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_CONTEXT_H__ */
