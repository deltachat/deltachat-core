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


#include <stdarg.h>
#include <unistd.h>
#include "mrmailbox_internal.h"
#include "mrkey.h"
#include "mrapeerstate.h"
#include "mrmimeparser.h"
#include "mrmimefactory.h"


/*******************************************************************************
 * Tools
 ******************************************************************************/


#define OPENPGP4FPR_SCHEME "OPENPGP4FPR:" /* yes: uppercase */
#define MAILTO_SCHEME      "mailto:"
#define MATMSG_SCHEME      "MATMSG:"
#define VCARD_BEGIN        "BEGIN:VCARD"
#define SMTP_SCHEME        "SMTP:"


/**
 * Check a scanned QR code.
 * The function should be called after a QR code is scanned.
 * The function takes the raw text scanned and checks what can be done with it.
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 * @param qr The text of the scanned QR code.
 *
 * @return Parsed QR code as an mrlot_t object.
 */
mrlot_t* mrmailbox_check_qr(mrmailbox_t* mailbox, const char* qr)
{
	int             locked      = 0;
	char*           payload     = NULL;
	char*           addr        = NULL; /* must be normalized, if set */
	char*           fingerprint = NULL; /* must be normalized, if set */
	char*           name        = NULL;
	char*           return_tag  = NULL;
	mrapeerstate_t* peerstate   = mrapeerstate_new();
	mrlot_t*        qr_parsed   = mrlot_new();

	qr_parsed->m_state = 0;

	if( mailbox==NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC || qr==NULL ) {
		goto cleanup;
	}

	mrmailbox_log_info(mailbox, 0, "Scanned QR code: %s", qr);

	/* split parameters from the qr code
	 ------------------------------------ */

	if( strncasecmp(qr, OPENPGP4FPR_SCHEME, strlen(OPENPGP4FPR_SCHEME)) == 0 )
	{
		/* scheme: OPENPGP4FPR:1234567890123456789012345678901234567890#v=mail%40domain.de&n=Name */
		payload  = safe_strdup(&qr[strlen(OPENPGP4FPR_SCHEME)]);
		char* fragment = strchr(payload, '#'); /* must not be freed, only a pointer inside payload */
		if( fragment )
		{
			*fragment = 0;
			fragment++;

			mrparam_t* param = mrparam_new();
			mrparam_set_urlencoded(param, fragment);

			addr = mrparam_get(param, 'v', NULL);
			if( addr ) {
				char* name_urlencoded = mrparam_get(param, 'n', NULL);
				if( name_urlencoded ) {
					name = mr_url_decode(name_urlencoded);
					mr_normalize_name(name);
					free(name_urlencoded);
				}
				return_tag = mrparam_get(param, 'r', "");
			}

			mrparam_unref(param);
		}

		fingerprint = mr_normalize_fingerprint(payload);
	}
	else if( strncasecmp(qr, MAILTO_SCHEME, strlen(MAILTO_SCHEME)) == 0 )
	{
		/* scheme: mailto:addr...?subject=...&body=... */
		payload = safe_strdup(&qr[strlen(MAILTO_SCHEME)]);
		char* query = strchr(payload, '?'); /* must not be freed, only a pointer inside payload */
		if( query ) {
			*query = 0;
		}
		addr = safe_strdup(payload);
	}
	else if( strncasecmp(qr, SMTP_SCHEME, strlen(SMTP_SCHEME)) == 0 )
	{
		/* scheme: `SMTP:addr...:subject...:body...` */
		payload = safe_strdup(&qr[strlen(SMTP_SCHEME)]);
		char* colon = strchr(payload, ':'); /* must not be freed, only a pointer inside payload */
		if( colon ) {
			*colon = 0;
		}
		addr = safe_strdup(payload);
	}
	else if( strncasecmp(qr, MATMSG_SCHEME, strlen(MATMSG_SCHEME)) == 0 )
	{
		/* scheme: `MATMSG:TO:addr...;SUB:subject...;BODY:body...;` - there may or may not be linebreaks after the fields */
		char* to = strstr(qr, "TO:"); /* does not work when the text `TO:` is used in subject/body _and_ TO: is not the first field. we ignore this case. */
		if( to ) {
			addr = safe_strdup(&to[3]);
			char* semicolon = strchr(addr, ';');
			if( semicolon ) { *semicolon = 0; }
		}
		else {
			qr_parsed->m_state = MR_QR_ERROR;
			qr_parsed->m_text1 = safe_strdup("Bad e-mail address.");
			goto cleanup;
		}
	}
	else if( strncasecmp(qr, VCARD_BEGIN, strlen(VCARD_BEGIN)) == 0 )
	{
		/* scheme: `VCARD:BEGIN\nN:last name;first name;...;\nEMAIL:addr...;` */
		carray* lines = mr_split_into_lines(qr);
		for( int i = 0; i < carray_count(lines); i++ ) {
			char* key   = (char*)carray_get(lines, i); mr_trim(key);
			char* value = strchr(key, ':');
			if( value ) {
				*value = 0;
				value++;
				char* semicolon = strchr(key, ';'); if( semicolon ) { *semicolon = 0; } /* handle `EMAIL;type=work:` stuff */
				if( strcasecmp(key, "EMAIL") == 0 ) {
					semicolon = strchr(value, ';'); if( semicolon ) { *semicolon = 0; } /* use the first EMAIL */
					addr = safe_strdup(value);
				}
				else if( strcasecmp(key, "N") == 0 ) {
					semicolon = strchr(value, ';'); if( semicolon ) { semicolon = strchr(semicolon+1, ';'); if( semicolon ) { *semicolon = 0; } } /* the N format is `lastname;prename;wtf;title` - skip everything after the second semicolon */
					name = safe_strdup(value);
					mr_str_replace(&name, ";", ","); /* the format "lastname,prename" is handled by mr_normalize_name() */
					mr_normalize_name(name);
				}
			}
		}
		mr_free_splitted_lines(lines);
	}

	/* check the paramters
	  ---------------------- */

	if( addr ) {
		char* temp = mr_url_decode(addr);     free(addr); addr = temp; /* urldecoding is needed at least for OPENPGP4FPR but should not hurt in the other cases */
		      temp = mr_normalize_addr(addr); free(addr); addr = temp;

		if( strlen(addr) < 3 || strchr(addr, '@')==NULL || strchr(addr, '.')==NULL ) {
			qr_parsed->m_state = MR_QR_ERROR;
			qr_parsed->m_text1 = safe_strdup("Bad e-mail address.");
			goto cleanup;
		}
	}

	if( fingerprint ) {
		if( strlen(fingerprint) != 40 ) {
			qr_parsed->m_state = MR_QR_ERROR;
			qr_parsed->m_text1 = safe_strdup("Bad fingerprint length in QR code.");
			goto cleanup;
		}
	}

	/* let's see what we can do with the parameters
	  ---------------------------------------------- */

	if( fingerprint )
	{
		/* fingerprint set ... */

		if( addr == NULL )
		{
			/* _only_ fingerprint set ... */
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				if( mrapeerstate_load_by_fingerprint__(peerstate, mailbox->m_sql, fingerprint) ) {
					qr_parsed->m_state = MR_QR_FPR_OK;
					qr_parsed->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, NULL, peerstate->m_addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
					// TODO: add this to the security log
				}
				else {
					qr_parsed->m_state = MR_QR_FPR_WITHOUT_ADDR;
				}

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
		else
		{
			/* fingerprint and addr set ... */  // TODO: add the states to the security log
			mrsqlite3_lock(mailbox->m_sql);
			locked = 1;

				qr_parsed->m_state = MR_QR_FPR_ASK_OOB;
				qr_parsed->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
				if( mrapeerstate_load_by_addr__(peerstate, mailbox->m_sql, addr) ) {
					if( strcasecmp(peerstate->m_fingerprint, fingerprint) != 0 ) {
						mrmailbox_log_info(mailbox, 0, "Fingerprint mismatch for %s: Scanned: %s, saved: %s", addr, fingerprint, peerstate->m_fingerprint);
						qr_parsed->m_state = MR_QR_FPR_MISMATCH;
					}
				}

				if( qr_parsed->m_state == MR_QR_FPR_ASK_OOB ) {
					qr_parsed->m_text2 = safe_strdup(return_tag);
				}

			mrsqlite3_unlock(mailbox->m_sql);
			locked = 0;
		}
	}
	else if( addr )
	{
        qr_parsed->m_state = MR_QR_ADDR;
		qr_parsed->m_id    = mrmailbox_add_or_lookup_contact__(mailbox, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
	}
	else
	{
        qr_parsed->m_state = MR_QR_TEXT;
		qr_parsed->m_text1 = safe_strdup(qr);
	}

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	free(addr);
	free(fingerprint);
	mrapeerstate_unref(peerstate);
	free(payload);
	return qr_parsed;
}


static void send_message(mrmailbox_t* mailbox, uint32_t chat_id, const char* step_name)
{
	mrmsg_t* msg = mrmsg_new();

	msg->m_type = MR_MSG_TEXT;
	msg->m_text = mr_mprintf("out-of-band-verification, %s", step_name);
	mrparam_set_int(msg->m_param, MRP_SYSTEM_CMD,       MR_SYSTEM_OOB_VERIFY_MESSAGE);
	mrparam_set    (msg->m_param, MRP_SYSTEM_CMD_PARAM, step_name);
	mrmailbox_send_msg_object(mailbox, chat_id, msg);

	mrmsg_unref(msg);
}


/*******************************************************************************
 * OOB verification main flow
 ******************************************************************************/


/**
 * Get QR code text that will offer an oob verification.
 * The QR code is compatible to the OPENPGP4FPR format so that a basic
 * fingerprint comparison also works eg. with K-9 or OpenKeychain.
 *
 * The scanning Delta Chat device will pass the scanned content to
 * mrmailbox_check_qr() then; if this function reutrns
 * MR_QR_FINGERPRINT_ASK_OOB oob-verification can be joined using
 * mrmailbox_oob_join()
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object.
 *
 * @return Text that should go to the qr code.
 */
char* mrmailbox_oob_get_qr(mrmailbox_t* mailbox)
{
	/* ==========================
	   ==== the inviter side ====
	   ========================== */

	int      locked               = 0;
	char*    qr                   = NULL;
	char*    self_addr            = NULL;
	char*    self_addr_urlencoded = NULL;
	char*    self_name            = NULL;
	char*    self_name_urlencoded = NULL;
	mrkey_t* self_key             = mrkey_new();
	char*    fingerprint          = NULL;
	char*    return_tag           = NULL;

	if( mailbox == NULL || mailbox->m_magic!=MR_MAILBOX_MAGIC ) {
		goto cleanup;
	}

	mrmailbox_ensure_secret_key_exists(mailbox);

	return_tag = mr_create_id();

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( (self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL)) == NULL
		 || !mrkey_load_self_public__(self_key, self_addr, mailbox->m_sql) ) {
			goto cleanup;
		}

		self_name = mrsqlite3_get_config__(mailbox->m_sql, "displayname", "");

		/* prepend return_tag to the list of all tags */
		{
			#define MAX_REMEMBERED_RETURN_TAGS 10
			#define MAX_REMEMBERED_CHARS (MAX_REMEMBERED_RETURN_TAGS*(MR_CREATE_ID_LEN+1))
			char* old_return_tags = mrsqlite3_get_config__(mailbox->m_sql, "return_tags", "");
			if( strlen(old_return_tags) > MAX_REMEMBERED_CHARS ) {
				old_return_tags[MAX_REMEMBERED_CHARS] = 0; /* the oldest tag may be incomplete und unrecognizable, however, this is no problem as it would be deleted soon anyway */
			}
			char* all_return_tags = mr_mprintf("%s,%s", return_tag, old_return_tags);
			mrsqlite3_set_config__(mailbox->m_sql, "return_tags", all_return_tags);
			free(all_return_tags);
			free(old_return_tags);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	if( (fingerprint=mrkey_get_fingerprint(self_key)) == NULL ) {
		goto cleanup;
	}

	self_addr_urlencoded = mr_url_encode(self_addr);
	self_name_urlencoded = mr_url_encode(self_name);
	qr = mr_mprintf(OPENPGP4FPR_SCHEME "%s#v=%s&n=%s&r=%s", fingerprint, self_addr_urlencoded, self_name_urlencoded, return_tag);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrkey_unref(self_key);
	free(self_addr_urlencoded);
	free(self_addr);
	free(self_name);
	free(self_name_urlencoded);
	free(fingerprint);
	free(return_tag);
	return qr? qr : safe_strdup(NULL);
}


/**
 * Join an OOB-verification initiated on another device with mrmailbox_oob_get_qr().
 * This function is typically called when mrmailbox_check_qr() returns
 * lot.m_state=MR_QR_FINGERPRINT_ASK_OOB
 *
 * This function takes some time and sends and receives several messages.
 * You should call it in a separate thread; if you want to abort it, you should
 * call mrmailbox_stop_ongoing_process().
 *
 * @memberof mrmailbox_t
 *
 * @param mailbox The mailbox object
 * @param qr The text of the scanned QR code. Typically, the same string as given
 *     to mrmailbox_check_qr().
 *
 * @return 0=Out-of-band verification failed or aborted, 1=Out-of-band
 *     verification successfull, the UI may redirect to the corresponding chat
 *     where a new system message with the state was added.
 */
int mrmailbox_oob_join(mrmailbox_t* mailbox, const char* qr)
{
	/* =========================
	   ==== the joiner side ====
	   ========================= */

	int      success           = 0;
	int      ongoing_allocated = 0;
	#define  CHECK_EXIT        if( mr_shall_stop_ongoing ) { goto cleanup; }
	uint32_t chat_id           = 0;
	mrlot_t* qr_parsed         = NULL;

	mrmailbox_log_info(mailbox, 0, "Joining oob-verification ...");

	if( (ongoing_allocated=mrmailbox_alloc_ongoing(mailbox)) == 0 ) {
		goto cleanup;
	}

	if( ((qr_parsed=mrmailbox_check_qr(mailbox, qr))==NULL) || qr_parsed->m_state!=MR_QR_FPR_ASK_OOB ) {
		goto cleanup;
	}

	if( (chat_id=mrmailbox_create_chat_by_contact_id(mailbox, qr_parsed->m_id)) == 0 ) {
		goto cleanup;
	}

	CHECK_EXIT

	send_message(mailbox, chat_id, "secure-join-requested");

	while( 1 ) {
		CHECK_EXIT

		usleep(300*1000);
	}

	success = 1;

cleanup:
	mrlot_unref(qr_parsed);
	if( ongoing_allocated ) { mrmailbox_free_ongoing(mailbox); }
	return success;
}


/*
 * mrmailbox_oob_is_handshake_message__() should be called called for each
 * incoming mail. if the mail belongs to an oob-verify handshake, the function
 * returns 1. The caller should unlock everything, stop normal message
 * processing and call mrmailbox_oob_handle_handshake_message() then.
 */
int mrmailbox_oob_is_handshake_message__(mrmailbox_t* mailbox, mrmimeparser_t* mimeparser)
{
	if( mailbox == NULL || mimeparser == NULL || mrmimeparser_lookup_field(mimeparser, "OOB-Verify-Step") == NULL ) {
		return 0;
	}

	return 1; /* processing is continued in mrmailbox_oob_handle_handshake_message() */
}


void mrmailbox_oob_handle_handshake_message(mrmailbox_t* mailbox, mrmimeparser_t* mimeparser, uint32_t chat_id)
{
	struct mailimf_field* field = NULL;
	const char*           step = NULL;

	if( mailbox == NULL || mimeparser == NULL || chat_id <= MR_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	field = mrmimeparser_lookup_field(mimeparser, "OOB-Verify-Step");
	if( field == NULL || field->fld_type != MAILIMF_FIELD_OPTIONAL_FIELD || field->fld_data.fld_optional_field == NULL ) {
		goto cleanup;
	}
	step = field->fld_data.fld_optional_field->fld_value;
	mrmailbox_log_info(mailbox, 0, "OOB-verify message '%s' received ...", step);

	/* ==========================
	   ==== the inviter side ====
	   ========================== */

	if( strcmp(step, "secure-join-requested")==0 )
	{
		send_message(mailbox, chat_id, "please-provide-random-secret");
	}

cleanup:
	;
}
