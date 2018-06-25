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
#include "dc_context.h"
#include "dc_key.h"
#include "dc_apeerstate.h"
#include "dc_mimeparser.h"
#include "dc_mimefactory.h"
#include "dc_job.h"
#include "dc_token.h"


#define      LOCK                 { dc_sqlite3_lock  (context->m_sql); locked = 1; }
#define      UNLOCK  if( locked ) { dc_sqlite3_unlock(context->m_sql); locked = 0; }


/*******************************************************************************
 * Tools: Handle degraded keys and lost verificaton
 ******************************************************************************/


void dc_handle_degrade_event(dc_context_t* context, dc_apeerstate_t* peerstate)
{
	sqlite3_stmt* stmt            = NULL;
	int           locked          = 0;
	uint32_t      contact_id      = 0;
	uint32_t      contact_chat_id = 0;

	if( context == NULL || peerstate == NULL ) {
		goto cleanup;
	}

	// - we do not issue an warning for DC_DE_ENCRYPTION_PAUSED as this is quite normal
	// - currently, we do not issue an extra warning for DC_DE_VERIFICATION_LOST - this always comes
	//   together with DC_DE_FINGERPRINT_CHANGED which is logged, the idea is not to bother
	//   with things they cannot fix, so the user is just kicked from the verified group
	//   (and he will know this and can fix this)

	if( peerstate->m_degrade_event & DC_DE_FINGERPRINT_CHANGED )
	{
		LOCK

			stmt = dc_sqlite3_prepare_v2_(context->m_sql, "SELECT id FROM contacts WHERE addr=?;");
				sqlite3_bind_text(stmt, 1, peerstate->m_addr, -1, SQLITE_STATIC);
				sqlite3_step(stmt);
				contact_id = sqlite3_column_int(stmt, 0);
			sqlite3_finalize(stmt);

			if( contact_id == 0 ) {
				goto cleanup;
			}

			dc_create_or_lookup_nchat_by_contact_id__(context, contact_id, DC_CHAT_DEADDROP_BLOCKED, &contact_chat_id, NULL);

		UNLOCK

		char* msg = dc_mprintf("Changed setup for %s", peerstate->m_addr);
		dc_add_device_msg(context, contact_chat_id, msg);
		free(msg);
		context->m_cb(context, DC_EVENT_CHAT_MODIFIED, contact_chat_id, 0);
	}

cleanup:
	UNLOCK
}


/*******************************************************************************
 * Tools: Misc.
 ******************************************************************************/


static int encrypted_and_signed(dc_mimeparser_t* mimeparser, const char* expected_fingerprint)
{
	if( !mimeparser->m_e2ee_helper->m_encrypted ) {
		dc_log_warning(mimeparser->m_context, 0, "Message not encrypted.");
		return 0;
	}

	if( dc_hash_count(mimeparser->m_e2ee_helper->m_signatures)<=0 ) {
		dc_log_warning(mimeparser->m_context, 0, "Message not signed.");
		return 0;
	}

	if( expected_fingerprint == NULL ) {
		dc_log_warning(mimeparser->m_context, 0, "Fingerprint for comparison missing.");
		return 0;
	}

	if( dc_hash_find_str(mimeparser->m_e2ee_helper->m_signatures, expected_fingerprint) == NULL ) {
		dc_log_warning(mimeparser->m_context, 0, "Message does not match expected fingerprint %s.", expected_fingerprint);
		return 0;
	}

	return 1;
}


static char* get_self_fingerprint(dc_context_t* context)
{
	int      locked      = 0;
	char*    self_addr   = NULL;
	dc_key_t* self_key    = dc_key_new();
	char*    fingerprint = NULL;

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		if( (self_addr = dc_sqlite3_get_config__(context->m_sql, "configured_addr", NULL)) == NULL
		 || !dc_key_load_self_public__(self_key, self_addr, context->m_sql) ) {
			goto cleanup;
		}

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	if( (fingerprint=dc_key_get_fingerprint(self_key)) == NULL ) {
		goto cleanup;
	}

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	free(self_addr);
	dc_key_unref(self_key);
	return fingerprint;
}


static uint32_t chat_id_2_contact_id(dc_context_t* context, uint32_t contact_chat_id)
{
	uint32_t   contact_id = 0;
	dc_array_t* contacts = dc_get_chat_contacts(context, contact_chat_id);

	if( dc_array_get_cnt(contacts) != 1 ) {
		goto cleanup;
	}

	contact_id = dc_array_get_id(contacts, 0);

cleanup:
	dc_array_unref(contacts);
	return contact_id;
}


static int fingerprint_equals_sender(dc_context_t* context, const char* fingerprint, uint32_t contact_chat_id)
{
	int             fingerprint_equal      = 0;
	int             locked                 = 0;
	dc_array_t*      contacts               = dc_get_chat_contacts(context, contact_chat_id);
	dc_contact_t*    contact                = dc_contact_new(context);
	dc_apeerstate_t* peerstate              = dc_apeerstate_new(context);
	char*           fingerprint_normalized = NULL;

	if( dc_array_get_cnt(contacts) != 1 ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		if( !dc_contact_load_from_db__(contact, context->m_sql, dc_array_get_id(contacts, 0))
		 || !dc_apeerstate_load_by_addr__(peerstate, context->m_sql, contact->m_addr) ) {
			goto cleanup;
		}

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	fingerprint_normalized = dc_normalize_fingerprint(fingerprint);

	if( strcasecmp(fingerprint_normalized, peerstate->m_public_key_fingerprint) == 0 ) {
		fingerprint_equal = 1;
	}

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	free(fingerprint_normalized);
	dc_contact_unref(contact);
	dc_array_unref(contacts);
	return fingerprint_equal;
}


static int mark_peer_as_verified__(dc_context_t* context, const char* fingerprint)
{
	int             success = 0;
	dc_apeerstate_t* peerstate = dc_apeerstate_new(context);

	if( !dc_apeerstate_load_by_fingerprint__(peerstate, context->m_sql, fingerprint) ) {
		goto cleanup;
	}

	if( !dc_apeerstate_set_verified(peerstate, MRA_PUBLIC_KEY, fingerprint, DC_BIDIRECT_VERIFIED) ) {
		goto cleanup;
	}

	// set MUTUAL as an out-of-band-verification is a strong hint that encryption is wanted.
	// the state may be corrected by the Autocrypt headers as usual later;
	// maybe it is a good idea to add the prefer-encrypt-state to the QR code.
	peerstate->m_prefer_encrypt = DC_PE_MUTUAL;
	peerstate->m_to_save       |= DC_SAVE_ALL;

	dc_apeerstate_save_to_db__(peerstate, context->m_sql, 0);
	success = 1;

cleanup:
	dc_apeerstate_unref(peerstate);
	return success;
}


static const char* lookup_field(dc_mimeparser_t* mimeparser, const char* key)
{
	const char* value = NULL;
	struct mailimf_field* field = dc_mimeparser_lookup_field(mimeparser, key);
	if( field == NULL || field->fld_type != MAILIMF_FIELD_OPTIONAL_FIELD
	 || field->fld_data.fld_optional_field == NULL || (value=field->fld_data.fld_optional_field->fld_value) == NULL ) {
		return NULL;
	}
	return value;
}


static void send_handshake_msg(dc_context_t* context, uint32_t contact_chat_id, const char* step, const char* param2, const char* fingerprint, const char* grpid)
{
	dc_msg_t* msg = dc_msg_new();

	msg->m_type = MR_MSG_TEXT;
	msg->m_text = dc_mprintf("Secure-Join: %s", step);
	msg->m_hidden = 1;
	dc_param_set_int(msg->m_param, DC_PARAM_CMD,       DC_CMD_SECUREJOIN_MESSAGE);
	dc_param_set    (msg->m_param, DC_PARAM_CMD_ARG, step);

	if( param2 ) {
		dc_param_set(msg->m_param, DC_PARAM_CMD_ARG2, param2); // depening on step, this goes either to Secure-Join-Invitenumber or Secure-Join-Auth in mrmimefactory.c
	}

	if( fingerprint ) {
		dc_param_set(msg->m_param, DC_PARAM_CMD_ARG3, fingerprint);
	}

	if( grpid ) {
		dc_param_set(msg->m_param, DC_PARAM_CMD_ARG4, grpid);
	}

	if( strcmp(step, "vg-request")==0 || strcmp(step, "vc-request")==0 ) {
		dc_param_set_int(msg->m_param, DC_PARAM_FORCE_PLAINTEXT, MRFP_ADD_AUTOCRYPT_HEADER); // the request message MUST NOT be encrypted - it may be that the key has changed and the message cannot be decrypted otherwise
	}
	else {
		dc_param_set_int(msg->m_param, DC_PARAM_GUARANTEE_E2EE, 1); /* all but the first message MUST be encrypted */
	}

	dc_send_msg_object(context, contact_chat_id, msg);

	dc_msg_unref(msg);
}


static void could_not_establish_secure_connection(dc_context_t* context, uint32_t contact_chat_id, const char* details)
{
	uint32_t     contact_id = chat_id_2_contact_id(context, contact_chat_id);
	dc_contact_t* contact    = dc_get_contact(context, contact_id);
	char*        msg        = dc_mprintf("Could not establish secure connection to %s.", contact? contact->m_addr : "?");

	dc_add_device_msg(context, contact_chat_id, msg);

	dc_log_error(context, 0, "%s (%s)", msg, details); // additionaly raise an error; this typically results in a toast (inviter side) or a dialog (joiner side)

	free(msg);
	dc_contact_unref(contact);
}


static void secure_connection_established(dc_context_t* context, uint32_t contact_chat_id)
{
	uint32_t     contact_id = chat_id_2_contact_id(context, contact_chat_id);
	dc_contact_t* contact    = dc_get_contact(context, contact_id);
	char*        msg        = dc_mprintf("Secure connection to %s established.", contact? contact->m_addr : "?");

	dc_add_device_msg(context, contact_chat_id, msg);

	// in addition to DC_EVENT_MSGS_CHANGED (sent by dc_add_device_msg()), also send DC_EVENT_CHAT_MODIFIED to update all views
	context->m_cb(context, DC_EVENT_CHAT_MODIFIED, contact_chat_id, 0);

	free(msg);
	dc_contact_unref(contact);
}


#define         VC_AUTH_REQUIRED     2
#define         VC_CONTACT_CONFIRM   6
static int      s_bob_expects = 0;

static dc_lot_t* s_bobs_qr_scan = NULL; // should be surround eg. by dc_sqlite3_lock/unlock

#define         BOB_ERROR       0
#define         BOB_SUCCESS     1
static int      s_bobs_status = 0;


static void end_bobs_joining(dc_context_t* context, int status)
{
	s_bobs_status = status;
	dc_stop_ongoing_process(context);
}


/*******************************************************************************
 * Secure-join main flow
 ******************************************************************************/


/**
 * Get QR code text that will offer an secure-join verification.
 * The QR code is compatible to the OPENPGP4FPR format so that a basic
 * fingerprint comparison also works eg. with K-9 or OpenKeychain.
 *
 * The scanning Delta Chat device will pass the scanned content to
 * dc_check_qr() then; if this function returns
 * DC_QR_ASK_VERIFYCONTACT or DC_QR_ASK_VERIFYGROUP an out-of-band-verification
 * can be joined using dc_join_securejoin()
 *
 * @memberof dc_context_t
 *
 * @param context The context object.
 *
 * @param group_chat_id If set to the ID of a chat, the "Joining a verified group" protocol is offered in the QR code.
 *     If set to 0, the "Setup Verified Contact" protocol is offered in the QR code.
 *
 * @return Text that should go to the qr code.
 */
char* dc_get_securejoin_qr(dc_context_t* context, uint32_t group_chat_id)
{
	/* =========================================================
	   ====             Alice - the inviter side            ====
	   ====   Step 1 in "Setup verified contact" protocol   ====
	   ========================================================= */

	int       locked               = 0;
	char*     qr                   = NULL;
	char*     self_addr            = NULL;
	char*     self_addr_urlencoded = NULL;
	char*     self_name            = NULL;
	char*     self_name_urlencoded = NULL;
	char*     fingerprint          = NULL;
	char*     invitenumber         = NULL;
	char*     auth                 = NULL;
	dc_chat_t* chat                 = NULL;
	char*     group_name           = NULL;
	char*     group_name_urlencoded= NULL;

	if( context == NULL || context->m_magic!=DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_ensure_secret_key_exists(context);

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		// invitenumber will be used to allow starting the handshake, auth will be used to verify the fingerprint
		invitenumber = mrtoken_lookup__(context, MRT_INVITENUMBER, group_chat_id);
		if( invitenumber == NULL ) {
			invitenumber = dc_create_id();
			mrtoken_save__(context, MRT_INVITENUMBER, group_chat_id, invitenumber);
		}

		auth = mrtoken_lookup__(context, MRT_AUTH, group_chat_id);
		if( auth == NULL ) {
			auth = dc_create_id();
			mrtoken_save__(context, MRT_AUTH, group_chat_id, auth);
		}

		if( (self_addr = dc_sqlite3_get_config__(context->m_sql, "configured_addr", NULL)) == NULL ) {
			dc_log_error(context, 0, "Not configured, cannot generate QR code.");
			goto cleanup;
		}

		self_name = dc_sqlite3_get_config__(context->m_sql, "displayname", "");

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	if( (fingerprint=get_self_fingerprint(context)) == NULL ) {
		goto cleanup;
	}

	self_addr_urlencoded = dc_urlencode(self_addr);
	self_name_urlencoded = dc_urlencode(self_name);

	if( group_chat_id )
	{
		// parameters used: a=g=x=i=s=
		chat = dc_get_chat(context, group_chat_id);
		if( chat == NULL || chat->m_type != DC_CHAT_TYPE_VERIFIED_GROUP ) {
			dc_log_error(context, 0, "Secure join is only available for verified groups.");
			goto cleanup;
		}
		group_name = dc_chat_get_name(chat);
		group_name_urlencoded = dc_urlencode(group_name);
		qr = dc_mprintf(DC_OPENPGP4FPR_SCHEME "%s#a=%s&g=%s&x=%s&i=%s&s=%s", fingerprint, self_addr_urlencoded, group_name_urlencoded, chat->m_grpid, invitenumber, auth);
	}
	else
	{
		// parameters used: a=n=i=s=
		qr = dc_mprintf(DC_OPENPGP4FPR_SCHEME "%s#a=%s&n=%s&i=%s&s=%s", fingerprint, self_addr_urlencoded, self_name_urlencoded, invitenumber, auth);
	}

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	free(self_addr_urlencoded);
	free(self_addr);
	free(self_name);
	free(self_name_urlencoded);
	free(fingerprint);
	free(invitenumber);
	free(auth);
	dc_chat_unref(chat);
	free(group_name);
	free(group_name_urlencoded);
	return qr? qr : dc_strdup(NULL);
}


/**
 * Join an out-of-band-verification initiated on another device with dc_get_securejoin_qr().
 * This function is typically called when dc_check_qr() returns
 * lot.m_state=DC_QR_ASK_VERIFYCONTACT or lot.m_state=DC_QR_ASK_VERIFYGROUP.
 *
 * This function takes some time and sends and receives several messages.
 * You should call it in a separate thread; if you want to abort it, you should
 * call dc_stop_ongoing_process().
 *
 * @memberof dc_context_t
 *
 * @param context The context object
 * @param qr The text of the scanned QR code. Typically, the same string as given
 *     to dc_check_qr().
 *
 * @return 0=Out-of-band verification failed or aborted, 1=Out-of-band
 *     verification successfull, the UI may redirect to the corresponding chat
 *     where a new system message with the state was added.
 *
 *     TODO: check if we should say to the caller, which activity to show after
 *     vc-request:
 *     - for a qr-scan while group-creation, returning to the chatlist might be better
 *     - for a qr-scan to add a contact (even without handshake), opening the created normal-chat is better
 *     (for vg-request always the new group is shown, this is perfect)
 */
uint32_t dc_join_securejoin(dc_context_t* context, const char* qr)
{
	/* ==========================================================
	   ====             Bob - the joiner's side             =====
	   ====   Step 2 in "Setup verified contact" protocol   =====
	   ========================================================== */

	int      ret_chat_id       = 0;
	int      ongoing_allocated = 0;
	#define  CHECK_EXIT        if( dc_shall_stop_ongoing ) { goto cleanup; }
	uint32_t contact_chat_id   = 0;
	dc_lot_t* qr_scan           = NULL;
	int      join_vg           = 0;

	dc_log_info(context, 0, "Requesting secure-join ...");

	dc_ensure_secret_key_exists(context);

	if( (ongoing_allocated=dc_alloc_ongoing(context)) == 0 ) {
		goto cleanup;
	}

	if( ((qr_scan=dc_check_qr(context, qr))==NULL)
	 || (qr_scan->m_state!=MR_QR_ASK_VERIFYCONTACT && qr_scan->m_state!=MR_QR_ASK_VERIFYGROUP) ) {
		dc_log_error(context, 0, "Unknown QR code.");
		goto cleanup;
	}

	if( (contact_chat_id=dc_create_chat_by_contact_id(context, qr_scan->m_id)) == 0 ) {
		dc_log_error(context, 0, "Unknown contact.");
		goto cleanup;
	}

	CHECK_EXIT

	if( context->m_cb(context, DC_EVENT_IS_OFFLINE, 0, 0)!=0 ) {
		dc_log_error(context, DC_ERROR_NO_NETWORK, NULL);
		goto cleanup;
	}

	CHECK_EXIT

	join_vg = (qr_scan->m_state==MR_QR_ASK_VERIFYGROUP);

	s_bobs_status = 0;
	dc_sqlite3_lock(context->m_sql);
		s_bobs_qr_scan = qr_scan;
	dc_sqlite3_unlock(context->m_sql);

	if( fingerprint_equals_sender(context, qr_scan->m_fingerprint, contact_chat_id) ) {
		// the scanned fingerprint matches Alice's key, we can proceed to step 4b) directly and save two mails
		dc_log_info(context, 0, "Taking protocol shortcut.");
		s_bob_expects = VC_CONTACT_CONFIRM;
		context->m_cb(context, DC_EVENT_SECUREJOIN_JOINER_PROGRESS, chat_id_2_contact_id(context, contact_chat_id), 4);
		char* own_fingerprint = get_self_fingerprint(context);
		send_handshake_msg(context, contact_chat_id, join_vg? "vg-request-with-auth" : "vc-request-with-auth",
			qr_scan->m_auth, own_fingerprint, join_vg? qr_scan->m_text2 : NULL); // Bob -> Alice
		free(own_fingerprint);
	}
	else {
		s_bob_expects = VC_AUTH_REQUIRED;
		send_handshake_msg(context, contact_chat_id, join_vg? "vg-request" : "vc-request",
			qr_scan->m_invitenumber, NULL, NULL); // Bob -> Alice
	}

	while( 1 ) {
		CHECK_EXIT

		usleep(300*1000); // 0.3 seconds
	}

cleanup:
	s_bob_expects = 0;

	if( s_bobs_status == BOB_SUCCESS ) {
		if( join_vg ) {
			dc_sqlite3_lock(context->m_sql);
				ret_chat_id = dc_get_chat_id_by_grpid__(context, qr_scan->m_text2, NULL, NULL);
			dc_sqlite3_unlock(context->m_sql);
		}
		else {
			ret_chat_id = contact_chat_id;
		}
	}

	dc_sqlite3_lock(context->m_sql);
		s_bobs_qr_scan = NULL;
	dc_sqlite3_unlock(context->m_sql);

	dc_lot_unref(qr_scan);

	if( ongoing_allocated ) { dc_free_ongoing(context); }
	return ret_chat_id;
}


int dc_handle_securejoin_handshake(dc_context_t* context, dc_mimeparser_t* mimeparser, uint32_t contact_id)
{
	int          locked = 0;
	const char*  step   = NULL;
	int          join_vg = 0;
	char*        scanned_fingerprint_of_alice = NULL;
	char*        auth = NULL;
	char*        own_fingerprint = NULL;
	uint32_t     contact_chat_id = 0;
	int          contact_chat_id_blocked = 0;
	char*        grpid = NULL;
	int          ret = 0;

	if( context == NULL || mimeparser == NULL || contact_id <= DC_CONTACT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	if( (step=lookup_field(mimeparser, "Secure-Join")) == NULL ) {
		goto cleanup;
	}
	dc_log_info(context, 0, ">>>>>>>>>>>>>>>>>>>>>>>>> secure-join message '%s' received", step);

	join_vg = (strncmp(step, "vg-", 3)==0);
	LOCK
		dc_create_or_lookup_nchat_by_contact_id__(context, contact_id, DC_CHAT_NOT_BLOCKED, &contact_chat_id, &contact_chat_id_blocked);
		if( contact_chat_id_blocked ) {
			dc_unblock_chat__(context, contact_chat_id);
		}
	UNLOCK

	ret = DC_IS_HANDSHAKE_STOP_NORMAL_PROCESSING;

	if( strcmp(step, "vg-request")==0 || strcmp(step, "vc-request")==0 )
	{
		/* =========================================================
		   ====             Alice - the inviter side            ====
		   ====   Step 3 in "Setup verified contact" protocol   ====
		   ========================================================= */

		// this message may be unencrypted (Bob, the joinder and the sender, might not have Alice's key yet)

		// it just ensures, we have Bobs key now. If we do _not_ have the key because eg. MitM has removed it,
		// send_message() will fail with the error "End-to-end-encryption unavailable unexpectedly.", so, there is no additional check needed here.

		// verify that the `Secure-Join-Invitenumber:`-header matches invitenumber written to the QR code
		const char* invitenumber = NULL;
		if( (invitenumber=lookup_field(mimeparser, "Secure-Join-Invitenumber")) == NULL ) {
			dc_log_warning(context, 0, "Secure-join denied (invitenumber missing)."); // do not raise an error, this might just be spam or come from an old request
			goto cleanup;
		}

		LOCK
			if( mrtoken_exists__(context, MRT_INVITENUMBER, invitenumber) == 0 ) {
				dc_log_warning(context, 0, "Secure-join denied (bad invitenumber).");  // do not raise an error, this might just be spam or come from an old request
				goto cleanup;
			}
		UNLOCK

		dc_log_info(context, 0, "Secure-join requested.");

		context->m_cb(context, DC_EVENT_SECUREJOIN_INVITER_PROGRESS, contact_id, 3);

		send_handshake_msg(context, contact_chat_id, join_vg? "vg-auth-required" : "vc-auth-required",
			NULL, NULL, NULL); // Alice -> Bob
	}
	else if( strcmp(step, "vg-auth-required")==0 || strcmp(step, "vc-auth-required")==0 )
	{
		/* ==========================================================
		   ====             Bob - the joiner's side             =====
		   ====   Step 4 in "Setup verified contact" protocol   =====
		   ========================================================== */

		// verify that Alice's Autocrypt key and fingerprint matches the QR-code
		LOCK
			if( s_bobs_qr_scan == NULL || s_bob_expects != VC_AUTH_REQUIRED || (join_vg && s_bobs_qr_scan->m_state!=MR_QR_ASK_VERIFYGROUP) ) {
				dc_log_warning(context, 0, "auth-required message out of sync.");
				goto cleanup; // no error, just aborted somehow or a mail from another handshake
			}
			scanned_fingerprint_of_alice = dc_strdup(s_bobs_qr_scan->m_fingerprint);
			auth = dc_strdup(s_bobs_qr_scan->m_auth);
			if( join_vg ) {
				grpid = dc_strdup(s_bobs_qr_scan->m_text2);
			}
		UNLOCK

		if( !encrypted_and_signed(mimeparser, scanned_fingerprint_of_alice) ) {
			could_not_establish_secure_connection(context, contact_chat_id, mimeparser->m_e2ee_helper->m_encrypted? "No valid signature." : "Not encrypted.");
			end_bobs_joining(context, BOB_ERROR);
			goto cleanup;
		}

		if( !fingerprint_equals_sender(context, scanned_fingerprint_of_alice, contact_chat_id) ) {
			// MitM?
			could_not_establish_secure_connection(context, contact_chat_id, "Fingerprint mismatch on joiner-side.");
			end_bobs_joining(context, BOB_ERROR);
			goto cleanup;
		}

		dc_log_info(context, 0, "Fingerprint verified.");

		own_fingerprint = get_self_fingerprint(context);

		context->m_cb(context, DC_EVENT_SECUREJOIN_JOINER_PROGRESS, contact_id, 4);

		s_bob_expects = VC_CONTACT_CONFIRM;
		send_handshake_msg(context, contact_chat_id, join_vg? "vg-request-with-auth" : "vc-request-with-auth",
			auth, own_fingerprint, grpid); // Bob -> Alice
	}
	else if( strcmp(step, "vg-request-with-auth")==0 || strcmp(step, "vc-request-with-auth")==0 )
	{
		/* ============================================================
		   ====              Alice - the inviter side              ====
		   ====   Steps 5+6 in "Setup verified contact" protocol   ====
		   ====  Step 6 in "Out-of-band verified groups" protocol  ====
		   ============================================================ */

		// verify that Secure-Join-Fingerprint:-header matches the fingerprint of Bob
		const char* fingerprint = NULL;
		if( (fingerprint=lookup_field(mimeparser, "Secure-Join-Fingerprint")) == NULL ) {
			could_not_establish_secure_connection(context, contact_chat_id, "Fingerprint not provided.");
			goto cleanup;
		}

		if( !encrypted_and_signed(mimeparser, fingerprint) ) {
			could_not_establish_secure_connection(context, contact_chat_id, "Auth not encrypted.");
			goto cleanup;
		}

		if( !fingerprint_equals_sender(context, fingerprint, contact_chat_id) ) {
			// MitM?
			could_not_establish_secure_connection(context, contact_chat_id, "Fingerprint mismatch on inviter-side.");
			goto cleanup;
		}

		dc_log_info(context, 0, "Fingerprint verified.");

		// verify that the `Secure-Join-Auth:`-header matches the secret written to the QR code
		const char* auth = NULL;
		if( (auth=lookup_field(mimeparser, "Secure-Join-Auth")) == NULL ) {
			could_not_establish_secure_connection(context, contact_chat_id, "Auth not provided.");
			goto cleanup;
		}

		LOCK
			if( mrtoken_exists__(context, MRT_AUTH, auth) == 0 ) {
				dc_sqlite3_unlock(context->m_sql);
				locked = 0;
				could_not_establish_secure_connection(context, contact_chat_id, "Auth invalid.");
				goto cleanup;
			}

			if( !mark_peer_as_verified__(context, fingerprint) ) {
				dc_sqlite3_unlock(context->m_sql);
				locked = 0;
				could_not_establish_secure_connection(context, contact_chat_id, "Fingerprint mismatch on inviter-side."); // should not happen, we've compared the fingerprint some lines above
				goto cleanup;
			}

			dc_scaleup_contact_origin__(context, contact_id, DC_ORIGIN_SECUREJOIN_INVITED);
		UNLOCK

		dc_log_info(context, 0, "Auth verified.");

		secure_connection_established(context, contact_chat_id);

		context->m_cb(context, DC_EVENT_CONTACTS_CHANGED, contact_id/*selected contact*/, 0);
		context->m_cb(context, DC_EVENT_SECUREJOIN_INVITER_PROGRESS, contact_id, 6);

		if( join_vg ) {
			// the vg-member-added message is special: this is a normal Chat-Group-Member-Added message with an additional Secure-Join header
			grpid = dc_strdup(lookup_field(mimeparser, "Secure-Join-Group"));
			int is_verified = 0;
			LOCK
				uint32_t verified_chat_id = dc_get_chat_id_by_grpid__(context, grpid, NULL, &is_verified);
			UNLOCK
			if( verified_chat_id == 0 || !is_verified ) {
				dc_log_error(context, 0, "Verified chat not found.");
				goto cleanup;
			}

			dc_add_contact_to_chat_ex(context, verified_chat_id, contact_id, DC_FROM_HANDSHAKE); // Alice -> Bob and all members
		}
		else {
			send_handshake_msg(context, contact_chat_id, "vc-contact-confirm",
				NULL, NULL, NULL); // Alice -> Bob
		}
	}
	else if( strcmp(step, "vg-member-added")==0 || strcmp(step, "vc-contact-confirm")==0 )
	{
		/* ==========================================================
		   ====             Bob - the joiner's side             =====
		   ====   Step 7 in "Setup verified contact" protocol   =====
		   ========================================================== */

		if( join_vg ) {
			// vg-member-added is just part of a Chat-Group-Member-Added which should be kept in any way, eg. for multi-client
			ret = DC_IS_HANDSHAKE_CONTINUE_NORMAL_PROCESSING;
		}

		if( s_bob_expects != VC_CONTACT_CONFIRM ) {
			if( join_vg ) {
				dc_log_info(context, 0, "vg-member-added received as broadcast.");
			}
			else {
				dc_log_warning(context, 0, "Unexpected secure-join mail order.");
			}
			goto cleanup;
		}

		LOCK
			if( s_bobs_qr_scan == NULL || (join_vg && s_bobs_qr_scan->m_state!=MR_QR_ASK_VERIFYGROUP) ) {
				dc_log_warning(context, 0, "Message out of sync or belongs to a different handshake.");
				goto cleanup;
			}
			scanned_fingerprint_of_alice = dc_strdup(s_bobs_qr_scan->m_fingerprint);
		UNLOCK

		if( !encrypted_and_signed(mimeparser, scanned_fingerprint_of_alice) ) {
			could_not_establish_secure_connection(context, contact_chat_id, "Contact confirm message not encrypted.");
			end_bobs_joining(context, BOB_ERROR);
			goto cleanup;
		}

		// TODO: for the broadcasted vg-member-added, make sure, the message is ours (eg. by comparing Chat-Group-Member-Added against SELF)

		LOCK
			if( !mark_peer_as_verified__(context, scanned_fingerprint_of_alice) ) {
				could_not_establish_secure_connection(context, contact_chat_id, "Fingerprint mismatch on joiner-side."); // MitM? - key has changed since vc-auth-required message
				goto cleanup;
			}

			dc_scaleup_contact_origin__(context, contact_id, DC_ORIGIN_SECUREJOIN_JOINED);
		UNLOCK

		secure_connection_established(context, contact_chat_id);

		context->m_cb(context, DC_EVENT_CONTACTS_CHANGED, 0/*no select event*/, 0);

		s_bob_expects = 0;
		end_bobs_joining(context, BOB_SUCCESS);
	}

	// delete the message, as SMTP and IMAP is done in separate threads it should be okay to delete the message just now.
	// for errors, we do not the corresponding message at all, it may come eg. from another device or may be useful to find out what was going wrong.
	if( ret == DC_IS_HANDSHAKE_STOP_NORMAL_PROCESSING ) {
		struct mailimf_field* field;
		if( (field=dc_mimeparser_lookup_field(mimeparser, "Message-ID"))!=NULL && field->fld_type==MAILIMF_FIELD_MESSAGE_ID ) {
			struct mailimf_message_id* fld_message_id = field->fld_data.fld_message_id;
			if( fld_message_id && fld_message_id->mid_value ) {
				dc_job_add(context, DC_JOB_DELETE_MSG_ON_IMAP, dc_rfc724_mid_exists__(context, fld_message_id->mid_value, NULL, NULL), NULL, 0);
			}
		}
	}

cleanup:

	UNLOCK

	free(scanned_fingerprint_of_alice);
	free(auth);
	free(own_fingerprint);
	free(grpid);
	return ret;
}
