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
#include "dc_apeerstate.h"


#define MAILTO_SCHEME      "mailto:"
#define MATMSG_SCHEME      "MATMSG:"
#define VCARD_BEGIN        "BEGIN:VCARD"
#define SMTP_SCHEME        "SMTP:"


/**
 * Check a scanned QR code.
 * The function should be called after a QR code is scanned.
 * The function takes the raw text scanned and checks what can be done with it.
 *
 * @memberof dc_context_t
 *
 * @param context The context object.
 * @param qr The text of the scanned QR code.
 *
 * @return Parsed QR code as an dc_lot_t object.
 */
dc_lot_t* dc_check_qr(dc_context_t* context, const char* qr)
{
	int             locked        = 0;
	char*           payload       = NULL;
	char*           addr          = NULL; /* must be normalized, if set */
	char*           fingerprint   = NULL; /* must be normalized, if set */
	char*           name          = NULL;
	char*           invitenumber  = NULL;
	char*           auth          = NULL;
	dc_apeerstate_t* peerstate     = dc_apeerstate_new(context);
	dc_lot_t*        qr_parsed     = dc_lot_new();
	uint32_t        chat_id       = 0;
	char*           device_msg    = NULL;
	char*           grpid         = NULL;
	char*           grpname       = NULL;

	qr_parsed->m_state = 0;

	if( context==NULL || context->m_magic!=DC_CONTEXT_MAGIC || qr==NULL ) {
		goto cleanup;
	}

	dc_log_info(context, 0, "Scanned QR code: %s", qr);

	/* split parameters from the qr code
	 ------------------------------------ */

	if( strncasecmp(qr, OPENPGP4FPR_SCHEME, strlen(OPENPGP4FPR_SCHEME)) == 0 )
	{
		/* scheme: OPENPGP4FPR:FINGERPRINT#a=ADDR&n=NAME&i=INVITENUMBER&s=AUTH
		       or: OPENPGP4FPR:FINGERPRINT#a=ADDR&g=GROUPNAME&x=GROUPID&i=INVITENUMBER&s=AUTH */

		payload  = safe_strdup(&qr[strlen(OPENPGP4FPR_SCHEME)]);
		char* fragment = strchr(payload, '#'); /* must not be freed, only a pointer inside payload */
		if( fragment )
		{
			*fragment = 0;
			fragment++;

			dc_param_t* param = dc_param_new();
			dc_param_set_urlencoded(param, fragment);

			addr = dc_param_get(param, 'a', NULL);
			if( addr ) {
				char* urlencoded = dc_param_get(param, 'n', NULL);
				if(urlencoded ) {
					name = dc_urldecode(urlencoded);
					mr_normalize_name(name);
					free(urlencoded);
				}

				invitenumber  = dc_param_get(param, 'i', NULL);
				auth          = dc_param_get(param, 's', NULL);

				grpid  = dc_param_get(param, 'x', NULL);
				if( grpid ) {
					urlencoded = dc_param_get(param, 'g', NULL);
					if( urlencoded ) {
						grpname = dc_urldecode(urlencoded);
						free(urlencoded);
					}
				}
			}

			dc_param_unref(param);
		}

		fingerprint = dc_normalize_fingerprint(payload);
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
					dc_str_replace(&name, ";", ","); /* the format "lastname,prename" is handled by mr_normalize_name() */
					mr_normalize_name(name);
				}
			}
		}
		mr_free_splitted_lines(lines);
	}

	/* check the paramters
	  ---------------------- */

	if( addr ) {
		char* temp = dc_urldecode(addr);      free(addr); addr = temp; /* urldecoding is needed at least for OPENPGP4FPR but should not hurt in the other cases */
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

		if( addr == NULL || invitenumber == NULL || auth == NULL )
		{
			// _only_ fingerprint set ...
			// (we could also do this before/instead of a secure-join, however, this may require complicated questions in the ui)
			dc_sqlite3_lock(context->m_sql);
			locked = 1;

				if( dc_apeerstate_load_by_fingerprint__(peerstate, context->m_sql, fingerprint) ) {
					qr_parsed->m_state = MR_QR_FPR_OK;
					qr_parsed->m_id    = dc_add_or_lookup_contact__(context, NULL, peerstate->m_addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);

					dc_create_or_lookup_nchat_by_contact_id__(context, qr_parsed->m_id, MR_CHAT_DEADDROP_BLOCKED, &chat_id, NULL);
					device_msg = dc_mprintf("%s verified.", peerstate->m_addr);
				}
				else {
					qr_parsed->m_text1 = mr_format_fingerprint(fingerprint);
					qr_parsed->m_state = MR_QR_FPR_WITHOUT_ADDR;
				}

			dc_sqlite3_unlock(context->m_sql);
			locked = 0;
		}
		else
		{
			// fingerprint + addr set, secure-join requested
			// do not comapre the fingerprint already - it may have changed - errors are catched later more proberly.
			// (theroretically, there is also the state "addr=set, fingerprint=set, invitenumber=0", however, currently, we won't get into this state)
			dc_sqlite3_lock(context->m_sql);
			locked = 1;

				if( grpid && grpname ) {
					qr_parsed->m_state = MR_QR_ASK_VERIFYGROUP;
					qr_parsed->m_text1 = safe_strdup(grpname);
					qr_parsed->m_text2 = safe_strdup(grpid);
				}
				else {
					qr_parsed->m_state = MR_QR_ASK_VERIFYCONTACT;
				}

				qr_parsed->m_id            = dc_add_or_lookup_contact__(context, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
				qr_parsed->m_fingerprint   = safe_strdup(fingerprint);
				qr_parsed->m_invitenumber  = safe_strdup(invitenumber);
				qr_parsed->m_auth          = safe_strdup(auth);


			dc_sqlite3_unlock(context->m_sql);
			locked = 0;
		}
	}
	else if( addr )
	{
        qr_parsed->m_state = MR_QR_ADDR;
		qr_parsed->m_id    = dc_add_or_lookup_contact__(context, name, addr, MR_ORIGIN_UNHANDLED_QR_SCAN, NULL);
	}
	else if( strstr(qr, "http://")==qr || strstr(qr, "https://")==qr )
	{
		qr_parsed->m_state = MR_QR_URL;
		qr_parsed->m_text1 = safe_strdup(qr);
	}
	else
	{
        qr_parsed->m_state = MR_QR_TEXT;
		qr_parsed->m_text1 = safe_strdup(qr);
	}

	if( device_msg ) {
		dc_add_device_msg(context, chat_id, device_msg);
	}

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	free(addr);
	free(fingerprint);
	dc_apeerstate_unref(peerstate);
	free(payload);
	free(name);
	free(invitenumber);
	free(auth);
	free(device_msg);
	free(grpname);
	free(grpid);
	return qr_parsed;
}


