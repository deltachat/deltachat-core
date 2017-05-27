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
 * File:    mre2ee.c
 * Purpose: Handle End-To-End-Encryption
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mre2ee.h"
#include "mre2ee_driver.h"
#include "mrapeerstate.h"
#include "mraheader.h"
#include "mrkeyring.h"
#include "mrmimeparser.h"
#include "mrtools.h"


#if 0
static int pgp_encrypt_mime(struct mailprivacy * privacy,
    mailmessage * msg,
    struct mailmime * mime, struct mailmime ** result)
{
  /*char original_filename[PATH_MAX];
  FILE * original_f;
  int res;
  int r;
  int col;
  char description_filename[PATH_MAX];
  char encrypted_filename[PATH_MAX];
  char version_filename[PATH_MAX];
  FILE * version_f;
  char command[PATH_MAX];
  char quoted_original_filename[PATH_MAX];
  struct mailmime * version_mime;
  struct mailmime * multipart;
  struct mailmime_content * content;
  struct mailmime_parameter * param;
  struct mailmime * encrypted_mime;
  char recipient[PATH_MAX];
  struct mailimf_fields * fields;
  struct mailmime * root;
  size_t written;
  int encrypt_ok;

  root = mime;
  while (root->mm_parent != NULL)
    root = root->mm_parent;

  fields = NULL;
  if (root->mm_type == MAILMIME_MESSAGE)
    fields = root->mm_data.mm_message.mm_fields;*/

  /* recipient */

  //collect_recipient(recipient, sizeof(recipient), fields);

  /* part to encrypt */

  /* encode quoted printable all text parts */

  mailprivacy_prepare_mime(mime);

  original_f = mailprivacy_get_tmp_file(privacy,
      original_filename, sizeof(original_filename));
  if (original_f == NULL) {
    res = MAIL_ERROR_FILE;
    goto err;
  }

  col = 0;
  r = mailmime_write(original_f, &col, mime); // <---- write mail to file which is given to GnuPG then
  if (r != MAILIMF_NO_ERROR) {				   // calls mailmime_write_file() -> mailmime_fields_write_driver
    fclose(original_f);
    res = MAIL_ERROR_FILE;
    goto unlink_original;
  }

  fclose(original_f);

  /* prepare destination file for encryption */

  r = mailprivacy_get_tmp_filename(privacy, encrypted_filename,
      sizeof(encrypted_filename));
  if (r != MAIL_NO_ERROR) {
    res = r;
    goto unlink_original;
  }

  r = mail_quote_filename(quoted_original_filename,
       sizeof(quoted_original_filename), original_filename);
  if (r < 0) {
    res = MAIL_ERROR_MEMORY;
    goto unlink_encrypted;
  }

  r = mailprivacy_get_tmp_filename(privacy, description_filename,
      sizeof(description_filename));
  if (r != MAIL_NO_ERROR) {
    res = r;
    goto unlink_encrypted;
  }

  snprintf(command, sizeof(command), "gpg %s -a --batch --yes -e '%s'",
      recipient, quoted_original_filename);

  encrypt_ok = 0;
  r = gpg_command_passphrase(privacy, msg, command, NULL,
      encrypted_filename, description_filename);
  switch (r) {
  case NO_ERROR_PGP:
    encrypt_ok = 1;
    break;
  case ERROR_PGP_NOPASSPHRASE:
  case ERROR_PGP_CHECK:
    encrypt_ok = 0;
    break;
  case ERROR_PGP_COMMAND:
    res = MAIL_ERROR_COMMAND;
    goto unlink_description;
  case ERROR_PGP_FILE:
    res = MAIL_ERROR_FILE;
    goto unlink_description;
  }

  if (!encrypt_ok) {
    res = MAIL_ERROR_COMMAND;
    goto unlink_description;
  }

  /* multipart */

  multipart = mailprivacy_new_file_part(privacy, NULL,
      "multipart/encrypted", -1);

  content = multipart->mm_content_type;

  param = mailmime_param_new_with_data("protocol",
      "application/pgp-encrypted");
  if (param == NULL) {
    mailmime_free(multipart);
    res = MAIL_ERROR_MEMORY;
    goto unlink_description;
  }

  r = clist_append(content->ct_parameters, param);
  if (r < 0) {
    mailmime_parameter_free(param);
    mailmime_free(multipart);
    res = MAIL_ERROR_MEMORY;
    goto unlink_description;
  }

  /* version part */

  version_f = mailprivacy_get_tmp_file(privacy,
      version_filename, sizeof(version_filename));
  if (version_f == NULL) {
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = MAIL_ERROR_FILE;
    goto unlink_description;
  }
  written = fwrite(PGP_VERSION, 1, sizeof(PGP_VERSION) - 1, version_f);
  if (written != sizeof(PGP_VERSION) - 1) {
    fclose(version_f);
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = MAIL_ERROR_FILE;
    goto unlink_description;
  }
  fclose(version_f);

  version_mime = mailprivacy_new_file_part(privacy,
      version_filename,
      "application/pgp-encrypted",
      MAILMIME_MECHANISM_8BIT);
  if (r != MAIL_NO_ERROR) {
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = r;
    goto unlink_version;
  }

  r = mailmime_smart_add_part(multipart, version_mime);
  if (r != MAIL_NO_ERROR) {
    mailprivacy_mime_clear(version_mime);
    mailmime_free(version_mime);
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = MAIL_ERROR_MEMORY;
    goto unlink_version;
  }

  /* encrypted part */

  encrypted_mime = mailprivacy_new_file_part(privacy,
      encrypted_filename,
      "application/octet-stream",
      MAILMIME_MECHANISM_8BIT);
  if (r != MAIL_NO_ERROR) {
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = r;
    goto unlink_version;
  }

  r = mailmime_smart_add_part(multipart, encrypted_mime);
  if (r != MAIL_NO_ERROR) {
    mailprivacy_mime_clear(encrypted_mime);
    mailmime_free(encrypted_mime);
    mailprivacy_mime_clear(multipart);
    mailmime_free(multipart);
    res = MAIL_ERROR_MEMORY;
    goto unlink_version;
  }

  unlink(version_filename);
  unlink(description_filename);
  unlink(encrypted_filename);
  unlink(original_filename);

  * result = multipart;

  return MAIL_NO_ERROR;

 unlink_version:
  unlink(version_filename);
 unlink_description:
  unlink(description_filename);
 unlink_encrypted:
  unlink(encrypted_filename);
 unlink_original:
  unlink(original_filename);
 err:
  return res;
}
#endif


/*******************************************************************************
 * Tools
 ******************************************************************************/


static int load_or_generate_public_key__(mrmailbox_t* mailbox, mrkey_t* public_key, const char* self_addr)
{
	static int s_in_key_creation = 0; /* avoid double creation (we unlock the database during creation) */
	int        key_created = 0;
	int        success = 0, key_creation_here = 0;

	if( mailbox == NULL || public_key == NULL ) {
		goto cleanup;
	}

	if( !mrkey_load_self_public__(public_key, self_addr, mailbox->m_sql) )
	{
		/* create the keypair - this may take a moment, however, as this is in a thread, this is no big deal */
		if( s_in_key_creation ) { goto cleanup; }
		key_creation_here = 1;
		s_in_key_creation = 1;

		{
			mrkey_t* private_key = mrkey_new();

			mrmailbox_log_info(mailbox, 0, "Generating keypair ...");

			mrsqlite3_unlock(mailbox->m_sql); /* SIC! unlock database during creation - otherwise the GUI may hang */

				/* The public key must contain the following:
				- a signing-capable primary key Kp
				- a user id
				- a self signature
				- an encryption-capable subkey Ke
				- a binding signature over Ke by Kp
				(see https://autocrypt.readthedocs.io/en/latest/level0.html#type-p-openpgp-based-key-data )*/
				key_created = mre2ee_driver_create_keypair(mailbox, self_addr, public_key, private_key);

			mrsqlite3_lock(mailbox->m_sql);

			if( !key_created ) {
				mrmailbox_log_warning(mailbox, 0, "Cannot create keypair.");
				goto cleanup;
			}

			if( !mre2ee_driver_is_valid_key(mailbox, public_key)
			 || !mre2ee_driver_is_valid_key(mailbox, private_key) ) {
				mrmailbox_log_warning(mailbox, 0, "Generated keys are not valid.");
				goto cleanup;
			}

			if( !mrkey_save_self_keypair__(public_key, private_key, self_addr, mailbox->m_sql) ) {
				mrmailbox_log_warning(mailbox, 0, "Cannot save keypair.");
				goto cleanup;
			}

			mrmailbox_log_info(mailbox, 0, "Keypair generated.");

			mrkey_unref(private_key);
		}
	}

	success = 1;

cleanup:
	if( key_creation_here ) { s_in_key_creation = 0; }
	return success;
}


/*******************************************************************************
 * Main interface
 ******************************************************************************/


void mre2ee_init(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	mre2ee_driver_init(mailbox);
}


void mre2ee_exit(mrmailbox_t* mailbox)
{
	if( mailbox == NULL ) {
		return;
	}

	mre2ee_driver_exit(mailbox);
}


void mre2ee_encrypt(mrmailbox_t* mailbox, const clist* recipients_addr, struct mailmime** in_out_message)
{
	int                    locked = 0, col = 0, do_encrypt = 0;
	mrapeerstate_t*        peerstate = mrapeerstate_new();
	mraheader_t*           autocryptheader = mraheader_new();
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mrkeyring_t*           keyring = mrkeyring_new();
	MMAPString*            plain = mmap_string_new("");
	char*                  ctext = NULL;
	size_t                 ctext_bytes = 0;

	if( mailbox == NULL || recipients_addr == NULL || in_out_message == NULL || *in_out_message == NULL
	 || (*in_out_message)->mm_parent /* libEtPan's pgp_encrypt_mime() takes the parent as the new root. We just expect the root as being given to this function. */
	 || peerstate == NULL || autocryptheader == NULL || keyring==NULL || plain == NULL ) {
		goto cleanup;
	}

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* encryption enabled? */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", MR_E2EE_DEFAULT_ENABLED) == 0 ) {
			goto cleanup;
		}

		/* load autocrypt header from db */
		autocryptheader->m_prefer_encrypted = MRA_PE_NOPREFERENCE;
		autocryptheader->m_to = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
		if( autocryptheader->m_to == NULL ) {
			goto cleanup;
		}

		if( !load_or_generate_public_key__(mailbox, autocryptheader->m_public_key, autocryptheader->m_to) ) {
			goto cleanup;
		}

		/* load peerstate information etc. */
		if( clist_count(recipients_addr)==1 ) {
			clistiter* iter1 = clist_begin(recipients_addr);
			const char* recipient_addr = clist_content(iter1);
			if( mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, recipient_addr)
			 && peerstate->m_prefer_encrypted!=MRA_PE_NO ) {
				do_encrypt = 1;
			}
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* encrypt message, if possible */
	if( do_encrypt )
	{
		struct mailmime* in_message = *in_out_message;

		mailprivacy_prepare_mime(in_message); /* encode quoted printable all text parts */

		mailmime_write_mem(plain, &col, in_message);
		if( plain->str == NULL || plain->len<=0 ) {
			goto cleanup;
		}

		// char* t1 = mr_null_terminate(plain->str, plain->len); printf("PLAIN:\n%s\n", t1); free(t1);

		mrkeyring_add(keyring, peerstate->m_public_key);
		if( !mre2ee_driver_encrypt__(mailbox, plain->str, plain->len, keyring, 1, (void**)&ctext, &ctext_bytes) ) {
			goto cleanup;
		}

		// char* t2 = mr_null_terminate(ctext, ctext_bytes); printf("ENCRYPTED:\n%s\n", t2); free(t2);
	}

	/* add Autocrypt:-header to allow the recipient to send us encrypted messages back
	(do this last to avoid blowing up the encrypted part and to allow reading the key if decryption fails) */
	imffields = mr_find_mailimf_fields(*in_out_message);
	char* p = mraheader_render(autocryptheader);
	if( p == NULL ) {
		goto cleanup;
	}
	mailimf_fields_add(imffields, mailimf_field_new_custom(strdup("Autocrypt"), p/*takes ownership of pointer*/));

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrapeerstate_unref(peerstate);
	mraheader_unref(autocryptheader);
	mrkeyring_unref(keyring);
	if( plain ) { mmap_string_free(plain); }
	free(ctext);
}


void mre2ee_decrypt(mrmailbox_t* mailbox, struct mailmime** in_out_message)
{
	struct mailmime*       in_message = NULL;
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mraheader_t*           autocryptheader = NULL;
	int                    autocryptheader_fine = 0;
	time_t                 message_time = 0;
	mrapeerstate_t*        peerstate = NULL;
	int                    locked = 0;
	char*                  from = NULL, *self_addr = NULL;
	mrkey_t*               private_key = mrkey_new();

	if( mailbox == NULL || in_out_message == NULL || *in_out_message == NULL
	 || private_key == NULL ) {
		goto cleanup;
	}

	peerstate = mrapeerstate_new();
	autocryptheader = mraheader_new();
	in_message = *in_out_message;
	imffields = mr_find_mailimf_fields(in_message);

	/* get From: and Date: */
	{
		struct mailimf_field* field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_FROM);
		if( field && field->fld_data.fld_from ) {
			from = mr_find_first_addr(field->fld_data.fld_from->frm_mb_list);
		}

		field = mr_find_mailimf_field(imffields, MAILIMF_FIELD_ORIG_DATE);
		if( field && field->fld_data.fld_orig_date ) {
			struct mailimf_orig_date* orig_date = field->fld_data.fld_orig_date;
			if( orig_date ) {
				message_time = mr_timestamp_from_date(orig_date->dt_date_time); /* is not yet checked against bad times! */
				if( message_time != MR_INVALID_TIMESTAMP && message_time > time(NULL) ) {
					message_time = time(NULL);
				}
			}
		}

		if( message_time <= 0 ) {
			goto cleanup; /* from checked later, may be set by Autocrypt:-header */
		}
	}

	/* check the autocrypt header, if any */
	autocryptheader_fine = mraheader_set_from_imffields(autocryptheader, imffields);
	if( autocryptheader_fine ) {
		if( from == NULL ) {
			from = safe_strdup(autocryptheader->m_to);
		}
		else if( strcasecmp(autocryptheader->m_to, from /*SIC! compare to= against From: - the key is for answering!*/)!=0 ) {
			autocryptheader_fine = 0;
		}

		if( !mre2ee_driver_is_valid_key(mailbox, autocryptheader->m_public_key) ) {
			autocryptheader_fine = 0;
		}
	}

	if( from == NULL ) {
		goto cleanup;
	}

	/* modify the peerstate (eg. if there is a peer but not autocrypt header, stop encryption) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		/* apply Autocrypt:-header only if encryption is enabled (if we're out of beta, we should do this always to track the correct state; now we want no bugs spread widely to the databases :-) */
		if( mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", MR_E2EE_DEFAULT_ENABLED) != 0 )
		{
			if( mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, from) ) {
				if( autocryptheader_fine ) {
					mrapeerstate_apply_header(peerstate, autocryptheader, message_time);
					mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0/*no not create*/);
				}
				else {
					if( message_time > peerstate->m_last_seen ) {
						mrapeerstate_degrade_encryption(peerstate, message_time);
						mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0/*no not create*/);
					}
				}
			}
			else if( autocryptheader_fine ) {
				mrapeerstate_init_from_header(peerstate, autocryptheader, message_time);
				mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 1/*create*/);
			}
		}

		/* load private key for decryption */
		if( (self_addr=mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL))==NULL ) {
			goto cleanup;
		}

		if( !mrkey_load_self_private__(private_key, self_addr, mailbox->m_sql) ) {
			goto cleanup;
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* finally, decrypt */
	//mre2ee_driver_decrypt__(mailbox, in_out_message, &private_key);

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mraheader_unref(autocryptheader);
	mrapeerstate_unref(peerstate);
	mrkey_unref(private_key);
	free(from);
	free(self_addr);
}

