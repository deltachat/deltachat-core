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


static struct mailmime* new_data_part(void* data, size_t data_bytes, char* default_content_type, int default_encoding)
{
  //char basename_buf[PATH_MAX];
  struct mailmime_mechanism * encoding;
  struct mailmime_content * content;
  struct mailmime * mime;
  //int r;
  //char * dup_filename;
  struct mailmime_fields * mime_fields;
  int encoding_type;
  char * content_type_str;
  int do_encoding;

  /*if (filename != NULL) {
    strncpy(basename_buf, filename, PATH_MAX);
    libetpan_basename(basename_buf);
  }*/

  encoding = NULL;

  /* default content-type */
  if (default_content_type == NULL)
    content_type_str = "application/octet-stream";
  else
    content_type_str = default_content_type;

  content = mailmime_content_new_with_str(content_type_str);
  if (content == NULL) {
    goto free_content;
  }

  do_encoding = 1;
  if (content->ct_type->tp_type == MAILMIME_TYPE_COMPOSITE_TYPE) {
    struct mailmime_composite_type * composite;

    composite = content->ct_type->tp_data.tp_composite_type;

    switch (composite->ct_type) {
    case MAILMIME_COMPOSITE_TYPE_MESSAGE:
      if (strcasecmp(content->ct_subtype, "rfc822") == 0)
        do_encoding = 0;
      break;

    case MAILMIME_COMPOSITE_TYPE_MULTIPART:
      do_encoding = 0;
      break;
    }
  }

  if (do_encoding) {
    if (default_encoding == -1)
      encoding_type = MAILMIME_MECHANISM_BASE64;
    else
      encoding_type = default_encoding;

    /* default Content-Transfer-Encoding */
    encoding = mailmime_mechanism_new(encoding_type, NULL);
    if (encoding == NULL) {
      goto free_content;
    }
  }

  mime_fields = mailmime_fields_new_with_data(encoding,
      NULL, NULL, NULL, NULL);
  if (mime_fields == NULL) {
    goto free_content;
  }

  mime = mailmime_new_empty(content, mime_fields);
  if (mime == NULL) {
    goto free_mime_fields;
  }

  /*if ((filename != NULL) && (mime->mm_type == MAILMIME_SINGLE)) {
    // duplicates the file so that the file can be deleted when
    // the MIME part is done
    dup_filename = dup_file(privacy, filename);
    if (dup_filename == NULL) {
      goto free_mime;
    }

    r = mailmime_set_body_file(mime, dup_filename);
    if (r != MAILIMF_NO_ERROR) {
      free(dup_filename);
      goto free_mime;
    }
  }*/
  if( data!=NULL && data_bytes>0 && mime->mm_type == MAILMIME_SINGLE ) {
	mailmime_set_body_text(mime, data, data_bytes);
  }

  return mime;

// free_mime:
  //mailmime_free(mime);
  goto err;
 free_mime_fields:
  mailmime_fields_free(mime_fields);
  mailmime_content_free(content);
  goto err;
 free_content:
  if (encoding != NULL)
    mailmime_mechanism_free(encoding);
  if (content != NULL)
    mailmime_content_free(content);
 err:
  return NULL;
}


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


void mre2ee_encrypt(mrmailbox_t* mailbox, const clist* recipients_addr, struct mailmime* in_out_message, mre2ee_helper_t* helper)
{
	int                    locked = 0, col = 0, do_encrypt = 0;
	mrapeerstate_t*        peerstate = mrapeerstate_new();
	mraheader_t*           autocryptheader = mraheader_new();
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mrkeyring_t*           keyring = mrkeyring_new();
	MMAPString*            plain = mmap_string_new("");
	char*                  ctext = NULL;
	size_t                 ctext_bytes = 0;

	if( helper ) { memset(helper, 0, sizeof(mre2ee_helper_t)); }

	if( mailbox == NULL || recipients_addr == NULL || in_out_message == NULL
	 || in_out_message->mm_parent /* libEtPan's pgp_encrypt_mime() takes the parent as the new root. We just expect the root as being given to this function. */
	 || peerstate == NULL || autocryptheader == NULL || keyring==NULL || plain == NULL || helper == NULL ) {
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
		/* prepare part to encrypt */
		mailprivacy_prepare_mime(in_out_message); /* encode quoted printable all text parts */

		struct mailmime* part_to_encrypt = in_out_message->mm_data.mm_message.mm_msg_mime;

		/* convert part to encrypt to plain text */
		mailmime_write_mem(plain, &col, part_to_encrypt);
		if( plain->str == NULL || plain->len<=0 ) {
			goto cleanup;
		}
		#if 0
		char* t1=mr_null_terminate(plain->str,plain->len);printf("PLAIN:\n%s\n",t1);free(t1);
		#endif

		/* encrypt the plain text */
		mrkeyring_add(keyring, peerstate->m_public_key);
		if( !mre2ee_driver_encrypt(mailbox, plain->str, plain->len, keyring, 1, (void**)&ctext, &ctext_bytes) ) {
			goto cleanup;
		}
		helper->m_cdata_to_free = ctext;
		#if 0
		char* t2=mr_null_terminate(ctext,ctext_bytes);printf("ENCRYPTED:\n%s\n",t2);free(t2);
		#endif

		/* create MIME-structure that will contain the encrypted text */
		struct mailmime* encrypted_part = new_data_part(NULL, 0, "multipart/encrypted", -1);

		struct mailmime_content* content = encrypted_part->mm_content_type;
		clist_append(content->ct_parameters, mailmime_param_new_with_data("protocol", "application/pgp-encrypted"));

		static char version_content[] = "Version: 1\r\n";
		struct mailmime* version_mime = new_data_part(version_content, strlen(version_content), "application/pgp-encrypted", MAILMIME_MECHANISM_7BIT);
		mailmime_smart_add_part(encrypted_part, version_mime);

		struct mailmime* ctext_part = new_data_part(ctext, ctext_bytes, "application/octet-stream", MAILMIME_MECHANISM_7BIT);
		mailmime_smart_add_part(encrypted_part, ctext_part);

		/* replace the original MIME-structure by the encrypted MIME-structure */
		in_out_message->mm_data.mm_message.mm_msg_mime = encrypted_part;
		encrypted_part->mm_parent = in_out_message;
		part_to_encrypt->mm_parent = NULL;
		mailmime_free(part_to_encrypt);

		#if 0
		MMAPString* t3=mmap_string_new("");mailmime_write_mem(t3,&col,in_out_message);char* t4=mr_null_terminate(t3->str,t3->len); printf("ENCRYPTED+MIME_ENCODED:\n%s\n",t4);free(t4);mmap_string_free(t3);
		#endif

		helper->m_encryption_successfull = 1;
		/* the subject in PGP-messages is not encrypted - replace it by a standard text à la "Chat: Encrypted message" */

		// TODO: subject
	}

	/* add Autocrypt:-header to allow the recipient to send us encrypted messages back */
	imffields = mr_find_mailimf_fields(in_out_message);
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
}


void mre2ee_thanks(mre2ee_helper_t* helper)
{
	if( helper == NULL ) {
		return;
	}

	free(helper->m_cdata_to_free);
	helper->m_cdata_to_free = NULL;
}


void mre2ee_decrypt(mrmailbox_t* mailbox, struct mailmime* in_out_message)
{
	struct mailimf_fields* imffields = NULL; /*just a pointer into mailmime structure, must not be freed*/
	mraheader_t*           autocryptheader = NULL;
	int                    autocryptheader_fine = 0;
	time_t                 message_time = 0;
	mrapeerstate_t*        peerstate = NULL;
	int                    locked = 0;
	char*                  from = NULL, *self_addr = NULL;
	mrkey_t*               private_key = mrkey_new();

	if( mailbox == NULL || in_out_message == NULL
	 || private_key == NULL ) {
		goto cleanup;
	}

	peerstate = mrapeerstate_new();
	autocryptheader = mraheader_new();
	imffields = mr_find_mailimf_fields(in_out_message);

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

