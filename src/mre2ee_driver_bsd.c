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
 * File:    mre2ee_driver_bsd.c
 * Purpose: End-To-End-Encryption based upon BSD's netpgp.
 *
 *******************************************************************************
 *
 * If we want to switch to other encryption engines, here are the functions to
 * be replaced.
 *
 * However, eg. GpgME cannot (easily) be used standalone and GnuPG's licence
 * would not allow the original creator of Delta Chat to release a proprietary
 * version, which, however, is required for the Apple store. (NB: the original
 * creator is the only person who could do this, a normal licensee is not
 * allowed to do so at all)
 *
 * So, we do not see a simple alternative - but everyone is welcome to implement
 * one :-)
 *
 ******************************************************************************/


#include <string.h>

#include <netpgp.h>
#include "packet-parse.h"
#include "errors.h"
#include "netpgpdefs.h"
#include "crypto.h"
#include "create.h"

#include "mrmailbox.h"
#include "mrkey.h"
#include "mre2ee.h"
#include "mre2ee_driver.h"

unsigned rsa_generate_keypair(pgp_key_t *keydata, const int numbits, const unsigned long e, const char *hashalg, const char *cipher);
unsigned write_seckey_body(const pgp_seckey_t *key, const uint8_t *passphrase, const size_t pplen, pgp_output_t *output);


void mre2ee_driver_init(mrmailbox_t* mailbox)
{
}


void mre2ee_driver_exit(mrmailbox_t* mailbox)
{
}


int mre2ee_driver_create_keypair(mrmailbox_t* mailbox, mrkey_t* ret_public_key, mrkey_t* ret_private_key)
{
	int           success = 0;
	pgp_key_t*    keypair = NULL;
	pgp_memory_t* public_key_mem = NULL;
	pgp_memory_t* private_key_mem = NULL;
	pgp_output_t* output = NULL;

	mrkey_empty(ret_public_key);
	mrkey_empty(ret_private_key);

	if( mailbox==NULL || ret_public_key==NULL || ret_private_key==NULL ) {
		goto cleanup;
	}

	/* original calls: */
	#if 0
	{
		netpgp_t netpgp;
		memset(&netpgp, 0, sizeof(netpgp_t));
		netpgp_set_homedir(&netpgp, mailbox->m_blobdir, NULL, 1);
		netpgp_init(&netpgp);
		netpgp_generate_key(&netpgp, "foobar", 2048); // <-- this calls rsa_generate_keypair()
		netpgp_end(&netpgp);
	}
	#endif

	/* generate keypair */
	if( (keypair=pgp_keydata_new())==NULL ) {
		goto cleanup;
	}

	if (!rsa_generate_keypair(keypair, 2048/*bits*/, 65537UL/*e*/, NULL/*hash*/, NULL/*cipher*/) ) {
		goto cleanup;
	}

	/* get public key */
	if( (public_key_mem=pgp_memory_new())==NULL ) {
		goto cleanup;
	}

	pgp_build_pubkey(public_key_mem, &keypair->key.seckey.pubkey, 0);
	if( public_key_mem->buf == NULL || public_key_mem->length <= 0 ) {
		goto cleanup;
	}

	mrkey_set_from_raw(ret_public_key, (const unsigned char*)public_key_mem->buf, public_key_mem->length, MR_PUBLIC);

	/* write private key
	(pgp_write_struct_seckey() would write public+private key according to RFC4880 Section 5.5.3, see also pgp_write_xfer_seckey()) */
	if( (private_key_mem=pgp_memory_new())==NULL ) {
		goto cleanup;
	}

	const char* passphrase = "passphrase";
	output = pgp_output_new();
	pgp_writer_set_memory(output, private_key_mem);
	write_seckey_body(&keypair->key.seckey, (const uint8_t*)passphrase, strlen(passphrase), output); // write only private key

	if( private_key_mem->buf == NULL || private_key_mem->length <= 0 ) {
		goto cleanup;
	}

	mrkey_set_from_raw(ret_private_key, (const unsigned char*)private_key_mem->buf, private_key_mem->length, MR_PRIVATE);

	success = 1;

cleanup:
	if( public_key_mem ) { pgp_memory_free(public_key_mem); }
	if( private_key_mem ) { pgp_memory_free(private_key_mem); }
	if( keypair ) { pgp_keydata_free(keypair); }
	if( output ) { pgp_output_delete(output); }
	return success;
}


void mre2ee_driver_encrypt__(mrmailbox_t* mailbox, struct mailmime** in_out_message, const mrkey_t* public_key)
{
	if( mailbox==NULL || in_out_message==NULL || *in_out_message==NULL || public_key==NULL ) {
		return;
	}
}


void mre2ee_driver_decrypt__(mrmailbox_t* mailbox, struct mailmime** in_out_message, const mrkey_t* private_key)
{
	if( mailbox==NULL || in_out_message==NULL || *in_out_message==NULL ) {
		return;
	}
}
