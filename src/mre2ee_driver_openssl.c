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
#include <sys/types.h> /* for getpid() */
#include <unistd.h>    /* for getpid() */
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <netpgp-extra.h>
#include "mrmailbox.h"
#include "mrkey.h"
#include "mre2ee.h"
#include "mre2ee_driver.h"
#include "mrtools.h"


void mre2ee_driver_init(mrmailbox_t* mailbox)
{
	SSL_library_init(); /* older, but more compatible function, simply defined as OPENSSL_init_ssl().
						SSL_library_init() should be called from the main thread before OpenSSL is called from other threads.
	                    libEtPan may call SSL_library_init() again later, however, this should be no problem.
	                    SSL_library_init() always returns "1", so it is safe to discard the return value */

	/* seed random generator a little bit */
	{
	uintptr_t seed[4];
	seed[0] = (uintptr_t)time(NULL); /* time */
	seed[1] = (uintptr_t)getpid();   /* process ID */
	seed[2] = (uintptr_t)seed;       /* stack */
	seed[3] = (uintptr_t)mailbox;    /* heap */
	RAND_seed(seed, sizeof(seed));
	}

}


void mre2ee_driver_exit(mrmailbox_t* mailbox)
{
}


int mre2ee_driver_create_keypair(mrmailbox_t* mailbox, const char* addr, mrkey_t* ret_public_key, mrkey_t* ret_private_key)
{
	int              success = 0;
	pgp_key_t        seckey, pubkey, subkey;
	pgp_subkey_t*    subkeyp; /* just a pointer inside another key, must not be freed */
	pgp_subkeysig_t* subkeysigp; /* just a pointer inside another key, must not be freed */
	uint8_t          subkeyid[PGP_KEY_ID_SIZE];
	char*            user_id = NULL;
	pgp_memory_t     *pubmem = pgp_memory_new(), *secmem = pgp_memory_new();
	pgp_output_t     *pubout = pgp_output_new(), *secout = pgp_output_new();

	mrkey_empty(ret_public_key);
	mrkey_empty(ret_private_key);
	memset(&seckey, 0, sizeof(pgp_key_t));
	memset(&pubkey, 0, sizeof(pgp_key_t));
	memset(&subkey, 0, sizeof(pgp_key_t));

	if( mailbox==NULL || addr==NULL || ret_public_key==NULL || ret_private_key==NULL
	 || pubmem==NULL || secmem==NULL || pubout==NULL || secout==NULL ) {
		goto cleanup;
	}

	/* seed random generator a little bit */
	{
	uintptr_t seed[4];
	RAND_seed(addr, strlen(addr));   /* user's mail address */
	seed[0] = (uintptr_t)time(NULL); /* time */
	seed[1] = (uintptr_t)getpid();   /* process ID */
	seed[2] = (uintptr_t)&addr;      /* stack */
	seed[3] = (uintptr_t)addr;       /* heap */
	RAND_seed(seed, sizeof(seed));
	}

	/* Generate User ID.  For convention, use the same address as given in `Autocrypt: to=...` in angle brackets
	(RFC 2822 grammar angle-addr, see also https://autocrypt.org/en/latest/level0.html#type-p-openpgp-based-key-data )
	We do not add the name to the ID for the following reasons:
	- privacy
	- the name may be changed
	- shorter keys
	- the name is already taken from From:
	- not Autocrypt:-standard */
	user_id = mr_mprintf("<%s>", addr);

	/* generate two keypairs */
	if( !pgp_rsa_generate_keypair(&seckey, 2048/*bits*/, 65537UL/*e*/, NULL, NULL, NULL, 0)
	 || !pgp_rsa_generate_keypair(&subkey, 2048/*bits*/, 65537UL/*e*/, NULL, NULL, NULL, 0) ) {
		goto cleanup;
	}

    /* make a public key out of generated secret key */
	pubkey.type = PGP_PTAG_CT_PUBLIC_KEY;
	pgp_pubkey_dup(&pubkey.key.pubkey, &seckey.key.pubkey);
	memcpy(pubkey.pubkeyid, seckey.pubkeyid, PGP_KEY_ID_SIZE);
	pgp_fingerprint(&pubkey.pubkeyfpr, &seckey.key.pubkey, 0);
	pgp_add_selfsigned_userid(&seckey, &pubkey, (const uint8_t*)user_id, 0/*never expire*/);

	/* add subkey to public key and sign it (cmp. pgp_update_subkey()) */
	EXPAND_ARRAY((&pubkey), subkey);
	subkeyp = &pubkey.subkeys[pubkey.subkeyc++];
	pgp_pubkey_dup(&subkeyp->key.pubkey, &subkey.key.pubkey);
	pgp_keyid(subkeyid, PGP_KEY_ID_SIZE, &pubkey.key.pubkey, PGP_HASH_SHA1);
	memcpy(subkeyp->id, subkeyid, PGP_KEY_ID_SIZE);

	// TODO: add "0x18: Subkey Binding Signature" packet
	//EXPAND_ARRAY((&pubkey), subkeysig);
	//subkeysigp = &pubkey.subkeysigs[pubkey.subkeysigc++];

	/* add subkey to private key */
	EXPAND_ARRAY((&seckey), subkey);
	subkeyp = &seckey.subkeys[seckey.subkeyc++];
	pgp_seckey_dup(&subkeyp->key.seckey, &subkey.key.seckey);
	pgp_keyid(subkeyid, PGP_KEY_ID_SIZE, &seckey.key.pubkey, PGP_HASH_SHA1);
	memcpy(subkeyp->id, subkeyid, PGP_KEY_ID_SIZE);

	/* return keys */
	pgp_writer_set_memory(pubout, pubmem);
	if( !pgp_write_xfer_key(pubout, &pubkey, 0/*armoured*/)
	 || pubmem->buf == NULL || pubmem->length <= 0 ) {
		goto cleanup;
	}

	pgp_writer_set_memory(secout, secmem);
	if( !pgp_write_xfer_key(secout, &seckey, 0/*armoured*/)
	 || secmem->buf == NULL || secmem->length <= 0 ) {
		goto cleanup;
	}

	mrkey_set_from_raw(ret_public_key, (const unsigned char*)pubmem->buf, pubmem->length, MR_PRIVATE);
	mrkey_set_from_raw(ret_private_key, (const unsigned char*)secmem->buf, secmem->length, MR_PRIVATE);

	success = 1;

cleanup:
	if( pubout ) { pgp_output_delete(pubout); }
	if( secout ) { pgp_output_delete(secout); }
	if( pubmem ) { pgp_memory_free(pubmem); }
	if( secmem ) { pgp_memory_free(secmem); }
	pgp_key_free(&seckey); pgp_key_free(&pubkey); pgp_key_free(&subkey); /* not: pgp_keydata_free() which will also free the pointer itself (we created it on the statck) */
	free(user_id);
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
