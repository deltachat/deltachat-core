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
 * File:    mrasetup.c
 * Purpose: Generate and process Autocrypt Setup Messages
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "mrmailbox.h"
#include "mrasetup.h"
#include "mrkey.h"
#include "mrkeyring.h"


/* a complete Autocrypt Setup Message looks like the following

To: me@mydomain.com
From: me@mydomain.com
Autocrypt-Setup-Message: v1
Content-type: multipart/mixed; boundary="==break1=="

	--==break1==
	Content-Type: text/plain

	This is the Autocrypt setup message.

	--==break1==
	Content-Type: application/autocrypt-key-backup
	Content-Disposition: attachment; filename="autocrypt-key-backup.html"

	<html>
	<body>
	<p>
		This is the Autocrypt setup file used to transfer keys between clients.
	</p>
	<pre>
	-----BEGIN PGP MESSAGE-----
	Version: BCPG v1.53
	Passphrase-Format: numeric9x4
	Passphrase-Begin: 12

	hQIMAxC7JraDy7DVAQ//SK1NltM+r6uRf2BJEg+rnpmiwfAEIiopU0LeOQ6ysmZ0
	CLlfUKAcryaxndj4sBsxLllXWzlNiFDHWw4OOUEZAZd8YRbOPfVq2I8+W4jO3Moe
	-----END PGP MESSAGE-----
	</pre>
	</body>
	</html>
	--==break1==--

The encrypted message part contains:

	Content-type: multipart/mixed; boundary="==break2=="
	Autocrypt-Prefer-Encrypt: mutual

	--==break2==
	Content-type: application/autocrypt-key-backup

	-----BEGIN PGP PRIVATE KEY BLOCK-----
	Version: GnuPG v1.2.3 (GNU/Linux)

	xcLYBFke7/8BCAD0TTmX9WJm9elc7/xrT4/lyzUDMLbuAuUqRINtCoUQPT2P3Snfx/jou1YcmjDgwT
	Ny9ddjyLcdSKL/aR6qQ1UBvlC5xtriU/7hZV6OZEmW2ckF7UgGd6ajE+UEjUwJg2+eKxGWFGuZ1P7a
	4Av1NXLayZDsYa91RC5hCsj+umLN2s+68ps5pzLP3NoK2zIFGoCRncgGI/pTAVmYDirhVoKh14hCh5
	.....
	-----END PGP PRIVATE KEY BLOCK-----
	--==break2==--

mrasetup_render_keys_to_html() renders the part after the second `-==break1==` part in this example. */
int mrasetup_render_keys_to_html(mrmailbox_t* mailbox, mrkeyring_t* private_keys, int prefer_encrypt, char** ret_msg, char** ret_setup_code)
{
	int              success = 0;
	struct mailmime* payload_mime = NULL;
	int              k;

	if( mailbox==NULL || private_keys==NULL || private_keys->m_count<=0 || ret_msg==NULL || ret_setup_code==NULL
	 || *ret_msg!=NULL || *ret_setup_code!=NULL ) {
		goto cleanup;
	}

	payload_mime = mailmime_multiple_new("multipart/mixed;");
    for( k = 0; k < private_keys->m_count; k++ )
    {
		char* key_asc = mrkey_render_asc(private_keys->m_keys[k]);
		if( key_asc == NULL ) {
			goto cleanup;
		}

		struct mailmime_content* content_type = mailmime_content_new_with_str("application/autocrypt-key-backup");
		struct mailmime_fields* mime_fields = mailmime_fields_new_empty();
		struct mailmime* key_mime = mailmime_new_empty(content_type, mime_fields);
		mailmime_set_body_text(key_mime, key_asc, strlen(key_asc));

		mailmime_smart_add_part(payload_mime, key_mime);
    }

cleanup:
	if( payload_mime ) {
		mailmime_free(payload_mime); //TODO: the text pointer set by mailmime_set_body_text() is not freed this way!
	}
	return success;
}


