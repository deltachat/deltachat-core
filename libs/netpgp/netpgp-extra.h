#ifndef __NETPGP_EXTRA_H__
#define __NETPGP_EXTRA_H__

#include <netpgp.h>
#include "packet-parse.h"
#include "errors.h"
#include "netpgpdefs.h"
#include "crypto.h"
#include "create.h"
unsigned rsa_generate_keypair(pgp_key_t *keydata, const int numbits, const unsigned long e, const char *hashalg, const char *cipher);
unsigned write_seckey_body(const pgp_seckey_t *key, const uint8_t *passphrase, const size_t pplen, pgp_output_t *output);

#endif // __NETPGP_EXTRA_H__
