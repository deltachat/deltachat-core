#ifndef __NETPGP_EXTRA_H__
#define __NETPGP_EXTRA_H__

#include <netpgp.h>
#include "packet-parse.h"
#include "errors-netpgp.h"
#include "netpgpdefs.h"
#include "crypto-netpgp.h"
#include "create-netpgp.h"
unsigned rsa_generate_keypair(pgp_key_t *keydata, const int numbits, const unsigned long e, const char *hashalg, const char *cipher);

#endif // __NETPGP_EXTRA_H__
