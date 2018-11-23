/*
 * Copyright (c) 2017-2018, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include "fingerprint.h"
#include "crypto/hash.h"
#include "packet-create.h"
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include "utils.h"

rnp_result_t
pgp_fingerprint(pgp_fingerprint_t *fp, const pgp_key_pkt_t *key)
{
    pgp_hash_t hash = {0};

    if ((key->version == PGP_V2) || (key->version == PGP_V3)) {
        if (!is_rsa_key_alg(key->alg)) {
            RNP_LOG("bad algorithm");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        if (!pgp_hash_create(&hash, PGP_HASH_MD5)) {
            RNP_LOG("bad md5 alloc");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        (void) mpi_hash(&key->material.rsa.n, &hash);
        (void) mpi_hash(&key->material.rsa.e, &hash);
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        RNP_DHEX("v2/v3 fingerprint", fp->fingerprint, fp->length);
        return RNP_SUCCESS;
    }

    if (key->version == PGP_V4) {
        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            RNP_LOG("bad sha1 alloc");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        if (!signature_hash_key(key, &hash)) {
            return RNP_ERROR_GENERIC;
        }
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        RNP_DHEX("sha1 fingerprint", fp->fingerprint, fp->length);
        return RNP_SUCCESS;
    }

    RNP_LOG("unsupported key version");
    return RNP_ERROR_NOT_SUPPORTED;
}

/**
 * \ingroup Core_Keys
 * \brief Calculate the Key ID from the public key.
 * \param keyid Space for the calculated ID to be stored
 * \param key The key for which the ID is calculated
 */

rnp_result_t
pgp_keyid(uint8_t *keyid, const size_t idlen, const pgp_key_pkt_t *key)
{
    pgp_fingerprint_t fp;
    rnp_result_t      ret;
    size_t            n;

    if ((key->version == PGP_V2) || (key->version == PGP_V3)) {
        if (!is_rsa_key_alg(key->alg)) {
            RNP_LOG("bad algorithm");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        n = mpi_bytes(&key->material.rsa.n);
        (void) memcpy(keyid, key->material.rsa.n.mpi + n - idlen, idlen);
        return RNP_SUCCESS;
    }

    if ((ret = pgp_fingerprint(&fp, key))) {
        return ret;
    }
    (void) memcpy(keyid, fp.fingerprint + fp.length - idlen, idlen);
    return RNP_SUCCESS;
}

bool
fingerprint_equal(pgp_fingerprint_t *fp1, pgp_fingerprint_t *fp2)
{
    return (fp1->length == fp2->length) &&
           (!memcmp(fp1->fingerprint, fp2->fingerprint, fp1->length));
}
