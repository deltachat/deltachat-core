/*-
 * Copyright (c) 2017-2018 Ribose Inc.
 * All rights reserved.
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

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include <stdlib.h>
#include <string.h>
#include <botan/ffi.h>
#include <rnp/rnp_def.h>
#include "dsa.h"
#include "hash.h"
#include "utils.h"

#define DSA_MAX_Q_BITLEN 256

rnp_result_t
dsa_validate_key(rng_t *rng, const pgp_dsa_key_t *key, bool secret)
{
    bignum_t *      p = NULL;
    bignum_t *      q = NULL;
    bignum_t *      g = NULL;
    bignum_t *      y = NULL;
    bignum_t *      x = NULL;
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;

    /* load and check public key part */
    p = mpi2bn(&key->p);
    q = mpi2bn(&key->q);
    g = mpi2bn(&key->g);
    y = mpi2bn(&key->y);

    if (!p || !q || !g || !y) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    if (botan_pubkey_load_dsa(
          &bpkey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(q), BN_HANDLE_PTR(g), BN_HANDLE_PTR(y))) {
        goto done;
    }

    if (botan_pubkey_check_key(bpkey, rng_handle(rng), 0)) {
        goto done;
    }

    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    /* load and check secret key part */
    if (!(x = mpi2bn(&key->x))) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    if (botan_privkey_load_dsa(
          &bskey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(q), BN_HANDLE_PTR(g), BN_HANDLE_PTR(x))) {
        goto done;
    }

    if (botan_privkey_check_key(bskey, rng_handle(rng), 0)) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}

rnp_result_t
dsa_sign(rng_t *              rng,
         pgp_dsa_signature_t *sig,
         const uint8_t *      hash,
         size_t               hash_len,
         const pgp_dsa_key_t *key)
{
    botan_privkey_t    dsa_key = NULL;
    botan_pk_op_sign_t sign_op = NULL;
    size_t             q_order = 0;
    uint8_t            sign_buf[2 * BITS_TO_BYTES(DSA_MAX_Q_BITLEN)] = {0};
    bignum_t *         p = NULL, *q = NULL, *g = NULL, *x = NULL;
    rnp_result_t       ret = RNP_ERROR_SIGNING_FAILED;
    size_t             sigbuf_size = sizeof(sign_buf);

    size_t z_len = 0;

    memset(sig, 0, sizeof(*sig));
    q_order = mpi_bytes(&key->q);
    if ((2 * q_order) > sizeof(sign_buf)) {
        RNP_LOG("wrong q order");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // As 'Raw' is used we need to reduce hash size (as per FIPS-186-4, 4.6)
    z_len = hash_len < q_order ? hash_len : q_order;

    p = mpi2bn(&key->p);
    q = mpi2bn(&key->q);
    g = mpi2bn(&key->g);
    x = mpi2bn(&key->x);

    if (!p || !q || !g || !x) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_privkey_load_dsa(
          &dsa_key, BN_HANDLE_PTR(p), BN_HANDLE_PTR(q), BN_HANDLE_PTR(g), BN_HANDLE_PTR(x))) {
        RNP_LOG("Can't load key");
        goto end;
    }

    if (botan_pk_op_sign_create(&sign_op, dsa_key, "Raw", 0)) {
        goto end;
    }

    if (botan_pk_op_sign_update(sign_op, hash, z_len)) {
        goto end;
    }

    if (botan_pk_op_sign_finish(sign_op, rng_handle(rng), sign_buf, &sigbuf_size)) {
        RNP_LOG("Signing has failed");
        goto end;
    }

    // Now load the DSA (r,s) values from the signature.
    if (!mem2mpi(&sig->r, sign_buf, q_order) ||
        !mem2mpi(&sig->s, sign_buf + q_order, q_order)) {
        goto end;
    }
    ret = RNP_SUCCESS;

end:
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(x);
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(dsa_key);
    return ret;
}

rnp_result_t
dsa_verify(const pgp_dsa_signature_t *sig,
           const uint8_t *            hash,
           size_t                     hash_len,
           const pgp_dsa_key_t *      key)
{
    botan_pubkey_t       dsa_key = NULL;
    botan_pk_op_verify_t verify_op = NULL;
    uint8_t              sign_buf[2 * BITS_TO_BYTES(DSA_MAX_Q_BITLEN)] = {0};
    size_t               q_order = 0;
    size_t               r_blen, s_blen;
    bignum_t *           p = NULL, *q = NULL, *g = NULL, *y = NULL;
    rnp_result_t         ret = RNP_ERROR_GENERIC;
    size_t               z_len = 0;

    q_order = mpi_bytes(&key->q);
    if ((2 * q_order) > sizeof(sign_buf)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    z_len = hash_len < q_order ? hash_len : q_order;

    r_blen = mpi_bytes(&sig->r);
    s_blen = mpi_bytes(&sig->s);
    if ((r_blen > q_order) || (s_blen > q_order)) {
        RNP_LOG("Wrong signature");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    p = mpi2bn(&key->p);
    q = mpi2bn(&key->q);
    g = mpi2bn(&key->g);
    y = mpi2bn(&key->y);

    if (!p || !q || !g || !y) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_pubkey_load_dsa(
          &dsa_key, BN_HANDLE_PTR(p), BN_HANDLE_PTR(q), BN_HANDLE_PTR(g), BN_HANDLE_PTR(y))) {
        RNP_LOG("Wrong key");
        goto end;
    }

    mpi2mem(&sig->r, sign_buf + q_order - r_blen);
    mpi2mem(&sig->s, sign_buf + 2 * q_order - s_blen);

    if (botan_pk_op_verify_create(&verify_op, dsa_key, "Raw", 0)) {
        RNP_LOG("Can't create verifier");
        goto end;
    }

    if (botan_pk_op_verify_update(verify_op, hash, z_len)) {
        goto end;
    }

    ret = (botan_pk_op_verify_finish(verify_op, sign_buf, 2 * q_order) == BOTAN_FFI_SUCCESS) ?
            RNP_SUCCESS :
            RNP_ERROR_SIGNATURE_INVALID;

end:
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(y);
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(dsa_key);
    return ret;
}

rnp_result_t
dsa_generate(rng_t *rng, pgp_dsa_key_t *key, size_t keylen, size_t qbits)
{
    botan_privkey_t key_priv = NULL;
    botan_pubkey_t  key_pub = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;

    bignum_t *p = bn_new();
    bignum_t *q = bn_new();
    bignum_t *g = bn_new();
    bignum_t *y = bn_new();
    bignum_t *x = bn_new();

    if (!p || !q || !g || !y || !x) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_privkey_create_dsa(&key_priv, rng_handle(rng), keylen, qbits) ||
        botan_privkey_check_key(key_priv, rng_handle(rng), 1) ||
        botan_privkey_export_pubkey(&key_pub, key_priv)) {
        RNP_LOG("Wrong parameters");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    if (botan_pubkey_get_field(BN_HANDLE_PTR(p), key_pub, "p") ||
        botan_pubkey_get_field(BN_HANDLE_PTR(q), key_pub, "q") ||
        botan_pubkey_get_field(BN_HANDLE_PTR(g), key_pub, "g") ||
        botan_pubkey_get_field(BN_HANDLE_PTR(y), key_pub, "y") ||
        botan_privkey_get_field(BN_HANDLE_PTR(x), key_priv, "x")) {
        RNP_LOG("Botan FFI call failed");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    if (!bn2mpi(p, &key->p) || !bn2mpi(q, &key->q) || !bn2mpi(g, &key->g) ||
        !bn2mpi(y, &key->y) || !bn2mpi(x, &key->x)) {
        RNP_LOG("failed to copy mpi");
        goto end;
    }
    ret = RNP_SUCCESS;
end:
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    botan_privkey_destroy(key_priv);
    botan_pubkey_destroy(key_pub);
    return ret;
}

pgp_hash_alg_t
dsa_get_min_hash(size_t qsize)
{
    /*
     * I'm using _broken_ SHA1 here only because
     * some old implementations may not understand keys created
     * with other hashes. If you're sure we don't have to support
     * such implementations, please be my guest and remove it.
     */
    return (qsize < 160) ? PGP_HASH_UNKNOWN :
                           (qsize == 160) ?
                           PGP_HASH_SHA1 :
                           (qsize <= 224) ?
                           PGP_HASH_SHA224 :
                           (qsize <= 256) ? PGP_HASH_SHA256 :
                                            (qsize <= 384) ? PGP_HASH_SHA384 :
                                                             (qsize <= 512) ? PGP_HASH_SHA512
                                                                              /*(qsize>512)*/ :
                                                                              PGP_HASH_UNKNOWN;
}

size_t
dsa_choose_qsize_by_psize(size_t psize)
{
    return (psize == 1024) ? 160 :
                             (psize <= 2047) ? 224 : (psize <= 3072) ? DSA_MAX_Q_BITLEN : 0;
}
