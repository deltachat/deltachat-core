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
#include <string.h>
#include <stdbool.h>
#include <botan/ffi.h>
#include "crypto/rsa.h"
#include "hash.h"
#include "config.h"
#include "utils.h"

rnp_result_t
rsa_validate_key(rng_t *rng, const pgp_rsa_key_t *key, bool secret)
{
    bignum_t *      n = NULL;
    bignum_t *      e = NULL;
    bignum_t *      p = NULL;
    bignum_t *      q = NULL;
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;

    /* load and check public key part */
    if (!(n = mpi2bn(&key->n)) || !(e = mpi2bn(&key->e))) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    if (botan_pubkey_load_rsa(&bpkey, BN_HANDLE_PTR(n), BN_HANDLE_PTR(e)) != 0) {
        goto done;
    }

    if (botan_pubkey_check_key(bpkey, rng_handle(rng), 1)) {
        goto done;
    }

    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    /* load and check secret key part */
    if (!(p = mpi2bn(&key->p)) || !(q = mpi2bn(&key->q))) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    /* p and q are reversed from normal usage in PGP */
    if (botan_privkey_load_rsa(&bskey, BN_HANDLE_PTR(q), BN_HANDLE_PTR(p), BN_HANDLE_PTR(e))) {
        goto done;
    }

    if (botan_privkey_check_key(bskey, rng_handle(rng), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_pubkey_destroy(bpkey);
    botan_privkey_destroy(bskey);
    bn_free(n);
    bn_free(e);
    bn_free(p);
    bn_free(q);
    return ret;
}

static bool
rsa_load_public_key(botan_pubkey_t *bkey, const pgp_rsa_key_t *key)
{
    bignum_t *n = NULL;
    bignum_t *e = NULL;
    bool      res = false;

    *bkey = NULL;
    n = mpi2bn(&key->n);
    e = mpi2bn(&key->e);

    if (!n || !e) {
        RNP_LOG("out of memory");
        goto done;
    }

    res = !botan_pubkey_load_rsa(bkey, BN_HANDLE_PTR(n), BN_HANDLE_PTR(e));
done:
    bn_free(n);
    bn_free(e);
    return res;
}

static bool
rsa_load_secret_key(botan_privkey_t *bkey, const pgp_rsa_key_t *key)
{
    bignum_t *p = NULL;
    bignum_t *q = NULL;
    bignum_t *e = NULL;
    bool      res = false;

    *bkey = NULL;
    p = mpi2bn(&key->p);
    q = mpi2bn(&key->q);
    e = mpi2bn(&key->e);

    if (!p || !q || !e) {
        RNP_LOG("out of memory");
        goto done;
    }

    /* p and q are reversed from normal usage in PGP */
    res = !botan_privkey_load_rsa(bkey, BN_HANDLE_PTR(q), BN_HANDLE_PTR(p), BN_HANDLE_PTR(e));
done:
    bn_free(p);
    bn_free(q);
    bn_free(e);
    return res;
}

rnp_result_t
rsa_encrypt_pkcs1(rng_t *              rng,
                  pgp_rsa_encrypted_t *out,
                  const uint8_t *      in,
                  size_t               in_len,
                  const pgp_rsa_key_t *key)
{
    rnp_result_t          ret = RNP_ERROR_GENERIC;
    botan_pubkey_t        rsa_key = NULL;
    botan_pk_op_encrypt_t enc_op = NULL;

    if (!rsa_load_public_key(&rsa_key, key)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (botan_pk_op_encrypt_create(&enc_op, rsa_key, "PKCS1v15", 0) != 0) {
        goto done;
    }

    out->m.len = sizeof(out->m.mpi);
    if (botan_pk_op_encrypt(enc_op, rng_handle(rng), out->m.mpi, &out->m.len, in, in_len)) {
        out->m.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_pk_op_encrypt_destroy(enc_op);
    botan_pubkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
rsa_verify_pkcs1(const pgp_rsa_signature_t *sig,
                 pgp_hash_alg_t             hash_alg,
                 const uint8_t *            hash,
                 size_t                     hash_len,
                 const pgp_rsa_key_t *      key)
{
    char                 padding_name[64] = {0};
    botan_pubkey_t       rsa_key = NULL;
    botan_pk_op_verify_t verify_op = NULL;
    rnp_result_t         ret = RNP_ERROR_SIGNATURE_INVALID;

    if (!rsa_load_public_key(&rsa_key, key)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             pgp_hash_name_botan(hash_alg));

    if (botan_pk_op_verify_create(&verify_op, rsa_key, padding_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_update(verify_op, hash, hash_len) != 0) {
        goto done;
    }

    if (botan_pk_op_verify_finish(verify_op, sig->s.mpi, sig->s.len) != 0) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    botan_pk_op_verify_destroy(verify_op);
    botan_pubkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
rsa_sign_pkcs1(rng_t *              rng,
               pgp_rsa_signature_t *sig,
               pgp_hash_alg_t       hash_alg,
               const uint8_t *      hash,
               size_t               hash_len,
               const pgp_rsa_key_t *key)
{
    char               padding_name[64] = {0};
    botan_privkey_t    rsa_key;
    botan_pk_op_sign_t sign_op;
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }

    if (!rsa_load_secret_key(&rsa_key, key)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    snprintf(padding_name,
             sizeof(padding_name),
             "EMSA-PKCS1-v1_5(Raw,%s)",
             pgp_hash_name_botan(hash_alg));

    if (botan_pk_op_sign_create(&sign_op, rsa_key, padding_name, 0) != 0) {
        goto done;
    }

    if (botan_pk_op_sign_update(sign_op, hash, hash_len)) {
        goto done;
    }

    sig->s.len = sizeof(sig->s.mpi);
    if (botan_pk_op_sign_finish(sign_op, rng_handle(rng), sig->s.mpi, &sig->s.len)) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    botan_pk_op_sign_destroy(sign_op);
    botan_privkey_destroy(rsa_key);
    return ret;
}

rnp_result_t
rsa_decrypt_pkcs1(rng_t *                    rng,
                  uint8_t *                  out,
                  size_t *                   out_len,
                  const pgp_rsa_encrypted_t *in,
                  const pgp_rsa_key_t *      key)
{
    botan_privkey_t       rsa_key = NULL;
    botan_pk_op_decrypt_t decrypt_op = NULL;
    rnp_result_t          ret = RNP_ERROR_GENERIC;

    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }

    if (!rsa_load_secret_key(&rsa_key, key)) {
        RNP_LOG("failed to load key");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (botan_pk_op_decrypt_create(&decrypt_op, rsa_key, "PKCS1v15", 0)) {
        goto done;
    }

    *out_len = PGP_MPINT_SIZE;
    if (botan_pk_op_decrypt(decrypt_op, out, out_len, in->m.mpi, in->m.len)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(rsa_key);
    botan_pk_op_decrypt_destroy(decrypt_op);
    return ret;
}

rnp_result_t
rsa_generate(rng_t *rng, pgp_rsa_key_t *key, size_t numbits)
{
    botan_privkey_t rsa_key = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;
    int             cmp;
    bignum_t *      n = bn_new();
    bignum_t *      e = bn_new();
    bignum_t *      p = bn_new();
    bignum_t *      q = bn_new();
    bignum_t *      d = bn_new();
    bignum_t *      u = bn_new();

    if (!n || !e || !p || !q || !d || !u) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_privkey_create_rsa(&rsa_key, rng_handle(rng), numbits) != 0) {
        goto end;
    }

    if (botan_privkey_check_key(rsa_key, rng_handle(rng), 1) != 0) {
        goto end;
    }

    /* Calls below never fail as calls above were OK */
    (void) botan_privkey_rsa_get_n(BN_HANDLE_PTR(n), rsa_key);
    (void) botan_privkey_rsa_get_e(BN_HANDLE_PTR(e), rsa_key);
    (void) botan_privkey_rsa_get_d(BN_HANDLE_PTR(d), rsa_key);
    (void) botan_privkey_rsa_get_p(BN_HANDLE_PTR(p), rsa_key);
    (void) botan_privkey_rsa_get_q(BN_HANDLE_PTR(q), rsa_key);

    /* RFC 4880, 5.5.3 tells that p < q. GnuPG relies on this. */
    (void) botan_mp_cmp(&cmp, BN_HANDLE_PTR(p), BN_HANDLE_PTR(q));
    if (cmp > 0) {
        (void) botan_mp_swap(BN_HANDLE_PTR(p), BN_HANDLE_PTR(q));
    }

    if (botan_mp_mod_inverse(BN_HANDLE_PTR(u), BN_HANDLE_PTR(p), BN_HANDLE_PTR(q)) != 0) {
        RNP_LOG("Error computing RSA u param");
        ret = RNP_ERROR_BAD_STATE;
        goto end;
    }

    bn2mpi(n, &key->n);
    bn2mpi(e, &key->e);
    bn2mpi(p, &key->p);
    bn2mpi(q, &key->q);
    bn2mpi(d, &key->d);
    bn2mpi(u, &key->u);

    ret = RNP_SUCCESS;
end:
    botan_privkey_destroy(rsa_key);
    bn_free(n);
    bn_free(e);
    bn_free(p);
    bn_free(q);
    bn_free(d);
    bn_free(u);
    return ret;
}
