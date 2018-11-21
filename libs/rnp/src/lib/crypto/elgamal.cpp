/*-
 * Copyright (c) 2017 Ribose Inc.
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
#include "elgamal.h"
#include "utils.h"

// Max supported key byte size
#define ELGAMAL_MAX_P_BYTELEN BITS_TO_BYTES(DSA_MAX_P_BITLEN)

static bool
elgamal_load_public_key(botan_pubkey_t *pubkey, const pgp_eg_key_t *keydata)
{
    bignum_t *p = NULL;
    bignum_t *g = NULL;
    bignum_t *y = NULL;
    bool      res = false;

    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (mpi_bytes(&keydata->p) > ELGAMAL_MAX_P_BYTELEN) {
        goto done;
    }

    if (!(p = mpi2bn(&keydata->p)) || !(g = mpi2bn(&keydata->g)) ||
        !(y = mpi2bn(&keydata->y))) {
        goto done;
    }

    res =
      !botan_pubkey_load_elgamal(pubkey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(g), BN_HANDLE_PTR(y));
done:
    bn_free(p);
    bn_free(g);
    bn_free(y);
    return res;
}

static bool
elgamal_load_secret_key(botan_privkey_t *seckey, const pgp_eg_key_t *keydata)
{
    bignum_t *p = NULL;
    bignum_t *g = NULL;
    bignum_t *x = NULL;
    bool      res = false;

    // Check if provided secret key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (mpi_bytes(&keydata->p) > ELGAMAL_MAX_P_BYTELEN) {
        goto done;
    }

    if (!(p = mpi2bn(&keydata->p)) || !(g = mpi2bn(&keydata->g)) ||
        !(x = mpi2bn(&keydata->x))) {
        goto done;
    }

    res = !botan_privkey_load_elgamal(
      seckey, BN_HANDLE_PTR(p), BN_HANDLE_PTR(g), BN_HANDLE_PTR(x));
done:
    bn_free(p);
    bn_free(g);
    bn_free(x);
    return res;
}

rnp_result_t
elgamal_validate_key(rng_t *rng, const pgp_eg_key_t *key, bool secret)
{
    botan_pubkey_t  bpkey = NULL;
    botan_privkey_t bskey = NULL;
    rnp_result_t    ret = RNP_ERROR_BAD_PARAMETERS;

    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    if (!elgamal_load_public_key(&bpkey, key) ||
        botan_pubkey_check_key(bpkey, rng_handle(rng), 0)) {
        goto done;
    }

    if (!secret) {
        ret = RNP_SUCCESS;
        goto done;
    }

    if (elgamal_load_secret_key(&bskey, key) ||
        botan_privkey_check_key(bskey, rng_handle(rng), 0)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    botan_privkey_destroy(bskey);
    botan_pubkey_destroy(bpkey);
    return ret;
}

rnp_result_t
elgamal_encrypt_pkcs1(rng_t *             rng,
                      pgp_eg_encrypted_t *out,
                      const uint8_t *     in,
                      size_t              in_len,
                      const pgp_eg_key_t *key)
{
    botan_pubkey_t        b_key = NULL;
    botan_pk_op_encrypt_t op_ctx = NULL;
    rnp_result_t          ret = RNP_ERROR_BAD_PARAMETERS;
    /* Max size of an output len is twice an order of underlying group (p length) */
    uint8_t enc_buf[ELGAMAL_MAX_P_BYTELEN * 2] = {0};
    size_t  p_len;

    if (!elgamal_load_public_key(&b_key, key)) {
        RNP_LOG("Failed to load public key");
        goto end;
    }

    /* Size of output buffer must be equal to twice the size of key byte len.
     * as ElGamal encryption outputs concatenation of two components, both
     * of size equal to size of public key byte len.
     * Successful call to botan's ElGamal encryption will return output that's
     * always 2*pubkey size.
     */
    p_len = mpi_bytes(&key->p) * 2;

    if (botan_pk_op_encrypt_create(&op_ctx, b_key, "PKCS1v15", 0) ||
        botan_pk_op_encrypt(op_ctx, rng_handle(rng), enc_buf, &p_len, in, in_len)) {
        RNP_LOG("Failed to create operation context");
        goto end;
    }

    /*
     * Botan's ElGamal formats the g^k and msg*(y^k) together into a single byte string.
     * We have to parse out the two values after encryption, as rnp stores those values
     * separatelly.
     *
     * We don't trim zeros from octet string as it is done before final marshalling
     * (add_packet_body_mpi)
     *
     * We must assume that botan copies even number of bytes to output buffer (to avoid
     * memory corruption)
     */
    p_len /= 2;
    if (mem2mpi(&out->g, enc_buf, p_len) && mem2mpi(&out->m, enc_buf + p_len, p_len)) {
        ret = RNP_SUCCESS;
    }
end:
    botan_pk_op_encrypt_destroy(op_ctx);
    botan_pubkey_destroy(b_key);
    return ret;
}

rnp_result_t
elgamal_decrypt_pkcs1(rng_t *                   rng,
                      uint8_t *                 out,
                      size_t *                  out_len,
                      const pgp_eg_encrypted_t *in,
                      const pgp_eg_key_t *      key)
{
    botan_privkey_t       b_key = NULL;
    botan_pk_op_decrypt_t op_ctx = NULL;
    rnp_result_t          ret = RNP_ERROR_BAD_PARAMETERS;
    uint8_t               enc_buf[ELGAMAL_MAX_P_BYTELEN * 2] = {0};
    size_t                p_len;
    size_t                g_len;
    size_t                m_len;

    if (!mpi_bytes(&key->x)) {
        RNP_LOG("empty secret key");
        goto end;
    }

    // Check if provided public key byte size is not greater than ELGAMAL_MAX_P_BYTELEN.
    p_len = mpi_bytes(&key->p);
    g_len = mpi_bytes(&in->g);
    m_len = mpi_bytes(&in->m);

    if ((2 * p_len > sizeof(enc_buf)) || (g_len > p_len) || (m_len > p_len)) {
        RNP_LOG("Unsupported/wrong public key or encrypted data");
        goto end;
    }

    if (!elgamal_load_secret_key(&b_key, key)) {
        RNP_LOG("Failed to load private key");
        goto end;
    }

    /* Botan expects ciphertext to be concatenated (g^k | encrypted m). Size must
     * be equal to twice the byte size of public key, potentially prepended with zeros.
     */
    memcpy(&enc_buf[p_len - g_len], in->g.mpi, g_len);
    memcpy(&enc_buf[2 * p_len - m_len], in->m.mpi, m_len);

    *out_len = p_len;
    if (botan_pk_op_decrypt_create(&op_ctx, b_key, "PKCS1v15", 0) ||
        botan_pk_op_decrypt(op_ctx, out, out_len, enc_buf, 2 * p_len)) {
        RNP_LOG("Decryption failed");
        goto end;
    }
    ret = RNP_SUCCESS;
end:
    botan_pk_op_decrypt_destroy(op_ctx);
    botan_privkey_destroy(b_key);
    return ret;
}

rnp_result_t
elgamal_generate(rng_t *rng, pgp_eg_key_t *key, size_t keybits)
{
    botan_privkey_t key_priv = NULL;
    botan_pubkey_t  key_pub = NULL;
    rnp_result_t    ret = RNP_ERROR_GENERIC;

    bignum_t *p = bn_new();
    bignum_t *g = bn_new();
    bignum_t *y = bn_new();
    bignum_t *x = bn_new();

    if (!p || !g || !y || !x) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    if (botan_privkey_create_elgamal(&key_priv, rng_handle(rng), keybits, keybits - 1) ||
        botan_privkey_export_pubkey(&key_pub, key_priv)) {
        RNP_LOG("Wrong parameters");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto end;
    }

    if (botan_pubkey_get_field(BN_HANDLE_PTR(p), key_pub, "p") ||
        botan_pubkey_get_field(BN_HANDLE_PTR(g), key_pub, "g") ||
        botan_pubkey_get_field(BN_HANDLE_PTR(y), key_pub, "y") ||
        botan_privkey_get_field(BN_HANDLE_PTR(x), key_priv, "x")) {
        RNP_LOG("Botan FFI call failed");
        ret = RNP_ERROR_GENERIC;
        goto end;
    }

    if (bn2mpi(p, &key->p) && bn2mpi(g, &key->g) && bn2mpi(y, &key->y) && bn2mpi(x, &key->x)) {
        ret = RNP_SUCCESS;
    }
end:
    bn_free(p);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    botan_privkey_destroy(key_priv);
    botan_pubkey_destroy(key_pub);
    return ret;
}
