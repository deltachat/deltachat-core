/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "crypto.h"
#include "config.h"
#include "defaults.h"
#include <rnp/rnp_sdk.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <botan/ffi.h>
#include "utils.h"

static const char *
pgp_sa_to_botan_string(pgp_symm_alg_t alg)
{
    switch (alg) {
#if defined(BOTAN_HAS_IDEA)
    case PGP_SA_IDEA:
        return "IDEA";
#endif

#if defined(BOTAN_HAS_DES)
    case PGP_SA_TRIPLEDES:
        return "TripleDES";
#endif

#if defined(BOTAN_HAS_CAST)
    case PGP_SA_CAST5:
        return "CAST-128";
#endif

#if defined(BOTAN_HAS_BLOWFISH)
    case PGP_SA_BLOWFISH:
        return "Blowfish";
#endif

#if defined(BOTAN_HAS_AES)
    case PGP_SA_AES_128:
        return "AES-128";
    case PGP_SA_AES_192:
        return "AES-192";
    case PGP_SA_AES_256:
        return "AES-256";
#endif

#if defined(BOTAN_HAS_SM4)
    case PGP_SA_SM4:
        return "SM4";
#endif

#if defined(BOTAN_HAS_TWOFISH)
    case PGP_SA_TWOFISH:
        return "Twofish";
#endif

#if defined(BOTAN_HAS_CAMELLIA)
    case PGP_SA_CAMELLIA_128:
        return "Camellia-128";
    case PGP_SA_CAMELLIA_192:
        return "Camellia-192";
    case PGP_SA_CAMELLIA_256:
        return "Camellia-256";
#endif

    case PGP_SA_PLAINTEXT:
        return NULL; // ???
    default:
        RNP_LOG("Unsupported PGP symmetric alg %d", (int) alg);
        return NULL;
    }
}

static bool
pgp_aead_to_botan_string(pgp_symm_alg_t ealg, pgp_aead_alg_t aalg, char *buf, size_t len)
{
    const char *ealg_name = pgp_sa_to_botan_string(ealg);
    size_t      ealg_len;

    if (!ealg_name) {
        return false;
    }

    ealg_len = strlen(ealg_name);

    if (len < ealg_len + 5) {
        RNP_LOG("buffer too small");
        return false;
    }

    switch (aalg) {
    case PGP_AEAD_EAX:
        strncpy(buf, ealg_name, ealg_len);
        strncpy(buf + ealg_len, "/EAX", len - ealg_len);
        break;
    case PGP_AEAD_OCB:
        strncpy(buf, ealg_name, ealg_len);
        strncpy(buf + ealg_len, "/OCB", len - ealg_len);
        break;
    default:
        RNP_LOG("unsupported AEAD alg %d", (int) aalg);
        return false;
    }

    return true;
}

bool
pgp_cipher_cfb_start(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t alg,
                     const uint8_t *key,
                     const uint8_t *iv)
{
    memset(crypt, 0x0, sizeof(*crypt));

    const char *cipher_name = pgp_sa_to_botan_string(alg);
    if (cipher_name == NULL) {
        RNP_LOG("Unsupported algorithm: %d", alg);
        return false;
    }

    crypt->alg = alg;
    crypt->blocksize = pgp_block_size(alg);

    // This shouldn't happen if pgp_sa_to_botan_string returned a ptr
    if (botan_block_cipher_init(&(crypt->cfb.obj), cipher_name) != 0) {
        RNP_LOG("Block cipher '%s' not available", cipher_name);
        return false;
    }

    const size_t keysize = pgp_key_size(alg);

    if (botan_block_cipher_set_key(crypt->cfb.obj, key, keysize) != 0) {
        RNP_LOG("Failure setting key on block cipher object");
        return false;
    }

    if (iv != NULL) {
        // Otherwise left as all zeros via memset at start of function
        memcpy(crypt->cfb.iv, iv, crypt->blocksize);
    }

    crypt->cfb.remaining = 0;

    return true;
}

void
pgp_cipher_cfb_resync(pgp_crypt_t *crypt, const uint8_t *buf)
{
    /* iv will be encrypted in the upcoming call to encrypt/decrypt */
    memcpy(crypt->cfb.iv, buf, crypt->blocksize);
    crypt->cfb.remaining = 0;
}

int
pgp_cipher_cfb_finish(pgp_crypt_t *crypt)
{
    if (!crypt) {
        return 0;
    }
    if (crypt->cfb.obj) {
        botan_block_cipher_destroy(crypt->cfb.obj);
        crypt->cfb.obj = NULL;
    }
    botan_scrub_mem((uint8_t *) crypt, sizeof(crypt));
    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    uint64_t *in64;
    uint64_t  buf64[512]; // 4KB - page size
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* encrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* encrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);
        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(buf64)) {
                blocks = sizeof(buf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(buf64, in, blockb);
            in64 = buf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->cfb.obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                    *in64 ^= iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->cfb.obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, buf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    botan_block_cipher_encrypt_blocks(crypt->cfb.obj, crypt->cfb.iv, crypt->cfb.iv, 1);
    crypt->cfb.remaining = blsize;

    /* encrypting tail */
    while (bytes) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
        bytes--;
    }

    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    /* for better code readability */
    uint64_t *out64, *in64;
    uint64_t  inbuf64[512]; // 4KB - page size
    uint64_t  outbuf64[512];
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* decrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* decrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);

        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(inbuf64)) {
                blocks = sizeof(inbuf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(inbuf64, in, blockb);
            out64 = outbuf64;
            in64 = inbuf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->cfb.obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                    *out64++ = *in64 ^ iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    botan_block_cipher_encrypt_blocks(
                      crypt->cfb.obj, (uint8_t *) iv64, (uint8_t *) iv64, 1);
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, outbuf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    botan_block_cipher_encrypt_blocks(crypt->cfb.obj, crypt->cfb.iv, crypt->cfb.iv, 1);
    crypt->cfb.remaining = blsize;

    /* decrypting tail */
    while (bytes) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    return 0;
}

pgp_symm_alg_t
pgp_cipher_alg_id(pgp_crypt_t *crypt)
{
    return crypt->alg;
}

size_t
pgp_cipher_block_size(pgp_crypt_t *crypt)
{
    return crypt->blocksize;
}

/* structure to map string to cipher def */
typedef struct str2cipher_t {
    const char *   s; /* cipher name */
    pgp_symm_alg_t i; /* cipher def */
} str2cipher_t;

static str2cipher_t str2cipher[] = {{"cast5", PGP_SA_CAST5},
                                    {"idea", PGP_SA_IDEA},
                                    {"blowfish", PGP_SA_BLOWFISH},
                                    {"twofish", PGP_SA_TWOFISH},
                                    {"sm4", PGP_SA_SM4},
                                    {"aes128", PGP_SA_AES_128},
                                    {"aes192", PGP_SA_AES_192},
                                    {"aes256", PGP_SA_AES_256},
                                    {"camellia128", PGP_SA_CAMELLIA_128},
                                    {"camellia192", PGP_SA_CAMELLIA_192},
                                    {"camellia256", PGP_SA_CAMELLIA_256},
                                    {"tripledes", PGP_SA_TRIPLEDES},
                                    {NULL, (pgp_symm_alg_t) 0}};

/* convert from a string to a cipher definition */
pgp_symm_alg_t
pgp_str_to_cipher(const char *cipher)
{
    str2cipher_t *sp;

    for (sp = str2cipher; cipher && sp->s; sp++) {
        if (rnp_strcasecmp(cipher, sp->s) == 0) {
            return sp->i;
        }
    }
    return DEFAULT_PGP_SYMM_ALG;
}

unsigned
pgp_block_size(pgp_symm_alg_t alg)
{
    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_TRIPLEDES:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
        return 8;

    case PGP_SA_AES_128:
    case PGP_SA_AES_192:
    case PGP_SA_AES_256:
    case PGP_SA_TWOFISH:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_CAMELLIA_192:
    case PGP_SA_CAMELLIA_256:
    case PGP_SA_SM4:
        return 16;

    default:
        RNP_DLOG("Unknown PGP symmetric alg %d", (int) alg);
        return 0;
    }
}

unsigned
pgp_key_size(pgp_symm_alg_t alg)
{
    /* Update MAX_SYMM_KEY_SIZE after adding algorithm
     * with bigger key size.
     */
    static_assert(32 == MAX_SYMM_KEY_SIZE, "MAX_SYMM_KEY_SIZE must be updated");

    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
    case PGP_SA_AES_128:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_SM4:
        return 16;

    case PGP_SA_TRIPLEDES:
    case PGP_SA_AES_192:
    case PGP_SA_CAMELLIA_192:
        return 24;

    case PGP_SA_TWOFISH:
    case PGP_SA_AES_256:
    case PGP_SA_CAMELLIA_256:
        return 32;

    default:
        return 0;
    }
}

/**
\ingroup HighLevel_Supported
\brief Is this Symmetric Algorithm supported?
\param alg Symmetric Algorithm to check
\return 1 if supported; else 0
*/
bool
pgp_is_sa_supported(pgp_symm_alg_t alg)
{
    const char *cipher_name = pgp_sa_to_botan_string(alg);
    if (cipher_name != NULL)
        return true;

    RNP_LOG("Warning: cipher %d not supported", (int) alg);
    return false;
}

bool
pgp_cipher_aead_init(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t ealg,
                     pgp_aead_alg_t aalg,
                     const uint8_t *key,
                     bool           decrypt)
{
    char     cipher_name[32];
    uint32_t flags;

    memset(crypt, 0x0, sizeof(*crypt));

    if (!pgp_aead_to_botan_string(ealg, aalg, cipher_name, sizeof(cipher_name))) {
        return false;
    }

    crypt->alg = ealg;
    crypt->blocksize = pgp_block_size(ealg);
    crypt->aead.alg = aalg;
    crypt->aead.decrypt = decrypt;
    crypt->aead.taglen = PGP_AEAD_EAX_OCB_TAG_LEN; /* it's the same for EAX and OCB */

    flags = decrypt ? BOTAN_CIPHER_INIT_FLAG_DECRYPT : BOTAN_CIPHER_INIT_FLAG_ENCRYPT;

    if (botan_cipher_init(&(crypt->aead.obj), cipher_name, flags)) {
        RNP_LOG("cipher %s is not available", cipher_name);
        return false;
    }

    if (botan_cipher_set_key(crypt->aead.obj, key, (size_t) pgp_key_size(ealg))) {
        RNP_LOG("failed to set key");
        return false;
    }

    if (botan_cipher_get_update_granularity(crypt->aead.obj, &crypt->aead.granularity)) {
        RNP_LOG("failed to get update granularity");
        return false;
    }

    return true;
}

size_t
pgp_cipher_aead_granularity(pgp_crypt_t *crypt)
{
    return crypt->aead.granularity;
}

size_t
pgp_cipher_aead_nonce_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}

size_t
pgp_cipher_aead_tag_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
    case PGP_AEAD_OCB:
        return PGP_AEAD_EAX_OCB_TAG_LEN;
    default:
        return 0;
    }
}

bool
pgp_cipher_aead_set_ad(pgp_crypt_t *crypt, const uint8_t *ad, size_t len)
{
    return botan_cipher_set_associated_data(crypt->aead.obj, ad, len) == 0;
}

bool
pgp_cipher_aead_start(pgp_crypt_t *crypt, const uint8_t *nonce, size_t len)
{
    return botan_cipher_start(crypt->aead.obj, nonce, len) == 0;
}

bool
pgp_cipher_aead_update(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    size_t outwr = 0;
    size_t inread = 0;

    if (len % crypt->aead.granularity) {
        RNP_LOG("aead wrong update len");
        return false;
    }

    if (botan_cipher_update(crypt->aead.obj, 0, out, len, &outwr, in, len, &inread) != 0) {
        RNP_LOG("aead update failed");
        return false;
    }

    if ((outwr != len) || (inread != len)) {
        RNP_LOG("wrong aead usage");
        return false;
    }

    return true;
}

void
pgp_cipher_aead_reset(pgp_crypt_t *crypt)
{
    botan_cipher_reset(crypt->aead.obj);
}

bool
pgp_cipher_aead_finish(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    uint32_t flags = BOTAN_CIPHER_UPDATE_FLAG_FINAL;
    size_t   inread = 0;
    size_t   outwr = 0;
    int      res;

    if (crypt->aead.decrypt) {
        size_t datalen = len - crypt->aead.taglen;
        /* for decryption we should have tag for the final update call */
        res =
          botan_cipher_update(crypt->aead.obj, flags, out, datalen, &outwr, in, len, &inread);
        if (res != 0) {
            if (res != BOTAN_FFI_ERROR_BAD_MAC) {
                RNP_LOG("aead finish failed: %d", res);
            }
            return false;
        }

        if ((outwr != datalen) || (inread != len)) {
            RNP_LOG("wrong decrypt aead finish usage");
            return false;
        }
    } else {
        /* for encryption tag will be generated */
        size_t outlen = len + crypt->aead.taglen;
        if (botan_cipher_update(
              crypt->aead.obj, flags, out, outlen, &outwr, in, len, &inread) != 0) {
            RNP_LOG("aead finish failed");
            return false;
        }

        if ((outwr != outlen) || (inread != len)) {
            RNP_LOG("wrong encrypt aead finish usage");
            return false;
        }
    }

    pgp_cipher_aead_reset(crypt);
    return true;
}

void
pgp_cipher_aead_destroy(pgp_crypt_t *crypt)
{
    botan_cipher_destroy(crypt->aead.obj);
}

size_t
pgp_cipher_aead_nonce(pgp_aead_alg_t aalg, const uint8_t *iv, uint8_t *nonce, size_t index)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        /* The nonce for EAX mode is computed by treating the starting
        initialization vector as a 16-octet, big-endian value and
        exclusive-oring the low eight octets of it with the chunk index.
        */
        memcpy(nonce, iv, PGP_AEAD_EAX_NONCE_LEN);
        for (int i = 15; (i > 7) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        /* The nonce for a chunk of chunk index "i" in OCB processing is defined as:
           OCB-Nonce_{i} = IV[1..120] xor i
        */
        memcpy(nonce, iv, PGP_AEAD_OCB_NONCE_LEN);
        for (int i = 14; (i >= 0) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}
