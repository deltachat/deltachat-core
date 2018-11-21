/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DEFAULTS_H_
#define DEFAULTS_H_

/* SHA1 is not considered secured anymore and SHOULD NOT be used to create messages (as per
 * Appendix C of RFC 4880-bis-02). SHA2 MUST be implemented.
 * Let's pre-empt this by specifying SHA256 - gpg interoperates just fine with SHA256 - agc,
 * 20090522
 */
#define DEFAULT_HASH_ALG "SHA256"

/* Default hash algorithm as PGP constant */
#define DEFAULT_PGP_HASH_ALG PGP_HASH_SHA256

/* Default symmetric algorithm */
#define DEFAULT_SYMM_ALG "AES256"

/* Default symmetric algorithm as PGP constant */
#define DEFAULT_PGP_SYMM_ALG PGP_SA_AES_256

/* Default number of msec to run S2K derivation */
#define DEFAULT_S2K_MSEC 150

/* Default number of msec to run S2K tuning */
#define DEFAULT_S2K_TUNE_MSEC 10

/* Default compression algorithm and level */
#define DEFAULT_Z_ALG PGP_C_ZIP
#define DEFAULT_Z_LEVEL 6

/* Default AEAD algorithm */
#define DEFAULT_AEAD_ALG "EAX"

/* Default AEAD chunk bits, equals to 100MB chunks */
#define DEFAULT_AEAD_CHUNK_BITS 21

/* Default cipher mode for secret key encryption */
#define DEFAULT_CIPHER_MODE "CFB"

/* Default cipher mode for secret key encryption */
#define DEFAULT_PGP_CIPHER_MODE PGP_CIPHER_MODE_CFB

/* Default public key algorithm for new key generation */
#define DEFAULT_PK_ALG PGP_PKA_RSA

/* Default RSA key length */
#define DEFAULT_RSA_NUMBITS 2048

#endif
