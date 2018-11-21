/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
#ifndef RNP_DEF_H_
#define RNP_DEF_H_

#include <stdint.h>

/* The dot directory relative to the user's home directory where keys
 * are stored.
 *
 * TODO: Consider making this an overridable config setting.
 *
 * TODO: For now the dot dot directory is .rnp to prevent competition with
 *       developers' .gnupg installations.
 */

#define SUBDIRECTORY_GNUPG ".gnupg"
#define SUBDIRECTORY_RNP ".rnp"
#define PUBRING_KBX "pubring.kbx"
#define SECRING_KBX "secring.kbx"
#define PUBRING_GPG "pubring.gpg"
#define SECRING_GPG "secring.gpg"
#define PUBRING_G10 "public-keys-v1.d"
#define SECRING_G10 "private-keys-v1.d"

#define MAX_PASSWORD_ATTEMPTS 3
#define INFINITE_ATTEMPTS -1

/*
 * Error code definitions
 */
enum {

    RNP_SUCCESS = 0x00000000,

    /* Common error codes */
    RNP_ERROR_GENERIC = 0x10000000,
    RNP_ERROR_BAD_FORMAT,
    RNP_ERROR_BAD_PARAMETERS,
    RNP_ERROR_NOT_IMPLEMENTED,
    RNP_ERROR_NOT_SUPPORTED,
    RNP_ERROR_OUT_OF_MEMORY,
    RNP_ERROR_SHORT_BUFFER,
    RNP_ERROR_NULL_POINTER,

    /* Storage */
    RNP_ERROR_ACCESS = 0x11000000,
    RNP_ERROR_READ,
    RNP_ERROR_WRITE,

    /* Crypto */
    RNP_ERROR_BAD_STATE = 0x12000000,
    RNP_ERROR_MAC_INVALID,
    RNP_ERROR_SIGNATURE_INVALID,
    RNP_ERROR_KEY_GENERATION,
    RNP_ERROR_BAD_PASSWORD,
    RNP_ERROR_KEY_NOT_FOUND,
    RNP_ERROR_NO_SUITABLE_KEY,
    RNP_ERROR_DECRYPT_FAILED,
    RNP_ERROR_RNG,
    RNP_ERROR_SIGNING_FAILED,
    RNP_ERROR_NO_SIGNATURES_FOUND,

    RNP_ERROR_SIGNATURE_EXPIRED,

    /* Parsing */
    RNP_ERROR_NOT_ENOUGH_DATA = 0x13000000,
    RNP_ERROR_UNKNOWN_TAG,
    RNP_ERROR_PACKET_NOT_CONSUMED,
    RNP_ERROR_NO_USERID,
    RNP_ERROR_EOF

};

/* rnp_result_t is the type used for return codes from the APIs. */
typedef uint32_t rnp_result_t;

enum { MAX_ID_LENGTH = 128, MAX_PASSWORD_LENGTH = 256 };

#endif
