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

/** \file
 *
 * Creates printable text strings from packet contents
 *
 */
#include "config.h"

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: packet-show.c,v 1.21 2011/08/14 11:19:51 christos Exp $");
#endif

#include <stddef.h>

#include <rnp/rnp_sdk.h>
#include <rnp/rnp_types.h>

#include "packet-show.h"
#include "utils.h"

/*
 * Arrays of value->text maps
 */

static pgp_map_t packet_tag_map[] = {
  {PGP_PTAG_CT_RESERVED, "Reserved"},
  {PGP_PTAG_CT_PK_SESSION_KEY, "Public-Key Encrypted Session Key"},
  {PGP_PTAG_CT_SIGNATURE, "Signature"},
  {PGP_PTAG_CT_SK_SESSION_KEY, "Symmetric-Key Encrypted Session Key"},
  {PGP_PTAG_CT_1_PASS_SIG, "One-Pass Signature"},
  {PGP_PTAG_CT_SECRET_KEY, "Secret Key"},
  {PGP_PTAG_CT_PUBLIC_KEY, "Public Key"},
  {PGP_PTAG_CT_SECRET_SUBKEY, "Secret Subkey"},
  {PGP_PTAG_CT_COMPRESSED, "Compressed Data"},
  {PGP_PTAG_CT_SE_DATA, "Symmetrically Encrypted Data"},
  {PGP_PTAG_CT_MARKER, "Marker"},
  {PGP_PTAG_CT_LITDATA, "Literal Data"},
  {PGP_PTAG_CT_TRUST, "Trust"},
  {PGP_PTAG_CT_USER_ID, "User ID"},
  {PGP_PTAG_CT_PUBLIC_SUBKEY, "Public Subkey"},
  {PGP_PTAG_CT_RESERVED2, "reserved2"},
  {PGP_PTAG_CT_RESERVED3, "reserved3"},
  {PGP_PTAG_CT_USER_ATTR, "User Attribute"},
  {PGP_PTAG_CT_SE_IP_DATA, "Symmetric Encrypted and Integrity Protected Data"},
  {PGP_PTAG_CT_MDC, "Modification Detection Code"},

  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t ss_rr_code_map[] = {
  {0x00, "No reason specified"},
  {0x01, "Key is superseded"},
  {0x02, "Key material has been compromised"},
  {0x03, "Key is retired and no longer used"},
  {0x20, "User ID information is no longer valid"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t sig_type_map[] = {
  {PGP_SIG_BINARY, "Signature of a binary document"},
  {PGP_SIG_TEXT, "Signature of a canonical text document"},
  {PGP_SIG_STANDALONE, "Standalone signature"},
  {PGP_CERT_GENERIC, "Generic certification of a User ID and Public Key packet"},
  {PGP_CERT_PERSONA, "Personal certification of a User ID and Public Key packet"},
  {PGP_CERT_CASUAL, "Casual certification of a User ID and Public Key packet"},
  {PGP_CERT_POSITIVE, "Positive certification of a User ID and Public Key packet"},
  {PGP_SIG_SUBKEY, "Subkey Binding Signature"},
  {PGP_SIG_PRIMARY, "Primary Key Binding Signature"},
  {PGP_SIG_DIRECT, "Signature directly on a key"},
  {PGP_SIG_REV_KEY, "Key revocation signature"},
  {PGP_SIG_REV_SUBKEY, "Subkey revocation signature"},
  {PGP_SIG_REV_CERT, "Certification revocation signature"},
  {PGP_SIG_TIMESTAMP, "Timestamp signature"},
  {PGP_SIG_3RD_PARTY, "Third-Party Confirmation signature"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t pubkey_alg_map[] = {
  {PGP_PKA_RSA, "RSA (Encrypt or Sign)"},
  {PGP_PKA_RSA_ENCRYPT_ONLY, "RSA Encrypt-Only"},
  {PGP_PKA_RSA_SIGN_ONLY, "RSA Sign-Only"},
  {PGP_PKA_ELGAMAL, "Elgamal (Encrypt-Only)"},
  {PGP_PKA_DSA, "DSA"},
  {PGP_PKA_ECDH, "ECDH"},
  {PGP_PKA_ECDSA, "ECDSA"},
  {PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN, "Reserved (formerly Elgamal Encrypt or Sign"},
  {PGP_PKA_RESERVED_DH, "Reserved for Diffie-Hellman (X9.42)"},
  {PGP_PKA_EDDSA, "EdDSA"},
  {PGP_PKA_SM2, "SM2"},
  {PGP_PKA_PRIVATE00, "Private/Experimental"},
  {PGP_PKA_PRIVATE01, "Private/Experimental"},
  {PGP_PKA_PRIVATE02, "Private/Experimental"},
  {PGP_PKA_PRIVATE03, "Private/Experimental"},
  {PGP_PKA_PRIVATE04, "Private/Experimental"},
  {PGP_PKA_PRIVATE05, "Private/Experimental"},
  {PGP_PKA_PRIVATE06, "Private/Experimental"},
  {PGP_PKA_PRIVATE07, "Private/Experimental"},
  {PGP_PKA_PRIVATE08, "Private/Experimental"},
  {PGP_PKA_PRIVATE09, "Private/Experimental"},
  {PGP_PKA_PRIVATE10, "Private/Experimental"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

static pgp_map_t symm_alg_map[] = {
  {PGP_SA_PLAINTEXT, "Plaintext or unencrypted data"},
  {PGP_SA_IDEA, "IDEA"},
  {PGP_SA_TRIPLEDES, "TripleDES"},
  {PGP_SA_CAST5, "CAST5"},
  {PGP_SA_BLOWFISH, "Blowfish"},
  {PGP_SA_AES_128, "AES (128-bit key)"},
  {PGP_SA_AES_192, "AES (192-bit key)"},
  {PGP_SA_AES_256, "AES (256-bit key)"},
  {PGP_SA_TWOFISH, "Twofish (256-bit key)"},
  {PGP_SA_CAMELLIA_128, "Camellia (128-bit key)"},
  {PGP_SA_CAMELLIA_192, "Camellia (192-bit key)"},
  {PGP_SA_CAMELLIA_256, "Camellia (256-bit key)"},
  {PGP_SA_SM4, "SM4"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

/*
 * Public Functions
 */

/**
 * \ingroup Core_Print
 * returns description of the Packet Tag
 * \param packet_tag
 * \return string or "Unknown"
 */
const char *
pgp_show_packet_tag(pgp_content_enum packet_tag)
{
    const char *ret;

    ret = pgp_str_from_map(packet_tag, packet_tag_map);
    if (!ret) {
        ret = "Unknown Tag";
    }
    return ret;
}

/**
 * \ingroup Core_Print
 *
 * returns description of the Revocation Reason code
 * \param ss_rr_code Revocation Reason code
 * \return string or "Unknown"
 */
const char *
pgp_show_ss_rr_code(pgp_ss_rr_code_t ss_rr_code)
{
    return pgp_str_from_map(ss_rr_code, ss_rr_code_map);
}

/**
 * \ingroup Core_Print
 *
 * returns description of the given Signature type
 * \param sig_type Signature type
 * \return string or "Unknown"
 */
const char *
pgp_show_sig_type(pgp_sig_type_t sig_type)
{
    return pgp_str_from_map(sig_type, sig_type_map);
}

/**
 * \ingroup Core_Print
 *
 * returns description of the given Public Key Algorithm
 * \param pka Public Key Algorithm type
 * \return string or "Unknown"
 */
const char *
pgp_show_pka(pgp_pubkey_alg_t pka)
{
    return pgp_str_from_map(pka, pubkey_alg_map);
}

const char *
pgp_show_symm_alg(uint8_t hash)
{
    return pgp_str_from_map(hash, symm_alg_map);
}
