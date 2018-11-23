/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "config.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "types.h"
#include "crypto.h"
#include "stream-packet.h"
#include "stream-key.h"
#include "utils.h"

uint32_t
read_uint32(const uint8_t *buf)
{
    return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) | ((uint32_t) buf[2] << 8) |
           (uint32_t) buf[3];
}

uint16_t
read_uint16(const uint8_t *buf)
{
    return ((uint16_t) buf[0] << 8) | buf[1];
}

void
write_uint16(uint8_t *buf, uint16_t val)
{
    buf[0] = val >> 8;
    buf[1] = val & 0xff;
}

size_t
write_packet_len(uint8_t *buf, size_t len)
{
    if (len < 192) {
        buf[0] = len;
        return 1;
    } else if (len < 8192 + 192) {
        buf[0] = ((len - 192) >> 8) + 192;
        buf[1] = (len - 192) & 0xff;
        return 2;
    } else {
        buf[0] = 0xff;
        STORE32BE(&buf[1], len);
        return 5;
    }
}

int
get_packet_type(uint8_t ptag)
{
    if (!(ptag & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (ptag & PGP_PTAG_NEW_FORMAT) {
        return (int) (ptag & PGP_PTAG_NF_CONTENT_TAG_MASK);
    } else {
        return (int) ((ptag & PGP_PTAG_OF_CONTENT_TAG_MASK) >> PGP_PTAG_OF_CONTENT_TAG_SHIFT);
    }
}

int
stream_pkt_type(pgp_source_t *src)
{
    uint8_t hdr[PGP_MAX_HEADER_SIZE];
    ssize_t hdrlen = 0;

    if (src_eof(src)) {
        return 0;
    }

    hdrlen = stream_pkt_hdr_len(src);
    if (hdrlen < 0) {
        return -1;
    }

    if (src_peek(src, hdr, hdrlen) != hdrlen) {
        return -1;
    }

    return get_packet_type(hdr[0]);
}

ssize_t
stream_pkt_hdr_len(pgp_source_t *src)
{
    uint8_t buf[2];
    ssize_t read;

    read = src_peek(src, buf, 2);
    if ((read < 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            return 2;
        } else if (buf[1] < 224) {
            return 3;
        } else if (buf[1] < 255) {
            return 2;
        } else {
            return 6;
        }
    } else {
        switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
        case PGP_PTAG_OLD_LEN_1:
            return 2;
        case PGP_PTAG_OLD_LEN_2:
            return 3;
        case PGP_PTAG_OLD_LEN_4:
            return 5;
        case PGP_PTAG_OLD_LEN_INDETERMINATE:
            return 1;
        default:
            return -1;
        }
    }
}

ssize_t
stream_read_pkt_len(pgp_source_t *src)
{
    uint8_t buf[6] = {};
    ssize_t read;

    if ((read = stream_pkt_hdr_len(src)) < 0) {
        return read;
    }

    if (!src_read_eq(src, buf, read)) {
        return -1;
    }

    return get_pkt_len(buf);
}

ssize_t
stream_read_partial_chunk_len(pgp_source_t *src, bool *last)
{
    uint8_t hdr[5] = {};
    ssize_t read = 0;

    read = src_read(src, hdr, 1);
    if (read < 0) {
        RNP_LOG("failed to read header");
        return -1;
    }
    if (read < 1) {
        RNP_LOG("wrong eof");
        return -1;
    }

    *last = true;

    // partial length
    if ((hdr[0] >= 224) && (hdr[0] < 255)) {
        *last = false;
        return get_partial_pkt_len(hdr[0]);
    }
    // 1-byte length
    if (hdr[0] < 192) {
        return hdr[0];
    }
    // 2-byte length
    if (hdr[0] < 224) {
        if (!src_read_eq(src, &hdr[1], 1)) {
            RNP_LOG("wrong 2-byte length");
            return -1;
        }
        return ((ssize_t)(hdr[0] - 192) << 8) + (ssize_t) hdr[1] + 192;
    }
    // 4-byte length
    if (!src_read_eq(src, &hdr[1], 4)) {
        RNP_LOG("wrong 4-byte length");
        return -1;
    }
    return ((ssize_t) hdr[1] << 24) | ((ssize_t) hdr[2] << 16) | ((ssize_t) hdr[3] << 8) |
           (ssize_t) hdr[4];
}

bool
stream_intedeterminate_pkt_len(pgp_source_t *src)
{
    uint8_t ptag = 0;
    if (src_peek(src, &ptag, 1) == 1) {
        return !(ptag & PGP_PTAG_NEW_FORMAT) &&
               ((ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK) == PGP_PTAG_OLD_LEN_INDETERMINATE);
    }
    return false;
}

bool
stream_partial_pkt_len(pgp_source_t *src)
{
    uint8_t hdr[2] = {};
    if (src_peek(src, hdr, 2) < 2) {
        return false;
    }
    return (hdr[0] & PGP_PTAG_NEW_FORMAT) && (hdr[1] >= 224) && (hdr[1] < 255);
}

size_t
get_partial_pkt_len(uint8_t blen)
{
    return 1 << (blen & 0x1f);
}

ssize_t
get_pkt_len(uint8_t *hdr)
{
    if (hdr[0] & PGP_PTAG_NEW_FORMAT) {
        // 1-byte length
        if (hdr[1] < 192) {
            return (ssize_t) hdr[1];
        }
        // 2-byte length
        if (hdr[1] < 224) {
            return ((ssize_t)(hdr[1] - 192) << 8) + (ssize_t) hdr[2] + 192;
        }
        // partial length - we do not allow it here
        if (hdr[1] < 255) {
            return -1;
        }
        // 4-byte length
        return read_uint32(&hdr[2]);
    }

    switch (hdr[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
    case PGP_PTAG_OLD_LEN_1:
        return (ssize_t) hdr[1];
    case PGP_PTAG_OLD_LEN_2:
        return read_uint16(&hdr[1]);
    case PGP_PTAG_OLD_LEN_4:
        return read_uint32(&hdr[1]);
    default:
        return -1;
    }
}

bool
init_packet_body(pgp_packet_body_t *body, int tag)
{
    body->data = (uint8_t *) malloc(16);
    if (!body->data) {
        return false;
    }
    body->allocated = 16;
    body->tag = tag;
    body->len = 0;
    return true;
}

bool
add_packet_body(pgp_packet_body_t *body, const void *data, size_t len)
{
    void * newdata;
    size_t newlen;

    if (body->len + len > body->allocated) {
        newlen = (body->len + len) * 2;
        newdata = (uint8_t *) realloc(body->data, newlen);
        if (!newdata) {
            return false;
        }
        body->data = (uint8_t *) newdata;
        body->allocated = newlen;
    }

    memcpy(body->data + body->len, data, len);
    body->len += len;

    return true;
}

bool
add_packet_body_byte(pgp_packet_body_t *body, uint8_t byte)
{
    if (body->len < body->allocated) {
        body->data[body->len++] = byte;
        return true;
    } else {
        return add_packet_body(body, &byte, 1);
    }
}

bool
add_packet_body_uint16(pgp_packet_body_t *body, uint16_t val)
{
    uint8_t bytes[2];

    write_uint16(bytes, val);
    return add_packet_body(body, bytes, 2);
}

bool
add_packet_body_uint32(pgp_packet_body_t *body, uint32_t val)
{
    uint8_t bytes[4];

    STORE32BE(bytes, val);
    return add_packet_body(body, bytes, 4);
}

bool
add_packet_body_mpi(pgp_packet_body_t *body, const pgp_mpi_t *val)
{
    unsigned bits;
    unsigned idx = 0;
    unsigned hibyte;
    uint8_t  hdr[2];

    if (!val->len) {
        return false;
    }

    while ((idx < val->len - 1) && (val->mpi[idx] == 0)) {
        idx++;
    }

    bits = (val->len - idx - 1) << 3;
    hibyte = val->mpi[idx];
    while (hibyte > 0) {
        bits++;
        hibyte = hibyte >> 1;
    }

    hdr[0] = bits >> 8;
    hdr[1] = bits & 0xff;
    return add_packet_body(body, hdr, 2) &&
           add_packet_body(body, val->mpi + idx, val->len - idx);
}

static bool
add_packet_body_key_curve(pgp_packet_body_t *body, const pgp_curve_t curve)
{
    const ec_curve_desc_t *desc = NULL;

    return (desc = get_curve_desc(curve)) &&
           add_packet_body_byte(body, (uint8_t) desc->OIDhex_len) &&
           add_packet_body(body, (void *) desc->OIDhex, desc->OIDhex_len);
}

static bool
add_packet_body_s2k(pgp_packet_body_t *body, const pgp_s2k_t *s2k)
{
    if (!add_packet_body_byte(body, s2k->specifier) ||
        !add_packet_body_byte(body, s2k->hash_alg)) {
        return false;
    }

    switch (s2k->specifier) {
    case PGP_S2KS_SIMPLE:
        return true;
    case PGP_S2KS_SALTED:
        return add_packet_body(body, s2k->salt, PGP_SALT_SIZE);
    case PGP_S2KS_ITERATED_AND_SALTED: {
        uint8_t iter = s2k->iterations;
        if (s2k->iterations > 255) {
            iter = pgp_s2k_encode_iterations(s2k->iterations);
        }
        return add_packet_body(body, s2k->salt, PGP_SALT_SIZE) &&
               add_packet_body_byte(body, iter);
    }
    default:
        RNP_LOG("unknown s2k specifier");
        return false;
    }
}

bool
add_packet_body_subpackets(pgp_packet_body_t *body, pgp_signature_t *sig, bool hashed)
{
    pgp_packet_body_t spbody;
    pgp_sig_subpkt_t *subpkt;
    size_t            lenlen;
    uint8_t           splen[6];
    bool              res;

    if (!init_packet_body(&spbody, 0)) {
        return false;
    }

    /* add space for subpackets length */
    res = add_packet_body_uint16(&spbody, 0);

    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        subpkt = (pgp_sig_subpkt_t *) sp;

        if (subpkt->hashed != hashed) {
            continue;
        }

        lenlen = write_packet_len(splen, subpkt->len + 1);
        res &= add_packet_body(&spbody, splen, lenlen) &&
               add_packet_body_byte(&spbody, subpkt->type | (subpkt->critical << 7)) &&
               add_packet_body(&spbody, subpkt->data, subpkt->len);
    }

    if (res) {
        /* now we know subpackets length */
        write_uint16(spbody.data, spbody.len - 2);
        res = add_packet_body(body, spbody.data, spbody.len);
    }

    free_packet_body(&spbody);
    return res;
}

bool
get_packet_body_byte(pgp_packet_body_t *body, uint8_t *val)
{
    if (body->pos >= body->len) {
        return false;
    }

    *val = body->data[body->pos++];
    return true;
}

bool
get_packet_body_uint16(pgp_packet_body_t *body, uint16_t *val)
{
    if (body->pos + 2 > body->len) {
        return false;
    }

    *val = read_uint16(body->data + body->pos);
    body->pos += 2;
    return true;
}

bool
get_packet_body_uint32(pgp_packet_body_t *body, uint32_t *val)
{
    if (body->pos + 4 > body->len) {
        return false;
    }

    *val = read_uint32(body->data + body->pos);
    body->pos += 4;
    return true;
}

bool
get_packet_body_buf(pgp_packet_body_t *body, uint8_t *val, size_t len)
{
    if (body->pos + len > body->len) {
        return false;
    }

    memcpy(val, body->data + body->pos, len);
    body->pos += len;
    return true;
}

bool
get_packet_body_mpi(pgp_packet_body_t *body, pgp_mpi_t *val)
{
    uint16_t bits;
    size_t   len;

    if (!get_packet_body_uint16(body, &bits)) {
        return false;
    }

    len = (bits + 7) >> 3;
    if (len > PGP_MPINT_SIZE) {
        RNP_LOG("too large mpi");
        return false;
    }
    if (len == 0) {
        RNP_LOG("0 mpi");
        return false;
    }
    if (!get_packet_body_buf(body, val->mpi, len)) {
        return false;
    }
    /* check the mpi bit count */
    unsigned hbits = bits & 7 ? bits & 7 : 8;
    if ((((unsigned) val->mpi[0] >> hbits) != 0) ||
        !((unsigned) val->mpi[0] & (1U << (hbits - 1)))) {
        RNP_LOG("wrong mpi bit count");
        return false;
    }

    val->len = len;
    return true;
}

/* @brief Read ECC key curve and convert it to pgp_curve_t */
static bool
get_packet_body_key_curve(pgp_packet_body_t *body, pgp_curve_t *val)
{
    uint8_t     oid[MAX_CURVE_OID_HEX_LEN] = {0};
    uint8_t     oidlen;
    pgp_curve_t res;

    if (!get_packet_body_byte(body, &oidlen)) {
        return false;
    }

    if ((oidlen == 0) || (oidlen == 0xff) || (oidlen > sizeof(oid))) {
        RNP_LOG("unsupported curve oid len: %d", (int) oidlen);
        return false;
    }

    if (!get_packet_body_buf(body, oid, oidlen)) {
        return false;
    }

    if ((res = find_curve_by_OID(oid, oidlen)) == PGP_CURVE_MAX) {
        RNP_LOG("unsupported curve");
        return false;
    }

    *val = res;
    return true;
}

static bool
get_packet_body_s2k(pgp_packet_body_t *body, pgp_s2k_t *s2k)
{
    uint8_t spec = 0, halg = 0;
    if (!get_packet_body_byte(body, &spec) || !get_packet_body_byte(body, &halg)) {
        return false;
    }
    s2k->specifier = (pgp_s2k_specifier_t) spec;
    s2k->hash_alg = (pgp_hash_alg_t) halg;

    switch (s2k->specifier) {
    case PGP_S2KS_SIMPLE:
        return true;
    case PGP_S2KS_SALTED:
        return get_packet_body_buf(body, s2k->salt, PGP_SALT_SIZE);
    case PGP_S2KS_ITERATED_AND_SALTED: {
        uint8_t iter;
        if (!get_packet_body_buf(body, s2k->salt, PGP_SALT_SIZE) ||
            !get_packet_body_byte(body, &iter)) {
            return false;
        }
        s2k->iterations = iter;
        return true;
    }
    default:
        RNP_LOG("unknown s2k specifier");
        return false;
    }
}

void
free_packet_body(pgp_packet_body_t *body)
{
    free(body->data);
    body->data = NULL;
}

void
stream_flush_packet_body(pgp_packet_body_t *body, pgp_dest_t *dst)
{
    uint8_t hdr[6];
    size_t  hlen;

    hdr[0] = body->tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    hlen = 1 + write_packet_len(&hdr[1], body->len);
    dst_write(dst, hdr, hlen);
    dst_write(dst, body->data, body->len);
    free_packet_body(body);
}

rnp_result_t
stream_read_packet_body(pgp_source_t *src, pgp_packet_body_t *body)
{
    ssize_t len;
    ssize_t read;

    memset(body, 0, sizeof(*body));

    /* Read the packet header and length */
    if ((len = stream_pkt_hdr_len(src)) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    if (src_peek(src, body->hdr, len) != len) {
        return RNP_ERROR_READ;
    }

    body->hdr_len = len;

    if ((body->tag = get_packet_type(body->hdr[0])) < 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    len = stream_read_pkt_len(src);
    if (len <= 0) {
        return RNP_ERROR_READ;
    }
    if (len > PGP_MAX_PKT_SIZE) {
        RNP_LOG("too large packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Read the packet contents */
    if (!(body->data = (uint8_t *) malloc(len))) {
        RNP_LOG("malloc of %d bytes failed", (int) len);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if ((read = src_read(src, body->data, len)) != len) {
        RNP_LOG("read %d instead of %d", (int) read, (int) len);
        free(body->data);
        body->data = NULL;
        return RNP_ERROR_READ;
    }

    body->allocated = len;
    body->len = len;
    body->pos = 0;

    return RNP_SUCCESS;
}

void
packet_body_part_from_mem(pgp_packet_body_t *body, const void *mem, size_t len)
{
    memset(body, 0, sizeof(*body));
    body->data = (uint8_t *) mem;
    body->len = len;
    body->allocated = len;
}

rnp_result_t
stream_skip_packet(pgp_source_t *src)
{
    ssize_t len;
    ssize_t partlen;
    bool    last = true;

    if (stream_intedeterminate_pkt_len(src)) {
        while (!src_eof(src)) {
            if (src_skip(src, PGP_MAX_PKT_SIZE) < 0) {
                return RNP_ERROR_READ;
            }
        }
        return RNP_SUCCESS;
    }

    if (stream_partial_pkt_len(src)) {
        src_skip(src, 1);
        partlen = stream_read_partial_chunk_len(src, &last);
        while (partlen > 0) {
            if (src_skip(src, partlen) != partlen) {
                return RNP_ERROR_READ;
            }
            if (last) {
                break;
            }
            partlen = stream_read_partial_chunk_len(src, &last);
            if (partlen < 0) {
                return RNP_ERROR_BAD_FORMAT;
            }
        }
        return RNP_SUCCESS;
    }

    len = stream_read_pkt_len(src);
    if (len <= 0) {
        return RNP_ERROR_READ;
    } else if (len > PGP_MAX_PKT_SIZE) {
        RNP_LOG("too large packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (src_skip(src, len) != len) {
        return RNP_ERROR_READ;
    }
    return RNP_SUCCESS;
}

bool
stream_write_sk_sesskey(pgp_sk_sesskey_t *skey, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_SK_SESSION_KEY)) {
        return false;
    }

    /* version and algorithm fields */
    res = add_packet_body_byte(&pktbody, skey->version) &&
          add_packet_body_byte(&pktbody, skey->alg);

    if (skey->version == PGP_SKSK_V5) {
        res = res && add_packet_body_byte(&pktbody, skey->aalg);
    }

    /* S2K specifier */
    res = res && add_packet_body_byte(&pktbody, skey->s2k.specifier) &&
          add_packet_body_byte(&pktbody, skey->s2k.hash_alg);

    switch (skey->s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
        res = res && add_packet_body(&pktbody, skey->s2k.salt, sizeof(skey->s2k.salt));
        break;
    case PGP_S2KS_ITERATED_AND_SALTED:
        res = res && add_packet_body(&pktbody, skey->s2k.salt, sizeof(skey->s2k.salt)) &&
              add_packet_body_byte(&pktbody, skey->s2k.iterations);
        break;
    }

    /* v5 : iv */
    if (skey->version == PGP_SKSK_V5) {
        res = res && add_packet_body(&pktbody, skey->iv, skey->ivlen);
    }

    /* encrypted key and auth tag for v5 */
    if (skey->enckeylen > 0) {
        res = res && add_packet_body(&pktbody, skey->enckey, skey->enckeylen);
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    }

    free_packet_body(&pktbody);
    return false;
}

bool
stream_write_pk_sesskey(pgp_pk_sesskey_t *pkey, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_PK_SESSION_KEY)) {
        return false;
    }

    res = add_packet_body_byte(&pktbody, pkey->version) &&
          add_packet_body(&pktbody, pkey->key_id, sizeof(pkey->key_id)) &&
          add_packet_body_byte(&pktbody, pkey->alg);
    if (!res) {
        goto error;
    }

    switch (pkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        res = add_packet_body_mpi(&pktbody, &pkey->material.rsa.m);
        break;
    case PGP_PKA_SM2:
        res = add_packet_body_mpi(&pktbody, &pkey->material.sm2.m);
        break;
    case PGP_PKA_ECDH:
        res = add_packet_body_mpi(&pktbody, &pkey->material.ecdh.p) &&
              add_packet_body_byte(&pktbody, pkey->material.ecdh.mlen) &&
              add_packet_body(&pktbody, pkey->material.ecdh.m, pkey->material.ecdh.mlen);
        break;
    case PGP_PKA_ELGAMAL:
        res = add_packet_body_mpi(&pktbody, &pkey->material.eg.g) &&
              add_packet_body_mpi(&pktbody, &pkey->material.eg.m);
        break;
    default:
        res = false;
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    }
error:
    free_packet_body(&pktbody);
    return false;
}

bool
stream_write_one_pass(pgp_one_pass_sig_t *onepass, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_1_PASS_SIG)) {
        return false;
    }

    res = add_packet_body_byte(&pktbody, onepass->version) &&
          add_packet_body_byte(&pktbody, onepass->type) &&
          add_packet_body_byte(&pktbody, onepass->halg) &&
          add_packet_body_byte(&pktbody, onepass->palg) &&
          add_packet_body(&pktbody, onepass->keyid, PGP_KEY_ID_SIZE) &&
          add_packet_body_byte(&pktbody, onepass->nested);

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return true;
    } else {
        free_packet_body(&pktbody);
        return false;
    }
}

bool
stream_write_signature(pgp_signature_t *sig, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }

    if (!init_packet_body(&pktbody, PGP_PTAG_CT_SIGNATURE)) {
        RNP_LOG("allocation failed");
        return false;
    }

    if (sig->version < PGP_V4) {
        /* for v3 signatures hashed data includes only type + creation_time */
        res = add_packet_body_byte(&pktbody, sig->version) &&
              add_packet_body_byte(&pktbody, sig->hashed_len) &&
              add_packet_body(&pktbody, sig->hashed_data, sig->hashed_len) &&
              add_packet_body(&pktbody, sig->signer, PGP_KEY_ID_SIZE) &&
              add_packet_body_byte(&pktbody, sig->palg) &&
              add_packet_body_byte(&pktbody, sig->halg);
    } else {
        /* for v4 sig->hashed_data must contain most of signature fields */
        res = add_packet_body(&pktbody, sig->hashed_data, sig->hashed_len) &&
              add_packet_body_subpackets(&pktbody, sig, false);
    }

    res &= add_packet_body(&pktbody, sig->lbits, 2);

    /* write mpis */
    switch (sig->palg) {
    case PGP_PKA_RSA:
        res &= add_packet_body_mpi(&pktbody, &sig->material.rsa.s);
        break;
    case PGP_PKA_DSA:
        res &= add_packet_body_mpi(&pktbody, &sig->material.dsa.r) &&
               add_packet_body_mpi(&pktbody, &sig->material.dsa.s);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res &= add_packet_body_mpi(&pktbody, &sig->material.ecc.r) &&
               add_packet_body_mpi(&pktbody, &sig->material.ecc.s);
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) sig->palg);
        res = false;
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        return dst->werr == RNP_SUCCESS;
    }

    free_packet_body(&pktbody);
    return false;
}

rnp_result_t
stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey)
{
    uint8_t           bt;
    int               ptag;
    pgp_packet_body_t pkt = {};
    rnp_result_t      res = RNP_ERROR_BAD_FORMAT;

    if ((ptag = stream_pkt_type(src)) != PGP_PTAG_CT_SK_SESSION_KEY) {
        RNP_LOG("wrong sk ptag: %d", ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    memset(skey, 0, sizeof(*skey));
    res = RNP_ERROR_BAD_FORMAT;

    /* version */
    if (!get_packet_body_byte(&pkt, &bt) || ((bt != PGP_SKSK_V4) && (bt != PGP_SKSK_V5))) {
        RNP_LOG("wrong packet version");
        goto finish;
    }
    skey->version = bt;

    /* symmetric algorithm */
    if (!get_packet_body_byte(&pkt, &bt)) {
        RNP_LOG("failed to get symm alg");
        goto finish;
    }
    skey->alg = (pgp_symm_alg_t) bt;

    if (skey->version == PGP_SKSK_V5) {
        /* aead algorithm */
        if (!get_packet_body_byte(&pkt, &bt)) {
            RNP_LOG("failed to get aead alg");
            goto finish;
        }
        skey->aalg = (pgp_aead_alg_t) bt;
        if ((skey->aalg != PGP_AEAD_EAX) && (skey->aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unsupported AEAD algorithm : %d", (int) skey->aalg);
            res = RNP_ERROR_BAD_PARAMETERS;
            goto finish;
        }
    }

    /* s2k */
    if (!get_packet_body_s2k(&pkt, &skey->s2k)) {
        RNP_LOG("failed to parse s2k");
        goto finish;
    }

    if (skey->version == PGP_SKSK_V5) {
        /* v5: iv + esk + tag. For both EAX and OCB ivlen and taglen are 16 octets */
        size_t ivlen = pgp_cipher_aead_nonce_len(skey->aalg);
        size_t taglen = pgp_cipher_aead_tag_len(skey->aalg);
        size_t keylen = 0;

        if (pkt.len > pkt.pos + ivlen + taglen + PGP_MAX_KEY_SIZE) {
            RNP_LOG("too long esk");
            goto finish;
        }
        if (pkt.len < ivlen + taglen + 8) {
            RNP_LOG("too short esk");
            goto finish;
        }

        /* iv */
        if (!get_packet_body_buf(&pkt, skey->iv, ivlen)) {
            RNP_LOG("failed to get iv");
            goto finish;
        }
        skey->ivlen = ivlen;

        /* key */
        keylen = pkt.len - pkt.pos;
        if (!get_packet_body_buf(&pkt, skey->enckey, keylen)) {
            RNP_LOG("failed to get key");
            goto finish;
        }
        skey->enckeylen = keylen;
    } else {
        /* v4: encrypted session key if present */
        size_t keylen = pkt.len - pkt.pos;
        if (keylen) {
            if (keylen > PGP_MAX_KEY_SIZE + 1) {
                RNP_LOG("too long esk");
                goto finish;
            }
            if (!get_packet_body_buf(&pkt, skey->enckey, keylen)) {
                RNP_LOG("failed to get key");
                goto finish;
            }
        }
        skey->enckeylen = keylen;
    }

    res = RNP_SUCCESS;
finish:
    free_packet_body(&pkt);
    return res;
}

rnp_result_t
stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey)
{
    uint8_t           bt = 0;
    pgp_packet_body_t pkt = {};
    rnp_result_t      res = RNP_ERROR_BAD_FORMAT;
    int               ptag;

    if ((ptag = stream_pkt_type(src)) != PGP_PTAG_CT_PK_SESSION_KEY) {
        RNP_LOG("wrong pk ptag: %d", ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    memset(pkey, 0, sizeof(*pkey));
    res = RNP_ERROR_BAD_FORMAT;

    /* version */
    if (!get_packet_body_byte(&pkt, &bt) || (bt != PGP_PKSK_V3)) {
        RNP_LOG("wrong packet version");
        goto finish;
    }
    pkey->version = bt;

    /* key id */
    if (!get_packet_body_buf(&pkt, pkey->key_id, PGP_KEY_ID_SIZE)) {
        RNP_LOG("failed to get key id");
        goto finish;
    }

    /* public key algorithm */
    if (!get_packet_body_byte(&pkt, &bt)) {
        RNP_LOG("failed to get palg");
        goto finish;
    }
    pkey->alg = (pgp_pubkey_alg_t) bt;

    switch (pkey->alg) {
    case PGP_PKA_RSA:
        /* RSA m */
        if (!get_packet_body_mpi(&pkt, &pkey->material.rsa.m)) {
            RNP_LOG("failed to get rsa m");
            goto finish;
        }
        break;
    case PGP_PKA_ELGAMAL:
        /* ElGamal g, m */
        if (!get_packet_body_mpi(&pkt, &pkey->material.eg.g) ||
            !get_packet_body_mpi(&pkt, &pkey->material.eg.m)) {
            RNP_LOG("failed to get elgamal mpis");
            goto finish;
        }
        break;
    case PGP_PKA_SM2:
        /* SM2 m */
        if (!get_packet_body_mpi(&pkt, &pkey->material.sm2.m)) {
            RNP_LOG("failed to get sm2 m");
            goto finish;
        }
        break;
    case PGP_PKA_ECDH:
        /* ECDH ephemeral point */
        if (!get_packet_body_mpi(&pkt, &pkey->material.ecdh.p)) {
            RNP_LOG("failed to get ecdh p");
            goto finish;
        }
        /* ECDH m */
        if (!get_packet_body_byte(&pkt, &bt)) {
            RNP_LOG("failed to get ecdh m len");
            goto finish;
        }
        if (bt > ECDH_WRAPPED_KEY_SIZE) {
            RNP_LOG("wrong ecdh m len");
            goto finish;
        }
        pkey->material.ecdh.mlen = bt;
        if (!get_packet_body_buf(&pkt, pkey->material.ecdh.m, bt)) {
            RNP_LOG("failed to get ecdh m len");
            goto finish;
        }
        break;
    default:
        RNP_LOG("unknown pk alg %d", (int) pkey->alg);
        return RNP_ERROR_BAD_FORMAT;
    }

    if (pkt.pos < pkt.len) {
        RNP_LOG("extra %d bytes in pk packet", (int) (pkt.len - pkt.pos));
        goto finish;
    }

    res = RNP_SUCCESS;
finish:
    free_packet_body(&pkt);
    return res;
}

rnp_result_t
stream_parse_one_pass(pgp_source_t *src, pgp_one_pass_sig_t *onepass)
{
    uint8_t           buf[13];
    pgp_packet_body_t pkt = {};
    rnp_result_t      res;

    /* Read the packet into memory */
    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    memset(onepass, 0, sizeof(*onepass));
    res = RNP_ERROR_BAD_FORMAT;

    if ((pkt.len != 13) || (!get_packet_body_buf(&pkt, buf, 13))) {
        goto finish;
    }

    /* vesrion */
    if (buf[0] != 3) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    onepass->version = buf[0];

    /* signature type */
    onepass->type = (pgp_sig_type_t) buf[1];

    /* hash algorithm */
    onepass->halg = (pgp_hash_alg_t) buf[2];

    /* pk algorithm */
    onepass->palg = (pgp_pubkey_alg_t) buf[3];

    /* key id */
    memcpy(onepass->keyid, &buf[4], PGP_KEY_ID_SIZE);

    /* nested flag */
    onepass->nested = !!buf[12];

    res = RNP_SUCCESS;
finish:
    free_packet_body(&pkt);
    return res;
}

/* parse v3-specific fields, not the whole signature */
static rnp_result_t
signature_read_v3(pgp_packet_body_t *pkt, pgp_signature_t *sig)
{
    uint8_t buf[16] = {};

    if (!get_packet_body_buf(pkt, buf, 16)) {
        RNP_LOG("cannot get enough bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* length of hashed data, 5 */
    if (buf[0] != 5) {
        RNP_LOG("wrong length of hashed data");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* hashed data */
    if ((sig->hashed_data = (uint8_t *) malloc(5)) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(sig->hashed_data, &buf[1], 5);
    sig->hashed_len = 5;

    /* signature type */
    sig->type = (pgp_sig_type_t) buf[1];

    /* creation time */
    sig->creation_time = read_uint32(&buf[2]);

    /* signer's key id */
    memcpy(sig->signer, &buf[6], PGP_KEY_ID_SIZE);

    /* public key algorithm */
    sig->palg = (pgp_pubkey_alg_t) buf[14];

    /* hash algorithm */
    sig->halg = (pgp_hash_alg_t) buf[15];

    return RNP_SUCCESS;
}

/* check the signature's subpacket for validity */
bool
signature_parse_subpacket(pgp_sig_subpkt_t *subpkt)
{
    bool oklen = true;
    bool checked = true;

    switch (subpkt->type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        if (!subpkt->hashed) {
            RNP_LOG("creation time subpacket must be hashed");
            checked = false;
        }
        if ((oklen = subpkt->len == 4)) {
            subpkt->fields.create = read_uint32(subpkt->data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        if ((oklen = subpkt->len == 4)) {
            subpkt->fields.expiry = read_uint32(subpkt->data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.exportable = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_TRUST:
        if ((oklen = subpkt->len == 2)) {
            subpkt->fields.trust.level = subpkt->data[0];
            subpkt->fields.trust.amount = subpkt->data[1];
        }
        break;
    case PGP_SIG_SUBPKT_REGEXP:
        subpkt->fields.regexp.str = (const char *) subpkt->data;
        subpkt->fields.regexp.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCABLE:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.revocable = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        subpkt->fields.preferred.arr = subpkt->data;
        subpkt->fields.preferred.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        if ((oklen = subpkt->len == 22)) {
            subpkt->fields.revocation_key.klass = subpkt->data[0];
            subpkt->fields.revocation_key.pkalg = (pgp_pubkey_alg_t) subpkt->data[1];
            subpkt->fields.revocation_key.fp = &subpkt->data[2];
        }
        break;
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        if ((oklen = subpkt->len == 8)) {
            subpkt->fields.issuer = subpkt->data;
        }
        break;
    case PGP_SIG_SUBPKT_NOTATION_DATA:
        if ((oklen = subpkt->len >= 8)) {
            memcpy(subpkt->fields.notation.flags, subpkt->data, 4);
            subpkt->fields.notation.nlen = read_uint16(&subpkt->data[4]);
            subpkt->fields.notation.vlen = read_uint16(&subpkt->data[6]);

            if (subpkt->len !=
                8 + subpkt->fields.notation.nlen + subpkt->fields.notation.vlen) {
                oklen = false;
            } else {
                subpkt->fields.notation.name = (const char *) &subpkt->data[8];
                subpkt->fields.notation.value =
                  (const char *) &subpkt->data[8 + subpkt->fields.notation.nlen];
            }
        }
        break;
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.ks_prefs.no_modify = (subpkt->data[0] & 0x80) != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        subpkt->fields.preferred_ks.uri = (const char *) subpkt->data;
        subpkt->fields.preferred_ks.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        if ((oklen = subpkt->len == 1)) {
            subpkt->fields.primary_uid = subpkt->data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_POLICY_URI:
        subpkt->fields.policy.uri = (const char *) subpkt->data;
        subpkt->fields.policy.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_KEY_FLAGS:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.key_flags = subpkt->data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        subpkt->fields.signer.uid = (const char *) subpkt->data;
        subpkt->fields.signer.len = subpkt->len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_REASON:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.revocation_reason.code = subpkt->data[0];
            subpkt->fields.revocation_reason.str = (const char *) &subpkt->data[1];
            subpkt->fields.revocation_reason.len = subpkt->len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_FEATURES:
        if ((oklen = subpkt->len >= 1)) {
            subpkt->fields.features.mdc = subpkt->data[0] & 0x01;
            subpkt->fields.features.aead = subpkt->data[0] & 0x02;
            subpkt->fields.features.key_v5 = subpkt->data[0] & 0x04;
        }
        break;
    case PGP_SIG_SUBPKT_SIGNATURE_TARGET:
        if ((oklen = subpkt->len >= 18)) {
            subpkt->fields.sig_target.pkalg = (pgp_pubkey_alg_t) subpkt->data[0];
            subpkt->fields.sig_target.halg = (pgp_hash_alg_t) subpkt->data[1];
            subpkt->fields.sig_target.hash = &subpkt->data[2];
            subpkt->fields.sig_target.hlen = subpkt->len - 2;
        }
        break;
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE: {
        /* parse signature */
        pgp_packet_body_t pkt = {};
        packet_body_part_from_mem(&pkt, subpkt->data, subpkt->len);
        oklen = checked = !stream_parse_signature_body(&pkt, &subpkt->fields.sig);
        break;
    }
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        if ((oklen = subpkt->len >= 21)) {
            subpkt->fields.issuer_fp.version = subpkt->data[0];
            subpkt->fields.issuer_fp.fp = &subpkt->data[1];
            subpkt->fields.issuer_fp.len = subpkt->len - 1;
        }
        break;
    default:
        RNP_LOG("unknown subpacket : %d", (int) subpkt->type);
        return !subpkt->critical;
    }

    if (!oklen) {
        RNP_LOG("wrong len %d of subpacket type %d", (int) subpkt->len, (int) subpkt->type);
    }

    if (oklen) {
        subpkt->parsed = 1;
    }

    return oklen && checked;
}

/* parse signature subpackets */
static bool
signature_parse_subpackets(pgp_signature_t *sig, uint8_t *buf, size_t len, bool hashed)
{
    pgp_sig_subpkt_t subpkt;
    size_t           splen;
    bool             res = true;

    while (len > 0) {
        if (len < 2) {
            RNP_LOG("got single byte %d", (int) *buf);
            return false;
        }

        /* subpacket length */
        if (*buf < 192) {
            splen = *buf;
            buf++;
            len--;
        } else if (*buf < 255) {
            splen = ((buf[0] - 192) << 8) + buf[1] + 192;
            buf += 2;
            len -= 2;
        } else {
            if (len < 5) {
                RNP_LOG("got 4-byte len but only %d bytes in buffer", (int) len);
                return false;
            }
            splen = read_uint32(&buf[1]);
            buf += 5;
            len -= 5;
        }

        if (splen < 1) {
            RNP_LOG("got subpacket with 0 length, skipping");
            continue;
        }

        /* subpacket data */
        if (len < splen) {
            RNP_LOG("got subpacket len %d, while only %d bytes left", (int) splen, (int) len);
            return false;
        }

        memset(&subpkt, 0, sizeof(subpkt));

        if ((subpkt.data = (uint8_t *) malloc(splen - 1)) == NULL) {
            RNP_LOG("subpacket data allocation failed");
            return false;
        }

        subpkt.type = (pgp_sig_subpacket_type_t)(*buf & 0x7f);
        subpkt.critical = !!(*buf & 0x80);
        subpkt.hashed = hashed;
        subpkt.parsed = 0;
        memcpy(subpkt.data, buf + 1, splen - 1);
        subpkt.len = splen - 1;

        res = res && signature_parse_subpacket(&subpkt);

        if (!list_append(&sig->subpkts, &subpkt, sizeof(subpkt))) {
            RNP_LOG("allocation failed");
            return false;
        }

        len -= splen;
        buf += splen;
    }

    return res;
}

/* parse v4-specific fields, not the whole signature */
static rnp_result_t
signature_read_v4(pgp_packet_body_t *pkt, pgp_signature_t *sig)
{
    uint8_t      buf[5];
    uint8_t *    spbuf;
    uint16_t     splen;
    rnp_result_t res = RNP_ERROR_BAD_FORMAT;

    if (!get_packet_body_buf(pkt, buf, 5)) {
        RNP_LOG("cannot get first 5 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* signature type */
    sig->type = (pgp_sig_type_t) buf[0];

    /* public key algorithm */
    sig->palg = (pgp_pubkey_alg_t) buf[1];

    /* hash algorithm */
    sig->halg = (pgp_hash_alg_t) buf[2];

    /* hashed subpackets length */
    splen = read_uint16(&buf[3]);

    /* hashed subpackets length + 2 bytes of length of unhashed subpackets */
    if (pkt->len < pkt->pos + splen + 2) {
        RNP_LOG("wrong packet or hashed subpackets length");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* building hashed data */
    if ((sig->hashed_data = (uint8_t *) malloc(splen + 6)) == NULL) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    sig->hashed_data[0] = sig->version;
    memcpy(sig->hashed_data + 1, buf, 5);

    if (!get_packet_body_buf(pkt, sig->hashed_data + 6, splen)) {
        RNP_LOG("cannot get hashed subpackets data");
        return RNP_ERROR_BAD_FORMAT;
    }
    sig->hashed_len = splen + 6;

    /* parsing hashed subpackets */
    if (!signature_parse_subpackets(sig, sig->hashed_data + 6, splen, true)) {
        RNP_LOG("failed to parse hashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* reading unhashed subpackets */
    if (!get_packet_body_uint16(pkt, &splen)) {
        RNP_LOG("cannot get unhashed len");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (pkt->len < pkt->pos + splen) {
        RNP_LOG("not enough data for unhashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((spbuf = (uint8_t *) malloc(splen)) == NULL) {
        RNP_LOG("allocation of unhashed subpackets failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!get_packet_body_buf(pkt, spbuf, splen)) {
        RNP_LOG("read of unhashed subpackets failed");
        goto finish;
    }

    if (!signature_parse_subpackets(sig, spbuf, splen, false)) {
        RNP_LOG("failed to parse unhashed subpackets");
        goto finish;
    }

    res = RNP_SUCCESS;
finish:
    free(spbuf);
    return res;
}

rnp_result_t
stream_parse_signature_body(pgp_packet_body_t *pkt, pgp_signature_t *sig)
{
    uint8_t      ver;
    rnp_result_t res = RNP_ERROR_BAD_FORMAT;

    memset(sig, 0, sizeof(*sig));
    if (!get_packet_body_byte(pkt, &ver)) {
        goto finish;
    }
    sig->version = (pgp_version_t) ver;

    /* v3 or v4 signature body */
    if ((ver == PGP_V2) || (ver == PGP_V3)) {
        res = signature_read_v3(pkt, sig);
    } else if (ver == PGP_V4) {
        res = signature_read_v4(pkt, sig);
    } else {
        RNP_LOG("unknown signature version: %d", (int) ver);
        goto finish;
    }

    /* left 16 bits of the hash */
    if (!get_packet_body_buf(pkt, sig->lbits, 2)) {
        RNP_LOG("not enough data for hash left bits");
        goto finish;
    }

    /* signature MPIs */
    switch (sig->palg) {
    case PGP_PKA_RSA:
        if (!get_packet_body_mpi(pkt, &sig->material.rsa.s)) {
            goto finish;
        }
        break;
    case PGP_PKA_DSA:
        if (!get_packet_body_mpi(pkt, &sig->material.dsa.r) ||
            !get_packet_body_mpi(pkt, &sig->material.dsa.s)) {
            goto finish;
        }
        break;
    case PGP_PKA_EDDSA:
        if (sig->version < PGP_V4) {
            RNP_LOG("Warning! v3 EdDSA signature.");
        }
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        if (!get_packet_body_mpi(pkt, &sig->material.ecc.r) ||
            !get_packet_body_mpi(pkt, &sig->material.ecc.s)) {
            goto finish;
        }
        break;
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!get_packet_body_mpi(pkt, &sig->material.eg.r) ||
            !get_packet_body_mpi(pkt, &sig->material.eg.s)) {
            goto finish;
        }
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) sig->palg);
        goto finish;
    }

    if (pkt->pos < pkt->len) {
        RNP_LOG("extra %d bytes in signature packet", (int) (pkt->len - pkt->pos));
        goto finish;
    }
    res = RNP_SUCCESS;
finish:
    if (res) {
        free_signature(sig);
    }
    return res;
}

rnp_result_t
stream_parse_signature(pgp_source_t *src, pgp_signature_t *sig)
{
    int               ptag;
    pgp_packet_body_t pkt = {};
    rnp_result_t      res = RNP_ERROR_BAD_FORMAT;

    if ((ptag = stream_pkt_type(src)) != PGP_PTAG_CT_SIGNATURE) {
        RNP_LOG("wrong signature ptag: %d", ptag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    res = stream_parse_signature_body(&pkt, sig);
    free_packet_body(&pkt);
    return res;
}

bool
copy_signature_packet(pgp_signature_t *dst, const pgp_signature_t *src)
{
    memcpy(dst, src, sizeof(*src));
    dst->hashed_data = NULL;
    dst->subpkts = NULL;
    if (src->hashed_data) {
        if (!(dst->hashed_data = (uint8_t *) malloc(dst->hashed_len))) {
            return false;
        }
        memcpy(dst->hashed_data, src->hashed_data, dst->hashed_len);
    }

    for (list_item *sp = list_front(src->subpkts); sp; sp = list_next(sp)) {
        pgp_sig_subpkt_t *dstsp;
        pgp_sig_subpkt_t *srcsp = (pgp_sig_subpkt_t *) sp;
        /* subpacket may have internal pointers to the subpkt->data ! */
        dstsp = (pgp_sig_subpkt_t *) list_append(&dst->subpkts, srcsp, sizeof(*dstsp));
        if (!dstsp) {
            free_signature(dst);
            return false;
        }
        if (!(dstsp->data = (uint8_t *) malloc(dstsp->len))) {
            free_signature(dst);
            return false;
        }
        memcpy(dstsp->data, srcsp->data, srcsp->len);
        dstsp->len = srcsp->len;
        memset(&dstsp->fields, 0, sizeof(dstsp->fields));
        signature_parse_subpacket(dstsp);
    }

    return true;
}

bool
signature_pkt_equal(const pgp_signature_t *sig1, const pgp_signature_t *sig2)
{
    if (memcmp(sig1->lbits, sig2->lbits, 2)) {
        return false;
    }

    if ((sig1->hashed_len != sig2->hashed_len) ||
        memcmp(sig1->hashed_data, sig2->hashed_data, sig1->hashed_len)) {
        return false;
    }

    switch (sig1->palg) {
    case PGP_PKA_RSA:
        return mpi_equal(&sig1->material.rsa.s, &sig2->material.rsa.s);
    case PGP_PKA_DSA:
        return mpi_equal(&sig1->material.dsa.r, &sig2->material.dsa.r) &&
               mpi_equal(&sig1->material.dsa.s, &sig2->material.dsa.s);
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return mpi_equal(&sig1->material.eg.r, &sig2->material.eg.r) &&
               mpi_equal(&sig1->material.eg.s, &sig2->material.eg.s);
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        return mpi_equal(&sig1->material.ecc.r, &sig2->material.ecc.r) &&
               mpi_equal(&sig1->material.ecc.s, &sig2->material.ecc.s);
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) sig1->palg);
        return false;
    }
}

void
free_signature_subpkt(pgp_sig_subpkt_t *subpkt)
{
    if (!subpkt) {
        return;
    }
    if (subpkt->parsed && (subpkt->type == PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE)) {
        free_signature(&subpkt->fields.sig);
    }
    free(subpkt->data);
}

void
free_signature(pgp_signature_t *sig)
{
    free(sig->hashed_data);
    for (list_item *sp = list_front(sig->subpkts); sp; sp = list_next(sp)) {
        free_signature_subpkt((pgp_sig_subpkt_t *) sp);
    }
    list_destroy(&sig->subpkts);
}

bool
is_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_subkey_pkt(int tag)
{
    return (tag == PGP_PTAG_CT_PUBLIC_SUBKEY) || (tag == PGP_PTAG_CT_SECRET_SUBKEY);
}

bool
is_primary_key_pkt(int tag)
{
    return (tag == PGP_PTAG_CT_PUBLIC_KEY) || (tag == PGP_PTAG_CT_SECRET_KEY);
}

bool
is_public_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_secret_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_rsa_key_alg(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return true;
    default:
        return false;
    }
}

/* @brief Fills the hashed (signed) data part of the key packet. Must be called before
          stream_write_key() on the newly generated key
 */
bool
key_fill_hashed_data(pgp_key_pkt_t *key)
{
    pgp_packet_body_t hbody;
    bool              res = false;

    /* we don't have a need to write v2-v3 signatures */
    if (key->version != PGP_V4) {
        RNP_LOG("unknown key version %d", (int) key->version);
        return false;
    }

    if (!init_packet_body(&hbody, 0)) {
        RNP_LOG("allocation failed");
        return false;
    }

    res = add_packet_body_byte(&hbody, key->version) &&
          add_packet_body_uint32(&hbody, key->creation_time) &&
          add_packet_body_byte(&hbody, key->alg);

    if (!res) {
        goto error;
    }

    /* Algorithm specific fields */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = add_packet_body_mpi(&hbody, &key->material.rsa.n) &&
              add_packet_body_mpi(&hbody, &key->material.rsa.e);
        break;
    case PGP_PKA_DSA:
        res = add_packet_body_mpi(&hbody, &key->material.dsa.p) &&
              add_packet_body_mpi(&hbody, &key->material.dsa.q) &&
              add_packet_body_mpi(&hbody, &key->material.dsa.g) &&
              add_packet_body_mpi(&hbody, &key->material.dsa.y);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        res = add_packet_body_mpi(&hbody, &key->material.eg.p) &&
              add_packet_body_mpi(&hbody, &key->material.eg.g) &&
              add_packet_body_mpi(&hbody, &key->material.eg.y);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        res = add_packet_body_key_curve(&hbody, key->material.ec.curve) &&
              add_packet_body_mpi(&hbody, &key->material.ec.p);
        break;
    case PGP_PKA_ECDH:
        res = add_packet_body_key_curve(&hbody, key->material.ec.curve) &&
              add_packet_body_mpi(&hbody, &key->material.ec.p) &&
              add_packet_body_byte(&hbody, 3) && add_packet_body_byte(&hbody, 1) &&
              add_packet_body_byte(&hbody, key->material.ec.kdf_hash_alg) &&
              add_packet_body_byte(&hbody, key->material.ec.key_wrap_alg);
        break;
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
        res = false;
    }

    /* get ownership on written data on success*/
    if (res) {
        key->hashed_data = hbody.data;
        key->hashed_len = hbody.len;
        return true;
    }
error:
    free_packet_body(&hbody);
    return false;
}

bool
stream_write_key(pgp_key_pkt_t *key, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if (!is_key_pkt(key->tag)) {
        RNP_LOG("wrong key tag");
        return false;
    }

    if (!key->hashed_data && !key_fill_hashed_data(key)) {
        return false;
    }

    if (!init_packet_body(&pktbody, key->tag)) {
        RNP_LOG("allocation failed");
        return false;
    }

    /* all public key data is written in hashed_data */
    if (!(res = add_packet_body(&pktbody, key->hashed_data, key->hashed_len))) {
        goto finish;
    }

    if (is_secret_key_pkt(key->tag)) {
        /* secret key fields should be pre-populated in sec_data field */
        if (!key->sec_data || !key->sec_len) {
            RNP_LOG("secret key data is not populated");
            res = false;
            goto finish;
        }
        if (!(res = add_packet_body_byte(&pktbody, key->sec_protection.s2k.usage))) {
            goto finish;
        }
        switch (key->sec_protection.s2k.usage) {
        case PGP_S2KU_NONE:
            res = true;
            break;
        case PGP_S2KU_ENCRYPTED_AND_HASHED:
        case PGP_S2KU_ENCRYPTED: {
            size_t blsize = pgp_block_size(key->sec_protection.symm_alg);
            if (!blsize) {
                res = false;
                goto finish;
            }
            res = add_packet_body_byte(&pktbody, key->sec_protection.symm_alg) &&
                  add_packet_body_s2k(&pktbody, &key->sec_protection.s2k) &&
                  add_packet_body(&pktbody, key->sec_protection.iv, blsize);
            if (!res) {
                goto finish;
            }
            break;
        }
        default:
            RNP_LOG("wrong s2k usage");
            res = false;
            goto finish;
        }
        res = add_packet_body(&pktbody, key->sec_data, key->sec_len);
    }

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        res = dst->werr == RNP_SUCCESS;
    }

finish:
    if (!res) {
        free_packet_body(&pktbody);
    }
    return res;
}

rnp_result_t
stream_parse_key(pgp_source_t *src, pgp_key_pkt_t *key)
{
    pgp_packet_body_t pkt;
    rnp_result_t      res;
    int               tag;
    uint8_t           alg = 0;
    uint8_t           ver = 0;

    /* check the key tag */
    tag = stream_pkt_type(src);
    if (!is_key_pkt(tag)) {
        RNP_LOG("wrong key packet tag: %d", tag);
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Read the packet into memory */
    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    res = RNP_ERROR_BAD_FORMAT;
    memset(key, 0, sizeof(*key));

    /* key type, i.e. tag */
    key->tag = pkt.tag;

    /* version */
    if (!get_packet_body_byte(&pkt, &ver) || (ver < PGP_V2) || (ver > PGP_V4)) {
        RNP_LOG("wrong key packet version");
        goto finish;
    }
    key->version = (pgp_version_t) ver;

    /* creation time */
    if (!get_packet_body_uint32(&pkt, &key->creation_time)) {
        goto finish;
    }

    /* v3: validity days */
    if ((key->version < PGP_V4) && !get_packet_body_uint16(&pkt, &key->v3_days)) {
        goto finish;
    }

    /* key algorithm */
    if (!get_packet_body_byte(&pkt, &alg)) {
        goto finish;
    }
    key->alg = (pgp_pubkey_alg_t) alg;
    key->material.alg = (pgp_pubkey_alg_t) alg;

    /* v3 keys must be RSA-only */
    if ((key->version < PGP_V4) && !is_rsa_key_alg(key->alg)) {
        RNP_LOG("wrong v3 pk algorithm");
        goto finish;
    }

    /* algorithm specific fields */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!get_packet_body_mpi(&pkt, &key->material.rsa.n) ||
            !get_packet_body_mpi(&pkt, &key->material.rsa.e)) {
            goto finish;
        }
        break;
    case PGP_PKA_DSA:
        if (!get_packet_body_mpi(&pkt, &key->material.dsa.p) ||
            !get_packet_body_mpi(&pkt, &key->material.dsa.q) ||
            !get_packet_body_mpi(&pkt, &key->material.dsa.g) ||
            !get_packet_body_mpi(&pkt, &key->material.dsa.y)) {
            goto finish;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!get_packet_body_mpi(&pkt, &key->material.eg.p) ||
            !get_packet_body_mpi(&pkt, &key->material.eg.g) ||
            !get_packet_body_mpi(&pkt, &key->material.eg.y)) {
            goto finish;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        if (!get_packet_body_key_curve(&pkt, &key->material.ec.curve) ||
            !get_packet_body_mpi(&pkt, &key->material.ec.p)) {
            goto finish;
        }
        break;
    case PGP_PKA_ECDH: {
        if (!get_packet_body_key_curve(&pkt, &key->material.ec.curve) ||
            !get_packet_body_mpi(&pkt, &key->material.ec.p)) {
            goto finish;
        }

        /* read KDF parameters. At the moment should be 0x03 0x01 halg ealg */
        uint8_t len = 0, halg = 0, walg = 0;
        if (!get_packet_body_byte(&pkt, &len) || (len != 3)) {
            goto finish;
        }
        if (!get_packet_body_byte(&pkt, &len) || (len != 1)) {
            goto finish;
        }
        if (!get_packet_body_byte(&pkt, &halg) || !get_packet_body_byte(&pkt, &walg)) {
            goto finish;
        }
        key->material.ec.kdf_hash_alg = (pgp_hash_alg_t) halg;
        key->material.ec.key_wrap_alg = (pgp_symm_alg_t) walg;
        break;
    }
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
        goto finish;
    }

    /* fill hashed data used for signatures */
    if (!(key->hashed_data = (uint8_t *) malloc(pkt.pos))) {
        RNP_LOG("allocation failed");
        res = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }
    memcpy(key->hashed_data, pkt.data, pkt.pos);
    key->hashed_len = pkt.pos;

    /* secret key fields if any */
    if (is_secret_key_pkt(key->tag)) {
        uint8_t usage = 0;
        if (!get_packet_body_byte(&pkt, &usage)) {
            RNP_LOG("failed to read key protection");
            goto finish;
        }
        key->sec_protection.s2k.usage = (pgp_s2k_usage_t) usage;
        key->sec_protection.cipher_mode = PGP_CIPHER_MODE_CFB;

        switch (key->sec_protection.s2k.usage) {
        case PGP_S2KU_NONE:
            break;
        case PGP_S2KU_ENCRYPTED:
        case PGP_S2KU_ENCRYPTED_AND_HASHED: {
            /* we have s2k */
            uint8_t salg = 0;
            if (!get_packet_body_byte(&pkt, &salg) ||
                !get_packet_body_s2k(&pkt, &key->sec_protection.s2k)) {
                RNP_LOG("failed to read key protection");
                goto finish;
            }
            key->sec_protection.symm_alg = (pgp_symm_alg_t) salg;
            break;
        }
        default:
            /* old-style: usage is symmetric algorithm identifier */
            key->sec_protection.symm_alg = (pgp_symm_alg_t) usage;
            key->sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED;
            key->sec_protection.s2k.specifier = PGP_S2KS_SIMPLE;
            key->sec_protection.s2k.hash_alg = PGP_HASH_MD5;
            break;
        }

        /* iv */
        if (key->sec_protection.s2k.usage) {
            size_t bl_size = pgp_block_size(key->sec_protection.symm_alg);
            if (!bl_size || !get_packet_body_buf(&pkt, key->sec_protection.iv, bl_size)) {
                RNP_LOG("failed to read iv");
                goto finish;
            }
        }

        /* encrypted/cleartext secret MPIs are left */
        size_t sec_len = pkt.len - pkt.pos;
        if (!(key->sec_data = (uint8_t *) calloc(1, sec_len))) {
            res = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }
        if (!get_packet_body_buf(&pkt, key->sec_data, sec_len)) {
            res = RNP_ERROR_BAD_STATE;
            goto finish;
        }
        key->sec_len = sec_len;
    }

    if (pkt.pos < pkt.len) {
        RNP_LOG("extra %d bytes in key packet", (int) (pkt.len - pkt.pos));
        goto finish;
    }
    res = RNP_SUCCESS;
finish:
    free_packet_body(&pkt);
    if (res) {
        free_key_pkt(key);
    }
    return res;
}

bool
copy_key_pkt(pgp_key_pkt_t *dst, const pgp_key_pkt_t *src, bool pubonly)
{
    if (!is_key_pkt(src->tag)) {
        return false;
    }

    memcpy(dst, src, sizeof(*src));
    if (src->hashed_data) {
        dst->hashed_data = (uint8_t *) malloc(src->hashed_len);
        if (!dst->hashed_data) {
            return false;
        }
        memcpy(dst->hashed_data, src->hashed_data, src->hashed_len);
    }

    if (!pubonly && src->sec_data) {
        dst->sec_data = (uint8_t *) malloc(src->sec_len);
        if (!dst->sec_data) {
            free(dst->hashed_data);
            return false;
        }
        memcpy(dst->sec_data, src->sec_data, src->sec_len);
    }

    if (!pubonly || is_public_key_pkt(src->tag)) {
        return true;
    }

    if (src->tag == PGP_PTAG_CT_SECRET_KEY) {
        dst->tag = PGP_PTAG_CT_PUBLIC_KEY;
    } else {
        dst->tag = PGP_PTAG_CT_PUBLIC_SUBKEY;
    }

    forget_secret_key_fields(&dst->material);
    dst->sec_data = NULL;
    dst->sec_len = 0;
    memset(&dst->sec_protection, 0, sizeof(dst->sec_protection));

    return true;
}

bool
key_pkt_equal(const pgp_key_pkt_t *key1, const pgp_key_pkt_t *key2, bool pubonly)
{
    /* check tag. We allow public/secret key comparision here */
    if (pubonly) {
        if (is_subkey_pkt(key1->tag) && !is_subkey_pkt(key2->tag)) {
            return false;
        }
        if (is_key_pkt(key1->tag) && !is_key_pkt(key2->tag)) {
            return false;
        }
    } else if (key1->tag != key2->tag) {
        return false;
    }

    /* check basic tags */
    if ((key1->version != key2->version) || (key1->alg != key2->alg) ||
        (key1->creation_time != key2->creation_time)) {
        return false;
    }

    /* check key material */
    return key_material_equal(&key1->material, &key2->material);
}

void
free_key_pkt(pgp_key_pkt_t *key)
{
    if (!key) {
        return;
    }
    free(key->hashed_data);
    if (key->sec_data) {
        pgp_forget(key->sec_data, key->sec_len);
        free(key->sec_data);
    }
    if (key->material.secret) {
        pgp_forget(&key->material, sizeof(key->material));
    }
    memset(key, 0, sizeof(*key));
}

bool
stream_write_userid(pgp_userid_pkt_t *userid, pgp_dest_t *dst)
{
    pgp_packet_body_t pktbody;
    bool              res;

    if ((userid->tag != PGP_PTAG_CT_USER_ID) && (userid->tag != PGP_PTAG_CT_USER_ATTR)) {
        RNP_LOG("wrong userid tag");
        return false;
    }

    if (!userid->uid || !userid->uid_len) {
        RNP_LOG("empty or null userid");
        return false;
    }

    if (!init_packet_body(&pktbody, userid->tag)) {
        RNP_LOG("allocation failed");
        return false;
    }

    res = add_packet_body(&pktbody, userid->uid, userid->uid_len);

    if (res) {
        stream_flush_packet_body(&pktbody, dst);
        res = dst->werr == RNP_SUCCESS;
    } else {
        free_packet_body(&pktbody);
    }

    return res;
}

rnp_result_t
stream_parse_userid(pgp_source_t *src, pgp_userid_pkt_t *userid)
{
    pgp_packet_body_t pkt;
    rnp_result_t      res;
    int               tag;

    /* check the tag */
    tag = stream_pkt_type(src);
    if ((tag != PGP_PTAG_CT_USER_ID) && (tag != PGP_PTAG_CT_USER_ATTR)) {
        RNP_LOG("wrong userid tag: %d", tag);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((res = stream_read_packet_body(src, &pkt))) {
        return res;
    }

    memset(userid, 0, sizeof(*userid));

    /* userid type, i.e. tag */
    userid->tag = pkt.tag;
    userid->uid = pkt.data; /* take ownership on data */
    userid->uid_len = pkt.len;
    return RNP_SUCCESS;
}

bool
copy_userid_pkt(pgp_userid_pkt_t *dst, const pgp_userid_pkt_t *src)
{
    *dst = *src;
    if (src->uid) {
        dst->uid = (uint8_t *) malloc(src->uid_len);
        if (!dst->uid) {
            return false;
        }
        memcpy(dst->uid, src->uid, src->uid_len);
    }

    return true;
}

bool
userid_pkt_equal(const pgp_userid_pkt_t *uid1, const pgp_userid_pkt_t *uid2)
{
    if ((uid1->tag != uid2->tag) || (uid1->uid_len != uid2->uid_len)) {
        return false;
    }

    return !memcmp(uid1->uid, uid2->uid, uid1->uid_len);
}

void
free_userid_pkt(pgp_userid_pkt_t *userid)
{
    free(userid->uid);
}
