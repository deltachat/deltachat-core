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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "stream-def.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "crypto/hash.h"
#include "types.h"
#include "utils.h"

#define ARMORED_BLOCK_SIZE (4096)

typedef struct pgp_source_armored_param_t {
    pgp_source_t *    readsrc;         /* source to read from */
    pgp_armored_msg_t type;            /* type of the message */
    char *            armorhdr;        /* armor header */
    char *            version;         /* Version: header if any */
    char *            comment;         /* Comment: header if any */
    char *            hash;            /* Hash: header if any */
    char *            charset;         /* Charset: header if any */
    uint8_t  rest[ARMORED_BLOCK_SIZE]; /* unread decoded bytes, makes implementation easier */
    unsigned restlen;                  /* number of bytes in rest */
    unsigned restpos;    /* index of first unread byte in rest, restpos <= restlen */
    uint8_t  brest[3];   /* decoded 6-bit tail bytes */
    unsigned brestlen;   /* number of bytes in brest */
    bool     eofb64;     /* end of base64 stream reached */
    uint8_t  readcrc[3]; /* crc-24 from the armored data */
    pgp_hash_t crc_ctx;  /* CTX used to calculate CRC */
} pgp_source_armored_param_t;

typedef struct pgp_dest_armored_param_t {
    pgp_dest_t *      writedst;
    pgp_armored_msg_t type;    /* type of the message */
    bool              usecrlf; /* use CR LF instead of LF as eol */
    unsigned          lout;    /* chars written in current line */
    unsigned          llen;    /* length of the base64 line, defaults to 76 as per RFC */
    uint8_t           tail[2]; /* bytes which didn't fit into 3-byte boundary */
    unsigned          tailc;   /* number of bytes in tail */
    pgp_hash_t        crc_ctx; /* CTX used to calculate CRC */
} pgp_dest_armored_param_t;

/*
   Table for base64 lookups:
   0xff - wrong character,
   0xfe - '='
   0xfd - eol/whitespace,
   0..0x3f - represented 6-bit number
*/
static const uint8_t B64DEC[256] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0xfd, 0xff, 0xff, 0xfd, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff,
  0xff, 0xff, 0x3f, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
  0xff, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
  0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff};

static int
armor_read_padding(pgp_source_t *src)
{
    char                        st[64];
    ssize_t                     stlen;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if ((stlen = src_peek_line(param->readsrc, st, 12)) < 0) {
        return -1;
    }

    if ((stlen == 1) || (stlen == 2)) {
        if ((st[0] != CH_EQ) || ((stlen == 2) && (st[1] != CH_EQ))) {
            return -1;
        }

        src_skip(param->readsrc, stlen);
        src_skip_eol(param->readsrc);
        return stlen;
    } else if (stlen == 5) {
        return 0;
    }

    return -1;
}

static bool
armor_read_crc(pgp_source_t *src)
{
    uint8_t                     dec[4];
    char                        crc[8];
    ssize_t                     clen;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if ((clen = src_peek_line(param->readsrc, crc, sizeof(crc))) < 0) {
        return false;
    }

    if ((clen == 5) && (crc[0] == CH_EQ)) {
        for (int i = 0; i < 4; i++) {
            if ((dec[i] = B64DEC[(int) crc[i + 1]]) >= 64) {
                return false;
            }
        }

        param->readcrc[0] = (dec[0] << 2) | ((dec[1] >> 4) & 0x0F);
        param->readcrc[1] = (dec[1] << 4) | ((dec[2] >> 2) & 0x0F);
        param->readcrc[2] = (dec[2] << 6) | dec[3];

        src_skip(param->readsrc, 5);
        src_skip_eol(param->readsrc);
        return true;
    }

    return false;
}

static bool
armor_read_trailer(pgp_source_t *src)
{
    char                        st[64];
    char                        str[64];
    size_t                      stlen;
    ssize_t                     read;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    stlen = strlen(param->armorhdr);
    strncpy(st, ST_ARMOR_END, 8); /* 8 here is mandatory */
    strncpy(st + 8, param->armorhdr + 5, stlen - 5);
    strncpy(st + stlen + 3, ST_DASHES, 5);
    stlen += 8;
    read = src_peek(param->readsrc, str, stlen);
    if ((read < (ssize_t) stlen) || strncmp(str, st, stlen)) {
        return false;
    }
    src_skip(param->readsrc, stlen);
    return true;
}

static ssize_t
armored_src_read(pgp_source_t *src, void *buf, size_t len)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;
    uint8_t  b64buf[ARMORED_BLOCK_SIZE];     /* input base64 data with spaces and so on */
    uint8_t  decbuf[ARMORED_BLOCK_SIZE + 4]; /* decoded 6-bit values */
    uint8_t *bufptr = (uint8_t *) buf;       /* for better readability below */
    uint8_t *bptr, *bend;                    /* pointer to input data in b64buf */
    uint8_t *dptr, *dend, *pend; /* pointers to decoded data in decbuf: working pointer, last
                                    available byte, last byte to process */
    uint8_t  bval;
    uint32_t b24;
    ssize_t  read;
    ssize_t  left = len;
    int      eqcount = 0; /* number of '=' at the end of base64 stream */

    if (!param) {
        return -1;
    }

    /* checking whether there are some decoded bytes */
    if (param->restpos < param->restlen) {
        if (param->restlen - param->restpos >= len) {
            memcpy(bufptr, &param->rest[param->restpos], len);
            param->restpos += len;
            pgp_hash_add(&param->crc_ctx, bufptr, len);
            return len;
        } else {
            left = len - (param->restlen - param->restpos);
            memcpy(bufptr, &param->rest[param->restpos], len - left);
            param->restpos = param->restlen = 0;
            bufptr += len - left;
        }
    }

    if (param->eofb64) {
        return len - left;
    }

    memcpy(decbuf, param->brest, param->brestlen);
    dend = decbuf + param->brestlen;

    do {
        read = src_peek(param->readsrc, b64buf, sizeof(b64buf));
        if (read < 0) {
            return read;
        }

        dptr = dend;
        bptr = b64buf;
        bend = b64buf + read;
        /* checking input data, stripping away whitespaces, checking for end of the b64 data */
        while (bptr < bend) {
            if ((bval = B64DEC[*(bptr++)]) < 64) {
                *(dptr++) = bval;
            } else if (bval == 0xfe) {
                /* '=' means the base64 padding or the beginning of checksum */
                param->eofb64 = true;
                break;
            } else if (bval == 0xff) {
                RNP_LOG("wrong base64 character %c", (char) *(bptr - 1));
                return -1;
            }
        }

        dend = dptr;
        dptr = decbuf;
        /* Processing full 4s which will go directly to the buf.
           After this left < 3 or decbuf has < 4 bytes */
        if ((dend - dptr) / 4 * 3 < left) {
            pend = decbuf + (dend - dptr) / 4 * 4;
            left -= (dend - dptr) / 4 * 3;
        } else {
            pend = decbuf + (left / 3) * 4;
            left -= left / 3 * 3;
        }

        /* this one would the most performance-consuming part for large chunks */
        while (dptr < pend) {
            b24 = *dptr++ << 18;
            b24 |= *dptr++ << 12;
            b24 |= *dptr++ << 6;
            b24 |= *dptr++;
            *bufptr++ = b24 >> 16;
            *bufptr++ = b24 >> 8;
            *bufptr++ = b24 & 0xff;
        }

        /* moving rest to the beginning of decbuf */
        memmove(decbuf, dptr, dend - dptr);
        dend = decbuf + (dend - dptr);

        if (param->eofb64) {
            /* '=' reached, bptr points on it */
            src_skip(param->readsrc, bptr - b64buf - 1);

            /* reading b64 padding if any */
            if ((eqcount = armor_read_padding(src)) < 0) {
                RNP_LOG("wrong padding");
                return -1;
            }

            /* reading crc */
            if (!armor_read_crc(src)) {
                RNP_LOG("wrong crc line");
                return -1;
            }
            /* reading armor trailing line */
            if (!armor_read_trailer(src)) {
                RNP_LOG("wrong armor trailer");
                return -1;
            }

            break;
        } else {
            /* all input is base64 data or eol/spaces, so skipping it */
            src_skip(param->readsrc, read);
        }
    } while (left >= 3);

    /* process bytes left in decbuf */

    dptr = decbuf;
    pend = decbuf + (dend - decbuf) / 4 * 4;
    bptr = param->rest;
    while (dptr < pend) {
        b24 = *dptr++ << 18;
        b24 |= *dptr++ << 12;
        b24 |= *dptr++ << 6;
        b24 |= *dptr++;
        *bptr++ = b24 >> 16;
        *bptr++ = b24 >> 8;
        *bptr++ = b24 & 0xff;
    }

    pgp_hash_add(&param->crc_ctx, buf, bufptr - (uint8_t *) buf);

    if (param->eofb64) {
        if ((dend - dptr + eqcount) % 4 != 0) {
            RNP_LOG("wrong b64 padding");
            return -1;
        }

        if (eqcount == 1) {
            b24 = (*dptr << 10) | (*(dptr + 1) << 4) | (*(dptr + 2) >> 2);
            *bptr++ = b24 >> 8;
            *bptr++ = b24 & 0xff;
        } else if (eqcount == 2) {
            *bptr++ = (*dptr << 2) | (*(dptr + 1) >> 4);
        }

        uint8_t crc_fin[5];
        /* Calculate CRC after reading whole input stream */
        pgp_hash_add(&param->crc_ctx, param->rest, bptr - param->rest);
        if (!pgp_hash_finish(&param->crc_ctx, crc_fin)) {
            RNP_LOG("Can't finalize RNP ctx");
            return -1;
        }

        if (memcmp(param->readcrc, crc_fin, 3)) {
            RNP_LOG("CRC mismatch");
            return -1;
        }
    } else {
        /* few bytes which do not fit to 4 boundary */
        for (int i = 0; i < dend - dptr; i++) {
            param->brest[i] = *(dptr + i);
        }
        param->brestlen = dend - dptr;
    }

    param->restlen = bptr - param->rest;

    /* check whether we have some bytes to add */
    if ((left > 0) && (param->restlen > 0)) {
        read = left > param->restlen ? param->restlen : left;
        memcpy(bufptr, param->rest, read);
        if (!param->eofb64) {
            pgp_hash_add(&param->crc_ctx, bufptr, read);
        }
        left -= read;
        param->restpos += read;
    }

    return len - left;
}

static void
armored_src_close(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    if (param) {
        (void) pgp_hash_finish(&param->crc_ctx, NULL);
        free(param->armorhdr);
        free(param->version);
        free(param->comment);
        free(param->hash);
        free(param->charset);
        free(param);
        param = NULL;
    }
}

/** @brief finds armor header position in the buffer, returning beginning of header or NULL.
 *  hdrlen will contain the length of the header
 **/
static const char *
find_armor_header(const char *buf, size_t len, size_t *hdrlen)
{
    int st = -1;

    for (unsigned i = 0; i < len - 10; i++) {
        if ((buf[i] == CH_DASH) && !strncmp(&buf[i + 1], ST_DASHES, 4)) {
            st = i;
            break;
        }
    }

    if (st < 0) {
        return NULL;
    }

    for (unsigned i = st + 5; i <= len - 5; i++) {
        if ((buf[i] == CH_DASH) && !strncmp(&buf[i + 1], ST_DASHES, 4)) {
            *hdrlen = i + 5 - st;
            return &buf[st];
        }
    }

    return NULL;
}

static pgp_armored_msg_t
armor_str_to_data_type(const char *str, size_t len)
{
    if (!str) {
        return PGP_ARMORED_UNKNOWN;
    }
    if (!strncmp(str, "BEGIN PGP MESSAGE", len)) {
        return PGP_ARMORED_MESSAGE;
    }
    if (!strncmp(str, "BEGIN PGP PUBLIC KEY BLOCK", len) ||
        !strncmp(str, "BEGIN PGP PUBLIC KEY", len)) {
        return PGP_ARMORED_PUBLIC_KEY;
    }
    if (!strncmp(str, "BEGIN PGP SECRET KEY BLOCK", len) ||
        !strncmp(str, "BEGIN PGP SECRET KEY", len) ||
        !strncmp(str, "BEGIN PGP PRIVATE KEY BLOCK", len) ||
        !strncmp(str, "BEGIN PGP PRIVATE KEY", len)) {
        return PGP_ARMORED_SECRET_KEY;
    }
    if (!strncmp(str, "BEGIN PGP SIGNATURE", len)) {
        return PGP_ARMORED_SIGNATURE;
    }
    if (!strncmp(str, "BEGIN PGP SIGNED MESSAGE", len)) {
        return PGP_ARMORED_CLEARTEXT;
    }
    return PGP_ARMORED_UNKNOWN;
}

pgp_armored_msg_t
rnp_armor_guess_type(pgp_source_t *src)
{
    uint8_t ptag;
    ssize_t read;
    int     ptype;

    read = src_peek(src, &ptag, 1);
    if (read < 1) {
        return PGP_ARMORED_UNKNOWN;
    }

    ptype = get_packet_type(ptag);

    switch (ptype) {
    case PGP_PTAG_CT_PK_SESSION_KEY:
    case PGP_PTAG_CT_SK_SESSION_KEY:
    case PGP_PTAG_CT_1_PASS_SIG:
    case PGP_PTAG_CT_SE_DATA:
    case PGP_PTAG_CT_SE_IP_DATA:
    case PGP_PTAG_CT_COMPRESSED:
    case PGP_PTAG_CT_LITDATA:
        return PGP_ARMORED_MESSAGE;
    case PGP_PTAG_CT_PUBLIC_KEY:
        return PGP_ARMORED_PUBLIC_KEY;
    case PGP_PTAG_CT_SECRET_KEY:
        return PGP_ARMORED_SECRET_KEY;
    case PGP_PTAG_CT_SIGNATURE:
        return PGP_ARMORED_SIGNATURE;
    default:
        return PGP_ARMORED_UNKNOWN;
    }
}

static bool
armor_parse_header(pgp_source_t *src)
{
    char                        hdr[128];
    const char *                armhdr;
    size_t                      armhdrlen;
    ssize_t                     read;
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;

    read = src_peek(param->readsrc, hdr, sizeof(hdr));
    if (read < 20) {
        return false;
    }

    if (!(armhdr = find_armor_header(hdr, read, &armhdrlen))) {
        RNP_LOG("no armor header");
        return false;
    }

    /* if there are non-whitespaces before the armor header then issue warning */
    for (char *ch = hdr; ch < armhdr; ch++) {
        if (B64DEC[(int) *ch] != 0xfd) {
            RNP_LOG("extra data before the header line");
            break;
        }
    }

    param->type = armor_str_to_data_type(armhdr + 5, armhdrlen - 10);
    if (param->type == PGP_ARMORED_UNKNOWN) {
        RNP_LOG("unknown armor header");
        return false;
    }

    if ((param->armorhdr = (char *) malloc(armhdrlen - 9)) == NULL) {
        RNP_LOG("allocation failed");
        return false;
    }

    memcpy(param->armorhdr, armhdr + 5, armhdrlen - 10);
    param->armorhdr[armhdrlen - 10] = '\0';
    src_skip(param->readsrc, armhdr - hdr + armhdrlen);
    return true;
}

static bool
armor_parse_headers(pgp_source_t *src)
{
    pgp_source_armored_param_t *param = (pgp_source_armored_param_t *) src->param;
    char                        header[1024];
    ssize_t                     hdrlen;
    char *                      hdrval;

    do {
        if ((hdrlen = src_peek_line(param->readsrc, header, sizeof(header))) < 0) {
            RNP_LOG("failed to peek line");
            return false;
        }

        if (hdrlen > 0) {
            if ((hdrval = (char *) malloc(hdrlen + 1)) == NULL) {
                RNP_LOG("malloc failed");
                return false;
            }

            if (strncmp(header, ST_HEADER_VERSION, 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 8);
                free(param->version);
                param->version = hdrval;
            } else if (strncmp(header, ST_HEADER_COMMENT, 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 8);
                free(param->comment);
                param->comment = hdrval;
            } else if (strncmp(header, ST_HEADER_HASH, 6) == 0) {
                memcpy(hdrval, header + 6, hdrlen - 5);
                free(param->hash);
                param->hash = hdrval;
            } else if (strncmp(header, ST_HEADER_CHARSET, 9) == 0) {
                memcpy(hdrval, header + 9, hdrlen - 8);
                free(param->charset);
                param->charset = hdrval;
            } else {
                RNP_LOG("unknown header '%s'", header);
                free(hdrval);
            }

            src_skip(param->readsrc, hdrlen);
        }

        if (!src_skip_eol(param->readsrc)) {
            return false;
        }
    } while (hdrlen > 0);

    return true;
}

rnp_result_t
init_armored_src(pgp_source_t *src, pgp_source_t *readsrc)
{
    rnp_result_t                errcode = RNP_ERROR_GENERIC;
    pgp_source_armored_param_t *param;

    if (!init_src_common(src, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    param = (pgp_source_armored_param_t *) src->param;
    param->readsrc = readsrc;

    if (!pgp_hash_create(&param->crc_ctx, PGP_HASH_CRC24)) {
        RNP_LOG("Internal error");
        return RNP_ERROR_GENERIC;
    }

    src->read = armored_src_read;
    src->close = armored_src_close;
    src->type = PGP_STREAM_ARMORED;

    /* parsing armored header */
    if (!armor_parse_header(src)) {
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* eol */
    if (!src_skip_eol(param->readsrc)) {
        RNP_LOG("no eol after the armor header");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }
    /* parsing headers */
    if (!armor_parse_headers(src)) {
        RNP_LOG("failed to parse headers");
        errcode = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    /* now we are good to go with base64-encoded data */
    errcode = RNP_SUCCESS;

finish:
    if (errcode != RNP_SUCCESS) {
        src_close(src);
    }
    return errcode;
}

/** @brief Copy armor header of tail to the buffer. Buffer should be at least ~40 chars. */
static bool
armor_message_header(pgp_armored_msg_t type, bool finish, char *buf)
{
    const char *str;
    str = finish ? ST_ARMOR_END : ST_ARMOR_BEGIN;
    strncpy(buf, str, strlen(str));
    buf += strlen(str);
    switch (type) {
    case PGP_ARMORED_MESSAGE:
        str = "MESSAGE";
        break;
    case PGP_ARMORED_PUBLIC_KEY:
        str = "PUBLIC KEY BLOCK";
        break;
    case PGP_ARMORED_SECRET_KEY:
        str = "PRIVATE KEY BLOCK";
        break;
    case PGP_ARMORED_SIGNATURE:
        str = "SIGNATURE";
        break;
    case PGP_ARMORED_CLEARTEXT:
        str = "SIGNED MESSAGE";
        break;
    default:
        return false;
    }

    strncpy(buf, str, strlen(str));
    buf += strlen(str);
    strncpy(buf, ST_DASHES, 5);
    buf[5] = '\0';
    return true;
}

static void
armor_write_eol(pgp_dest_armored_param_t *param)
{
    if (param->usecrlf) {
        dst_write(param->writedst, ST_CRLF, 2);
    } else {
        dst_write(param->writedst, ST_LF, 1);
    }
}

/* Base 64 encoded table, quadruplicated to save cycles on use & 0x3f operation  */
static const uint8_t B64ENC[256] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
  'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
  '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F',
  'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
  'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'};

static void
armored_encode3(uint8_t *out, uint8_t *in)
{
    out[0] = B64ENC[in[0] >> 2];
    out[1] = B64ENC[((in[0] << 4) | (in[1] >> 4)) & 0xff];
    out[2] = B64ENC[((in[1] << 2) | (in[2] >> 6)) & 0xff];
    out[3] = B64ENC[in[2] & 0xff];
}

static rnp_result_t
armored_dst_write(pgp_dest_t *dst, const void *buf, size_t len)
{
    uint8_t                   encbuf[PGP_INPUT_CACHE_SIZE / 2];
    uint8_t *                 encptr = encbuf;
    uint8_t *                 enclast;
    uint8_t                   dec3[3];
    uint8_t *                 bufptr = (uint8_t *) buf;
    uint8_t *                 bufend = bufptr + len;
    uint8_t *                 inlend;
    uint32_t                  t;
    unsigned                  inllen;
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    if (!param) {
        RNP_LOG("wrong param");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* update crc */
    pgp_hash_add(&param->crc_ctx, buf, len);

    /* processing tail if any */
    if (len + param->tailc < 3) {
        memcpy(&param->tail[param->tailc], buf, len);
        param->tailc += len;
        return RNP_SUCCESS;
    } else if (param->tailc > 0) {
        memcpy(dec3, param->tail, param->tailc);
        memcpy(&dec3[param->tailc], bufptr, 3 - param->tailc);
        bufptr += 3 - param->tailc;
        param->tailc = 0;
        armored_encode3(encptr, dec3);
        encptr += 4;
        param->lout += 4;
        if (param->lout == param->llen) {
            if (param->usecrlf) {
                *encptr++ = CH_CR;
            }
            *encptr++ = CH_LF;
            param->lout = 0;
        }
    }

    /* number of input bytes to form a whole line of output, param->llen / 4 * 3 */
    inllen = (param->llen >> 2) + (param->llen >> 1);
    /* pointer to the last full line space in encbuf */
    enclast = encbuf + sizeof(encbuf) - param->llen - 2;

    /* processing line chunks, this is the main performance-hitting cycle */
    while (bufptr + 3 <= bufend) {
        /* checking whether we have enough space in encbuf */
        if (encptr > enclast) {
            dst_write(param->writedst, encbuf, encptr - encbuf);
            encptr = encbuf;
        }
        /* setup length of the input to process in this iteration */
        inlend =
          param->lout == 0 ? bufptr + inllen : bufptr + ((param->llen - param->lout) >> 2) * 3;
        if (inlend > bufend) {
            /* no enough input for the full line */
            inlend = bufptr + (bufend - bufptr) / 3 * 3;
            param->lout += (inlend - bufptr) / 3 * 4;
        } else {
            /* we have full line of input */
            param->lout = 0;
        }

        /* processing one line */
        while (bufptr < inlend) {
            t = (bufptr[0] << 16) | (bufptr[1] << 8) | (bufptr[2]);
            bufptr += 3;
            *encptr++ = B64ENC[(t >> 18) & 0xff];
            *encptr++ = B64ENC[(t >> 12) & 0xff];
            *encptr++ = B64ENC[(t >> 6) & 0xff];
            *encptr++ = B64ENC[t & 0xff];
        }

        /* adding line ending */
        if (param->lout == 0) {
            if (param->usecrlf) {
                *encptr++ = CH_CR;
            }
            *encptr++ = CH_LF;
        }
    }

    dst_write(param->writedst, encbuf, encptr - encbuf);

    /* saving tail */
    param->tailc = bufend - bufptr;
    memcpy(param->tail, bufptr, param->tailc);

    return RNP_SUCCESS;
}

static rnp_result_t
armored_dst_finish(pgp_dest_t *dst)
{
    uint8_t                   buf[64];
    uint8_t                   crcbuf[3];
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    /* writing tail */
    if (param->tailc == 1) {
        buf[0] = B64ENC[param->tail[0] >> 2];
        buf[1] = B64ENC[(param->tail[0] << 4) & 0xff];
        buf[2] = CH_EQ;
        buf[3] = CH_EQ;
        dst_write(param->writedst, buf, 4);
    } else if (param->tailc == 2) {
        buf[0] = B64ENC[(param->tail[0] >> 2)];
        buf[1] = B64ENC[((param->tail[0] << 4) | (param->tail[1] >> 4)) & 0xff];
        buf[2] = B64ENC[(param->tail[1] << 2) & 0xff];
        buf[3] = CH_EQ;
        dst_write(param->writedst, buf, 4);
    }

    /* writing EOL if needed */
    if ((param->tailc > 0) || (param->lout > 0)) {
        armor_write_eol(param);
    }

    /* writing CRC and EOL */
    buf[0] = CH_EQ;

    // At this point crc_ctx is initialized, so call can't fail
    (void) pgp_hash_finish(&param->crc_ctx, crcbuf);
    armored_encode3(&buf[1], crcbuf);
    dst_write(param->writedst, buf, 5);
    armor_write_eol(param);

    /* writing armor header */
    armor_message_header(param->type, true, (char *) buf);
    dst_write(param->writedst, buf, strlen((char *) buf));
    armor_write_eol(param);

    return param->writedst->werr;
}

static void
armored_dst_close(pgp_dest_t *dst, bool discard)
{
    pgp_dest_armored_param_t *param = (pgp_dest_armored_param_t *) dst->param;

    if (!param) {
        return;
    }

    /* dst_close may be called without dst_finish on error */
    (void) pgp_hash_finish(&param->crc_ctx, NULL);
    free(param);
    dst->param = NULL;
}

rnp_result_t
init_armored_dst(pgp_dest_t *dst, pgp_dest_t *writedst, pgp_armored_msg_t msgtype)
{
    char                      hdr[64];
    pgp_dest_armored_param_t *param;
    rnp_result_t              ret = RNP_SUCCESS;

    if (!init_dst_common(dst, sizeof(*param))) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    param = (pgp_dest_armored_param_t *) dst->param;

    dst->write = armored_dst_write;
    dst->finish = armored_dst_finish;
    dst->close = armored_dst_close;
    dst->type = PGP_STREAM_ARMORED;
    dst->writeb = 0;
    dst->clen = 0;
    dst->param = param;

    if (!pgp_hash_create(&param->crc_ctx, PGP_HASH_CRC24)) {
        RNP_LOG("Internal error");
        return RNP_ERROR_GENERIC;
    }

    param->writedst = writedst;
    param->type = msgtype;
    param->usecrlf = true;
    param->llen = 76; /* must be multiple of 4 */

    if (!armor_message_header(param->type, false, hdr)) {
        RNP_LOG("unknown data type");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto finish;
    }

    /* armor header */
    dst_write(writedst, hdr, strlen(hdr));
    armor_write_eol(param);
    /* version string */
    strncpy(hdr, "Version: " PACKAGE_STRING, sizeof(hdr));
    hdr[sizeof(hdr) - 1] = '\0';
    dst_write(writedst, hdr, strlen(hdr));
    armor_write_eol(param);
    /* empty line */
    armor_write_eol(param);

finish:
    if (ret != RNP_SUCCESS) {
        armored_dst_close(dst, true);
    }

    return ret;
}

bool
is_armored_source(pgp_source_t *src)
{
    uint8_t buf[128];
    ssize_t read;

    read = src_peek(src, buf, sizeof(buf));
    if (read < (ssize_t) strlen(ST_ARMOR_BEGIN) + 1) {
        return false;
    }

    buf[read - 1] = 0;
    return !!strstr((char *) buf, ST_ARMOR_BEGIN);
}

bool
is_cleartext_source(pgp_source_t *src)
{
    uint8_t buf[128];
    ssize_t read;

    read = src_peek(src, buf, sizeof(buf));
    if (read < (ssize_t) strlen(ST_CLEAR_BEGIN)) {
        return false;
    }

    buf[read - 1] = 0;
    return !!strstr((char *) buf, ST_CLEAR_BEGIN);
}

rnp_result_t
rnp_dearmor_source(pgp_source_t *src, pgp_dest_t *dst)
{
    rnp_result_t res = RNP_ERROR_BAD_FORMAT;
    pgp_source_t armorsrc = {0};
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;

    read = src_peek(src, readbuf, strlen(ST_CLEAR_BEGIN) + 1);
    if (read < (ssize_t) strlen(ST_ARMOR_BEGIN)) {
        RNP_LOG("can't read enough data from source");
        return RNP_ERROR_READ;
    }

    /* Trying armored or cleartext data */
    readbuf[read - 1] = 0;
    if (strstr((char *) readbuf, ST_ARMOR_BEGIN)) {
        /* checking whether it is cleartext */
        if (strstr((char *) readbuf, ST_CLEAR_BEGIN)) {
            RNP_LOG("source is cleartext, not armored");
            return RNP_ERROR_BAD_FORMAT;
        }

        /* initializing armored message */
        res = init_armored_src(&armorsrc, src);

        if (res != RNP_SUCCESS) {
            goto finish;
        }
    } else {
        RNP_LOG("source is not armored data");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Reading data from armored source and writing it to the output */
    while (!armorsrc.eof) {
        read = src_read(&armorsrc, readbuf, PGP_INPUT_CACHE_SIZE);
        if (read < 0) {
            res = RNP_ERROR_GENERIC;
            break;
        } else if (read > 0) {
            dst_write(dst, readbuf, read);
            if (dst->werr != RNP_SUCCESS) {
                RNP_LOG("failed to output data");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    src_close(&armorsrc);
    return res;
}

rnp_result_t
rnp_armor_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armored_msg_t msgtype)
{
    pgp_dest_t   armordst = {0};
    rnp_result_t res = RNP_ERROR_GENERIC;
    uint8_t      readbuf[PGP_INPUT_CACHE_SIZE];
    ssize_t      read;

    res = init_armored_dst(&armordst, dst, msgtype);
    if (res != RNP_SUCCESS) {
        goto finish;
    }

    while (!src->eof) {
        read = src_read(src, readbuf, PGP_INPUT_CACHE_SIZE);
        if (read < 0) {
            res = RNP_ERROR_READ;
            break;
        } else if (read > 0) {
            dst_write(&armordst, readbuf, read);
            if (armordst.werr != RNP_SUCCESS) {
                RNP_LOG("failed to output data");
                res = RNP_ERROR_WRITE;
                break;
            }
        }
    }

finish:
    dst_close(&armordst, res != RNP_SUCCESS);
    return res;
}
