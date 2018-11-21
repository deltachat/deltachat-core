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

#ifndef STREAM_PACKET_H_
#define STREAM_PACKET_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"

/* maximum size of the 'small' packet */
#define PGP_MAX_PKT_SIZE 0x100000

/* structure for convenient writing or parsing of non-stream packets */
typedef struct pgp_packet_body_t {
    int      tag;       /* packet tag */
    uint8_t *data;      /* packet body data */
    size_t   len;       /* length of the data */
    size_t   allocated; /* allocated bytes in data */

    /* fields below are filled only for parsed packet */
    uint8_t hdr[PGP_MAX_HEADER_SIZE]; /* packet header bytes */
    size_t  hdr_len;                  /* number of bytes in hdr */
    size_t  pos;                      /* current read position in packet data */
} pgp_packet_body_t;

uint16_t read_uint16(const uint8_t *buf);

uint32_t read_uint32(const uint8_t *buf);

void write_uint16(uint8_t *buf, uint16_t val);

/** @brief write new packet length
 *  @param buf pre-allocated buffer, must have 5 bytes
 *  @param len packet length
 *  @return number of bytes, saved in buf
 **/
size_t write_packet_len(uint8_t *buf, size_t len);

/** @brief get packet type from the packet header byte
 *  @param ptag first byte of the packet header
 *  @return packet type or -1 if ptag is wrong
 **/
int get_packet_type(uint8_t ptag);

/** @brief peek the packet type from the stream
 *  @param src source to peek from
 *  @return packet tag or -1 if read failed or packet header is malformed
 */
int stream_pkt_type(pgp_source_t *src);

/** @brief Peek length of the packet header. Returns -1 on error.
 *  @param src source to read length from
 *  @return number of bytes in packet header or -1 if there is a read error or packet length
 *          is ill-formed
 **/
ssize_t stream_pkt_hdr_len(pgp_source_t *src);

bool stream_intedeterminate_pkt_len(pgp_source_t *src);

bool stream_partial_pkt_len(pgp_source_t *src);

size_t get_partial_pkt_len(uint8_t blen);

ssize_t get_pkt_len(uint8_t *hdr);

/** @brief Read packet length for fixed-size (say, small) packet. Returns -1 on error.
 *  Will also read packet tag byte. We do not allow partial length here as well as large
 *  packets (so ignoring possible ssize_t overflow)
 *
 *  @param src source to read length from
 *  @return length of the packet or -1 if there is read error or packet length is ill-formed
 **/
ssize_t stream_read_pkt_len(pgp_source_t *src);

/** @brief Read partial packet chunk length.
 *
 *  @param src source to read length from
 *  @param last will be set to true if chunk is last (i.e. has non-partial length)
 *  @return length of the chunk or -1 if there is read error or packet length is ill-formed
 **/
ssize_t stream_read_partial_chunk_len(pgp_source_t *src, bool *last);

/** @brief initialize writing of packet body
 *  @param body preallocated structure
 *  @param tag tag of the packet
 *  @return true on success or false otherwise
 **/
bool init_packet_body(pgp_packet_body_t *body, int tag);

/** @brief append chunk of the data to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param data non-NULL pointer to the data
 *  @param len number of bytes to add
 *  @return true if data was copied successfully, or false otherwise
 **/
bool add_packet_body(pgp_packet_body_t *body, const void *data, size_t len);

/** @brief append single byte to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param byte byte to append
 *  @return true if byte was appended successfully, or false otherwise
 **/
bool add_packet_body_byte(pgp_packet_body_t *body, uint8_t byte);

/** @brief append big endian 16-bit value to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param val value to append
 *  @return true if value was appended successfully, or false otherwise
 **/
bool add_packet_body_uint16(pgp_packet_body_t *body, uint16_t val);

/** @brief append big endian 32-bit value to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param val value to append
 *  @return true if value was appended successfully, or false otherwise
 **/
bool add_packet_body_uint32(pgp_packet_body_t *body, uint32_t val);

/** @brief add pgp mpi (including header) to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param val pointer to structure with mpi data
 *  @return true if mpi was added successfully, or false otherwise
 **/
bool add_packet_body_mpi(pgp_packet_body_t *body, const pgp_mpi_t *val);

/**
 * @brief add pgp signature subpackets (including their length) to the packet body
 *
 * @param body pointer to the structure, initialized with init_packet_body
 * @param sig signature, containing subpackets
 * @param hashed whether write hashed or not hashed subpackets
 * @return true on success or false otherwise (if out of memory)
 */
bool add_packet_body_subpackets(pgp_packet_body_t *body, pgp_signature_t *sig, bool hashed);

/** @brief get next byte from the packet body
 *  @param body pointer to the structure. It must be filled via stream_read_packet_body
 *  @param val result will be stored here
 *  @return true on success or false otherwise (if end of the packet is reached)
 **/
bool get_packet_body_byte(pgp_packet_body_t *body, uint8_t *val);

/** @brief get next big-endian uint16 from the packet body
 *  @param body pointer to the structure. It must be filled via stream_read_packet_body
 *  @param val result will be stored here
 *  @return true on success or false otherwise (if end of the packet is reached)
 **/
bool get_packet_body_uint16(pgp_packet_body_t *body, uint16_t *val);

/** @brief get next big-endian uint32 from the packet body
 *  @param body pointer to the structure. It must be filled via stream_read_packet_body
 *  @param val result will be stored here
 *  @return true on success or false otherwise (if end of the packet is reached)
 **/
bool get_packet_body_uint32(pgp_packet_body_t *body, uint32_t *val);

/** @brief get some bytes from the packet body
 *  @param body pointer to the structure. It must be filled via stream_read_packet_body
 *  @param val packet body bytes will be stored here. Must be capable of storing len bytes.
 *  @param len number of bytes to read
 *  @return true on success or false otherwise (if end of the packet is reached)
 **/
bool get_packet_body_buf(pgp_packet_body_t *body, uint8_t *val, size_t len);

/** @brief get next mpi from the packet body
 *  @param body pointer to the structure. It must be filled via stream_read_packet_body
 *  @param val pointer to structure where result will be stored
 *  @return true on success or false otherwise (if end of the packet is reached
 *          or mpi is ill-formed)
 **/
bool get_packet_body_mpi(pgp_packet_body_t *body, pgp_mpi_t *val);

/** @brief deallocate data inside of packet body structure
 *  @param body initialized packet body
 *  @return void
 **/
void free_packet_body(pgp_packet_body_t *body);

/** @brief write packet header, length and body to the dest
 *  This will also deallocate internally used memory, so no free_packet_body call is needed
 *
 *  @param body populated with data packet body
 *  @param dst destination to write to
 *  @return void
 **/
void stream_flush_packet_body(pgp_packet_body_t *body, pgp_dest_t *dst);

/** @brief read 'short-length' packet body (including tag and length bytes) from the source
 *  @param src source to read from
 *  @param body pre-allocated body structure. Do not call init_packet_body on it!
 *  @return RNP_SUCCESS or error code if operation failed
 **/
rnp_result_t stream_read_packet_body(pgp_source_t *src, pgp_packet_body_t *body);

/** @brief put part of the packet body, i.e. without headers, to structure.
 *         Used for easier data parsing, using get_packet_body_* functions. Mem is not copied.
 *  @param mem buffer with packet body part
 *  @param len number of available bytes in mem
 *  @param body pre-allocated body structure
 */
void packet_body_part_from_mem(pgp_packet_body_t *body, const void *mem, size_t len);

/* Packet handling functions */

rnp_result_t stream_skip_packet(pgp_source_t *src);

/* Symmetric-key encrypted session key */

bool stream_write_sk_sesskey(pgp_sk_sesskey_t *skey, pgp_dest_t *dst);

rnp_result_t stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey);

/* Public-key encrypted session key */

bool stream_write_pk_sesskey(pgp_pk_sesskey_t *pkey, pgp_dest_t *dst);

rnp_result_t stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey);

/* One-pass signature */

bool stream_write_one_pass(pgp_one_pass_sig_t *onepass, pgp_dest_t *dst);

rnp_result_t stream_parse_one_pass(pgp_source_t *src, pgp_one_pass_sig_t *onepass);

/* Signature */

bool stream_write_signature(pgp_signature_t *sig, pgp_dest_t *dst);

bool signature_parse_subpacket(pgp_sig_subpkt_t *subpkt);

rnp_result_t stream_parse_signature_body(pgp_packet_body_t *pkt, pgp_signature_t *sig);

rnp_result_t stream_parse_signature(pgp_source_t *src, pgp_signature_t *sig);

bool copy_signature_packet(pgp_signature_t *dst, const pgp_signature_t *src);

bool signature_pkt_equal(const pgp_signature_t *sig1, const pgp_signature_t *sig2);

void free_signature_subpkt(pgp_sig_subpkt_t *subpkt);

void free_signature(pgp_signature_t *sig);

/* Public/Private key or Subkey */

bool is_key_pkt(int tag);

bool is_subkey_pkt(int tag);

bool is_primary_key_pkt(int tag);

bool is_public_key_pkt(int tag);

bool is_secret_key_pkt(int tag);

bool is_rsa_key_alg(pgp_pubkey_alg_t alg);

bool key_fill_hashed_data(pgp_key_pkt_t *key);

bool stream_write_key(pgp_key_pkt_t *key, pgp_dest_t *dst);

rnp_result_t stream_parse_key(pgp_source_t *src, pgp_key_pkt_t *key);

bool copy_key_pkt(pgp_key_pkt_t *dst, const pgp_key_pkt_t *src, bool pubonly);

bool key_pkt_equal(const pgp_key_pkt_t *key1, const pgp_key_pkt_t *key2, bool pubonly);

void free_key_pkt(pgp_key_pkt_t *key);

/* User ID packet */

bool stream_write_userid(pgp_userid_pkt_t *userid, pgp_dest_t *dst);

rnp_result_t stream_parse_userid(pgp_source_t *src, pgp_userid_pkt_t *userid);

bool copy_userid_pkt(pgp_userid_pkt_t *dst, const pgp_userid_pkt_t *src);

bool userid_pkt_equal(const pgp_userid_pkt_t *uid1, const pgp_userid_pkt_t *uid2);

void free_userid_pkt(pgp_userid_pkt_t *userid);

#endif
