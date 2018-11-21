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

/* Enumerates types of handles */
typedef enum {
    /* Operates on standard input/output */
    REPGP_HANDLE_FILE,

    /* Operates on memory buffer */
    REPGP_HANDLE_BUFFER

} repgp_handle_type_t;

/* Data handle */
typedef struct repgp_handle_t {
    repgp_handle_type_t type;

    union {
        /* Used by REPGP_HANDLE_FILE */
        char *filepath;

        /* Used by REPGP_HANDLE_BUFFER */
        struct {
            unsigned char *data;     // buffer which stores data
            size_t         data_len; // length of data in the `data buffer' (in bytes)
            size_t         size;     // size of the buffer (in bytes)
        } buffer;
    };
} repgp_handle_t;

/* Defines input/output object */
typedef struct repgp_io_t {
    struct repgp_handle_t *in;
    struct repgp_handle_t *out;
} repgp_io_t;
