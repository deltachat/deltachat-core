/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * This code is originally derived from software contributed by
 * Ribose Inc (https://www.ribose.com).
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

#ifndef REPGP_H_
#define REPGP_H_

/** \file
 * Parser for OpenPGP packets - headers.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <rnp/rnp_def.h>
#include "repgp_def.h"

typedef struct repgp_handle_t repgp_handle_t;
typedef struct repgp_io_t     repgp_io_t;

/** Used to specify whether subpackets should be returned raw, parsed
 * or ignored.  */
typedef enum {
    REPGP_PARSE_RAW,    /* Callback Raw */
    REPGP_PARSE_PARSED, /* Callback Parsed */
    REPGP_PARSE_IGNORE  /* Don't callback */
} repgp_parse_type_t;

/*
 * @brief   Creates handle to be used with file input
 *
 * @param   filename NULL-terminated string with full path to the file
 *
 * @return  Initialized handle on success or NULL
 *          if input parameters are invalid.
 */
repgp_handle_t *create_filepath_handle(const char *filename);

/*
 * @brief   Creates handle to data read from stdin.
 *          Currently internally this function reads
 *          all the data from standard input and coppies
 *          it to internal buffer.
 *
 * @return  Initialized handle on success or NULL
 *          if input parameters are invalid.
 */
repgp_handle_t *create_stdin_handle(void);

/*
 * @brief   Creates handle to data kept in the buffer
 *          memory. Function allocates buffer internally
 *
 * @param   buffer_size size of the buffer to allocate
 *
 * @return  Initialized handle on success or NULL
 *          if input parameters are invalid.
 */
repgp_handle_t *create_buffer_handle(const size_t buffer_size);

/*
 * @brief   Creates handle to data kept in the buffer
 *          memory. Function internally allocates buffer
 *          internally and copies data provided by the caller
 *          to the internal buffer.
 *
 * @param   data data provided by the caller
 * @param   data_len length of the data
 *
 * @return  Initialized handle on success or NULL
 *          if input parameters are invalid.
 */
repgp_handle_t *create_data_handle(const uint8_t *data, size_t data_len);

/*
 * @brief   Destroys previously allocated buffer. Can be safely
 *          called with RNP_HANDLER_NULL (in which case function
 *          simply returns).
 */
void repgp_destroy_handle(repgp_handle_t *handle);

/*
 * @brief   Copies data from internal buffer into buffer
 *          provided by the caller
 *
 * @param   out [out] destination buffer
 * @param   out_size [in/out]
 *            - on input size of the out buffer
 *            - on output amount of data coppied into `out' buffer
 *
 * @return  RNP_SUCCESS
 *          RNP_ERROR_BAD_PARAMETERS wrong input parameters
 *          RNP_ERROR_SHORT_BUFFER out buffer to short. `out_size'
 *          will be assigned minimal required value
 *
 */
rnp_result_t repgp_copy_buffer_from_handle(uint8_t *             out,
                                           size_t *              out_size,
                                           const repgp_handle_t *handle);

/*
 * @brief   Creates opaque repgp_io_t object
 *
 * @returns Initialized repgp_io_t object or NULL on
 *          error.
 */
repgp_io_t *repgp_create_io(void);

/*
 * @brief   Sets input handler. If another handler was already
 *          set, it gets destroyed in order to make sure no
 *          memory leak is introduced.
 *          Function can be called with handle set to NULL
 *
 * @param   io input/output object on which input handler will be set
 * @param   handle handle object to be set
 */
void repgp_set_input(repgp_io_t *io, repgp_handle_t *handle);

/*
 * @brief   Sets output handler. If another handler was already
 *          set, it gets destroyed in order to make sure no
 *          memory leak is introduced.
 *          Function can be called with handle set to NULL
 *
 * @param   io input/output object on which input handler will be set
 * @param   handle handle object to be set
 */
void repgp_set_output(repgp_io_t *io, repgp_handle_t *handle);

/*
 * @brief   Destroys `repgp_io_t' object
 */
void repgp_destroy_io(repgp_io_t *io);

/**
 * @brief   Performs PGP signature verification
 *
 * @param   ctx Initialized context
 * @param   io input/output object. If output handle is set then
 *          then signature data is removed from input and is then
 *          written to the output handle.
 *
 * @pre     Input handles must be correctly set
 *
 * @returns RNP_SUCCESS signature is valid
 *          RNP_ERROR_BAD_PARAMETERS incorrect input parameters
 *          RNP_ERROR_SIGNATURE_INVALID Signature is invalid
 */
rnp_result_t repgp_verify(const void *ctx, repgp_io_t *io);

/**
 * @brief   Performs PGP decryption
 *
 * @param   ctx Initialized context
 * @param   io input/output object. Currently input and output
 *          must either read/write to file or of memory, but
 *          it can't be mixed (i.e. reading from file and outputing
 *          to memory).
 *
 * @pre     Both, input and output, handles must be correctly set
 *
 * @returns RNP_SUCCESS operation successful
 *          RNP_ERROR_BAD_PARAMETERS incorrect input parameters
 *          RNP_ERROR_GENERIC Decryption could not be correctly performed
 *          RNP_ERROR_SHORT_BUFFER Output buffer too small
 *          RNP_ERROR_OUT_OF_MEMORY Not enough memory to perform operation
 */
rnp_result_t repgp_decrypt(const void *ctx, repgp_io_t *io);

/**
 * @brief   Validate all signatures on a single key against the given keyring
 *
 * @param   ctx Context initialized with key ring
 *
 * @returns RNP_SUCCESS all signatures valid
 *          RNP_ERROR_GENERIC at least one signature is invalid
 *          RNP_ERROR_BAD_PARAMETERS incorrect input parameters
 */
rnp_result_t repgp_validate_pubkeys_signatures(void *ctx);

#endif /* REPGP_H_ */
