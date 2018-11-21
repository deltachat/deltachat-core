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

#ifndef RNP_RANDOM_H_
#define RNP_RANDOM_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum { RNG_DRBG, RNG_SYSTEM };
typedef uint8_t                  rng_type_t;
typedef struct botan_rng_struct *botan_rng_t;

typedef struct rng_st_t {
    bool        initialized;
    rng_type_t  rng_type;
    botan_rng_t botan_rng;
} rng_t;

/*
 * @brief Initializes rng structure
 *
 * @param rng_type indicates which random generator to initialize.
 *        Two values possible
 *          RNG_DRBG - will initialize HMAC_DRBG, this generator
 *                     is initialized on-demand (when used for the
 *                     first time)
 *          RNG_SYSTEM will initialize /dev/(u)random
 * @returns false if lazy initialization wasn't requested
 *          and initialization failed, otherwise true
 */
bool rng_init(rng_t *ctx, rng_type_t rng_type);

/*
 * Frees memory allocated by `rng_get_data'
 */
void rng_destroy(rng_t *ctx);

/*
 *  @brief  Used to retrieve random data. First successfull completition
 *          of this function initializes memory in `ctx' which
 *          needs to be released with `rng_destroy'.
 *
 *          Function initializes HMAC_DRBG with automatic reseeding
 *          after each 1024'th call.
 *
 *  @param ctx pointer to rng_t
 *  @param data [out] output buffer of size at least `len`
 *  @param len number of bytes to get
 *
 *  @return true on success, false indicates implementation error.
 **/
bool rng_get_data(rng_t *ctx, uint8_t *data, size_t len);

/*
 * @brief   Returns internal handle to botan rng. Returned
 *          handle is always initialized. In case of
 *          internal error NULL is returned
 *
 * @param   valid pointer to rng_t object
 */
struct botan_rng_struct *rng_handle(rng_t *);

/*
 * @brief   Initializes RNG_SYSTEM and generates random data.
 *          This function should be used only in places where
 *          rng_t is not available. Using this function may
 *          impact performance
 *
 * @param   data[out] Output buffer storing random data
 * @param   data_len length of data to be generated
 *
 * @returs  true one success, otherwise false
 */
bool rng_generate(uint8_t *data, size_t data_len);

#endif // RNP_RANDOM_H_
