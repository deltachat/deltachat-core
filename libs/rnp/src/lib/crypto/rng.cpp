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

#include <assert.h>
#include <botan/ffi.h>
#include "rng.h"

static inline bool
rng_ensure_initialized(rng_t *ctx)
{
    assert(ctx);
    if (ctx->initialized) {
        return true;
    }

    ctx->initialized =
      !botan_rng_init(&ctx->botan_rng, ctx->rng_type == RNG_DRBG ? "user" : NULL);
    return ctx->initialized;
}

bool
rng_init(rng_t *ctx, rng_type_t rng_type)
{
    if (!ctx) {
        return false;
    }

    if ((rng_type != RNG_DRBG) && (rng_type != RNG_SYSTEM)) {
        return false;
    }

    ctx->initialized = false;
    ctx->rng_type = rng_type;
    return (rng_type == RNG_SYSTEM) ? rng_ensure_initialized(ctx) : true;
}

void
rng_destroy(rng_t *ctx)
{
    if (!ctx || !ctx->initialized) {
        return;
    }

    (void) botan_rng_destroy(ctx->botan_rng);
    ctx->botan_rng = NULL;
    ctx->initialized = false;
}

bool
rng_get_data(rng_t *ctx, uint8_t *data, size_t len)
{
    if (!ctx) {
        return false;
    }

    if (!rng_ensure_initialized(ctx)) {
        return false;
    }

    if (botan_rng_get(ctx->botan_rng, data, len)) {
        // This should never happen
        return false;
    }

    return true;
}

struct botan_rng_struct *
rng_handle(rng_t *ctx)
{
    (void) rng_ensure_initialized(ctx);
    return ctx->initialized ? ctx->botan_rng : NULL;
}

bool
rng_generate(uint8_t *data, size_t data_len)
{
    botan_rng_t rng;
    if (botan_rng_init(&rng, NULL)) {
        return false;
    }
    const bool rc = botan_rng_get(rng, data, data_len) == 0;
    (void) botan_rng_destroy(rng);
    return rc;
}
