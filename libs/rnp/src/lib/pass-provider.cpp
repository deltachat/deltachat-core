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
#include "pass-provider.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>

#include <pgp-key.h>
#include <rnp/rnp_sdk.h>

static bool
rnp_getpass(const char *prompt, char *buffer, size_t size)
{
    struct termios saved_flags, noecho_flags;
    bool           restore_ttyflags = false;
    bool           ok = false;
    FILE *         in = NULL;
    FILE *         out = NULL;

    // validate args
    if (!buffer) {
        goto end;
    }
    // doesn't hurt
    *buffer = '\0';

    in = fopen("/dev/tty", "w+ce");
    if (!in) {
        in = stdin;
        out = stderr;
    } else {
        out = in;
    }

    // save the original termios
    if (tcgetattr(fileno(in), &saved_flags) == 0) {
        noecho_flags = saved_flags;
        // disable echo in the local modes
        noecho_flags.c_lflag = (noecho_flags.c_lflag & ~ECHO) | ECHONL | ISIG;
        restore_ttyflags = (tcsetattr(fileno(in), TCSANOW, &noecho_flags) == 0);
    }
    if (prompt) {
        fputs(prompt, out);
    }
    if (fgets(buffer, size, in) == NULL) {
        goto end;
    }

    rnp_strip_eol(buffer);
    ok = true;
end:
    if (restore_ttyflags) {
        tcsetattr(fileno(in), TCSAFLUSH, &saved_flags);
    }
    if (in != stdin) {
        fclose(in);
    }
    return ok;
}

bool
rnp_password_provider_stdin(const pgp_password_ctx_t *ctx,
                            char *                    password,
                            size_t                    password_size,
                            void *                    userdata)
{
    char keyidhex[PGP_KEY_ID_SIZE * 2 + 1];
    char target[sizeof(keyidhex) + 16];
    char prompt[128];
    char buffer[MAX_PASSWORD_LENGTH];
    bool ok = false;

    if (!ctx || !password || !password_size) {
        goto done;
    }

    if ((ctx->op != PGP_OP_DECRYPT_SYM) && (ctx->op != PGP_OP_ENCRYPT_SYM)) {
        rnp_strhexdump(keyidhex, ctx->key->keyid, PGP_KEY_ID_SIZE, "");
        snprintf(target, sizeof(target), "key 0x%s", keyidhex);
    }
start:
    if (ctx->op == PGP_OP_DECRYPT_SYM) {
        snprintf(prompt, sizeof(prompt), "Enter password to decrypt data: ");
    } else if (ctx->op == PGP_OP_ENCRYPT_SYM) {
        snprintf(prompt, sizeof(prompt), "Enter password to encrypt data: ");
    } else {
        snprintf(prompt, sizeof(prompt), "Enter password for %s: ", target);
    }

    if (!rnp_getpass(prompt, password, password_size)) {
        goto done;
    }
    if ((ctx->op == PGP_OP_PROTECT) || (ctx->op == PGP_OP_ENCRYPT_SYM)) {
        if (ctx->op == PGP_OP_PROTECT) {
            snprintf(prompt, sizeof(prompt), "Repeat password for %s: ", target);
        } else {
            snprintf(prompt, sizeof(prompt), "Repeat password: ");
        }

        if (!rnp_getpass(prompt, buffer, sizeof(buffer))) {
            goto done;
        }
        if (strcmp(password, buffer) != 0) {
            puts("\nPasswords do not match!");
            // currently will loop forever
            goto start;
        }
    }
    ok = true;

done:
    puts("");
    pgp_forget(buffer, sizeof(buffer));
    return ok;
}

bool
rnp_password_provider_file(const pgp_password_ctx_t *ctx,
                           char *                    password,
                           size_t                    password_size,
                           void *                    userdata)
{
    FILE *fp = (FILE *) userdata;

    if (!ctx || !password || !password_size || !userdata) {
        return false;
    }
    if (!fgets(password, password_size, fp)) {
        return false;
    }
    rnp_strip_eol(password);
    return true;
}

bool
rnp_password_provider_string(const pgp_password_ctx_t *ctx,
                             char *                    password,
                             size_t                    password_size,
                             void *                    userdata)
{
    char *passc = (char *) userdata;

    if (!passc || strlen(passc) >= (password_size - 1)) {
        return false;
    }

    strncpy(password, passc, password_size - 1);
    return true;
}

bool
pgp_request_password(const pgp_password_provider_t *provider,
                     const pgp_password_ctx_t *     ctx,
                     char *                         password,
                     size_t                         password_size)
{
    if (!provider || !provider->callback || !ctx || !password || !password_size) {
        return false;
    }
    return provider->callback(ctx, password, password_size, provider->userdata);
}
