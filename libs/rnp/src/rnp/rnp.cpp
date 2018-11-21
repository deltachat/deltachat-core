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
/* Command line program to perform rnp operations */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <regex.h>
#include <rnp/rnp.h>
#include <rnp/rnp_sdk.h>
#include <repgp/repgp.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-armor.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-dump.h>
#include <librepgp/stream-sig.h>
#include <librepgp/packet-show.h>
#include <librepgp/packet-print.h>
#include <rekey/rnp_key_store.h>
#include "rnpcfg.h"
#include "crypto/common.h"
#include "rnpcfg.h"
#include "pgp-key.h"
#include "defaults.h"
#include "utils.h"

extern char *__progname;

static const char *usage = "--help OR\n"
                           "\t--encrypt [--output=file] [options] files... OR\n"
                           "\t--decrypt [--output=file] [options] files... OR\n"
                           "\t--sign [--detach] [--hash=alg] [--output=file]\n"
                           "\t\t[options] files... OR\n"
                           "\t--verify [options] files... OR\n"
                           "\t--cat [--output=file] [options] files... OR\n"
                           "\t--clearsign [--output=file] [options] files... OR\n"
                           "\t--list-packets [options] OR\n"
                           "\t--dearmor [--output=file] file OR\n"
                           "\t--enarmor=<msg|pubkey|seckey|sign> \n"
                           "\t\t[--output=file] file OR\n"
                           "\t--version\n"
                           "where options are:\n"
                           "\t[-r, --recipient] AND/OR\n"
                           "\t[--passwords] AND/OR\n"
                           "\t[--armor] AND/OR\n"
                           "\t[--cipher=<ciphername>] AND/OR\n"
                           "\t[--zip, --zlib, --bzip, -z 0..9] AND/OR\n"
                           "\t[--aead[=EAX, OCB]] AND/OR\n"
                           "\t[--aead-chunk-bits=0..56] AND/OR\n"
                           "\t[--coredumps] AND/OR\n"
                           "\t[--homedir=<homedir>] AND/OR\n"
                           "\t[-f, --keyfile=<path to key] AND/OR\n"
                           "\t[--keyring=<keyring>] AND/OR\n"
                           "\t[--keystore-format=<format>] AND/OR\n"
                           "\t[--numtries=<attempts>] AND/OR\n"
                           "\t[-u, --userid=<userid>] AND/OR\n"
                           "\t[--maxmemalloc=<number of bytes>] AND/OR\n"
                           "\t[--verbose]\n";

enum optdefs {
    /* Commands as they are get via CLI */
    CMD_ENCRYPT = 260,
    CMD_DECRYPT,
    CMD_SIGN,
    CMD_CLEARSIGN,
    CMD_VERIFY,
    CMD_VERIFY_CAT,
    CMD_SYM_ENCRYPT,
    CMD_DEARMOR,
    CMD_ENARMOR,
    CMD_LIST_PACKETS,
    CMD_SHOW_KEYS,
    CMD_VERSION,
    CMD_HELP,

    /* OpenPGP data processing commands. Sign/Encrypt/Decrypt mapped to these */
    CMD_PROTECT,
    CMD_PROCESS,

    /* Options */
    OPT_KEYRING,
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_RECIPIENT,
    OPT_ARMOR,
    OPT_HOMEDIR,
    OPT_DETACHED,
    OPT_HASH_ALG,
    OPT_OUTPUT,
    OPT_RESULTS,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_PASSWD,
    OPT_PASSWORDS,
    OPT_EXPIRATION,
    OPT_CREATION,
    OPT_CIPHER,
    OPT_NUMTRIES,
    OPT_ZALG_ZIP,
    OPT_ZALG_ZLIB,
    OPT_ZALG_BZIP,
    OPT_ZLEVEL,
    OPT_OVERWRITE,
    OPT_AEAD,
    OPT_AEAD_CHUNK,
    OPT_KEYFILE,

    /* debug */
    OPT_DEBUG
};

#define EXIT_ERROR 2

static struct option options[] = {
  /* file manipulation commands */
  {"encrypt", no_argument, NULL, CMD_ENCRYPT},
  {"decrypt", no_argument, NULL, CMD_DECRYPT},
  {"sign", no_argument, NULL, CMD_SIGN},
  {"clearsign", no_argument, NULL, CMD_CLEARSIGN},
  {"verify", no_argument, NULL, CMD_VERIFY},
  {"cat", no_argument, NULL, CMD_VERIFY_CAT},
  {"vericat", no_argument, NULL, CMD_VERIFY_CAT},
  {"verify-cat", no_argument, NULL, CMD_VERIFY_CAT},
  {"verify-show", no_argument, NULL, CMD_VERIFY_CAT},
  {"verifyshow", no_argument, NULL, CMD_VERIFY_CAT},
  {"symmetric", no_argument, NULL, CMD_SYM_ENCRYPT},
  {"dearmor", no_argument, NULL, CMD_DEARMOR},
  {"enarmor", required_argument, NULL, CMD_ENARMOR},
  /* file listing commands */
  {"list-packets", no_argument, NULL, CMD_LIST_PACKETS},
  /* debugging commands */
  {"help", no_argument, NULL, CMD_HELP},
  {"version", no_argument, NULL, CMD_VERSION},
  {"debug", required_argument, NULL, OPT_DEBUG},
  {"show-keys", no_argument, NULL, CMD_SHOW_KEYS},
  {"showkeys", no_argument, NULL, CMD_SHOW_KEYS},
  /* options */
  {"coredumps", no_argument, NULL, OPT_COREDUMPS},
  {"keyring", required_argument, NULL, OPT_KEYRING},
  {"keystore-format", required_argument, NULL, OPT_KEY_STORE_FORMAT},
  {"userid", required_argument, NULL, OPT_USERID},
  {"recipient", required_argument, NULL, OPT_RECIPIENT},
  {"home", required_argument, NULL, OPT_HOMEDIR},
  {"homedir", required_argument, NULL, OPT_HOMEDIR},
  {"keyfile", required_argument, NULL, OPT_KEYFILE},
  {"ascii", no_argument, NULL, OPT_ARMOR},
  {"armor", no_argument, NULL, OPT_ARMOR},
  {"armour", no_argument, NULL, OPT_ARMOR},
  {"detach", no_argument, NULL, OPT_DETACHED},
  {"detached", no_argument, NULL, OPT_DETACHED},
  {"hash-alg", required_argument, NULL, OPT_HASH_ALG},
  {"hash", required_argument, NULL, OPT_HASH_ALG},
  {"algorithm", required_argument, NULL, OPT_HASH_ALG},
  {"verbose", no_argument, NULL, OPT_VERBOSE},
  {"pass-fd", required_argument, NULL, OPT_PASSWDFD},
  {"password", required_argument, NULL, OPT_PASSWD},
  {"passwords", required_argument, NULL, OPT_PASSWORDS},
  {"output", required_argument, NULL, OPT_OUTPUT},
  {"results", required_argument, NULL, OPT_RESULTS},
  {"creation", required_argument, NULL, OPT_CREATION},
  {"expiration", required_argument, NULL, OPT_EXPIRATION},
  {"expiry", required_argument, NULL, OPT_EXPIRATION},
  {"cipher", required_argument, NULL, OPT_CIPHER},
  {"num-tries", required_argument, NULL, OPT_NUMTRIES},
  {"numtries", required_argument, NULL, OPT_NUMTRIES},
  {"attempts", required_argument, NULL, OPT_NUMTRIES},
  {"zip", no_argument, NULL, OPT_ZALG_ZIP},
  {"zlib", no_argument, NULL, OPT_ZALG_ZLIB},
  {"bzip", no_argument, NULL, OPT_ZALG_BZIP},
  {"bzip2", no_argument, NULL, OPT_ZALG_BZIP},
  {"overwrite", no_argument, NULL, OPT_OVERWRITE},
  {"aead", optional_argument, NULL, OPT_AEAD},
  {"aead-chunk-bits", required_argument, NULL, OPT_AEAD_CHUNK},

  {NULL, 0, NULL, 0},
};

static void
print_praise(void)
{
    fprintf(stderr,
            "%s\nAll bug reports, praise and chocolate, please, to:\n%s\n",
            rnp_get_info("version"),
            rnp_get_info("maintainer"));
}

/* print a usage message */
static void
print_usage(const char *usagemsg)
{
    print_praise();
    fprintf(stderr, "Usage: %s %s", __progname, usagemsg);
}

static void
rnp_on_signatures(pgp_parse_handler_t *handler, pgp_signature_info_t *sigs, int count)
{
    unsigned         invalidc = 0;
    unsigned         unknownc = 0;
    unsigned         validc = 0;
    time_t           create;
    uint32_t         expiry;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    char             id[MAX_ID_LENGTH + 1];
    const pgp_key_t *key;
    const char *     title = "UNKNOWN signature";
    FILE *           resfp = handler->ctx->rnp->resfp;

    for (int i = 0; i < count; i++) {
        if (sigs[i].unknown || sigs[i].no_signer) {
            unknownc++;
        } else {
            if (!sigs[i].valid) {
                if (sigs[i].no_signer) {
                    title = "NO PUBLIC KEY for signature";
                } else {
                    title = "BAD signature";
                }
                invalidc++;
            } else {
                if (sigs[i].expired) {
                    title = "EXPIRED signature";
                    invalidc++;
                } else {
                    title = "Good signature";
                    validc++;
                }
            }
        }

        create = signature_get_creation(sigs[i].sig);
        expiry = signature_get_expiration(sigs[i].sig);

        if (create > 0) {
            fprintf(resfp, "%s made %s", title, ctime(&create));
            if (expiry > 0) {
                create += expiry;
                fprintf(resfp, "Valid until %s\n", ctime(&create));
            }
        } else {
            fprintf(resfp, "%s\n", title);
        }

        signature_get_keyid(sigs[i].sig, keyid);
        fprintf(resfp,
                "using %s key %s\n",
                pgp_show_pka(sigs[i].sig->palg),
                userid_to_id(keyid, id));

        if (!sigs[i].no_signer) {
            key = rnp_key_store_get_key_by_id(handler->ctx->rnp->pubring, keyid, NULL);
            repgp_print_key(resfp, handler->ctx->rnp->pubring, key, "signature ", 0);
        }
    }

    if (count == 0) {
        fprintf(stderr, "No signature(s) found - is this a signed file?\n");
    } else if (invalidc > 0 || unknownc > 0) {
        fprintf(
          stderr,
          "Signature verification failure: %u invalid signature(s), %u unknown signature(s)\n",
          invalidc,
          unknownc);
    } else {
        fprintf(stderr, "Signature(s) verified successfully\n");
    }
}

static bool
setup_ctx(rnp_cfg_t *cfg, rnp_t *rnp, rnp_ctx_t *ctx)
{
    int         cmd;
    const char *fname;

    /* some rnp_t setup */
    if (rnp_cfg_getstr(cfg, CFG_PASSWD)) {
        rnp->password_provider.callback = rnp_password_provider_string;
        rnp->password_provider.userdata = (void *) rnp_cfg_getstr(cfg, CFG_PASSWD);
    }
    rnp->pswdtries = rnp_cfg_get_pswdtries(cfg);

    /* operation context initialization */
    rnp_ctx_init(ctx, rnp);
    ctx->armor = rnp_cfg_getint(cfg, CFG_ARMOR);
    ctx->overwrite = rnp_cfg_getbool(cfg, CFG_OVERWRITE);
    if ((fname = rnp_cfg_getstr(cfg, CFG_INFILE))) {
        ctx->filename = strdup(rnp_filename(fname));
        ctx->filemtime = rnp_filemtime(fname);
    }

    /* get the ongoing command. OpenPGP commands are only ENCRYPT/ENCRYPT_SIGN/SIGN/DECRYPT */
    cmd = rnp_cfg_getint(cfg, CFG_COMMAND);

    /* options used for signing */
    if (cmd == CMD_PROTECT) {
        ctx->zalg = rnp_cfg_getint(cfg, CFG_ZALG);
        ctx->zlevel = rnp_cfg_getint(cfg, CFG_ZLEVEL);

        /* setting signing parameters if needed */
        if (rnp_cfg_getbool(cfg, CFG_SIGN_NEEDED)) {
            ctx->halg = pgp_str_to_hash_alg(rnp_cfg_gethashalg(cfg));

            if (ctx->halg == PGP_HASH_UNKNOWN) {
                fprintf(stderr, "Unknown hash algorithm: %s\n", rnp_cfg_getstr(cfg, CFG_HASH));
                return false;
            }

            list signers = NULL;
            if (!rnp_cfg_copylist_str(cfg, &signers, CFG_SIGNERS)) {
                fprintf(stderr, "Failed to copy signers list\n");
                return false;
            }
            for (list_item *signer = list_front(signers); signer; signer = list_next(signer)) {
                pgp_key_t *key =
                  rnp_key_store_get_key_by_name(rnp->secring, (const char *) signer, NULL);
                if (!key) {
                    fprintf(
                      stderr, "Invalid or unavailable signer: %s\n", (const char *) signer);
                    list_destroy(&signers);
                    return false;
                }
                if (!list_append(&ctx->signers, &key, sizeof(key))) {
                    list_destroy(&signers);
                    return false;
                }
            }
            list_destroy(&signers);

            if (!list_length(ctx->signers)) {
                if (!rnp->defkey) {
                    fprintf(stderr, "No userid or default key for signing\n");
                    return false;
                }
                pgp_key_t *key =
                  rnp_key_store_get_key_by_name(rnp->secring, rnp->defkey, NULL);
                if (!key) {
                    return false;
                }
                if (!list_append(&ctx->signers, &key, sizeof(key))) {
                    RNP_LOG("allocation failed");
                    return false;
                }
            }

            ctx->sigcreate = get_creation(rnp_cfg_getstr(cfg, CFG_CREATION));
            ctx->sigexpire = get_expiration(rnp_cfg_getstr(cfg, CFG_EXPIRATION));
            ctx->clearsign = rnp_cfg_getbool(cfg, CFG_CLEARTEXT);
            ctx->detached = rnp_cfg_getbool(cfg, CFG_DETACHED);
        }

        /* setting encryption parameters if needed */
        if (rnp_cfg_getbool(cfg, CFG_ENCRYPT_PK) || rnp_cfg_getbool(cfg, CFG_ENCRYPT_SK)) {
            ctx->ealg = pgp_str_to_cipher(rnp_cfg_getstr(cfg, CFG_CIPHER));
            ctx->halg = pgp_str_to_hash_alg(rnp_cfg_getstr(cfg, CFG_HASH));
            ctx->zalg = rnp_cfg_getint(cfg, CFG_ZALG);
            ctx->zlevel = rnp_cfg_getint(cfg, CFG_ZLEVEL);
            ctx->aalg = (pgp_aead_alg_t) rnp_cfg_getint(cfg, CFG_AEAD);
            ctx->abits = rnp_cfg_getint_default(cfg, CFG_AEAD_CHUNK, DEFAULT_AEAD_CHUNK_BITS);

            /* adding passwords if password-based encryption is used */
            if (rnp_cfg_getbool(cfg, CFG_ENCRYPT_SK)) {
                int passwordc = rnp_cfg_getint_default(cfg, CFG_PASSWORDC, 1);

                for (int i = 0; i < passwordc; i++) {
                    if (rnp_encrypt_add_password(ctx)) {
                        RNP_LOG("Failed to add password");
                        return false;
                    }
                }
            }

            /* adding recipients if public-key encryption is used */
            if (rnp_cfg_getbool(cfg, CFG_ENCRYPT_PK)) {
                list recipients = NULL;
                if (!rnp_cfg_copylist_str(cfg, &recipients, CFG_RECIPIENTS)) {
                    RNP_LOG("Failed to copy recipients list");
                    return false;
                }
                for (list_item *recipient = list_front(recipients); recipient;
                     recipient = list_next(recipient)) {
                    pgp_key_t *key = rnp_key_store_get_key_by_name(
                      rnp->pubring, (const char *) recipient, NULL);
                    if (!key) {
                        fprintf(stderr,
                                "Invalid or unavailable recipient: %s\n",
                                (const char *) recipient);
                        list_destroy(&recipients);
                        return false;
                    }
                    if (!list_append(&ctx->recipients, &key, sizeof(key))) {
                        RNP_LOG("Failed to add key to recipient list");
                        list_destroy(&recipients);
                        return false;
                    }
                }
                list_destroy(&recipients);

                if (!list_length(ctx->recipients)) {
                    if (!rnp->defkey) {
                        fprintf(stderr, "No userid or default key for encryption\n");
                        return false;
                    }
                    pgp_key_t *key = rnp_key_store_get_key_by_name(
                      rnp->pubring, (const char *) rnp->defkey, NULL);
                    if (!key) {
                        fprintf(stderr,
                                "Invalid or unavailable recipient: %s\n",
                                (const char *) rnp->defkey);
                        return false;
                    }

                    if (!list_append(&ctx->recipients, &key, sizeof(key))) {
                        RNP_LOG("allocation failed");
                        return false;
                    }
                }
            }
        }
    } else if (cmd == CMD_PROCESS) {
        ctx->discard =
          rnp_cfg_getbool(cfg, CFG_NO_OUTPUT) && !rnp_cfg_getstr(cfg, CFG_OUTFILE);
        ctx->on_signatures = (void *) rnp_on_signatures;
    }

    return true;
}

/* do a command once for a specified config */
static bool
rnp_cmd(rnp_cfg_t *cfg, rnp_t *rnp)
{
    bool        ret = false;
    rnp_ctx_t   ctx = {0};
    const char *infile;
    const char *outfile;

    if (!(ret = setup_ctx(cfg, rnp, &ctx))) {
        goto done;
    }

    infile = rnp_cfg_getstr(cfg, CFG_INFILE);
    outfile = rnp_cfg_getstr(cfg, CFG_OUTFILE);

    switch (rnp_cfg_getint(cfg, CFG_COMMAND)) {
    case CMD_PROTECT:
        ret = rnp_protect_file(&ctx, infile, outfile) == RNP_SUCCESS;
        break;
    case CMD_PROCESS:
        ret = rnp_process_file(&ctx, infile, outfile) == RNP_SUCCESS;
        break;
    case CMD_LIST_PACKETS:
        ret = rnp_dump_file(&ctx, infile, outfile) == RNP_SUCCESS;
        break;
    case CMD_DEARMOR:
        ret = rnp_armor_stream(&ctx, false, infile, outfile) == RNP_SUCCESS;
        break;
    case CMD_ENARMOR:
        ctx.armortype = rnp_cfg_getint_default(cfg, CFG_ARMOR_DATA_TYPE, PGP_ARMORED_UNKNOWN);
        ret = rnp_armor_stream(&ctx, true, infile, outfile) == RNP_SUCCESS;
        break;
    case CMD_SHOW_KEYS:
        ret = repgp_validate_pubkeys_signatures(&ctx) == RNP_SUCCESS;
        break;
    case CMD_VERSION:
        print_praise();
        ret = true;
        break;
    default:
        print_usage(usage);
        ret = true;
    }

done:
    rnp_ctx_free(&ctx);
    return ret;
}

static bool
setcmd(rnp_cfg_t *cfg, int cmd, const char *arg)
{
    int newcmd = cmd;

    /* set file processing command to one of PROTECT or PROCESS */
    switch (cmd) {
    case CMD_ENCRYPT:
        rnp_cfg_setbool(cfg, CFG_ENCRYPT_PK, true);
        newcmd = CMD_PROTECT;
        break;
    case CMD_SYM_ENCRYPT:
        rnp_cfg_setbool(cfg, CFG_ENCRYPT_SK, true);
        newcmd = CMD_PROTECT;
        break;
    case CMD_CLEARSIGN:
        rnp_cfg_setbool(cfg, CFG_CLEARTEXT, true);
    /* FALLTHROUGH */
    case CMD_SIGN:
        rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        rnp_cfg_setbool(cfg, CFG_SIGN_NEEDED, true);
        newcmd = CMD_PROTECT;
        break;
    case CMD_DECRYPT:
        /* for decryption, we probably need a seckey */
        rnp_cfg_setbool(cfg, CFG_NEEDSSECKEY, true);
        newcmd = CMD_PROCESS;
        break;
    case CMD_VERIFY:
        /* single verify will discard output, decrypt will not */
        rnp_cfg_setbool(cfg, CFG_NO_OUTPUT, true);
    /* FALLTHROUGH */
    case CMD_VERIFY_CAT:
        newcmd = CMD_PROCESS;
        break;
    case CMD_LIST_PACKETS:
    case CMD_SHOW_KEYS:
        break;
    case CMD_DEARMOR:
        rnp_cfg_setint(cfg, CFG_KEYSTORE_DISABLED, 1);
        break;
    case CMD_ENARMOR: {
        pgp_armored_msg_t msgt = PGP_ARMORED_UNKNOWN;

        if (arg) {
            if (!strncmp("msg", arg, strlen(arg))) {
                msgt = PGP_ARMORED_MESSAGE;
            } else if (!strncmp("pubkey", arg, strlen(arg))) {
                msgt = PGP_ARMORED_PUBLIC_KEY;
            } else if (!strncmp("seckey", arg, strlen(arg))) {
                msgt = PGP_ARMORED_SECRET_KEY;
            } else if (!strncmp("sign", arg, strlen(arg))) {
                msgt = PGP_ARMORED_SIGNATURE;
            } else {
                fprintf(stderr, "Wrong enarmor argument: %s\n", arg);
                return false;
            }
        }

        rnp_cfg_setint(cfg, CFG_ARMOR_DATA_TYPE, msgt);
        rnp_cfg_setint(cfg, CFG_KEYSTORE_DISABLED, 1);
        break;
    }
    case CMD_HELP:
    case CMD_VERSION:
        break;
    default:
        newcmd = CMD_HELP;
        break;
    }

    rnp_cfg_setint(cfg, CFG_COMMAND, newcmd);
    return true;
}

/* set an option */
static bool
setoption(rnp_cfg_t *cfg, int val, char *arg)
{
    switch (val) {
    /* redirect commands to setcmd */
    case CMD_ENCRYPT:
    case CMD_SIGN:
    case CMD_CLEARSIGN:
    case CMD_DECRYPT:
    case CMD_SYM_ENCRYPT:
    case CMD_VERIFY:
    case CMD_VERIFY_CAT:
    case CMD_LIST_PACKETS:
    case CMD_SHOW_KEYS:
    case CMD_DEARMOR:
    case CMD_ENARMOR:
    case CMD_HELP:
    case CMD_VERSION:
        if (!setcmd(cfg, val, arg)) {
            return false;
        }
        break;
    /* options */
    case OPT_COREDUMPS:
        rnp_cfg_setbool(cfg, CFG_COREDUMPS, true);
        break;
    case OPT_KEYRING:
        if (arg == NULL) {
            fputs("No keyring argument provided\n", stderr);
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_KEYRING, arg);
        break;
    case OPT_KEY_STORE_FORMAT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyring format argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_KEYSTOREFMT, arg);
        break;
    case OPT_USERID:
        if (arg == NULL) {
            fputs("No userid argument provided\n", stderr);
            return false;
        }
        rnp_cfg_addstr(cfg, CFG_SIGNERS, arg);
        break;
    case OPT_RECIPIENT:
        if (arg == NULL) {
            fputs("No recipient argument provided\n", stderr);
            return false;
        }
        rnp_cfg_addstr(cfg, CFG_RECIPIENTS, arg);
        break;
    case OPT_ARMOR:
        rnp_cfg_setint(cfg, CFG_ARMOR, 1);
        break;
    case OPT_DETACHED:
        rnp_cfg_setbool(cfg, CFG_DETACHED, true);
        break;
    case OPT_VERBOSE:
        rnp_cfg_setint(cfg, CFG_VERBOSE, rnp_cfg_getint(cfg, CFG_VERBOSE) + 1);
        break;
    case OPT_HOMEDIR:
        if (arg == NULL) {
            (void) fprintf(stderr, "No home directory argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_HOMEDIR, arg);
        break;
    case OPT_KEYFILE:
        if (arg == NULL) {
            (void) fprintf(stderr, "No keyfile argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_KEYFILE, arg);
        rnp_cfg_setbool(cfg, CFG_KEYSTORE_DISABLED, true);
        break;
    case OPT_HASH_ALG:
        if (arg == NULL) {
            (void) fprintf(stderr, "No hash algorithm argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_HASH, arg);
        break;
    case OPT_PASSWDFD:
        if (arg == NULL) {
            (void) fprintf(stderr, "No pass-fd argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_PASSFD, arg);
        break;
    case OPT_PASSWD:
        if (arg == NULL) {
            (void) fprintf(stderr, "No password argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_PASSWD, arg);
        break;
    case OPT_PASSWORDS: {
        int count;
        if (arg == NULL) {
            (void) fprintf(stderr, "You must provide a number with --passwords option\n");
            return false;
        }

        count = atoi(arg);
        if (count <= 0) {
            (void) fprintf(stderr, "Incorrect value for --passwords option: %s\n", arg);
            return false;
        }

        rnp_cfg_setint(cfg, CFG_PASSWORDC, count);
        if (count > 0) {
            rnp_cfg_setbool(cfg, CFG_ENCRYPT_SK, true);
        }
        break;
    }
    case OPT_OUTPUT:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_OUTFILE, arg);
        break;
    case OPT_RESULTS:
        if (arg == NULL) {
            (void) fprintf(stderr, "No output filename argument provided\n");
            return false;
        }
        rnp_cfg_setstr(cfg, CFG_RESULTS, arg);
        break;
    case OPT_EXPIRATION:
        rnp_cfg_setstr(cfg, CFG_EXPIRATION, arg);
        break;
    case OPT_CREATION:
        rnp_cfg_setstr(cfg, CFG_CREATION, arg);
        break;
    case OPT_CIPHER:
        rnp_cfg_setstr(cfg, CFG_CIPHER, arg);
        break;
    case OPT_NUMTRIES:
        rnp_cfg_setstr(cfg, CFG_NUMTRIES, arg);
        break;
    case OPT_ZALG_ZIP:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_ZIP);
        break;
    case OPT_ZALG_ZLIB:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_ZLIB);
        break;
    case OPT_ZALG_BZIP:
        rnp_cfg_setint(cfg, CFG_ZALG, PGP_C_BZIP2);
        break;
    case OPT_AEAD: {
        pgp_aead_alg_t alg = PGP_AEAD_NONE;
        if (!arg || !strcmp(arg, "1") || !rnp_strcasecmp(arg, "eax")) {
            alg = PGP_AEAD_EAX;
        } else if (!strcmp(arg, "2") || !rnp_strcasecmp(arg, "ocb")) {
            alg = PGP_AEAD_OCB;
        } else {
            (void) fprintf(stderr, "Wrong AEAD algorithm: %s\n", arg);
            return false;
        }

        rnp_cfg_setint(cfg, CFG_AEAD, alg);
        break;
    }
    case OPT_AEAD_CHUNK: {
        if (!arg) {
            (void) fprintf(stderr, "Option aead-chunk-bits requires parameter\n");
            return false;
        }

        int bits = atoi(arg);

        if ((bits < 0) || (bits > 56)) {
            (void) fprintf(stderr, "Wrong argument value %s for aead-chunk-bits\n", arg);
            return false;
        }

        rnp_cfg_setint(cfg, CFG_AEAD_CHUNK, bits);

        break;
    }
    case OPT_OVERWRITE:
        rnp_cfg_setbool(cfg, CFG_OVERWRITE, true);
        break;
    case OPT_DEBUG:
        rnp_set_debug(arg);
        break;
    default:
        if (!setcmd(cfg, CMD_HELP, arg)) {
            return false;
        }
        break;
    }

    return true;
}

/* we have -o option=value -- parse, and process */
static bool
parse_option(rnp_cfg_t *cfg, const char *s)
{
    static regex_t opt;
    struct option *op;
    static int     compiled;
    regmatch_t     matches[10];
    char           option[128];
    char           value[128];

    if (!compiled) {
        compiled = 1;
        if (regcomp(&opt, "([^=]{1,128})(=(.*))?", REG_EXTENDED) != 0) {
            fprintf(stderr, "Can't compile regex\n");
            return 0;
        }
    }
    if (regexec(&opt, s, 10, matches, 0) == 0) {
        snprintf(option,
                 sizeof(option),
                 "%.*s",
                 (int) (matches[1].rm_eo - matches[1].rm_so),
                 &s[matches[1].rm_so]);
        if (matches[2].rm_so > 0) {
            snprintf(value,
                     sizeof(value),
                     "%.*s",
                     (int) (matches[3].rm_eo - matches[3].rm_so),
                     &s[matches[3].rm_so]);
        } else {
            value[0] = 0x0;
        }
        for (op = options; op->name; op++) {
            if (strcmp(op->name, option) == 0)
                return setoption(cfg, op->val, value);
        }
    }
    return 0;
}

#ifndef RNP_RUN_TESTS
int main(int argc, char **argv)
#else
int rnp_main(int argc, char **argv);
int rnp_main(int argc, char **argv)
#endif
{
    rnp_params_t rnp_params = {0};
    rnp_t        rnp = {0};
    rnp_cfg_t    cfg;
    int          optindex;
    int          ret = EXIT_ERROR;
    int          ch;
    int          i;

    if (argc < 2) {
        print_usage(usage);
        return EXIT_ERROR;
    }

    rnp_cfg_init(&cfg);
    rnp_cfg_load_defaults(&cfg);
    optindex = 0;

    /* TODO: These options should be set after initialising the context. */
    while ((ch = getopt_long(argc, argv, "S:Vdeco:r:su:vz:f:", options, &optindex)) != -1) {
        if (ch >= CMD_ENCRYPT) {
            /* getopt_long returns 0 for long options */
            if (!setoption(&cfg, options[optindex].val, optarg)) {
                ret = EXIT_ERROR;
                goto finish;
            }
        } else {
            int cmd = 0;
            switch (ch) {
            case 'V':
                cmd = CMD_VERSION;
                break;
            case 'd':
                cmd = CMD_DECRYPT;
                break;
            case 'e':
                cmd = CMD_ENCRYPT;
                break;
            case 'c':
                cmd = CMD_SYM_ENCRYPT;
                break;
            case 's':
                cmd = CMD_SIGN;
                break;
            case 'v':
                cmd = CMD_VERIFY;
                break;
            case 'o':
                if (!parse_option(&cfg, optarg)) {
                    (void) fprintf(stderr, "Bad option\n");
                    ret = EXIT_ERROR;
                    goto finish;
                }
                break;
            case 'r':
                if (strlen(optarg) < 1) {
                    fprintf(stderr, "Recipient should not be empty\n");
                } else {
                    rnp_cfg_addstr(&cfg, CFG_RECIPIENTS, optarg);
                }
                break;
            case 'u':
                if (!optarg) {
                    fputs("No userid argument provided\n", stderr);
                    ret = EXIT_ERROR;
                    goto finish;
                }
                rnp_cfg_addstr(&cfg, CFG_SIGNERS, optarg);
                break;
            case 'z':
                if ((strlen(optarg) != 1) || (optarg[0] < '0') || (optarg[0] > '9')) {
                    fprintf(stderr, "Bad compression level: %s. Should be 0..9\n", optarg);
                } else {
                    rnp_cfg_setint(&cfg, CFG_ZLEVEL, (int) (optarg[0] - '0'));
                }
                break;
            case 'f':
                if (!optarg) {
                    (void) fprintf(stderr, "No keyfile argument provided\n");
                    ret = EXIT_ERROR;
                    goto finish;
                }
                rnp_cfg_setstr(&cfg, CFG_KEYFILE, optarg);
                rnp_cfg_setbool(&cfg, CFG_KEYSTORE_DISABLED, true);
                break;
            default:
                cmd = CMD_HELP;
                break;
            }

            if (cmd && !setcmd(&cfg, cmd, optarg)) {
                ret = EXIT_ERROR;
                goto finish;
            }
        }
    }

    switch (rnp_cfg_getint(&cfg, CFG_COMMAND)) {
    case CMD_HELP:
    case CMD_VERSION:
        ret = rnp_cmd(&cfg, &rnp) ? EXIT_SUCCESS : EXIT_FAILURE;
        goto finish;
    default:;
    }

    rnp_params_init(&rnp_params);
    if (!rnp_cfg_apply(&cfg, &rnp_params)) {
        fputs("fatal: cannot apply configuration\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    if (rnp_init(&rnp, &rnp_params) != RNP_SUCCESS) {
        fputs("fatal: cannot initialise\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    if (!rnp_params.keystore_disabled &&
        !rnp_key_store_load_keys(&rnp, rnp_cfg_getbool(&cfg, CFG_NEEDSSECKEY))) {
        fputs("fatal: failed to load keys\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    /* load the keyfile if any */
    if (rnp_params.keystore_disabled && rnp_cfg_getstr(&cfg, CFG_KEYFILE) &&
        !rnp_add_key(&rnp, rnp_cfg_getstr(&cfg, CFG_KEYFILE), false)) {
        fputs("fatal: failed to load key(s) from the file\n", stderr);
        ret = EXIT_ERROR;
        goto finish;
    }

    /* now do the required action for each of the command line args */
    ret = EXIT_SUCCESS;
    if (optind == argc) {
        if (!rnp_cmd(&cfg, &rnp))
            ret = EXIT_FAILURE;
    } else {
        for (i = optind; i < argc; i++) {
            rnp_cfg_setstr(&cfg, CFG_INFILE, argv[i]);
            if (!rnp_cmd(&cfg, &rnp)) {
                ret = EXIT_FAILURE;
            }
        }
    }

finish:
    rnp_params_free(&rnp_params);
    rnp_cfg_free(&cfg);
    rnp_end(&rnp);

    return ret;
}
