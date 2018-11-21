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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <regex.h>
#include <time.h>
#include <errno.h>

#include "rnpcfg.h"
#include "utils.h"
#include "defaults.h"
#include <rnp/rnp_sdk.h>
#include <rekey/rnp_key_store.h>

typedef enum rnp_cfg_val_type_t {
    RNP_CFG_VAL_NULL = 0,
    RNP_CFG_VAL_INT = 1,
    RNP_CFG_VAL_BOOL = 2,
    RNP_CFG_VAL_STRING = 3,
    RNP_CFG_VAL_LIST = 4
} rnp_cfg_val_type_t;

typedef struct rnp_cfg_val_t {
    rnp_cfg_val_type_t type;
    union {
        int   _int;
        bool  _bool;
        char *_string;
        list  _list;
    } val;
} rnp_cfg_val_t;

typedef struct rnp_cfg_item_t {
    char *        key;
    rnp_cfg_val_t val;
} rnp_cfg_item_t;

void
rnp_cfg_init(rnp_cfg_t *cfg)
{
    memset(cfg, '\0', sizeof(rnp_cfg_t));
}

void
rnp_cfg_load_defaults(rnp_cfg_t *cfg)
{
    rnp_cfg_setbool(cfg, CFG_OVERWRITE, false);
    rnp_cfg_setstr(cfg, CFG_OUTFILE, NULL);
    rnp_cfg_setint(cfg, CFG_ZALG, DEFAULT_Z_ALG);
    rnp_cfg_setint(cfg, CFG_ZLEVEL, DEFAULT_Z_LEVEL);
    rnp_cfg_setstr(cfg, CFG_CIPHER, DEFAULT_SYMM_ALG);
    rnp_cfg_setstr(cfg, CFG_SUBDIRGPG, SUBDIRECTORY_RNP);
    rnp_cfg_setint(cfg, CFG_NUMTRIES, MAX_PASSWORD_ATTEMPTS);
    rnp_cfg_setint(cfg, CFG_S2K_MSEC, DEFAULT_S2K_MSEC);
}

bool
rnp_cfg_apply(rnp_cfg_t *cfg, rnp_params_t *params)
{
    int         fd;
    const char *stream;

    /* enabling core dumps if user wants this */
    if (rnp_cfg_getbool(cfg, CFG_COREDUMPS)) {
        params->enable_coredumps = 1;
    }

    /* checking if password input was specified */
    if ((fd = rnp_cfg_getint(cfg, CFG_PASSFD))) {
        params->passfd = fd;
    }

    /* checking if user input was specified */
    if ((fd = rnp_cfg_getint(cfg, CFG_USERINPUTFD))) {
        params->userinputfd = fd;
    }

    if ((stream = rnp_cfg_getstr(cfg, CFG_IO_RESS))) {
        params->ress = stream;
    }

    /* detecting keystore pathes and format */
    if (!rnp_cfg_get_ks_info(cfg, params)) {
        RNP_LOG("cannot obtain keystore path(es)");
        return false;
    }

    /* default key/userid */
    rnp_cfg_get_defkey(cfg, params);

    return true;
}

static void
rnp_cfg_val_free(rnp_cfg_val_t *val)
{
    switch (val->type) {
    case RNP_CFG_VAL_STRING:
        free(val->val._string);
        break;
    case RNP_CFG_VAL_LIST:
        for (list_item *li = list_front(val->val._list); li; li = list_next(li)) {
            rnp_cfg_val_free((rnp_cfg_val_t *) li);
        }
        list_destroy(&val->val._list);
        break;
    default:
        break;
    }

    memset(val, 0, sizeof(*val));
}

static void
rnp_cfg_item_free(rnp_cfg_item_t *item)
{
    rnp_cfg_val_free(&item->val);
    free(item->key);
    item->key = NULL;
}

const char *
rnp_cfg_val_getstr(rnp_cfg_val_t *val)
{
    return val && (val->type == RNP_CFG_VAL_STRING) ? val->val._string : NULL;
}

static bool
rnp_cfg_val_copy(rnp_cfg_val_t *dst, rnp_cfg_val_t *src)
{
    memset(dst, 0, sizeof(*dst));

    switch (src->type) {
    case RNP_CFG_VAL_NULL:
    case RNP_CFG_VAL_INT:
    case RNP_CFG_VAL_BOOL:
        *dst = *src;
        break;
    case RNP_CFG_VAL_STRING:
        dst->type = RNP_CFG_VAL_STRING;
        if (!(dst->val._string = strdup(src->val._string))) {
            return false;
        }
        break;
    case RNP_CFG_VAL_LIST:
        dst->type = RNP_CFG_VAL_LIST;
        for (list_item *li = list_front(src->val._list); li; li = list_next(li)) {
            rnp_cfg_val_t val = {};
            if (!rnp_cfg_val_copy(&val, (rnp_cfg_val_t *) li) ||
                !list_append(&dst->val._list, &val, sizeof(val))) {
                rnp_cfg_val_free(dst);
                return false;
            }
        }
        break;
    default:
        return false;
    }

    return true;
}

/* find the value name in the rnp_cfg */
static rnp_cfg_item_t *
rnp_cfg_find(const rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = NULL;

    for (list_item *li = list_front(cfg->vals); li; li = list_next(li)) {
        if (strcmp(((rnp_cfg_item_t *) li)->key, key) == 0) {
            it = (rnp_cfg_item_t *) li;
            break;
        }
    }

    return it;
}

/** @brief set val for the key in config, copying key and assigning val
 *  @param cfg rnp config, must be allocated and initialized
 *  @param key must be null-terminated string
 *  @param val value, which will be copied as it is
 *
 *  @return false if allocation is failed. keys and vals fields will be freed in rnp_cfg_free
 **/
static rnp_cfg_item_t *
rnp_cfg_set(rnp_cfg_t *cfg, const char *key, rnp_cfg_val_t *val)
{
    rnp_cfg_item_t *it;

    if (!(it = rnp_cfg_find(cfg, key))) {
        it = (rnp_cfg_item_t *) list_append(&cfg->vals, NULL, sizeof(*it));

        if (!it || !(it->key = strdup(key))) {
            RNP_LOG("bad alloc");
            return NULL;
        }
    } else {
        rnp_cfg_val_free(&it->val);
    }

    it->val = *val;
    return it;
}

bool
rnp_cfg_unset(rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it;

    if ((it = rnp_cfg_find(cfg, key))) {
        rnp_cfg_item_free(it);
        list_remove((list_item *) it);
        return true;
    }

    return false;
}

bool
rnp_cfg_hasval(const rnp_cfg_t *cfg, const char *key)
{
    return rnp_cfg_find(cfg, key) != NULL;
}

bool
rnp_cfg_setint(rnp_cfg_t *cfg, const char *key, int val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_INT, .val = {._int = val}};
    return rnp_cfg_set(cfg, key, &_val) != NULL;
}

bool
rnp_cfg_setbool(rnp_cfg_t *cfg, const char *key, bool val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_BOOL, .val = {._bool = val}};
    return rnp_cfg_set(cfg, key, &_val) != NULL;
}

bool
rnp_cfg_setstr(rnp_cfg_t *cfg, const char *key, const char *val)
{
    rnp_cfg_val_t _val = {.type = RNP_CFG_VAL_STRING, .val = {._string = NULL}};

    if (val && !(_val.val._string = strdup(val))) {
        return false;
    }

    if (!rnp_cfg_set(cfg, key, &_val)) {
        free(_val.val._string);
        return false;
    }

    return true;
}

bool
rnp_cfg_addstr(rnp_cfg_t *cfg, const char *key, const char *str)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);
    rnp_cfg_val_t   val;
    bool            added = false;

    if (!it) {
        memset(&val, 0, sizeof(val));
        val.type = RNP_CFG_VAL_LIST;
        if (!(it = rnp_cfg_set(cfg, key, &val))) {
            return false;
        }
        added = true;
    }

    if (it->val.type != RNP_CFG_VAL_LIST) {
        RNP_LOG("wrong param");
        return false;
    }

    val.type = RNP_CFG_VAL_STRING;
    if (!(val.val._string = strdup(str)) ||
        !list_append(&it->val.val._list, &val, sizeof(val))) {
        if (added) {
            rnp_cfg_unset(cfg, key);
        }
        return false;
    }

    return true;
}

const char *
rnp_cfg_getstr(const rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it && (it->val.type == RNP_CFG_VAL_STRING)) {
        return it->val.val._string;
    }

    return NULL;
}

const char* rnp_cfg_gethashalg(rnp_cfg_t* cfg)
{
    const char* hash_alg = rnp_cfg_getstr(cfg, CFG_HASH);
    if(hash_alg) {
        return hash_alg;
    }
    return DEFAULT_HASH_ALG;
}

int
rnp_cfg_getint(rnp_cfg_t *cfg, const char *key)
{
    return rnp_cfg_getint_default(cfg, key, 0);
}

int
rnp_cfg_getint_default(rnp_cfg_t *cfg, const char *key, int def)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it) {
        switch (it->val.type) {
        case RNP_CFG_VAL_INT:
            return it->val.val._int;
        case RNP_CFG_VAL_BOOL:
            return it->val.val._bool;
        case RNP_CFG_VAL_STRING:
            return atoi(it->val.val._string);
        default:
            break;
        }
    }

    return def;
}

bool
rnp_cfg_getbool(rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it) {
        switch (it->val.type) {
        case RNP_CFG_VAL_INT:
            return it->val.val._int != 0;
        case RNP_CFG_VAL_BOOL:
            return it->val.val._bool;
        case RNP_CFG_VAL_STRING:
            return (strcasecmp(it->val.val._string, "true") == 0) ||
                   (atoi(it->val.val._string) > 0);
        default:
            break;
        }
    }

    return false;
}

list *
rnp_cfg_getlist(rnp_cfg_t *cfg, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (it && (it->val.type == RNP_CFG_VAL_LIST)) {
        return &it->val.val._list;
    }

    return NULL;
}

bool
rnp_cfg_copylist_str(rnp_cfg_t *cfg, list *dst, const char *key)
{
    rnp_cfg_item_t *it = rnp_cfg_find(cfg, key);

    if (!it) {
        /* copy empty list is okay */
        return true;
    }

    if (it->val.type != RNP_CFG_VAL_LIST) {
        goto fail;
    }

    for (list_item *li = list_front(it->val.val._list); li; li = list_next(li)) {
        rnp_cfg_val_t *val = (rnp_cfg_val_t *) li;
        if ((val->type != RNP_CFG_VAL_STRING) || !val->val._string) {
            RNP_LOG("wrong item in string list");
            goto fail;
        }
        if (!list_append(dst, val->val._string, strlen(val->val._string) + 1)) {
            RNP_LOG("allocation failed");
            goto fail;
        }
    }

    return true;

fail:
    list_destroy(dst);
    return false;
}

void
rnp_cfg_free(rnp_cfg_t *cfg)
{
    const char *passwd = rnp_cfg_getstr(cfg, CFG_PASSWD);

    if (passwd) {
        pgp_forget((void *) passwd, strlen(passwd) + 1);
    }

    for (list_item *li = list_front(cfg->vals); li; li = list_next(li)) {
        rnp_cfg_item_free((rnp_cfg_item_t *) li);
    }

    list_destroy(&cfg->vals);
}

int
rnp_cfg_get_pswdtries(rnp_cfg_t *cfg)
{
    const char *numtries;
    int         num;

    numtries = rnp_cfg_getstr(cfg, CFG_NUMTRIES);

    if ((numtries == NULL) || ((num = atoi(numtries)) <= 0)) {
        return MAX_PASSWORD_ATTEMPTS;
    } else if (strcmp(numtries, "unlimited")) {
        return INFINITE_ATTEMPTS;
    } else {
        return num;
    }
}

#if 0
bool
rnp_cfg_check_homedir(rnp_cfg_t *cfg, char *homedir)
{
    struct stat st;
    int         ret;

    if (homedir == NULL) {
        fputs("rnp: homedir option and HOME environment variable are not set \n", stderr);
        return false;
    } else if ((ret = stat(homedir, &st)) == 0 && !S_ISDIR(st.st_mode)) {
        /* file exists in place of homedir */
        RNP_LOG("homedir \"%s\" is not a dir", homedir);
        return false;
    } else if (ret != 0 && errno == ENOENT) {
        /* If the path doesn't exist then fail. */
        RNP_LOG("warning homedir \"%s\" not found", homedir);
        return false;
    } else if (ret != 0) {
        /* If any other occurred then fail. */
        RNP_LOG("an unspecified error occurred");
        return false;
    }

    return true;
}
#endif

/* read any gpg config file */
static bool
conffile(const char *homedir, char *userid, size_t length)
{
    regmatch_t matchv[10];
    regex_t    keyre;
    char       buf[BUFSIZ];
    FILE *     fp;

    (void) snprintf(buf, sizeof(buf), "%s/.gnupg/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return false;
    }
    (void) memset(&keyre, 0x0, sizeof(keyre));
    if (regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)", REG_EXTENDED) != 0) {
        RNP_LOG("failed to compile regular expression");
        fclose(fp);
        return false;
    }
    while (fgets(buf, (int) sizeof(buf), fp) != NULL) {
        if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
            (void) memcpy(userid,
                          &buf[(int) matchv[1].rm_so],
                          MIN((unsigned) (matchv[1].rm_eo - matchv[1].rm_so), length));

            (void) fprintf(stderr,
                           "rnp: default key set to \"%.*s\"\n",
                           (int) (matchv[1].rm_eo - matchv[1].rm_so),
                           &buf[(int) matchv[1].rm_so]);
        }
    }
    (void) fclose(fp);
    regfree(&keyre);
    return true;
}

/** @brief compose path from dir, subdir and filename, and store it in the res
 *  @param dir [in] null-terminated directory path, cannot be NULL
 *  @param subddir [in] null-terminated subdirectory to add to the path, can be NULL
 *  @param filename [in] null-terminated filename (or path/filename), cannot be NULL
 *  @param res [out] preallocated buffer
 *  @param res_size [in] size of output res buffer
 *
 *  @return true if path constructed successfully, or false otherwise
 **/
static bool
rnp_path_compose(
  const char *dir, const char *subdir, const char *filename, char *res, size_t res_size)
{
    int pos;

    /* checking input parameters for conrrectness */
    if (!dir || !filename || !res) {
        return false;
    }

    /* concatenating dir, subdir and filename */
    if (strlen(dir) > res_size - 1) {
        return false;
    }

    strcpy(res, dir);
    pos = strlen(dir);

    if (subdir) {
        if ((pos > 0) && (res[pos - 1] != '/')) {
            res[pos++] = '/';
        }

        if (strlen(subdir) + pos > res_size - 1) {
            return false;
        }

        strcpy(res + pos, subdir);
        pos += strlen(subdir);
    }

    if ((pos > 0) && (res[pos - 1] != '/')) {
        res[pos++] = '/';
    }

    if (strlen(filename) + pos > res_size - 1) {
        return false;
    }

    strcpy(res + pos, filename);

    return true;
}

/* helper function : get key storage subdir in case when user didn't specify homedir */
static const char *
rnp_cfg_get_ks_subdir(rnp_cfg_t *cfg, int defhomedir, const char *ksfmt)
{
    const char *subdir;

    if (!defhomedir) {
        subdir = NULL;
    } else {
        if ((subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG)) == NULL) {
            subdir = SUBDIRECTORY_RNP;
        }
    }

    return subdir;
}

bool
rnp_cfg_get_ks_info(rnp_cfg_t *cfg, rnp_params_t *params)
{
    bool        defhomedir = false;
    const char *homedir;
    const char *subdir;
    const char *ks_format;
    char        pubpath[MAXPATHLEN] = {0};
    char        secpath[MAXPATHLEN] = {0};
    struct stat st;

    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path */
    params->keystore_disabled = rnp_cfg_getint_default(cfg, CFG_KEYSTORE_DISABLED, 0);
    if (params->keystore_disabled) {
        if ((homedir = rnp_cfg_getstr(cfg, CFG_KEYFILE))) {
            params->pubpath = strdup("");
            params->secpath = strdup("");
            params->ks_pub_format = RNP_KEYSTORE_GPG;
            params->ks_sec_format = RNP_KEYSTORE_GPG;
        }

        return true;
    }

    if ((homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* detecting key storage format */
    if ((ks_format = rnp_cfg_getstr(cfg, CFG_KEYSTOREFMT)) == NULL) {
        if ((subdir = rnp_cfg_getstr(cfg, CFG_SUBDIRGPG)) == NULL) {
            subdir = SUBDIRECTORY_RNP;
        }
        rnp_path_compose(
          homedir, defhomedir ? subdir : NULL, PUBRING_KBX, pubpath, sizeof(pubpath));
        rnp_path_compose(
          homedir, defhomedir ? subdir : NULL, SECRING_G10, secpath, sizeof(secpath));

        bool pubpath_exists = stat(pubpath, &st) == 0;
        bool secpath_exists = stat(secpath, &st) == 0;

        if (pubpath_exists && secpath_exists) {
            ks_format = RNP_KEYSTORE_GPG21;
        } else if (secpath_exists) {
            ks_format = RNP_KEYSTORE_G10;
        } else if (pubpath_exists) {
            ks_format = RNP_KEYSTORE_KBX;
        } else {
            ks_format = RNP_KEYSTORE_GPG;
        }
    }

    /* building pubring/secring pathes */
    subdir = rnp_cfg_get_ks_subdir(cfg, defhomedir, ks_format);

    /* creating home dir if needed */
    if (defhomedir && subdir) {
        rnp_path_compose(homedir, NULL, subdir, pubpath, sizeof(pubpath));
        if (mkdir(pubpath, 0700) == -1 && errno != EEXIST) {
            RNP_LOG("cannot mkdir '%s' errno = %d", pubpath, errno);
            return false;
        }
    }

    if (strcmp(ks_format, RNP_KEYSTORE_GPG) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_GPG, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_GPG, secpath, sizeof(secpath))) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
        params->ks_pub_format = RNP_KEYSTORE_GPG;
        params->ks_sec_format = RNP_KEYSTORE_GPG;
    } else if (strcmp(ks_format, RNP_KEYSTORE_GPG21) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
        params->ks_pub_format = RNP_KEYSTORE_KBX;
        params->ks_sec_format = RNP_KEYSTORE_G10;
    } else if (strcmp(ks_format, RNP_KEYSTORE_KBX) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_KBX, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_KBX, secpath, sizeof(secpath))) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
        params->ks_pub_format = RNP_KEYSTORE_KBX;
        params->ks_sec_format = RNP_KEYSTORE_KBX;
    } else if (strcmp(ks_format, RNP_KEYSTORE_G10) == 0) {
        if (!rnp_path_compose(homedir, subdir, PUBRING_G10, pubpath, sizeof(pubpath)) ||
            !rnp_path_compose(homedir, subdir, SECRING_G10, secpath, sizeof(secpath))) {
            return false;
        }
        params->pubpath = strdup(pubpath);
        params->secpath = strdup(secpath);
        params->ks_pub_format = RNP_KEYSTORE_G10;
        params->ks_sec_format = RNP_KEYSTORE_G10;
    } else {
        RNP_LOG("unsupported keystore format: \"%s\"", ks_format);
        return false;
    }

    return true;
}

void
rnp_cfg_get_defkey(rnp_cfg_t *cfg, rnp_params_t *params)
{
    char        id[MAX_ID_LENGTH];
    const char *userid;
    const char *homedir;
    bool        defhomedir = false;

    if ((homedir = rnp_cfg_getstr(cfg, CFG_HOMEDIR)) == NULL) {
        homedir = getenv("HOME");
        defhomedir = true;
    }

    /* If a userid has been given, we'll use it. */
    if ((userid = rnp_cfg_getstr(cfg, CFG_USERID)) == NULL) {
        /* also search in config file for default id */

        if (defhomedir) {
            memset(id, 0, sizeof(id));
            conffile(homedir, id, sizeof(id));
            if (id[0] != 0x0) {
                params->defkey = strdup(id);
                rnp_cfg_setstr(cfg, CFG_USERID, id);
            }
        }
    } else {
        params->defkey = strdup(userid);
    }
}

/**
 * @brief Grabs date from the string in %Y-%m-%d format
 *
 * @param s [in] NULL-terminated string with the date
 * @param t [out] On successfull return result will be placed here
 * @return true on success or false otherwise
 */

static bool
grabdate(const char *s, int64_t *t)
{
    static regex_t r;
    static int     compiled;
    regmatch_t     matches[10];
    struct tm      tm;

    if (!compiled) {
        compiled = 1;
        if (regcomp(&r,
                    "([0-9][0-9][0-9][0-9])[-/]([0-9][0-9])[-/]([0-9][0-9])",
                    REG_EXTENDED) != 0) {
            RNP_LOG("failed to compile regexp");
            return false;
        }
    }
    if (regexec(&r, s, 10, matches, 0) == 0) {
        (void) memset(&tm, 0x0, sizeof(tm));
        tm.tm_year = (int) strtol(&s[(int) matches[1].rm_so], NULL, 10);
        tm.tm_mon = (int) strtol(&s[(int) matches[2].rm_so], NULL, 10) - 1;
        tm.tm_mday = (int) strtol(&s[(int) matches[3].rm_so], NULL, 10);
        *t = mktime(&tm);
        return true;
    }
    return false;
}

uint64_t
get_expiration(const char *s)
{
    uint64_t    now;
    int64_t     t;
    const char *mult;

    if ((s == NULL) || (strlen(s) < 1)) {
        return 0;
    }
    now = (uint64_t) strtoull(s, NULL, 10);
    if ((mult = strchr("hdwmy", s[strlen(s) - 1])) != NULL) {
        switch (*mult) {
        case 'h':
            return now * 60 * 60;
        case 'd':
            return now * 60 * 60 * 24;
        case 'w':
            return now * 60 * 60 * 24 * 7;
        case 'm':
            return now * 60 * 60 * 24 * 31;
        case 'y':
            return now * 60 * 60 * 24 * 365;
        }
    }
    if (grabdate(s, &t)) {
        return t;
    }
    return (uint64_t) strtoll(s, NULL, 10);
}

int64_t
get_creation(const char *s)
{
    int64_t t;

    if (s == NULL) {
        return time(NULL);
    }
    if (grabdate(s, &t)) {
        return t;
    }
    return (uint64_t) strtoll(s, NULL, 10);
}

void
rnp_cfg_copy(rnp_cfg_t *dst, const rnp_cfg_t *src)
{
    bool          res = true;
    rnp_cfg_val_t val;

    if (!src || !dst) {
        return;
    }

    rnp_cfg_free(dst);

    for (list_item *li = list_front(src->vals); li; li = list_next(li)) {
        if (!rnp_cfg_val_copy(&val, &((rnp_cfg_item_t *) li)->val) ||
            !rnp_cfg_set(dst, ((rnp_cfg_item_t *) li)->key, &val)) {
            res = false;
            break;
        }
    }

    if (!res) {
        rnp_cfg_free(dst);
    }
}
