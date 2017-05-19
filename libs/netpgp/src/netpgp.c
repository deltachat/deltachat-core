/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "netpgp/config-netpgp.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD$");
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "netpgp.h"

#include "netpgp/packet.h"
#include "netpgp/packet-parse.h"
#include "netpgp/keyring.h"
#include "netpgp/errors.h"
#include "netpgp/packet-show.h"
#include "netpgp/create.h"
#include "netpgp/netpgpsdk.h"
#include "netpgp/memory.h"
#include "netpgp/validate.h"
#include "netpgp/readerwriter.h"
#include "netpgp/netpgpdefs.h"
#include "netpgp/crypto.h"
#include "netpgp/defs.h"

/* read any gpg config file */
static int
conffile(netpgp_t *netpgp, char *homedir, char *userid, size_t length)
{
	regmatch_t	 matchv[10];
	regex_t		 keyre;
	char		 buf[BUFSIZ];
	FILE		*fp;

	__PGP_USED(netpgp);
	(void) snprintf(buf, sizeof(buf), "%s/gpg.conf", homedir);
	if ((fp = fopen(buf, "r")) == NULL) {
		return 0;
	}
	(void) memset(&keyre, 0x0, sizeof(keyre));
	(void) regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)",
		REG_EXTENDED);
	while (fgets(buf, (int)sizeof(buf), fp) != NULL) {
		if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
			(void) memcpy(userid, &buf[(int)matchv[1].rm_so],
				MIN((unsigned)(matchv[1].rm_eo -
						matchv[1].rm_so), length));
			if (netpgp->passfp == NULL) {
				(void) fprintf(stderr,
				"netpgp: default key set to \"%.*s\"\n",
				(int)(matchv[1].rm_eo - matchv[1].rm_so),
				&buf[(int)matchv[1].rm_so]);
			}
		}
	}
	(void) fclose(fp);
	regfree(&keyre);
	return 1;
}

/* check there's enough space in the arrays */
static int
size_arrays(netpgp_t *netpgp, unsigned needed)
{
	char	**temp;

	if (netpgp->size == 0) {
		/* only get here first time around */
		netpgp->size = needed;
		if ((netpgp->name = calloc(sizeof(char *), needed)) == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		if ((netpgp->value = calloc(sizeof(char *), needed)) == NULL) {
			free(netpgp->name);
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
	} else if (netpgp->c == netpgp->size) {
		/* only uses 'needed' when filled array */
		netpgp->size += needed;
		temp = realloc(netpgp->name, sizeof(char *) * needed);
		if (temp == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		netpgp->name = temp;
		temp = realloc(netpgp->value, sizeof(char *) * needed);
		if (temp == NULL) {
			(void) fprintf(stderr, "size_arrays: bad alloc\n");
			return 0;
		}
		netpgp->value = temp;
	}
	return 1;
}

/* find the name in the array */
static int
findvar(netpgp_t *netpgp, const char *name)
{
	unsigned	i;

	for (i = 0 ; i < netpgp->c && strcmp(netpgp->name[i], name) != 0; i++) {
	}
	return (i == netpgp->c) ? -1 : (int)i;
}

/* read a keyring and return it */
static unsigned
readkeyring(netpgp_t *netpgp,
            const char *name,
            pgp_keyring_t *pubring,
            pgp_keyring_t *secring)
{
	const unsigned	 noarmor = 0;
	char		*filename;
    char		 f[MAXPATHLEN];

	if ((filename = netpgp_getvar(netpgp, name)) == NULL) {
	    char		*homedir;
	    homedir = netpgp_getvar(netpgp, "homedir");
		(void) snprintf(f, sizeof(f), "%s/%s.gpg", homedir, name);
		filename = f;
	}
	if (!pgp_keyring_fileread(netpgp->io, pubring, secring, noarmor, filename)) {
		(void) fprintf(stderr, "Can't read %s %s\n", name, filename);
		return 0;
	}
	netpgp_setvar(netpgp, name, filename);
	return 1;
}

/* get the uid of the first key in the keyring */
static int
get_first_ring(pgp_keyring_t *ring, char *id, size_t len, int last)
{
	uint8_t	*src;
	int	 i;
	int	 n;

	if (ring == NULL) {
		return 0;
	}
	(void) memset(id, 0x0, len);
	src = ring->keys[(last) ? ring->keyc - 1 : 0].pubkeyid;
	for (i = 0, n = 0 ; i < PGP_KEY_ID_SIZE ; i += 2) {
		n += snprintf(&id[n], len - n, "%02x%02x", src[i], src[i + 1]);
	}
	id[n] = 0x0;
	return 1;
}
/***************************************************************************/
/* exported functions start here */
/***************************************************************************/

/* initialise a netpgp_t structure */
int
netpgp_init(netpgp_t *netpgp)
{
	pgp_io_t	*io;
	time_t		 t;
	char		 id[MAX_ID_LENGTH];
	char		*homedir;
	char		*userid;
	char		*stream;
	char		*passfd;
	char		*results;
	int		 coredumps;

#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit	limit;

	coredumps = netpgp_getvar(netpgp, "coredumps") != NULL;
	if (!coredumps) {
		(void) memset(&limit, 0x0, sizeof(limit));
		if (setrlimit(RLIMIT_CORE, &limit) != 0) {
			(void) fprintf(stderr,
			"netpgp: warning - can't turn off core dumps\n");
			coredumps = 1;
		}
	}
#else
	coredumps = 1;
#endif
	if ((io = calloc(1, sizeof(*io))) == NULL) {
		(void) fprintf(stderr, "netpgp_init: bad alloc\n");
		return 0;
	}
	io->outs = stdout;
	if ((stream = netpgp_getvar(netpgp, "outs")) != NULL &&
	    strcmp(stream, "<stderr>") == 0) {
		io->outs = stderr;
	}
	io->errs = stderr;
	if ((stream = netpgp_getvar(netpgp, "errs")) != NULL &&
	    strcmp(stream, "<stdout>") == 0) {
		io->errs = stdout;
	}
	if ((results = netpgp_getvar(netpgp, "res")) == NULL) {
		io->res = io->errs;
	} else if (strcmp(results, "<stdout>") == 0) {
		io->res = stdout;
	} else if (strcmp(results, "<stderr>") == 0) {
		io->res = stderr;
	} else {
		if ((io->res = fopen(results, "w")) == NULL) {
			(void) fprintf(io->errs, "Can't open results %s for writing\n",
				results);
			free(io);
			return 0;
		}
	}
	netpgp->io = io;
	/* get passphrase from an fd */
	if ((passfd = netpgp_getvar(netpgp, "pass-fd")) != NULL &&
	    (netpgp->passfp = fdopen(atoi(passfd), "r")) == NULL) {
		(void) fprintf(io->errs, "Can't open fd %s for reading\n",
			passfd);
		return 0;
	}
	/* warn if core dumps are enabled */
	if (coredumps) {
		(void) fprintf(io->errs,
			"netpgp: warning: core dumps enabled\n");
	}
	/* get home directory - where keyrings are in a subdir */
	if ((homedir = netpgp_getvar(netpgp, "homedir")) == NULL) {
		(void) fprintf(io->errs, "netpgp: bad homedir\n");
		return 0;
	}

    if ((netpgp->pubring = calloc(1, sizeof(pgp_keyring_t))) == NULL) {
        (void) fprintf(io->errs, "Can't alloc pubring\n");
        return 0;
    }
    if ((netpgp->secring = calloc(1, sizeof(pgp_keyring_t))) == NULL) {
        (void) fprintf(io->errs, "Can't alloc secring\n");
        return 0;
    }

    if (!readkeyring(netpgp,
                    "pubring",
                    netpgp->pubring,
                    netpgp->secring)) {
        (void) fprintf(io->errs, "Can't read pub keyring\n");
        // return 0;
    }
    /* if a userid has been given, we'll use it */
    if ((userid = netpgp_getvar(netpgp, "userid")) == NULL) {
        /* also search in config file for default id */
        (void) memset(id, 0x0, sizeof(id));
        (void) conffile(netpgp, homedir, id, sizeof(id));
        if (id[0] != 0x0) {
            netpgp_setvar(netpgp, "userid", userid = id);
        }
    }
    /* only read secret keys if we need to */
    if (netpgp_getvar(netpgp, "need seckey")) {
        /* read the secret ring */
        if (!readkeyring(netpgp,
                        "secring",
                        netpgp->pubring,
                        netpgp->secring)) {
            (void) fprintf(io->errs, "Can't read sec keyring\n");
            // return 0;
        }
        /* now, if we don't have a valid user, use the first in secring */
        if (!userid && netpgp_getvar(netpgp, "need userid") != NULL) {
            /* signing - need userid and sec key */
            (void) memset(id, 0x0, sizeof(id));
            if (get_first_ring(netpgp->secring, id, sizeof(id), 0)) {
                netpgp_setvar(netpgp, "userid", userid = id);
            }
        }
    } else if (netpgp_getvar(netpgp, "need userid") != NULL) {
        /* encrypting - get first in pubring */
        if (!userid && get_first_ring(netpgp->pubring, id, sizeof(id), 0)) {
            (void) netpgp_setvar(netpgp, "userid", userid = id);
        }
    }
    if (!userid && netpgp_getvar(netpgp, "need userid")) {
        /* if we don't have a user id, and we need one, fail */
        (void) fprintf(io->errs, "Cannot find user id\n");
        return 0;
    }
	t = time(NULL);
	netpgp_setvar(netpgp, "initialised", ctime(&t));
	return 1;
}

/* finish off with the netpgp_t struct */
int
netpgp_end(netpgp_t *netpgp)
{
	unsigned	i;

	for (i = 0 ; i < netpgp->c ; i++) {
		if (netpgp->name[i] != NULL) {
			free(netpgp->name[i]);
		}
		if (netpgp->value[i] != NULL) {
			free(netpgp->value[i]);
		}
	}
	if (netpgp->name != NULL) {
		free(netpgp->name);
	}
	if (netpgp->value != NULL) {
		free(netpgp->value);
	}
	if (netpgp->pubring != NULL) {
		pgp_keyring_free(netpgp->pubring);
	}
	if (netpgp->secring != NULL) {
		pgp_keyring_free(netpgp->secring);
	}
	free(netpgp->io);
	return 1;
}

static int
netpgp_save_ring(netpgp_t           *netpgp,
                 pgp_keyring_t      *keyring,
                 char               *name)
{
    pgp_io_t        *io;
    pgp_key_t       *key;
    unsigned         n;
    pgp_output_t    *output;
    int              fd;
    int              err = 0;
    char             swpfile[MAXPATHLEN];
    char             backup[MAXPATHLEN];
    char            *ringfile;
    int              cur;
    time_t           curtime;
    char		 f[MAXPATHLEN];

    io = netpgp->io;

    /* file names */
    if ((ringfile = netpgp_getvar(netpgp, name)) == NULL) {
	    char		*homedir;
	    homedir = netpgp_getvar(netpgp, "homedir");
		(void) snprintf(f, sizeof(f), "%s/%s.gpg", homedir, name);
        ringfile = f;
    }
    curtime = time(NULL);
    if (snprintf(swpfile, sizeof(swpfile),
                 "%s.swp", ringfile) >= sizeof(swpfile) ||
        (cur = snprintf(backup, sizeof(backup),
                        "%s.backup_", ringfile)) >= sizeof(backup) ||
        strftime(&backup[cur], sizeof(backup)-cur,
                     "%F.%T", localtime(&curtime)) >= sizeof(backup)-cur){
        (void) fprintf(io->errs,
                "netpgp_save_%s : file path too long\n", name);
        return 0;
    }

    /* ensure temporary file isn't already existing */
    unlink(swpfile);

    if ((fd = pgp_setup_file_write(&output, swpfile, 0)) < 0) {
        (void) fprintf(io->errs,
                "netpgp_save_%s : can't setup write for %s\n", name, swpfile);
        return 0;
    }

    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key) {
        pgp_write_xfer_key(output, key, 0);
    }

    pgp_teardown_file_write(output, fd);

    if(err){
        unlink(swpfile);
        return 0;
    }

    /* save ring if "backup rings" variable is set */
    if (netpgp_getvar(netpgp, "backup rings") != NULL) {
        rename(ringfile, backup);
    }

    /* replace ring file with swap file */
    rename(swpfile, ringfile);

	netpgp_setvar(netpgp, name, ringfile);

    return 1;
}

int
netpgp_save_pubring(netpgp_t *netpgp)
{
    return netpgp_save_ring(netpgp, netpgp->pubring, "pubring");
}

int
netpgp_save_secring(netpgp_t *netpgp)
{
    return netpgp_save_ring(netpgp, netpgp->secring, "secring");
}

/* set a variable */
int
netpgp_setvar(netpgp_t *netpgp, const char *name, const char *value)
{
	char	*newval;
	int	 i;

	/* protect against the case where 'value' is netpgp->value[i] */
	newval = netpgp_strdup(value);
	if ((i = findvar(netpgp, name)) < 0) {
		/* add the element to the array */
		if (size_arrays(netpgp, netpgp->size + 15)) {
			netpgp->name[i = netpgp->c++] = netpgp_strdup(name);
		}
	} else {
		/* replace the element in the array */
		if (netpgp->value[i]) {
			free(netpgp->value[i]);
			netpgp->value[i] = NULL;
		}
	}
	/* sanity checks for range of values */
	if (strcmp(name, "hash") == 0 || strcmp(name, "algorithm") == 0) {
		if (pgp_str_to_hash_alg(newval) == PGP_HASH_UNKNOWN) {
			free(newval);
			return 0;
		}
	}
	netpgp->value[i] = newval;
	return 1;
}

/* unset a variable */
int
netpgp_unsetvar(netpgp_t *netpgp, const char *name)
{
	int	i;

	if ((i = findvar(netpgp, name)) >= 0) {
		if (netpgp->value[i]) {
			free(netpgp->value[i]);
			netpgp->value[i] = NULL;
		}
		netpgp->value[i] = NULL;
		return 1;
	}
	return 0;
}

/* get a variable's value (NULL if not set) */
char *
netpgp_getvar(netpgp_t *netpgp, const char *name)
{
	int	i;

	return ((i = findvar(netpgp, name)) < 0) ? NULL : netpgp->value[i];
}

/* increment a value */
int
netpgp_incvar(netpgp_t *netpgp, const char *name, const int delta)
{
	char	*cp;
	char	 num[16];
	int	 val;

	val = 0;
	if ((cp = netpgp_getvar(netpgp, name)) != NULL) {
		val = atoi(cp);
	}
	(void) snprintf(num, sizeof(num), "%d", val + delta);
	netpgp_setvar(netpgp, name, num);
	return 1;
}

/* set the home directory value to "home/subdir" */
int
netpgp_set_homedir(netpgp_t *netpgp, char *home, const char *subdir, const int quiet)
{
	struct stat	st;
	char		d[MAXPATHLEN];

	if (home == NULL) {
		if (!quiet) {
			(void) fprintf(stderr, "NULL HOME directory\n");
		}
		return 0;
	}
	(void) snprintf(d, sizeof(d), "%s%s", home, (subdir) ? subdir : "");
	if (stat(d, &st) == 0) {
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			netpgp_setvar(netpgp, "homedir", d);
			return 1;
		}
		(void) fprintf(stderr, "netpgp: homedir \"%s\" is not a dir\n",
					d);
		return 0;
	}
	if (!quiet) {
		(void) fprintf(stderr,
			"netpgp: warning homedir \"%s\" not found\n", d);
	}
	netpgp_setvar(netpgp, "homedir", d);
	return 1;
}
