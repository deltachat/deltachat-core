/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 ******************************************************************************/


#include <sys/stat.h>
#include <sys/types.h> /* for getpid() */
#include <unistd.h>    /* for getpid() */
#include <openssl/opensslv.h>
#include <assert.h>
#include "dc_context.h"
#include "dc_imap.h"
#include "dc_smtp.h"
#include "dc_mimefactory.h"
#include "dc_tools.h"
#include "dc_job.h"
#include "dc_key.h"
#include "dc_pgp.h"
#include "dc_apeerstate.h"


/*******************************************************************************
 * Main interface
 ******************************************************************************/


static uintptr_t cb_dummy(dc_context_t* context, int event, uintptr_t data1, uintptr_t data2)
{
	return 0;
}


static char* cb_get_config(dc_imap_t* imap, const char* key, const char* def)
{
	dc_context_t* context = (dc_context_t*)imap->m_userData;
	return dc_sqlite3_get_config(context->m_sql, key, def);
}


static void cb_set_config(dc_imap_t* imap, const char* key, const char* value)
{
	dc_context_t* context = (dc_context_t*)imap->m_userData;
	dc_sqlite3_set_config(context->m_sql, key, value);
}


static void cb_receive_imf(dc_imap_t* imap, const char* imf_raw_not_terminated, size_t imf_raw_bytes, const char* server_folder, uint32_t server_uid, uint32_t flags)
{
	dc_context_t* context = (dc_context_t*)imap->m_userData;
	dc_receive_imf(context, imf_raw_not_terminated, imf_raw_bytes, server_folder, server_uid, flags);
}


/**
 * Create a new context object.  After creation it is usually
 * opened, connected and mails are fetched.
 * After usage, the object should be deleted using dc_context_unref().
 *
 * @memberof dc_context_t
 * @param cb a callback function that is called for events (update,
 *     state changes etc.) and to get some information form the client (eg. translation
 *     for a given string).
 *     See @ref DC_EVENT for a list of possible events that may be passed to the callback.
 *     - The callback MAY be called from _any_ thread, not only the main/GUI thread!
 *     - The callback MUST NOT call any dc_* and related functions unless stated
 *       otherwise!
 *     - The callback SHOULD return _fast_, for GUI updates etc. you should
 *       post yourself an asynchronous message to your GUI thread, if needed.
 *     - If not mentioned otherweise, the callback should return 0.
 * @param userdata can be used by the client for any purpuse.  He finds it
 *     later in dc_get_userdata().
 * @param os_name is only for decorative use and is shown eg. in the `X-Mailer:` header
 *     in the form "Delta Chat <version> for <os_name>".
 *     You can give the name of the operating system and/or the used environment here.
 *     It is okay to give NULL, in this case `X-Mailer:` header is set to "Delta Chat <version>".
 * @return a context object with some public members the object must be passed to the other context functions
 *     and the object must be freed using dc_context_unref() after usage.
 */
dc_context_t* dc_context_new(dc_callback_t cb, void* userdata, const char* os_name)
{
	dc_context_t* context = NULL;

	if( (context=calloc(1, sizeof(dc_context_t)))==NULL ) {
		exit(23); /* cannot allocate little memory, unrecoverable error */
	}

	pthread_mutex_init(&context->m_log_ringbuf_critical, NULL);
	pthread_mutex_init(&context->m_imapidle_condmutex, NULL);
	pthread_mutex_init(&context->m_smtpidle_condmutex, NULL);
	pthread_cond_init(&context->m_smtpidle_cond, NULL);

	context->m_magic    = DC_CONTEXT_MAGIC;
	context->m_sql      = dc_sqlite3_new(context);
	context->m_cb       = cb? cb : cb_dummy;
	context->m_userdata = userdata;
	context->m_imap     = dc_imap_new(cb_get_config, cb_set_config, cb_receive_imf, (void*)context, context);
	context->m_smtp     = dc_smtp_new(context);
	context->m_os_name  = dc_strdup_keep_null(os_name);

	dc_pgp_init(context);

	/* Random-seed.  An additional seed with more random data is done just before key generation
	(the timespan between this call and the key generation time is typically random.
	Moreover, later, we add a hash of the first message data to the random-seed
	(it would be okay to seed with even more sensible data, the seed values cannot be recovered from the PRNG output, see OpenSSL's RAND_seed() ) */
	{
	uintptr_t seed[5];
	seed[0] = (uintptr_t)time(NULL);     /* time */
	seed[1] = (uintptr_t)seed;           /* stack */
	seed[2] = (uintptr_t)context;            /* heap */
	seed[3] = (uintptr_t)pthread_self(); /* thread ID */
	seed[4] = (uintptr_t)getpid();       /* process ID */
	dc_pgp_rand_seed(context, seed, sizeof(seed));
	}

	if( s_localize_mb_obj==NULL ) {
		s_localize_mb_obj = context;
	}

	return context;
}


/**
 * Free a context object.
 * If app runs can only be terminated by a forced kill, this may be superfluous.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @return none
 */
void dc_context_unref(dc_context_t* context)
{
	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
	}

	dc_pgp_exit(context);

	if( dc_is_open(context) ) {
		dc_close(context);
	}

	dc_imap_unref(context->m_imap);
	dc_smtp_unref(context->m_smtp);
	dc_sqlite3_unref(context->m_sql);

	pthread_mutex_destroy(&context->m_log_ringbuf_critical);
	pthread_mutex_destroy(&context->m_imapidle_condmutex);
	pthread_cond_destroy(&context->m_smtpidle_cond);
	pthread_mutex_destroy(&context->m_smtpidle_condmutex);

	for( int i = 0; i < DC_LOG_RINGBUF_SIZE; i++ ) {
		free(context->m_log_ringbuf[i]);
	}

	free(context->m_os_name);
	context->m_magic = 0;
	free(context);

	if( s_localize_mb_obj==context ) {
		s_localize_mb_obj = NULL;
	}
}


/**
 * Get user data associated with a context object.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @return User data, this is the second parameter given to dc_context_new().
 */
void* dc_get_userdata(dc_context_t* context)
{
	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return NULL;
	}
	return context->m_userdata;
}


static void update_config_cache(dc_context_t* context, const char* key)
{
	if( key==NULL || strcmp(key, "e2ee_enabled")==0 ) {
		context->m_e2ee_enabled = dc_sqlite3_get_config_int(context->m_sql, "e2ee_enabled", DC_E2EE_DEFAULT_ENABLED);
	}
}


/**
 * Open context database.  If the given file does not exist, it is
 * created and can be set up using dc_set_config() afterwards.
 *
 * @memberof dc_context_t
 * @param context: the context object as created by dc_context_new()
 * @param dbfile the file to use to store the database, sth. like "~/file" won't
 *     work on all systems, if in doubt, use absolute paths.
 * @param blobdir a directory to store the blobs in, the trailing slash is added
 *     by us, so if you want to avoid double slashes, do not add one. If you
 *     give NULL as blobdir, `dbfile-blobs` is used in the same directory as
 *     _dbfile_ will be created in.
 * @return 1 on success, 0 on failure
 */
int dc_open(dc_context_t* context, const char* dbfile, const char* blobdir)
{
	int success = 0;
	int db_locked = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || dbfile == NULL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	db_locked = 1;

		/* Open() sets up the object and connects to the given database
		from which all configuration is read/written to. */

		/* Create/open sqlite database */
		if( !dc_sqlite3_open__(context->m_sql, dbfile, 0) ) {
			goto cleanup;
		}

		/* backup dbfile name */
		context->m_dbfile = dc_strdup(dbfile);

		/* set blob-directory
		(to avoid double slashed, the given directory should not end with an slash) */
		if( blobdir && blobdir[0] ) {
			context->m_blobdir = dc_strdup(blobdir);
		}
		else {
			context->m_blobdir = dc_mprintf("%s-blobs", dbfile);
			dc_create_folder(context->m_blobdir, context);
		}

		update_config_cache(context, NULL);

		success = 1;

cleanup:
		if( !success ) {
			if( dc_sqlite3_is_open(context->m_sql) ) {
				dc_sqlite3_close__(context->m_sql);
			}
		}

	if( db_locked ) { dc_sqlite3_unlock(context->m_sql); }

	return success;
}


/**
 * Close context database.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new()
 * @return none
 */
void dc_close(dc_context_t* context)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
	}

	dc_imap_disconnect(context->m_imap);
	dc_smtp_disconnect(context->m_smtp);

	dc_sqlite3_lock(context->m_sql);

		if( dc_sqlite3_is_open(context->m_sql) ) {
			dc_sqlite3_close__(context->m_sql);
		}

		free(context->m_dbfile);
		context->m_dbfile = NULL;

		free(context->m_blobdir);
		context->m_blobdir = NULL;

	dc_sqlite3_unlock(context->m_sql);
}


/**
 * Check if the context database is open.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @return 0=context is not open, 1=context is open.
 */
int dc_is_open(const dc_context_t* context)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return 0; /* error - database not opened */
	}

	return dc_sqlite3_is_open(context->m_sql);
}


/**
 * Get the blob directory.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @return Blob directory associated with the context object, empty string if unset or on errors. NULL is never returned.
 *     The returned string must be free()'d.
 */
char* dc_get_blobdir(dc_context_t* context)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return dc_strdup(NULL);
	}
	return dc_strdup(context->m_blobdir);
}


/*******************************************************************************
 * INI-handling, Information
 ******************************************************************************/


/**
 * Configure the context.  The configuration is handled by key=value pairs. Typical configuration options are:
 *
 * - addr         = address to display (needed)
 * - mail_server  = IMAP-server, guessed if left out
 * - mail_user    = IMAP-username, guessed if left out
 * - mail_pw      = IMAP-password (needed)
 * - mail_port    = IMAP-port, guessed if left out
 * - send_server  = SMTP-server, guessed if left out
 * - send_user    = SMTP-user, guessed if left out
 * - send_pw      = SMTP-password, guessed if left out
 * - send_port    = SMTP-port, guessed if left out
 * - server_flags = IMAP-/SMTP-flags, guessed if left out
 * - displayname  = Own name to use when sending messages.  MUAs are allowed to spread this way eg. using CC, defaults to empty
 * - selfstatus   = Own status to display eg. in email footers, defaults to a standard text
 * - e2ee_enabled = 0=no e2ee, 1=prefer encryption (default)
 *
 * @memberof dc_context_t
 * @param context the context object
 * @param key the option to change, typically one of the strings listed above
 * @param value the value to save for "key"
 * @return 0=failure, 1=success
 */
int dc_set_config(dc_context_t* context, const char* key, const char* value)
{
	int ret;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || key == NULL ) { /* "value" may be NULL */
		return 0;
	}

	ret = dc_sqlite3_set_config(context->m_sql, key, value);
	update_config_cache(context, key);

	return ret;
}


/**
 * Get a configuration option.  The configuration option is typically set by dc_set_config() or by the library itself.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new()
 * @param key the key to query
 * @param def default value to return if "key" is unset
 * @return Returns current value of "key", if "key" is unset, "def" is returned (which may be NULL)
 *     If the returned values is not NULL, the return value must be free()'d,
 */
char* dc_get_config(dc_context_t* context, const char* key, const char* def)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || key == NULL ) { /* "def" may be NULL */
		return dc_strdup_keep_null(def);
	}

	return dc_sqlite3_get_config(context->m_sql, key, def);
}


/**
 * Configure the context.  Similar to dc_set_config() but sets an integer instead of a string.
 * If there is already a key with a string set, this is overwritten by the given integer value.
 *
 * @memberof dc_context_t
 */
int dc_set_config_int(dc_context_t* context, const char* key, int32_t value)
{
	int ret;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || key == NULL ) {
		return 0;
	}

	ret = dc_sqlite3_set_config_int(context->m_sql, key, value);
	update_config_cache(context, key);

	return ret;
}


/**
 * Get a configuration option. Similar as dc_get_config() but gets the value as an integer instead of a string.
 *
 * @memberof dc_context_t
 */
int32_t dc_get_config_int(dc_context_t* context, const char* key, int32_t def)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || key == NULL ) {
		return def;
	}

	return dc_sqlite3_get_config_int(context->m_sql, key, def);
}


/**
 * Find out the version of the Delta Chat core library.
 *
 * @memberof dc_context_t
 * @return String with version number as `major.minor.revision`. The return value must be free()'d.
 */
char* dc_get_version_str(void)
{
	return dc_strdup(DC_VERSION_STR);
}


/**
 * Get information about the context.  The information is returned by a multi-line string and contains information about the current
 * configuration and the last log entries.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @return String which must be free()'d after usage.  Never returns NULL.
 */
char* dc_get_info(dc_context_t* context)
{
	const char      *unset = "0";
	char            *displayname = NULL, *temp = NULL, *l_readable_str = NULL, *l2_readable_str = NULL, *fingerprint_str = NULL;
	dc_loginparam_t *l = NULL, *l2 = NULL;
	int             contacts, chats, real_msgs, deaddrop_msgs, is_configured, dbversion, mdns_enabled, e2ee_enabled, prv_key_count, pub_key_count;
	dc_key_t        *self_public = dc_key_new();

	dc_strbuilder_t  ret;
	dc_strbuilder_init(&ret, 0);

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return dc_strdup("ErrBadPtr");
	}

	/* read data (all pointers may be NULL!) */
	l = dc_loginparam_new();
	l2 = dc_loginparam_new();

	dc_sqlite3_lock(context->m_sql);

		dc_loginparam_read(l, context->m_sql, "");
		dc_loginparam_read(l2, context->m_sql, "configured_" /*the trailing underscore is correct*/);

		displayname     = dc_sqlite3_get_config(context->m_sql, "displayname", NULL);

		chats           = dc_get_chat_cnt(context);
		real_msgs       = dc_get_real_msg_cnt(context);
		deaddrop_msgs   = dc_get_deaddrop_msg_cnt(context);
		contacts        = dc_get_real_contact_cnt(context);

		is_configured   = dc_sqlite3_get_config_int(context->m_sql, "configured", 0);

		dbversion       = dc_sqlite3_get_config_int(context->m_sql, "dbversion", 0);

		e2ee_enabled    = context->m_e2ee_enabled;

		mdns_enabled    = dc_sqlite3_get_config_int(context->m_sql, "mdns_enabled", DC_MDNS_DEFAULT_ENABLED);

		sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql, "SELECT COUNT(*) FROM keypairs;");
		sqlite3_step(stmt);
		prv_key_count = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);

		stmt = dc_sqlite3_prepare(context->m_sql, "SELECT COUNT(*) FROM acpeerstates;");
		sqlite3_step(stmt);
		pub_key_count = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);

		if( dc_key_load_self_public(self_public, l2->m_addr, context->m_sql) ) {
			fingerprint_str = dc_key_get_formatted_fingerprint(self_public);
		}
		else {
			fingerprint_str = dc_strdup("<Not yet calculated>");
		}

	dc_sqlite3_unlock(context->m_sql);

	l_readable_str = dc_loginparam_get_readable(l);
	l2_readable_str = dc_loginparam_get_readable(l2);

	/* create info
	- some keys are display lower case - these can be changed using the `set`-command
	- we do not display the password here; in the cli-utility, you can see it using `get mail_pw`
	- use neutral speach; the Delta Chat Core is not directly related to any front end or end-product
	- contributors: You're welcome to add your names here */
	temp = dc_mprintf(
		"Chats: %i\n"
		"Chat messages: %i\n"
		"Messages in context requests: %i\n"
		"Contacts: %i\n"
		"Database=%s, dbversion=%i, Blobdir=%s\n"
		"\n"
		"displayname=%s\n"
		"configured=%i\n"
		"config0=%s\n"
		"config1=%s\n"
		"mdns_enabled=%i\n"
		"e2ee_enabled=%i\n"
		"E2EE_DEFAULT_ENABLED=%i\n"
		"Private keys=%i, public keys=%i, fingerprint=\n%s\n"
		"\n"
		"Using Delta Chat Core v%s, SQLite %s-ts%i, libEtPan %i.%i, OpenSSL %i.%i.%i%c. Compiled " __DATE__ ", " __TIME__ " for %i bit usage.\n\n"
		"Log excerpt:\n"
		/* In the frontends, additional software hints may follow here. */

		, chats, real_msgs, deaddrop_msgs, contacts
		, context->m_dbfile? context->m_dbfile : unset,   dbversion,   context->m_blobdir? context->m_blobdir : unset

        , displayname? displayname : unset
		, is_configured
		, l_readable_str, l2_readable_str

		, mdns_enabled

		, e2ee_enabled
		, DC_E2EE_DEFAULT_ENABLED
		, prv_key_count, pub_key_count, fingerprint_str

		, DC_VERSION_STR
		, SQLITE_VERSION, sqlite3_threadsafe()   ,  libetpan_get_version_major(), libetpan_get_version_minor()
		, (int)(OPENSSL_VERSION_NUMBER>>28), (int)(OPENSSL_VERSION_NUMBER>>20)&0xFF, (int)(OPENSSL_VERSION_NUMBER>>12)&0xFF, (char)('a'-1+((OPENSSL_VERSION_NUMBER>>4)&0xFF))
		, sizeof(void*)*8

		);
	dc_strbuilder_cat(&ret, temp);
	free(temp);

	/* add log excerpt */
	pthread_mutex_lock(&context->m_log_ringbuf_critical); /*take care not to log here! */
		for( int i = 0; i < DC_LOG_RINGBUF_SIZE; i++ ) {
			int j = (context->m_log_ringbuf_pos+i) % DC_LOG_RINGBUF_SIZE;
			if( context->m_log_ringbuf[j] ) {
				struct tm wanted_struct;
				memcpy(&wanted_struct, localtime(&context->m_log_ringbuf_times[j]), sizeof(struct tm));
				temp = dc_mprintf("\n%02i:%02i:%02i ", (int)wanted_struct.tm_hour, (int)wanted_struct.tm_min, (int)wanted_struct.tm_sec);
					dc_strbuilder_cat(&ret, temp);
					dc_strbuilder_cat(&ret, context->m_log_ringbuf[j]);
				free(temp);
			}
		}
	pthread_mutex_unlock(&context->m_log_ringbuf_critical);

	/* free data */
	dc_loginparam_unref(l);
	dc_loginparam_unref(l2);
	free(displayname);
	free(l_readable_str);
	free(l2_readable_str);
	free(fingerprint_str);
	dc_key_unref(self_public);
	return ret.m_buf; /* must be freed by the caller */
}


/*******************************************************************************
 * Handle chatlists
 ******************************************************************************/


int dc_get_archived_count(dc_context_t* context)
{
	int ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM chats WHERE blocked=0 AND archived=1;");
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = sqlite3_column_int(stmt, 0);
	}
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get a list of chats. The list can be filtered by query parameters.
 * To get the chat messages, use dc_get_chat_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned by dc_context_new()
 * @param listflags A combination of flags:
 *     - if the flag DC_GCL_ARCHIVED_ONLY is set, only archived chats are returned.
 *       if DC_GCL_ARCHIVED_ONLY is not set, only unarchived chats are returned and
 *       the pseudo-chat DC_CHAT_ID_ARCHIVED_LINK is added if there are _any_ archived
 *       chats
 *     - if the flag DC_GCL_NO_SPECIALS is set, deaddrop and archive link are not added
 *       to the list (may be used eg. for selecting chats on forwarding, the flag is
 *       not needed when DC_GCL_ARCHIVED_ONLY is already set)
 * @param query_str An optional query for filtering the list.  Only chats matching this query
 *     are returned.  Give NULL for no filtering.
 * @param query_id An optional contact ID for filtering the list.  Only chats including this contact ID
 *     are returned.  Give 0 for no filtering.
 * @return A chatlist as an dc_chatlist_t object. Must be freed using
 *     dc_chatlist_unref() when no longer used
 */
dc_chatlist_t* dc_get_chatlist(dc_context_t* context, int listflags, const char* query_str, uint32_t query_id)
{
	int            success = 0;
	dc_chatlist_t* obj = dc_chatlist_new(context);

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	if( !dc_chatlist_load_from_db(obj, listflags, query_str, query_id) ) {
		goto cleanup;
	}

	success = 1;

cleanup:
	if( success ) {
		return obj;
	}
	else {
		dc_chatlist_unref(obj);
		return NULL;
	}
}


/*******************************************************************************
 * Handle chats
 ******************************************************************************/


/**
 * Get chat object by a chat ID.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to get the chat object for.
 * @return A chat object of the type dc_chat_t, must be freed using dc_chat_unref() when done.
 */
dc_chat_t* dc_get_chat(dc_context_t* context, uint32_t chat_id)
{
	int        success = 0;
	int        db_locked = 0;
	dc_chat_t* obj = dc_chat_new(context);

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	db_locked = 1;

		if( !dc_chat_load_from_db(obj, chat_id) ) {
			goto cleanup;
		}

		success = 1;

cleanup:
	if( db_locked ) { dc_sqlite3_unlock(context->m_sql); }

	if( success ) {
		return obj;
	}
	else {
		dc_chat_unref(obj);
		return NULL;
	}
}


/**
 * Mark all messages in a chat as _noticed_.
 * _Noticed_ messages are no longer _fresh_ and do not count as being unseen.
 * IMAP/MDNs is not done for noticed messages.  See also dc_marknoticed_contact()
 * and dc_markseen_msgs()
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which all messages should be marked as being noticed.
 * @return None.
 */
void dc_marknoticed_chat(dc_context_t* context, uint32_t chat_id)
{
	/* marking a chat as "seen" is done by marking all fresh chat messages as "noticed" -
	"noticed" messages are not counted as being unread but are still waiting for being marked as "seen" using dc_markseen_msgs() */
	sqlite3_stmt* stmt;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE msgs SET state=" DC_STRINGIFY(DC_STATE_IN_NOTICED) " WHERE chat_id=? AND state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


/**
 * Check, if there is a normal chat with a given contact.
 * To get the chat messages, use dc_get_chat_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param contact_id The contact ID to check.
 * @return If there is a normal chat with the given contact_id, this chat_id is
 *     returned.  If there is no normal chat with the contact_id, the function
 *     returns 0.
 */
uint32_t dc_get_chat_id_by_contact_id(dc_context_t* context, uint32_t contact_id)
{
	uint32_t chat_id = 0;
	int      chat_id_blocked = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return 0;
	}

	dc_lookup_real_nchat_by_contact_id(context, contact_id, &chat_id, &chat_id_blocked);

	return chat_id_blocked? 0 : chat_id; /* from outside view, chats only existing in the deaddrop do not exist */
}


uint32_t dc_get_chat_id_by_grpid(dc_context_t* context, const char* grpid, int* ret_blocked, int* ret_verified)
{
	uint32_t      chat_id = 0;
	sqlite3_stmt* stmt = NULL;

	if(ret_blocked)  { *ret_blocked = 0;  }
	if(ret_verified) { *ret_verified = 0; }

	if( context == NULL || grpid == NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id, blocked, type FROM chats WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt)==SQLITE_ROW ) {
		                    chat_id      =  sqlite3_column_int(stmt, 0);
		if(ret_blocked)  { *ret_blocked  =  sqlite3_column_int(stmt, 1); }
		if(ret_verified) { *ret_verified = (sqlite3_column_int(stmt, 2)==DC_CHAT_TYPE_VERIFIED_GROUP); }
	}

cleanup:
	sqlite3_finalize(stmt);
	return chat_id;
}


/**
 * Create a normal chat with a single user.  To create group chats,
 * see dc_create_group_chat().
 *
 * If there is already an exitant chat, this ID is returned and no new chat is
 * crated.  If there is no existant chat with the user, a new chat is created;
 * this new chat may already contain messages, eg. from the deaddrop, to get the
 * chat messages, use dc_get_chat_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param contact_id The contact ID to create the chat for.  If there is already
 *     a chat with this contact, the already existing ID is returned.
 * @return The created or reused chat ID on success. 0 on errors.
 */
uint32_t dc_create_chat_by_contact_id(dc_context_t* context, uint32_t contact_id)
{
	uint32_t      chat_id = 0;
	int           chat_blocked = 0;
	int           send_event = 0, locked = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return 0;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		dc_lookup_real_nchat_by_contact_id(context, contact_id, &chat_id, &chat_blocked);
		if( chat_id ) {
			if( chat_blocked ) {
				dc_unblock_chat(context, chat_id); /* unblock chat (typically move it from the deaddrop to view) */
				send_event = 1;
			}
			goto cleanup; /* success */
		}

        if( 0==dc_real_contact_exists__(context, contact_id) && contact_id!=DC_CONTACT_ID_SELF ) {
			dc_log_warning(context, 0, "Cannot create chat, contact %i does not exist.", (int)contact_id);
			goto cleanup;
        }

		dc_create_or_lookup_nchat_by_contact_id(context, contact_id, DC_CHAT_NOT_BLOCKED, &chat_id, NULL);
		if( chat_id ) {
			send_event = 1;
		}

		dc_scaleup_contact_origin(context, contact_id, DC_ORIGIN_CREATE_CHAT);

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }

	if( send_event ) {
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
	}

	return chat_id;
}


/**
 * Create a normal chat or a group chat by a messages ID that comes typically
 * from the deaddrop, DC_CHAT_ID_DEADDROP (1).
 *
 * If the given message ID already belongs to a normal chat or to a group chat,
 * the chat ID of this chat is returned and no new chat is created.
 * If a new chat is created, the given message ID is moved to this chat, however,
 * there may be more messages moved to the chat from the deaddrop. To get the
 * chat messages, use dc_get_chat_msgs().
 *
 * If the user should be start asked the chat is created, he should just be
 * asked whether he wants to chat with the _contact_ belonging to the message;
 * the group names may be really weired when take from the subject of implicit
 * groups and this may look confusing.
 *
 * Moreover, this function also scales up the origin of the contact belonging
 * to the message and, depending on the contacts origin, messages from the
 * same group may be shown or not - so, all in all, it is fine to show the
 * contact name only.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param msg_id The message ID to create the chat for.
 * @return The created or reused chat ID on success. 0 on errors.
 */
uint32_t dc_create_chat_by_msg_id(dc_context_t* context, uint32_t msg_id)
{
	uint32_t  chat_id    = 0;
	int       send_event = 0;
	dc_msg_t*  msg        = dc_msg_new();
	dc_chat_t* chat       = dc_chat_new(context);

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	if( !dc_msg_load_from_db(msg, context, msg_id)
	 || !dc_chat_load_from_db(chat, msg->m_chat_id)
	 || chat->m_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	chat_id = chat->m_id;

	if( chat->m_blocked ) {
		dc_unblock_chat(context, chat->m_id);
		send_event = 1;
	}

	dc_scaleup_contact_origin(context, msg->m_from_id, DC_ORIGIN_CREATE_CHAT);

cleanup:
	dc_msg_unref(msg);
	dc_chat_unref(chat);
	if( send_event ) {
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
	}
	return chat_id;
}


/**
 * Returns all message IDs of the given types in a chat.  Typically used to show
 * a gallery.  The result must be dc_array_unref()'d
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID to get all messages with media from.
 * @param msg_type Specify a message type to query here, one of the DC_MSG_* constats.
 * @param or_msg_type Another message type to return, one of the DC_MSG_* constats.
 *     The function will return both types then.  0 if you need only one.
 * @return An array with messages from the given chat ID that have the wanted message types.
 */
dc_array_t* dc_get_chat_media(dc_context_t* context, uint32_t chat_id, int msg_type, int or_msg_type)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return NULL;
	}

	dc_array_t* ret = dc_array_new(context, 100);

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id FROM msgs WHERE chat_id=? AND (type=? OR type=?) ORDER BY timestamp, id;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_type);
	sqlite3_bind_int(stmt, 3, or_msg_type>0? or_msg_type : msg_type);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}
	sqlite3_finalize(stmt);

	return ret;
}


/**
 * Get next/previous message of the same type.
 * Typically used to implement the "next" and "previous" buttons on a media
 * player playing eg. voice messages.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param curr_msg_id  This is the current (image) message displayed.
 * @param dir 1=get the next (image) message, -1=get the previous one.
 * @return Returns the message ID that should be played next. The
 *     returned message is in the same chat as the given one and has the same type.
 *     Typically, this result is passed again to dc_get_next_media()
 *     later on the next swipe. If there is not next/previous message, the function returns 0.
 */
uint32_t dc_get_next_media(dc_context_t* context, uint32_t curr_msg_id, int dir)
{
	uint32_t    ret_msg_id = 0;
	dc_msg_t*   msg = dc_msg_new();
	int         locked = 0;
	dc_array_t* list = NULL;
	int         i, cnt;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		if( !dc_msg_load_from_db(msg, context, curr_msg_id) ) {
			goto cleanup;
		}

		if( (list=dc_get_chat_media(context, msg->m_chat_id, msg->m_type, 0))==NULL ) {
			goto cleanup;
		}

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	cnt = dc_array_get_cnt(list);
	for( i = 0; i < cnt; i++ ) {
		if( curr_msg_id == dc_array_get_id(list, i) )
		{
			if( dir > 0 ) {
				/* get the next message from the current position */
				if( i+1 < cnt ) {
					ret_msg_id = dc_array_get_id(list, i+1);
				}
			}
			else if( dir < 0 ) {
				/* get the previous message from the current position */
				if( i-1 >= 0 ) {
					ret_msg_id = dc_array_get_id(list, i-1);
				}
			}
			break;
		}
	}


cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	dc_array_unref(list);
	dc_msg_unref(msg);
	return ret_msg_id;
}


/**
 * Get contact IDs belonging to a chat.
 *
 * - for normal chats, the function always returns exactly one contact,
 *   DC_CONTACT_ID_SELF is _not_ returned.
 *
 * - for group chats all members are returned, DC_CONTACT_ID_SELF is returned
 *   explicitly as it may happen that oneself gets removed from a still existing
 *   group
 *
 * - for the deaddrop, all contacts are returned, DC_CONTACT_ID_SELF is not
 *   added
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to get the belonging contact IDs for.
 * @return an array of contact IDs belonging to the chat; must be freed using dc_array_unref() when done.
 */
dc_array_t* dc_get_chat_contacts(dc_context_t* context, uint32_t chat_id)
{
	/* Normal chats do not include SELF.  Group chats do (as it may happen that one is deleted from a
	groupchat but the chats stays visible, moreover, this makes displaying lists easier) */
	dc_array_t*   ret = dc_array_new(context, 100);
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	if( chat_id == DC_CHAT_ID_DEADDROP ) {
		goto cleanup; /* we could also create a list for all contacts in the deaddrop by searching contacts belonging to chats with chats.blocked=2, however, currently this is not needed */
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT cc.contact_id FROM chats_contacts cc"
			" LEFT JOIN contacts c ON c.id=cc.contact_id"
			" WHERE cc.chat_id=?"
			" ORDER BY c.id=1, LOWER(c.name||c.addr), c.id;");
	sqlite3_bind_int(stmt, 1, chat_id);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Returns the message IDs of all _fresh_ messages of any chat. Typically used for implementing
 * notification summaries.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @return Array of message IDs, must be dc_array_unref()'d when no longer used.
 */
dc_array_t* dc_get_fresh_msgs(dc_context_t* context)
{
	int           show_deaddrop, success = 0;
	dc_array_t*   ret = dc_array_new(context, 128);
	sqlite3_stmt* stmt = NULL;

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || ret == NULL ) {
		goto cleanup;
	}

	show_deaddrop = 0;//dc_sqlite3_get_config_int__(context->m_sql, "show_deaddrop", 0);

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT m.id"
			" FROM msgs m"
			" LEFT JOIN contacts ct ON m.from_id=ct.id"
			" LEFT JOIN chats c ON m.chat_id=c.id"
			" WHERE m.state=" DC_STRINGIFY(DC_STATE_IN_FRESH) " AND ct.blocked=0 AND (c.blocked=0 OR c.blocked=?)"
			" ORDER BY m.timestamp DESC,m.id DESC;"); /* the list starts with the newest messages*/
	sqlite3_bind_int(stmt, 1, show_deaddrop? DC_CHAT_DEADDROP_BLOCKED : 0);

	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

	success = 1;

cleanup:
	sqlite3_finalize(stmt);

	if( success ) {
		return ret;
	}
	else {
		if( ret ) {
			dc_array_unref(ret);
		}
		return NULL;
	}
}


/**
 * Get all message IDs belonging to a chat.
 * Optionally, some special markers added to the ID-array may help to
 * implement virtual lists.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which the messages IDs should be queried.
 * @param flags If set to DC_GCM_ADD_DAY_MARKER, the marker DC_MSG_ID_DAYMARKER will
 *     be added before each day (regarding the local timezone).  Set this to 0 if you do not want this behaviour.
 * @param marker1before An optional message ID.  If set, the id DC_MSG_ID_MARKER1 will be added just
 *   before the given ID in the returned array.  Set this to 0 if you do not want this behaviour.
 * @return Array of message IDs, must be dc_array_unref()'d when no longer used.
 */
dc_array_t* dc_get_chat_msgs(dc_context_t* context, uint32_t chat_id, uint32_t flags, uint32_t marker1before)
{
	//clock_t       start = clock();

	int           success = 0;
	dc_array_t*   ret = dc_array_new(context, 512);
	sqlite3_stmt* stmt = NULL;

	uint32_t      curr_id;
	time_t        curr_local_timestamp;
	int           curr_day, last_day = 0;
	long          cnv_to_local = dc_gm2local_offset();
	#define       SECONDS_PER_DAY 86400

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || ret == NULL ) {
		goto cleanup;
	}

	if( chat_id == DC_CHAT_ID_DEADDROP )
	{
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				" LEFT JOIN chats ON m.chat_id=chats.id"
				" LEFT JOIN contacts ON m.from_id=contacts.id"
				" WHERE m.from_id!=" DC_STRINGIFY(DC_CONTACT_ID_SELF)
				"   AND m.hidden=0 "
				"   AND chats.blocked=" DC_STRINGIFY(DC_CHAT_DEADDROP_BLOCKED)
				"   AND contacts.blocked=0"
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
	}
	else if( chat_id == DC_CHAT_ID_STARRED )
	{
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.starred=1 "
				"   AND m.hidden=0 "
				"   AND ct.blocked=0"
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
	}
	else
	{
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				//" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.chat_id=? "
				"   AND m.hidden=0 "
				//"   AND ct.blocked=0" -- we hide blocked-contacts from starred and deaddrop, but we have to show them in groups (otherwise it may be hard to follow conversation, wa and tg do the same. however, maybe this needs discussion some time :)
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
		sqlite3_bind_int(stmt, 1, chat_id);
	}

	while( sqlite3_step(stmt) == SQLITE_ROW )
	{
		curr_id = sqlite3_column_int(stmt, 0);

		/* add user marker */
		if( curr_id == marker1before ) {
			dc_array_add_id(ret, DC_MSG_ID_MARKER1);
		}

		/* add daymarker, if needed */
		if( flags&DC_GCM_ADDDAYMARKER ) {
			curr_local_timestamp = (time_t)sqlite3_column_int64(stmt, 1) + cnv_to_local;
			curr_day = curr_local_timestamp/SECONDS_PER_DAY;
			if( curr_day != last_day ) {
				dc_array_add_id(ret, DC_MSG_ID_DAYMARKER);
				last_day = curr_day;
			}
		}

		dc_array_add_id(ret, curr_id);
	}

	success = 1;

cleanup:
	sqlite3_finalize(stmt);

	//dc_log_info(context, 0, "Message list for chat #%i created in %.3f ms.", chat_id, (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	if( success ) {
		return ret;
	}
	else {
		if( ret ) {
			dc_array_unref(ret);
		}
		return NULL;
	}
}


/**
 * Search messages containing the given query string.
 * Searching can be done globally (chat_id=0) or in a specified chat only (chat_id
 * set).
 *
 * Global chat results are typically displayed using dc_msg_get_summary(), chat
 * search results may just hilite the corresponding messages and present a
 * prev/next button.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id ID of the chat to search messages in.
 *     Set this to 0 for a global search.
 * @param query The query to search for.
 * @return An array of message IDs. Must be freed using dc_array_unref() when no longer needed.
 *     If nothing can be found, the function returns NULL.
 */
dc_array_t* dc_search_msgs(dc_context_t* context, uint32_t chat_id, const char* query)
{
	//clock_t       start = clock();

	int           success = 0;
	dc_array_t*   ret = dc_array_new(context, 100);
	char*         strLikeInText = NULL, *strLikeBeg=NULL, *real_query = NULL;
	sqlite3_stmt* stmt = NULL;

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || ret == NULL || query == NULL ) {
		goto cleanup;
	}

	real_query = dc_strdup(query);
	dc_trim(real_query);
	if( real_query[0]==0 ) {
		success = 1; /*empty result*/
		goto cleanup;
	}

	strLikeInText = dc_mprintf("%%%s%%", real_query);
	strLikeBeg = dc_mprintf("%s%%", real_query); /*for the name search, we use "Name%" which is fast as it can use the index ("%Name%" could not). */

	/* Incremental search with "LIKE %query%" cannot take advantages from any index
	("query%" could for COLLATE NOCASE indexes, see http://www.sqlite.org/optoverview.html#like_opt )
	An alternative may be the FULLTEXT sqlite stuff, however, this does not really help with incremental search.
	An extra table with all words and a COLLATE NOCASE indexes may help, however,
	this must be updated all the time and probably consumes more time than we can save in tenthousands of searches.
	For now, we just expect the following query to be fast enough :-) */
	if( chat_id ) {
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.id, m.timestamp FROM msgs m"
			" LEFT JOIN contacts ct ON m.from_id=ct.id"
			" WHERE m.chat_id=? "
				" AND m.hidden=0 "
				" AND ct.blocked=0 AND (txt LIKE ? OR ct.name LIKE ?)"
			" ORDER BY m.timestamp,m.id;"); /* chats starts with the oldest message*/
		sqlite3_bind_int (stmt, 1, chat_id);
		sqlite3_bind_text(stmt, 2, strLikeInText, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, strLikeBeg, -1, SQLITE_STATIC);
	}
	else {
		int show_deaddrop = 0;//dc_sqlite3_get_config_int__(context->m_sql, "show_deaddrop", 0);
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.id, m.timestamp FROM msgs m"
			" LEFT JOIN contacts ct ON m.from_id=ct.id"
			" LEFT JOIN chats c ON m.chat_id=c.id"
			" WHERE m.chat_id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL)
				" AND m.hidden=0 "
				" AND (c.blocked=0 OR c.blocked=?)"
				" AND ct.blocked=0 AND (m.txt LIKE ? OR ct.name LIKE ?)"
			" ORDER BY m.timestamp DESC,m.id DESC;"); /* chat overview starts with the newest message*/
		sqlite3_bind_int (stmt, 1, show_deaddrop? DC_CHAT_DEADDROP_BLOCKED : 0);
		sqlite3_bind_text(stmt, 2, strLikeInText, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, strLikeBeg, -1, SQLITE_STATIC);
	}

	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

	success = 1;

cleanup:
	free(strLikeInText);
	free(strLikeBeg);
	free(real_query);
	sqlite3_finalize(stmt);

	//dc_log_info(context, 0, "Message list for search \"%s\" in chat #%i created in %.3f ms.", query, chat_id, (double)(clock()-start)*1000.0/CLOCKS_PER_SEC);

	if( success ) {
		return ret;
	}
	else {
		if( ret ) {
			dc_array_unref(ret);
		}
		return NULL;
	}
}


/**
 * Save a draft for a chat.
 *
 * To get the draft for a given chat ID, use dc_chat_get_draft().
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to save the draft for.
 * @param msg The message text to save as a draft.
 * @return None.
 */
void dc_set_draft(dc_context_t* context, uint32_t chat_id, const char* msg)
{
	sqlite3_stmt* stmt = NULL;
	dc_chat_t*    chat = NULL;

	if (context==NULL || context->m_magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if ((chat=dc_get_chat(context, chat_id))==NULL) {
		goto cleanup;
	}

	if (msg && msg[0]==0) {
		msg = NULL; // an empty draft is no draft
	}

	if (chat->m_draft_text==NULL && msg==NULL
	 && chat->m_draft_timestamp==0) {
		goto cleanup; // nothing to do - there is no old and no new draft
	}

	if (chat->m_draft_timestamp && chat->m_draft_text && msg && strcmp(chat->m_draft_text, msg)==0) {
		goto cleanup; // for equal texts, we do not update the timestamp
	}

	// save draft in object - NULL or empty: clear draft
	free(chat->m_draft_text);
	chat->m_draft_text      = msg? dc_strdup(msg) : NULL;
	chat->m_draft_timestamp = msg? time(NULL) : 0;

	// save draft in database
	stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE chats SET draft_timestamp=?, draft_txt=? WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, chat->m_draft_timestamp);
	sqlite3_bind_text (stmt, 2, chat->m_draft_text? chat->m_draft_text : "", -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt, 3, chat->m_id);
	sqlite3_step(stmt);

	context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);

cleanup:
	sqlite3_finalize(stmt);
	dc_chat_unref(chat);
}


uint32_t dc_get_last_deaddrop_fresh_msg(dc_context_t* context)
{
	uint32_t      ret = 0;
	sqlite3_stmt* stmt = NULL;

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT m.id "
		" FROM msgs m "
		" LEFT JOIN chats c ON c.id=m.chat_id "
		" WHERE m.state=" DC_STRINGIFY(DC_STATE_IN_FRESH)
		"   AND m.hidden=0 "
		"   AND c.blocked=" DC_STRINGIFY(DC_CHAT_DEADDROP_BLOCKED)
		" ORDER BY m.timestamp DESC, m.id DESC;"); /* we have an index over the state-column, this should be sufficient as there are typically only few fresh messages */

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


size_t dc_get_chat_cnt(dc_context_t* context)
{
	size_t        ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		goto cleanup; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM chats WHERE id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL) " AND blocked=0;");
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


void dc_lookup_real_nchat_by_contact_id(dc_context_t* context, uint32_t contact_id, uint32_t* ret_chat_id, int* ret_chat_blocked)
{
	/* checks for "real" chats or self-chat */
	sqlite3_stmt* stmt = NULL;

	if( ret_chat_id )      { *ret_chat_id = 0;      }
	if( ret_chat_blocked ) { *ret_chat_blocked = 0; }

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		return; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT c.id, c.blocked"
			" FROM chats c"
			" INNER JOIN chats_contacts j ON c.id=j.chat_id"
			" WHERE c.type=" DC_STRINGIFY(DC_CHAT_TYPE_SINGLE) " AND c.id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL) " AND j.contact_id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		if( ret_chat_id )      { *ret_chat_id      = sqlite3_column_int(stmt, 0); }
		if( ret_chat_blocked ) { *ret_chat_blocked = sqlite3_column_int(stmt, 1); }
	}
	sqlite3_finalize(stmt);
}


void dc_create_or_lookup_nchat_by_contact_id(dc_context_t* context, uint32_t contact_id, int create_blocked, uint32_t* ret_chat_id, int* ret_chat_blocked)
{
	uint32_t      chat_id = 0;
	int           chat_blocked = 0;
	dc_contact_t* contact = NULL;
	char*         chat_name;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if( ret_chat_id )      { *ret_chat_id = 0;      }
	if( ret_chat_blocked ) { *ret_chat_blocked = 0; }

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		return; /* database not opened - error */
	}

	if( contact_id == 0 ) {
		return;
	}

	dc_lookup_real_nchat_by_contact_id(context, contact_id, &chat_id, &chat_blocked);
	if( chat_id != 0 ) {
		if( ret_chat_id )      { *ret_chat_id      = chat_id;      }
		if( ret_chat_blocked ) { *ret_chat_blocked = chat_blocked; }
		return; /* soon success */
	}

	/* get fine chat name */
	contact = dc_contact_new(context);
	if( !dc_contact_load_from_db(contact, context->m_sql, contact_id) ) {
		goto cleanup;
	}

	chat_name = (contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_addr;

	/* create chat record */
	q = sqlite3_mprintf("INSERT INTO chats (type, name, param, blocked) VALUES(%i, %Q, %Q, %i)", DC_CHAT_TYPE_SINGLE, chat_name,
		contact_id==DC_CONTACT_ID_SELF? "K=1" : "", create_blocked);
	assert( DC_PARAM_SELFTALK == 'K' );
	stmt = dc_sqlite3_prepare(context->m_sql, q);
	if( stmt == NULL) {
		goto cleanup;
	}

    if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
    }

    chat_id = sqlite3_last_insert_rowid(context->m_sql->m_cobj);

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	/* add contact IDs to the new chat record (may be replaced by dc_add_to_chat_contacts_table__()) */
	q = sqlite3_mprintf("INSERT INTO chats_contacts (chat_id, contact_id) VALUES(%i, %i)", chat_id, contact_id);
	stmt = dc_sqlite3_prepare(context->m_sql, q);

	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
	}

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

cleanup:
	sqlite3_free(q);
	sqlite3_finalize(stmt);
	dc_contact_unref(contact);

	if( ret_chat_id )      { *ret_chat_id      = chat_id; }
	if( ret_chat_blocked ) { *ret_chat_blocked = create_blocked; }
}


void dc_unarchive_chat(dc_context_t* context, uint32_t chat_id)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
	    "UPDATE chats SET archived=0 WHERE id=?");
	sqlite3_bind_int (stmt, 1, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


/**
 * Get the total number of messages in a chat.
 *
 * @memberof dc_context_t
 *
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to count the messages for.
 * @return Number of total messages in the given chat. 0 for errors or empty chats.
 */
int dc_get_total_msg_count(dc_context_t* context, uint32_t chat_id)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get the number of _fresh_ messages in a chat.  Typically used to implement
 * a badge with a number in the chatlist.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to count the messages for.
 * @return Number of fresh messages in the given chat. 0 for errors or if there are no fresh messages.
 */
int dc_get_fresh_msg_count(dc_context_t* context, uint32_t chat_id)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs "
		" WHERE state=" DC_STRINGIFY(DC_STATE_IN_FRESH)
		"   AND hidden=0 "
		"   AND chat_id=?;"); /* we have an index over the state-column, this should be sufficient as there are typically only few fresh messages */
	sqlite3_bind_int(stmt, 1, chat_id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Archive or unarchive a chat.
 *
 * Archived chats are not included in the default chatlist returned
 * by dc_get_chatlist().  Instead, if there are _any_ archived chats,
 * the pseudo-chat with the chat_id DC_CHAT_ID_ARCHIVED_LINK will be added the the
 * end of the chatlist.
 *
 * - To get a list of archived chats, use dc_get_chatlist() with the flag DC_GCL_ARCHIVED_ONLY.
 * - To find out the archived state of a given chat, use dc_chat_get_archived()
 * - Calling this function usually results in the event #DC_EVENT_MSGS_CHANGED
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to archive or unarchive.
 * @param archive 1=archive chat, 0=unarchive chat, all other values are reserved for future use
 * @return None
 */
void dc_archive_chat(dc_context_t* context, uint32_t chat_id, int archive)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || (archive!=0 && archive!=1) ) {
		return;
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE chats SET archived=? WHERE id=?;");
	sqlite3_bind_int  (stmt, 1, archive);
	sqlite3_bind_int  (stmt, 2, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
}


/*******************************************************************************
 * Delete a chat
 ******************************************************************************/


/**
 * Delete a chat.
 *
 * Messages are deleted from the device and the chat database entry is deleted.
 * After that, the event #DC_EVENT_MSGS_CHANGED is posted.
 *
 * Things that are _not_ done implicitly:
 *
 * - Messages are **not deleted from the server**.
 * - The chat or the contact is **not blocked**, so new messages from the user/the group may appear
 *   and the user may create the chat again.
 * - **Groups are not left** - this would
 *   be unexpected as (1) deleting a normal chat also does not prevent new mails
 *   from arriving, (2) leaving a group requires sending a message to
 *   all group members - esp. for groups not used for a longer time, this is
 *   really unexpected when deletion results in contacting all members again,
 *   (3) only leaving groups is also a valid usecase.
 *
 * To leave a chat explicitly, use dc_remove_contact_from_chat() with
 * chat_id=DC_CONTACT_ID_SELF)
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to delete.
 * @return None
 */
void dc_delete_chat(dc_context_t* context, uint32_t chat_id)
{
	/* Up to 2017-11-02 deleting a group also implied leaving it, see above why we have changed this. */
	int        locked = 0, pending_transaction = 0;
	dc_chat_t* obj = dc_chat_new(context);
	char*      q3 = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

        if( !dc_chat_load_from_db(obj, chat_id) ) {
			goto cleanup;
        }

		dc_sqlite3_begin_transaction__(context->m_sql);
		pending_transaction = 1;

			q3 = sqlite3_mprintf("DELETE FROM msgs_mdns WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=%i);", chat_id);
			if( !dc_sqlite3_execute(context->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;

			q3 = sqlite3_mprintf("DELETE FROM msgs WHERE chat_id=%i;", chat_id);
			if( !dc_sqlite3_execute(context->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;

			q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i;", chat_id);
			if( !dc_sqlite3_execute(context->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;

			q3 = sqlite3_mprintf("DELETE FROM chats WHERE id=%i;", chat_id);
			if( !dc_sqlite3_execute(context->m_sql, q3) ) {
				goto cleanup;
			}
			sqlite3_free(q3);
			q3 = NULL;

		dc_sqlite3_commit__(context->m_sql);
		pending_transaction = 0;

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);

cleanup:
	if( pending_transaction ) { dc_sqlite3_rollback__(context->m_sql); }
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	dc_chat_unref(obj);
	sqlite3_free(q3);
}


/*******************************************************************************
 * Sending messages
 ******************************************************************************/


static int last_msg_in_chat_encrypted(dc_sqlite3_t* sql, uint32_t chat_id)
{
	int last_is_encrypted = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(sql,
		"SELECT param "
		" FROM msgs "
		" WHERE timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=?) "
		" ORDER BY id DESC;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_param_t* msg_param = dc_param_new();
		dc_param_set_packed(msg_param, (char*)sqlite3_column_text(stmt, 0));
		if( dc_param_exists(msg_param, DC_PARAM_GUARANTEE_E2EE) ) {
			last_is_encrypted = 1;
		}
		dc_param_unref(msg_param);
	}
	sqlite3_finalize(stmt);
	return last_is_encrypted;
}


static uint32_t dc_send_msg_raw(dc_context_t* context, dc_chat_t* chat, const dc_msg_t* msg, time_t timestamp)
{
	char*         rfc724_mid = NULL;
	sqlite3_stmt* stmt = NULL;
	uint32_t      msg_id = 0, to_id = 0;

	if( !DC_CHAT_TYPE_CAN_SEND(chat->m_type) ) {
		dc_log_error(context, 0, "Cannot send to chat type #%i.", chat->m_type);
		goto cleanup;
	}

	if( DC_CHAT_TYPE_IS_MULTI(chat->m_type) && !dc_is_contact_in_chat(context, chat->m_id, DC_CONTACT_ID_SELF) ) {
		dc_log_error(context, DC_ERROR_SELF_NOT_IN_GROUP, NULL);
		goto cleanup;
	}

	{
		char* from = dc_sqlite3_get_config(context->m_sql, "configured_addr", NULL);
		if( from == NULL ) {
			dc_log_error(context, 0, "Cannot send message, not configured.");
			goto cleanup;
		}
		rfc724_mid = dc_create_outgoing_rfc724_mid(DC_CHAT_TYPE_IS_MULTI(chat->m_type)? chat->m_grpid : NULL, from);
		free(from);
	}

	if( chat->m_type == DC_CHAT_TYPE_SINGLE )
	{
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT contact_id FROM chats_contacts WHERE chat_id=?;");
		sqlite3_bind_int(stmt, 1, chat->m_id);
		if( sqlite3_step(stmt) != SQLITE_ROW ) {
			dc_log_error(context, 0, "Cannot send message, contact for chat #%i not found.", chat->m_id);
			goto cleanup;
		}
		to_id = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	else if( DC_CHAT_TYPE_IS_MULTI(chat->m_type) )
	{
		if( dc_param_get_int(chat->m_param, DC_PARAM_UNPROMOTED, 0)==1 ) {
			/* mark group as being no longer unpromoted */
			dc_param_set(chat->m_param, DC_PARAM_UNPROMOTED, NULL);
			dc_chat_update_param(chat);
		}
	}

	/* check if we can guarantee E2EE for this message.  If we can, we won't send the message without E2EE later (because of a reset, changed settings etc. - messages may be delayed significally if there is no network present) */
	int do_guarantee_e2ee = 0;
	if( context->m_e2ee_enabled && dc_param_get_int(msg->m_param, DC_PARAM_FORCE_PLAINTEXT, 0)==0 )
	{
		int can_encrypt = 1, all_mutual = 1; /* be optimistic */
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT ps.prefer_encrypted "
			 " FROM chats_contacts cc "
			 " LEFT JOIN contacts c ON cc.contact_id=c.id "
			 " LEFT JOIN acpeerstates ps ON c.addr=ps.addr "
			 " WHERE cc.chat_id=? "                                               /* take care that this statement returns NULL rows if there is no peerstates for a chat member! */
			 " AND cc.contact_id>" DC_STRINGIFY(DC_CONTACT_ID_LAST_SPECIAL) ";"); /* for DC_PARAM_SELFTALK this statement does not return any row */
		sqlite3_bind_int(stmt, 1, chat->m_id);
		while( sqlite3_step(stmt) == SQLITE_ROW )
		{
			if( sqlite3_column_type(stmt, 0)==SQLITE_NULL ) {
				can_encrypt = 0;
				all_mutual = 0;
			}
			else {
				/* the peerstate exist, so we have either public_key or gossip_key and can encrypt potentially */
				int prefer_encrypted = sqlite3_column_int(stmt, 0);
				if( prefer_encrypted != DC_PE_MUTUAL ) {
					all_mutual = 0;
				}
			}
		}
		sqlite3_finalize(stmt);
		stmt = NULL;

		if( can_encrypt )
		{
			if( all_mutual ) {
				do_guarantee_e2ee = 1;
			}
			else {
				if( last_msg_in_chat_encrypted(context->m_sql, chat->m_id) ) {
					do_guarantee_e2ee = 1;
				}
			}
		}
	}

	if( do_guarantee_e2ee ) {
		dc_param_set_int(msg->m_param, DC_PARAM_GUARANTEE_E2EE, 1);
	}
	dc_param_set(msg->m_param, DC_PARAM_ERRONEOUS_E2EE, NULL); /* reset eg. on forwarding */

	/* add message to the database */
	stmt = dc_sqlite3_prepare(context->m_sql,
		"INSERT INTO msgs (rfc724_mid,chat_id,from_id,to_id, timestamp,type,state, txt,param,hidden) VALUES (?,?,?,?, ?,?,?, ?,?,?);");
	sqlite3_bind_text (stmt,  1, rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt,  2, chat->m_id);
	sqlite3_bind_int  (stmt,  3, DC_CONTACT_ID_SELF);
	sqlite3_bind_int  (stmt,  4, to_id);
	sqlite3_bind_int64(stmt,  5, timestamp);
	sqlite3_bind_int  (stmt,  6, msg->m_type);
	sqlite3_bind_int  (stmt,  7, DC_STATE_OUT_PENDING);
	sqlite3_bind_text (stmt,  8, msg->m_text? msg->m_text : "",  -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt,  9, msg->m_param->m_packed, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt, 10, msg->m_hidden);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		dc_log_error(context, 0, "Cannot send message, cannot insert to database.", chat->m_id);
		goto cleanup;
	}

	msg_id = sqlite3_last_insert_rowid(context->m_sql->m_cobj);
	dc_job_add(context, DC_JOB_SEND_MSG_TO_SMTP, msg_id, NULL, 0);

cleanup:
	free(rfc724_mid);
	sqlite3_finalize(stmt);
	return msg_id;
}


/**
 * Send a message of any type to a chat. The given message object is not unref'd
 * by the function but some fields are set up.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * To send a simple text message, you can also use dc_send_text_msg()
 * which is easier to use.
 *
 * @private @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the message to.
 * @param msg Message object to send to the chat defined by the chat ID.
 *     The function does not take ownership of the object, so you have to
 *     free it using dc_msg_unref() as usual.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_msg_object(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	int   locked = 0, transaction_pending = 0;
	char* pathNfilename = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || msg == NULL || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		return 0;
	}

	msg->m_id      = 0;
	msg->m_context = context;

	if( msg->m_type == DC_MSG_TEXT )
	{
		; /* the caller should check if the message text is empty */
	}
	else if( DC_MSG_NEEDS_ATTACHMENT(msg->m_type) )
	{
		pathNfilename = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
		if( pathNfilename )
		{
			/* Got an attachment. Take care, the file may not be ready in this moment!
			This is useful eg. if a video should be sent and already shown as "being processed" in the chat.
			In this case, the user should create an `.increation`; when the file is deleted later on, the message is sent.
			(we do not use a state in the database as this would make eg. forwarding such messages much more complicated) */

			if( msg->m_type == DC_MSG_FILE || msg->m_type == DC_MSG_IMAGE )
			{
				/* Correct the type, take care not to correct already very special formats as GIF or VOICE.
				Typical conversions:
				- from FILE to AUDIO/VIDEO/IMAGE
				- from FILE/IMAGE to GIF */
				int   better_type = 0;
				char* better_mime = NULL;
				dc_msg_guess_msgtype_from_suffix(pathNfilename, &better_type, &better_mime);
				if( better_type ) {
					msg->m_type = better_type;
					dc_param_set(msg->m_param, DC_PARAM_MIMETYPE, better_mime);
				}
				free(better_mime);
			}

			if( (msg->m_type == DC_MSG_IMAGE || msg->m_type == DC_MSG_GIF)
			 && (dc_param_get_int(msg->m_param, DC_PARAM_WIDTH, 0)<=0 || dc_param_get_int(msg->m_param, DC_PARAM_HEIGHT, 0)<=0) ) {
				/* set width/height of images, if not yet done */
				unsigned char* buf = NULL; size_t buf_bytes; uint32_t w, h;
				if( dc_read_file(pathNfilename, (void**)&buf, &buf_bytes, msg->m_context) ) {
					if( dc_get_filemeta(buf, buf_bytes, &w, &h) ) {
						dc_param_set_int(msg->m_param, DC_PARAM_WIDTH, w);
						dc_param_set_int(msg->m_param, DC_PARAM_HEIGHT, h);
					}
				}
				free(buf);
			}

			dc_log_info(context, 0, "Attaching \"%s\" for message type #%i.", pathNfilename, (int)msg->m_type);

			if( msg->m_text ) { free(msg->m_text); }
			if( msg->m_type == DC_MSG_AUDIO ) {
				char* filename = dc_get_filename(pathNfilename);
				char* author = dc_param_get(msg->m_param, DC_PARAM_AUTHORNAME, "");
				char* title = dc_param_get(msg->m_param, DC_PARAM_TRACKNAME, "");
				msg->m_text = dc_mprintf("%s %s %s", filename, author, title); /* for outgoing messages, also add the mediainfo. For incoming messages, this is not needed as the filename is build from these information */
				free(filename);
				free(author);
				free(title);
			}
			else if( DC_MSG_MAKE_FILENAME_SEARCHABLE(msg->m_type) ) {
				msg->m_text = dc_get_filename(pathNfilename);
			}
			else if( DC_MSG_MAKE_SUFFIX_SEARCHABLE(msg->m_type) ) {
				msg->m_text = dc_get_filesuffix_lc(pathNfilename);
			}
		}
		else
		{
			dc_log_error(context, 0, "Attachment missing for message of type #%i.", (int)msg->m_type); /* should not happen */
			goto cleanup;
		}
	}
	else
	{
		dc_log_error(context, 0, "Cannot send messages of type #%i.", (int)msg->m_type); /* should not happen */
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;
	dc_sqlite3_begin_transaction__(context->m_sql);
	transaction_pending = 1;

		dc_unarchive_chat(context, chat_id);

		context->m_smtp->m_log_connect_errors = 1;

		{
			dc_chat_t* chat = dc_chat_new(context);
			if( dc_chat_load_from_db(chat, chat_id) ) {
				msg->m_id = dc_send_msg_raw(context, chat, msg, dc_create_smeared_timestamp__());
				if( msg ->m_id == 0 ) {
					goto cleanup; /* error already logged */
				}
			}
			dc_chat_unref(chat);
		}

	dc_sqlite3_commit__(context->m_sql);
	transaction_pending = 0;
	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->m_id);

cleanup:
	if( transaction_pending ) { dc_sqlite3_rollback__(context->m_sql); }
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	free(pathNfilename);
	return msg->m_id;
}


/**
 * Send a simple text message a given chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * See also dc_send_image_msg().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the text message to.
 * @param text_to_send Text to send to the chat defined by the chat ID.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_text_msg(dc_context_t* context, uint32_t chat_id, const char* text_to_send)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t  ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || text_to_send == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_TEXT;
	msg->m_text = dc_strdup(text_to_send);

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;
}


/**
 * Send an image to a chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * See also dc_send_text_msg().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the image to.
 * @param file Full path of the image file to send. The core may make a copy of the file.
 * @param filemime Mime type of the file to send. NULL if you don't know or don't care.
 * @param width Width in pixel of the file. 0 if you don't know or don't care.
 * @param height Width in pixel of the file. 0 if you don't know or don't care.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_image_msg(dc_context_t* context, uint32_t chat_id, const char* file, const char* filemime, int width, int height)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t  ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || file == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_IMAGE;
	dc_param_set    (msg->m_param, DC_PARAM_FILE,   file);
	dc_param_set_int(msg->m_param, DC_PARAM_WIDTH,  width);  /* set in sending job, if 0 */
	dc_param_set_int(msg->m_param, DC_PARAM_HEIGHT, height); /* set in sending job, if 0 */

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;

}


/**
 * Send a video to a chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * See also dc_send_image_msg().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the video to.
 * @param file Full path of the video file to send. The core may make a copy of the file.
 * @param filemime Mime type of the file to send. NULL if you don't know or don't care.
 * @param width Width in video of the file, if known. 0 if you don't know or don't care.
 * @param height Width in video of the file, if known. 0 if you don't know or don't care.
 * @param duration Length of the video in milliseconds. 0 if you don't know or don't care.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_video_msg(dc_context_t* context, uint32_t chat_id, const char* file, const char* filemime, int width, int height, int duration)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t  ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || file == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_VIDEO;
	dc_param_set    (msg->m_param, DC_PARAM_FILE,     file);
	dc_param_set    (msg->m_param, DC_PARAM_MIMETYPE, filemime);
	dc_param_set_int(msg->m_param, DC_PARAM_WIDTH,    width);
	dc_param_set_int(msg->m_param, DC_PARAM_HEIGHT,   height);
	dc_param_set_int(msg->m_param, DC_PARAM_DURATION, duration);

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;

}


/**
 * Send a voice message to a chat.  Voice messages are messages just recorded though the device microphone.
 * For sending music or other audio data, use dc_send_audio_msg().
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the voice message to.
 * @param file Full path of the file to send. The core may make a copy of the file.
 * @param filemime Mime type of the file to send. NULL if you don't know or don't care.
 * @param duration Length of the voice message in milliseconds. 0 if you don't know or don't care.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_voice_msg(dc_context_t* context, uint32_t chat_id, const char* file, const char* filemime, int duration)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t  ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || file == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_VOICE;
	dc_param_set    (msg->m_param, DC_PARAM_FILE,     file);
	dc_param_set    (msg->m_param, DC_PARAM_MIMETYPE, filemime);
	dc_param_set_int(msg->m_param, DC_PARAM_DURATION, duration);

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;
}


/**
 * Send an audio file to a chat.  Audio messages are eg. music tracks.
 * For voice messages just recorded though the device microphone, use dc_send_voice_msg().
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the audio to.
 * @param file Full path of the file to send. The core may make a copy of the file.
 * @param filemime Mime type of the file to send. NULL if you don't know or don't care.
 * @param duration Length of the audio in milliseconds. 0 if you don't know or don't care.
 * @param author Author or artist of the file. NULL if you don't know or don't care.
 * @param trackname Trackname or title of the file. NULL if you don't know or don't care.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_audio_msg(dc_context_t* context, uint32_t chat_id, const char* file, const char* filemime, int duration, const char* author, const char* trackname)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || file == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_AUDIO;
	dc_param_set    (msg->m_param, DC_PARAM_FILE,       file);
	dc_param_set    (msg->m_param, DC_PARAM_MIMETYPE,   filemime);
	dc_param_set_int(msg->m_param, DC_PARAM_DURATION,   duration);
	dc_param_set    (msg->m_param, DC_PARAM_AUTHORNAME, author);
	dc_param_set    (msg->m_param, DC_PARAM_TRACKNAME,  trackname);

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;
}


/**
 * Send a document to a chat. Use this function to send any document or file to
 * a chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the document to.
 * @param file Full path of the file to send. The core may make a copy of the file.
 * @param filemime Mime type of the file to send. NULL if you don't know or don't care.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_file_msg(dc_context_t* context, uint32_t chat_id, const char* file, const char* filemime)
{
	dc_msg_t* msg = dc_msg_new();
	uint32_t  ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || file == NULL ) {
		goto cleanup;
	}

	msg->m_type = DC_MSG_FILE;
	dc_param_set(msg->m_param, DC_PARAM_FILE,     file);
	dc_param_set(msg->m_param, DC_PARAM_MIMETYPE, filemime);

	ret = dc_send_msg_object(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
	return ret;
}


/**
 * Send foreign contact data to a chat.
 *
 * Sends the name and the email address of another contact to a chat.
 * The contact this may or may not be a member of the chat.
 *
 * Typically used to share a contact to another member or to a group of members.
 *
 * Internally, the function just creates an appropriate text message and sends it
 * using dc_send_text_msg().
 *
 * NB: The "vcard" in the function name is just an abbreviation of "visiting card" and
 * is not related to the VCARD data format.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat to send the message to.
 * @param contact_id The contact whichs data should be shared to the chat.
 * @return Returns the ID of the message sent.
 */
uint32_t dc_send_vcard_msg(dc_context_t* context, uint32_t chat_id, uint32_t contact_id)
{
	uint32_t      ret = 0;
	dc_msg_t*     msg = dc_msg_new();
	dc_contact_t* contact = NULL;
	char*         text_to_send = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	if( (contact=dc_get_contact(context, contact_id)) == NULL ) {
		goto cleanup;
	}

	if( contact->m_authname && contact->m_authname[0] ) {
		text_to_send = dc_mprintf("%s: %s", contact->m_authname, contact->m_addr);
	}
	else {
		text_to_send = dc_strdup(contact->m_addr);
	}

	ret = dc_send_text_msg(context, chat_id, text_to_send);

cleanup:
	dc_msg_unref(msg);
	dc_contact_unref(contact);
	free(text_to_send);
	return ret;
}


/*
 * Log a device message.
 * Such a message is typically shown in the "middle" of the chat, the user can check this using dc_msg_is_info().
 * Texts are typically "Alice has added Bob to the group" or "Alice fingerprint verified."
 */
void dc_add_device_msg(dc_context_t* context, uint32_t chat_id, const char* text)
{
	uint32_t      msg_id = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || text == NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"INSERT INTO msgs (chat_id,from_id,to_id, timestamp,type,state, txt) VALUES (?,?,?, ?,?,?, ?);");
	sqlite3_bind_int  (stmt,  1, chat_id);
	sqlite3_bind_int  (stmt,  2, DC_CONTACT_ID_DEVICE);
	sqlite3_bind_int  (stmt,  3, DC_CONTACT_ID_DEVICE);
	sqlite3_bind_int64(stmt,  4, dc_create_smeared_timestamp__());
	sqlite3_bind_int  (stmt,  5, DC_MSG_TEXT);
	sqlite3_bind_int  (stmt,  6, DC_STATE_IN_NOTICED);
	sqlite3_bind_text (stmt,  7, text,  -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
	}
	msg_id = sqlite3_last_insert_rowid(context->m_sql->m_cobj);
	context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg_id);

cleanup:
	sqlite3_finalize(stmt);
}


/*******************************************************************************
 * Handle Group Chats
 ******************************************************************************/


#define IS_SELF_IN_GROUP     (dc_is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF)==1)
#define DO_SEND_STATUS_MAILS (dc_param_get_int(chat->m_param, DC_PARAM_UNPROMOTED, 0)==0)


int dc_is_group_explicitly_left(dc_context_t* context, const char* grpid)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql, "SELECT id FROM leftgrps WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	int ret = (sqlite3_step(stmt)==SQLITE_ROW);
	sqlite3_finalize(stmt);
	return ret;
}


void dc_set_group_explicitly_left(dc_context_t* context, const char* grpid)
{
	if( !dc_is_group_explicitly_left(context, grpid) )
	{
		sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql, "INSERT INTO leftgrps (grpid) VALUES(?);");
		sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
}


static int dc_real_group_exists(dc_context_t* context, uint32_t chat_id)
{
	// check if a group or a verified group exists under the given ID
	sqlite3_stmt* stmt = NULL;
	int           ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL
	 || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		return 0;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id FROM chats "
		" WHERE id=? "
		"   AND (type=" DC_STRINGIFY(DC_CHAT_TYPE_GROUP) " OR type=" DC_STRINGIFY(DC_CHAT_TYPE_VERIFIED_GROUP) ");");
	sqlite3_bind_int(stmt, 1, chat_id);
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = 1;
	}
	sqlite3_finalize(stmt);

	return ret;
}


int dc_add_to_chat_contacts_table__(dc_context_t* context, uint32_t chat_id, uint32_t contact_id)
{
	/* add a contact to a chat; the function does not check the type or if any of the record exist or are already added to the chat! */
	int ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"INSERT INTO chats_contacts (chat_id, contact_id) VALUES(?, ?)");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	ret = (sqlite3_step(stmt)==SQLITE_DONE)? 1 : 0;
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Create a new group chat.
 *
 * After creation, the group has one member with the
 * ID DC_CONTACT_ID_SELF and is in _unpromoted_ state.  This means, you can
 * add or remove members, change the name, the group image and so on without
 * messages being sent to all group members.
 *
 * This changes as soon as the first message is sent to the group members and
 * the group becomes _promoted_.  After that, all changes are synced with all
 * group members by sending status message.
 *
 * To check, if a chat is still unpromoted, you dc_chat_is_unpromoted()
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param verified If set to 1 the function creates a secure verfied group.
 *     Only secure-verified members are allowd in these groups and end-to-end-encryption is always enabled.
 * @param chat_name The name of the group chat to create.
 *     The name may be changed later using dc_set_chat_name().
 *     To find out the name of a group later, see dc_chat_get_name()
 * @return The chat ID of the new group chat, 0 on errors.
 */
uint32_t dc_create_group_chat(dc_context_t* context, int verified, const char* chat_name)
{
	uint32_t      chat_id = 0;
	int           locked = 0;
	char*         draft_txt = NULL, *grpid = NULL;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_name==NULL || chat_name[0]==0 ) {
		return 0;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		draft_txt = dc_stock_str_repl_string(DC_STR_NEWGROUPDRAFT, chat_name);
		grpid = dc_create_id();

		stmt = dc_sqlite3_prepare(context->m_sql,
			"INSERT INTO chats (type, name, draft_timestamp, draft_txt, grpid, param) VALUES(?, ?, ?, ?, ?, 'U=1');" /*U=DC_PARAM_UNPROMOTED*/ );
		sqlite3_bind_int  (stmt, 1, verified? DC_CHAT_TYPE_VERIFIED_GROUP : DC_CHAT_TYPE_GROUP);
		sqlite3_bind_text (stmt, 2, chat_name, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 3, time(NULL));
		sqlite3_bind_text (stmt, 4, draft_txt, -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 5, grpid, -1, SQLITE_STATIC);
		if(  sqlite3_step(stmt)!=SQLITE_DONE ) {
			goto cleanup;
		}

		if( (chat_id=sqlite3_last_insert_rowid(context->m_sql->m_cobj)) == 0 ) {
			goto cleanup;
		}

		if( dc_add_to_chat_contacts_table__(context, chat_id, DC_CONTACT_ID_SELF) ) {
			goto cleanup;
		}

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	sqlite3_finalize(stmt);
	free(draft_txt);
	free(grpid);

	if( chat_id ) {
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
	}

	return chat_id;
}


/**
 * Set group name.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param chat_id The chat ID to set the name for.  Must be a group chat.
 * @param new_name New name of the group.
 * @param context The context as created by dc_context_new().
 * @return 1=success, 0=error
 */
int dc_set_chat_name(dc_context_t* context, uint32_t chat_id, const char* new_name)
{
	/* the function only sets the names of group chats; normal chats get their names from the contacts */
	int        success = 0;
	dc_chat_t* chat = dc_chat_new(context);
	dc_msg_t*  msg = dc_msg_new();
	char*      q3 = NULL;

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || new_name==NULL || new_name[0]==0 || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	if( 0==dc_real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id) ) {
		goto cleanup;
	}

	if( strcmp(chat->m_name, new_name)==0 ) {
		success = 1;
		goto cleanup; /* name not modified */
	}

	if( !IS_SELF_IN_GROUP ) {
		dc_log_error(context, DC_ERROR_SELF_NOT_IN_GROUP, NULL);
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	q3 = sqlite3_mprintf("UPDATE chats SET name=%Q WHERE id=%i;", new_name, chat_id);
	if( !dc_sqlite3_execute(context->m_sql, q3) ) {
		goto cleanup;
	}

	/* send a status mail to all group members, also needed for outself to allow multi-client */
	if( DO_SEND_STATUS_MAILS )
	{
		msg->m_type = DC_MSG_TEXT;
		msg->m_text = dc_stock_str_repl_string2(DC_STR_MSGGRPNAME, chat->m_name, new_name);
		dc_param_set_int(msg->m_param, DC_PARAM_CMD, DC_CMD_GROUPNAME_CHANGED);
		msg->m_id = dc_send_msg_object(context, chat_id, msg);
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
	}
	context->m_cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	sqlite3_free(q3);
	dc_chat_unref(chat);
	dc_msg_unref(msg);
	return success;
}


/**
 * Set group profile image.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * To find out the profile image of a chat, use dc_chat_get_profile_image()
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to set the image for.
 * @param new_image Full path of the image to use as the group image.  If you pass NULL here,
 *     the group image is deleted (for promoted groups, all members are informed about this change anyway).
 * @return 1=success, 0=error
 */
int dc_set_chat_profile_image(dc_context_t* context, uint32_t chat_id, const char* new_image /*NULL=remove image*/)
{
	int        success = 0;
	dc_chat_t* chat = dc_chat_new(context);
	dc_msg_t*  msg = dc_msg_new();

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	if( 0==dc_real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id) ) {
		goto cleanup;
	}

	if( !IS_SELF_IN_GROUP ) {
		dc_log_error(context, DC_ERROR_SELF_NOT_IN_GROUP, NULL);
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	dc_param_set(chat->m_param, DC_PARAM_PROFILE_IMAGE, new_image/*may be NULL*/);
	if( !dc_chat_update_param(chat) ) {
		goto cleanup;
	}

	/* send a status mail to all group members, also needed for outself to allow multi-client */
	if( DO_SEND_STATUS_MAILS )
	{
		dc_param_set_int(msg->m_param, DC_PARAM_CMD,       DC_CMD_GROUPIMAGE_CHANGED);
		dc_param_set    (msg->m_param, DC_PARAM_CMD_ARG, new_image);
		msg->m_type = DC_MSG_TEXT;
		msg->m_text = dc_stock_str(new_image? DC_STR_MSGGRPIMGCHANGED : DC_STR_MSGGRPIMGDELETED);
		msg->m_id = dc_send_msg_object(context, chat_id, msg);
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
	}
	context->m_cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	dc_chat_unref(chat);
	dc_msg_unref(msg);
	return success;
}


int dc_get_chat_contact_count(dc_context_t* context, uint32_t chat_id)
{
	int ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = sqlite3_column_int(stmt, 0);
	}
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Check if a given contact ID is a member of a group chat.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to check.
 * @param contact_id The contact ID to check.  To check if yourself is member
 *     of the chat, pass DC_CONTACT_ID_SELF (1) here.
 * @return 1=contact ID is member of chat ID, 0=contact is not in chat
 */
int dc_is_contact_in_chat(dc_context_t* context, uint32_t chat_id, uint32_t contact_id)
{
	/* this function works for group and for normal chats, however, it is more useful for group chats.
	DC_CONTACT_ID_SELF may be used to check, if the user itself is in a group chat (DC_CONTACT_ID_SELF is not added to normal chats) */
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT contact_id FROM chats_contacts WHERE chat_id=? AND contact_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	ret = (sqlite3_step(stmt) == SQLITE_ROW)? 1 : 0;

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


int dc_add_contact_to_chat_ex(dc_context_t* context, uint32_t chat_id, uint32_t contact_id, int flags)
{
	int              success   = 0, locked = 0;
	dc_contact_t*    contact   = dc_get_contact(context, contact_id);
	dc_apeerstate_t* peerstate = dc_apeerstate_new(context);
	dc_chat_t*       chat      = dc_chat_new(context);
	dc_msg_t*        msg       = dc_msg_new();
	char*            self_addr = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || contact == NULL || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		if( 0==dc_real_group_exists(context, chat_id) /*this also makes sure, not contacts are added to special or normal chats*/
		 || (0==dc_real_contact_exists__(context, contact_id) && contact_id!=DC_CONTACT_ID_SELF)
		 || 0==dc_chat_load_from_db(chat, chat_id) ) {
			goto cleanup;
		}

		if( !IS_SELF_IN_GROUP ) {
			dc_log_error(context, DC_ERROR_SELF_NOT_IN_GROUP, NULL);
			goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
		}

		if( (flags&DC_FROM_HANDSHAKE) && dc_param_get_int(chat->m_param, DC_PARAM_UNPROMOTED, 0)==1 ) {
			// after a handshake, force sending the `Chat-Group-Member-Added` message
			dc_param_set(chat->m_param, DC_PARAM_UNPROMOTED, NULL);
			dc_chat_update_param(chat);
		}

		self_addr = dc_sqlite3_get_config(context->m_sql, "configured_addr", "");
		if( strcasecmp(contact->m_addr, self_addr)==0 ) {
			goto cleanup; /* ourself is added using DC_CONTACT_ID_SELF, do not add it explicitly. if SELF is not in the group, members cannot be added at all. */
		}

		if( dc_is_contact_in_chat(context, chat_id, contact_id) )
		{
			if( !(flags&DC_FROM_HANDSHAKE) ) {
				success = 1;
				goto cleanup;
			}
			// else continue and send status mail
		}
		else
		{
			if( chat->m_type == DC_CHAT_TYPE_VERIFIED_GROUP )
			{
				if( !dc_apeerstate_load_by_addr(peerstate, context->m_sql, contact->m_addr)
				 || dc_contact_is_verified__(contact, peerstate) != DC_BIDIRECT_VERIFIED ) {
					dc_log_error(context, 0, "Only bidirectional verified contacts can be added to verfied groups.");
					goto cleanup;
				}
			}

			if( 0==dc_add_to_chat_contacts_table__(context, chat_id, contact_id) ) {
				goto cleanup;
			}
		}

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	/* send a status mail to all group members */
	if( DO_SEND_STATUS_MAILS )
	{
		msg->m_type = DC_MSG_TEXT;
		msg->m_text = dc_stock_str_repl_string(DC_STR_MSGADDMEMBER, (contact->m_authname&&contact->m_authname[0])? contact->m_authname : contact->m_addr);
		dc_param_set_int(msg->m_param, DC_PARAM_CMD,       DC_CMD_MEMBER_ADDED_TO_GROUP);
		dc_param_set    (msg->m_param, DC_PARAM_CMD_ARG ,contact->m_addr);
		dc_param_set_int(msg->m_param, DC_PARAM_CMD_ARG2,flags); // combine the Secure-Join protocol headers with the Chat-Group-Member-Added header
		msg->m_id = dc_send_msg_object(context, chat_id, msg);
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
	}
	context->m_cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	dc_chat_unref(chat);
	dc_contact_unref(contact);
	dc_apeerstate_unref(peerstate);
	dc_msg_unref(msg);
	free(self_addr);
	return success;
}


/**
 * Add a member to a group.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * If the group is a verified group, only verified contacts can be added to the group.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to add the contact to.  Must be a group chat.
 * @param contact_id The contact ID to add to the chat.
 * @return 1=member added to group, 0=error
 */
int dc_add_contact_to_chat(dc_context_t* context, uint32_t chat_id, uint32_t contact_id /*may be DC_CONTACT_ID_SELF*/)
{
	return dc_add_contact_to_chat_ex(context, chat_id, contact_id, 0);
}


/**
 * Remove a member from a group.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to remove the contact from.  Must be a group chat.
 * @param contact_id The contact ID to remove from the chat.
 * @return 1=member removed from group, 0=error
 */
int dc_remove_contact_from_chat(dc_context_t* context, uint32_t chat_id, uint32_t contact_id /*may be DC_CONTACT_ID_SELF*/)
{
	int           success = 0;
	dc_contact_t* contact = dc_get_contact(context, contact_id);
	dc_chat_t*    chat = dc_chat_new(context);
	dc_msg_t*     msg = dc_msg_new();
	char*         q3 = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || chat_id <= DC_CHAT_ID_LAST_SPECIAL || (contact_id<=DC_CONTACT_ID_LAST_SPECIAL && contact_id!=DC_CONTACT_ID_SELF) ) {
		goto cleanup; /* we do not check if "contact_id" exists but just delete all records with the id from chats_contacts */
	}                 /* this allows to delete pending references to deleted contacts.  Of course, this should _not_ happen. */

	if( 0==dc_real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id) ) {
		goto cleanup;
	}

	if( !IS_SELF_IN_GROUP ) {
		dc_log_error(context, DC_ERROR_SELF_NOT_IN_GROUP, NULL);
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	/* send a status mail to all group members - we need to do this before we update the database -
	otherwise the !IS_SELF_IN_GROUP__-check in dc_chat_send_msg() will fail. */
	if( contact )
	{
		if( DO_SEND_STATUS_MAILS )
		{
			msg->m_type = DC_MSG_TEXT;
			if( contact->m_id == DC_CONTACT_ID_SELF ) {
				dc_set_group_explicitly_left(context, chat->m_grpid);
				msg->m_text = dc_stock_str(DC_STR_MSGGROUPLEFT);
			}
			else {
				msg->m_text = dc_stock_str_repl_string(DC_STR_MSGDELMEMBER, (contact->m_authname&&contact->m_authname[0])? contact->m_authname : contact->m_addr);
			}
			dc_param_set_int(msg->m_param, DC_PARAM_CMD,       DC_CMD_MEMBER_REMOVED_FROM_GROUP);
			dc_param_set    (msg->m_param, DC_PARAM_CMD_ARG, contact->m_addr);
			msg->m_id = dc_send_msg_object(context, chat_id, msg);
			context->m_cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->m_id);
		}
	}

	q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i AND contact_id=%i;", chat_id, contact_id);
	if( !dc_sqlite3_execute(context->m_sql, q3) ) {
		goto cleanup;
	}

	context->m_cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	sqlite3_free(q3);
	dc_chat_unref(chat);
	dc_contact_unref(contact);
	dc_msg_unref(msg);
	return success;
}


/*******************************************************************************
 * Handle Contacts
 ******************************************************************************/


int dc_real_contact_exists__(dc_context_t* context, uint32_t contact_id)
{
	sqlite3_stmt* stmt = NULL;
	int           ret = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL
	 || contact_id <= DC_CONTACT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id FROM contacts WHERE id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);

	if( sqlite3_step(stmt) == SQLITE_ROW ) {
		ret = 1;
	}

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


size_t dc_get_real_contact_cnt(dc_context_t* context)
{
	size_t        ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql, "SELECT COUNT(*) FROM contacts WHERE id>?;");
	sqlite3_bind_int(stmt, 1, DC_CONTACT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


uint32_t dc_add_or_lookup_contact( dc_context_t* context,
                                   const char*   name /*can be NULL, the caller may use dc_normalize_name() before*/,
                                   const char*   addr__,
                                   int           origin,
                                   int*          sth_modified )
{
	#define       CONTACT_MODIFIED 1
	#define       CONTACT_CREATED  2
	sqlite3_stmt* stmt = NULL;
	uint32_t      row_id = 0;
	int           dummy;
	char*         addr = NULL;

	if( sth_modified == NULL ) {
		sth_modified = &dummy;
	}

	*sth_modified = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || addr__ == NULL || origin <= 0 ) {
		goto cleanup;
	}

	/* normalize the email-address:
	- remove leading `mailto:` */
	addr = dc_normalize_addr(addr__);

	/* rough check if email-address is valid */
	if( strlen(addr) < 3 || strchr(addr, '@')==NULL || strchr(addr, '.')==NULL ) {
		dc_log_warning(context, 0, "Bad address \"%s\" for contact \"%s\".", addr, name?name:"<unset>");
		goto cleanup;
	}

	/* insert email-address to database or modify the record with the given email-address.
	we treat all email-addresses case-insensitive. */
	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id, name, addr, origin, authname FROM contacts WHERE addr=? COLLATE NOCASE;");
	sqlite3_bind_text(stmt, 1, (const char*)addr, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) == SQLITE_ROW )
	{
		const char  *row_name, *row_addr, *row_authname;
		int         row_origin, update_addr = 0, update_name = 0, update_authname = 0;

		row_id       = sqlite3_column_int(stmt, 0);
		row_name     = (const char*)sqlite3_column_text(stmt, 1); if( row_name == NULL ) { row_name = ""; }
		row_addr     = (const char*)sqlite3_column_text(stmt, 2); if( row_addr == NULL ) { row_addr = addr; }
		row_origin   = sqlite3_column_int(stmt, 3);
		row_authname = (const char*)sqlite3_column_text(stmt, 4); if( row_authname == NULL ) { row_authname = ""; }
		sqlite3_finalize (stmt);
		stmt = NULL;

		if( name && name[0] ) {
			if( row_name && row_name[0] ) {
				if( origin>=row_origin && strcmp(name, row_name)!=0 ) {
					update_name = 1;
				}
			}
			else {
				update_name = 1;
			}

			if( origin == DC_ORIGIN_INCOMING_UNKNOWN_FROM && strcmp(name, row_authname)!=0 ) {
				update_authname = 1;
			}
		}

		if( origin>=row_origin && strcmp(addr, row_addr)!=0 /*really compare case-sensitive here*/ ) {
			update_addr = 1;
		}

		if( update_name || update_authname || update_addr || origin>row_origin )
		{
			stmt = dc_sqlite3_prepare(context->m_sql,
				"UPDATE contacts SET name=?, addr=?, origin=?, authname=? WHERE id=?;");
			sqlite3_bind_text(stmt, 1, update_name?       name   : row_name, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, update_addr?       addr   : row_addr, -1, SQLITE_STATIC);
			sqlite3_bind_int (stmt, 3, origin>row_origin? origin : row_origin);
			sqlite3_bind_text(stmt, 4, update_authname?   name   : row_authname, -1, SQLITE_STATIC);
			sqlite3_bind_int (stmt, 5, row_id);
			sqlite3_step     (stmt);
			sqlite3_finalize (stmt);
			stmt = NULL;

			if( update_name )
			{
				/* Update the contact name also if it is used as a group name.
				This is one of the few duplicated data, however, getting the chat list is easier this way.*/
				stmt = dc_sqlite3_prepare(context->m_sql,
					"UPDATE chats SET name=? WHERE type=? AND id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?);");
				sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
				sqlite3_bind_int (stmt, 2, DC_CHAT_TYPE_SINGLE);
				sqlite3_bind_int (stmt, 3, row_id);
				sqlite3_step     (stmt);
			}

			*sth_modified = CONTACT_MODIFIED;
		}
	}
	else
	{
		sqlite3_finalize (stmt);
		stmt = NULL;

		stmt = dc_sqlite3_prepare(context->m_sql,
			"INSERT INTO contacts (name, addr, origin) VALUES(?, ?, ?);");
		sqlite3_bind_text(stmt, 1, name? name : "", -1, SQLITE_STATIC); /* avoid NULL-fields in column */
		sqlite3_bind_text(stmt, 2, addr,    -1, SQLITE_STATIC);
		sqlite3_bind_int (stmt, 3, origin);
		if( sqlite3_step(stmt) == SQLITE_DONE )
		{
			row_id = sqlite3_last_insert_rowid(context->m_sql->m_cobj);
			*sth_modified = CONTACT_CREATED;
		}
		else
		{
			dc_log_error(context, 0, "Cannot add contact."); /* should not happen */
		}
	}

cleanup:
	free(addr);
	sqlite3_finalize(stmt);
	return row_id;
}


void dc_scaleup_contact_origin(dc_context_t* context, uint32_t contact_id, int origin)
{
	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE contacts SET origin=? WHERE id=? AND origin<?;");
	sqlite3_bind_int(stmt, 1, origin);
	sqlite3_bind_int(stmt, 2, contact_id);
	sqlite3_bind_int(stmt, 3, origin);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


int dc_is_contact_blocked(dc_context_t* context, uint32_t contact_id)
{
	int           is_blocked = 0;
	dc_contact_t* contact = dc_contact_new(context);

	if( dc_contact_load_from_db(contact, context->m_sql, contact_id) ) {
		if( contact->m_blocked ) {
			is_blocked = 1;
		}
	}

	dc_contact_unref(contact);
	return is_blocked;
}


int dc_get_contact_origin(dc_context_t* context, uint32_t contact_id, int* ret_blocked)
{
	int          ret = 0;
	int          dummy; if( ret_blocked==NULL ) { ret_blocked = &dummy; }
	dc_contact_t* contact = dc_contact_new(context);

	*ret_blocked = 0;

	if( !dc_contact_load_from_db(contact, context->m_sql, contact_id) ) { /* we could optimize this by loading only the needed fields */
		goto cleanup;
	}

	if( contact->m_blocked ) {
		*ret_blocked = 1;
		goto cleanup;
	}

	ret = contact->m_origin;

cleanup:
	dc_contact_unref(contact);
	return ret;
}


/**
 * Add a single contact as a result of an _explicit_ user action.
 *
 * We assume, the contact name, if any, is entered by the user and is used "as is" therefore,
 * normalize() is _not_ called for the name. If the contact is blocked, it is unblocked.
 *
 * To add a number of contacts, see dc_add_address_book() which is much faster for adding
 * a bunch of addresses.
 *
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param name Name of the contact to add. If you do not know the name belonging
 *     to the address, you can give NULL here.
 * @param addr E-mail-address of the contact to add. If the email address
 *     already exists, the name is updated and the origin is increased to
 *     "manually created".
 * @return Contact ID of the created or reused contact.
 */
uint32_t dc_create_contact(dc_context_t* context, const char* name, const char* addr)
{
	uint32_t contact_id = 0;
	int      sth_modified = 0;
	int      blocked = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || addr == NULL || addr[0]==0 ) {
		goto cleanup;
	}

	contact_id = dc_add_or_lookup_contact(context, name, addr, DC_ORIGIN_MANUALLY_CREATED, &sth_modified);

	blocked = dc_is_contact_blocked(context, contact_id);

	context->m_cb(context, DC_EVENT_CONTACTS_CHANGED, sth_modified==CONTACT_CREATED? contact_id : 0, 0);

	if( blocked ) {
		dc_block_contact(context, contact_id, 0);
	}

cleanup:
	return contact_id;
}


/**
 * Add a number of contacts.
 *
 * Typically used to add the whole address book from the OS. As names here are typically not
 * well formatted, we call normalize() for each name given.
 *
 * To add a single contact entered by the user, you should prefer dc_create_contact(),
 * however, for adding a bunch of addresses, this function is _much_ faster.
 *
 * The function takes are of not overwriting names manually added or edited by dc_create_contact().
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @param adr_book A multi-line string in the format in the format
 *     `Name one\nAddress one\nName two\Address two`.  If an email address
 *      already exists, the name is updated and the origin is increased to
 *      "manually created".
 * @return The number of modified or added contacts.
 */
int dc_add_address_book(dc_context_t* context, const char* adr_book) /* format: Name one\nAddress one\nName two\Address two */
{
	carray* lines = NULL;
	size_t  i, iCnt;
	int     sth_modified, modify_cnt = 0;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || adr_book == NULL ) {
		goto cleanup;
	}

	if( (lines=dc_split_into_lines(adr_book))==NULL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);

		dc_sqlite3_begin_transaction__(context->m_sql);

		iCnt = carray_count(lines);
		for( i = 0; i+1 < iCnt; i += 2 ) {
			char* name = (char*)carray_get(lines, i);
			char* addr = (char*)carray_get(lines, i+1);
			dc_normalize_name(name);
			dc_add_or_lookup_contact(context, name, addr, DC_ORIGIN_ADRESS_BOOK, &sth_modified);
			if( sth_modified ) {
				modify_cnt++;
			}
		}

		dc_sqlite3_commit__(context->m_sql);

	dc_sqlite3_unlock(context->m_sql);

cleanup:
	dc_free_splitted_lines(lines);

	return modify_cnt;
}


/**
 * Returns known and unblocked contacts.
 *
 * To get information about a single contact, see dc_get_contact().
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param listflags A combination of flags:
 *     - if the flag DC_GCL_ADD_SELF is set, SELF is added to the list unless filtered by other parameters
 *     - if the flag DC_GCL_VERIFIED_ONLY is set, only verified contacts are returned.
 *       if DC_GCL_VERIFIED_ONLY is not set, verified and unverified contacts are returned.
 * @param query A string to filter the list.  Typically used to implement an
 *     incremental search.  NULL for no filtering.
 * @return An array containing all contact IDs.  Must be dc_array_unref()'d
 *     after usage.
 */
dc_array_t* dc_get_contacts(dc_context_t* context, uint32_t listflags, const char* query)
{
	char*         self_addr = NULL;
	char*         self_name = NULL;
	char*         self_name2 = NULL;
	int           add_self = 0;
	dc_array_t*   ret = dc_array_new(context, 100);
	char*         s3strLikeCmd = NULL;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	self_addr = dc_sqlite3_get_config(context->m_sql, "configured_addr", ""); /* we add DC_CONTACT_ID_SELF explicitly; so avoid doubles if the address is present as a normal entry for some case */

	if( (listflags&DC_GCL_VERIFIED_ONLY) || query )
	{
		if( (s3strLikeCmd=sqlite3_mprintf("%%%s%%", query? query : ""))==NULL ) {
			goto cleanup;
		}
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT c.id FROM contacts c"
				" LEFT JOIN acpeerstates ps ON c.addr=ps.addr "
				" WHERE c.addr!=? AND c.id>" DC_STRINGIFY(DC_CONTACT_ID_LAST_SPECIAL) " AND c.origin>=" DC_STRINGIFY(DC_ORIGIN_MIN_CONTACT_LIST) " AND c.blocked=0 AND (c.name LIKE ? OR c.addr LIKE ?)" /* see comments in dc_search_msgs() about the LIKE operator */
				" AND (1=? OR LENGTH(ps.verified_key_fingerprint)!=0) "
				" ORDER BY LOWER(c.name||c.addr),c.id;");
		sqlite3_bind_text(stmt, 1, self_addr, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 2, s3strLikeCmd, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 3, s3strLikeCmd, -1, SQLITE_STATIC);
		sqlite3_bind_int (stmt, 4, (listflags&DC_GCL_VERIFIED_ONLY)? 0/*force checking for verified_key*/ : 1/*force statement being always true*/);

		self_name  = dc_sqlite3_get_config(context->m_sql, "displayname", "");
		self_name2 = dc_stock_str(DC_STR_SELF);
		if( query==NULL || dc_str_contains(self_addr, query) || dc_str_contains(self_name, query) || dc_str_contains(self_name2, query) ) {
			add_self = 1;
		}
	}
	else
	{
		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT id FROM contacts"
				" WHERE addr!=? AND id>" DC_STRINGIFY(DC_CONTACT_ID_LAST_SPECIAL) " AND origin>=" DC_STRINGIFY(DC_ORIGIN_MIN_CONTACT_LIST) " AND blocked=0"
				" ORDER BY LOWER(name||addr),id;");
		sqlite3_bind_text(stmt, 1, self_addr, -1, SQLITE_STATIC);

		add_self = 1;
	}

	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

	/* to the end of the list, add self - this is to be in sync with member lists and to allow the user to start a self talk */
	if( (listflags&DC_GCL_ADD_SELF) && add_self ) {
		dc_array_add_id(ret, DC_CONTACT_ID_SELF);
	}

cleanup:
	sqlite3_finalize(stmt);
	sqlite3_free(s3strLikeCmd);
	free(self_addr);
	free(self_name);
	free(self_name2);
	return ret;
}


/**
 * Get blocked contacts.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @return An array containing all blocked contact IDs.  Must be dc_array_unref()'d
 *     after usage.
 */
dc_array_t* dc_get_blocked_contacts(dc_context_t* context)
{
	dc_array_t*   ret = dc_array_new(context, 100);
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT id FROM contacts"
			" WHERE id>? AND blocked!=0"
			" ORDER BY LOWER(name||addr),id;");
	sqlite3_bind_int(stmt, 1, DC_CONTACT_ID_LAST_SPECIAL);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get the number of blocked contacts.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @return The number of blocked contacts.
 */
int dc_get_blocked_count(dc_context_t* context)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM contacts"
			" WHERE id>? AND blocked!=0");
	sqlite3_bind_int(stmt, 1, DC_CONTACT_ID_LAST_SPECIAL);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}
	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get a single contact object.  For a list, see eg. dc_get_contacts().
 *
 * For contact DC_CONTACT_ID_SELF (1), the function returns sth.
 * like "Me" in the selected language and the email address
 * defined by dc_set_config().
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param contact_id ID of the contact to get the object for.
 * @return The contact object, must be freed using dc_contact_unref() when no
 *     longer used.  NULL on errors.
 */
dc_contact_t* dc_get_contact(dc_context_t* context, uint32_t contact_id)
{
	dc_contact_t* ret = dc_contact_new(context);

	if( !dc_contact_load_from_db(ret, context->m_sql, contact_id) ) {
		dc_contact_unref(ret);
		ret = NULL;
	}

	return ret; /* may be NULL */
}


/**
 * Mark all messages sent by the given contact
 * as _noticed_.  See also dc_marknoticed_chat() and
 * dc_markseen_msgs()
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new()
 * @param contact_id The contact ID of which all messages should be marked as noticed.
 * @return none
 */
void dc_marknoticed_contact(dc_context_t* context, uint32_t contact_id)
{
    if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
    }

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE msgs SET state=" DC_STRINGIFY(DC_STATE_IN_NOTICED) " WHERE from_id=? AND state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	sqlite3_bind_int(stmt, 1, contact_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


void dc_block_chat(dc_context_t* context, uint32_t chat_id, int new_blocking)
{
	sqlite3_stmt* stmt;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		return;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE chats SET blocked=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, new_blocking);
	sqlite3_bind_int(stmt, 2, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


void dc_unblock_chat(dc_context_t* context, uint32_t chat_id)
{
	dc_block_chat(context, chat_id, DC_CHAT_NOT_BLOCKED);
}


/**
 * Block or unblock a contact.
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param contact_id The ID of the contact to block or unblock.
 * @param new_blocking 1=block contact, 0=unblock contact
 * @return None.
 */
void dc_block_contact(dc_context_t* context, uint32_t contact_id, int new_blocking)
{
	int           locked = 0;
	int           send_event = 0;
	int           transaction_pending = 0;
	dc_contact_t* contact = dc_contact_new(context);
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || contact_id <= DC_CONTACT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;

		if( dc_contact_load_from_db(contact, context->m_sql, contact_id)
		 && contact->m_blocked != new_blocking )
		{
			dc_sqlite3_begin_transaction__(context->m_sql);
			transaction_pending = 1;

				stmt = dc_sqlite3_prepare(context->m_sql,
					"UPDATE contacts SET blocked=? WHERE id=?;");
				sqlite3_bind_int(stmt, 1, new_blocking);
				sqlite3_bind_int(stmt, 2, contact_id);
				if( sqlite3_step(stmt)!=SQLITE_DONE ) {
					goto cleanup;
				}
				sqlite3_finalize(stmt);
				stmt = NULL;

				/* also (un)block all chats with _only_ this contact - we do not delete them to allow a non-destructive blocking->unblocking.
				(Maybe, beside normal chats (type=100) we should also block group chats with only this user.
				However, I'm not sure about this point; it may be confusing if the user wants to add other people;
				this would result in recreating the same group...) */
				stmt = dc_sqlite3_prepare(context->m_sql,
					"UPDATE chats SET blocked=? WHERE type=? AND id IN (SELECT chat_id FROM chats_contacts WHERE contact_id=?);");
				sqlite3_bind_int(stmt, 1, new_blocking);
				sqlite3_bind_int(stmt, 2, DC_CHAT_TYPE_SINGLE);
				sqlite3_bind_int(stmt, 3, contact_id);
				if( sqlite3_step(stmt)!=SQLITE_DONE ) {
					goto cleanup;
				}

				/* mark all messages from the blocked contact as being noticed (this is to remove the deaddrop popup) */
				dc_marknoticed_contact(context, contact_id);

			dc_sqlite3_commit__(context->m_sql);
			transaction_pending = 0;

			send_event = 1;
		}

	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	if( send_event ) {
		context->m_cb(context, DC_EVENT_CONTACTS_CHANGED, 0, 0);
	}

cleanup:
	if( transaction_pending ) { dc_sqlite3_rollback__(context->m_sql); }
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	sqlite3_finalize(stmt);
	dc_contact_unref(contact);
}


static void cat_fingerprint(dc_strbuilder_t* ret, const char* addr, const char* fingerprint_verified, const char* fingerprint_unverified)
{
	dc_strbuilder_cat(ret, "\n\n");
	dc_strbuilder_cat(ret, addr);
	dc_strbuilder_cat(ret, ":\n");
	dc_strbuilder_cat(ret, (fingerprint_verified&&fingerprint_verified[0])? fingerprint_verified : fingerprint_unverified);

	if( fingerprint_verified && fingerprint_verified[0]
	 && fingerprint_unverified && fingerprint_unverified[0]
	 && strcmp(fingerprint_verified, fingerprint_unverified)!=0 ) {
		// might be that for verified chats the - older - verified gossiped key is used
		// and for normal chats the - newer - unverified key :/
		dc_strbuilder_cat(ret, "\n\n");
		dc_strbuilder_cat(ret, addr);
		dc_strbuilder_cat(ret, " (alternative):\n");
		dc_strbuilder_cat(ret, fingerprint_unverified);
	}
}


/**
 * Get encryption info for a contact.
 * Get a multi-line encryption info, containing your fingerprint and the
 * fingerprint of the contact, used eg. to compare the fingerprints for a simple out-of-band verification.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param contact_id ID of the contact to get the encryption info for.
 * @return multi-line text, must be free()'d after usage.
 */
char* dc_get_contact_encrinfo(dc_context_t* context, uint32_t contact_id)
{
	dc_loginparam_t* loginparam = dc_loginparam_new();
	dc_contact_t*    contact = dc_contact_new(context);
	dc_apeerstate_t* peerstate = dc_apeerstate_new(context);
	dc_key_t*        self_key = dc_key_new();
	char*            fingerprint_self = NULL;
	char*            fingerprint_other_verified = NULL;
	char*            fingerprint_other_unverified = NULL;
	char*            p = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_strbuilder_t  ret;
	dc_strbuilder_init(&ret, 0);

	if( !dc_contact_load_from_db(contact, context->m_sql, contact_id) ) {
		goto cleanup;
	}
	dc_apeerstate_load_by_addr(peerstate, context->m_sql, contact->m_addr);
	dc_loginparam_read(loginparam, context->m_sql, "configured_");

	dc_key_load_self_public(self_key, loginparam->m_addr, context->m_sql);

	if( dc_apeerstate_peek_key(peerstate, DC_NOT_VERIFIED) )
	{
		// E2E available :)
		p = dc_stock_str(peerstate->m_prefer_encrypt == DC_PE_MUTUAL? DC_STR_E2E_PREFERRED : DC_STR_E2E_AVAILABLE); dc_strbuilder_cat(&ret, p); free(p);

		if( self_key->m_binary == NULL ) {
			dc_pgp_rand_seed(context, peerstate->m_addr, strlen(peerstate->m_addr) /*just some random data*/);
			dc_ensure_secret_key_exists(context);
			dc_key_load_self_public(self_key, loginparam->m_addr, context->m_sql);
		}

		dc_strbuilder_cat(&ret, " ");
		p = dc_stock_str(DC_STR_FINGERPRINTS); dc_strbuilder_cat(&ret, p); free(p);
		dc_strbuilder_cat(&ret, ":");

		fingerprint_self = dc_key_get_formatted_fingerprint(self_key);
		fingerprint_other_verified = dc_key_get_formatted_fingerprint(dc_apeerstate_peek_key(peerstate, DC_BIDIRECT_VERIFIED));
		fingerprint_other_unverified = dc_key_get_formatted_fingerprint(dc_apeerstate_peek_key(peerstate, DC_NOT_VERIFIED));

		if( strcmp(loginparam->m_addr, peerstate->m_addr)<0 ) {
			cat_fingerprint(&ret, loginparam->m_addr, fingerprint_self, NULL);
			cat_fingerprint(&ret, peerstate->m_addr, fingerprint_other_verified, fingerprint_other_unverified);
		}
		else {
			cat_fingerprint(&ret, peerstate->m_addr, fingerprint_other_verified, fingerprint_other_unverified);
			cat_fingerprint(&ret, loginparam->m_addr, fingerprint_self, NULL);
		}
	}
	else
	{
		// No E2E available
		if( !(loginparam->m_server_flags&DC_LP_IMAP_SOCKET_PLAIN)
		 && !(loginparam->m_server_flags&DC_LP_SMTP_SOCKET_PLAIN) )
		{
			p = dc_stock_str(DC_STR_ENCR_TRANSP); dc_strbuilder_cat(&ret, p); free(p);
		}
		else
		{
			p = dc_stock_str(DC_STR_ENCR_NONE); dc_strbuilder_cat(&ret, p); free(p);
		}
	}

cleanup:
	dc_apeerstate_unref(peerstate);
	dc_contact_unref(contact);
	dc_loginparam_unref(loginparam);
	dc_key_unref(self_key);
	free(fingerprint_self);
	free(fingerprint_other_verified);
	free(fingerprint_other_unverified);
	return ret.m_buf;
}


/**
 * Delete a contact.  The contact is deleted from the local device.  It may happen that this is not
 * possible as the contact is in use.  In this case, the contact can be blocked.
 *
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param contact_id ID of the contact to delete.
 * @return 1=success, 0=error
 */
int dc_delete_contact(dc_context_t* context, uint32_t contact_id)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || contact_id <= DC_CONTACT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	/* we can only delete contacts that are not in use anywhere; this function is mainly for the user who has just
	created an contact manually and wants to delete it a moment later */
	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM chats_contacts WHERE contact_id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if( sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) >= 1 ) {
		goto cleanup;
	}
	sqlite3_finalize(stmt);
	stmt = NULL;

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs WHERE from_id=? OR to_id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	if( sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) >= 1 ) {
		goto cleanup;
	}
	sqlite3_finalize(stmt);
	stmt = NULL;

	stmt = dc_sqlite3_prepare(context->m_sql,
		"DELETE FROM contacts WHERE id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if( sqlite3_step(stmt) != SQLITE_DONE ) {
		goto cleanup;
	}

	context->m_cb(context, DC_EVENT_CONTACTS_CHANGED, 0, 0);

	success = 1;

cleanup:
	sqlite3_finalize(stmt);
	return success;
}


int dc_contact_addr_equals(dc_context_t* context, uint32_t contact_id, const char* other_addr)
{
	int addr_are_equal = 0;
	if( other_addr ) {
		dc_contact_t* contact = dc_contact_new(context);
		if( dc_contact_load_from_db(contact, context->m_sql, contact_id) ) {
			if( contact->m_addr ) {
				if( strcasecmp(contact->m_addr, other_addr)==0 ) {
					addr_are_equal = 1;
				}
			}
		}
		dc_contact_unref(contact);
	}
	return addr_are_equal;
}


/*******************************************************************************
 * Handle Messages
 ******************************************************************************/


void dc_update_msg_chat_id(dc_context_t* context, uint32_t msg_id, uint32_t chat_id)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE msgs SET chat_id=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


void dc_update_msg_state(dc_context_t* context, uint32_t msg_id, int state)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE msgs SET state=? WHERE id=?;");
	sqlite3_bind_int(stmt, 1, state);
	sqlite3_bind_int(stmt, 2, msg_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


size_t dc_get_real_msg_cnt(dc_context_t* context)
{
	sqlite3_stmt* stmt = NULL;
	size_t        ret = 0;

	if( context->m_sql->m_cobj==NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) "
		" FROM msgs m "
		" LEFT JOIN chats c ON c.id=m.chat_id "
		" WHERE m.id>" DC_STRINGIFY(DC_MSG_ID_LAST_SPECIAL)
		" AND m.chat_id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL)
		" AND c.blocked=0;");
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		dc_sqlite3_log_error(context->m_sql, "dc_get_real_msg_cnt() failed.");
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


size_t dc_get_deaddrop_msg_cnt(dc_context_t* context)
{
	sqlite3_stmt* stmt = NULL;
	size_t        ret = 0;

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs m LEFT JOIN chats c ON c.id=m.chat_id WHERE c.blocked=2;");
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


int dc_rfc724_mid_cnt(dc_context_t* context, const char* rfc724_mid)
{
	/* check the number of messages with the same rfc724_mid */
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if( context==NULL || context->m_magic != DC_CONTEXT_MAGIC || context->m_sql->m_cobj==NULL ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/* check, if the given Message-ID exists in the database (if not, the message is normally downloaded from the server and parsed,
so, we should even keep unuseful messages in the database (we can leave the other fields empty to save space) */
uint32_t dc_rfc724_mid_exists__(dc_context_t* context, const char* rfc724_mid, char** ret_server_folder, uint32_t* ret_server_uid)
{
	uint32_t ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT server_folder, server_uid, id FROM msgs WHERE rfc724_mid=?;");
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		if( ret_server_folder ) { *ret_server_folder = NULL; }
		if( ret_server_uid )    { *ret_server_uid    = 0; }
		goto cleanup;
	}

	if( ret_server_folder ) { *ret_server_folder = dc_strdup((char*)sqlite3_column_text(stmt, 0)); }
	if( ret_server_uid )    { *ret_server_uid = sqlite3_column_int(stmt, 1); /* may be 0 */ }
	ret = sqlite3_column_int(stmt, 2);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


void dc_update_server_uid(dc_context_t* context, const char* rfc724_mid, const char* server_folder, uint32_t server_uid)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
		"UPDATE msgs SET server_folder=?, server_uid=? WHERE rfc724_mid=?;"); /* we update by "rfc724_mid" instead of "id" as there may be several db-entries refering to the same "rfc724_mid" */
	sqlite3_bind_text(stmt, 1, server_folder, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, server_uid);
	sqlite3_bind_text(stmt, 3, rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


/**
 * Get a single message object of the type dc_msg_t.
 * For a list of messages in a chat, see dc_get_chat_msgs()
 * For a list or chats, see dc_get_chatlist()
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param msg_id The message ID for which the message object should be created.
 * @return A dc_msg_t message object. When done, the object must be freed using dc_msg_unref()
 */
dc_msg_t* dc_get_msg(dc_context_t* context, uint32_t msg_id)
{
	int success = 0;
	int db_locked = 0;
	dc_msg_t* obj = dc_msg_new();

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	db_locked = 1;

		if( !dc_msg_load_from_db(obj, context, msg_id) ) {
			goto cleanup;
		}

		success = 1;

cleanup:
	if( db_locked ) { dc_sqlite3_unlock(context->m_sql); }

	if( success ) {
		return obj;
	}
	else {
		dc_msg_unref(obj);
		return NULL;
	}
}


/**
 * Get an informational text for a single message. the text is multiline and may
 * contain eg. the raw text of the message.
 *
 * The max. text returned is typically longer (about 100000 characters) than the
 * max. text returned by dc_msg_get_text() (about 30000 characters).
 *
 * If the library is compiled for andoid, some basic html-formatting for he
 * subject and the footer is added. However we should change this function so
 * that it returns eg. an array of pairwise key-value strings and the caller
 * can show the whole stuff eg. in a table.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new().
 * @param msg_id the message id for which information should be generated
 * @return text string, must be free()'d after usage
 */
char* dc_get_msg_info(dc_context_t* context, uint32_t msg_id)
{
	dc_strbuilder_t ret;
	sqlite3_stmt*   stmt = NULL;
	dc_msg_t*       msg = dc_msg_new();
	dc_contact_t*   contact_from = dc_contact_new(context);
	char            *rawtxt = NULL, *p;
	dc_strbuilder_init(&ret, 0);

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC ) {
		goto cleanup;
	}

	dc_msg_load_from_db(msg, context, msg_id);
	dc_contact_load_from_db(contact_from, context->m_sql, msg->m_from_id);

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT txt_raw FROM msgs WHERE id=?;");
	sqlite3_bind_int(stmt, 1, msg_id);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		p = dc_mprintf("Cannot load message #%i.", (int)msg_id); dc_strbuilder_cat(&ret, p); free(p);
		goto cleanup;
	}
	rawtxt = dc_strdup((char*)sqlite3_column_text(stmt, 0));
	sqlite3_finalize(stmt);
	stmt = NULL;

	#ifdef __ANDROID__
		p = strchr(rawtxt, '\n');
		if( p ) {
			char* subject = rawtxt;
			*p = 0;
			p++;
			rawtxt = dc_mprintf("<b>%s</b>\n%s", subject, p);
			free(subject);
		}
	#endif

	dc_trim(rawtxt);
	dc_truncate_str(rawtxt, DC_MAX_GET_INFO_LEN);

	/* add time */
	dc_strbuilder_cat(&ret, "Sent: ");
	p = dc_timestamp_to_str(dc_msg_get_timestamp(msg)); dc_strbuilder_cat(&ret, p); free(p);
	dc_strbuilder_cat(&ret, "\n");

	if( msg->m_from_id != DC_CONTACT_ID_SELF ) {
		dc_strbuilder_cat(&ret, "Received: ");
		p = dc_timestamp_to_str(msg->m_timestamp_rcvd? msg->m_timestamp_rcvd : msg->m_timestamp); dc_strbuilder_cat(&ret, p); free(p);
		dc_strbuilder_cat(&ret, "\n");
	}

	if( msg->m_from_id == DC_CONTACT_ID_DEVICE || msg->m_to_id == DC_CONTACT_ID_DEVICE ) {
		goto cleanup; // device-internal message, no further details needed
	}

	/* add mdn's time and readers */
	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT contact_id, timestamp_sent FROM msgs_mdns WHERE msg_id=?;");
	sqlite3_bind_int (stmt, 1, msg_id);
	while( sqlite3_step(stmt) == SQLITE_ROW ) {
		dc_strbuilder_cat(&ret, "Read: ");
		p = dc_timestamp_to_str(sqlite3_column_int64(stmt, 1)); dc_strbuilder_cat(&ret, p); free(p);
		dc_strbuilder_cat(&ret, " by ");

		dc_contact_t* contact = dc_contact_new(context);
			dc_contact_load_from_db(contact, context->m_sql, sqlite3_column_int64(stmt, 0));
			p = dc_contact_get_display_name(contact); dc_strbuilder_cat(&ret, p); free(p);
		dc_contact_unref(contact);
		dc_strbuilder_cat(&ret, "\n");
	}
	sqlite3_finalize(stmt);
	stmt = NULL;

	/* add state */
	p = NULL;
	switch( msg->m_state ) {
		case DC_STATE_IN_FRESH:      p = dc_strdup("Fresh");           break;
		case DC_STATE_IN_NOTICED:    p = dc_strdup("Noticed");         break;
		case DC_STATE_IN_SEEN:       p = dc_strdup("Seen");            break;
		case DC_STATE_OUT_DELIVERED: p = dc_strdup("Delivered");       break;
		case DC_STATE_OUT_ERROR:     p = dc_strdup("Error");           break;
		case DC_STATE_OUT_MDN_RCVD:  p = dc_strdup("Read");            break;
		case DC_STATE_OUT_PENDING:   p = dc_strdup("Pending");         break;
		default:                     p = dc_mprintf("%i", msg->m_state); break;
	}
	dc_strbuilder_catf(&ret, "State: %s", p);
	free(p);

	p = NULL;
	int e2ee_errors;
	if( (e2ee_errors=dc_param_get_int(msg->m_param, DC_PARAM_ERRONEOUS_E2EE, 0)) ) {
		if( e2ee_errors&DC_E2EE_NO_VALID_SIGNATURE ) {
			p = dc_strdup("Encrypted, no valid signature");
		}
	}
	else if( dc_param_get_int(msg->m_param, DC_PARAM_GUARANTEE_E2EE, 0) ) {
		p = dc_strdup("Encrypted");
	}

	if( p ) {
		dc_strbuilder_catf(&ret, ", %s", p);
		free(p);
	}
	dc_strbuilder_cat(&ret, "\n");

	/* add sender (only for info messages as the avatar may not be shown for them) */
	if( dc_msg_is_info(msg) ) {
		dc_strbuilder_cat(&ret, "Sender: ");
		p = dc_contact_get_name_n_addr(contact_from); dc_strbuilder_cat(&ret, p); free(p);
		dc_strbuilder_cat(&ret, "\n");
	}

	/* add file info */
	char* file = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
	if( file ) {
		p = dc_mprintf("\nFile: %s, %i bytes\n", file, (int)dc_get_filebytes(file)); dc_strbuilder_cat(&ret, p); free(p);
	}

	if( msg->m_type != DC_MSG_TEXT ) {
		p = NULL;
		switch( msg->m_type )  {
			case DC_MSG_AUDIO: p = dc_strdup("Audio");          break;
			case DC_MSG_FILE:  p = dc_strdup("File");           break;
			case DC_MSG_GIF:   p = dc_strdup("GIF");            break;
			case DC_MSG_IMAGE: p = dc_strdup("Image");          break;
			case DC_MSG_VIDEO: p = dc_strdup("Video");          break;
			case DC_MSG_VOICE: p = dc_strdup("Voice");          break;
			default:           p = dc_mprintf("%i", msg->m_type); break;
		}
		dc_strbuilder_catf(&ret, "Type: %s\n", p);
		free(p);
	}

	int w = dc_param_get_int(msg->m_param, DC_PARAM_WIDTH, 0), h = dc_param_get_int(msg->m_param, DC_PARAM_HEIGHT, 0);
	if( w != 0 || h != 0 ) {
		p = dc_mprintf("Dimension: %i x %i\n", w, h); dc_strbuilder_cat(&ret, p); free(p);
	}

	int duration = dc_param_get_int(msg->m_param, DC_PARAM_DURATION, 0);
	if( duration != 0 ) {
		p = dc_mprintf("Duration: %i ms\n", duration); dc_strbuilder_cat(&ret, p); free(p);
	}

	/* add rawtext */
	if( rawtxt && rawtxt[0] ) {
		dc_strbuilder_cat(&ret, "\n");
		dc_strbuilder_cat(&ret, rawtxt);
		dc_strbuilder_cat(&ret, "\n");
	}

	/* add Message-ID, Server-Folder and Server-UID; the database ID is normally only of interest if you have access to sqlite; if so you can easily get it from the "msgs" table. */
	#ifdef __ANDROID__
		dc_strbuilder_cat(&ret, "<c#808080>");
	#endif

	if( msg->m_rfc724_mid && msg->m_rfc724_mid[0] ) {
		dc_strbuilder_catf(&ret, "\nMessage-ID: %s", msg->m_rfc724_mid);
	}

	if( msg->m_server_folder && msg->m_server_folder[0] ) {
		dc_strbuilder_catf(&ret, "\nLast seen as: %s/%i", msg->m_server_folder, (int)msg->m_server_uid);
	}

	#ifdef __ANDROID__
		dc_strbuilder_cat(&ret, "</c>");
	#endif

cleanup:
	sqlite3_finalize(stmt);
	dc_msg_unref(msg);
	dc_contact_unref(contact_from);
	free(rawtxt);
	return ret.m_buf;
}


/**
 * Forward messages to another chat.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new()
 * @param msg_ids an array of uint32_t containing all message IDs that should be forwarded
 * @param msg_cnt the number of messages IDs in the msg_ids array
 * @param chat_id The destination chat ID.
 * @return none
 */
void dc_forward_msgs(dc_context_t* context, const uint32_t* msg_ids, int msg_cnt, uint32_t chat_id)
{
	dc_msg_t*      msg = dc_msg_new();
	dc_chat_t*     chat = dc_chat_new(context);
	dc_contact_t*  contact = dc_contact_new(context);
	int           locked = 0, transaction_pending = 0;
	carray*       created_db_entries = carray_new(16);
	char*         idsstr = NULL, *q3 = NULL;
	sqlite3_stmt* stmt = NULL;
	time_t        curr_timestamp;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || msg_ids==NULL || msg_cnt <= 0 || chat_id <= DC_CHAT_ID_LAST_SPECIAL ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;
	dc_sqlite3_begin_transaction__(context->m_sql);
	transaction_pending = 1;

		dc_unarchive_chat(context, chat_id);

		context->m_smtp->m_log_connect_errors = 1;

		if( !dc_chat_load_from_db(chat, chat_id) ) {
			goto cleanup;
		}

		curr_timestamp = dc_create_smeared_timestamps__(msg_cnt);

		idsstr = dc_arr_to_string(msg_ids, msg_cnt);
		q3 = sqlite3_mprintf("SELECT id FROM msgs WHERE id IN(%s) ORDER BY timestamp,id", idsstr);
		stmt = dc_sqlite3_prepare(context->m_sql, q3);
		while( sqlite3_step(stmt)==SQLITE_ROW )
		{
			int src_msg_id = sqlite3_column_int(stmt, 0);
			if( !dc_msg_load_from_db(msg, context, src_msg_id) ) {
				goto cleanup;
			}

			dc_param_set_int(msg->m_param, DC_PARAM_FORWARDED, 1);
			dc_param_set    (msg->m_param, DC_PARAM_GUARANTEE_E2EE, NULL);
			dc_param_set    (msg->m_param, DC_PARAM_FORCE_PLAINTEXT, NULL);

			uint32_t new_msg_id = dc_send_msg_raw(context, chat, msg, curr_timestamp++);
			carray_add(created_db_entries, (void*)(uintptr_t)chat_id, NULL);
			carray_add(created_db_entries, (void*)(uintptr_t)new_msg_id, NULL);
		}

	dc_sqlite3_commit__(context->m_sql);
	transaction_pending = 0;

cleanup:
	if( transaction_pending ) { dc_sqlite3_rollback__(context->m_sql); }
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	if( created_db_entries ) {
		size_t i, icnt = carray_count(created_db_entries);
		for( i = 0; i < icnt; i += 2 ) {
			context->m_cb(context, DC_EVENT_MSGS_CHANGED, (uintptr_t)carray_get(created_db_entries, i), (uintptr_t)carray_get(created_db_entries, i+1));
		}
		carray_free(created_db_entries);
	}
	dc_contact_unref(contact);
	dc_msg_unref(msg);
	dc_chat_unref(chat);
	sqlite3_finalize(stmt);
	free(idsstr);
	sqlite3_free(q3);
}


/**
 * Star/unstar messages by setting the last parameter to 0 (unstar) or 1 (star).
 * Starred messages are collected in a virtual chat that can be shown using
 * dc_get_chat_msgs() using the chat_id DC_CHAT_ID_STARRED.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new()
 * @param msg_ids An array of uint32_t message IDs defining the messages to star or unstar
 * @param msg_cnt The number of IDs in msg_ids
 * @param star 0=unstar the messages in msg_ids, 1=star them
 * @return none
 */
void dc_star_msgs(dc_context_t* context, const uint32_t* msg_ids, int msg_cnt, int star)
{
	int i;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || msg_ids == NULL || msg_cnt <= 0 || (star!=0 && star!=1) ) {
		return;
	}

	dc_sqlite3_lock(context->m_sql);
	dc_sqlite3_begin_transaction__(context->m_sql);

		sqlite3_stmt* stmt = dc_sqlite3_prepare(context->m_sql,
			"UPDATE msgs SET starred=? WHERE id=?;");
		for( i = 0; i < msg_cnt; i++ )
		{
			sqlite3_reset(stmt);
			sqlite3_bind_int(stmt, 1, star);
			sqlite3_bind_int(stmt, 2, msg_ids[i]);
			sqlite3_step(stmt);
		}
		sqlite3_finalize(stmt);

	dc_sqlite3_commit__(context->m_sql);
	dc_sqlite3_unlock(context->m_sql);
}


/*******************************************************************************
 * Delete messages
 ******************************************************************************/


/**
 * Delete messages. The messages are deleted on the current device and
 * on the IMAP server.
 *
 * @memberof dc_context_t
 * @param context the context object as created by dc_context_new()
 * @param msg_ids an array of uint32_t containing all message IDs that should be deleted
 * @param msg_cnt the number of messages IDs in the msg_ids array
 * @return none
 */
void dc_delete_msgs(dc_context_t* context, const uint32_t* msg_ids, int msg_cnt)
{
	int i;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || msg_ids == NULL || msg_cnt <= 0 ) {
		return;
	}

	dc_sqlite3_lock(context->m_sql);
	dc_sqlite3_begin_transaction__(context->m_sql);

		for( i = 0; i < msg_cnt; i++ )
		{
			dc_update_msg_chat_id(context, msg_ids[i], DC_CHAT_ID_TRASH);
			dc_job_add(context, DC_JOB_DELETE_MSG_ON_IMAP, msg_ids[i], NULL, 0);
		}

	dc_sqlite3_commit__(context->m_sql);
	dc_sqlite3_unlock(context->m_sql);
}


/*******************************************************************************
 * mark message as seen
 ******************************************************************************/


/**
 * Mark a message as _seen_, updates the IMAP state and
 * sends MDNs. If the message is not in a real chat (eg. a contact request), the
 * message is only marked as NOTICED and no IMAP/MDNs is done.  See also
 * dc_marknoticed_chat() and dc_marknoticed_contact()
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids an array of uint32_t containing all the messages IDs that should be marked as seen.
 * @param msg_cnt The number of message IDs in msg_ids.
 * @return none
 */
void dc_markseen_msgs(dc_context_t* context, const uint32_t* msg_ids, int msg_cnt)
{
	int locked = 0;
	int transaction_pending = 0;
	int i = 0;
	int send_event = 0;
	int curr_state = 0;
	int curr_blocked = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || msg_ids == NULL || msg_cnt <= 0 ) {
		goto cleanup;
	}

	dc_sqlite3_lock(context->m_sql);
	locked = 1;
	dc_sqlite3_begin_transaction__(context->m_sql);
	transaction_pending = 1;

		stmt = dc_sqlite3_prepare(context->m_sql,
			"SELECT m.state, c.blocked "
			" FROM msgs m "
			" LEFT JOIN chats c ON c.id=m.chat_id "
			" WHERE m.id=? AND m.chat_id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL));
		for( i = 0; i < msg_cnt; i++ )
		{
			sqlite3_reset(stmt);
			sqlite3_bind_int(stmt, 1, msg_ids[i]);
			if( sqlite3_step(stmt) != SQLITE_ROW ) {
				continue;
			}
			curr_state   = sqlite3_column_int(stmt, 0);
			curr_blocked = sqlite3_column_int(stmt, 1);
			if( curr_blocked == 0 )
			{
				if( curr_state == DC_STATE_IN_FRESH || curr_state == DC_STATE_IN_NOTICED ) {
					dc_update_msg_state(context, msg_ids[i], DC_STATE_IN_SEEN);
					dc_log_info(context, 0, "Seen message #%i.", msg_ids[i]);
					dc_job_add(context, DC_JOB_MARKSEEN_MSG_ON_IMAP, msg_ids[i], NULL, 0); /* results in a call to dc_markseen_msg_on_imap() */
					send_event = 1;
				}
			}
			else
			{
				/* message may be in contact requests, mark as NOTICED, this does not force IMAP updated nor send MDNs */
				if( curr_state == DC_STATE_IN_FRESH ) {
					dc_update_msg_state(context, msg_ids[i], DC_STATE_IN_NOTICED);
					send_event = 1;
				}
			}
		}

	dc_sqlite3_commit__(context->m_sql);
	transaction_pending = 0;
	dc_sqlite3_unlock(context->m_sql);
	locked = 0;

	/* the event is needed eg. to remove the deaddrop from the chatlist */
	if( send_event ) {
		context->m_cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
	}

cleanup:
	if( transaction_pending ) { dc_sqlite3_rollback__(context->m_sql); }
	if( locked ) { dc_sqlite3_unlock(context->m_sql); }
	sqlite3_finalize(stmt);
}


int dc_mdn_from_ext(dc_context_t* context, uint32_t from_id, const char* rfc724_mid, time_t timestamp_sent,
                    uint32_t* ret_chat_id, uint32_t* ret_msg_id)
{
	int           read_by_all = 0;
	sqlite3_stmt* stmt = NULL;

	if( context == NULL || context->m_magic != DC_CONTEXT_MAGIC || from_id <= DC_CONTACT_ID_LAST_SPECIAL || rfc724_mid == NULL || ret_chat_id==NULL || ret_msg_id==NULL
	 || *ret_chat_id != 0 || *ret_msg_id != 0 ) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT m.id, c.id, c.type, m.state FROM msgs m "
		" LEFT JOIN chats c ON m.chat_id=c.id "
		" WHERE rfc724_mid=? AND from_id=1 "
		" ORDER BY m.id;"); /* the ORDER BY makes sure, if one rfc724_mid is splitted into its parts, we always catch the same one. However, we do not send multiparts, we do not request MDNs for multiparts, and should not receive read requests for multiparts. So this is currently more theoretical. */
	sqlite3_bind_text(stmt, 1, rfc724_mid, -1, SQLITE_STATIC);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup;
	}
	*ret_msg_id    = sqlite3_column_int(stmt, 0);
	*ret_chat_id   = sqlite3_column_int(stmt, 1);
	int chat_type  = sqlite3_column_int(stmt, 2);
	int msg_state  = sqlite3_column_int(stmt, 3);
	sqlite3_finalize(stmt);
	stmt = NULL;

	if( msg_state!=DC_STATE_OUT_PENDING && msg_state!=DC_STATE_OUT_DELIVERED ) {
		goto cleanup; /* eg. already marked as MDNS_RCVD. however, it is importent, that the message ID is set above as this will allow the caller eg. to move the message away */
	}

	// collect receipt senders, we do this also for normal chats as we may want to show the timestamp
	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT contact_id FROM msgs_mdns WHERE msg_id=? AND contact_id=?;");
	sqlite3_bind_int(stmt, 1, *ret_msg_id);
	sqlite3_bind_int(stmt, 2, from_id);
	int mdn_already_in_table = (sqlite3_step(stmt) == SQLITE_ROW)? 1 : 0;
	sqlite3_finalize(stmt);
	stmt = NULL;

	if( !mdn_already_in_table ) {
		stmt = dc_sqlite3_prepare(context->m_sql,
			"INSERT INTO msgs_mdns (msg_id, contact_id, timestamp_sent) VALUES (?, ?, ?);");
		sqlite3_bind_int  (stmt, 1, *ret_msg_id);
		sqlite3_bind_int  (stmt, 2, from_id);
		sqlite3_bind_int64(stmt, 3, timestamp_sent);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	// Normal chat? that's quite easy.
	if( chat_type == DC_CHAT_TYPE_SINGLE ) {
		dc_update_msg_state(context, *ret_msg_id, DC_STATE_OUT_MDN_RCVD);
		read_by_all = 1;
		goto cleanup; /* send event about new state */
	}

	// Group chat: get the number of receipt senders
	stmt = dc_sqlite3_prepare(context->m_sql,
		"SELECT COUNT(*) FROM msgs_mdns WHERE msg_id=?;");
	sqlite3_bind_int(stmt, 1, *ret_msg_id);
	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		goto cleanup; /* error */
	}
	int ist_cnt  = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	stmt = NULL;

	/*
	Groupsize:  Min. MDNs

	1 S         n/a
	2 SR        1
	3 SRR       2
	4 SRRR      2
	5 SRRRR     3
	6 SRRRRR    3

	(S=Sender, R=Recipient)
	*/
	int soll_cnt = (dc_get_chat_contact_count(context, *ret_chat_id)+1/*for rounding, SELF is already included!*/) / 2;
	if( ist_cnt < soll_cnt ) {
		goto cleanup; /* wait for more receipts */
	}

	/* got enough receipts :-) */
	dc_update_msg_state(context, *ret_msg_id, DC_STATE_OUT_MDN_RCVD);
	read_by_all = 1;

cleanup:
	sqlite3_finalize(stmt);
	return read_by_all;
}
