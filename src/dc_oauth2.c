#include "dc_context.h"
#include "dc_oauth2.h"
#include "dc_jsmn.h"


// TODO: refactor code so that it works with non-google oauth2 (outlook?, ??)


static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	// from the jsmn parser example
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}


static char* jsondup(const char *json, jsmntok_t *tok) {
	if (tok->type == JSMN_STRING || tok->type == JSMN_PRIMITIVE) {
		return strndup(json+tok->start, tok->end - tok->start);
	}
	return strdup("");
}


static int is_expired(dc_context_t* context)
{
	time_t expire_timestamp = dc_sqlite3_get_config_int64(context->sql,
		"oauth2_timestamp_expires", 0);

	if (expire_timestamp<=0) {
		return 0; // timestamp does never expire
	}

	if (expire_timestamp>time(NULL)) {
		return 0; // expire timestamp is in the future and not yet expired
	}

	return 1; // expired
}


/**
 * Get url that can be used to initiate an OAuth2 authorisation.
 *
 * If an OAuth2 authorization is possible for a given e-mail-address,
 * this function returns the URL that should be opened in a browser.
 *
 * If the user authorizes access,
 * the given redirect_uri is called by the provider.
 * It's up to the UI to handle this call.
 *
 * The provider will attach some parameters to the url,
 * most important the parameter `code` that should be set as the `mail_pw`.
 * With `server_flags` set to #DC_LP_AUTH_OAUTH2,
 * dc_configure() can be called as usual afterwards.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @param addr E-mail address the user has entered.
 *     In case the user selects a different e-mail-address during
 *     authorization, this is corrected in dc_configure()
 * @param redirect_uri URL that will get `code` that is used as `mail_pw` then.
 *     Not all URLs are allowed here, however, the following should work:
 *     `chat.delta:/PATH`, `http://localhost:PORT/PATH`,
 *     `https://localhost:PORT/PATH`, `urn:ietf:wg:oauth:2.0:oob`
 *     (the latter just displays the code the user can copy+paste then)
 * @return URL that can be opened in the browser to start OAuth2.
 *     If OAuth2 is not possible for the given e-mail-address, NULL is returned.
 */
char* dc_get_oauth2_url(dc_context_t* context, const char* addr,
                        const char* redirect_uri)
{
	#define CLIENT_ID     "959970109878-4mvtgf6feshskf7695nfln6002mom908.apps.googleusercontent.com"
	#define AUTH_SCOPE    "https%3A%2F%2Fmail.google.com%2F%20email"

	char*       oauth2_url = NULL;
	char*       addr_normalized = NULL;
	char*       redirect_uri_urlencoded = NULL;
	const char* domain = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || redirect_uri==NULL || redirect_uri[0]==0) {
		goto cleanup;
	}

	addr_normalized = dc_addr_normalize(addr);
	domain = strchr(addr_normalized, '@');
	if (domain==NULL || domain[0]==0) {
		goto cleanup;
	}
	domain++;

	redirect_uri_urlencoded = dc_urlencode(redirect_uri);
	dc_sqlite3_set_config(context->sql, "oauth2_pending_redirect_uri", redirect_uri);

	if (strcasecmp(domain, "gmail.com")==0
	 || strcasecmp(domain, "googlemail.com")==0) {
		oauth2_url = dc_mprintf("https://accounts.google.com/o/oauth2/auth"
			"?client_id=%s"
			"&redirect_uri=%s"
			"&response_type=code"
			"&scope=%s"
			"&access_type=offline",
			CLIENT_ID, redirect_uri_urlencoded, AUTH_SCOPE);
	}

cleanup:
	free(addr_normalized);
	free(redirect_uri_urlencoded);
	return oauth2_url;
}


char* dc_get_oauth2_access_token(dc_context_t* context, const char* code, int flags)
{
	char*       access_token = NULL;
	char*       refresh_token = NULL;
	char*       refresh_token_for = NULL;
	char*       redirect_uri = NULL;
	char*       redirect_uri_urlencoded = NULL;
	int         update_redirect_uri_on_success = 0;
	char*       token_url = NULL;
	time_t      expires_in = 0;
	char*       error = NULL;
	char*       error_description = NULL;
	char*       json = NULL;
	jsmn_parser parser;
	jsmntok_t   tok[128]; // we do not expect nor read more tokens
	int         tok_cnt = 0;
	int         locked = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || code==NULL || code[0]==0) {
		dc_log_warning(context, 0, "Internal OAuth2 error");
		goto cleanup;
	}

	pthread_mutex_lock(&context->oauth2_critical);
	locked = 1;

	// read generated token
	if ( !(flags&DC_REGENERATE) && !is_expired(context) ) {
		access_token = dc_sqlite3_get_config(context->sql, "oauth2_access_token", NULL);
		if (access_token!=NULL) {
			goto cleanup; // success
		}
	}

	// generate new token: build & call auth url
	refresh_token = dc_sqlite3_get_config(context->sql, "oauth2_refresh_token", NULL);
	refresh_token_for = dc_sqlite3_get_config(context->sql, "oauth2_refresh_token_for", "unset");
	if (refresh_token==NULL || strcmp(refresh_token_for, code)!=0)
	{
		dc_log_info(context, 0, "Generate OAuth2 refresh_token and access_token...");

		redirect_uri = dc_sqlite3_get_config(context->sql, "oauth2_pending_redirect_uri", "unset");
		redirect_uri_urlencoded = dc_urlencode(redirect_uri);
		update_redirect_uri_on_success = 1;

		token_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&grant_type=authorization_code"
			"&code=%s"
			"&redirect_uri=%s",
			CLIENT_ID, code, redirect_uri_urlencoded);
	}
	else
	{
		dc_log_info(context, 0, "Regenerate OAuth2 access_token by refresh_token...");

		redirect_uri = dc_sqlite3_get_config(context->sql, "oauth2_redirect_uri", "unset");
		redirect_uri_urlencoded = dc_urlencode(redirect_uri);

		token_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&grant_type=refresh_token"
			"&refresh_token=%s"
			"&redirect_uri=%s",
			CLIENT_ID, refresh_token, redirect_uri_urlencoded);
	}

	json = (char*)context->cb(context, DC_EVENT_HTTP_POST, (uintptr_t)token_url, 0);
	if (json==NULL) {
		dc_log_warning(context, 0, "Error calling OAuth2 url");
		goto cleanup;
	}

	// generate new token: parse returned json
	jsmn_init(&parser);
	tok_cnt = jsmn_parse(&parser, json, strlen(json), tok, sizeof(tok)/sizeof(tok[0]));
	if (tok_cnt<2 || tok[0].type!=JSMN_OBJECT) {
		dc_log_warning(context, 0, "Failed to parse OAuth2 json");
		goto cleanup;
	}

	for (int i = 1; i < tok_cnt; i++) {
		if (access_token==NULL && jsoneq(json, &tok[i], "access_token")==0) {
			access_token = jsondup(json, &tok[i+1]);
		}
		else if (refresh_token==NULL && jsoneq(json, &tok[i], "refresh_token")==0) {
			refresh_token = jsondup(json, &tok[i+1]);
		}
		else if (jsoneq(json, &tok[i], "expires_in")==0) {
			char* expires_in_str = jsondup(json, &tok[i+1]);
			if (expires_in_str) {
				time_t val = atol(expires_in_str);
				// val should be reasonable, maybe between 20 seconds and 5 years.
				// if out of range, we re-create when the token gets invalid,
				// which may create some additional load and requests wrt threads.
				if (val>20 && val<(60*60*24*365*5)) {
					expires_in = val;
				}
				free(expires_in_str);
			}
		}
		else if (error==NULL && jsoneq(json, &tok[i], "error")==0) {
			error = jsondup(json, &tok[i+1]);
		}
		else if (error_description==NULL && jsoneq(json, &tok[i], "error_description")==0) {
			error_description = jsondup(json, &tok[i+1]);
		}
	}

	if (error || error_description) {
		dc_log_warning(context, 0, "OAuth error: %s: %s",
			error? error : "unknown",
			error_description? error_description : "no details");
		// continue, errors do not imply everything went wrong
	}

	// update refresh_token if given, typically on the first round, but we update it later as well.
	if (refresh_token && refresh_token[0]) {
		dc_sqlite3_set_config(context->sql, "oauth2_refresh_token", refresh_token);
		dc_sqlite3_set_config(context->sql, "oauth2_refresh_token_for", code);
	}

	// after that, save the access token.
	// if it's unset, we may get it in the next round as we have the refresh_token now.
	if (access_token==NULL || access_token[0]==0) {
		dc_log_warning(context, 0, "Failed to find OAuth2 access token");
		goto cleanup;
	}

	dc_sqlite3_set_config(context->sql, "oauth2_access_token", access_token);
	dc_sqlite3_set_config_int64(context->sql, "oauth2_timestamp_expires",
		expires_in? time(NULL)+expires_in-5/*refresh a bet before*/ : 0);

	if (update_redirect_uri_on_success) {
		dc_sqlite3_set_config(context->sql, "oauth2_redirect_uri", redirect_uri);
	}

cleanup:
	if (locked) { pthread_mutex_unlock(&context->oauth2_critical); }
	free(refresh_token);
	free(refresh_token_for);
	free(redirect_uri);
	free(redirect_uri_urlencoded);
	free(token_url);
	free(json);
	free(error);
	free(error_description);
	return access_token? access_token : dc_strdup(NULL);
}


static char* get_oauth2_addr(dc_context_t* context, char* access_token)
{
	char*       addr_out = NULL;
	char*       userinfo_url = NULL;
	char*       json = NULL;
	jsmn_parser parser;
	jsmntok_t   tok[128]; // we do not expect nor read more tokens
	int         tok_cnt = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || access_token==NULL || access_token[0]==0) {
		goto cleanup;
	}

	userinfo_url = dc_mprintf(
		"https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s",
		access_token);
	// returns sth. as
	// {
	//   "id": "100000000831024152393",
	//   "email": "NAME@gmail.com",
	//   "verified_email": true,
	//   "picture": "https://lh4.googleusercontent.com/-Gj5jh_9R0BY/AAAAAAAAAAI/AAAAAAAAAAA/IAjtjfjtjNA/photo.jpg"
	// }

	json = (char*)context->cb(context, DC_EVENT_HTTP_GET, (uintptr_t)userinfo_url, 0);
	if (json==NULL) {
		dc_log_warning(context, 0, "Error getting userinfo.");
		goto cleanup;
	}

	jsmn_init(&parser);
	tok_cnt = jsmn_parse(&parser, json, strlen(json), tok, sizeof(tok)/sizeof(tok[0]));
	if (tok_cnt<2 || tok[0].type!=JSMN_OBJECT) {
		dc_log_warning(context, 0, "Failed to parse userinfo.");
		goto cleanup;
	}

	for (int i = 1; i < tok_cnt; i++) {
		if (addr_out==NULL && jsoneq(json, &tok[i], "email")==0) {
			addr_out = jsondup(json, &tok[i+1]);
		}
	}

	if (addr_out==NULL) {
		dc_log_warning(context, 0, "E-mail missing in userinfo.");
	}

cleanup:
	free(userinfo_url);
	free(json);
	return addr_out;
}


char* dc_get_oauth2_addr(dc_context_t* context, const char* code)
{
	char* access_token = NULL;
	char* addr_out = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	access_token = dc_get_oauth2_access_token(context, code, 0);
	addr_out = get_oauth2_addr(context, access_token);
	if (addr_out==NULL) {
		free(access_token);
		access_token = dc_get_oauth2_access_token(context, code, DC_REGENERATE);
		addr_out = get_oauth2_addr(context, access_token);
	}

cleanup:
	free(access_token);
	return addr_out;
}
