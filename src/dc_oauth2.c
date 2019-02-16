#include "dc_context.h"
#include "dc_oauth2.h"
#include "dc_jsmn.h"


static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	// from the jsmn parser example
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}


static char* jsondup(const char *json, jsmntok_t *tok) {
	if (tok->type == JSMN_STRING) {
		return strndup(json+tok->start, tok->end - tok->start);
	}
	return strdup("");
}


static int is_expired(dc_context_t* context)
{
	time_t expire_timestamp = dc_sqlite3_get_config_int64(context->sql,
		"oauth2_timestamp_expires", 0);

	if (expire_timestamp<=0) {
		dc_log_info(context, 0, "===== OAuth: no expire time =====");
		return 0; // timestamp does never expire
	}

	if (expire_timestamp>time(NULL)) {
		dc_log_info(context, 0, "===== OAuth: still valid =====");
		return 0; // expire timestamp is in the future and not yet expired
	}

	dc_log_info(context, 0, "===== OAuth: expired =====");
	return 1; // expired
}


char* dc_get_oauth2_url(dc_context_t* context, const char* addr)
{
	#define CLIENT_ID     "959970109878-t6pl4k9fmsdvfnobae862urapdmhfvbe.apps.googleusercontent.com"
	#define CLIENT_SECRET "g2f_Gc1YUJ-fWjnTkdsuk4Xo"
	#define AUTH_REDIRECT "urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob"
	#define AUTH_SCOPE    "https%3A%2F%2Fmail.google.com%2F%20email"

	char*       oauth2_url = NULL;
	char*       addr_normalized = NULL;
	const char* domain = NULL;

	addr_normalized = dc_addr_normalize(addr);
	domain = strchr(addr_normalized, '@');
	if (domain==NULL || domain[0]==0) {
		goto cleanup;
	}
	domain++;

	if (strcasecmp(domain, "gmail.com")==0
	 || strcasecmp(domain, "googlemail.com")==0) {
		oauth2_url = dc_mprintf("https://accounts.google.com/o/oauth2/auth"
			"?client_id=%s"
			"&redirect_uri=%s"
			"&response_type=code"
			"&scope=%s"
			"&access_type=offline",
			CLIENT_ID, AUTH_REDIRECT, AUTH_SCOPE);
	}

cleanup:
	free(addr_normalized);
	return oauth2_url;
}


char* dc_get_oauth2_access_token(dc_context_t* context, const char* code, int flags)
{
	char*       access_token = NULL;
	char*       refresh_token = NULL;
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
	#define TOKEN_REDIRECT_URI "urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob"

	refresh_token = dc_sqlite3_get_config(context->sql, "oauth2_refresh_token", NULL);
	if (refresh_token==NULL)
	{
		dc_log_info(context, 0, "===== OAuth: get code =====");
		token_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&client_secret=%s"
			"&grant_type=authorization_code"
			"&code=%s"
			"&redirect_uri=%s",
			CLIENT_ID, CLIENT_SECRET, code, TOKEN_REDIRECT_URI);
	}
	else
	{
		dc_log_info(context, 0, "===== OAuth: regen =====");
		token_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&client_secret=%s"
			"&grant_type=refresh_token"
			"&refresh_token=%s"
			"&redirect_uri=%s",
			CLIENT_ID, CLIENT_SECRET, refresh_token, TOKEN_REDIRECT_URI);
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
		if (jsoneq(json, &tok[i], "access_token")==0) {
			access_token = jsondup(json, &tok[i+1]);
		}
		else if (jsoneq(json, &tok[i], "refresh_token")==0) {
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
		else if (jsoneq(json, &tok[i], "error")==0) {
			error = jsondup(json, &tok[i+1]);
		}
		else if (jsoneq(json, &tok[i], "error_description")==0) {
			error_description = jsondup(json, &tok[i+1]);
		}
	}

	if (error || error_description) {
		dc_log_warning(context, 0, "OAuth error: %s: %s",
			error? error : "unknown",
			error_description? error_description : "no details");
		// continue, errors do not imply everything went wrong
	}

	if (access_token==NULL || access_token[0]==0) {
		dc_log_warning(context, 0, "Failed to find OAuth2 access token");
		goto cleanup;
	}

	dc_sqlite3_set_config(context->sql, "oauth2_access_token", access_token);

	dc_sqlite3_set_config_int64(context->sql, "oauth2_timestamp_expires",
		expires_in? time(NULL)+expires_in-5/*refresh a bet before*/ : 0);

	// update refresh_token if given,
	// typically this is on the first round with `grant_type=authorization_code`
	// but we update it later, too.
	if (refresh_token && refresh_token[0]) {
		dc_sqlite3_set_config(context->sql, "oauth2_refresh_token", refresh_token);
	}

cleanup:
	if (locked) { pthread_mutex_unlock(&context->oauth2_critical); }
	free(refresh_token);
	free(token_url);
	free(json);
	free(error);
	free(error_description);
	return access_token? access_token : dc_strdup(NULL);
}
