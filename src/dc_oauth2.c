#include "dc_context.h"
#include "dc_oauth2.h"
#include "../libs/jsmn/jsmn.h"


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


char* dc_oauth2_get_access_token(dc_context_t* context, const char* code, int flags)
{
	char*       access_token = NULL;
	char*       refresh_token = NULL;
	char*       auth_url = NULL;
	char*       expires_in_str = NULL;
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
	if (!(flags&DC_REGENERATE)) {
		access_token = dc_sqlite3_get_config(context->sql, "oauth2_access_token", NULL);
		if (access_token!=NULL) {
			goto cleanup; // success
		}
	}

	// generate new token: build & call auth url
	#define CLIENT_ID     "959970109878-t6pl4k9fmsdvfnobae862urapdmhfvbe.apps.googleusercontent.com"
	#define CLIENT_SECRET "g2f_Gc1YUJ-fWjnTkdsuk4Xo"
	#define REDIRECT_URI  "urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob"

	refresh_token = dc_sqlite3_get_config(context->sql, "oauth2_refresh_token", NULL);
	if (refresh_token==NULL)
	{
		auth_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&client_secret=%s"
			"&grant_type=authorization_code"
			"&code=%s"
			"&redirect_uri=%s",
			CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI);
	}
	else
	{
		auth_url = dc_mprintf("https://accounts.google.com/o/oauth2/token"
			"?client_id=%s"
			"&client_secret=%s"
			"&grant_type=refresh_token"
			"&refresh_token=%s"
			"&redirect_uri=%s",
			CLIENT_ID, CLIENT_SECRET, refresh_token, REDIRECT_URI);
	}

	json = (char*)context->cb(context, DC_EVENT_HTTP_POST, (uintptr_t)auth_url, 0);
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
			expires_in_str = jsondup(json, &tok[i+1]);
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
		dc_log_warning(context, 0, "FULL COMMAND WAS: %s", auth_url);
		// continue, errors do not imply everything went wrong
	}

	if (access_token==NULL || access_token[0]==0) {
		dc_log_warning(context, 0, "Failed to find OAuth2 access token");
		goto cleanup;
	}

	dc_sqlite3_set_config(context->sql, "oauth2_access_token", access_token);

	// update refresh_token if given,
	// typically this is on the first round with `grant_type=authorization_code`
	// but we update it later, too.
	if (refresh_token && refresh_token[0]) {
		dc_sqlite3_set_config(context->sql, "oauth2_refresh_token", refresh_token);
	}

cleanup:
	if (locked) { pthread_mutex_unlock(&context->oauth2_critical); }
	free(refresh_token);
	free(auth_url);
	free(json);
	free(expires_in_str);
	free(error);
	free(error_description);
	return access_token? access_token : dc_strdup(NULL);
}
