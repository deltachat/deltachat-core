#include "dc_context.h"
#include "dc_saxparser.h"


/*******************************************************************************
 * create kml-files
 ******************************************************************************/


static char* get_kml_timestamp(time_t utc)
{
	// Returns a string formatted as YYYY-MM-DDTHH:MM:SSZ. The trailing `Z` indicates UTC.
	struct tm wanted_struct;
	memcpy(&wanted_struct, gmtime(&utc), sizeof(struct tm));
	return dc_mprintf("%04i-%02i-%02iT%02i:%02i:%02iZ",
		(int)wanted_struct.tm_year+1900, (int)wanted_struct.tm_mon+1, (int)wanted_struct.tm_mday,
		(int)wanted_struct.tm_hour, (int)wanted_struct.tm_min, (int)wanted_struct.tm_sec);
}


char* dc_get_location_kml(dc_context_t* context, uint32_t chat_id)
{
	int              success = 0;
	sqlite3_stmt*    stmt = NULL;
	double           latitude = 0.0;
	double           longitude = 0.0;
	double           accuracy = 0.0;
	char*            timestamp = NULL;
	char*            self_addr = NULL;
	time_t           now = time(NULL);
	time_t           locations_send_begin = 0;
	time_t           locations_send_until = 0;
	int              location_count = 0;
	dc_strbuilder_t  ret;
	dc_strbuilder_init(&ret, 1000);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	// get info about the contact and the chat
	self_addr = dc_sqlite3_get_config(context->sql, "configured_addr", "");

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT locations_send_begin, locations_send_until "
		"  FROM chats "
		" WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}
	locations_send_begin = sqlite3_column_int64(stmt, 0);
	locations_send_until = sqlite3_column_int64(stmt, 1);
	sqlite3_finalize(stmt);
	stmt = NULL;

	if (locations_send_begin==0 || now>locations_send_until) {
		goto cleanup;
	}

	// build kml file
	dc_strbuilder_catf(&ret,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n"
		"<Document addr=\"%s\">\n",
		self_addr);

	stmt = dc_sqlite3_prepare(context->sql,
			"SELECT latitude, longitude, accuracy, timestamp "
			" FROM locations "
			" WHERE from_id=? "
			"   AND timestamp>=? "
			"   AND timestamp=(SELECT MAX(timestamp) FROM locations WHERE from_id=?) ");
	sqlite3_bind_int   (stmt, 1, DC_CONTACT_ID_SELF);
	sqlite3_bind_int   (stmt, 2, locations_send_begin);
	sqlite3_bind_int   (stmt, 3, DC_CONTACT_ID_SELF);
	while (sqlite3_step(stmt)==SQLITE_ROW)
	{
		latitude  = sqlite3_column_double(stmt, 0);
		longitude = sqlite3_column_double(stmt, 1);
		accuracy  = sqlite3_column_double(stmt, 2);
		timestamp = get_kml_timestamp(sqlite3_column_int64 (stmt, 3));

		dc_strbuilder_catf(&ret,
			"<Placemark>"
				"<Timestamp><when>%s</when></Timestamp>"
				"<Point><coordinates accuracy=\"%f\">%f,%f</coordinates></Point>"
			"</Placemark>\n",
			timestamp,
			accuracy,
			longitude, // reverse order!
			latitude);

		location_count++;

		free(timestamp);
		timestamp = NULL;
	}

	if (location_count==0) {
		goto cleanup;
	}

	dc_strbuilder_cat(&ret,
		"</Document>\n"
		"</kml>");

	success = 1;

cleanup:
	sqlite3_finalize(stmt);
	free(self_addr);
	if (!success) {
		free(ret.buf);
	}
	return success? ret.buf : NULL;
}


/*******************************************************************************
 * parse kml-files
 ******************************************************************************/


#define TAG_PLACEMARK   0x01
#define TAG_TIMESTAMP   0x02
#define TAG_WHEN        0x04
#define TAG_POINT       0x08
#define TAG_COORDINATES 0x10


static void kml_starttag_cb(void* userdata, const char* tag, char** attr)
{
	dc_kml_t* kml = (dc_kml_t*)userdata;

	if (strcmp(tag, "document")==0)
	{
		const char* addr = dc_attr_find(attr, "addr");
		if (addr) {
			kml->addr = dc_strdup(addr);
		}
	}
	else if (strcmp(tag, "placemark")==0)
	{
		kml->tag            = TAG_PLACEMARK;
		kml->curr.timestamp = 0;
		kml->curr.latitude  = 0;
		kml->curr.longitude = 0.0;
		kml->curr.accuracy  = 0.0;
	}
	else if (strcmp(tag, "timestamp")==0 && kml->tag&TAG_PLACEMARK)
	{
		kml->tag = TAG_PLACEMARK|TAG_TIMESTAMP;
	}
	else if (strcmp(tag, "when")==0 && kml->tag&TAG_TIMESTAMP)
	{
		kml->tag = TAG_PLACEMARK|TAG_TIMESTAMP|TAG_WHEN;
	}
	else if (strcmp(tag, "point")==0 && kml->tag&TAG_PLACEMARK)
	{
		kml->tag = TAG_PLACEMARK|TAG_POINT;
	}
	else if (strcmp(tag, "coordinates")==0 && kml->tag&TAG_POINT)
	{
		kml->tag = TAG_PLACEMARK|TAG_POINT|TAG_COORDINATES;
		const char* accuracy = dc_attr_find(attr, "accuracy");
		if (accuracy) {
			kml->curr.accuracy = atof(accuracy);
		}
	}
}


static void kml_text_cb(void* userdata, const char* text, int len)
{
	dc_kml_t* kml = (dc_kml_t*)userdata;

	if (kml->tag&(TAG_WHEN|TAG_COORDINATES))
	{
		char* val = dc_strdup(text);
		dc_str_replace(&val, "\n", "");
		dc_str_replace(&val, "\r", "");
		dc_str_replace(&val, "\t", "");
		dc_str_replace(&val, " ", "");

		if (kml->tag&TAG_WHEN && strlen(val)>=19) {
			struct tm tmval;
			memset(&tmval, 0, sizeof(struct tm));
			// YYYY-MM-DDTHH:MM:SS
			// 0   4  7  10 13 16 19
			val[4]  = 0; tmval.tm_year = atoi(val) - 1900;
			val[7]  = 0; tmval.tm_mon  = atoi(val+5) - 1;
			val[10] = 0; tmval.tm_mday = atoi(val+8);
			val[13] = 0; tmval.tm_hour = atoi(val+11);
			val[16] = 0; tmval.tm_min  = atoi(val+14);
			val[19] = 0; tmval.tm_sec  = atoi(val+17);
			kml->curr.timestamp = mkgmtime(&tmval);
			if (kml->curr.timestamp>time(NULL)) {
				kml->curr.timestamp = time(NULL);
			}
		}
		else if (kml->tag&TAG_COORDINATES) {
			char* comma = strchr(val, ',');
			if (comma) {
				char* longitude = val; // reverse order!
				char* latitude = comma+1;
				*comma = 0;
				comma = strchr(latitude, ',');
				if (comma) { *comma = 0; }
				kml->curr.latitude = atof(latitude);
				kml->curr.longitude = atof(longitude);
			}
		}

		free(val);
	}
}


static void kml_endtag_cb(void* userdata, const char* tag)
{
	dc_kml_t* kml = (dc_kml_t*)userdata;

	if (strcmp(tag, "placemark")==0)
	{
		if (kml->tag&TAG_PLACEMARK && kml->curr.timestamp
		 && kml->curr.latitude && kml->curr.longitude)
		{
			dc_location_t* location = calloc(1, sizeof(dc_location_t));
			*location = kml->curr;
			dc_array_add_ptr(kml->locations, location);
		}
		kml->tag = 0;
	}
}


dc_kml_t* dc_kml_parse(dc_context_t* context,
                       const char* content, size_t content_bytes)
{
	dc_kml_t*      kml = calloc(1, sizeof(dc_kml_t));
	char*          content_nullterminated = NULL;
	dc_saxparser_t saxparser;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (content_bytes > 1*1024*1024) {
		dc_log_warning(context, 0,
			"A kml-files with %i bytes is larger than reasonably expected.",
			content_bytes);
		goto cleanup;
	}

	content_nullterminated = dc_null_terminate(content, content_bytes);
	if (content_nullterminated==NULL) {
		goto cleanup;
	}

	kml->locations = dc_array_new_typed(context, DC_ARRAY_LOCATIONS, 100);

	dc_saxparser_init            (&saxparser, kml);
	dc_saxparser_set_tag_handler (&saxparser, kml_starttag_cb, kml_endtag_cb);
	dc_saxparser_set_text_handler(&saxparser, kml_text_cb);
	dc_saxparser_parse           (&saxparser, content_nullterminated);

cleanup:
	free(content_nullterminated);
	return kml;
}


void dc_kml_unref(dc_kml_t* kml)
{
	if (kml==NULL) {
		return;
	}

	dc_array_unref(kml->locations);
	free(kml->addr);
	free(kml);
}


int dc_save_locations(dc_context_t* context,
                      uint32_t chat_id, uint32_t contact_id,
                      const dc_array_t* locations)
{
	int           saved_locations = 0;
	sqlite3_stmt* stmt_test = NULL;
	sqlite3_stmt* stmt_insert = NULL;

	if (context==NULL ||  context->magic!=DC_CONTEXT_MAGIC
	 || chat_id<=DC_CHAT_ID_LAST_SPECIAL || locations==NULL) {
		goto cleanup;
	}

	if (contact_id==DC_CONTACT_ID_SELF) {
		// incoming locations from a multi-device setup are ignored currently,
		// otherise, this could go easily result in a mess if once device
		// is at home and the other goes around.
		// however, if needed and resources are there,
		// this special situation, could be improved someday.
		goto cleanup;
	}

	stmt_test = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM locations WHERE timestamp=? AND from_id=?");

	stmt_insert = dc_sqlite3_prepare(context->sql,
		"INSERT INTO locations "
		" (timestamp, from_id, chat_id, latitude, longitude, accuracy)"
		" VALUES (?,?,?,?,?,?);");

	for (int i=0; i<dc_array_get_cnt(locations); i++)
	{
		dc_location_t* location = dc_array_get_ptr(locations, i);

		sqlite3_reset     (stmt_test);
		sqlite3_bind_int64(stmt_test, 1, location->timestamp);
		sqlite3_bind_int  (stmt_test, 2, contact_id);
		if (sqlite3_step(stmt_test)!=SQLITE_ROW)
		{
			sqlite3_reset      (stmt_insert);
			sqlite3_bind_int64 (stmt_insert, 1, location->timestamp);
			sqlite3_bind_int   (stmt_insert, 2, contact_id);
			sqlite3_bind_int   (stmt_insert, 3, chat_id);
			sqlite3_bind_double(stmt_insert, 4, location->latitude);
			sqlite3_bind_double(stmt_insert, 5, location->longitude);
			sqlite3_bind_double(stmt_insert, 6, location->accuracy);
			sqlite3_step(stmt_insert);
		}
	}

cleanup:
	sqlite3_finalize(stmt_test);
	sqlite3_finalize(stmt_insert);
	return saved_locations;
}


/*******************************************************************************
 * high-level ui-functions
 ******************************************************************************/


/**
 * Enable or disable location streaming for a chat.
 * Locations are sent to all members of the chat for the given number of seconds;
 * after that, location streaming is automatically disabled for the chat.
 * The current location streaming state of a chat
 * can be checked using dc_is_sending_locations_to_chat().
 *
 * The locations that should be sent to the chat can be set using
 * dc_set_location().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id Chat id to enable location streaming for.
 * @param seconds >0: enable location streaming for the given number of seconds;
 *     0: disable location streaming.
 * @return None.
 */
void dc_send_locations_to_chat(dc_context_t* context, uint32_t chat_id,
                               int seconds)
{
	sqlite3_stmt* stmt = NULL;
	time_t        now = time(NULL);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || seconds<0) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE chats "
		"   SET locations_send_begin=?, "
		"       locations_send_until=? "
		" WHERE id=?");
	sqlite3_bind_int64(stmt, 1, now);
	sqlite3_bind_int64(stmt, 2, now+seconds);
	sqlite3_bind_int  (stmt, 3, chat_id);
	sqlite3_step(stmt);

	// TODO: send a status message

cleanup:
	sqlite3_finalize(stmt);
}


/**
 * Check if location streaming is enabled for a chat.
 * Location stream can be enabled or disabled using dc_send_locations_to_chat().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id Chat id to check.
 * @return 1: location streaming is enabled for the given chat;
 *     0: location streaming is disabled for the given chat.
 */
int dc_is_sending_locations_to_chat(dc_context_t* context, uint32_t chat_id)
{
	int           is_sending_locations = 0;
	sqlite3_stmt* stmt = NULL;
	time_t        send_until = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT locations_send_until "
		" FROM chats "
		" WHERE id=?");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}

	send_until = sqlite3_column_int64(stmt, 0);

	if (time(NULL) < send_until) {
		is_sending_locations = 1;
	}

cleanup:
	sqlite3_finalize(stmt);
	return is_sending_locations;
}


/**
 * Set current location.
 * The location is sent to all chats where location streaming is enabled
 * using dc_send_locations_to_chat().
 *
 * Typically results in the event #DC_EVENT_LOCATION_CHANGED with
 * contact_id set to DC_CONTACT_ID_SELF.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param latitude North-south position of the location.
 *     Set to 0.0 if the latitude is not known.
 * @param longitude East-west position of the location.
 *     Set to 0.0 if the longitude is not known.
 * @param accuracy Estimated accuracy of the location, radial, in meters.
 *     Set to 0.0 if the accuracy is not known.
 * @return 1: location streaming is still enabled for at least one chat,
 *     this dc_set_location() should be called as soon as the location changes;
 *     0: location streaming is no longer needed,
 *     dc_is_sending_locations_to_chat() is false for all chats.
 */
int dc_set_location(dc_context_t* context,
                    double latitude, double longitude, double accuracy)
{
	sqlite3_stmt* stmt = NULL;
	int           continue_streaming = 1;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || (latitude==0.0 && longitude==0.0)) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
			"INSERT INTO locations "
			" (latitude, longitude, accuracy, timestamp, from_id)"
			" VALUES (?,?,?,?,?);");
	sqlite3_bind_double(stmt, 1, latitude);
	sqlite3_bind_double(stmt, 2, longitude);
	sqlite3_bind_double(stmt, 3, accuracy);
	sqlite3_bind_int64 (stmt, 4, time(NULL));
	sqlite3_bind_int   (stmt, 5, DC_CONTACT_ID_SELF);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;

	context->cb(context, DC_EVENT_LOCATION_CHANGED, DC_CONTACT_ID_SELF, 0);

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM chats WHERE locations_send_until>?;");
	sqlite3_bind_int64(stmt, 1, time(NULL));
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		continue_streaming = 0;
	}


cleanup:
	sqlite3_finalize(stmt);
	return continue_streaming;
}


/**
 * Get last locations for a contact in a given chat.
 * The number of returned locations can be retrieved using dc_array_get_cnt(),
 * to get information for each location,
 * use dc_array_get_latitude(), dc_array_get_longitude(),
 * dc_array_get_accuracy(), dc_array_get_timestamp() and dc_array_get_msg_id().
 * The latter returns 0 if there is no message bound to the location.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id Chat id to get location information for.
 * @param contact_id Contact id to get location information for.
 *     Must be a member of the given chat.
 * @return Array of locations, NULL is never returned.
 *     The returned array must be freed using dc_array_unref().
 */
dc_array_t* dc_get_locations(dc_context_t* context, uint32_t chat_id, uint32_t  contact_id)
{
	#define MAX_AGE   (3*60*60) // truncate list after 3 hours ...
	#define MIN_ITEMS 100       // ... but add at least the 100 last items
	#define LOC_LIMIT "1000"    // hard limit, must be larger than MIN_ITEMS

	dc_array_t*   ret = dc_array_new_typed(context, DC_ARRAY_LOCATIONS, 500);
	sqlite3_stmt* stmt = NULL;
	time_t        newest = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (contact_id==DC_CONTACT_ID_SELF) {
		#define LOC_FIELDS "latitude, longitude, accuracy, timestamp, msg_id"
		stmt = dc_sqlite3_prepare(context->sql,
				"SELECT " LOC_FIELDS
				" FROM locations "
				" WHERE from_id=? "
				" ORDER BY timestamp DESC, id DESC "
				" LIMIT " LOC_LIMIT);
		sqlite3_bind_int(stmt, 1, DC_CONTACT_ID_SELF);
	}
	else {
		stmt = dc_sqlite3_prepare(context->sql,
				"SELECT " LOC_FIELDS
				" FROM locations "
				" WHERE chat_id=? "
				"   AND from_id=? "
				" ORDER BY timestamp DESC, id DESC "
				" LIMIT " LOC_LIMIT);
		sqlite3_bind_int(stmt, 1, chat_id);
		sqlite3_bind_int(stmt, 2, contact_id);
	}

	while (sqlite3_step(stmt)==SQLITE_ROW) {
        struct _dc_location* loc = calloc(1, sizeof(struct _dc_location));
        if (loc==NULL) {
			goto cleanup;
        }

		loc->latitude   = sqlite3_column_double(stmt, 0);
		loc->longitude  = sqlite3_column_double(stmt, 1);
		loc->accuracy   = sqlite3_column_double(stmt, 2);
		loc->timestamp  = sqlite3_column_int64 (stmt, 3);
		loc->msg_id     = sqlite3_column_int   (stmt, 4);
		dc_array_add_ptr(ret, loc);

		if (newest==0) {
			newest = loc->timestamp;
		}

		if (newest-loc->timestamp > MAX_AGE
		 && ret->count > MIN_ITEMS) {
			break;
		}
	}

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Delete all locations on the current device.
 * Locations already sent cannot be deleted.
 *
 * Typically results in the event #DC_EVENT_LOCATION_CHANGED
 * with contact_id set to 0.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return None.
 */
void dc_delete_all_locations(dc_context_t* context)
{
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"DELETE FROM locations;");
	sqlite3_step(stmt);

	context->cb(context, DC_EVENT_LOCATION_CHANGED, 0, 0);

cleanup:
	sqlite3_finalize(stmt);
}