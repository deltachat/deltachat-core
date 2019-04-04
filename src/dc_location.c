#include "dc_context.h"
#include "dc_saxparser.h"
#include "dc_mimefactory.h"


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


char* dc_get_location_kml(dc_context_t* context, uint32_t chat_id,
                          uint32_t* last_added_location_id)
{
	int              success = 0;
	sqlite3_stmt*    stmt = NULL;
	char*            self_addr = NULL;
	time_t           now = time(NULL);
	time_t           locations_send_begin = 0;
	time_t           locations_send_until = 0;
	time_t           locations_last_sent = 0;
	int              location_count = 0;
	dc_strbuilder_t  ret;
	dc_strbuilder_init(&ret, 1000);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	// get info about the contact and the chat
	self_addr = dc_sqlite3_get_config(context->sql, "configured_addr", "");

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT locations_send_begin, locations_send_until, locations_last_sent"
		"  FROM chats "
		" WHERE id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}
	locations_send_begin = sqlite3_column_int64(stmt, 0);
	locations_send_until = sqlite3_column_int64(stmt, 1);
	locations_last_sent  = sqlite3_column_int64(stmt, 2);
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
			"SELECT id, latitude, longitude, accuracy, timestamp "
			" FROM locations "
			" WHERE from_id=? "
			"   AND timestamp>=? "
			"   AND (timestamp>=? OR timestamp=(SELECT MAX(timestamp) FROM locations WHERE from_id=?)) "
			"   GROUP BY timestamp "
			"   ORDER BY timestamp;");
	sqlite3_bind_int   (stmt, 1, DC_CONTACT_ID_SELF);
	sqlite3_bind_int64 (stmt, 2, locations_send_begin);
	sqlite3_bind_int64 (stmt, 3, locations_last_sent);
	sqlite3_bind_int   (stmt, 4, DC_CONTACT_ID_SELF);
	while (sqlite3_step(stmt)==SQLITE_ROW)
	{
		uint32_t location_id = sqlite3_column_int(stmt, 0);
		char*    latitude    = dc_ftoa(sqlite3_column_double(stmt, 1));
		char*    longitude   = dc_ftoa(sqlite3_column_double(stmt, 2));
		char*    accuracy    = dc_ftoa(sqlite3_column_double(stmt, 3));
		char*    timestamp   = get_kml_timestamp(sqlite3_column_int64 (stmt, 4));

		dc_strbuilder_catf(&ret,
			"<Placemark>"
				"<Timestamp><when>%s</when></Timestamp>"
				"<Point><coordinates accuracy=\"%s\">%s,%s</coordinates></Point>"
			"</Placemark>\n",
			timestamp,
			accuracy,
			longitude, // reverse order!
			latitude);

		location_count++;

		if (last_added_location_id) {
			*last_added_location_id = location_id;
		}

		free(latitude);
		free(longitude);
		free(accuracy);
		free(timestamp);
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


void dc_set_kml_sent_timestamp(dc_context_t* context,
                               uint32_t chat_id, time_t timestamp)
{
	sqlite3_stmt* stmt = NULL;

	stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE chats SET locations_last_sent=? WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, timestamp);
	sqlite3_bind_int  (stmt, 2, chat_id);

	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


void dc_set_msg_location_id(dc_context_t* context, uint32_t msg_id, uint32_t location_id)
{
	sqlite3_stmt* stmt = NULL;

	stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE msgs SET location_id=? WHERE id=?;");
	sqlite3_bind_int64(stmt, 1, location_id);
	sqlite3_bind_int  (stmt, 2, msg_id);

	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
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
			kml->curr.accuracy = dc_atof(accuracy);
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
				kml->curr.latitude = dc_atof(latitude);
				kml->curr.longitude = dc_atof(longitude);
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


uint32_t dc_save_locations(dc_context_t* context,
                           uint32_t chat_id, uint32_t contact_id,
                           const dc_array_t* locations)
{
	sqlite3_stmt* stmt_test = NULL;
	sqlite3_stmt* stmt_insert = NULL;
	time_t        newest_timestamp = 0;
	uint32_t      newest_location_id = 0;

	if (context==NULL ||  context->magic!=DC_CONTEXT_MAGIC
	 || chat_id<=DC_CHAT_ID_LAST_SPECIAL || locations==NULL) {
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

		if (location->timestamp > newest_timestamp) {
			newest_timestamp = location->timestamp;
			newest_location_id = dc_sqlite3_get_rowid2(context->sql, "locations",
				"timestamp", location->timestamp,
				"from_id", contact_id);
		}
	}

cleanup:
	sqlite3_finalize(stmt_test);
	sqlite3_finalize(stmt_insert);
	return newest_location_id;
}


/*******************************************************************************
 * job to send locations out to all chats that want them
 ******************************************************************************/


#define MAYBE_SEND_LOCATIONS_WAIT_SECONDS 60


static void schedule_MAYBE_SEND_LOCATIONS(dc_context_t* context, int flags)
{
	#define FORCE_SCHEDULE 0x01
	if ((flags&FORCE_SCHEDULE)
	 || !dc_job_action_exists(context, DC_JOB_MAYBE_SEND_LOCATIONS)) {
		dc_job_add(context, DC_JOB_MAYBE_SEND_LOCATIONS, 0, NULL,
			MAYBE_SEND_LOCATIONS_WAIT_SECONDS);
	}
}


void dc_job_do_DC_JOB_MAYBE_SEND_LOCATIONS(dc_context_t* context, dc_job_t* job)
{
	sqlite3_stmt* stmt_chats = NULL;
	sqlite3_stmt* stmt_locations = NULL;
	time_t        now = time(NULL);
	int           continue_streaming = 1;

	dc_log_info(context, 0, " ----------------- MAYBE_SEND_LOCATIONS -------------- ");

	stmt_chats = dc_sqlite3_prepare(context->sql,
		"SELECT id, locations_send_begin, locations_last_sent "
		"  FROM chats "
		"  WHERE locations_send_until>?;"); // this should be the same condition as for the return value dc_set_location()
	sqlite3_bind_int64(stmt_chats, 1, now);
	while (sqlite3_step(stmt_chats)==SQLITE_ROW)
	{
		uint32_t chat_id              = sqlite3_column_int  (stmt_chats, 0);
		time_t   locations_send_begin = sqlite3_column_int64(stmt_chats, 1);
		time_t   locations_last_sent  = sqlite3_column_int64(stmt_chats, 2);

		continue_streaming = 1;

		// be a bit tolerant as the timer may not align exactly with time(NULL)
		if (now-locations_last_sent < (MAYBE_SEND_LOCATIONS_WAIT_SECONDS-3)) {
			continue;
		}

		if (stmt_locations==NULL)  {
			stmt_locations = dc_sqlite3_prepare(context->sql,
					"SELECT id "
					" FROM locations "
					" WHERE from_id=? "
					"   AND timestamp>=? "
					"   AND timestamp>? "
					"   ORDER BY timestamp;");
		}
		else {
			sqlite3_reset(stmt_locations);
		}
		sqlite3_bind_int   (stmt_locations, 1, DC_CONTACT_ID_SELF);
		sqlite3_bind_int64 (stmt_locations, 2, locations_send_begin);
		sqlite3_bind_int64 (stmt_locations, 3, locations_last_sent);

		// if there is no new location, there's nothing to send.
		// however, maybe we want to bypass this test eg. 15 minutes
        if (sqlite3_step(stmt_locations)!=SQLITE_ROW) {
			continue;
        }

		// TODO: send this as a hidden `Chat-Content: position` message

		// TODO: send the message only if the last scheduled location message was sent
		// to avoid flooding queued messages which may result in normal messages not
		// coming through (positions are sent combined then)
		// (an alternative would be to remove unsent messages and to create new ones,
		// however, as positions may also be shared by normal messages,
		// tracking this state seems to be harder)

		dc_send_text_msg(context, chat_id, "-location-");
	}

	if (continue_streaming) {
		// force scheduing as there is at least one job - the current one
		schedule_MAYBE_SEND_LOCATIONS(context, FORCE_SCHEDULE);
	}

//cleanup:
	sqlite3_finalize(stmt_chats);
	sqlite3_finalize(stmt_locations);
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
	dc_msg_t*     msg = NULL;

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

	// send a status message
	msg = dc_msg_new(context, DC_MSG_TEXT);
	msg->text = dc_stock_system_msg(context,
		seconds? DC_STR_MSGLOCATIONENABLED : DC_STR_MSGLOCATIONDISABLED,
		NULL, NULL, 0);
	dc_param_set_int(msg->param, DC_PARAM_CMD, DC_CMD_LOCATION_STREAMING_SECONDS);
	dc_param_set_int(msg->param, DC_PARAM_CMD_ARG, seconds);
	msg->id = dc_send_msg(context, chat_id, msg);
	context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->id);

	if (seconds) {
		schedule_MAYBE_SEND_LOCATIONS(context, 0);
	}

cleanup:
	dc_msg_unref(msg);
	sqlite3_finalize(stmt);
}


/**
 * Check if location streaming is enabled.
 * Location stream can be enabled or disabled using dc_send_locations_to_chat().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id >0: Check if location streaming is enabled for the given chat.
 *     0: Check of location streaming is enabled for any chat.
 * @return 1: location streaming is enabled for the given chat(s);
 *     0: location streaming is disabled for the given chat(s).
 */
int dc_is_sending_locations_to_chat(dc_context_t* context, uint32_t chat_id)
{
	int           is_sending_locations = 0;
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id "
		" FROM chats "
		" WHERE (? OR id=?)"
		"   AND locations_send_until>?;");
	sqlite3_bind_int  (stmt, 1, chat_id==0? 1 : 0);
	sqlite3_bind_int  (stmt, 2, chat_id);
	sqlite3_bind_int64(stmt, 3, time(NULL));
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}

	is_sending_locations = 1;

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
 * The UI should call this function on all location changes.
 * The locations set by this function are not sent immediately,
 * instead a message with the last locations is sent out every some minutes
 * or when the user sends out a normal message,
 * the last locations are attached.
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
	sqlite3_stmt* stmt_chats = NULL;
	sqlite3_stmt* stmt_insert = NULL;
	int           continue_streaming = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || (latitude==0.0 && longitude==0.0)) {
		continue_streaming = 1;
		goto cleanup;
	}

	stmt_chats = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM chats WHERE locations_send_until>?;");
	sqlite3_bind_int64(stmt_chats, 1, time(NULL));
	while (sqlite3_step(stmt_chats)==SQLITE_ROW)
	{
		uint32_t chat_id = sqlite3_column_int(stmt_chats, 0);

		stmt_insert = dc_sqlite3_prepare(context->sql,
				"INSERT INTO locations "
				" (latitude, longitude, accuracy, timestamp, chat_id, from_id)"
				" VALUES (?,?,?,?,?,?);");
		sqlite3_bind_double(stmt_insert, 1, latitude);
		sqlite3_bind_double(stmt_insert, 2, longitude);
		sqlite3_bind_double(stmt_insert, 3, accuracy);
		sqlite3_bind_int64 (stmt_insert, 4, time(NULL));
		sqlite3_bind_int   (stmt_insert, 5, chat_id);
		sqlite3_bind_int   (stmt_insert, 6, DC_CONTACT_ID_SELF);
		sqlite3_step(stmt_insert);

		continue_streaming = 1;
	}

	if (continue_streaming) {
		context->cb(context, DC_EVENT_LOCATION_CHANGED, DC_CONTACT_ID_SELF, 0);
		schedule_MAYBE_SEND_LOCATIONS(context, 0);
	}

cleanup:
	sqlite3_finalize(stmt_chats);
	sqlite3_finalize(stmt_insert);
	return continue_streaming;
}


/**
 * Get shared locations from the database.
 * The locations can be filtered by the chat-id, the contact-id
 * and by a timespan.
 *
 * The number of returned locations can be retrieved using dc_array_get_cnt().
 * To get information for each location,
 * use dc_array_get_latitude(), dc_array_get_longitude(),
 * dc_array_get_accuracy(), dc_array_get_timestamp(), dc_array_get_contact_id()
 * and dc_array_get_msg_id().
 * The latter returns 0 if there is no message bound to the location.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id Chat-id to get location information for.
 *     0 to get locations independently of the chat.
 * @param contact_id Contact id to get location information for.
 *     If also a chat-id is given, this should be a member of the given chat.
 *     0 to get locations independently of the contact.
 * @param timestamp_from Start of timespan to return.
 *     Must be given in number of seconds since 00:00 hours, Jan 1, 1970 UTC.
 *     0 for "start from the beginning".
 * @param timestamp_to End of timespan to return.
 *     Must be given in number of seconds since 00:00 hours, Jan 1, 1970 UTC.
 *     0 for "all up to now".
 * @return Array of locations, NULL is never returned.
 *     The array is sorted decending;
 *     the first entry in the array is the location with the newest timestamp.
 *     The returned array must be freed using dc_array_unref().
 *
 * Examples:
 * ~~~
 * // get locations from the last hour for a global map
 * dc_array_t* loc = dc_get_locations(context, 0, 0, time(NULL)-60*60, 0);
 * for (int i=0; i<dc_array_get_cnt(); i++) {
 *     double lat = dc_array_get_latitude(loc, i);
 *     ...
 * }
 * dc_array_unref(loc);
 *
 * // get locations from a contact for a global map
 * dc_array_t* loc = dc_get_locations(context, 0, contact_id, 0, 0);
 * ...
 *
 * // get all locations known for a given chat
 * dc_array_t* loc = dc_get_locations(context, chat_id, 0, 0, 0);
 * ...
 *
 * // get locations from a single contact for a given chat
 * dc_array_t* loc = dc_get_locations(context, chat_id, contact_id, 0, 0);
 * ...
 * ~~~

 */
dc_array_t* dc_get_locations(dc_context_t* context,
                             uint32_t chat_id, uint32_t  contact_id,
                             time_t timestamp_from, time_t timestamp_to)
{
	dc_array_t*   ret = dc_array_new_typed(context, DC_ARRAY_LOCATIONS, 500);
	sqlite3_stmt* stmt = NULL;
	time_t        newest = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (timestamp_to==0) {
		timestamp_to = time(NULL) + 10/*messages may be inserted by another thread just now*/;
	}

	stmt = dc_sqlite3_prepare(context->sql,
			"SELECT l.id, l.latitude, l.longitude, l.accuracy, l.timestamp, "
			"       m.id, l.from_id, l.chat_id "
			" FROM locations l "
			" LEFT JOIN msgs m ON l.id=m.location_id "
			" WHERE (? OR l.chat_id=?) "
			"   AND (? OR l.from_id=?) "
			"   AND l.timestamp>=? AND l.timestamp<=? "
			" ORDER BY l.timestamp DESC, l.id DESC;");
	sqlite3_bind_int(stmt, 1, chat_id==0? 1 : 0);
	sqlite3_bind_int(stmt, 2, chat_id);
	sqlite3_bind_int(stmt, 3, contact_id==0? 1 : 0);
	sqlite3_bind_int(stmt, 4, contact_id);
	sqlite3_bind_int(stmt, 5, timestamp_from);
	sqlite3_bind_int(stmt, 6, timestamp_to);

	while (sqlite3_step(stmt)==SQLITE_ROW) {
        struct _dc_location* loc = calloc(1, sizeof(struct _dc_location));
        if (loc==NULL) {
			goto cleanup;
        }

		loc->location_id = sqlite3_column_double(stmt, 0);
		loc->latitude    = sqlite3_column_double(stmt, 1);
		loc->longitude   = sqlite3_column_double(stmt, 2);
		loc->accuracy    = sqlite3_column_double(stmt, 3);
		loc->timestamp   = sqlite3_column_int64 (stmt, 4);
		loc->msg_id      = sqlite3_column_int   (stmt, 5);
		loc->contact_id  = sqlite3_column_int   (stmt, 6);
		loc->chat_id     = sqlite3_column_int   (stmt, 7);
		dc_array_add_ptr(ret, loc);

		if (newest==0) {
			newest = loc->timestamp;
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
