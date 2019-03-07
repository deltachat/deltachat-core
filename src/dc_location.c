#include "dc_context.h"
#include "dc_mimeparser.h"
#include "dc_job.h"


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

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || seconds<0) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE chats "
		" SET locations_send_until=? "
		" WHERE id=?");
	sqlite3_bind_int64(stmt, 1, time(NULL)+seconds);
	sqlite3_bind_int  (stmt, 2, chat_id);
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



char* dc_get_location_str(dc_context_t* context)
{
	sqlite3_stmt* stmt = NULL;
	double        latitude = 0.0;
	double        longitude = 0.0;
	double        accuracy = 0.0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
			"SELECT latitude, longitude, accuracy, timestamp "
			" FROM locations "
			" WHERE from_id=? "
			"   AND timestamp=(SELECT MAX(timestamp) FROM locations WHERE from_id=?) ");
	sqlite3_bind_int   (stmt, 1, DC_CONTACT_ID_SELF);
	sqlite3_bind_int   (stmt, 2, DC_CONTACT_ID_SELF);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		latitude  = sqlite3_column_double(stmt, 0);
		longitude = sqlite3_column_double(stmt, 1);
		accuracy  = sqlite3_column_double(stmt, 2);
	}

cleanup:
	sqlite3_finalize(stmt);
    return dc_mprintf("%f %f %f", latitude, longitude, accuracy);
}


/**
 * Get last location for a contact in a given chat.
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
	return ret;
}
