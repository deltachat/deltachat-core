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

	if (context==0 || context->magic!=DC_CONTEXT_MAGIC || seconds<0) {
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

	if (context==0 || context->magic!=DC_CONTEXT_MAGIC) {
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

	if (context==0 || context->magic!=DC_CONTEXT_MAGIC
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

	context->cb(context, DC_EVENT_LOCATION_CHANGED, DC_CONTACT_ID_SELF, 0);

cleanup:
	sqlite3_finalize(stmt);
	return 1; // TODO: check state
}



char* dc_get_location_str(dc_context_t* context)
{
	sqlite3_stmt* stmt = NULL;
	double        latitude = 0.0;
	double        longitude = 0.0;
	double        accuracy = 0.0;

	if (context==0 || context->magic!=DC_CONTEXT_MAGIC) {
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
