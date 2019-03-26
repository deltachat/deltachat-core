#include <assert.h>
#include "dc_context.h"
#include "dc_job.h"
#include "dc_smtp.h"
#include "dc_imap.h"
#include "dc_mimefactory.h"
#include "dc_apeerstate.h"


#define DC_CHAT_MAGIC 0xc4a7c4a7


/**
 * Create a chat object in memory.
 *
 * @private @memberof dc_chat_t
 * @param context The context that should be stored in the chat object.
 * @return New and empty chat object, must be freed using dc_chat_unref().
 */
dc_chat_t* dc_chat_new(dc_context_t* context)
{
	dc_chat_t* chat = NULL;

	if (context==NULL || (chat=calloc(1, sizeof(dc_chat_t)))==NULL) {
		exit(14); /* cannot allocate little memory, unrecoverable error */
	}

	chat->magic    = DC_CHAT_MAGIC;
	chat->context  = context;
	chat->type     = DC_CHAT_TYPE_UNDEFINED;
	chat->param    = dc_param_new();

    return chat;
}


/**
 * Free a chat object.
 *
 * @memberof dc_chat_t
 * @param chat Chat object are returned eg. by dc_get_chat().
 *     If NULL is given, nothing is done.
 * @return None.
 */
void dc_chat_unref(dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return;
	}

	dc_chat_empty(chat);
	dc_param_unref(chat->param);
	chat->magic = 0;
	free(chat);
}


/**
 * Empty a chat object.
 *
 * @private @memberof dc_chat_t
 * @param chat The chat object to empty.
 * @return None.
 */
void dc_chat_empty(dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return;
	}

	free(chat->name);
	chat->name = NULL;

	chat->type = DC_CHAT_TYPE_UNDEFINED;
	chat->id   = 0;

	free(chat->grpid);
	chat->grpid = NULL;

	chat->blocked = 0;
	chat->gossiped_timestamp = 0;

	dc_param_set_packed(chat->param, NULL);
}


/**
 * Get chat ID. The chat ID is the ID under which the chat is filed in the database.
 *
 * Special IDs:
 * - DC_CHAT_ID_DEADDROP         (1) - Virtual chat containing messages which senders are not confirmed by the user.
 * - DC_CHAT_ID_STARRED          (5) - Virtual chat containing all starred messages-
 * - DC_CHAT_ID_ARCHIVED_LINK    (6) - A link at the end of the chatlist, if present the UI should show the button "Archived chats"-
 *
 * "Normal" chat IDs are larger than these special IDs (larger than DC_CHAT_ID_LAST_SPECIAL).
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Chat ID. 0 on errors.
 */
uint32_t dc_chat_get_id(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return 0;
	}

	return chat->id;
}


/**
 * Get chat type.
 *
 * Currently, there are two chat types:
 *
 * - DC_CHAT_TYPE_SINGLE (100) - a normal chat is a chat with a single contact,
 *   chats_contacts contains one record for the user.  DC_CONTACT_ID_SELF
 *   (see dc_contact_t::id) is added _only_ for a self talk.
 *
 * - DC_CHAT_TYPE_GROUP  (120) - a group chat, chats_contacts contain all group
 *   members, incl. DC_CONTACT_ID_SELF
 *
 * - DC_CHAT_TYPE_VERIFIED_GROUP  (130) - a verified group chat. In verified groups,
 *   all members are verified and encryption is always active and cannot be disabled.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Chat type.
 */
int dc_chat_get_type(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return DC_CHAT_TYPE_UNDEFINED;
	}
	return chat->type;
}


/**
 * Get name of a chat. For one-to-one chats, this is the name of the contact.
 * For group chats, this is the name given eg. to dc_create_group_chat() or
 * received by a group-creation message.
 *
 * To change the name, use dc_set_chat_name()
 *
 * See also: dc_chat_get_subtitle()
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Chat name as a string. Must be free()'d after usage. Never NULL.
 */
char* dc_chat_get_name(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return dc_strdup("Err");
	}

	return dc_strdup(chat->name);
}


/**
 * Get a subtitle for a chat.  The subtitle is eg. the email-address or the
 * number of group members.
 *
 * See also: dc_chat_get_name()
 *
 * @memberof dc_chat_t
 * @param chat The chat object to calulate the subtitle for.
 * @return Subtitle as a string. Must be free()'d after usage. Never NULL.
 */
char* dc_chat_get_subtitle(const dc_chat_t* chat)
{
	/* returns either the address or the number of chat members */
	char*         ret = NULL;

	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return dc_strdup("Err");
	}

	if (chat->type==DC_CHAT_TYPE_SINGLE && dc_param_exists(chat->param, DC_PARAM_SELFTALK))
	{
		ret = dc_stock_str(chat->context, DC_STR_SELFTALK_SUBTITLE);
	}
	else if (chat->type==DC_CHAT_TYPE_SINGLE)
	{
		int r;
		sqlite3_stmt* stmt = dc_sqlite3_prepare(chat->context->sql,
			"SELECT c.addr FROM chats_contacts cc "
			" LEFT JOIN contacts c ON c.id=cc.contact_id "
			" WHERE cc.chat_id=?;");
		sqlite3_bind_int(stmt, 1, chat->id);

		r = sqlite3_step(stmt);
		if (r==SQLITE_ROW) {
			ret = dc_strdup((const char*)sqlite3_column_text(stmt, 0));
		}

		sqlite3_finalize(stmt);
	}
	else if (DC_CHAT_TYPE_IS_MULTI(chat->type))
	{
		int cnt = 0;
		if (chat->id==DC_CHAT_ID_DEADDROP)
		{
			ret = dc_stock_str(chat->context, DC_STR_DEADDROP); /* typically, the subtitle for the deaddropn is not displayed at all */
		}
		else
		{
			cnt = dc_get_chat_contact_cnt(chat->context, chat->id);
			ret = dc_stock_str_repl_int(chat->context, DC_STR_MEMBER, cnt /*SELF is included in group chats (if not removed)*/);
		}
	}

	return ret? ret : dc_strdup("Err");
}


/**
 * Get the chat's profile image.
 * For groups, this is the image set by any group member
 * using dc_set_chat_profile_image().
 * For normal chats, this is the image set by each remote user on their own
 * using dc_set_config(context, "selfavatar", image).
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Path and file if the profile image, if any.
 *     NULL otherwise.
 *     Must be free()'d after usage.
 */
char* dc_chat_get_profile_image(const dc_chat_t* chat)
{
	char*         image_rel = NULL;
	char*         image_abs = NULL;
	dc_array_t*   contacts = NULL;
	dc_contact_t* contact = NULL;

	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		goto cleanup;
	}

	image_rel = dc_param_get(chat->param, DC_PARAM_PROFILE_IMAGE, NULL);
	if (image_rel && image_rel[0]) {
		image_abs = dc_get_abs_path(chat->context, image_rel);
	}
	else if(chat->type==DC_CHAT_TYPE_SINGLE) {
		contacts = dc_get_chat_contacts(chat->context, chat->id);
		if (contacts->count >= 1) {
			contact = dc_get_contact(chat->context, contacts->array[0]);
			image_abs = dc_contact_get_profile_image(contact);
		}
	}

cleanup:
	free(image_rel);
	dc_array_unref(contacts);
	dc_contact_unref(contact);
	return image_abs;
}


/**
 * Get a color for the chat.
 * For 1:1 chats, the color is calculated from the contact's email address.
 * Otherwise, the chat name is used.
 * The color can be used for an fallback avatar with white initials
 * as well as for headlines in bubbles of group chats.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Color as 0x00rrggbb with rr=red, gg=green, bb=blue
 *     each in the range 0-255.
 */
uint32_t dc_chat_get_color(const dc_chat_t* chat)
{
	uint32_t      color = 0;
	dc_array_t*   contacts = NULL;
	dc_contact_t* contact = NULL;

	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		goto cleanup;
	}

	if(chat->type==DC_CHAT_TYPE_SINGLE) {
		contacts = dc_get_chat_contacts(chat->context, chat->id);
		if (contacts->count >= 1) {
			contact = dc_get_contact(chat->context, contacts->array[0]);
			color = dc_str_to_color(contact->addr);
		}
	}
	else {
		color = dc_str_to_color(chat->name);
	}

cleanup:
	dc_array_unref(contacts);
	dc_contact_unref(contact);
	return color;
}


/**
 * Get archived state.
 *
 * - 0 = normal chat, not archived, not sticky.
 * - 1 = chat archived
 * - 2 = chat sticky (reserved for future use, if you do not support this value, just treat the chat as a normal one)
 *
 * To archive or unarchive chats, use dc_archive_chat().
 * If chats are archived, this should be shown in the UI by a little icon or text,
 * eg. the search will also return archived chats.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Archived state.
 */
int dc_chat_get_archived(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return 0;
	}
	return chat->archived;
}


/**
 * Check if a group chat is still unpromoted.
 *
 * After the creation with dc_create_group_chat() the chat is usually unpromoted
 * until the first call to dc_send_text_msg() or another sending function.
 *
 * With unpromoted chats, members can be added
 * and settings can be modified without the need of special status messages being sent.
 *
 * While the core takes care of the unpromoted state on its own,
 * checking the state from the UI side may be useful to decide whether a hint as
 * "Send the first message to allow others to reply within the group"
 * should be shown to the user or not.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is still unpromoted, no message was ever send to the chat,
 *     0=chat is not unpromoted, messages were send and/or received
 *     or the chat is not group chat.
 */
int dc_chat_is_unpromoted(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return 0;
	}
	return dc_param_get_int(chat->param, DC_PARAM_UNPROMOTED, 0);
}


/**
 * Check if a chat is verified.  Verified chats contain only verified members
 * and encryption is alwasy enabled.  Verified chats are created using
 * dc_create_group_chat() by setting the 'verified' parameter to true.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat verified, 0=chat is not verified
 */
int dc_chat_is_verified(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return 0;
	}
	return (chat->type==DC_CHAT_TYPE_VERIFIED_GROUP);
}


/**
 * Check if a chat is a self talk.  Self talks are normal chats with
 * the only contact DC_CONTACT_ID_SELF.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is self talk, 0=chat is no self talk
 */
int dc_chat_is_self_talk(const dc_chat_t* chat)
{
	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		return 0;
	}
	return dc_param_exists(chat->param, DC_PARAM_SELFTALK);
}


int dc_chat_update_param(dc_chat_t* chat)
{
	int success = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(chat->context->sql,
		"UPDATE chats SET param=? WHERE id=?");
	sqlite3_bind_text(stmt, 1, chat->param->packed, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, chat->id);
	success = (sqlite3_step(stmt)==SQLITE_DONE)? 1 : 0;
	sqlite3_finalize(stmt);
	return success;
}


static int set_from_stmt(dc_chat_t* chat, sqlite3_stmt* row)
{
	int         row_offset = 0;

	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC || row==NULL) {
		return 0;
	}

	dc_chat_empty(chat);

	#define CHAT_FIELDS " c.id,c.type,c.name, c.grpid,c.param,c.archived, c.blocked, c.gossiped_timestamp "
	chat->id              =                    sqlite3_column_int  (row, row_offset++); /* the columns are defined in CHAT_FIELDS */
	chat->type            =                    sqlite3_column_int  (row, row_offset++);
	chat->name            =   dc_strdup((char*)sqlite3_column_text (row, row_offset++));
	chat->grpid           =   dc_strdup((char*)sqlite3_column_text (row, row_offset++));
	dc_param_set_packed(chat->param,    (char*)sqlite3_column_text (row, row_offset++));
	chat->archived        =                    sqlite3_column_int  (row, row_offset++);
	chat->blocked         =                    sqlite3_column_int  (row, row_offset++);
	chat->gossiped_timestamp =                 sqlite3_column_int64(row, row_offset++);

	/* correct the title of some special groups */
	if (chat->id==DC_CHAT_ID_DEADDROP) {
		free(chat->name);
		chat->name = dc_stock_str(chat->context, DC_STR_DEADDROP);
	}
	else if (chat->id==DC_CHAT_ID_ARCHIVED_LINK) {
		free(chat->name);
		char* tempname = dc_stock_str(chat->context, DC_STR_ARCHIVEDCHATS);
			chat->name = dc_mprintf("%s (%i)", tempname, dc_get_archived_cnt(chat->context));
		free(tempname);
	}
	else if (chat->id==DC_CHAT_ID_STARRED) {
		free(chat->name);
		chat->name = dc_stock_str(chat->context, DC_STR_STARREDMSGS);
	}
	else if (dc_param_exists(chat->param, DC_PARAM_SELFTALK)) {
		free(chat->name);
		chat->name = dc_stock_str(chat->context, DC_STR_SELF);
	}

	return row_offset; /* success, return the next row offset */
}


/**
 * Load a chat from the database to the chat object.
 *
 * @private @memberof dc_chat_t
 * @param chat The chat object that should be filled with the data from the database.
 *     Existing data are free()'d before using dc_chat_empty().
 * @param chat_id Chat ID that should be loaded from the database.
 * @return 1=success, 0=error.
 */
int dc_chat_load_from_db(dc_chat_t* chat, uint32_t chat_id)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;

	if (chat==NULL || chat->magic!=DC_CHAT_MAGIC) {
		goto cleanup;
	}

	dc_chat_empty(chat);

	stmt = dc_sqlite3_prepare(chat->context->sql,
		"SELECT " CHAT_FIELDS " FROM chats c WHERE c.id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);

	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}

	if (!set_from_stmt(chat, stmt)) {
		goto cleanup;
	}

	success = 1;

cleanup:
	sqlite3_finalize(stmt);
	return success;
}


void dc_set_gossiped_timestamp(dc_context_t* context,
                               uint32_t chat_id, time_t timestamp)
{
	sqlite3_stmt* stmt = NULL;

	if (chat_id) {
		dc_log_info(context, 0, "set gossiped_timestamp for chat #%i to %i.",
			(int)chat_id, (int)timestamp);

		stmt = dc_sqlite3_prepare(context->sql,
			"UPDATE chats SET gossiped_timestamp=? WHERE id=?;");
		sqlite3_bind_int64(stmt, 1, timestamp);
		sqlite3_bind_int  (stmt, 2, chat_id);
	}
	else {
		dc_log_info(context, 0, "set gossiped_timestamp for all chats to %i.",
			(int)timestamp);

		stmt = dc_sqlite3_prepare(context->sql,
			"UPDATE chats SET gossiped_timestamp=?;");
		sqlite3_bind_int64(stmt, 1, timestamp);
	}

	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}


void dc_reset_gossiped_timestamp(dc_context_t* context, uint32_t chat_id)
{
	dc_set_gossiped_timestamp(context, chat_id, 0);
}


/*******************************************************************************
 * Context functions to work with chats
 ******************************************************************************/


size_t dc_get_chat_cnt(dc_context_t* context)
{
	size_t        ret = 0;
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->sql->cobj==NULL) {
		goto cleanup; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT COUNT(*) FROM chats WHERE id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL) " AND blocked=0;");
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


int dc_add_to_chat_contacts_table(dc_context_t* context, uint32_t chat_id, uint32_t contact_id)
{
	/* add a contact to a chat; the function does not check the type or if any of the record exist or are already added to the chat! */
	int ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO chats_contacts (chat_id, contact_id) VALUES(?, ?)");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	ret = (sqlite3_step(stmt)==SQLITE_DONE)? 1 : 0;
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get chat object by a chat ID.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to get the chat object for.
 * @return A chat object of the type dc_chat_t,
 *     must be freed using dc_chat_unref() when done.
 *     On errors, NULL is returned.
 */
dc_chat_t* dc_get_chat(dc_context_t* context, uint32_t chat_id)
{
	int        success = 0;
	dc_chat_t* obj = dc_chat_new(context);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (!dc_chat_load_from_db(obj, chat_id)) {
		goto cleanup;
	}

	success = 1;

cleanup:
	if (success) {
		return obj;
	}
	else {
		dc_chat_unref(obj);
		return NULL;
	}
}


/**
 * Mark all messages in a chat as _noticed_.
 * _Noticed_ messages are no longer _fresh_ and do not count as being unseen
 * but are still waiting for being marked as "seen" using dc_markseen_msgs()
 * (IMAP/MDNs is not done for noticed messages).
 *
 * Calling this function usually results in the event #DC_EVENT_MSGS_CHANGED.
 * See also dc_marknoticed_all_chats(), dc_marknoticed_contact() and dc_markseen_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which all messages should be marked as being noticed.
 * @return None.
 */
void dc_marknoticed_chat(dc_context_t* context, uint32_t chat_id)
{
	sqlite3_stmt* check = NULL;
	sqlite3_stmt* update = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	// as there is no thread-safe way to find out the affected rows
	// and as we want to send the event only on changes,
	// we first check if there is sth. to update.
	// there is a chance of a race condition,
	// however, this would result in an additional event only.
	check = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM msgs "
		" WHERE chat_id=? AND state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	sqlite3_bind_int(check, 1, chat_id);
	if (sqlite3_step(check)!=SQLITE_ROW) {
		goto cleanup;
	}

	update = dc_sqlite3_prepare(context->sql,
		"UPDATE msgs "
		"   SET state=" DC_STRINGIFY(DC_STATE_IN_NOTICED)
		" WHERE chat_id=? AND state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	sqlite3_bind_int(update, 1, chat_id);
	sqlite3_step(update);

	context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);

cleanup:
	sqlite3_finalize(check);
	sqlite3_finalize(update);
}


/**
 * Same as dc_marknoticed_chat() but for _all_ chats.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @return None.
 */
void dc_marknoticed_all_chats(dc_context_t* context)
{
	sqlite3_stmt* check = NULL;
	sqlite3_stmt* update = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	check = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM msgs "
		" WHERE state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	if (sqlite3_step(check)!=SQLITE_ROW) {
		goto cleanup;
	}

	update = dc_sqlite3_prepare(context->sql,
		"UPDATE msgs "
		"   SET state=" DC_STRINGIFY(DC_STATE_IN_NOTICED)
		" WHERE state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
	sqlite3_step(update);

	context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);

cleanup:
	sqlite3_finalize(check);
	sqlite3_finalize(update);
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

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
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

	if (context==NULL || grpid==NULL) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id, blocked, type FROM chats WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
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
 * If a chat already exists, this ID is returned, otherwise a new chat is created;
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
	int           send_event = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return 0;
	}

	dc_lookup_real_nchat_by_contact_id(context, contact_id, &chat_id, &chat_blocked);
	if (chat_id) {
		if (chat_blocked) {
			dc_unblock_chat(context, chat_id); /* unblock chat (typically move it from the deaddrop to view) */
			send_event = 1;
		}
		goto cleanup; /* success */
	}

	if (0==dc_real_contact_exists(context, contact_id) && contact_id!=DC_CONTACT_ID_SELF) {
		dc_log_warning(context, 0, "Cannot create chat, contact %i does not exist.", (int)contact_id);
		goto cleanup;
	}

	dc_create_or_lookup_nchat_by_contact_id(context, contact_id, DC_CHAT_NOT_BLOCKED, &chat_id, NULL);
	if (chat_id) {
		send_event = 1;
	}

	dc_scaleup_contact_origin(context, contact_id, DC_ORIGIN_CREATE_CHAT);

cleanup:
	if (send_event) {
		context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
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
 * If the user is asked before creation, he should be
 * asked whether he wants to chat with the _contact_ belonging to the message;
 * the group names may be really weird when taken from the subject of implicit
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
	uint32_t   chat_id  = 0;
	int        send_event = 0;
	dc_msg_t*  msg = dc_msg_new_untyped(context);
	dc_chat_t* chat = dc_chat_new(context);

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (!dc_msg_load_from_db(msg, context, msg_id)
	 || !dc_chat_load_from_db(chat, msg->chat_id)
	 || chat->id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	chat_id = chat->id;

	if (chat->blocked) {
		dc_unblock_chat(context, chat->id);
		send_event = 1;
	}

	dc_scaleup_contact_origin(context, msg->from_id, DC_ORIGIN_CREATE_CHAT);

cleanup:
	dc_msg_unref(msg);
	dc_chat_unref(chat);
	if (send_event) {
		context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
	}
	return chat_id;
}


/**
 * Returns all message IDs of the given types in a chat.
 * Typically used to show a gallery.
 * The result must be dc_array_unref()'d
 *
 * The list is already sorted and starts with the oldest message.
 * Clients should not try to re-sort the list as this would be an expensive action
 * and would result in inconsistencies between clients.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID to get all messages with media from.
 * @param msg_type Specify a message type to query here, one of the DC_MSG_* constats.
 * @param msg_type2 Alternative message type to search for. 0 to skip.
 * @param msg_type3 Alternative message type to search for. 0 to skip.
 * @return An array with messages from the given chat ID that have the wanted message types.
 */
dc_array_t* dc_get_chat_media(dc_context_t* context, uint32_t chat_id,
                              int msg_type, int msg_type2, int msg_type3)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return NULL;
	}

	dc_array_t* ret = dc_array_new(context, 100);

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM msgs WHERE chat_id=? AND (type=? OR type=? OR type=?) ORDER BY timestamp, id;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, msg_type);
	sqlite3_bind_int(stmt, 3, msg_type2>0? msg_type2 : msg_type);
	sqlite3_bind_int(stmt, 4, msg_type3>0? msg_type3 : msg_type);
	while (sqlite3_step(stmt)==SQLITE_ROW) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}
	sqlite3_finalize(stmt);

	return ret;
}


/**
 * Search next/previous message based on a given message and a list of types.
 * The
 * Typically used to implement the "next" and "previous" buttons
 * in a gallery or in a media player.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param curr_msg_id  This is the current message
 *     from which the next or previous message should be searched.
 * @param dir 1=get the next message, -1=get the previous one.
 * @param msg_type Message type to search for.
 *     If 0, the message type from curr_msg_id is used.
 * @param msg_type2 Alternative message type to search for. 0 to skip.
 * @param msg_type3 Alternative message type to search for. 0 to skip.
 * @return Returns the message ID that should be played next.
 *     The returned message is in the same chat as the given one
 *     and has one of the given types.
 *     Typically, this result is passed again to dc_get_next_media()
 *     later on the next swipe.
 *     If there is not next/previous message, the function returns 0.
 */
uint32_t dc_get_next_media(dc_context_t* context, uint32_t curr_msg_id, int dir,
                              int msg_type, int msg_type2, int msg_type3)
{
	uint32_t    ret_msg_id = 0;
	dc_msg_t*   msg = dc_msg_new_untyped(context);
	dc_array_t* list = NULL;
	int         i = 0;
	int         cnt = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (!dc_msg_load_from_db(msg, context, curr_msg_id)) {
		goto cleanup;
	}

	if ((list=dc_get_chat_media(context, msg->chat_id,
			msg_type>0? msg_type : msg->type,
			msg_type2, msg_type3))==NULL) {
		goto cleanup;
	}

	cnt = dc_array_get_cnt(list);
	for (i = 0; i < cnt; i++) {
		if (curr_msg_id==dc_array_get_id(list, i))
		{
			if (dir > 0) {
				/* get the next message from the current position */
				if (i+1 < cnt) {
					ret_msg_id = dc_array_get_id(list, i+1);
				}
			}
			else if (dir < 0) {
				/* get the previous message from the current position */
				if (i-1 >= 0) {
					ret_msg_id = dc_array_get_id(list, i-1);
				}
			}
			break;
		}
	}


cleanup:
	dc_array_unref(list);
	dc_msg_unref(msg);
	return ret_msg_id;
}


/**
 * Get contact IDs belonging to a chat.
 *
 * - for normal chats, the function always returns exactly one contact,
 *   DC_CONTACT_ID_SELF is returned only for SELF-chats.
 *
 * - for group chats all members are returned, DC_CONTACT_ID_SELF is returned
 *   explicitly as it may happen that oneself gets removed from a still existing
 *   group
 *
 * - for the deaddrop, the list is empty
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to get the belonging contact IDs for.
 * @return An array of contact IDs belonging to the chat; must be freed using dc_array_unref() when done.
 */
dc_array_t* dc_get_chat_contacts(dc_context_t* context, uint32_t chat_id)
{
	/* Normal chats do not include SELF.  Group chats do (as it may happen that one is deleted from a
	groupchat but the chats stays visible, moreover, this makes displaying lists easier) */
	dc_array_t*   ret = dc_array_new(context, 100);
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	if (chat_id==DC_CHAT_ID_DEADDROP) {
		goto cleanup; /* we could also create a list for all contacts in the deaddrop by searching contacts belonging to chats with chats.blocked=2, however, currently this is not needed */
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT cc.contact_id FROM chats_contacts cc"
			" LEFT JOIN contacts c ON c.id=cc.contact_id"
			" WHERE cc.chat_id=?"
			" ORDER BY c.id=1, LOWER(c.name||c.addr), c.id;");
	sqlite3_bind_int(stmt, 1, chat_id);
	while (sqlite3_step(stmt)==SQLITE_ROW) {
		dc_array_add_id(ret, sqlite3_column_int(stmt, 0));
	}

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


/**
 * Get all message IDs belonging to a chat.
 *
 * The list is already sorted and starts with the oldest message.
 * Clients should not try to re-sort the list as this would be an expensive action
 * and would result in inconsistencies between clients.
 *
 * Optionally, some special markers added to the ID-array may help to
 * implement virtual lists.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which the messages IDs should be queried.
 * @param flags If set to DC_GCM_ADDDAYMARKER, the marker DC_MSG_ID_DAYMARKER will
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

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || ret==NULL) {
		goto cleanup;
	}

	if (chat_id==DC_CHAT_ID_DEADDROP)
	{
		int show_emails = dc_sqlite3_get_config_int(context->sql,
			"show_emails", DC_SHOW_EMAILS_DEFAULT);

		stmt = dc_sqlite3_prepare(context->sql,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				" LEFT JOIN chats ON m.chat_id=chats.id"
				" LEFT JOIN contacts ON m.from_id=contacts.id"
				" WHERE m.from_id!=" DC_STRINGIFY(DC_CONTACT_ID_SELF)
				"   AND m.from_id!=" DC_STRINGIFY(DC_CONTACT_ID_DEVICE)
				"   AND m.hidden=0 "
				"   AND chats.blocked=" DC_STRINGIFY(DC_CHAT_DEADDROP_BLOCKED)
				"   AND contacts.blocked=0"
				"   AND m.msgrmsg>=? "
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
		sqlite3_bind_int(stmt, 1, show_emails==DC_SHOW_EMAILS_ALL? 0 : 1);
	}
	else if (chat_id==DC_CHAT_ID_STARRED)
	{
		stmt = dc_sqlite3_prepare(context->sql,
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
		stmt = dc_sqlite3_prepare(context->sql,
			"SELECT m.id, m.timestamp"
				" FROM msgs m"
				//" LEFT JOIN contacts ct ON m.from_id=ct.id"
				" WHERE m.chat_id=? "
				"   AND m.hidden=0 "
				//"   AND ct.blocked=0" -- we hide blocked-contacts from starred and deaddrop, but we have to show them in groups (otherwise it may be hard to follow conversation, wa and tg do the same. however, maybe this needs discussion some time :)
				" ORDER BY m.timestamp,m.id;"); /* the list starts with the oldest message*/
		sqlite3_bind_int(stmt, 1, chat_id);
	}

	while (sqlite3_step(stmt)==SQLITE_ROW)
	{
		curr_id = sqlite3_column_int(stmt, 0);

		/* add user marker */
		if (curr_id==marker1before) {
			dc_array_add_id(ret, DC_MSG_ID_MARKER1);
		}

		/* add daymarker, if needed */
		if (flags&DC_GCM_ADDDAYMARKER) {
			curr_local_timestamp = (time_t)sqlite3_column_int64(stmt, 1) + cnv_to_local;
			curr_day = curr_local_timestamp/DC_SECONDS_PER_DAY;
			if (curr_day!=last_day) {
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

	if (success) {
		return ret;
	}
	else {
		if (ret) {
			dc_array_unref(ret);
		}
		return NULL;
	}
}


static uint32_t get_draft_msg_id(dc_context_t* context, uint32_t chat_id)
{
	uint32_t draft_msg_id = 0;

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM msgs WHERE chat_id=? AND state=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, DC_STATE_OUT_DRAFT);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		draft_msg_id = sqlite3_column_int(stmt, 0);
	}
	sqlite3_finalize(stmt);

	return draft_msg_id;
}


static int set_draft_raw(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	// similar to as dc_set_draft() but does not emit an event
	sqlite3_stmt* stmt = NULL;
	char*         pathNfilename = NULL;
	uint32_t      prev_draft_msg_id = 0;
	int           sth_changed = 0;

	// delete old draft
	prev_draft_msg_id = get_draft_msg_id(context, chat_id);
	if (prev_draft_msg_id) {
		dc_delete_msg_from_db(context, prev_draft_msg_id);
		sth_changed = 1;
	}

	// save new draft
	if (msg==NULL)
	{
		goto cleanup;
	}
	else if (msg->type==DC_MSG_TEXT)
	{
		if (msg->text==NULL || msg->text[0]==0) {
			goto cleanup;
		}
	}
	else if (DC_MSG_NEEDS_ATTACHMENT(msg->type))
	{
		pathNfilename = dc_param_get(msg->param, DC_PARAM_FILE, NULL);
		if (pathNfilename==NULL) {
			goto cleanup;
		}

		if (dc_msg_is_increation(msg) && !dc_is_blobdir_path(context, pathNfilename)) {
			goto cleanup;
		}

		if (!dc_make_rel_and_copy(context, &pathNfilename)) {
			goto cleanup;
		}
		dc_param_set(msg->param, DC_PARAM_FILE, pathNfilename);
	}
	else
	{
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO msgs (chat_id, from_id, timestamp,"
		" type, state, txt, param, hidden)"
		" VALUES (?,?,?, ?,?,?,?,?);");
	sqlite3_bind_int  (stmt,  1, chat_id);
	sqlite3_bind_int  (stmt,  2, DC_CONTACT_ID_SELF);
	sqlite3_bind_int64(stmt,  3, time(NULL));
	sqlite3_bind_int  (stmt,  4, msg->type);
	sqlite3_bind_int  (stmt,  5, DC_STATE_OUT_DRAFT);
	sqlite3_bind_text (stmt,  6, msg->text? msg->text : "",  -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt,  7, msg->param->packed, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt,  8, 1);
	if (sqlite3_step(stmt)!=SQLITE_DONE) {
		goto cleanup;
	}

	sth_changed = 1;


cleanup:
	sqlite3_finalize(stmt);
	free(pathNfilename);
	return sth_changed;
}


/**
 * Save a draft for a chat in the database.
 *
 * The UI should call this function if the user has prepared a message
 * and exits the compose window without clicking the "send" button before.
 * When the user later opens the same chat again,
 * the UI can load the draft using dc_get_draft()
 * allowing the user to continue editing and sending.
 *
 * Drafts are considered when sorting messages
 * and are also returned eg. by dc_chatlist_get_summary().
 *
 * Each chat can have its own draft but only one draft per chat is possible.
 *
 * If the draft is modified, an #DC_EVENT_MSGS_CHANGED will be sent.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to save the draft for.
 * @param msg The message to save as a draft.
 *     Existing draft will be overwritten.
 *     NULL deletes the existing draft, if any, without sending it.
 *     Currently, also non-text-messages
 *     will delete the existing drafts.
 * @return None.
 */
void dc_set_draft(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		return;
	}

	if (set_draft_raw(context, chat_id, msg)) {
		context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, 0);
	}
}


/**
 * Get draft for a chat, if any.
 * See dc_set_draft() for more details about drafts.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param chat_id The chat ID to get the draft for.
 * @return Message object.
 *     Can be passed directly to dc_send_msg().
 *     Must be freed using dc_msg_unref() after usage.
 *     If there is no draft, NULL is returned.
 */
dc_msg_t* dc_get_draft(dc_context_t* context, uint32_t chat_id)
{
	uint32_t  draft_msg_id = 0;
	dc_msg_t* draft_msg = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC
	 || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		return NULL;
	}

	draft_msg_id = get_draft_msg_id(context, chat_id);
	if (draft_msg_id==0) {
		return NULL;
	}

	draft_msg = dc_msg_new_untyped(context);
	if (!dc_msg_load_from_db(draft_msg, context, draft_msg_id)) {
		dc_msg_unref(draft_msg);
		return NULL;
	}

	return draft_msg;
}


void dc_lookup_real_nchat_by_contact_id(dc_context_t* context, uint32_t contact_id, uint32_t* ret_chat_id, int* ret_chat_blocked)
{
	/* checks for "real" chats or self-chat */
	sqlite3_stmt* stmt = NULL;

	if (ret_chat_id)      { *ret_chat_id = 0;      }
	if (ret_chat_blocked) { *ret_chat_blocked = 0; }

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->sql->cobj==NULL) {
		return; /* no database, no chats - this is no error (needed eg. for information) */
	}

	stmt = dc_sqlite3_prepare(context->sql,
			"SELECT c.id, c.blocked"
			" FROM chats c"
			" INNER JOIN chats_contacts j ON c.id=j.chat_id"
			" WHERE c.type=" DC_STRINGIFY(DC_CHAT_TYPE_SINGLE) " AND c.id>" DC_STRINGIFY(DC_CHAT_ID_LAST_SPECIAL) " AND j.contact_id=?;");
	sqlite3_bind_int(stmt, 1, contact_id);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		if (ret_chat_id)      { *ret_chat_id      = sqlite3_column_int(stmt, 0); }
		if (ret_chat_blocked) { *ret_chat_blocked = sqlite3_column_int(stmt, 1); }
	}
	sqlite3_finalize(stmt);
}


void dc_create_or_lookup_nchat_by_contact_id(dc_context_t* context, uint32_t contact_id, int create_blocked, uint32_t* ret_chat_id, int* ret_chat_blocked)
{
	uint32_t      chat_id = 0;
	int           chat_blocked = 0;
	dc_contact_t* contact = NULL;
	char*         chat_name = NULL;
	char*         q = NULL;
	sqlite3_stmt* stmt = NULL;

	if (ret_chat_id)      { *ret_chat_id = 0;      }
	if (ret_chat_blocked) { *ret_chat_blocked = 0; }

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->sql->cobj==NULL) {
		return; /* database not opened - error */
	}

	if (contact_id==0) {
		return;
	}

	dc_lookup_real_nchat_by_contact_id(context, contact_id, &chat_id, &chat_blocked);
	if (chat_id!=0) {
		if (ret_chat_id)      { *ret_chat_id      = chat_id;      }
		if (ret_chat_blocked) { *ret_chat_blocked = chat_blocked; }
		return; /* soon success */
	}

	/* get fine chat name */
	contact = dc_contact_new(context);
	if (!dc_contact_load_from_db(contact, context->sql, contact_id)) {
		goto cleanup;
	}

	chat_name = (contact->name&&contact->name[0])? contact->name : contact->addr;

	/* create chat record; the grpid is only used to make dc_sqlite3_get_rowid() work (we cannot use last_insert_id() due multi-threading) */
	q = sqlite3_mprintf("INSERT INTO chats (type, name, param, blocked, grpid) VALUES(%i, %Q, %Q, %i, %Q)", DC_CHAT_TYPE_SINGLE, chat_name,
		contact_id==DC_CONTACT_ID_SELF? "K=1" : "", create_blocked, contact->addr);
	assert( DC_PARAM_SELFTALK=='K');
	stmt = dc_sqlite3_prepare(context->sql, q);
	if (stmt==NULL) {
		goto cleanup;
	}

    if (sqlite3_step(stmt)!=SQLITE_DONE) {
		goto cleanup;
    }

    chat_id = dc_sqlite3_get_rowid(context->sql, "chats", "grpid", contact->addr);

	sqlite3_free(q);
	q = NULL;
	sqlite3_finalize(stmt);
	stmt = NULL;

	/* add contact IDs to the new chat record (may be replaced by dc_add_to_chat_contacts_table()) */
	q = sqlite3_mprintf("INSERT INTO chats_contacts (chat_id, contact_id) VALUES(%i, %i)", chat_id, contact_id);
	stmt = dc_sqlite3_prepare(context->sql, q);

	if (sqlite3_step(stmt)!=SQLITE_DONE) {
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

	if (ret_chat_id)      { *ret_chat_id      = chat_id; }
	if (ret_chat_blocked) { *ret_chat_blocked = create_blocked; }
}


/**
 * Get the total number of messages in a chat.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to count the messages for.
 * @return Number of total messages in the given chat. 0 for errors or empty chats.
 */
int dc_get_msg_cnt(dc_context_t* context, uint32_t chat_id)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT COUNT(*) FROM msgs WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)!=SQLITE_ROW) {
		goto cleanup;
	}

	ret = sqlite3_column_int(stmt, 0);

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


void dc_unarchive_chat(dc_context_t* context, uint32_t chat_id)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
	    "UPDATE chats SET archived=0 WHERE id=?");
	sqlite3_bind_int (stmt, 1, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
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
int dc_get_fresh_msg_cnt(dc_context_t* context, uint32_t chat_id)
{
	int           ret = 0;
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT COUNT(*) FROM msgs "
		" WHERE state=" DC_STRINGIFY(DC_STATE_IN_FRESH)
		"   AND hidden=0 "
		"   AND chat_id=?;"); /* we have an index over the state-column, this should be sufficient as there are typically only few fresh messages */
	sqlite3_bind_int(stmt, 1, chat_id);

	if (sqlite3_step(stmt)!=SQLITE_ROW) {
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
 * - Messages in archived chats are marked as being noticed, so they do not count as "fresh"
 * - Calling this function usually results in the event #DC_EVENT_MSGS_CHANGED
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to archive or unarchive.
 * @param archive 1=archive chat, 0=unarchive chat, all other values are reserved for future use
 * @return None.
 */
void dc_archive_chat(dc_context_t* context, uint32_t chat_id, int archive)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL || (archive!=0 && archive!=1)) {
		return;
	}

	if (archive) {
		sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
			"UPDATE msgs SET state=" DC_STRINGIFY(DC_STATE_IN_NOTICED)
			" WHERE chat_id=? AND state=" DC_STRINGIFY(DC_STATE_IN_FRESH) ";");
		sqlite3_bind_int(stmt, 1, chat_id);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}

	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"UPDATE chats SET archived=? WHERE id=?;");
	sqlite3_bind_int  (stmt, 1, archive);
	sqlite3_bind_int  (stmt, 2, chat_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
}


void dc_block_chat(dc_context_t* context, uint32_t chat_id, int new_blocking)
{
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		return;
	}

	stmt = dc_sqlite3_prepare(context->sql,
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
 *   all group members - especially for groups not used for a longer time, this is
 *   really unexpected when deletion results in contacting all members again,
 *   (3) only leaving groups is also a valid usecase.
 *
 * To leave a chat explicitly, use dc_remove_contact_from_chat() with
 * chat_id=DC_CONTACT_ID_SELF)
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to delete.
 * @return None.
 */
void dc_delete_chat(dc_context_t* context, uint32_t chat_id)
{
	/* Up to 2017-11-02 deleting a group also implied leaving it, see above why we have changed this. */
	int        pending_transaction = 0;
	dc_chat_t* obj = dc_chat_new(context);
	char*      q3 = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	if (!dc_chat_load_from_db(obj, chat_id)) {
		goto cleanup;
	}

	dc_sqlite3_begin_transaction(context->sql);
	pending_transaction = 1;

		q3 = sqlite3_mprintf("DELETE FROM msgs_mdns WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=%i);", chat_id);
		if (!dc_sqlite3_execute(context->sql, q3)) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

		q3 = sqlite3_mprintf("DELETE FROM msgs WHERE chat_id=%i;", chat_id);
		if (!dc_sqlite3_execute(context->sql, q3)) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

		q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i;", chat_id);
		if (!dc_sqlite3_execute(context->sql, q3)) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

		q3 = sqlite3_mprintf("DELETE FROM chats WHERE id=%i;", chat_id);
		if (!dc_sqlite3_execute(context->sql, q3)) {
			goto cleanup;
		}
		sqlite3_free(q3);
		q3 = NULL;

	dc_sqlite3_commit(context->sql);
	pending_transaction = 0;

	context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);

	dc_job_kill_action(context, DC_JOB_HOUSEKEEPING);
	dc_job_add(context, DC_JOB_HOUSEKEEPING, 0, NULL, DC_HOUSEKEEPING_DELAY_SEC);

cleanup:
	if (pending_transaction) { dc_sqlite3_rollback(context->sql); }
	dc_chat_unref(obj);
	sqlite3_free(q3);
}


/*******************************************************************************
 * Handle Group Chats
 ******************************************************************************/


#define IS_SELF_IN_GROUP     (dc_is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF)==1)
#define DO_SEND_STATUS_MAILS (dc_param_get_int(chat->param, DC_PARAM_UNPROMOTED, 0)==0)


int dc_is_group_explicitly_left(dc_context_t* context, const char* grpid)
{
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql, "SELECT id FROM leftgrps WHERE grpid=?;");
	sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
	int ret = (sqlite3_step(stmt)==SQLITE_ROW);
	sqlite3_finalize(stmt);
	return ret;
}


void dc_set_group_explicitly_left(dc_context_t* context, const char* grpid)
{
	if (!dc_is_group_explicitly_left(context, grpid))
	{
		sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql, "INSERT INTO leftgrps (grpid) VALUES(?);");
		sqlite3_bind_text (stmt, 1, grpid, -1, SQLITE_STATIC);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
}


static int real_group_exists(dc_context_t* context, uint32_t chat_id)
{
	// check if a group or a verified group exists under the given ID
	sqlite3_stmt* stmt = NULL;
	int           ret = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || context->sql->cobj==NULL
	 || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		return 0;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT id FROM chats "
		" WHERE id=? "
		"   AND (type=" DC_STRINGIFY(DC_CHAT_TYPE_GROUP) " OR type=" DC_STRINGIFY(DC_CHAT_TYPE_VERIFIED_GROUP) ");");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		ret = 1;
	}
	sqlite3_finalize(stmt);

	return ret;
}


/**
 * Create a new group chat.
 *
 * After creation,
 * the draft of the chat is set to a default text,
 * the group has one member with the ID DC_CONTACT_ID_SELF
 * and is in _unpromoted_ state.
 * This means, you can add or remove members, change the name,
 * the group image and so on without messages being sent to all group members.
 *
 * This changes as soon as the first message is sent to the group members
 * and the group becomes _promoted_.
 * After that, all changes are synced with all group members
 * by sending status message.
 *
 * To check, if a chat is still unpromoted, you dc_chat_is_unpromoted().
 * This may be useful if you want to show some help for just created groups.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param verified If set to 1 the function creates a secure verified group.
 *     Only secure-verified members are allowed in these groups
 *     and end-to-end-encryption is always enabled.
 * @param chat_name The name of the group chat to create.
 *     The name may be changed later using dc_set_chat_name().
 *     To find out the name of a group later, see dc_chat_get_name()
 * @return The chat ID of the new group chat, 0 on errors.
 */
uint32_t dc_create_group_chat(dc_context_t* context, int verified, const char* chat_name)
{
	uint32_t      chat_id = 0;
	char*         draft_txt = NULL;
	dc_msg_t*     draft_msg = NULL;
	char*         grpid = NULL;
	sqlite3_stmt* stmt = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_name==NULL || chat_name[0]==0) {
		return 0;
	}

	draft_txt = dc_stock_str_repl_string(context, DC_STR_NEWGROUPDRAFT, chat_name);
	grpid = dc_create_id();

	stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO chats (type, name, grpid, param) VALUES(?, ?, ?, 'U=1');" /*U=DC_PARAM_UNPROMOTED*/);
	sqlite3_bind_int  (stmt, 1, verified? DC_CHAT_TYPE_VERIFIED_GROUP : DC_CHAT_TYPE_GROUP);
	sqlite3_bind_text (stmt, 2, chat_name, -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 3, grpid, -1, SQLITE_STATIC);
	if ( sqlite3_step(stmt)!=SQLITE_DONE) {
		goto cleanup;
	}

	if ((chat_id=dc_sqlite3_get_rowid(context->sql, "chats", "grpid", grpid))==0) {
		goto cleanup;
	}

	if (!dc_add_to_chat_contacts_table(context, chat_id, DC_CONTACT_ID_SELF)) {
		goto cleanup;
	}

	draft_msg = dc_msg_new(context, DC_MSG_TEXT);
	dc_msg_set_text(draft_msg, draft_txt);
	set_draft_raw(context, chat_id, draft_msg);

cleanup:
	sqlite3_finalize(stmt);
	free(draft_txt);
	dc_msg_unref(draft_msg);
	free(grpid);

	if (chat_id) {
		context->cb(context, DC_EVENT_MSGS_CHANGED, 0, 0);
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
	dc_msg_t*  msg = dc_msg_new_untyped(context);
	char*      q3 = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || new_name==NULL || new_name[0]==0 || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	if (0==real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id)) {
		goto cleanup;
	}

	if (strcmp(chat->name, new_name)==0) {
		success = 1;
		goto cleanup; /* name not modified */
	}

	if (!IS_SELF_IN_GROUP) {
		dc_log_event(context, DC_EVENT_ERROR_SELF_NOT_IN_GROUP, 0,
		             "Cannot set chat name; self not in group");
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	q3 = sqlite3_mprintf("UPDATE chats SET name=%Q WHERE id=%i;", new_name, chat_id);
	if (!dc_sqlite3_execute(context->sql, q3)) {
		goto cleanup;
	}

	/* send a status mail to all group members, also needed for outself to allow multi-client */
	if (DO_SEND_STATUS_MAILS)
	{
		msg->type = DC_MSG_TEXT;
		msg->text = dc_stock_system_msg(context, DC_STR_MSGGRPNAME, chat->name, new_name, DC_CONTACT_ID_SELF);
		dc_param_set_int(msg->param, DC_PARAM_CMD,     DC_CMD_GROUPNAME_CHANGED);
		dc_param_set    (msg->param, DC_PARAM_CMD_ARG, chat->name);
		msg->id = dc_send_msg(context, chat_id, msg);
		context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->id);
	}
	context->cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

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
	dc_msg_t*  msg = dc_msg_new_untyped(context);
	char*      new_image_rel = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	if (0==real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id)) {
		goto cleanup;
	}

	if (!IS_SELF_IN_GROUP) {
		dc_log_event(context, DC_EVENT_ERROR_SELF_NOT_IN_GROUP, 0,
		             "Cannot set chat profile image; self not in group.");
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	if (new_image) {
		new_image_rel = dc_strdup(new_image);
		if (!dc_make_rel_and_copy(context, &new_image_rel)) {
			goto cleanup;
		}
	}

	dc_param_set(chat->param, DC_PARAM_PROFILE_IMAGE, new_image_rel/*may be NULL*/);
	if (!dc_chat_update_param(chat)) {
		goto cleanup;
	}

	/* send a status mail to all group members, also needed for outself to allow multi-client */
	if (DO_SEND_STATUS_MAILS)
	{
		dc_param_set_int(msg->param, DC_PARAM_CMD,     DC_CMD_GROUPIMAGE_CHANGED);
		dc_param_set    (msg->param, DC_PARAM_CMD_ARG, new_image_rel);
		msg->type = DC_MSG_TEXT;
		msg->text = dc_stock_system_msg(context, new_image_rel? DC_STR_MSGGRPIMGCHANGED : DC_STR_MSGGRPIMGDELETED, NULL, NULL, DC_CONTACT_ID_SELF);
		msg->id = dc_send_msg(context, chat_id, msg);
		context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->id);
	}
	context->cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	dc_chat_unref(chat);
	dc_msg_unref(msg);
	free(new_image_rel);
	return success;
}


int dc_get_chat_contact_cnt(dc_context_t* context, uint32_t chat_id)
{
	int ret = 0;
	sqlite3_stmt* stmt = dc_sqlite3_prepare(context->sql,
		"SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
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

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"SELECT contact_id FROM chats_contacts WHERE chat_id=? AND contact_id=?;");
	sqlite3_bind_int(stmt, 1, chat_id);
	sqlite3_bind_int(stmt, 2, contact_id);
	ret = (sqlite3_step(stmt)==SQLITE_ROW)? 1 : 0;

cleanup:
	sqlite3_finalize(stmt);
	return ret;
}


int dc_add_contact_to_chat_ex(dc_context_t* context, uint32_t chat_id, uint32_t contact_id, int flags)
{
	int              success = 0;
	dc_contact_t*    contact = dc_get_contact(context, contact_id);
	dc_chat_t*       chat = dc_chat_new(context);
	dc_msg_t*        msg = dc_msg_new_untyped(context);
	char*            self_addr = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || contact==NULL || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	dc_reset_gossiped_timestamp(context, chat_id);

	if (0==real_group_exists(context, chat_id) /*this also makes sure, not contacts are added to special or normal chats*/
	 || (0==dc_real_contact_exists(context, contact_id) && contact_id!=DC_CONTACT_ID_SELF)
	 || 0==dc_chat_load_from_db(chat, chat_id)) {
		goto cleanup;
	}

	if (!IS_SELF_IN_GROUP) {
		dc_log_event(context, DC_EVENT_ERROR_SELF_NOT_IN_GROUP, 0,
		             "Cannot add contact to group; self not in group.");
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	if ((flags&DC_FROM_HANDSHAKE) && dc_param_get_int(chat->param, DC_PARAM_UNPROMOTED, 0)==1) {
		// after a handshake, force sending the `Chat-Group-Member-Added` message
		dc_param_set(chat->param, DC_PARAM_UNPROMOTED, NULL);
		dc_chat_update_param(chat);
	}

	self_addr = dc_sqlite3_get_config(context->sql, "configured_addr", "");
	if (strcasecmp(contact->addr, self_addr)==0) {
		goto cleanup; /* ourself is added using DC_CONTACT_ID_SELF, do not add it explicitly. if SELF is not in the group, members cannot be added at all. */
	}

	if (dc_is_contact_in_chat(context, chat_id, contact_id))
	{
		if (!(flags&DC_FROM_HANDSHAKE)) {
			success = 1;
			goto cleanup;
		}
		// else continue and send status mail
	}
	else
	{
		if (chat->type==DC_CHAT_TYPE_VERIFIED_GROUP)
		{
			if (dc_contact_is_verified(contact)!=DC_BIDIRECT_VERIFIED) {
				dc_log_error(context, 0, "Only bidirectional verified contacts can be added to verified groups.");
				goto cleanup;
			}
		}

		if (0==dc_add_to_chat_contacts_table(context, chat_id, contact_id)) {
			goto cleanup;
		}
	}

	/* send a status mail to all group members */
	if (DO_SEND_STATUS_MAILS)
	{
		msg->type = DC_MSG_TEXT;
		msg->text = dc_stock_system_msg(context, DC_STR_MSGADDMEMBER, contact->addr, NULL, DC_CONTACT_ID_SELF);
		dc_param_set_int(msg->param, DC_PARAM_CMD,      DC_CMD_MEMBER_ADDED_TO_GROUP);
		dc_param_set    (msg->param, DC_PARAM_CMD_ARG,  contact->addr);
		dc_param_set_int(msg->param, DC_PARAM_CMD_ARG2, flags); // combine the Secure-Join protocol headers with the Chat-Group-Member-Added header
		msg->id = dc_send_msg(context, chat_id, msg);
		context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->id);
	}
	context->cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	dc_chat_unref(chat);
	dc_contact_unref(contact);
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
	dc_msg_t*     msg = dc_msg_new_untyped(context);
	char*         q3 = NULL;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL || (contact_id<=DC_CONTACT_ID_LAST_SPECIAL && contact_id!=DC_CONTACT_ID_SELF)) {
		goto cleanup; /* we do not check if "contact_id" exists but just delete all records with the id from chats_contacts */
	}                 /* this allows to delete pending references to deleted contacts.  Of course, this should _not_ happen. */

	if (0==real_group_exists(context, chat_id)
	 || 0==dc_chat_load_from_db(chat, chat_id)) {
		goto cleanup;
	}

	if (!IS_SELF_IN_GROUP) {
		dc_log_event(context, DC_EVENT_ERROR_SELF_NOT_IN_GROUP, 0,
		             "Cannot remove contact from chat; self not in group.");
		goto cleanup; /* we shoud respect this - whatever we send to the group, it gets discarded anyway! */
	}

	/* send a status mail to all group members - we need to do this before we update the database -
	otherwise the !IS_SELF_IN_GROUP__-check in dc_chat_send_msg() will fail. */
	if (contact)
	{
		if (DO_SEND_STATUS_MAILS)
		{
			msg->type = DC_MSG_TEXT;
			if (contact->id==DC_CONTACT_ID_SELF) {
				dc_set_group_explicitly_left(context, chat->grpid);
				msg->text = dc_stock_system_msg(context, DC_STR_MSGGROUPLEFT, NULL, NULL, DC_CONTACT_ID_SELF);
			}
			else {
				msg->text = dc_stock_system_msg(context, DC_STR_MSGDELMEMBER, contact->addr, NULL, DC_CONTACT_ID_SELF);
			}
			dc_param_set_int(msg->param, DC_PARAM_CMD,       DC_CMD_MEMBER_REMOVED_FROM_GROUP);
			dc_param_set    (msg->param, DC_PARAM_CMD_ARG, contact->addr);
			msg->id = dc_send_msg(context, chat_id, msg);
			context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg->id);
		}
	}

	q3 = sqlite3_mprintf("DELETE FROM chats_contacts WHERE chat_id=%i AND contact_id=%i;", chat_id, contact_id);
	if (!dc_sqlite3_execute(context->sql, q3)) {
		goto cleanup;
	}

	context->cb(context, DC_EVENT_CHAT_MODIFIED, chat_id, 0);

	success = 1;

cleanup:
	sqlite3_free(q3);
	dc_chat_unref(chat);
	dc_contact_unref(contact);
	dc_msg_unref(msg);
	return success;
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
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		dc_param_t* msg_param = dc_param_new();
		dc_param_set_packed(msg_param, (char*)sqlite3_column_text(stmt, 0));
		if (dc_param_exists(msg_param, DC_PARAM_GUARANTEE_E2EE)) {
			last_is_encrypted = 1;
		}
		dc_param_unref(msg_param);
	}
	sqlite3_finalize(stmt);
	return last_is_encrypted;
}


static int get_parent_mime_headers(const dc_chat_t* chat,
                                   char**           parent_rfc724_mid,
                                   char**           parent_in_reply_to,
                                   char**           parent_references)
{
	int           success = 0;
	sqlite3_stmt* stmt = NULL;

	if (chat==NULL
	 || parent_rfc724_mid==NULL || parent_in_reply_to==NULL || parent_references==NULL) {
		goto cleanup;
	}

	// use the last messsage of another user in the group as the parent
	stmt = dc_sqlite3_prepare(chat->context->sql,
		"SELECT rfc724_mid, mime_in_reply_to, mime_references"
		" FROM msgs"
		" WHERE timestamp=(SELECT max(timestamp) FROM msgs WHERE chat_id=? AND from_id!=?);");
	sqlite3_bind_int  (stmt, 1, chat->id);
	sqlite3_bind_int  (stmt, 2, DC_CONTACT_ID_SELF);
	if (sqlite3_step(stmt)==SQLITE_ROW) {
		*parent_rfc724_mid  = dc_strdup((const char*)sqlite3_column_text(stmt, 0));
		*parent_in_reply_to = dc_strdup((const char*)sqlite3_column_text(stmt, 1));
		*parent_references  = dc_strdup((const char*)sqlite3_column_text(stmt, 2));
		success = 1;
	}
	sqlite3_finalize(stmt);
	stmt = NULL;

	if (!success) {
		// there are no messages of other users - use the first message if SELF as parent
		stmt = dc_sqlite3_prepare(chat->context->sql,
			"SELECT rfc724_mid, mime_in_reply_to, mime_references"
			" FROM msgs"
			" WHERE timestamp=(SELECT min(timestamp) FROM msgs WHERE chat_id=? AND from_id==?);");
		sqlite3_bind_int  (stmt, 1, chat->id);
		sqlite3_bind_int  (stmt, 2, DC_CONTACT_ID_SELF);
		if (sqlite3_step(stmt)==SQLITE_ROW) {
			*parent_rfc724_mid  = dc_strdup((const char*)sqlite3_column_text(stmt, 0));
			*parent_in_reply_to = dc_strdup((const char*)sqlite3_column_text(stmt, 1));
			*parent_references  = dc_strdup((const char*)sqlite3_column_text(stmt, 2));
			success = 1;
		}
	}

cleanup:
	sqlite3_finalize(stmt);
	return success;
}


static uint32_t prepare_msg_raw(dc_context_t* context, dc_chat_t* chat, const dc_msg_t* msg, time_t timestamp)
{
	char*         parent_rfc724_mid = NULL;
	char*         parent_references = NULL;
	char*         parent_in_reply_to = NULL;
	char*         new_rfc724_mid = NULL;
	char*         new_references = NULL;
	char*         new_in_reply_to = NULL;
	sqlite3_stmt* stmt = NULL;
	uint32_t      msg_id = 0;
	uint32_t      to_id = 0;

	if (!DC_CHAT_TYPE_CAN_SEND(chat->type)) {
		dc_log_error(context, 0, "Cannot send to chat type #%i.", chat->type);
		goto cleanup;
	}

	if (DC_CHAT_TYPE_IS_MULTI(chat->type) && !dc_is_contact_in_chat(context, chat->id, DC_CONTACT_ID_SELF)) {
		dc_log_event(context, DC_EVENT_ERROR_SELF_NOT_IN_GROUP, 0,
		             "Cannot send message; self not in group.");
		goto cleanup;
	}

	{
		char* from = dc_sqlite3_get_config(context->sql, "configured_addr", NULL);
		if (from==NULL) {
			dc_log_error(context, 0, "Cannot send message, not configured.");
			goto cleanup;
		}
		new_rfc724_mid = dc_create_outgoing_rfc724_mid(DC_CHAT_TYPE_IS_MULTI(chat->type)? chat->grpid : NULL, from);
		free(from);
	}

	if (chat->type==DC_CHAT_TYPE_SINGLE)
	{
		stmt = dc_sqlite3_prepare(context->sql,
			"SELECT contact_id FROM chats_contacts WHERE chat_id=?;");
		sqlite3_bind_int(stmt, 1, chat->id);
		if (sqlite3_step(stmt)!=SQLITE_ROW) {
			dc_log_error(context, 0, "Cannot send message, contact for chat #%i not found.", chat->id);
			goto cleanup;
		}
		to_id = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	else if (DC_CHAT_TYPE_IS_MULTI(chat->type))
	{
		if (dc_param_get_int(chat->param, DC_PARAM_UNPROMOTED, 0)==1) {
			/* mark group as being no longer unpromoted */
			dc_param_set(chat->param, DC_PARAM_UNPROMOTED, NULL);
			dc_chat_update_param(chat);
		}
	}

	/* check if we can guarantee E2EE for this message.
	if we guarantee E2EE, and circumstances change
	so that E2EE is no longer available at a later point (reset, changed settings),
	we do not send the message out at all */
	int do_guarantee_e2ee = 0;
	int e2ee_enabled = dc_sqlite3_get_config_int(context->sql, "e2ee_enabled", DC_E2EE_DEFAULT_ENABLED);
	if (e2ee_enabled && dc_param_get_int(msg->param, DC_PARAM_FORCE_PLAINTEXT, 0)==0)
	{
		int can_encrypt = 1, all_mutual = 1; /* be optimistic */
		stmt = dc_sqlite3_prepare(context->sql,
			"SELECT ps.prefer_encrypted, c.addr"
			 " FROM chats_contacts cc "
			 " LEFT JOIN contacts c ON cc.contact_id=c.id "
			 " LEFT JOIN acpeerstates ps ON c.addr=ps.addr "
			 " WHERE cc.chat_id=? "                                               /* take care that this statement returns NULL rows if there is no peerstates for a chat member! */
			 " AND cc.contact_id>" DC_STRINGIFY(DC_CONTACT_ID_LAST_SPECIAL) ";"); /* for DC_PARAM_SELFTALK this statement does not return any row */
		sqlite3_bind_int(stmt, 1, chat->id);
		while (sqlite3_step(stmt)==SQLITE_ROW)
		{
			if (sqlite3_column_type(stmt, 0)==SQLITE_NULL) {
				dc_log_info(context, 0, "[autocrypt] no peerstate for %s",
					sqlite3_column_text(stmt, 1));
				can_encrypt = 0;
				all_mutual = 0;
			}
			else {
				/* the peerstate exist, so we have either public_key or gossip_key and can encrypt potentially */
				int prefer_encrypted = sqlite3_column_int(stmt, 0);
				if (prefer_encrypted!=DC_PE_MUTUAL) {
					dc_log_info(context, 0, "[autocrypt] peerstate for %s is %s",
						sqlite3_column_text(stmt, 1),
						prefer_encrypted==DC_PE_NOPREFERENCE? "NOPREFERENCE" : "RESET");
					all_mutual = 0;
				}
			}
		}
		sqlite3_finalize(stmt);
		stmt = NULL;

		if (can_encrypt)
		{
			if (all_mutual) {
				do_guarantee_e2ee = 1;
			}
			else {
				if (last_msg_in_chat_encrypted(context->sql, chat->id)) {
					do_guarantee_e2ee = 1;
				}
			}
		}
	}

	if (do_guarantee_e2ee) {
		dc_param_set_int(msg->param, DC_PARAM_GUARANTEE_E2EE, 1);
	}
	dc_param_set(msg->param, DC_PARAM_ERRONEOUS_E2EE, NULL); /* reset eg. on forwarding */

	// set "In-Reply-To:" to identify the message to which the composed message is a reply;
	// set "References:" to identify the "thread" of the conversation;
	// both according to RFC 5322 3.6.4, page 25
	//
	// as self-talks are mainly used to transfer data between devices,
	// we do not set In-Reply-To/References in this case.
	if (!dc_chat_is_self_talk(chat)
	 && get_parent_mime_headers(chat, &parent_rfc724_mid, &parent_in_reply_to, &parent_references))
	{
		if (parent_rfc724_mid && parent_rfc724_mid[0]) {
			new_in_reply_to = dc_strdup(parent_rfc724_mid);
		}

		// the whole list of messages referenced may be huge;
		// only use the oldest and and the parent message
		if (parent_references) {
			char* space = NULL;
			if ((space=strchr(parent_references, ' '))!=NULL) {
				*space = 0;
			}
		}

		if (parent_references && parent_references[0]
		 && parent_rfc724_mid && parent_rfc724_mid[0]) {
			// angle brackets are added by the mimefactory later
			new_references = dc_mprintf("%s %s", parent_references, parent_rfc724_mid);
		}
		else if (parent_references && parent_references[0]) {
			new_references = dc_strdup(parent_references);
		}
		else if (parent_in_reply_to && parent_in_reply_to[0]
		      && parent_rfc724_mid && parent_rfc724_mid[0]) {
			new_references = dc_mprintf("%s %s", parent_in_reply_to, parent_rfc724_mid);
		}
		else if (parent_in_reply_to && parent_in_reply_to[0]) {
			new_references = dc_strdup(parent_in_reply_to);
		}
	}

	/* add message to the database */
	stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO msgs (rfc724_mid, chat_id, from_id, to_id, timestamp,"
		" type, state, txt, param, hidden,"
		" mime_in_reply_to, mime_references)"
		" VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?);");
	sqlite3_bind_text (stmt,  1, new_rfc724_mid, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt,  2, chat->id);
	sqlite3_bind_int  (stmt,  3, DC_CONTACT_ID_SELF);
	sqlite3_bind_int  (stmt,  4, to_id);
	sqlite3_bind_int64(stmt,  5, timestamp);
	sqlite3_bind_int  (stmt,  6, msg->type);
	sqlite3_bind_int  (stmt,  7, msg->state);
	sqlite3_bind_text (stmt,  8, msg->text? msg->text : "",  -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt,  9, msg->param->packed, -1, SQLITE_STATIC);
	sqlite3_bind_int  (stmt, 10, msg->hidden);
	sqlite3_bind_text (stmt, 11, new_in_reply_to, -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 12, new_references, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt)!=SQLITE_DONE) {
		dc_log_error(context, 0, "Cannot send message, cannot insert to database.", chat->id);
		goto cleanup;
	}

	msg_id = dc_sqlite3_get_rowid(context->sql, "msgs", "rfc724_mid", new_rfc724_mid);

cleanup:
	free(parent_rfc724_mid);
	free(parent_in_reply_to);
	free(parent_references);
	free(new_rfc724_mid);
	free(new_in_reply_to);
	free(new_references);
	sqlite3_finalize(stmt);
	return msg_id;
}


static uint32_t prepare_msg_common(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	char*      pathNfilename = NULL;
	dc_chat_t* chat = NULL;

	msg->id      = 0;
	msg->context = context;

	if (msg->type==DC_MSG_TEXT)
	{
		; /* the caller should check if the message text is empty */
	}
	else if (DC_MSG_NEEDS_ATTACHMENT(msg->type))
	{
		pathNfilename = dc_param_get(msg->param, DC_PARAM_FILE, NULL);
		if (pathNfilename==NULL) {
			dc_log_error(context, 0, "Attachment missing for message of type #%i.", (int)msg->type);
			goto cleanup;
		}

		if (msg->state==DC_STATE_OUT_PREPARING && !dc_is_blobdir_path(context, pathNfilename)) {
			dc_log_error(context, 0, "Files must be created in the blob-directory.");
			goto cleanup;
		}

		if (!dc_make_rel_and_copy(context, &pathNfilename)) {
			goto cleanup;
		}
		dc_param_set(msg->param, DC_PARAM_FILE, pathNfilename);

		if (msg->type==DC_MSG_FILE || msg->type==DC_MSG_IMAGE)
		{
			/* Correct the type, take care not to correct already very special formats as GIF or VOICE.
			Typical conversions:
			- from FILE to AUDIO/VIDEO/IMAGE
			- from FILE/IMAGE to GIF */
			int   better_type = 0;
			char* better_mime = NULL;
			dc_msg_guess_msgtype_from_suffix(pathNfilename, &better_type, &better_mime);
			if (better_type) {
				msg->type = better_type;
				dc_param_set(msg->param, DC_PARAM_MIMETYPE, better_mime);
			}
			free(better_mime);
		}
		else if (!dc_param_exists(msg->param, DC_PARAM_MIMETYPE))
		{
			char* better_mime = NULL;
			dc_msg_guess_msgtype_from_suffix(pathNfilename, NULL, &better_mime);
			dc_param_set(msg->param, DC_PARAM_MIMETYPE, better_mime);
			free(better_mime);
		}

		dc_log_info(context, 0, "Attaching \"%s\" for message type #%i.", pathNfilename, (int)msg->type);
	}
	else
	{
		dc_log_error(context, 0, "Cannot send messages of type #%i.", (int)msg->type); /* should not happen */
		goto cleanup;
	}

	dc_unarchive_chat(context, chat_id);

	context->smtp->log_connect_errors = 1;

	chat = dc_chat_new(context);
	if (dc_chat_load_from_db(chat, chat_id)) {
		/* ensure the message is in a valid state */
		if (msg->state!=DC_STATE_OUT_PREPARING) msg->state = DC_STATE_OUT_PENDING;

		msg->id = prepare_msg_raw(context, chat, msg, dc_create_smeared_timestamp(context));
		msg->chat_id = chat_id;
		/* potential error already logged */
	}

cleanup:
	dc_chat_unref(chat);
	free(pathNfilename);
	return msg->id;
}


/**
 * Prepare a message for sending.
 *
 * Call this function if the file to be sent is still in creation.
 * Once you're done with creating the file, call dc_send_msg() as usual
 * and the message will really be sent.
 *
 * This is useful as the user can already send the next messages while
 * e.g. the recoding of a video is not yet finished. Or the user can even forward
 * the message with the file being still in creation to other groups.
 *
 * Files being sent with the increation-method must be placed in the
 * blob directory, see dc_get_blobdir().
 * If the increation-method is not used - which is probably the normal case -
 * dc_send_msg() copies the file to the blob directory if it is not yet there.
 * To distinguish the two cases, msg->state must be set properly. The easiest
 * way to ensure this is to re-use the same object for both calls.
 *
 * Example:
 * ~~~
 * dc_msg_t* msg = dc_msg_new(context, DC_MSG_VIDEO);
 * dc_msg_set_file(msg, "/file/to/send.mp4", NULL);
 * dc_prepare_msg(context, chat_id, msg);
 * // ... after /file/to/send.mp4 is ready:
 * dc_send_msg(context, chat_id, msg);
 * ~~~
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the message to.
 * @param msg Message object to send to the chat defined by the chat ID.
 *     On succcess, msg_id and state of the object are set up,
 *     The function does not take ownership of the object,
 *     so you have to free it using dc_msg_unref() as usual.
 * @return The ID of the message that is being prepared.
 */
uint32_t dc_prepare_msg(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || msg==NULL || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		return 0;
	}

	msg->state = DC_STATE_OUT_PREPARING;
	uint32_t msg_id = prepare_msg_common(context, chat_id, msg);

	context->cb(context, DC_EVENT_MSGS_CHANGED, msg->chat_id, msg->id);

	return msg_id;
}

/**
 * Send a message defined by a dc_msg_t object to a chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * Example:
 * ~~~
 * dc_msg_t* msg = dc_msg_new(context, DC_MSG_IMAGE);
 * dc_msg_set_file(msg, "/file/to/send.jpg", NULL);
 * dc_send_msg(context, chat_id, msg);
 * ~~~
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the message to.
 *     If dc_prepare_msg() was called before, this parameter can be 0.
 * @param msg Message object to send to the chat defined by the chat ID.
 *     On succcess, msg_id of the object is set up,
 *     The function does not take ownership of the object,
 *     so you have to free it using dc_msg_unref() as usual.
 * @return The ID of the message that is about to be sent. 0 in case of errors.
 */
uint32_t dc_send_msg(dc_context_t* context, uint32_t chat_id, dc_msg_t* msg)
{
	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || msg==NULL) {
		return 0;
	}

	// automatically prepare normal messages
	if (msg->state!=DC_STATE_OUT_PREPARING) {
		if (!prepare_msg_common(context, chat_id, msg)) {
			return 0;
		};
	}
	// update message state of separately prepared messages
	else {
		if (chat_id!=0 && chat_id!=msg->chat_id) {
			return 0;
		}
		dc_update_msg_state(context, msg->id, DC_STATE_OUT_PENDING);
	}

	// create message file and submit SMTP job
	if (!dc_job_send_msg(context, msg->id)) {
		return 0;
	}

	context->cb(context, DC_EVENT_MSGS_CHANGED, msg->chat_id, msg->id);

	// recursively send any forwarded copies
	if (!chat_id) {
		char* forwards = dc_param_get(msg->param, DC_PARAM_PREP_FORWARDS, NULL);
		if (forwards) {
			char* p = forwards;
			while (*p) {
				int32_t id = strtol(p, &p, 10);
				if (!id) break; // avoid hanging if user tampers with db
				dc_msg_t* copy = dc_get_msg(context, id);
				if (copy) {
					dc_send_msg(context, 0, copy);
				}
				dc_msg_unref(copy);
			}
			dc_param_set(msg->param, DC_PARAM_PREP_FORWARDS, NULL);
			dc_msg_save_param_to_disk(msg);
		}
		free(forwards);
	}

	return msg->id;
}


/**
 * Send a simple text message a given chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed eg. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * See also dc_send_msg().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id Chat ID to send the text message to.
 * @param text_to_send Text to send to the chat defined by the chat ID.
 *     Passing an empty text here causes an empty text to be sent,
 *     it's up to the caller to handle this if undesired.
 *     Passing NULL as the text causes the function to return 0.
 * @return The ID of the message that is about being sent.
 */
uint32_t dc_send_text_msg(dc_context_t* context, uint32_t chat_id, const char* text_to_send)
{
	dc_msg_t* msg = dc_msg_new(context, DC_MSG_TEXT);
	uint32_t  ret = 0;

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || chat_id<=DC_CHAT_ID_LAST_SPECIAL || text_to_send==NULL) {
		goto cleanup;
	}

	msg->text = dc_strdup(text_to_send);

	ret = dc_send_msg(context, chat_id, msg);

cleanup:
	dc_msg_unref(msg);
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
	char*         rfc724_mid = dc_create_outgoing_rfc724_mid(NULL, "@device");

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || text==NULL) {
		goto cleanup;
	}

	stmt = dc_sqlite3_prepare(context->sql,
		"INSERT INTO msgs (chat_id,from_id,to_id, timestamp,type,state, txt,rfc724_mid) VALUES (?,?,?, ?,?,?, ?,?);");
	sqlite3_bind_int  (stmt,  1, chat_id);
	sqlite3_bind_int  (stmt,  2, DC_CONTACT_ID_DEVICE);
	sqlite3_bind_int  (stmt,  3, DC_CONTACT_ID_DEVICE);
	sqlite3_bind_int64(stmt,  4, dc_create_smeared_timestamp(context));
	sqlite3_bind_int  (stmt,  5, DC_MSG_TEXT);
	sqlite3_bind_int  (stmt,  6, DC_STATE_IN_NOTICED);
	sqlite3_bind_text (stmt,  7, text,  -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt,  8, rfc724_mid,  -1, SQLITE_STATIC);
	if (sqlite3_step(stmt)!=SQLITE_DONE) {
		goto cleanup;
	}
	msg_id = dc_sqlite3_get_rowid(context->sql, "msgs", "rfc724_mid", rfc724_mid);
	context->cb(context, DC_EVENT_MSGS_CHANGED, chat_id, msg_id);

cleanup:
	free(rfc724_mid);
	sqlite3_finalize(stmt);
}


/**
 * Forward messages to another chat.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new()
 * @param msg_ids An array of uint32_t containing all message IDs that should be forwarded
 * @param msg_cnt The number of messages IDs in the msg_ids array
 * @param chat_id The destination chat ID.
 * @return None.
 */
void dc_forward_msgs(dc_context_t* context, const uint32_t* msg_ids, int msg_cnt, uint32_t chat_id)
{
	dc_msg_t*      msg = dc_msg_new_untyped(context);
	dc_chat_t*     chat = dc_chat_new(context);
	dc_contact_t*  contact = dc_contact_new(context);
	int            transaction_pending = 0;
	carray*        created_db_entries = carray_new(16);
	char*          idsstr = NULL;
	char*          q3 = NULL;
	sqlite3_stmt*  stmt = NULL;
	time_t         curr_timestamp = 0;
	dc_param_t*    original_param = dc_param_new();

	if (context==NULL || context->magic!=DC_CONTEXT_MAGIC || msg_ids==NULL || msg_cnt<=0 || chat_id<=DC_CHAT_ID_LAST_SPECIAL) {
		goto cleanup;
	}

	dc_sqlite3_begin_transaction(context->sql);
	transaction_pending = 1;

		dc_unarchive_chat(context, chat_id);

		context->smtp->log_connect_errors = 1;

		if (!dc_chat_load_from_db(chat, chat_id)) {
			goto cleanup;
		}

		curr_timestamp = dc_create_smeared_timestamps(context, msg_cnt);

		idsstr = dc_arr_to_string(msg_ids, msg_cnt);
		q3 = sqlite3_mprintf("SELECT id FROM msgs WHERE id IN(%s) ORDER BY timestamp,id", idsstr);
		stmt = dc_sqlite3_prepare(context->sql, q3);
		while (sqlite3_step(stmt)==SQLITE_ROW)
		{
			int src_msg_id = sqlite3_column_int(stmt, 0);
			if (!dc_msg_load_from_db(msg, context, src_msg_id)) {
				goto cleanup;
			}

			dc_param_set_packed(original_param, msg->param->packed);

			// do not mark own messages as being forwarded.
			// this allows sort of broadcasting
			// by just forwarding messages to other chats.
			if (msg->from_id!=DC_CONTACT_ID_SELF) {
				dc_param_set_int(msg->param, DC_PARAM_FORWARDED, 1);
			}

			dc_param_set(msg->param, DC_PARAM_GUARANTEE_E2EE, NULL);
			dc_param_set(msg->param, DC_PARAM_FORCE_PLAINTEXT, NULL);
			dc_param_set(msg->param, DC_PARAM_CMD, NULL);

			uint32_t new_msg_id;
			// PREPARING messages can't be forwarded immediately
			if (msg->state==DC_STATE_OUT_PREPARING) {
				new_msg_id = prepare_msg_raw(context, chat, msg, curr_timestamp++);

				// to update the original message, perform in-place surgery
				// on msg to avoid copying the entire structure, text, etc.
				dc_param_t* save_param = msg->param;
				msg->param = original_param;
				msg->id = src_msg_id;
				{
					// append new id to the original's param.
					char* old_fwd = dc_param_get(msg->param, DC_PARAM_PREP_FORWARDS, "");
					char* new_fwd = dc_mprintf("%s %d", old_fwd, new_msg_id);
					dc_param_set(msg->param, DC_PARAM_PREP_FORWARDS, new_fwd);
					dc_msg_save_param_to_disk(msg);
					free(new_fwd);
					free(old_fwd);
				}
				msg->param = save_param;
			}
			else {
				msg->state = DC_STATE_OUT_PENDING;
				new_msg_id = prepare_msg_raw(context, chat, msg, curr_timestamp++);
				dc_job_send_msg(context, new_msg_id);
			}

			carray_add(created_db_entries, (void*)(uintptr_t)chat_id, NULL);
			carray_add(created_db_entries, (void*)(uintptr_t)new_msg_id, NULL);
		}

	dc_sqlite3_commit(context->sql);
	transaction_pending = 0;

cleanup:
	if (transaction_pending) { dc_sqlite3_rollback(context->sql); }
	if (created_db_entries) {
		size_t i, icnt = carray_count(created_db_entries);
		for (i = 0; i < icnt; i += 2) {
			context->cb(context, DC_EVENT_MSGS_CHANGED, (uintptr_t)carray_get(created_db_entries, i), (uintptr_t)carray_get(created_db_entries, i+1));
		}
		carray_free(created_db_entries);
	}
	dc_contact_unref(contact);
	dc_msg_unref(msg);
	dc_chat_unref(chat);
	sqlite3_finalize(stmt);
	free(idsstr);
	sqlite3_free(q3);
	dc_param_unref(original_param);
}
