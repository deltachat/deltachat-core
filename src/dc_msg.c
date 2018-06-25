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


#include "dc_context.h"
#include "dc_imap.h"
#include "dc_smtp.h"
#include "dc_job.h"
#include "dc_pgp.h"
#include "dc_mimefactory.h"

#define DC_MSG_MAGIC 0x11561156


/**
 * Create new message object. Message objects are needed eg. for sending messages using
 * dc_send_msg().  Moreover, they are returned eg. from dc_get_msg(),
 * set up with the current state of a message. The message object is not updated;
 * to achieve this, you have to recreate it.
 *
 * @private @memberof dc_msg_t
 *
 * @return The created message object.
 */
dc_msg_t* dc_msg_new()
{
	dc_msg_t* ths = NULL;

	if( (ths=calloc(1, sizeof(dc_msg_t)))==NULL ) {
		exit(15); /* cannot allocate little memory, unrecoverable error */
	}

	ths->m_magic     = DC_MSG_MAGIC;
	ths->m_type      = DC_MSG_UNDEFINED;
	ths->m_state     = DC_STATE_UNDEFINED;
	ths->m_param     = dc_param_new();

	return ths;
}


/**
 * Free a message object. Message objects are created eg. by dc_get_msg().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object to free.
 *
 * @return None.
 */
void dc_msg_unref(dc_msg_t* msg)
{
	if( msg==NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return;
	}

	dc_msg_empty(msg);
	dc_param_unref(msg->m_param);
	msg->m_magic = 0;
	free(msg);
}


/**
 * Empty a message object.
 *
 * @private @memberof dc_msg_t
 *
 * @param msg The message object to empty.
 *
 * @return None.
 */
void dc_msg_empty(dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return;
	}

	free(msg->m_text);
	msg->m_text = NULL;

	free(msg->m_rfc724_mid);
	msg->m_rfc724_mid = NULL;

	free(msg->m_server_folder);
	msg->m_server_folder = NULL;

	dc_param_set_packed(msg->m_param, NULL);

	msg->m_context = NULL;

	msg->m_hidden = 0;
}


/*******************************************************************************
 * Getters
 ******************************************************************************/


/**
 * Get the ID of the message.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return the ID of the message, 0 on errors.
 */
uint32_t dc_msg_get_id(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return msg->m_id;
}


/**
 * Get the ID of contact who wrote the message.
 *
 * If the ID is equal to DC_CONTACT_ID_SELF (1), the message is an outgoing
 * message that is typically shown on the right side of the chat view.
 *
 * Otherwise, the message is an incoming message; to get details about the sender,
 * pass the returned ID to dc_get_contact().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return the ID of the contact who wrote the message, DC_CONTACT_ID_SELF (1)
 *     if this is an outgoing message, 0 on errors.
 */
uint32_t dc_msg_get_from_id(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return msg->m_from_id;
}


/**
 * Get the ID of chat the message belongs to.
 * To get details about the chat, pass the returned ID to dc_get_chat().
 * If a message is still in the deaddrop, the ID DC_CHAT_ID_DEADDROP is returned
 * although internally another ID is used.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return the ID of the chat the message belongs to, 0 on errors.
 */
uint32_t dc_msg_get_chat_id(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return msg->m_chat_blocked? DC_CHAT_ID_DEADDROP : msg->m_chat_id;
}


/**
 * Get the type of the message.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return One of DC_MSG_TEXT (10), DC_MSG_IMAGE (20), DC_MSG_GIF (21),
 *     DC_MSG_AUDIO (40), DC_MSG_VOICE (41), DC_MSG_VIDEO (50), DC_MSG_FILE (60)
 *     or DC_MSG_UNDEFINED (0) if the type is undefined.
 */
int dc_msg_get_type(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return DC_MSG_UNDEFINED;
	}
	return msg->m_type;
}


/**
 * Get the state of a message.
 *
 * Incoming message states:
 * - DC_STATE_IN_FRESH (10) - Incoming _fresh_ message. Fresh messages are not noticed nor seen and are typically shown in notifications. Use dc_get_fresh_msgs() to get all fresh messages.
 * - DC_STATE_IN_NOTICED (13) - Incoming _noticed_ message. Eg. chat opened but message not yet read - noticed messages are not counted as unread but did not marked as read nor resulted in MDNs. Use dc_marknoticed_chat() or dc_marknoticed_contact() to mark messages as being noticed.
 * - DC_STATE_IN_SEEN (16) - Incoming message, really _seen_ by the user. Marked as read on IMAP and MDN may be send. Use dc_markseen_msgs() to mark messages as being seen.
 *
 * Outgoing message states:
 * - DC_STATE_OUT_PENDING (20) - The user has send the "send" button but the
 *   message is not yet sent and is pending in some way. Maybe we're offline (no checkmark).
 * - DC_STATE_OUT_ERROR (24) - _Unrecoverable_ error (_recoverable_ errors result in pending messages)
 * - DC_STATE_OUT_DELIVERED (26) - Outgoing message successfully delivered to server (one checkmark). Note, that already delivered messages may get into the state DC_STATE_OUT_ERROR if we get such a hint from the server.
 *   If a sent message changes to this state, you'll receive the event #DC_EVENT_MSG_DELIVERED.
 * - DC_STATE_OUT_MDN_RCVD (28) - Outgoing message read by the recipient (two checkmarks; this requires goodwill on the receiver's side)
 *   If a sent message changes to this state, you'll receive the event #DC_EVENT_MSG_READ.
 *
 * If you just want to check if a message is sent or not, please use dc_msg_is_sent() which regards all states accordingly.
 *
 * The state of just created message objects is DC_STATE_UNDEFINED (0).
 * The state is always set by the core-library, users of the library cannot set the state directly, but it is changed implicitly eg.
 * when calling  dc_marknoticed_chat() or dc_markseen_msgs().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return The state of the message.
 */
int dc_msg_get_state(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return DC_STATE_UNDEFINED;
	}
	return msg->m_state;
}


/**
 * Get message sending time. The sending time is returned by a unix timestamp.
 * Note that the message list is not sorted by the _sending_ time but by the _receiving_ time.
 * Cave: the message list is sorted by receiving time (otherwise new messages would non pop up at the expected place),
 * however, if a message is delayed for any reason, the correct sending time will be displayed.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return The time of the message.
 */
time_t dc_msg_get_timestamp(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}

	return msg->m_timestamp_sent? msg->m_timestamp_sent : msg->m_timestamp;
}


/**
 * Get the text of the message.
 * If there is no text associalted with the message, an empty string is returned.
 * NULL is never returned.
 *
 * The returned text is plain text, HTML is stripped.
 * The returned text is truncated to a max. length of currently about 30000 characters,
 * it does not make sense to show more text in the message list and typical controls
 * will have problems with showing much more text.
 * This max. length is to avoid passing _lots_ of data to the frontend which may
 * result eg. from decoding errors (assume some bytes missing in a mime structure, forcing
 * an attachment to be plain text).
 *
 * To get information about the message and more/raw text, use dc_get_msg_info().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Message text. The result must be free()'d. Never returns NULL.
 */
char* dc_msg_get_text(const dc_msg_t* msg)
{
	char* ret;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return dc_strdup(NULL);
	}

	ret = dc_strdup(msg->m_text);
	dc_truncate_str(ret, DC_MAX_GET_TEXT_LEN); /* we do not do this on load: (1) for speed reasons (2) we may decide to process the full text on other places */
	return ret;
}


/**
 * Find out full path, file name and extension of the file associated with a
 * message.
 *
 * Typically files are associated with images, videos, audios, documents.
 * Plain text messages do not have a file.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Full path, file name and extension of the file associated with the
 *     message.  If there is no file associated with the message, an emtpy
 *     string is returned.  NULL is never returned and the returned value must be free()'d.
 */
char* dc_msg_get_file(const dc_msg_t* msg)
{
	char* ret = NULL;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	ret = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);

cleanup:
	return ret? ret : dc_strdup(NULL);
}


/**
 * Get base file name without path. The base file name includes the extension; the path
 * is not returned. To get the full path, use dc_msg_get_file().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Base file name plus extension without part.  If there is no file
 *     associated with the message, an empty string is returned.  The returned
 *     value must be free()'d.
 */
char* dc_msg_get_filename(const dc_msg_t* msg)
{
	char* ret = NULL, *pathNfilename = NULL;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	pathNfilename = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
	if( pathNfilename == NULL ) {
		goto cleanup;
	}

	ret = dc_get_filename(pathNfilename);

cleanup:
	free(pathNfilename);
	return ret? ret : dc_strdup(NULL);
}


/**
 * Get mime type of the file.  If there is not file, an empty string is returned.
 * If there is no associated mime type with the file, the function guesses on; if
 * in doubt, `application/octet-stream` is returned. NULL is never returned.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return String containing the mime type. Must be free()'d after usage. NULL is never returned.
 */
char* dc_msg_get_filemime(const dc_msg_t* msg)
{
	char* ret = NULL;
	char* file = NULL;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	ret = dc_param_get(msg->m_param, DC_PARAM_MIMETYPE, NULL);
	if( ret == NULL ) {
		file = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
		if( file == NULL ) {
			goto cleanup;
		}
		dc_msg_guess_msgtype_from_suffix(file, NULL, &ret);

		if( ret == NULL ) {
			ret = dc_strdup("application/octet-stream");
		}
	}

cleanup:
	free(file);
	return ret? ret : dc_strdup(NULL);
}


/**
 * Get the size of the file.  Returns the size of the file associated with a
 * message, if applicable.
 *
 * Typically, this is used to show the size of document messages, eg. a PDF.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return File size in bytes, 0 if not applicable or on errors.
 */
uint64_t dc_msg_get_filebytes(const dc_msg_t* msg)
{
	uint64_t ret = 0;
	char*    file = NULL;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	file = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
	if( file == NULL ) {
		goto cleanup;
	}

	ret = dc_get_filebytes(file);

cleanup:
	free(file);
	return ret;
}


/**
 * Get real author and title.
 *
 * The information is returned by a dc_lot_t object with the following fields:
 *
 * - dc_lot_t::m_text1: Author of the media.  For voice messages, this is the sender.
 *   For music messages, the information are read from the filename. NULL if unknown.
 *
 * - dc_lot_t::m_text2: Title of the media.  For voice messages, this is the date.
 *   For music messages, the information are read from the filename. NULL if unknown.
 *
 * Currently, we do not read ID3 and such at this stage, the needed libraries are too complicated and oversized.
 * However, this is no big problem, as the sender usually sets the filename in a way we expect it.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Media information as an dc_lot_t object. Must be freed using dc_lot_unref().  NULL is never returned.
 */
dc_lot_t* dc_msg_get_mediainfo(const dc_msg_t* msg)
{
	dc_lot_t*   ret = dc_lot_new();
	char*        pathNfilename = NULL;
	dc_contact_t* contact = NULL;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC || msg->m_context == NULL ) {
		goto cleanup;
	}

	if( msg->m_type == DC_MSG_VOICE )
	{
		if( (contact = dc_get_contact(msg->m_context, msg->m_from_id))==NULL ) {
			goto cleanup;
		}
		ret->m_text1 = dc_strdup((contact->m_name&&contact->m_name[0])? contact->m_name : contact->m_addr);
		ret->m_text2 = dc_stock_str(DC_STR_VOICEMESSAGE);
	}
	else
	{
		ret->m_text1 = dc_param_get(msg->m_param, DC_PARAM_AUTHORNAME, NULL);
		ret->m_text2 = dc_param_get(msg->m_param, DC_PARAM_TRACKNAME, NULL);
		if( ret->m_text1 && ret->m_text1[0] && ret->m_text2 && ret->m_text2[0] ) {
			goto cleanup;
		}
		free(ret->m_text1); ret->m_text1 = NULL;
		free(ret->m_text2); ret->m_text2 = NULL;

		pathNfilename = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
		if( pathNfilename == NULL ) {
			goto cleanup;
		}
		dc_msg_get_authorNtitle_from_filename(pathNfilename, &ret->m_text1, &ret->m_text2);
		if( ret->m_text1 == NULL && ret->m_text2 != NULL ) {
			ret->m_text1 = dc_stock_str(DC_STR_AUDIO);
		}
	}

cleanup:
	free(pathNfilename);
	dc_contact_unref(contact);
	return ret;
}


/**
 * Get width of image or video.  The width is returned in pixels.
 * If the width is unknown or if the associated file is no image or video file,
 * 0 is returned.
 *
 * Often the ascpect ratio is the more interesting thing. You can calculate
 * this using dc_msg_get_width() / dc_msg_get_height().
 *
 * See also dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Width in pixels, if applicable. 0 otherwise or if unknown.
 */
int dc_msg_get_width(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return dc_param_get_int(msg->m_param, DC_PARAM_WIDTH, 0);
}


/**
 * Get height of image or video.  The height is returned in pixels.
 * If the height is unknown or if the associated file is no image or video file,
 * 0 is returned.
 *
 * Often the ascpect ratio is the more interesting thing. You can calculate
 * this using dc_msg_get_width() / dc_msg_get_height().
 *
 * See also dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Height in pixels, if applicable. 0 otherwise or if unknown.
 */
int dc_msg_get_height(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return dc_param_get_int(msg->m_param, DC_PARAM_HEIGHT, 0);
}


/**
 * Get duration of audio or video.  The duration is returned in milliseconds (ms).
 * If the duration is unknown or if the associated file is no audio or video file,
 * 0 is returned.
 *
 * See also dc_msg_get_width() and dc_msg_get_height().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Duration in milliseconds, if applicable. 0 otherwise or if unknown.
 */
int dc_msg_get_duration(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return dc_param_get_int(msg->m_param, DC_PARAM_DURATION, 0);
}


/**
 * Check if a padlock should be shown beside the message.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=padlock should be shown beside message, 0=do not show a padlock beside the message.
 */
int dc_msg_get_showpadlock(const dc_msg_t* msg)
{
	/* a padlock guarantees that the message is e2ee _and_ answers will be as well */
	int show_encryption_state = 0;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC || msg->m_context == NULL ) {
		return 0;
	}

	if( msg->m_context->m_e2ee_enabled ) {
		show_encryption_state = 1;
	}
	else {
		dc_chat_t* chat = dc_get_chat(msg->m_context, msg->m_chat_id);
		show_encryption_state = dc_chat_is_verified(chat);
		dc_chat_unref(chat);
	}

	if( show_encryption_state ) {
		if( dc_param_get_int(msg->m_param, DC_PARAM_GUARANTEE_E2EE, 0) != 0 ) {
			return 1;
		}
	}

	return 0;
}


/**
 * Get a summary for a message.
 *
 * The summary is returned by a dc_lot_t object with the following fields:
 *
 * - dc_lot_t::m_text1: contains the username or the string "Me".
 *   The string may be colored by having a look at m_text1_meaning.
 *   If the name should not be displayed, the element is NULL.
 *
 * - dc_lot_t::m_text1_meaning: one of DC_TEXT1_USERNAME or DC_TEXT1_SELF.
 *   Typically used to show dc_lot_t::m_text1 with different colors. 0 if not applicable.
 *
 * - dc_lot_t::m_text2: contains an excerpt of the message text.
 *
 * - dc_lot_t::m_timestamp: the timestamp of the message.
 *
 * - dc_lot_t::m_state: The state of the message as one of the DC_STATE_* constants (see #dc_msg_get_state()).
 *
 * Typically used to display a search result. See also dc_chatlist_get_summary() to display a list of chats.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @param chat To speed up things, pass an already available chat object here.
 *     If the chat object is not yet available, it is faster to pass NULL.
 *
 * @return The summary as an dc_lot_t object. Must be freed using dc_lot_unref().  NULL is never returned.
 */
dc_lot_t* dc_msg_get_summary(const dc_msg_t* msg, const dc_chat_t* chat)
{
	dc_lot_t*      ret = dc_lot_new();
	dc_contact_t*  contact = NULL;
	dc_chat_t*     chat_to_delete = NULL;

	if( msg==NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	if( chat == NULL ) {
		if( (chat_to_delete=dc_get_chat(msg->m_context, msg->m_chat_id)) == NULL ) {
			goto cleanup;
		}
		chat = chat_to_delete;
	}

	if( msg->m_from_id != DC_CONTACT_ID_SELF && DC_CHAT_TYPE_IS_MULTI(chat->m_type) ) {
		contact = dc_get_contact(chat->m_context, msg->m_from_id);
	}

	dc_lot_fill(ret, msg, chat, contact);

cleanup:
	dc_contact_unref(contact);
	dc_chat_unref(chat_to_delete);
	return ret;
}


/**
 * Get a message summary as a single line of text.  Typically used for
 * notifications.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @param approx_characters Rough length of the expected string.
 *
 * @return A summary for the given messages. The returned string must be free()'d.
 *     Returns an empty string on errors, never returns NULL.
 */
char* dc_msg_get_summarytext(const dc_msg_t* msg, int approx_characters)
{
	if( msg==NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return dc_strdup(NULL);
	}

	return dc_msg_get_summarytext_by_raw(msg->m_type, msg->m_text, msg->m_param, approx_characters);
}


/**
 * Check if a message was sent successfully.
 *
 * Currently, "sent" messages are messages that are in the state "delivered" or "mdn received",
 * see dc_msg_get_state().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=message sent successfully, 0=message not yet sent or message is an incoming message.
 */
int dc_msg_is_sent(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return (msg->m_state >= DC_STATE_OUT_DELIVERED)? 1 : 0;
}


/**
 * Check if a message is starred.  Starred messages are "favorites" marked by the user
 * with a "star" or something like that.  Starred messages can typically be shown
 * easily and are not deleted automatically.
 *
 * To star one or more messages, use dc_star_msgs(), to get a list of starred messages,
 * use dc_get_chat_msgs() using DC_CHAT_ID_STARRED as the chat_id.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=message is starred, 0=message not starred.
 */
int dc_msg_is_starred(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return msg->m_starred? 1 : 0;
}


/**
 * Check if the message is a forwarded message.
 *
 * Forwarded messages may not be created by the contact given as "from".
 *
 * Typically, the UI shows a little text for a symbol above forwarded messages.
 *
 * For privacy reasons, we do not provide the name or the email address of the
 * original author (in a typical GUI, you select the messages text and click on
 * "forwared"; you won't expect other data to be send to the new recipient,
 * esp. as the new recipient may not be in any relationship to the original author)
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=message is a forwarded message, 0=message not forwarded.
 */
int dc_msg_is_forwarded(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}
	return dc_param_get_int(msg->m_param, DC_PARAM_FORWARDED, 0)? 1 : 0;
}


/**
 * Check if the message is an informational message, created by the
 * device or by another users. Such messages are not "typed" by the user but
 * created due to other actions, eg. dc_set_chat_name(), dc_set_chat_profile_image()
 * or dc_add_contact_to_chat().
 *
 * These messages are typically shown in the center of the chat view,
 * dc_msg_get_text() returns a descriptive text about what is going on.
 *
 * There is no need to perfrom any action when seeing such a message - this is already done by the core.
 * Typically, these messages are displayed in the center of the chat.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=message is a system command, 0=normal message
 */
int dc_msg_is_info(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}

	int cmd = dc_param_get_int(msg->m_param, DC_PARAM_CMD, 0);

	if( msg->m_from_id == DC_CONTACT_ID_DEVICE
	 || msg->m_to_id == DC_CONTACT_ID_DEVICE
	 || (cmd && cmd != DC_CMD_AUTOCRYPT_SETUP_MESSAGE) ) {
		return 1;
	}

	return 0;
}


/**
 * Check if the message is an Autocrypt Setup Message.
 *
 * Setup messages should be shown in an unique way eg. using a different text color.
 * On a click or another action, the user should be prompted for the setup code
 * which is forwarded to dc_continue_key_transfer() then.
 *
 * Setup message are typically generated by dc_initiate_key_transfer() on another device.
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return 1=message is a setup message, 0=no setup message.
 *     For setup messages, dc_msg_get_type() returns DC_MSG_FILE.
 */
int dc_msg_is_setupmessage(const dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC || msg->m_type != DC_MSG_FILE ) {
		return 0;
	}

	return dc_param_get_int(msg->m_param, DC_PARAM_CMD, 0)==DC_CMD_AUTOCRYPT_SETUP_MESSAGE? 1 : 0;
}


/**
 * Get the first characters of the setup code.
 *
 * Typically, this is used to pre-fill the first entry field of the setup code.
 * If the user has several setup messages, he can be sure typing in the correct digits.
 *
 * To check, if a message is a setup message, use dc_msg_is_setupmessage().
 * To decrypt a secret key from a setup message, use dc_continue_key_transfer().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @return Typically, the first two digits of the setup code or an empty string if unknown.
 *     NULL is never returned. Must be free()'d when done.
 */
char* dc_msg_get_setupcodebegin(const dc_msg_t* msg)
{
	char*        filename = NULL;
	char*        buf = NULL;
	size_t       buf_bytes = 0;
	const char*  buf_headerline = NULL; // just a pointer inside buf, MUST NOT be free()'d
	const char*  buf_setupcodebegin = NULL; // just a pointer inside buf, MUST NOT be free()'d
	char*        ret = NULL;

	if( !dc_msg_is_setupmessage(msg) ) {
		goto cleanup;
	}

	if( (filename=dc_msg_get_file(msg))==NULL || filename[0]==0 ) {
		goto cleanup;
	}

	if( !dc_read_file(filename, (void**)&buf, &buf_bytes, msg->m_context) || buf == NULL || buf_bytes <= 0 ) {
		goto cleanup;
	}

	if( !dc_split_armored_data(buf, &buf_headerline, &buf_setupcodebegin, NULL, NULL)
	 || strcmp(buf_headerline, "-----BEGIN PGP MESSAGE-----")!=0 || buf_setupcodebegin==NULL ) {
		goto cleanup;
	}

	ret = dc_strdup(buf_setupcodebegin); /* we need to make a copy as buf_setupcodebegin just points inside buf (which will be free()'d on cleanup) */

cleanup:
	free(filename);
	free(buf);
	return ret? ret : dc_strdup(NULL);
}


/*******************************************************************************
 * Misc.
 ******************************************************************************/


#define DC_MSG_FIELDS " m.id,rfc724_mid,m.server_folder,m.server_uid,m.chat_id, " \
                      " m.from_id,m.to_id,m.timestamp,m.timestamp_sent,m.timestamp_rcvd, m.type,m.state,m.msgrmsg,m.txt, " \
                      " m.param,m.starred,m.hidden,c.blocked "


static int dc_msg_set_from_stmt__(dc_msg_t* ths, sqlite3_stmt* row, int row_offset) /* field order must be DC_MSG_FIELDS */
{
	dc_msg_empty(ths);

	ths->m_id           =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_rfc724_mid   =  dc_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_server_folder=  dc_strdup((char*)sqlite3_column_text (row, row_offset++));
	ths->m_server_uid   =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_chat_id      =           (uint32_t)sqlite3_column_int  (row, row_offset++);

	ths->m_from_id      =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_to_id        =           (uint32_t)sqlite3_column_int  (row, row_offset++);
	ths->m_timestamp    =             (time_t)sqlite3_column_int64(row, row_offset++);
	ths->m_timestamp_sent =           (time_t)sqlite3_column_int64(row, row_offset++);
	ths->m_timestamp_rcvd =           (time_t)sqlite3_column_int64(row, row_offset++);

	ths->m_type         =                     sqlite3_column_int  (row, row_offset++);
	ths->m_state        =                     sqlite3_column_int  (row, row_offset++);
	ths->m_is_msgrmsg   =                     sqlite3_column_int  (row, row_offset++);
	ths->m_text         =  dc_strdup((char*)sqlite3_column_text (row, row_offset++));

	dc_param_set_packed(  ths->m_param, (char*)sqlite3_column_text (row, row_offset++));
	ths->m_starred      =                     sqlite3_column_int  (row, row_offset++);
	ths->m_hidden       =                     sqlite3_column_int  (row, row_offset++);
	ths->m_chat_blocked =                     sqlite3_column_int  (row, row_offset++);

	if( ths->m_chat_blocked == 2 ) {
		dc_truncate_n_unwrap_str(ths->m_text, 256 /* 256 characters is about a half screen on a 5" smartphone display */,
			0/*unwrap*/);
	}

	return 1;
}


/**
 * Library-internal.
 *
 * Calling this function is not thread-safe, locking is up to the caller.
 *
 * @private @memberof dc_msg_t
 */
int dc_msg_load_from_db__(dc_msg_t* ths, dc_context_t* mailbox, uint32_t id)
{
	sqlite3_stmt* stmt;

	if( ths==NULL || ths->m_magic != DC_MSG_MAGIC || mailbox==NULL || mailbox->m_sql==NULL ) {
		return 0;
	}

	stmt = dc_sqlite3_predefine__(mailbox->m_sql, SELECT_ircftttstpb_FROM_msg_WHERE_i,
		"SELECT " DC_MSG_FIELDS
		" FROM msgs m LEFT JOIN chats c ON c.id=m.chat_id"
		" WHERE m.id=?;");
	sqlite3_bind_int(stmt, 1, id);

	if( sqlite3_step(stmt) != SQLITE_ROW ) {
		return 0;
	}

	if( !dc_msg_set_from_stmt__(ths, stmt, 0) ) { /* also calls dc_msg_empty() */
		return 0;
	}

	ths->m_context = mailbox;

	return 1;
}


/**
 * Guess message type from suffix.
 *
 * @private @memberof dc_msg_t
 *
 * @param pathNfilename Path and filename of the file to guess the type for.
 *
 * @param[out] ret_msgtype Guessed message type is copied here as one of the DC_MSG_* constants.
 *     May be NULL if you're not interested in this value.
 *
 * @param[out] ret_mime The pointer to a string buffer is set to the guessed MIME-type. May be NULL. Must be free()'d by the caller.
 *
 * @return None. But there are output parameters.
 */
void dc_msg_guess_msgtype_from_suffix(const char* pathNfilename, int* ret_msgtype, char** ret_mime)
{
	char* suffix = NULL;
	int   dummy_msgtype = 0;
	char* dummy_buf = NULL;

	if( pathNfilename == NULL ) {
		goto cleanup;
	}

	if( ret_msgtype == NULL ) { ret_msgtype = &dummy_msgtype; }
	if( ret_mime == NULL )    { ret_mime = &dummy_buf; }

	*ret_msgtype = DC_MSG_UNDEFINED;
	*ret_mime = NULL;

	suffix = dc_get_filesuffix_lc(pathNfilename);
	if( suffix == NULL ) {
		goto cleanup;
	}

	if( strcmp(suffix, "mp3")==0 ) {
		*ret_msgtype = DC_MSG_AUDIO;
		*ret_mime = dc_strdup("audio/mpeg");
	}
	else if( strcmp(suffix, "mp4")==0 ) {
		*ret_msgtype = DC_MSG_VIDEO;
		*ret_mime = dc_strdup("video/mp4");
	}
	else if( strcmp(suffix, "jpg")==0 || strcmp(suffix, "jpeg")==0 ) {
		*ret_msgtype = DC_MSG_IMAGE;
		*ret_mime = dc_strdup("image/jpeg");
	}
	else if( strcmp(suffix, "png")==0 ) {
		*ret_msgtype = DC_MSG_IMAGE;
		*ret_mime = dc_strdup("image/png");
	}
	else if( strcmp(suffix, "gif")==0 ) {
		*ret_msgtype = DC_MSG_GIF;
		*ret_mime = dc_strdup("image/gif");
	}

cleanup:
	free(suffix);
	free(dummy_buf);
}


void dc_msg_get_authorNtitle_from_filename(const char* pathNfilename, char** ret_author, char** ret_title)
{
	/* function extracts AUTHOR and TITLE from a path given as `/path/other folder/AUTHOR - TITLE.mp3`
	if the mark ` - ` is not preset, the whole name (without suffix) is used as the title and the author is NULL. */
	char *author = NULL, *title = NULL, *p;
	dc_split_filename(pathNfilename, &title, NULL);
	p = strstr(title, " - ");
	if( p ) {
		*p = 0;
		author = title;
		title  = dc_strdup(&p[3]);
	}

	if( ret_author ) { *ret_author = author; } else { free(author); }
	if( ret_title  ) { *ret_title  = title;  } else { free(title);  }
}


char* dc_msg_get_summarytext_by_raw(int type, const char* text, dc_param_t* param, int approx_characters)
{
	/* get a summary text, result must be free()'d, never returns NULL. */
	char* ret = NULL;
	char* pathNfilename = NULL, *label = NULL, *value = NULL;

	switch( type ) {
		case DC_MSG_IMAGE:
			ret = dc_stock_str(DC_STR_IMAGE);
			break;

		case DC_MSG_GIF:
			ret = dc_stock_str(DC_STR_GIF);
			break;

		case DC_MSG_VIDEO:
			ret = dc_stock_str(DC_STR_VIDEO);
			break;

		case DC_MSG_VOICE:
			ret = dc_stock_str(DC_STR_VOICEMESSAGE);
			break;

		case DC_MSG_AUDIO:
			if( (value=dc_param_get(param, DC_PARAM_TRACKNAME, NULL))==NULL ) { /* although we send files with "author - title" in the filename, existing files may follow other conventions, so this lookup is neccessary */
				pathNfilename = dc_param_get(param, DC_PARAM_FILE, "ErrFilename");
				dc_msg_get_authorNtitle_from_filename(pathNfilename, NULL, &value);
			}
			label = dc_stock_str(DC_STR_AUDIO);
			ret = dc_mprintf("%s: %s", label, value);
			break;

		case DC_MSG_FILE:
			if( dc_param_get_int(param, DC_PARAM_CMD, 0)==DC_CMD_AUTOCRYPT_SETUP_MESSAGE ) {
				ret = dc_stock_str(DC_STR_AC_SETUP_MSG_SUBJECT);
			}
			else {
				pathNfilename = dc_param_get(param, DC_PARAM_FILE, "ErrFilename");
				value = dc_get_filename(pathNfilename);
				label = dc_stock_str(DC_STR_FILE);
				ret = dc_mprintf("%s: %s", label, value);
			}
			break;

		default:
			if( text ) {
				ret = dc_strdup(text);
				dc_truncate_n_unwrap_str(ret, approx_characters, 1/*unwrap*/);
			}
			break;
	}

	/* cleanup */
	free(pathNfilename);
	free(label);
	free(value);
	if( ret == NULL ) {
		ret = dc_strdup(NULL);
	}
	return ret;
}


int dc_msg_is_increation__(const dc_msg_t* msg)
{
	int is_increation = 0;
	if( DC_MSG_NEEDS_ATTACHMENT(msg->m_type) )
	{
		char* pathNfilename = dc_param_get(msg->m_param, DC_PARAM_FILE, NULL);
		if( pathNfilename ) {
			char* totest = dc_mprintf("%s.increation", pathNfilename);
			if( dc_file_exist(totest) ) {
				is_increation = 1;
			}
			free(totest);
			free(pathNfilename);
		}
	}
	return is_increation;
}


/**
 * Check if a message is still in creation.  The user can mark files as being
 * in creation by simply creating a file `<filename>.increation`. If
 * `<filename>` is created then, the user should just delete
 * `<filename>.increation`.
 *
 * Typically, this is used for videos that should be recoded by the user before
 * they can be sent.
 *
 * @memberof dc_msg_t
 *
 * @param msg the message object
 *
 * @return 1=message is still in creation (`<filename>.increation` exists),
 *     0=message no longer in creation
 */
int dc_msg_is_increation(const dc_msg_t* msg)
{
	/* surrounds dc_msg_is_increation__() with locking and error checking */
	int is_increation = 0;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		return 0;
	}

	if( msg->m_context && DC_MSG_NEEDS_ATTACHMENT(msg->m_type) /*additional check for speed reasons*/ )
	{
		dc_sqlite3_lock(msg->m_context->m_sql);

			is_increation = dc_msg_is_increation__(msg);

		dc_sqlite3_unlock(msg->m_context->m_sql);
	}

	return is_increation;
}


void dc_msg_save_param_to_disk__(dc_msg_t* msg)
{
	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC || msg->m_context == NULL || msg->m_context->m_sql == NULL ) {
		return;
	}

	sqlite3_stmt* stmt = dc_sqlite3_predefine__(msg->m_context->m_sql, UPDATE_msgs_SET_param_WHERE_id,
		"UPDATE msgs SET param=? WHERE id=?;");
	sqlite3_bind_text(stmt, 1, msg->m_param->m_packed, -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 2, msg->m_id);
	sqlite3_step(stmt);
}


/**
 * Late filing information to a message.
 *
 * Sometimes, the core cannot find out the width, the height or the duration
 * of an image, an audio or a video.
 *
 * If, in these cases, the frontend can provide the information, it can save
 * them together with the message object for later usage.
 *
 * This function should only be used if dc_msg_get_width(), dc_msg_get_height() or dc_msg_get_duration()
 * do not provide the expected values.
 *
 * To get the stored values later, use dc_msg_get_width(), dc_msg_get_height() or dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 *
 * @param msg The message object.
 *
 * @param width The new width to store in the message object. 0 if you do not want to change it.
 *
 * @param height The new height to store in the message object. 0 if you do not want to change it.
 *
 * @param duration The new duration to store in the message object. 0 if you do not want to change it.
 *
 * @return None.
 */
void dc_msg_latefiling_mediasize(dc_msg_t* msg, int width, int height, int duration)
{
	int locked = 0;

	if( msg == NULL || msg->m_magic != DC_MSG_MAGIC ) {
		goto cleanup;
	}

	dc_sqlite3_lock(msg->m_context->m_sql);
	locked = 1;

		if( width > 0 ) {
			dc_param_set_int(msg->m_param, DC_PARAM_WIDTH, width);
		}

		if( height > 0 ) {
			dc_param_set_int(msg->m_param, DC_PARAM_HEIGHT, height);
		}

		if( duration > 0 ) {
			dc_param_set_int(msg->m_param, DC_PARAM_DURATION, duration);
		}

		dc_msg_save_param_to_disk__(msg);

	dc_sqlite3_unlock(msg->m_context->m_sql);
	locked = 0;

cleanup:
	if( locked ) { dc_sqlite3_unlock(msg->m_context->m_sql); }
}
