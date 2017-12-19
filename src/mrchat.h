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


#ifndef __MRCHAT_H__
#define __MRCHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


typedef struct mrmailbox_t mrmailbox_t;
typedef struct mrparam_t   mrparam_t;


/**
 * An object representing a single chat in memory. Chat objects are created using eg. mrmailbox_get_chat() and
 * are not updated on database changes;  if you want an update, you have to recreate the
 * object.
 */
typedef struct mrchat_t
{
	uint32_t        m_magic;            /**< @private */

	/**
	 * Chat ID under which the chat is filed in the database.
	 *
	 * Special IDs:
	 * - MR_CHAT_ID_DEADDROP         (1) - Messages send from unknown/unwanted users to us, chats_contacts is not set up. This group may be shown normally.
	 * - MR_CHAT_ID_STARRED          (5) - Virtual chat containing all starred messages-
	 * - MR_CHAT_ID_ARCHIVED_LINK    (6) - A link at the end of the chatlist, if present the UI should show the button "Archived chats"-
	 *
	 * "Normal" chat IDs are larger than these special IDs (larger than MR_CHAT_ID_LAST_SPECIAL).
	 */
	uint32_t        m_id;
	#define         MR_CHAT_ID_DEADDROP         1
	#define         MR_CHAT_ID_TO_DEADDROP      2 /* messages send from us to unknown/unwanted users (this may happen when deleting chats or when using CC: in the email-program) */
	#define         MR_CHAT_ID_TRASH            3 /* messages that should be deleted get this chat_id; the messages are deleted from the working thread later then. This is also needed as rfc724_mid should be preset as long as the message is not deleted on the server (otherwise it is downloaded again) */
	#define         MR_CHAT_ID_MSGS_IN_CREATION 4 /* a message is just in creation but not yet assigned to a chat (eg. we may need the message ID to set up blobs; this avoids unready message to be send and shown) */
	#define         MR_CHAT_ID_STARRED          5
	#define         MR_CHAT_ID_ARCHIVED_LINK    6
	#define         MR_CHAT_ID_LAST_SPECIAL     9 /* larger chat IDs are "real" chats, their messages are "real" messages. */


	/** @privatesection */
	int             m_type;             /**< Chat type. Use mrchat_get_type() to access this field. */
	#define         MR_CHAT_TYPE_UNDEFINED      0
	#define         MR_CHAT_TYPE_NORMAL       100
	#define         MR_CHAT_TYPE_GROUP        120

	char*           m_name;             /**< Name of the chat. Use mrchat_get_name() to access this field. NULL if unset. */
	char*           m_draft_text;	    /**< Draft text. NULL if there is no draft. */
	time_t          m_draft_timestamp;  /**< Timestamp of the draft. 0 if there is no draft. */
	int             m_archived;         /**< Archived state. Better use mrchat_get_archived() to access this object. */
	mrmailbox_t*    m_mailbox;          /**< The mailbox object the chat belongs to. */
	char*           m_grpid;            /**< Group ID that is used by all clients. Only used if the chat is a group. NULL if unset */
	mrparam_t*      m_param;            /**< Additional parameters for a chat. Should not be used directly. */
} mrchat_t;


mrchat_t*       mrchat_new                  (mrmailbox_t*);
void            mrchat_empty                (mrchat_t*);
void            mrchat_unref                (mrchat_t*);

int             mrchat_get_type             (mrchat_t*);
char*           mrchat_get_name             (mrchat_t*);
char*           mrchat_get_subtitle         (mrchat_t*);
char*           mrchat_get_profile_image    (mrchat_t*);
char*           mrchat_get_draft            (mrchat_t*);
int             mrchat_get_archived         (mrchat_t*);
int             mrchat_is_unpromoted        (mrchat_t*);
int             mrchat_is_self_talk         (mrchat_t*);

/* library-internal */
int             mrchat_load_from_db__       (mrchat_t*, uint32_t id);
int             mrchat_update_param__       (mrchat_t*);

#define         MR_CHAT_PREFIX              "Chat:"      /* you MUST NOT modify this or the following strings */
#define         MR_CHATS_FOLDER             "Chats"      /* if we want to support Gma'l-labels - "Chats" is a reserved word for Gma'l */


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCHAT_H__ */