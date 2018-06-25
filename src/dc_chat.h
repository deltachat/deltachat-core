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


#ifndef __DC_CHAT_H__
#define __DC_CHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


/* values for the chats.blocked database field */
#define         DC_CHAT_NOT_BLOCKED       0
#define         DC_CHAT_MANUALLY_BLOCKED  1
#define         DC_CHAT_DEADDROP_BLOCKED  2


/** the structure behind dc_chat_t */
struct _dc_chat
{
	/** @privatesection */
	uint32_t        m_magic;
	uint32_t        m_id;
	int             m_type;             /**< Chat type. Use dc_chat_get_type() to access this field. */
	char*           m_name;             /**< Name of the chat. Use dc_chat_get_name() to access this field. NULL if unset. */
	char*           m_draft_text;	    /**< Draft text. NULL if there is no draft. */
	time_t          m_draft_timestamp;  /**< Timestamp of the draft. 0 if there is no draft. */
	int             m_archived;         /**< Archived state. Better use dc_chat_get_archived() to access this object. */
	dc_context_t*   m_context;          /**< The mailbox object the chat belongs to. */
	char*           m_grpid;            /**< Group ID that is used by all clients. Only used if the chat is a group. NULL if unset */
	int             m_blocked;          /**< One of DC_CHAT_*_BLOCKED */
	dc_param_t*     m_param;            /**< Additional parameters for a chat. Should not be used directly. */
};


int             dc_chat_load_from_db__             (dc_chat_t*, uint32_t id);
int             dc_chat_update_param__             (dc_chat_t*);
int             dc_chat_are_all_members_verified__ (dc_chat_t*);


#define         DC_CHAT_TYPE_IS_MULTI(a)   ((a)==DC_CHAT_TYPE_GROUP || (a)==DC_CHAT_TYPE_VERIFIED_GROUP)
#define         DC_CHAT_TYPE_CAN_SEND(a)   ((a)==DC_CHAT_TYPE_SINGLE || (a)==DC_CHAT_TYPE_GROUP || (a)==DC_CHAT_TYPE_VERIFIED_GROUP)


#define         DC_CHAT_PREFIX              "Chat:"      /* you MUST NOT modify this or the following strings */
#define         DC_CHATS_FOLDER             "DeltaChat"  // make sure not to use reserved words here, eg. "Chats" or "Chat" are reserved in gmail


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_CHAT_H__ */
