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


#ifndef __MRMIMEFACTORY_H__
#define __MRMIMEFACTORY_H__
#ifdef __cplusplus
extern "C" {
#endif



#define MR_CMD_GROUPNAME_CHANGED           2
#define MR_CMD_GROUPIMAGE_CHANGED          3
#define MR_CMD_MEMBER_ADDED_TO_GROUP       4
#define MR_CMD_MEMBER_REMOVED_FROM_GROUP   5
#define MR_CMD_AUTOCRYPT_SETUP_MESSAGE     6
#define MR_CMD_SECUREJOIN_MESSAGE          7


typedef enum {
	MR_MF_NOTHING_LOADED = 0,
	MR_MF_MSG_LOADED,
	MR_MF_MDN_LOADED
} dc_mimefactory_loaded_t;


/**
 * Library-internal.
 */
typedef struct dc_mimefactory_t {

	/** @privatesection */

	/* in: parameters, set eg. by dc_mimefactory_load_msg() */
	char*        m_from_addr;
	char*        m_from_displayname;
	char*        m_selfstatus;
	clist*       m_recipients_names;
	clist*       m_recipients_addr;
	time_t       m_timestamp;
	char*        m_rfc724_mid;

	/* what is loaded? */
	dc_mimefactory_loaded_t m_loaded;

	dc_msg_t*     m_msg;
	dc_chat_t*    m_chat;
	int          m_increation;
	char*        m_predecessor;
	char*        m_references;
	int          m_req_mdn;

	/* out: after a successfull dc_mimefactory_render(), here's the data */
	MMAPString*  m_out;
	int          m_out_encrypted;

	/* private */
	mrmailbox_t* m_mailbox;

} dc_mimefactory_t;


void        dc_mimefactory_init              (dc_mimefactory_t*, mrmailbox_t*);
void        dc_mimefactory_empty             (dc_mimefactory_t*);
int         dc_mimefactory_load_msg          (dc_mimefactory_t*, uint32_t msg_id);
int         dc_mimefactory_load_mdn          (dc_mimefactory_t*, uint32_t msg_id);
int         dc_mimefactory_render            (dc_mimefactory_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRMIMEFACTORY_H__ */

