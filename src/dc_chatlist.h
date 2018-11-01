/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

#ifndef __DC_CHATLIST_H__
#define __DC_CHATLIST_H__
#ifdef __cplusplus
extern "C" {
#endif


/** the structure behind dc_chatlist_t */
struct _dc_chatlist
{
	/** @privatesection */
	uint32_t        magic;
	dc_context_t*   context; /**< The context, the chatlist belongs to */
	#define         DC_CHATLIST_IDS_PER_RESULT 2
	size_t          cnt;
	dc_array_t*     chatNlastmsg_ids;
};


// Context functions to work with chatlist
int             dc_get_archived_cnt        (dc_context_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_CHATLIST_H__ */
