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


#ifndef __MRLOT_H__
#define __MRLOT_H__
#ifdef __cplusplus
extern "C" {
#endif


/**
 * An object containing a set of values.  The meaning of the values is defined by the function returning the set object.
 * Set objects are created eg. by mrchatlist_get_summary(), mrmsg_get_summary() or by mrmsg_get_mediainfo().
 *
 * NB: _Lot_ is used in the meaning _heap_ here.
 */
typedef struct mrlot_t
{
	uint32_t        m_magic;           /**< @private */
	int             m_text1_meaning;   /**< The meaning of this value is defined by the creator of the object. 0 if not applicable. */
	char*           m_text1;           /**< The meaning of this string is defined by the creator of the object. The string is freed with mrlot_unref(). NULL if not applicable. */
	char*           m_text2;           /**< The meaning of this string is defined by the creator of the object. The string is freed with mrlot_unref(). NULL if not applicable. */
	time_t          m_timestamp;       /**< The meaning of this value is defined by the creator of the object. 0 if not applicable. */
	int             m_state;           /**< The meaning of this value is defined by the creator of the object. 0 if not applicable. */
} mrlot_t;


#define         MR_TEXT1_DRAFT     1
#define         MR_TEXT1_USERNAME  2
#define         MR_TEXT1_SELF      3


mrlot_t*        mrlot_new     ();
void            mrlot_empty   (mrlot_t*);
void            mrlot_unref   (mrlot_t*);


/* library-internal */
#define MR_SUMMARY_CHARACTERS 160 /* in practice, the user additionally cuts the string himself pixel-accurate */
void            mrlot_fill      (mrlot_t*, const mrmsg_t*, const mrchat_t*, const mrcontact_t*);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRLOT_H__ */
