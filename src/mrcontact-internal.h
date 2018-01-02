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


#ifndef __MRCONTACT_INTERNAL_H__
#define __MRCONTACT_INTERNAL_H__
#ifdef __cplusplus
extern "C" {
#endif


/** the structure behind mrcontact_t */
struct _mrcontact
{
	/** @privatesection */

	uint32_t        m_magic;

	/**
	 * The contact ID.
	 *
	 * Special message IDs:
	 * - MR_CONTACT_ID_SELF (1) - this is the owner of the mailbox with the email-address set by mrmailbox_set_config() using "addr".
	 *
	 * Normal contact IDs are larger than these special ones (larger than MR_CONTACT_ID_LAST_SPECIAL).
	 */
	uint32_t        m_id;
	char*           m_name;     /**< Contact name.  It is recommended to use mrcontact_get_name(), mrcontact_get_display_name() or mrcontact_get_name_n_addr() to access this field. May be NULL or empty, initially set to #m_authname. */
	char*           m_authname; /**< Name authorized by the contact himself. Only this name may be speaded to others, eg. in To:-lists. May be NULL or empty. It is recommended to use mrcontact_get_name(),  mrcontact_get_display_name() or mrcontact_get_name_n_addr() to access this field. */
	char*           m_addr;     /**< E-Mail-Address of the contact. It is recommended to use mrcontact_get_addr() to access this field. May be NULL. */
	int             m_blocked;  /**< Blocked state. Use mrcontact_is_blocked() to access this field. */
	int             m_origin;   /**< The original of the contact. One of the MR_ORIGIN_* constants. */
};


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __MRCONTACT_INTERNAL_H__ */
