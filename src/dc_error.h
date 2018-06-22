/*******************************************************************************
 *
 *                              Delta Chat Core
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


#ifndef __DC_ERROR_H__
#define __DC_ERROR_H__
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 *
 * The following constants are used as error codes used by the event
 * #DC_EVENT_ERROR (see dc_event.h) and reported to the callback given to
 * dc_context_new().
 */


/**
 * Details about the error can be found in data2. Reported by #DC_EVENT_ERROR.
 */
#define DC_ERR_SEE_STRING                 0


/**
 * Details about the error can be found in data2. Reported by #DC_EVENT_ERROR.
 */
#define DC_ERR_SELF_NOT_IN_GROUP          1


/**
 * Details about the error can be found in data2. Reported by #DC_EVENT_ERROR.
 */
#define DC_ERR_NONETWORK                  2


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif /* __DC_ERROR_H__ */

