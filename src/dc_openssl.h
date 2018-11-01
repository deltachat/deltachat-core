/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

#ifndef __DC_OPENSSL_H__
#define __DC_OPENSSL_H__
#ifdef __cplusplus
extern "C" {
#endif


/*** library-private **********************************************************/


void dc_openssl_init(void);
void dc_openssl_exit(void);


#ifdef __cplusplus
} /* /extern "C" */
#endif
#endif // __DC_OPENSSL_H__
