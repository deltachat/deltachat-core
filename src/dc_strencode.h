/*************************************************************************
 * (C) 2018 Bjoern Petersen and contributors.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *************************************************************************/

#ifndef __DC_STRENCODE_H__
#define __DC_STRENCODE_H__
#ifdef __cplusplus
extern "C" {
#endif


char*   dc_urlencode              (const char*);
char*   dc_urldecode              (const char*);

char*   dc_encode_header_words    (const char*);
char*   dc_decode_header_words    (const char*);

char*   dc_encode_modified_utf7   (const char*, int change_spaces);
char*   dc_decode_modified_utf7   (const char*, int change_spaces);

int     dc_needs_ext_header       (const char*);
char*   dc_encode_ext_header      (const char*);
char*   dc_decode_ext_header      (const char*);


#ifdef __cplusplus
} // /extern "C"
#endif
#endif // __DC_STRENCODE_H__

