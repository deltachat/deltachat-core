# API changes

This file mainly documents changes in the API of deltachat-core.

For a full list of changes in deltachat-core, please have a look at the commits at
https://github.com/deltachat/deltachat-core/commits/master

For a high-level overview about changes in the single apps,
see the changelogs linked eg. from https://delta.chat/en/download

## v0.43.0

* add location-streaming functions `dc_msg_set_location()`,
  `dc_msg_has_location()`, `dc_array_is_independent()`

The changes have been done by Björn Petersen, cyBerta and Nico de Haen

## v0.42.0

* add location-streaming function and events:
  `dc_send_locations_to_chat()`, `dc_set_location()`, `dc_get_locations()`,
  `dc_is_sending_locations_to_chat()`, `dc_chat_is_sending_locations()`,
  `dc_array_get_latitude|longitude|accuracy|timestamp|marker()`,
  `dc_array_get_chat|contact|msg_id()`, `DC_EVENT_LOCATION_CHANGED`
* add `dc_prepare_msg()` and the state `DC_STATE_OUT_PREPARING`
  that may be used to prepare large files before sending
* new string constants `DC_STR_MSGLOCATIONENABLED|MSGLOCATIONDISABLED|LOCATION`
* trigger `DC_EVENT_IMEX_PROGRESS|FILE_WRITTEN` more carefully
* implement early-mime-creation to streamline and speed up message sending
* RPGP improvements
* handle image/webp and text/vcard files
* bug fixes

The changes have been done by Björn Petersen, cyBerta, Daniel Böhrs,
Floris Bruynooghe, Friedel Ziegelmayer, Holger Krekel, Jikstra,
Nico de Haen and Viktor Pracht

## v0.41.0

* optionally support RPGP by the global define `DC_USE_RPGP`
* new `show_emails` config option taking one of the `DC_SHOW_EMAILS_*` values;
  defaults to `DC_SHOW_EMAILS_OFF` for new installations
  and to `DC_SHOW_EMAILS_ALL` for existing installations
* more reliable moving of chat messages to the DeltaChat folder
* oauth2 optionally supported via `dc_get_oauth2_url()`;
  currently gmail and yandex are supported
* added `DC_EVENT_HTTP_POST` and `DC_LP_AUTH_OAUTH2`; needed for oauth2
* probing STARTTLS on ports 993, 143 and 25
* gossip keys only after changes or once every few days
* add core-version to X-Mailer header

The changes have been done by Björn Petersen, Floris Bruynooghe,
Friedel Ziegelmayer and Holger Krekel

## v0.40.0

* do not truncate messenger messages
* avoid group splits
* avoid possible polling of unconfigured folders
* refine error handling on export/import
* read autoconfig from http-servers if https fails
* limit the number of messages referenced in the header
* meson handles iconv and calls the stress test

The changes have been done by Ampli-fier, Björn Petersen, Floris Bruynooghe
and Holger Krekel

## v0.39.1

* bugfix release

The changes have been done by Ampli-fier, Björn Petersen and Lars-Magnus Skog

## v0.39.0

* add sender to system messages
* translatable system messages
* three new strings `DC_STR_CONTACT_*`

The changes have been done by Björn Petersen and Lars-Magnus Skog

## v0.38.0

* enable `sentbox_watch`, `mvbox_watch` and `mvbox_move` by default

## v0.37.0

* join normal groups via qr-code
* add `dc_msg_get_sort_timestamp()` and `dc_msg_has_deviating_timestamp()`
* improved internal housekeeping

The changes have been done by Björn Petersen and Holger Krekel

## v0.36.0

* build improvements

The changes have been done by Björn Petersen, Jikstra
and Lars-Magnus Skog

## v0.35.0

* additional parameter for `dc_get_chat_media()` to pass a third type
* additional parameters for `dc_get_next_media()`
  to be in sync with `dc_get_chat_media()`
* on sending, missing mime types are guessed from extension
* fix sending files without extension

The changes have been done by Björn Petersen, Holger Krekel
and Simon Laux

## v0.34.0

* re-create goup-member-list if members are missing; avoid group-splits

## v0.32.0

* add function to add a thread watching the Send folder
* add config-options `inbox_watch` and `sendbox_watch`
* move chat messages from inbox/sent to DeltaChat folder

The changes have been done by Björn Petersen and Holger Krekel

## v0.31.1
2018-12-20

* bugfix release

## v0.31.0

* add config-options `mvbox_watch` and `mvbox_move`
* remove config-options `imap_folder`, `mvbox_enabled`

The changes have been done by Björn Petersen and Holger Krekel,
Lars-Magnus Skog

## v0.30.0

* the core can second folder simultanous to the INBOX now;
  for this purposes, users shoud create a 3rd thread calling
  the new functions `dc_perform_mvbox_fetch()` and `dc_perform_mvbox_idle()`
* add config-option `mvbox_enabled`

The changes have been done by Björn Petersen and Holger Krekel

## v0.29.0

* add `dc_chat_get_color()` and `dc_contact_get_color()`

The changes have been done by Björn Petersen

## v0.28.0

* allow any messages as drafts
* enhance profile image api, add `dc_contact_get_profile_image()`
* `dc_msg_get_filemime()` returns the mimetype for incoming messages

The changes have been done by Björn Petersen, Holger Krekel,
Lars-Magnus Skog

## v0.27.0

* use '...' as the subject-fallback-text
* empty messages are returned as such
* build improvements, bug fixes

The changes have been done by Björn Petersen, Floris Bruynooghe,
Holger Krekel, Lars-Magnus Skog

## v0.26.1
2018-11-23

* bugfix release

## v0.26.0
2018-11-18

* remove `DC_EVENT_IS_OFFLINE`
* remove error code from `DC_EVENT_ERROR`
* add `DC_EVENT_ERROR_SELF_NOT_IN_GROUP`
* add flag to `DC_EVENT_ERROR_NETWORK` to differ between first/subsequent errors
* block concurrent calls to `dc_configure()`

The changes have been done by Björn Petersen, Holger Krekel, Lars-Magnus Skog

## v0.25.1
2018-11-14

* bugfix release

The changes have been done by Björn Petersen, Lars-Magnus Skog

## v0.25.0
2018-11-12

* use a single folder for all incoming and outgoing messages;
  defaults to INBOX and can be configured using
  `dc_set_config(context, "imap_folder", folder)`
* `dc_set_config()` and `dc_get_config()` check for correct key
* new function `dc_maybe_network()` to trigger jobs (as sending messages)
  and bypass the new exponential backoff algorithm

The changes have been done by Azul, Björn Petersen, Borys Piddubnyi,
Floris Bruynooghe, Holger Krekel, Stefan Strogin

## v0.24.1
2018-11-01

* Re-licensed files in src, doc, cmdline and python directories to MPL 2.0. 
  For confirmations from contributors see the thus finalized issue
  https://github.com/deltachat/deltachat-core/issues/403.

## v0.24.0
2018-10-29

* removed `DC_EVENT_GET_QUANTITY_STRING`
* added quantity parameter to `DC_EVENT_GET_STRING`

## v0.23.0
2018-10-17

* add `dc_get_received_timestamp()`
* `dc_send_X_msg()` functions removed in favor to `dc_send_msg()`
* removed deprcated mrmailbox.h


## v0.22.0
2018-10-11

* `dc_send_msg()` creates a copy of passed files before returning
* the event `DC_EVENT_FILE_COPIED` is no longer used


## v0.21.0
2018-10-11

* default parameter removed from `dc_get_config()`.
  if the requested value was not set before, 
  the core returns an appropriate default value on its own.
* messages of all types can contain text now;
  use `dc_msg_get_text()` to check.
