# API changes

This file mainly documents changes in the API of deltachat-core.

For a full list of changes in deltachat-core, please have a look at the commits at
https://github.com/deltachat/deltachat-core/commits/master

For a high-level overview about changes anywhere in the Delta Chat ecosystem,
see https://delta.chat/en/changelog

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

* remove DC_EVENT_IS_OFFLINE
* remove error code from DC_EVENT_ERROR
* add DC_EVENT_ERROR_SELF_NOT_IN_GROUP
* add flag to DC_EVENT_ERROR_NETWORK to differ between first/subsequent errors
* block concurrent calls to dc_configure()

The changes have been done by Björn Petersen, Holger Krekel, Lars-Magnus Skog

## v0.25.1
2018-11-14

* bugfix release

The changes have been done by Björn Petersen, Lars-Magnus Skog

## v0.25.0
2018-11-12

* use a single folder for all incoming and outgoing messages;
  defaults to INBOX and can be configured using
  dc_set_config(context, "imap_folder", folder)
* dc_set_config() and dc_get_config() check for correct key
* new function dc_maybe_network() to trigger jobs (as sending messages)
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

* removed DC_EVENT_GET_QUANTITY_STRING
* added quantity parameter to DC_EVENT_GET_STRING

## v0.23.0
2018-10-17

* add dc_get_received_timestamp()
* dc_send_X_msg() functions removed in favor to dc_send_msg()
* removed deprcated mrmailbox.h


## v0.22.0
2018-10-11

* dc_send_msg() creates a copy of passed files before returning
* the event DC_EVENT_FILE_COPIED is no longer used


## v0.21.0
2018-10-11

* default parameter removed from dc_get_config().
  if the requested value was not set before, 
  the core returns an appropriate default value on its own.
* messages of all types can contain text now;
  use dc_msg_get_text() to check.
