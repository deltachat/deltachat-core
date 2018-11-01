# API changes

This file mainly documents changes in the API of deltachat-core.

For a full list of changes in deltachat-core, please have a look at the commits at
https://github.com/deltachat/deltachat-core/commits/master

For a high-level overview about changes anywhere in the Delta Chat ecosystem,
see https://delta.chat/en/changelog

## v0.24.1
2018-11-01

* Re-licensed to MPL 2.0. For confirmations from contributors see
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
