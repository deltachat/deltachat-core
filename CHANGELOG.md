# API changes

This file mainly documents changes in the API of deltachat-core.

For a full list of changes in deltachat-core, please have a look at the commits at
https://github.com/deltachat/deltachat-core/commits/master

For a high-level overview about changes anywhere in the Delta Chat ecosystem,
see https://delta.chat/en/changelog


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
