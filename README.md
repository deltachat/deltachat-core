LibreChat Backend
================================================================================

**LibreChat** is a project that aims to create a messaging app that is
completely **compatible** to the existing e-mail infrastructure.

So, with LibreChat you get the **ease** of well-known messengers with the
**reach** of e-mail. Moreover, you're **indepentent** from other companies or
services - as your data are not related to LibreChat, you won't even add new
dependecies here.

Some features at a glance

- **Fast** by the use of Push-IMAP
- **Largest userbase** - receivers _not_ using LibreChat can be reached as well
- **Elegant** and **simple** user interface
- **Distributed** system
- **Trustworthy** - can even be used for business messages
- fully **OpenSource** and **Standards** based


Download
--------------------------------------------------------------------------------

Currently, the project is in alpha state under heavy development.  There is 
_no working prototype yet_ - only this bunch of files and the frontends as
https://github.com/r10s/messenger-android .

If you're interested in this project, you can contact me using 
_r10s at b44t dotcom_.


Build
--------------------------------------------------------------------------------

This repository contains only the messenger backend that is used by all 
frontends.

The backend requires _LibEtPan_ and _SQLite_ - the usage at a glance on unix
systems:

- _LibEtPan_ is available at https://github.com/dinhviethoa/libetpan ; for
  compilation, use eg. the following commands: `./autogen.sh; make; 
  sudo make install prefix=/usr`  
  To link against LibEtPan, add `libetpan-config --libs` in backticks to your
  project.
  
- _SQLite_ ( http://sqlite.org/ ) is available on most systems, however, you
  will also need the headers, please look for packages as `libsqlite3-dev`.  
  To link against SQLite, add `-lsqlite3` to your project.

Information about how to build the frontends can be found in the corresponding
repositories as https://github.com/r10s/messenger-android .

You're a developer and have an idea for another crazy chat, social or messaging
app?  We encourage you to take this source code as a base.  We love to see 
_many_ different messengers out there, based on existing, distributed 
infrastructure.  But we hate to see the user's data hidden on some companies
servers with undefined backgrounds.


Copyright (c) Bjoern Petersen Software Design and Development,
http://b44t.com and contributors.
