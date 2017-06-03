Delta Chat Core
================================================================================

**Delta Chat** is a project that aims to create a messaging app that is
completely **compatible** to the existing e-mail infrastructure.

![Logo](https://delta.chat/assets/features/start-img4.png)

So, with Delta Chat you get the **ease** of well-known messengers with the
**reach** of e-mail. Moreover, you're **independent** from other companies or
services - as your data are not related to Delta Chat, you won't even add new
dependecies here.

Some features at a glance

- **Fast** by the use of Push-IMAP
- **Largest userbase** - receivers _not_ using Delta Chat can be reached as well
- **Compatible** - not only to itself
- **Elegant** and **simple** user interface
- **Distributed** system
- **No Spam** - only messages of known users are shown by default
- **Reliable** - safe for professional use
- **Trustworthy** - can even be used for business messages
- fully **OpenSource** and **Standards** based


Download
--------------------------------------------------------------------------------

Currently, the project is in alpha state under heavy development.  A working
**Android version** is available eg. on F-Droid or at https://delta.chat .

The source code for the Android version is available at
https://github.com/r10s/deltachat-android .


Build
--------------------------------------------------------------------------------

This repository contains only the core library that is used by all frontends.

The core relies on the following external libs:

- [LibEtPan](https://github.com/dinhviethoa/libetpan); for
  compilation, use eg. the following commands: `./autogen.sh; make;
  sudo make install prefix=/usr`
  To link against LibEtPan, add `libetpan-config --libs` in backticks to your
  project.  
  Alternatively, use the ready-to-use files from the libs-directory which are
  suitable for common system.

- [SQLite](http://sqlite.org/) is available on most systems, however, you
  will also need the headers, please look for packages as `libsqlite3-dev`.
  To link against SQLite, add `-lsqlite3` to your project.

- [libgcrypt](https://www.gnupg.org/related_software/libgcrypt/) for the
  headers, please look for packages as `libgrypt20-dev` and `libgpg-error-dev`.
  To link against libgcrypt, add `-lgcrypt -lgpg-error` to your project.

Information about how to build the frontends can be found in the corresponding
repositories as https://github.com/r10s/deltachat-android .


Coding
--------------------------------------------------------------------------------

You're a developer and have an idea for another crazy chat, social or messaging
app?  We encourage you to take this source code as a base.  We love to see
_many_ different messengers out there, based on existing, distributed
infrastructure.  But we hate to see the user's data hidden on some companies
servers with undefined backgrounds.

Some hints:

- Regard the header files in the `src`-directory as a documentation;
  `mrmailbox.h` is a good starting point

- Headers may cointain headlines as "library-private" - stull following there
  is not meant to be used by the library user.

- Two underscores at the end of a function-name may be a _hint_, that this
  function does no resource locking.

- For objects, C-structures are used.  If not mentioned otherwise, you can
  read the members here directly.

- For `get`-functions, you have to unref the return value in some way.

- Strings in function arguments or return values are usually UTF-8 encoded

- Threads are implemented using POSIX threads (pthread_* functions)

- For indentation we use tabs.  Alignments that are not placed at the beginning
  of a line should be done with spaces.

- For padding between funktions, classes etc. we use 2 empty lines

- Source files are encoded as UTF-8 with Unix-Lineends (a simple `LF`, `0x0A` or
  `\n`)

Please keep in mind, that your derived work must be released under a
GPL-compatible licence.  For details, please have a look at the file LICENSE
that comes together with the source code.

---

Copyright (C) 2017 Delta Chat contributors
