# Delta Chat Core Library

[![Build Status](https://travis-ci.org/deltachat/deltachat-core.svg?branch=master)](https://travis-ci.org/deltachat/deltachat-core)

You can use the _Delta Chat Core Library_ to build **your own messenger** or
plugin that is completely **compatible** with the existing email infrastructure.

The library is written in **C** and language bindings are available for
**Node.js, Java, Python** and **Swift**. They are used currently to create frontends eg. for
[Android](https://github.com/deltachat/deltachat-android),
[Desktop](https://github.com/deltachat/deltachat-desktop),
[iOS](https://github.com/deltachat/deltachat-ios) and
[Pidgin](https://gitlab.com/lupine/purple-plugin-delta)
but can also be used for completely different messenger projects.

![Logo](https://delta.chat/assets/features/start-img4.png)

Using this library in your app, you get the **ease** of well-known messengers
with the **reach** of email. Moreover, you're **independent** from other companies or
services as your data is not relayed through Delta Chat, only your email
provider. That means that there are no Delta Chat servers, only clients made compatible via Delta Chat Core.

Some features at a glance:

- **Secure** with automatic end-to-end-encryption, supporting the new
  [Autocrypt](https://autocrypt.org/) standard
- **Fast** by the use of Push-IMAP
- **Read receipts**
- **Largest userbase** - recipients _not_ using Delta Chat can be reached as well
- **Compatible** - not only to itself
- **Elegant** and **simple** user interface
- **Distributed** system
- **No Spam** - only messages of known users are shown by default
- **Reliable** - safe for professional use
- **Trustworthy** - can even be used for business messages
- **Libre software** and [standards-based](https://delta.chat/en/standards)


API Documentation
--------------------------------------------------------------------------------

The C-API is documented at <https://deltachat.github.io/api/>.

Please keep in mind, that your derived work must be released under a
GPL-compatible licence.  For details, please have a look at the [LICENSE file](https://github.com/deltachat/deltachat-core/blob/master/LICENSE) accompanying the source code.


Build
--------------------------------------------------------------------------------

Delta Chat Core can be built as a library using the
[meson](http://mesonbuild.com) build system. It depends on a number
of external libraries, most of which are detected using
[pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/).
Usually this just works automatically, provided the depending libraries are
installed correctly.

By default stripped-down versions of the dependencies are bundled with
Delta Chat Core and these will be used when a dependency is missing.
You can choose to always use the bundled version of the dependencies
by invoking meson with the `--wrap-mode=forcefallback` option.
Likewise you can forbid using the bundled dependencies using
`--wrap-mode=nofallback`.

Otherwise installing all of these using your system libraries is the
easiest route.  Please note that you may need "development" packages
installed for these to work.

- [LibEtPan](https://github.com/dinhviethoa/libetpan); Note that this
  library does not use pkg-config so the system-provided version will
  be looked up by using `libetpan-config` which must be in the PATH.
  Version 1.8 or newer is required.

- [OpenSSL](https://www.openssl.org/)

- [SQLite](https://sqlite.org/)

- [zlib](https://zlib.net)

- [libsasl](https://cyrusimap.org/sasl/)

- [bzip2](http://bzip.org)

There is an experimental feature where you can build a version of the
shared `libdeltachat.so` library with no further external
dependencies.  This can be done by passing the `-Dmonolith=true`
option to meson.  Note that this implies `--wrap-mode=forcefallback`
since this will always use all the bundled dependencies.

To build you need to have [meson](http://mesonbuild.com) (at least version 0.47.2) and
[ninja](https://ninja-build.org) installed as well.

On Linux (e.g. Debian Stretch) you can install all these using:

`sudo apt install libetpan-dev libssl-dev libsqlite3-dev libsasl2-dev libbz2-dev zlib1g-dev meson ninja-build`.

Once all dependencies are installed, creating a build is as follows,
starting from the project's root directory:

```
mkdir builddir
cd builddir
meson
# Optionally configure some other parameters
# run `meson configure` to see the options, e.g.
#    meson configure --default-library=static
ninja
sudo ninja install
sudo ldconfig
```

The install keeps a log of which files were installed. Uninstalling
is thus also supported:
```
sudo ninja uninstall
```

Note that the above assumes `/usr/local/lib` is configured somewhere
in `/etc/ld.so.conf` or `/etc/ld.so.conf.d/*`, which is fairly
standard.  It is possible your system uses
`/usr/local/lib/x86_64-linux-gnu` which should be auto-detected and
just work as well.


Testing program
--------------------------------------------------------------------------------

After a successful build there is also a little testing program in `builddir/cmdline`.
You start the program with `./delta <database-file>`
(if the database file does not exist, it is created).
The program then shows a prompt and typing `help` gives some help about the available commands.


License
--------------------------------------------------------------------------------

Licensed under the GPLv3, see [LICENSE](./LICENSE) file for details.

Copyright © 2017, 2018 Delta Chat contributors.
