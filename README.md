# Delta Chat Core Library

[![Build Status](https://travis-ci.org/deltachat/deltachat-core.svg?branch=master)](https://travis-ci.org/deltachat/deltachat-core)

The _Delta Chat Core Library_ is written in cross-platform **C**,
documented at <https://deltachat.github.io/api/>.

Building the C-library 
----------------------

Delta Chat Core is built as a C-library using the 
[meson build system](http://mesonbuild.com). 
It depends on a number of external libraries, most of which are detected using
[pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/).
Usually this just works automatically, provided the depending libraries are
installed correctly.  You may need to install "development" packages of
these dependencies: 

- [LibEtPan](https://github.com/dinhviethoa/libetpan); Note that this
  library does not use pkg-config so the system-provided version will
  be looked up by using `libetpan-config` which must be in the PATH.
  Version 1.8 or newer is required.

- [OpenSSL](https://www.openssl.org/)

- [SQLite](https://sqlite.org/)

- [zlib](https://zlib.net)

- [libsasl](https://cyrusimap.org/sasl/)

- [bzip2](http://bzip.org)

- [meson build system at least in version 0.47.2](http://mesonbuild.com) 
  and [ninja](https://ninja-build.org).

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

Building without system-level dependencies 
------------------------------------------

By default stripped-down versions of the dependencies are bundled with
Delta Chat Core and these will be used when a dependency is missing.
You can choose to always use the bundled version of the dependencies
by invoking meson with the `--wrap-mode=forcefallback` option.
Likewise you can forbid using the bundled dependencies using
`--wrap-mode=nofallback`.

There also is an experimental feature where you can build a version of the
shared `libdeltachat.so` library with no further external
dependencies.  This can be done by passing the `-Dmonolith=true`
option to meson.  Note that this implies `--wrap-mode=forcefallback`
since this will always use all the bundled dependencies.


Language bindings and frontend Projects
---------------------------------------

Language bindings are available for:

- [Node.js](https://www.npmjs.com/package/deltachat-node)
- [Python](https://py.delta.chat)
- **Java** and **Swift** (contained in the Android/iOS repos) 

The following "frontend" project make use of the C-library
or its language bindings: 

- [Android](https://github.com/deltachat/deltachat-android)
- [iOS](https://github.com/deltachat/deltachat-ios) 
- [Desktop](https://github.com/deltachat/deltachat-desktop)
- [Pidgin](https://gitlab.com/lupine/purple-plugin-delta)


Testing program
--------------------------------------------------------------------------------

After a successful build there is also a little testing program in `builddir/cmdline`.
You start the program with `./delta <database-file>`
(if the database file does not exist, it is created).
The program then shows a prompt and typing `help` gives some help about the available commands.

New tests are currently developed using Python, see 
https://github.com/deltachat/deltachat-core/tree/master/python/tests


License
--------------------------------------------------------------------------------

Licensed under the GPLv3, see [LICENSE](./LICENSE) file for details.

Copyright © 2017, 2018 Bjoern Petersen and Delta Chat contributors.
