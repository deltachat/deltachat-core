Delta Chat Core Library
================================================================================

You can use the _Delta Chat Core Library_ to build **your own messenger** or
plugin, that is completely **compatible** to the existing email infrastructure.

![Logo](https://delta.chat/assets/features/start-img4.png)

Using this library in your app, you get the **ease** of well-known messengers
with the **reach** of e-mail. Moreover, you're **independent** from other companies or
services as your data is not relayed through Delta Chat, only your email
provider. That means that there are no Delta Chat servers, only clients that
are compatible via Delta Chat Core.

The library is used eg. in the [Delta Chat Android Frontend](https://github.com/deltachat/deltachat-android)
or in the [Delta Chat iOS Frontend](https://github.com/deltachat/deltachat-ios) but can also be used for
completely different messenger projects.

Some features at a glance

- **Secure** with automatic end-to-end-encryption, supporting the new
  [Autocrypt](https://autocrypt.readthedocs.io/en/latest/) standard
- **Fast** by the use of Push-IMAP
- **Read receipts**
- **Largest userbase** - receivers _not_ using Delta Chat can be reached as well
- **Compatible** - not only to itself
- **Elegant** and **simple** user interface
- **Distributed** system
- **No Spam** - only messages of known users are shown by default
- **Reliable** - safe for professional use
- **Trustworthy** - can even be used for business messages
- **Libre software** and [standards-based](https://delta.chat/en/standards)


API Documentation
--------------------------------------------------------------------------------

The C-API is documented at <https://deltachat.github.io/deltachat-core/html/>.

Please keep in mind, that your derived work must be released under a
GPL-compatible licence.  For details, please have a look at the [LICENSE file](https://github.com/deltachat/deltachat-core/blob/master/LICENSE) accompanying the source code.


Build
--------------------------------------------------------------------------------

Deta Chat Core can be built as a library using the
[meson](http://mesonbuild.com) build system.  It depends on a number
of external libraries, most of which are detected using
[pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/).
Usually this just works automatically when the depending libraries are
installed correctly.

It is easiest to install all of these using your system libraries.
Please note that you may need "development" packages installed for
these to work.

- [LibEtPan](https://github.com/dinhviethoa/libetpan); this does not
  use `pkg-config`, instead ships with a `libetpan-config` binary
  which must be in the PATH to be picked up by the build system.

- [OpenSSL](https://www.openssl.org/)

- [SQLite](http://sqlite.org/)

- [zlib](http://zlib.net)

- libsasl

- [bzip2](http://bzip.org)

To build you need to have [meson](http://mesonbuild.com) and
[ninja](https://ninja-build.org) installed as well.

On Debian stretch you can install all these using: `apt install
libetpan-dev libssl-dev libsqlite3-dev libsasl2-dev libbz2-dev
zlib1g-dev meson ninja-build`.

Onece all dependencies are installed creating a build is as follows,
starting from the project's root directory:

```
mkdir builddir
cd builddir
meson
# optionally configure some parameters
# run `meson configure` to see the options, e.g.
meson config -Dlibdir=lib
ninja
sudo ninja install
sudo ldconfig
```

The install keeps a log of which files where installed.  Uninstalling
is thus supported too:
```
ninja uninstall
```

Note that the above assumes `/usr/local/lib` is configured somewhere
in `/etc/ld.so.conf` or `/etc/ld.so.conf.d/*`, which is fairly
standard.

---

Copyright © 2017 Delta Chat contributors
