=========================
Delta Chat Python bindings
=========================

This package provides bindings to the `deltachat-core`_ C library
which provides imap/smtp/crypto handling as well as chat/group/messages
handling to Android, Desktop and IO user interfaces.

Installing pre-built packages (Linux only)
==========================================

If you have a Linux system, you can install the ``deltachat`` binary "wheel" package
without any "build-from-source" steps.

1. Install the Python 3 development files, e.g. on Ubuntu::

        sudo apt install python3-dev

2. `Install virtualenv <https://virtualenv.pypa.io/en/stable/installation/>`_,
   then create a clean Python environment and activate it in your shell::

        virtualenv -p python3 venv
        source venv/bin/activate

   Afterwards, invoking ``python`` or ``pip install`` will only
   modify files in your ``venv`` directory and leave your system installation
   alone.

   Alternatively, you can use `Pipenv`_ for which a ``Pipfile`` already exists.
   In this case, instead of ``virtualenv``, ``source`` and ``pip``, execute the
   following::

        pipenv install --dev
        pipenv shell

3. Install the wheel for Linux::

        pip install deltachat

   Verify it worked by typing::

        python -c "import deltachat"

.. _`Pipenv`: https://pipenv.readthedocs.io/en/latest/install/#installing-pipenv


Installing a wheel from a PR/branch
---------------------------------------

For Linux, we automatically build wheels for all GitHub PR branches
and push them to a Python package index. To install the latest GitHub master::

    pip install -i https://m.devpi.net/dc/master deltachat


Installing bindings from source
===============================

If you can't use the "binary" method above, you will need
to `install the deltachat-core C library <https://github.com/deltachat/deltachat-core/blob/master/README.md>`_
and then invoke installation of the source bindings::

    pip install --no-binary :all: deltachat

.. note::
   If you can help to automate the building of wheels for Mac or Windows,
   that'd be much appreciated! Please then get
   `in contact with us <https://delta.chat/en/contribute>`_.


Code examples
=============

`Code examples <https://py.delta.chat/examples.html>`_ are available.


Running tests
=============

Get a checkout of the `deltachat-core`_ GitHub repository and type::

    cd python
    pip install tox
    tox

If you want to run functional tests with real
e-mail test accounts, generate a "liveconfig" file where each
line contains test account settings, for example::

    # 'liveconfig' file specifying imap/smtp accounts
    addr=some-email@example.org mail_pw=password
    addr=other-email@example.org mail_pw=otherpassword

The "keyword=value" style allows to specify any
`Delta Chat account config setting <https://c.delta.chat/classdc__context__t.html#aff3b894f6cfca46cab5248fdffdf083d>`_
so you can also specify SMTP or IMAP servers, ports, SSL modes etc.
Typically DC's automatic configuration allows not to specify these settings.

You can now run tests with this ``liveconfig`` file::

    tox -- --liveconfig liveconfig


.. _`deltachat-core`: https://github.com/deltachat/deltachat-core


Building manylinux1 wheels
==========================

Building portable manylinux1 wheels which come with libdeltachat.so
and all it's dependencies is easy using the provided Docker tooling.

Using Docker pull/pre-made images
------------------------------------

We publish a build environment under the ``deltachat/wheel`` tag so
that you can pull it from the ``hub.docker.com`` site's "deltachat"
organization::

    $ docker pull deltachat/wheel

The ``deltachat/wheel`` image can be used to build both ``libdeltachat.so``
and the Python wheels::

    $ docker run --rm -it -v $(pwd):/io/ deltachat/wheel /io/python/wheelbuilder/build-wheels.sh

This command runs a script within the Docker image after mounting ``$(pwd)`` as ``/io`` within
the image. The script is specified as a path within the Docker image's filesystem.
The resulting wheel files will be in ``python/wheelhouse``.


Optionally build your own Docker image
--------------------------------------

If you want to build your own custom Docker image, you can do this::

   $ cd deltachat-core # cd to deltachat-core checkout directory
   $ docker build -t deltachat/wheel python/wheelbuilder/

This will use the ``python/wheelbuilder/Dockerfile`` to build
up a Docker image called ``deltachat/wheel``. You can afterwards
find it with::

   $ docker images


Troubleshooting
---------------

On more recent systems running the Docker image may crash.  You can
fix this by adding ``vsyscall=emulate`` to the Linux kernel boot
arguments commandline.  E.g. on Debian you'd add this to
``GRUB_CMDLINE_LINUX_DEFAULT`` in ``/etc/default/grub``.
