=========================
deltachat python bindings
=========================

This package provides bindings to the `deltachat-core`_ C-library
which provides imap/smtp/crypto handling as well as chat/group/messages
handling to Android, Desktop and IO user interfaces.

Install
=======

You may also want to build a wheel using Docker instead of manually
building deltachat-core.  See below for this.

1. First you need to `install the delta-core C-library
   <https://github.com/deltachat/deltachat-core/blob/master/README.md>`_.

2. Install the Python 3 development files, e.g. on Ubuntu::

        sudo apt install python3-dev

3. `Install virtualenv <https://virtualenv.pypa.io/en/stable/installation/>`_
   if you don't have it, then create and use a fresh clean Python environment::

        virtualenv -p python3 venv
        source venv/bin/activate

   Afterwards invoking ``python`` or ``pip install`` will only modify files
   in your ``venv`` directory.

   Alternatively, you can use `Pipenv`_ for which a ``Pipfile`` already exists.
   In this case, instead of ``virtualenv``, ``source`` and ``pip``, execute the
   following::

        pipenv install --dev
        pipenv shell

4. Install the bindings with pip::

        pip install deltachat

   Afterwards you should be able to successfully import the bindings::

        python -c "import deltachat"

You may now look at `examples <https://py.delta.chat/examples.html>`_.

.. _`Pipenv`: https://pipenv.readthedocs.io/en/latest/install/#installing-pipenv



Running tests
=============

Get a checkout of the `deltachat-core`_ GitHub repository and type::

    cd python
    pip install tox
    tox

If you want to run functional tests that run against real
e-mail accounts, generate a "liveconfig" file where each
lines contains account settings, for example::

    # 'liveconfig' file specifying imap/smtp accounts
    addr=some-email@example.org mail_pw=password
    addr=other-email@example.org mail_pw=otherpassword

And then run the tests with this live account's config file::

    tox -- --liveconfig liveconfig


.. _`deltachat-core`: https://github.com/deltachat/deltachat-core


Building manylinux1 wheels
==========================

Building portable manylinux1 wheels which come with libdeltachat.so
and all it's dependencies is easy using the provided Docker tooling.

You will need Docker, the first builds a custom Docker image.  This is
slow initially but normally updates are cached by Docker.  If no
changes were made to the dependencies, this step is not needed at all
even, though as mentioned Docker will cache the results so there's no
harm in running it again::

   $ pwd               # Make sure the current working directory is the
   .../deltachat-core  # top of the deltachat-core project checkout.
   $ docker build -t deltachat-wheel python/wheelbuilder/


Now you should have an image called ``dcwhl`` listed if you run ``docker
images``. This image can now be used to build both ``libdeltachat.so`` and
the Python wheel with the bindings which bundle this::

   $ docker run --rm -it -v $(pwd):/io/ deltachat-wheel /io/python/wheelbuilder/build-wheels.sh

The wheels will be in ``python/wheelhouse``.


Troubleshooting
---------------

On more recent systems running the Docker image may crash.  You can
fix this by adding ``vsyscall=emulate`` to the Linux kernel boot
arguments commandline.  E.g. on Debian you'd add this to
``GRUB_CMDLINE_LINUX_DEFAULT`` in ``/etc/default/grub``.
