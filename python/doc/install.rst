
building and installing deltachat
======================================

This package provides bindings to the delta-core_ C-library
which provides imap/smtp/crypto handling as well as chat/group/messages
handling to Android, Desktop and IO user interfaces.

build
-------

.. note::

    Currently the install instructions exist only for Debian based systems (Ubuntu etc.).

First you need to execute all the build steps to install the delta-core C-library,
see https://github.com/deltachat/deltachat-core/blob/master/README.md#build

install
-------

Presuming you have the delta-core library installed, you can then from the root of the repo::

    cd python
    pip install -e .

Afterwards you should be able to successfully import the bindings::

    python -c "import deltachat"


running tests
-------------

Install the delta-core C-library and the deltachat bindings (see _Install)
and then type the following to execute tests::

    pip install tox
    tox

If you want to run functional tests that run against real
e-mail accounts, generate a "liveconfig" file where each
lines contains account settings, for example::

    # 'liveconfig' file specifying imap/smtp accounts
    addr=some-email@example.org mail_pw=password
    addr=other-email@example.org mail_pw=otherpassword

And then run the tests with this live-accounts config file::

    tox -- --liveconfig liveconfig


.. _`delta-core`: https://github.com/deltachat/deltachat-core
