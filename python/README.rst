
deltachat python bindings
=========================

This package provides bindings to the deltachat-core_ C-library
which provides imap/smtp/crypto handling as well as chat/group/messages
handling to Android, Desktop and IO user interfaces.

Install
-------

1. First you need to `install the delta-core C-library
   <https://github.com/deltachat/deltachat-core/blob/master/README.md>`_.

2. `Install virtualenv <https://virtualenv.pypa.io/en/stable/installation/>`_
   if you don't have it, then create and use a fresh clean python environment::

        virtualenv -p python3 venv
        source venv/bin/activate

   Afterwards invoking ``python`` or ``pip install`` will only modify files
   in your ``venv`` directory.

3. Install the bindings with pip::

        pip install deltachat

   Afterwards you should be able to successfully import the bindings::

        python -c "import deltachat"

You may now look at `examples <https://py.delta.chat/examples.html>`_.



Running tests
-------------

Get a checkout of the `deltachat-core github repository`_ and type::

    cd python
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


.. _`deltachat-core github repository`: https://github.com/deltachat/deltachat-core
.. _`deltachat-core`: https://github.com/deltachat/deltachat-core
