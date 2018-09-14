deltachat: e-mail messaging/chatting API / deltachat-core C lib bindings
========================================================================

.. include:: links.rst

The deltachat library provides interfaces into the core
C-library for https://delta.chat:

- **low level bindings to deltachat-core**: ``deltachat.capi.lib`` exposes
  a CFFI-interface to the `deltachat-core C-API <https://deltachat.github.io/api/index.html>`.

- **higher level bindings**: :class:`deltachat.Account` serves as a high
  level object through which you can configure, send and receive messages,
  create and manage groups.

Getting started
-----------------------------------------

.. toctree::
   :maxdepth: 2

   install
   getting-started
   api

.. toctree::
   :hidden:

   links
   changelog

..
    Indices and tables
    ==================

    * :ref:`genindex`
    * :ref:`modindex`
    * :ref:`search`

