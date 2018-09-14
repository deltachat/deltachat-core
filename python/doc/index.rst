DeltaChat Python Bindings
=========================

The deltachat package provides two bindings for the core C-library
of the https://delta.chat messaging ecosystem:

- :doc:`capi` is a lowlevel CFFI-binding to the
  `deltachat-core C-API <https://deltachat.github.io/api/index.html>`_.

- :doc:`api` [work-in-progress] is a high level interface to deltachat-core which aims
  to be memory safe and thoroughly tested through continous tox/pytest runs.


Getting started
-----------------------------------------

.. toctree::
   :maxdepth: 2

   install
   getting-started
   api
   capi

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

