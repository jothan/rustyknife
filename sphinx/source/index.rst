.. rustyknife documentation master file, created by
   sphinx-quickstart on Fri May 18 08:50:54 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

rustyknife: The quicker email chopper
=====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

.. automodule:: rustyknife
    :members:
    :exclude-members: mail_command, dsn_mail_params, rcpt_command, orcpt_address, xforward_params, from_, sender, reply_to, unstructured, content_type, content_transfer_encoding, content_disposition
    :undoc-members:
    :show-inheritance:

MIME parameter parsing
======================

.. autofunction:: content_type
.. autofunction:: content_transfer_encoding
.. autofunction:: content_disposition

RFC 5322 Email content parsing
==============================

.. autofunction:: from_
.. autofunction:: sender
.. autofunction:: reply_to
.. autofunction:: unstructured

SMTP command parsing
====================

.. autofunction:: mail_command
.. autofunction:: dsn_mail_params
.. autofunction:: rcpt_command
.. autofunction:: orcpt_address
.. autofunction:: xforward_params

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
