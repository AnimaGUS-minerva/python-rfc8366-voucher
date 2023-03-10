.. vim:tw=72

==================================================
Python bindings around the RFC8366 Voucher library
==================================================

.. image::
   https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/blob/master/LICENSE

.. image::
   https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/workflows/CI/badge.svg
   :target: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/actions


`python-rfc8366-voucher`_ is a Python bindings around the (compact CBOR-encoded) RFC8366 Voucher `Rust library crate`_.

.. _python-rfc8366-voucher: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher
.. _Rust library crate: https://github.com/AnimaGUS-minerva/voucher


License
=======

*python-rfc8366-voucher* is licensed under the MIT License (see `LICENSE`_).

.. _LICENCE: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/blob/master/LICENSE


Credits
=======

We have used the `python-mbedtls`_ project as template for organizing
our Cython module builds and Sphinx based docs.

.. _python-mbedtls: https://github.com/Synss/python-mbedtls


API documentation
=================

(TBA)
https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/docs/build/html/index.html


Installation
============

The bindings are tested with AnimaGUS-minerva/voucher 0.8.8 for Python 3.10,
and 3.11 on Linux and macOS.


Usage and examples
==================

In this section, we show how to use the basic parts of the library.


Check versions of the underlying libraries used by python-rfc8366-voucher
-------------------------------------------------------------------------

*voucher.version* keeps the version string of the Rust-based voucher crate:

>>> import voucher
>>> _ = voucher.version  # 'Rust voucher 0.8.8'


Using the *voucher.mbedtls_version* module, we can obtain the run-time version
information of the mbed TLS backend:

>>> from voucher import mbedtls_version
>>> _ = mbedtls_version.version  # 'mbed TLS 3.0.0'
>>> _ = mbedtls_version.version_info  # (3, 0, 0)

!! ex 1/3
---------

WIP

!! ex 2/3
---------

!! ex 3/3
---------

