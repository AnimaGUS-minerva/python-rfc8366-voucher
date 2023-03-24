.. vim:tw=72

======================
python-rfc8366-voucher
======================

.. image::
   https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/blob/master/LICENSE

.. image::
   https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/workflows/CI/badge.svg
   :target: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/actions


`python-rfc8366-voucher`_ is a Python bindings around the (compact CBOR-encoded) RFC8366 Voucher `Rust library crate`_.

.. _python-rfc8366-voucher: https://github.com/AnimaGUS-minerva/python-rfc8366-voucher
.. _Rust library crate: https://github.com/AnimaGUS-minerva/voucher


API documentation
=================

(TBA)
https://github.com/AnimaGUS-minerva/python-rfc8366-voucher/docs/build/html/index.html


Credits
=======

We have used the `python-mbedtls`_ project as template for organizing
our internal Cython module builds and Sphinx based docs.

.. _python-mbedtls: https://github.com/Synss/python-mbedtls


Installation
============

The bindings are tested with `AnimaGUS-minerva/voucher`_ 0.8.8 for
 Python 3.10, and 3.11 on Linux and macOS.

.. _AnimaGUS-minerva/voucher: https://github.com/AnimaGUS-minerva/voucher

Usage and examples
==================

In this section, we show how to use the basic parts of the library.


Checking the underlying library versions
----------------------------------------

``voucher.version`` keeps the version string of the Rust-based voucher crate:

>>> import voucher
>>> _ = voucher.version  # 'Rust voucher 0.8.8'


Using the ``voucher.mbedtls_version`` module, we can obtain the run-time version
information of the mbed TLS backend:

>>> from voucher import mbedtls_version
>>> _ = mbedtls_version.version  # 'mbed TLS 3.0.0'
>>> _ = mbedtls_version.version_info  # (3, 0, 0)


!! ex prelude
-------------

WIP description

..  code-block:: python3

    import voucher
    from voucher import *  # Vrq, Vch, ATTR_*, ...
    from voucher import from_cbor

    import os
    VOUCHER_SAMPLE_DIR = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '../voucher/data')

    def read_bytes_from(filepath):
        return open(filepath, 'rb').read()


Example (1/3): Using the ``Vrq`` (and ``Vch``) class
----------------------------------------------------

Each ``voucher.Vrq`` and ``voucher.Vch`` class abstracts "Voucher Request" and "Voucher" artifacts of
Constrained BRSKI, respectively. Once the class is instatiated, we can manage its attributes
using the dedicated API methods (``.get()``, ``.set()``, ``.remove()``, etc.).
These methods operate with ``ATTR_*`` constants that represents the BRSKI voucher attributes.

In this example, we demonstrate how to use the ``Vrq`` class for a "voucher request" instance
created by ``Vrq()``.  (Note that all of the methods belonging to the ``Vrq`` instance shown below
can also be called by a "voucher" instance created by ``Vch()``.)


..  code-block:: python3

    # Create an empty voucher request.
    vrq = Vrq()

    # Add some attributes.
    vrq[ATTR_ASSERTION] = ASSERTION_PROXIMITY
    vrq[ATTR_CREATED_ON] = 1599086034
    vrq[ATTR_SERIAL_NUMBER] = '00-D0-E5-F2-00-02'

    # Count attributes.
    assert len(vrq) == 3

    # Check for specific ones.
    assert vrq[ATTR_CREATED_ON] == 1599086034
    assert vrq[ATTR_EXPIRES_ON] == None

    # Remove a specific one.
    assert vrq.remove(ATTR_CREATED_ON) == True

    # Count attributes again.
    assert len(vrq) == 2

    # Iterate over everything.
    for k, v in vrq:
        print(f'vrq[{k}]: {v}')

    # The built-in `print()` works for the object (since the `Vrq` class implements the
    # `__repr__()` method).
    print(vrq)
    """
    voucher type: 'vrq'
    # of attributes: 2

      [ATTR_ASSERTION] ASSERTION_PROXIMITY
      [ATTR_SERIAL_NUMBER] b'00-D0-E5-F2-00-02'

    COSE signature algorithm: unknown
    COSE signature: None
    COSE content: None
    COSE signer cert: None
    """


Example (2/3): Encoding a Voucher into CBOR
-------------------------------------------

WIP description

..  code-block:: python3

    # Create a voucher request with five attributes.
    vrq = Vrq()
    vrq[ATTR_ASSERTION] = ASSERTION_PROXIMITY
    vrq[ATTR_CREATED_ON] = 1599086034
    vrq[ATTR_NONCE] = bytes([48, 130, 1, 216, 48, 130, 1, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 115, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 66, 48, 64, 6, 3, 85, 4, 3, 12, 57, 35, 60, 83, 121, 115, 116, 101, 109, 86, 97, 114, 105, 97, 98, 108, 101, 58, 48, 120, 48, 48, 48, 48, 53, 53, 98, 56, 50, 53, 48, 99, 48, 100, 98, 56, 62, 32, 85, 110, 115, 116, 114, 117, 110, 103, 32, 70, 111, 117, 110, 116, 97, 105, 110, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 23, 13, 50, 50, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 48, 70, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 85, 110, 115, 116, 114, 117, 110, 103, 32, 74, 82, 67, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 150, 101, 80, 114, 52, 186, 159, 229, 221, 230, 95, 246, 240, 129, 111, 233, 72, 158, 129, 12, 18, 7, 59, 70, 143, 151, 100, 43, 99, 0, 141, 2, 15, 87, 201, 124, 148, 127, 132, 140, 178, 14, 97, 214, 201, 136, 141, 21, 180, 66, 31, 215, 242, 106, 183, 228, 206, 5, 248, 167, 76, 211, 139, 58, 163, 16, 48, 14, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 49, 0, 135, 158, 205, 227, 138, 5, 18, 46, 182, 247, 44, 178, 27, 195, 210, 92, 190, 230, 87, 55, 112, 86, 156, 236, 35, 12, 164, 140, 57, 241, 64, 77, 114, 212, 215, 85, 5, 155, 128, 130, 2, 14, 212, 29, 79, 17, 159, 231, 2, 48, 60, 20, 216, 138, 10, 252, 64, 71, 207, 31, 135, 184, 115, 193, 106, 40, 191, 184, 60, 15, 136, 67, 77, 157, 243, 247, 168, 110, 45, 198, 189, 136, 149, 68, 47, 32, 55, 237, 204, 228, 133, 91, 17, 218, 154, 25, 228, 232])
    vrq[ATTR_PROXIMITY_REGISTRAR_CERT] = bytes([102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81])
    vrq[ATTR_SERIAL_NUMBER] = '00-D0-E5-F2-00-02'

    # COSE-sign the voucher request.
    KEY_PEM_F2_00_02 = read_bytes_from(
        os.path.join(VOUCHER_SAMPLE_DIR, '00-D0-E5-F2-00-02/key.pem'))
    vrq.sign(KEY_PEM_F2_00_02, SA_ES256)

    # Encode the voucher request.
    cbor = vrq.to_cbor()

    assert len(cbor) == 630


Example (3/3): Decoding a CBOR-encoded voucher into an instance
---------------------------------------------------------------

WIP description

..  code-block:: python3

    VCH_F2_00_02 = read_bytes_from(
        os.path.join(VOUCHER_SAMPLE_DIR, '00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch'))
    MASA_CRT_F2_00_02 = read_bytes_from(
        os.path.join(VOUCHER_SAMPLE_DIR, '00-D0-E5-F2-00-02/masa.crt'))

    # Decode the voucher.
    vch = from_cbor(VCH_F2_00_02)

    # COSE-validate the voucher.
    assert vch.validate(MASA_CRT_F2_00_02)

    # This voucher has five attributes.
    assert len(vch) == 5

    for k, v in vch:
        print(f'vch[{k}] = {v}')

        # Check data belonging to the attribute.
        if k == ATTR_ASSERTION:
            assert v == ASSERTION_LOGGED
        elif k == ATTR_CREATED_ON:
            assert v == 1599525239
        elif k == ATTR_NONCE:
            assert v == bytes([88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103])
        elif k == ATTR_PINNED_DOMAIN_CERT:
            assert v[0:4] == bytes([77, 73, 73, 66])
        elif k == ATTR_SERIAL_NUMBER:
            assert v == b'00-D0-E5-F2-00-02'
        else:
            assert False
