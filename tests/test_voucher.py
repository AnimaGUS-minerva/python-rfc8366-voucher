import voucher
from voucher import *  # Vrq, Vch, ATTR_*, ...
from voucher import from_cbor

_voucher = voucher.voucher  # debug


def test_voucher_mbedtls_version():
    import voucher.mbedtls.version as mbedtls_version

    assert mbedtls_version.version.startswith('mbed TLS 3.')

def test_voucher_version():
    assert voucher.voucher.version.startswith('Rust voucher ')



if 0:  # !!!! content of test_sample.py - https://docs.pytest.org/en/7.1.x/getting-started.html
    def func(x):
        return x + 1


    def test_answer():
        assert func(3) == 4


    class TestClass:
        def test_one(self):
            x = "this"
            assert "h" in x

        def test_two(self):
            x = "hello"
            assert hasattr(x, "check")