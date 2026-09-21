import pytest

from pwnlib import encoders
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.exception import PwnlibException


def test_i386_printable_uses_ascii_shellcode_encoder():
    with context.local(arch='i386'):
        encoded = encoders.encoder.printable(b'\x00\x00\x00\x00')

    assert encoded != b'\x00\x00\x00\x00'
    assert all(0x21 <= byte <= 0x7e for byte in encoded)


@pytest.mark.parametrize(
    ('arch', 'encoder'),
    (
        ('i386', encoders.i386.xor.encode),
        ('arm', encoders.arm.xor.encode),
    ),
)
def test_xor_encoder_rejects_unusable_avoid_set(arch, encoder):
    with context.local(arch=arch):
        with pytest.raises(PwnlibException):
            encoder(b'ABCD', bytes(range(256)))


def test_encode_tries_next_encoder_after_failure(monkeypatch):
    class FailingEncoder:
        blacklist = set()

        def __call__(self, raw_bytes, avoid, pcreg):
            raise PwnlibException('cannot encode')

    class FallbackEncoder:
        blacklist = set()

        def __call__(self, raw_bytes, avoid, pcreg):
            return b'A'

    monkeypatch.setitem(
        Encoder._encoders,
        'i386',
        [FailingEncoder(), FallbackEncoder()],
    )
    monkeypatch.setattr(encoders.encoder.random, 'shuffle', lambda encoders: None)

    with context.local(arch='i386'):
        assert encoders.encoder.encode(b'\x00', avoid=b'\x00') == b'A'
