import pathlib
import minmon.crypto


def load_context():
    context = (pathlib.Path(__file__).parent / 'context.bin').open('rb').read()
    return minmon.crypto.context(context)


def test_cipher():
    context = load_context()
    sample = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    result = minmon.crypto.cipher(context, sample)
    assert b'\x92\xc7\x70\xf9\xc0\xe4\x7b\xfa\xbe\xb1\xeb\xf7\x8f\xfa\xad\x00' == result
