"""Tests for the strict base64 parsing in signing_spec.

Run with: python3 -m unittest implementation/test_signing_spec.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import ecdsa
import signing_spec


SIGNER = ecdsa.Signer.construct(
    curve='P-256',
    d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
    point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
    point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)
VERIFIERS = [('mykey', ecdsa.Verifier(SIGNER.public_key))]

PAYLOAD_TYPE = 'http://example.com/HelloWorld'
PAYLOAD = b'hello world'
CANONICAL_PAYLOAD_B64 = 'aGVsbG8gd29ybGQ='
# Deterministic signature over PAE(PAYLOAD_TYPE, PAYLOAD).
CANONICAL_SIG_B64 = ('A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKci'
                     'JTfUiHqJPcIAriEGAHTVeCUjW2JIZA==')


def make_envelope(payload=CANONICAL_PAYLOAD_B64, sig=CANONICAL_SIG_B64,
                  keyid='66301bbf'):
    return json.dumps({
        'payload': payload,
        'payloadType': PAYLOAD_TYPE,
        'signatures': [{'keyid': keyid, 'sig': sig}],
    })


class B64DecMatrixTest(unittest.TestCase):
    """Each encoding variant has exactly one deterministic outcome."""

    # (encoding, expected decoded bytes, or None if it must be rejected)
    CASES = [
        ('aGVsbG8gd29ybGQ=', b'hello world'),  # canonical standard
        ('aGVsbG8td29ybGQ=', b'hello-world'),  # canonical, different bytes
        ('', b''),                             # canonical empty
        ('+/8=', b'\xfb\xff'),                 # canonical standard alphabet
        ('aGVsbG8gd29ybGQ', None),     # missing padding
        ('aGVsbG8gd29ybGQ==', None),   # excess padding
        ('aGVsbG8gd29ybGQ===', None),  # excess padding
        ('aGVsbG8gd29ybGQ=A', None),   # data after padding
        ('aGVsbG8gd29ybGQ=\n', None),  # trailing whitespace
        (' aGVsbG8gd29ybGQ=', None),   # leading whitespace
        ('aGVsbG8gd29ybGR=', None),    # non-zero trailing bits
        ('aGVsbG8gd29ybGO=', None),    # non-zero trailing bits
        ('aGVsbG8_d29ybGQ=', None),    # URL-safe alphabet
        ('-_8=', None),                # URL-safe alphabet
        ('!!!!', None),                # non-alphabet characters
    ]

    def test_matrix(self):
        for encoding, expected in self.CASES:
            with self.subTest(encoding=encoding):
                if expected is None:
                    with self.assertRaises(ValueError):
                        signing_spec.b64dec(encoding)
                else:
                    self.assertEqual(signing_spec.b64dec(encoding), expected)

    def test_non_text_input_fails_closed(self):
        for value in (None, 42, b'aGVsbG8gd29ybGQ=', ['aGVsbG8gd29ybGQ=']):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    signing_spec.b64dec(value)


class VerifyTest(unittest.TestCase):

    def test_canonical_sample_verifies(self):
        result = signing_spec.Verify(make_envelope(), VERIFIERS)
        self.assertEqual(result.payloadType, PAYLOAD_TYPE)
        self.assertEqual(result.payload, PAYLOAD)
        self.assertEqual(result.recognizedSigners, ['mykey'])

    def test_noncanonical_payload_rejected(self):
        # Same bytes as the canonical payload, non-canonical encoding.
        for bad in ('aGVsbG8gd29ybGQ', 'aGVsbG8gd29ybGQ==',
                    'aGVsbG8gd29ybGR=', 'aGVsbG8gd29ybGQ=\n'):
            with self.subTest(payload=bad):
                with self.assertRaises(ValueError):
                    signing_spec.Verify(make_envelope(payload=bad), VERIFIERS)

    def test_noncanonical_sig_rejected(self):
        # Same signature bytes, non-canonical or alternative encodings.
        url_safe = CANONICAL_SIG_B64.replace('+', '-').replace('/', '_')
        for bad in (CANONICAL_SIG_B64.rstrip('='),
                    CANONICAL_SIG_B64 + '=',
                    CANONICAL_SIG_B64 + '\n',
                    url_safe):
            with self.subTest(sig=bad):
                with self.assertRaises(ValueError):
                    signing_spec.Verify(make_envelope(sig=bad), VERIFIERS)

    def test_non_text_sig_fails_closed(self):
        for bad in (None, 42, ['sig']):
            with self.subTest(sig=bad):
                with self.assertRaises(TypeError):
                    signing_spec.Verify(make_envelope(sig=bad), VERIFIERS)

    def test_keyid_mismatch_not_recognized(self):
        with self.assertRaises(ValueError):
            signing_spec.Verify(make_envelope(keyid='other'), VERIFIERS)


if __name__ == '__main__':
    unittest.main()
