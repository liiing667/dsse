"""Fixed fixtures for the hardened envelope parser in signing_spec.py.

Each rejection fixture asserts the exact failure reason, and the valid
envelope fixture shows the normal VerifiedPayload response. Run with:

    python3 -m unittest test_signing_spec -v

or directly (`python3 test_signing_spec.py`) to also print a summary table of
every fixture and its outcome. Uses a deterministic toy signer so no crypto
dependencies are required.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import signing_spec
from signing_spec import EnvelopeError, PAE, Sign, Verify

PAYLOAD_TYPE = 'http://example.com/HelloWorld'
PAYLOAD = b'hello world'


class ToySigner:
    """Deterministic stand-in for a real signer: sig = b'sig:' + message."""

    def keyid(self):
        return 'toy-key-1'

    def sign(self, message):
        return b'sig:' + message


class ToyVerifier:
    def __init__(self, keyid='toy-key-1'):
        self._keyid = keyid

    def keyid(self):
        return self._keyid

    def verify(self, message, signature):
        return signature == b'sig:' + message


VERIFIERS = [('mykey', ToyVerifier())]
VALID_ENVELOPE = Sign(PAYLOAD_TYPE, PAYLOAD, ToySigner())
OVERSIZED_ENVELOPE = '{"payload": "' + 'A' * (signing_spec.MAX_ENVELOPE_BYTES + 1)

# (name, envelope_producer, expected_rejection_reason). A reason of None means
# the envelope must verify normally.
FIXTURES = [
    ('valid envelope (legacy format)',
     lambda: VALID_ENVELOPE,
     None),
    ('duplicate payloadType member',
     lambda: VALID_ENVELOPE.replace(
         '"payloadType": "%s"' % PAYLOAD_TYPE,
         '"payloadType": "application/evil", "payloadType": "%s"' % PAYLOAD_TYPE),
     "duplicate JSON member: 'payloadType'"),
    ('duplicate keyid member in signature',
     lambda: VALID_ENVELOPE.replace(
         '"keyid": "toy-key-1"',
         '"keyid": "other", "keyid": "toy-key-1"'),
     "duplicate JSON member: 'keyid'"),
    ('missing payload field',
     lambda: json.dumps({'payloadType': PAYLOAD_TYPE, 'signatures': []}),
     "missing required field: 'payload'"),
    ('missing signatures field',
     lambda: json.dumps({'payload': 'aGVsbG8=', 'payloadType': PAYLOAD_TYPE}),
     "missing required field: 'signatures'"),
    ('oversized envelope',
     lambda: OVERSIZED_ENVELOPE,
     'envelope too large: %d bytes > %d byte limit' % (
         len(OVERSIZED_ENVELOPE.encode('utf-8')),
         signing_spec.MAX_ENVELOPE_BYTES)),
    ('empty signatures array',
     lambda: json.dumps({
         'payload': 'aGVsbG8gd29ybGQ=', 'payloadType': PAYLOAD_TYPE,
         'signatures': []}),
     'signatures must be a non-empty array'),
    ('signatures not an array',
     lambda: json.dumps({
         'payload': 'aGVsbG8gd29ybGQ=', 'payloadType': PAYLOAD_TYPE,
         'signatures': {'sig': 'AA=='}}),
     'signatures must be a non-empty array'),
    ('signature missing sig',
     lambda: json.dumps({
         'payload': 'aGVsbG8gd29ybGQ=', 'payloadType': PAYLOAD_TYPE,
         'signatures': [{'keyid': 'toy-key-1'}]}),
     "signatures[0]: missing required field: 'sig'"),
    ('sig not valid base64',
     lambda: json.dumps({
         'payload': 'aGVsbG8gd29ybGQ=', 'payloadType': PAYLOAD_TYPE,
         'signatures': [{'sig': '!!!not-base64!!!'}]}),
     'signatures[0]: sig is not valid base64'),
    ('payload not valid base64',
     lambda: json.dumps({
         'payload': '%%%', 'payloadType': PAYLOAD_TYPE,
         'signatures': [{'sig': 'AA=='}]}),
     'payload is not valid base64'),
    ('payloadType wrong type',
     lambda: json.dumps({
         'payload': 'aGVsbG8=', 'payloadType': 42,
         'signatures': [{'sig': 'AA=='}]}),
     "envelope: field 'payloadType' must be a string"),
    ('top-level array',
     lambda: '[1, 2, 3]',
     'envelope must be a JSON object'),
    ('not JSON at all',
     lambda: 'this is not json',
     None),  # reason checked by prefix: 'invalid JSON'
]


class TestEnvelopeFixtures(unittest.TestCase):
    def test_valid_envelope_round_trip(self):
        result = Verify(VALID_ENVELOPE, VERIFIERS)
        self.assertEqual(result.payloadType, PAYLOAD_TYPE)
        self.assertEqual(result.payload, PAYLOAD)
        self.assertEqual(result.recognizedSigners, ['mykey'])

    def test_valid_envelope_from_bytes(self):
        result = Verify(VALID_ENVELOPE.encode('utf-8'), VERIFIERS)
        self.assertEqual(result.payload, PAYLOAD)

    def test_fixtures(self):
        for name, make_envelope, expected_reason in FIXTURES:
            with self.subTest(fixture=name):
                envelope = make_envelope()
                if expected_reason is None and name == 'valid envelope (legacy format)':
                    Verify(envelope, VERIFIERS)
                elif expected_reason is None:
                    with self.assertRaises(EnvelopeError) as ctx:
                        Verify(envelope, VERIFIERS)
                    self.assertTrue(str(ctx.exception).startswith('invalid JSON'),
                                    str(ctx.exception))
                else:
                    with self.assertRaises(EnvelopeError) as ctx:
                        Verify(envelope, VERIFIERS)
                    self.assertTrue(
                        str(ctx.exception).startswith(expected_reason),
                        f'{ctx.exception!r} does not start with {expected_reason!r}')

    def test_bad_signature_still_fails_closed(self):
        envelope = json.dumps({
            'payload': 'aGVsbG8gd29ybGQ=', 'payloadType': PAYLOAD_TYPE,
            'signatures': [{'keyid': 'toy-key-1', 'sig': 'AAAA'}]})
        with self.assertRaisesRegex(ValueError, 'No valid signature found'):
            Verify(envelope, VERIFIERS)

    def test_keyid_mismatch_is_skipped_not_rejected(self):
        envelope = json.loads(VALID_ENVELOPE)
        envelope['signatures'].append({'keyid': 'unknown-key', 'sig': 'AAAA'})
        result = Verify(json.dumps(envelope), VERIFIERS)
        self.assertEqual(result.recognizedSigners, ['mykey'])


def _print_summary():
    print(f'{"fixture":<40} {"outcome":<8} detail')
    print('-' * 100)
    for name, make_envelope, _ in FIXTURES:
        try:
            result = Verify(make_envelope(), VERIFIERS)
        except EnvelopeError as e:
            print(f'{name:<40} REJECT   {e}')
        except ValueError as e:
            print(f'{name:<40} REJECT   {e}')
        else:
            print(f'{name:<40} ACCEPT   {result!r}')


if __name__ == '__main__':
    _print_summary()
    print()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
