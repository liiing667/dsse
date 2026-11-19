"""Regression tests for the bounded, fail-closed PAE domain.

Runs on the standard library only:

    python3 implementation/test_pae.py
"""

import base64
import doctest
import json
import os
import unittest

import signing_spec as ss


FIXTURE_PATH = os.path.join(os.path.dirname(__file__),
                            'fixtures', 'pae_fixtures.json')


def parse_pae(pae: bytes):
    """Parse a PAE byte string back into its declared fields.

    Independently walks the SP/LEN framing instead of trusting the producer,
    proving that each LEN field points exactly at its own byte sequence and
    that the two fields cannot bleed into each other.
    """
    prefix = b'DSSEv1 '
    assert pae.startswith(prefix)
    pos = len(prefix)

    def read_field():
        nonlocal pos
        sp = pae.index(b' ', pos)
        length = int(pae[pos:sp])
        start = sp + 1
        value = pae[start:start + length]
        assert len(value) == length, 'LEN does not match actual field bytes'
        pos = start + length
        return length, value

    type_len, type_bytes = read_field()
    assert pae[pos:pos + 1] == b' '
    pos += 1
    body_len, body = read_field()
    assert pos == len(pae), 'trailing bytes outside the declared PAE domain'
    return type_len, type_bytes, body_len, body


def load_fixtures():
    with open(FIXTURE_PATH, encoding='utf-8') as handle:
        return json.load(handle)


class PaeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures()

    def test_bounds_match_implementation(self):
        bounds = self.fixtures['bounds']
        self.assertEqual(bounds['maxTypeBytes'], ss.MAX_TYPE_BYTES)
        self.assertEqual(bounds['maxPayloadBytes'], ss.MAX_PAYLOAD_BYTES)

    def test_accept_vectors_round_trip_with_exact_pae_bytes(self):
        for case in self.fixtures['accept']:
            with self.subTest(case=case['name']):
                body = base64.b64decode(case['payloadB64'])
                pae = ss.PAE(case['payloadType'], body)

                expected = case['expected']
                self.assertEqual(pae.hex(), expected['paeHex'])
                if 'paeUtf8' in expected:
                    self.assertEqual(pae.decode('utf-8'), expected['paeUtf8'])

                type_len, type_bytes, body_len, parsed_body = parse_pae(pae)
                self.assertEqual(type_len, expected['typeLen'])
                self.assertEqual(body_len, expected['payloadLen'])
                self.assertEqual(
                    type_len, len(case['payloadType'].encode('utf-8')))
                self.assertEqual(type_bytes,
                                 case['payloadType'].encode('utf-8'))
                self.assertEqual(parsed_body, body)

    def test_reject_vectors_fail_closed(self):
        for case in self.fixtures['reject']:
            with self.subTest(case=case['name']):
                entry = case['input']
                body = base64.b64decode(entry.get('payloadB64', ''))
                with self.assertRaises(ss.PAEError):
                    if entry['kind'] == 'pae_raw':
                        ss._pae(bytes.fromhex(entry['typeHex']), body)
                    else:
                        payload_type = entry.get('payloadType')
                        if 'payloadTypeEscape' in entry:
                            payload_type = json.loads(
                                '"%s"' % entry['payloadTypeEscape'])
                        elif 'descriptor' in case and \
                                case['descriptor']['field'] == 'payloadType':
                            payload_type = payload_type * \
                                case['descriptor']['length']
                        if case.get('descriptor', {}).get('field') == \
                                'payload':
                            body = bytes([
                                int(case['descriptor']['repeatByte'], 16)
                            ]) * case['descriptor']['length']
                        ss.PAE(payload_type, body)


class PaeBoundaryTests(unittest.TestCase):
    def test_boundary_values_are_accepted(self):
        self.assertEqual(
            ss.PAE('a' * ss.MAX_TYPE_BYTES, b''),
            b'DSSEv1 %d %s 0 ' % (ss.MAX_TYPE_BYTES, b'a' * ss.MAX_TYPE_BYTES))
        self.assertEqual(
            ss.PAE('', b'\x00' * ss.MAX_PAYLOAD_BYTES),
            b'DSSEv1 0  %d %s' % (
                ss.MAX_PAYLOAD_BYTES, b'\x00' * ss.MAX_PAYLOAD_BYTES))

    def test_over_boundary_values_are_rejected(self):
        with self.assertRaises(ss.PAEError):
            ss.PAE('a' * (ss.MAX_TYPE_BYTES + 1), b'')
        with self.assertRaises(ss.PAEError):
            ss.PAE('', b'\x00' * (ss.MAX_PAYLOAD_BYTES + 1))

    def test_non_string_type_and_non_bytes_payload_are_rejected(self):
        with self.assertRaises(ss.PAEError):
            ss.PAE(b'not-a-string', b'')
        with self.assertRaises(ss.PAEError):
            ss.PAE('ok', 'not-bytes')
        with self.assertRaises(ss.PAEError):
            ss._pae(b'\xff\xfe', b'')


class _RecordingVerifier:
    def __init__(self):
        self.verified_messages = []

    def verify(self, message: bytes, signature: bytes) -> bool:
        self.verified_messages.append(message)
        return True

    def keyid(self):
        return None


class VerifyFailClosedTests(unittest.TestCase):
    def _envelope(self, payload_type, body):
        return json.dumps({
            'payload': base64.standard_b64encode(body).decode('ascii'),
            'payloadType': payload_type,
            'signatures': [{'sig': 'AA=='}],
        })

    def test_verify_rejects_before_touching_any_verifier(self):
        verifier = _RecordingVerifier()
        cases = [
            ('a' * (ss.MAX_TYPE_BYTES + 1), b''),
            ('ok', b'\x00' * (ss.MAX_PAYLOAD_BYTES + 1)),
            ('bad\udfff surrogate', b''),
        ]
        for payload_type, body in cases:
            with self.subTest(payload_type=payload_type[:3], len=len(body)):
                with self.assertRaises(ss.PAEError):
                    ss.Verify(self._envelope(payload_type, body),
                              [('k', verifier)])
        self.assertEqual(verifier.verified_messages, [])

    def test_verify_rejects_wrong_json_field_types(self):
        with self.assertRaises(ss.PAEError):
            ss.Verify(json.dumps({
                'payload': 'AA==',
                'payloadType': 123,
                'signatures': [],
            }), [])
        with self.assertRaises(ss.PAEError):
            ss.Verify(json.dumps({
                'payload': 123,
                'payloadType': 'ok',
                'signatures': [],
            }), [])

    def test_verify_accepts_binary_payload_and_preserves_bytes(self):
        body = bytes([0, 1, 2, 11, 255, 255, 0])
        verifier = _RecordingVerifier()
        result = ss.Verify(
            self._envelope('application/octet-stream', body),
            [('mykey', verifier)])
        self.assertEqual(result.payload, body)
        self.assertEqual(
            verifier.verified_messages,
            [ss.PAE('application/octet-stream', body)])


def load_tests(loader, tests, ignore):
    # Only the standalone PAE docstring runs without pycryptodome; the
    # end-to-end signing examples in the module docstring need ecdsa.py.
    finder = doctest.DocTestFinder()
    for test in finder.find(ss):
        if test.name == '%s.PAE' % ss.__name__:
            tests.addTest(doctest.DocTestCase(
                test, optionflags=doctest.ELLIPSIS))
    return tests


if __name__ == '__main__':
    unittest.main(verbosity=2)
