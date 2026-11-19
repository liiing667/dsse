r"""Fixed resource-limit matrix for signing_spec.Verify.

Each matrix row maps a synthesized envelope and a ResourceLimits budget to
either a rejection category (ResourceLimitExceeded.category) or a pass
result. Run with: python3 test_resource_limits.py
"""

import dataclasses
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ecdsa
from signing_spec import (
    DEFAULT_LIMITS,
    ResourceLimitExceeded,
    ResourceLimits,
    Sign,
    Verify,
    b64enc,
)

PASS = 'pass'

SIGNER = ecdsa.Signer.construct(
    curve='P-256',
    d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
    point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
    point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)
VERIFIERS = [('mykey', ecdsa.Verifier(SIGNER.public_key))]

PAYLOAD_TYPE = 'http://example.com/HelloWorld'
PAYLOAD = b'hello world'


def good_envelope():
    return Sign(PAYLOAD_TYPE, PAYLOAD, SIGNER)


def envelope_with_signatures(count):
    wrapper = json.loads(good_envelope())
    wrapper['signatures'] = wrapper['signatures'] * count
    return json.dumps(wrapper)


def envelope_with_payload(payload):
    wrapper = json.loads(good_envelope())
    wrapper['payload'] = b64enc(payload)
    return json.dumps(wrapper)


def envelope_with_payload_type(payload_type):
    wrapper = json.loads(good_envelope())
    wrapper['payloadType'] = payload_type
    return json.dumps(wrapper)


def envelope_with_extra_depth(depth):
    # Splice the nesting in textually: json.dumps would itself hit the
    # recursion limit on pathologically deep structures.
    text = good_envelope()
    deep = '[' * depth + '0' + ']' * depth
    return text[:-1] + ',"extra":' + deep + '}'


def limits(**overrides):
    return dataclasses.replace(DEFAULT_LIMITS, **overrides)


# (name, envelope factory, limits, expected): expected is PASS or a
# ResourceLimitExceeded category.
MATRIX = [
    # Normal synthesized samples pass, even against exact-fit budgets.
    ('baseline valid envelope',
     good_envelope, DEFAULT_LIMITS, PASS),
    ('signature count exactly at budget',
     lambda: envelope_with_signatures(4), limits(max_signatures=4), PASS),
    ('payload size exactly at budget',
     lambda: envelope_with_payload(PAYLOAD), limits(max_payload_size=len(PAYLOAD)), PASS),
    ('payloadType length exactly at budget',
     lambda: envelope_with_payload_type(PAYLOAD_TYPE),
     limits(max_payload_type_length=len(PAYLOAD_TYPE)), PASS),
    ('json depth exactly at budget',
     good_envelope, limits(max_json_depth=3), PASS),

    # Over-budget envelopes are rejected with a visible category.
    ('too many signatures',
     lambda: envelope_with_signatures(5), limits(max_signatures=4), 'signatures'),
    ('oversized payload',
     lambda: envelope_with_payload(b'A' * 1025),
     limits(max_payload_size=1024), 'payload_size'),
    ('oversized payloadType',
     lambda: envelope_with_payload_type('x' * 33),
     limits(max_payload_type_length=32), 'payload_type_length'),
    ('json too deep',
     lambda: envelope_with_extra_depth(10), limits(max_json_depth=8), 'json_depth'),
    ('json far too deep for the parser',
     lambda: envelope_with_extra_depth(100000), DEFAULT_LIMITS, 'json_depth'),
]


class TestResourceLimits(unittest.TestCase):

    def test_matrix(self):
        for name, make_envelope, limit, expected in MATRIX:
            with self.subTest(name=name):
                envelope = make_envelope()
                if expected == PASS:
                    result = Verify(envelope, VERIFIERS, limit)
                    self.assertEqual(result.payloadType, PAYLOAD_TYPE)
                    self.assertEqual(result.payload, PAYLOAD)
                    self.assertEqual(set(result.recognizedSigners), {'mykey'})
                else:
                    with self.assertRaises(ResourceLimitExceeded) as ctx:
                        Verify(envelope, VERIFIERS, limit)
                    self.assertEqual(ctx.exception.category, expected)

    def test_no_partial_results_on_rejection(self):
        # A rejected envelope yields no VerifiedPayload at all, even though
        # it carries an otherwise valid signature.
        envelope = envelope_with_signatures(DEFAULT_LIMITS.max_signatures + 1)
        with self.assertRaises(ResourceLimitExceeded):
            Verify(envelope, VERIFIERS)

    def test_invalid_signature_still_rejected_as_before(self):
        wrapper = json.loads(good_envelope())
        wrapper['signatures'][0]['sig'] = b64enc(b'forged')
        with self.assertRaises(ValueError):
            Verify(json.dumps(wrapper), VERIFIERS)


if __name__ == '__main__':
    unittest.main()
