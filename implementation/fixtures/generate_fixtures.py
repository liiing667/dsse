r"""Deterministic fixture generator for signing_spec.Verify.

Run from the implementation directory::

    python3 fixtures/generate_fixtures.py

All material is derived from two fixed P-256 keys, so regenerating the
fixtures produces byte-identical output. The fixtures are checked in and
compared byte-for-byte by ``test_verify.py``; this script documents exactly
how they were produced.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import ecdsa
from signing_spec import Sign

PAYLOAD_TYPE = 'http://example.com/HelloWorld'
PAYLOAD = b'hello world'

# Fixed key A, identical to the vector in signing_spec.py.
SIGNER_A = ecdsa.Signer.construct(
    curve='P-256',
    d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
    point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
    point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)

# Fixed key B, derived deterministically from the seed documented in the test.
SIGNER_B = ecdsa.Signer.construct(
    curve='P-256',
    d=75002936671790620084666985758187467519637777847128398193958539958218240600044,
    point_x=106001429014846879170083702026853737228471439704857873196952114129888402175342,
    point_y=81870907312626483622242293968843383799885751114593003242789886220364536897450)


def _write(name, envelope):
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(envelope)
        f.write('\n')


def main():
    # Canonical envelope signed by key A, including its real keyid.
    signed_a = Sign(PAYLOAD_TYPE, PAYLOAD, SIGNER_A)
    _write('envelope_a_signed.json', signed_a)

    envelope = json.loads(signed_a)

    # Attacker replaces the unauthenticated keyid hint with another value.
    swapped = json.loads(signed_a)
    swapped['signatures'][0]['keyid'] = 'deadbeef'
    _write('envelope_a_keyid_swapped.json', json.dumps(swapped))

    # Envelope keyid removed (equivalent to empty per envelope.md).
    missing = json.loads(signed_a)
    del missing['signatures'][0]['keyid']
    _write('envelope_a_keyid_missing.json', json.dumps(missing))

    # Envelope keyid explicitly empty.
    empty = json.loads(signed_a)
    empty['signatures'][0]['keyid'] = ''
    _write('envelope_a_keyid_empty.json', json.dumps(empty))

    # Signature bytes tampered with; the keyid still claims key A.
    tampered = json.loads(signed_a)
    import base64
    raw = bytearray(base64.b64decode(tampered['signatures'][0]['sig']))
    raw[0] ^= 0x01
    tampered['signatures'][0]['sig'] = base64.standard_b64encode(
        bytes(raw)).decode('utf-8')
    _write('envelope_a_sig_tampered.json', json.dumps(tampered))

    # Legitimately signed by the second trusted key B.
    signed_b = Sign(PAYLOAD_TYPE, PAYLOAD, SIGNER_B)
    _write('envelope_b_signed.json', signed_b)

    # Multi-signature envelope: both trusted keys sign the same PAE.
    multi = json.loads(signed_a)
    multi['signatures'].append(json.loads(signed_b)['signatures'][0])
    _write('envelope_multi_signed.json', json.dumps(multi))

    print('key A keyid:', ecdsa.Verifier(SIGNER_A.public_key).keyid())
    print('key B keyid:', ecdsa.Verifier(SIGNER_B.public_key).keyid())


if __name__ == '__main__':
    main()
