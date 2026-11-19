r"""Fixed tests for signing_spec.Verify identity handling.

The signer identity reported by Verify must be decided jointly by:

1. the trusted (name, verifier) source entry that performed the verification,
2. the trusted verifier's keyid,
3. the (unauthenticated) keyid hint carried by the envelope, and
4. the exact signature bytes from the envelope.

These tests use checked-in, deterministic fixtures (see
``fixtures/generate_fixtures.py``) and compare both the trusted source and the
raw signature result. Run with::

    python3 -m pytest test_verify.py
"""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import ecdsa
from signing_spec import Sign, Verify

HERE = os.path.dirname(__file__)
FIXTURES = os.path.join(HERE, 'fixtures')

SIGNER_A = ecdsa.Signer.construct(
    curve='P-256',
    d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
    point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
    point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)

# Fixed key B: d = SHA256(b'dsse-fixed-key-B-seed-v1') reduced mod the P-256
# order, then +1. The full coordinates are recorded in the fixture generator.
SIGNER_B = ecdsa.Signer.construct(
    curve='P-256',
    d=75002936671790620084666985758187467519637777847128398193958539958218240600044,
    point_x=106001429014846879170083702026853737228471439704857873196952114129888402175342,
    point_y=81870907312626483622242293968843383799885751114593003242789886220364536897450)

VERIFIER_A = ecdsa.Verifier(SIGNER_A.public_key)
VERIFIER_B = ecdsa.Verifier(SIGNER_B.public_key)
KEYID_A = VERIFIER_A.keyid()
KEYID_B = VERIFIER_B.keyid()


class KeylessVerifier:
    """Wraps a verifier while reporting no keyid, as a keyless source would."""

    def __init__(self, inner):
        self.inner = inner

    def verify(self, message, signature):
        return self.inner.verify(message, signature)

    def keyid(self):
        return None


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as f:
        return f.read().strip()


def fixture_sig(name, index=0):
    wrapper = json.loads(fixture(name))
    return base64.b64decode(wrapper['signatures'][index]['sig'])


def test_fixtures_are_deterministic_and_complete():
    # The checked-in signature bytes must equal what the fixed source keys
    # produce deterministically, pinning both the source and the signature.
    regenerated_a = json.loads(Sign(
        'http://example.com/HelloWorld', b'hello world', SIGNER_A))
    regenerated_b = json.loads(Sign(
        'http://example.com/HelloWorld', b'hello world', SIGNER_B))
    assert KEYID_A == '66301bbf'
    assert KEYID_B == '361ff22d'
    assert regenerated_a['signatures'][0]['sig'] == json.loads(
        fixture('envelope_a_signed.json'))['signatures'][0]['sig']
    assert regenerated_b['signatures'][0]['sig'] == json.loads(
        fixture('envelope_b_signed.json'))['signatures'][0]['sig']

    expected = {
        'envelope_a_signed.json',
        'envelope_a_keyid_swapped.json',
        'envelope_a_keyid_missing.json',
        'envelope_a_keyid_empty.json',
        'envelope_a_sig_tampered.json',
        'envelope_b_signed.json',
        'envelope_multi_signed.json',
    }
    assert expected.issubset(set(os.listdir(FIXTURES)))


def test_recognized_signer_is_bound_to_source_keyid_and_bytes():
    result = Verify(fixture('envelope_a_signed.json'),
                    [('alice', VERIFIER_A), ('bob', VERIFIER_B)])
    assert len(result.recognizedSigners) == 1
    info = result.recognizedSigners[0]
    assert info.source == 'alice'
    assert info.keyid == KEYID_A
    assert info.envelopeKeyid == KEYID_A
    assert info.signature == fixture_sig('envelope_a_signed.json')
    assert info.aliases == ()


def test_keyid_swap_cannot_hang_signature_on_another_identity():
    # The swapped keyid matches no trusted key, so the signature must not be
    # recognized under any name -- including a keyless catch-all source.
    verifiers = [
        ('alice', VERIFIER_A),
        ('catch-all', KeylessVerifier(VERIFIER_A)),
    ]
    with pytest.raises(ValueError, match='No valid signature found'):
        Verify(fixture('envelope_a_keyid_swapped.json'), verifiers)


def test_unknown_keyid_never_grants_trust():
    # An unrecognized keyid plus an unknown signature cannot elevate trust.
    with pytest.raises(ValueError, match='No valid signature found'):
        Verify(fixture('envelope_a_keyid_swapped.json'),
               [('bob', VERIFIER_B)])


def test_unrecognized_signature_is_audit_only_not_trusted():
    # A mixed envelope: one trusted signature plus one whose keyid was
    # replaced. The envelope verifies, but the replaced signature stays out of
    # recognizedSigners and is preserved as audit-only evidence.
    good = json.loads(fixture('envelope_a_signed.json'))
    swapped = json.loads(fixture('envelope_a_keyid_swapped.json'))
    good['signatures'].append(swapped['signatures'][0])
    result = Verify(json.dumps(good), [('alice', VERIFIER_A)])

    assert len(result.recognizedSigners) == 1
    assert result.recognizedSigners[0].source == 'alice'

    assert len(result.unrecognizedSignatures) == 1
    rejected = result.unrecognizedSignatures[0]
    assert rejected.envelopeKeyid == 'deadbeef'
    assert rejected.signature == fixture_sig('envelope_a_keyid_swapped.json')
    assert rejected.reason == (
        'no trusted verifier matches the envelope keyid')


def test_invalid_signature_is_audited_with_crypto_reason():
    # The keyid selects a trusted key but the signature bytes do not verify.
    # Pair the tampered signature with a valid one so Verify still returns.
    good = json.loads(fixture('envelope_a_signed.json'))
    tampered = json.loads(fixture('envelope_a_sig_tampered.json'))
    good['signatures'].append(tampered['signatures'][0])
    result = Verify(json.dumps(good), [('alice', VERIFIER_A)])

    assert [info.source for info in result.recognizedSigners] == ['alice']
    assert len(result.unrecognizedSignatures) == 1
    rejected = result.unrecognizedSignatures[0]
    assert rejected.envelopeKeyid == KEYID_A
    assert rejected.signature == fixture_sig('envelope_a_sig_tampered.json')
    assert rejected.reason == 'signature failed cryptographic verification'


def test_missing_or_empty_keyid_equivalent_and_auditable():
    for name in ('envelope_a_keyid_missing.json',
                 'envelope_a_keyid_empty.json'):
        # A keyed verifier does not match an envelope with no keyid claim...
        with pytest.raises(ValueError, match='No valid signature found'):
            Verify(fixture(name), [('alice', VERIFIER_A)])
        # ...but a keyless trusted source does, and the absent hint is
        # preserved as None for auditing.
        result = Verify(fixture(name),
                        [('keyless-alice', KeylessVerifier(VERIFIER_A))])
        info = result.recognizedSigners[0]
        assert info.source == 'keyless-alice'
        assert info.keyid is None
        assert info.envelopeKeyid is None
        assert info.signature == fixture_sig(name)


def test_rename_or_duplicate_source_does_not_inflate_trust():
    result = Verify(fixture('envelope_a_signed.json'),
                    [('alice', VERIFIER_A),
                     ('alice-renamed', ecdsa.Verifier(SIGNER_A.public_key))])
    assert len(result.recognizedSigners) == 1
    info = result.recognizedSigners[0]
    # Trusted identity stays anchored to the first (deterministic) source...
    assert info.source == 'alice'
    assert info.keyid == KEYID_A
    # ...while the historical/renamed name remains auditable as an alias,
    # without counting as a second unique trusted key.
    assert info.aliases == ('alice-renamed',)
    assert info.signature == fixture_sig('envelope_a_signed.json')


def test_tampered_signature_is_rejected_even_with_matching_keyid():
    with pytest.raises(ValueError, match='No valid signature found'):
        Verify(fixture('envelope_a_sig_tampered.json'),
               [('alice', VERIFIER_A)])


def test_distinct_trusted_keys_produce_distinct_recognized_signers():
    result = Verify(fixture('envelope_multi_signed.json'),
                    [('alice', VERIFIER_A), ('bob', VERIFIER_B)])
    assert len(result.recognizedSigners) == 2
    by_keyid = {info.keyid: info for info in result.recognizedSigners}
    assert set(by_keyid) == {KEYID_A, KEYID_B}
    assert by_keyid[KEYID_A].source == 'alice'
    assert by_keyid[KEYID_B].source == 'bob'
    assert by_keyid[KEYID_A].signature == fixture_sig(
        'envelope_multi_signed.json', 0)
    assert by_keyid[KEYID_B].signature == fixture_sig(
        'envelope_multi_signed.json', 1)


def test_untrusted_key_signature_is_not_recognized():
    # Key B signs, but only key A is trusted: no recognized signer.
    with pytest.raises(ValueError, match='No valid signature found'):
        Verify(fixture('envelope_b_signed.json'), [('alice', VERIFIER_A)])


def test_envelope_keyid_hint_is_recorded_but_not_trusted():
    # On acceptance the unauthenticated hint is recorded verbatim for audit
    # while the trusted identity still comes from the verifier source.
    result = Verify(fixture('envelope_a_signed.json'),
                    [('alice', VERIFIER_A)])
    info = result.recognizedSigners[0]
    wrapper = json.loads(fixture('envelope_a_signed.json'))
    assert info.envelopeKeyid == wrapper['signatures'][0]['keyid'] == KEYID_A
    assert info.source == 'alice'

    # A foreign hint survives in the envelope but never becomes an identity.
    swapped = json.loads(fixture('envelope_a_keyid_swapped.json'))
    assert swapped['signatures'][0]['keyid'] == 'deadbeef'
