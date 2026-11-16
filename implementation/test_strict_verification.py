"""Tests for the strict DSSE verification policy.

Run with:
    python -m unittest discover -s implementation -p 'test_*.py' -v
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ecdsa
from signing_spec import PAE, Sign, Verify, b64enc
from strict_verification import (
    DEFAULT_MAX_PAE_BYTES,
    StrictVerificationPolicy,
    VerificationError,
    VerifyStrict,
)

# Sentinel: use the signer's own keyid / produce a real signature.
USE_SIGNER = object()
# Sentinel: omit the keyid field entirely.
OMIT_KEYID = object()


def make_envelope(payload_type, payload, signer_keyid_sig_triples):
    """Builds a JSON envelope from (signer, keyid_override, sig_override).

    A `keyid_override` of OMIT_KEYID omits the keyid field entirely;
    USE_SIGNER keeps the signer's own keyid; any string overrides it. A
    `sig_override` of USE_SIGNER produces a real signature, otherwise the
    given raw bytes are encoded as-is.
    """
    signatures = []
    for signer, keyid_override, sig_override in signer_keyid_sig_triples:
        raw_sig = (signer.sign(PAE(payload_type, payload))
                   if sig_override is USE_SIGNER else sig_override)
        entry = {'sig': b64enc(raw_sig)}
        if keyid_override is not OMIT_KEYID:
            entry['keyid'] = (signer.keyid()
                              if keyid_override is USE_SIGNER
                              else keyid_override)
        signatures.append(entry)
    return json.dumps({
        'payload': b64enc(payload),
        'payloadType': payload_type,
        'signatures': signatures,
    })


class KeylessVerifier:
    """Verifier whose keyid() returns None, simulating a key without an ID."""

    def __init__(self, delegate):
        self._delegate = delegate

    def verify(self, message, signature):
        return self._delegate.verify(message, signature)

    def keyid(self):
        return None


class RaisingVerifier:
    """Verifier that raises instead of returning a boolean."""

    def keyid(self):
        return 'raising'

    def verify(self, message, signature):
        raise RuntimeError('verifier exploded')


class StrictVerificationTest(unittest.TestCase):

    def setUp(self):
        self.payload_type = 'http://example.com/HelloWorld'
        self.payload = b'hello world'

        self.signers = [
            ecdsa.Signer.generate(curve='P-256') for _ in range(3)
        ]
        self.verifiers = [
            ('signer-%d' % idx, ecdsa.Verifier(signer.public_key))
            for idx, signer in enumerate(self.signers)
        ]
        self.keyids = [verifier.keyid() for _, verifier in self.verifiers]

    def _policy(self, **kwargs):
        params = {'verifiers': self.verifiers, 'threshold': 1}
        params.update(kwargs)
        return StrictVerificationPolicy(**params)

    def _single_sig_envelope(self, signer_index=0,
                             keyid_override=USE_SIGNER):
        return make_envelope(
                self.payload_type, self.payload,
                [(self.signers[signer_index], keyid_override,
                  USE_SIGNER)])

    # ---- Happy paths ---------------------------------------------------

    def test_valid_single_signature(self):
        envelope = Sign(self.payload_type, self.payload, self.signers[0])
        result = VerifyStrict(envelope, self._policy())
        self.assertEqual(result.payloadType, self.payload_type)
        self.assertEqual(result.payload, self.payload)
        self.assertEqual(result.recognizedSigners, ['signer-0'])

    def test_valid_multi_signature_meets_threshold(self):
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], USE_SIGNER, USE_SIGNER),
            (self.signers[1], USE_SIGNER, USE_SIGNER),
        ])
        result = VerifyStrict(envelope, self._policy(threshold=2))
        self.assertEqual(result.recognizedSigners,
                         ['signer-0', 'signer-1'])

    def test_recognized_signers_deduplicated_by_signer_name(self):
        # Two verifier entries with the same name but different keyids both
        # validate; the name must only appear once.
        shared_name_verifiers = [
            ('shared', self.verifiers[0][1]),
            ('shared', self.verifiers[1][1]),
        ]
        policy = StrictVerificationPolicy(
                verifiers=shared_name_verifiers, threshold=1)
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], USE_SIGNER, USE_SIGNER),
            (self.signers[1], USE_SIGNER, USE_SIGNER),
        ])
        result = VerifyStrict(envelope, policy)
        self.assertEqual(result.recognizedSigners, ['shared'])

    # ---- keyid handling ------------------------------------------------

    def test_missing_keyid_is_rejected(self):
        envelope = self._single_sig_envelope(keyid_override=OMIT_KEYID)
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy())

    def test_empty_keyid_is_rejected(self):
        envelope = self._single_sig_envelope(keyid_override='')
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy())

    def test_mismatched_keyid_is_rejected(self):
        envelope = self._single_sig_envelope(
                keyid_override='unknown-keyid')
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy())

    def test_verifier_without_keyid_cannot_be_configured(self):
        with self.assertRaises(VerificationError):
            StrictVerificationPolicy(
                    verifiers=[('keyless',
                                KeylessVerifier(self.verifiers[0][1]))])

    def test_duplicate_verifier_keyid_cannot_be_configured(self):
        duplicated = [
            ('a', self.verifiers[0][1]),
            ('b', self.verifiers[0][1]),
        ]
        with self.assertRaises(VerificationError):
            StrictVerificationPolicy(verifiers=duplicated)

    # ---- Duplicate signatures ------------------------------------------

    def test_duplicate_keyid_in_envelope_is_rejected(self):
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], self.keyids[0], USE_SIGNER),
            (self.signers[0], self.keyids[0], USE_SIGNER),
        ])
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy())

    # ---- Threshold ------------------------------------------------------

    def test_threshold_not_met_is_rejected(self):
        envelope = self._single_sig_envelope()
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy(threshold=2))

    def test_threshold_larger_than_verifiers_cannot_be_configured(self):
        with self.assertRaises(VerificationError):
            self._policy(threshold=len(self.verifiers) + 1)

    # ---- Malformed signatures (fail closed) ----------------------------

    def test_invalid_signature_base64_is_rejected(self):
        wrapper = json.loads(self._single_sig_envelope())
        wrapper['signatures'][0]['sig'] = '!!!not-base64!!!'
        with self.assertRaises(VerificationError):
            VerifyStrict(json.dumps(wrapper), self._policy())

    def test_signature_that_does_not_verify_is_rejected(self):
        bogus = b'X' * 64  # well-formed length, but wrong signature
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], USE_SIGNER, bogus),
        ])
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy())

    def test_verifier_exception_fails_closed(self):
        policy = StrictVerificationPolicy(
                verifiers=[('raising', RaisingVerifier())])
        wrapper = json.loads(self._single_sig_envelope())
        wrapper['signatures'][0]['keyid'] = 'raising'
        with self.assertRaises(VerificationError):
            VerifyStrict(json.dumps(wrapper), policy)

    def test_malformed_json_is_rejected(self):
        with self.assertRaises(VerificationError):
            VerifyStrict('{not valid json', self._policy())

    def test_missing_signatures_field_is_rejected(self):
        wrapper = {
            'payload': b64enc(self.payload),
            'payloadType': self.payload_type,
        }
        with self.assertRaises(VerificationError):
            VerifyStrict(json.dumps(wrapper), self._policy())

    # ---- Resource budgets ----------------------------------------------

    def test_payload_over_budget_is_rejected(self):
        policy = self._policy(max_payload_bytes=8)
        envelope = Sign(self.payload_type, self.payload, self.signers[0])
        self.assertGreater(len(self.payload), 8)
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, policy)

    def test_pae_over_budget_is_rejected(self):
        # PAE is always slightly larger than the payload, so a budget
        # between the two sizes must trip the PAE check (and be allowed by
        # the policy's consistency validation).
        pae = PAE(self.payload_type, self.payload)
        policy = self._policy(
                max_payload_bytes=len(self.payload),
                max_pae_bytes=len(pae) - 1)
        envelope = Sign(self.payload_type, self.payload, self.signers[0])
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, policy)

    def test_envelope_over_budget_is_rejected(self):
        envelope = Sign(self.payload_type, self.payload, self.signers[0])
        policy = self._policy(max_envelope_bytes=len(envelope) - 1)
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, policy)

    def test_too_many_signatures_is_rejected(self):
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], self.keyids[0], USE_SIGNER),
            (self.signers[1], self.keyids[1], USE_SIGNER),
        ])
        with self.assertRaises(VerificationError):
            VerifyStrict(envelope, self._policy(max_signatures=1))

    def test_default_pae_budget_constant_is_sane(self):
        self.assertGreater(DEFAULT_MAX_PAE_BYTES, 0)

    # ---- Legacy behavior stays unchanged -------------------------------

    def test_legacy_verify_still_accepts_matching_signature(self):
        # The legacy Verify accepts the first valid signature; strict mode
        # is an additive layer and must not change this behavior.
        envelope = self._single_sig_envelope(
                keyid_override=self.keyids[0])
        result = Verify(envelope, self.verifiers)
        self.assertEqual(result.recognizedSigners, ['signer-0'])

    def test_legacy_verify_still_counts_duplicate_signers(self):
        envelope = make_envelope(self.payload_type, self.payload, [
            (self.signers[0], USE_SIGNER, USE_SIGNER),
            (self.signers[0], USE_SIGNER, USE_SIGNER),
        ])
        result = Verify(envelope, self.verifiers)
        self.assertEqual(result.recognizedSigners,
                         ['signer-0', 'signer-0'])


if __name__ == '__main__':
    unittest.main()
