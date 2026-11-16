r"""Strict verification policy for DSSE envelopes.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

This module adds a strict, fail-closed verification layer on top of the
reference implementation in `signing_spec.py`. The legacy `Verify` function is
intentionally left untouched; use `VerifyStrict` together with a
`StrictVerificationPolicy` when the following guarantees are required:

*   Every configured verifier must expose a non-empty, unique `keyid`, and
    every envelope signature must carry a `keyid` that matches exactly one
    configured verifier. A missing, empty, or unknown `keyid` is rejected.
*   Duplicate `keyid` values inside one envelope are rejected.
*   Valid signers are de-duplicated by signer name and a minimum threshold of
    distinct valid signers must be met.
*   Resource budgets cap the raw envelope size, decoded payload size, PAE
    size, and number of signatures.
*   Malformed envelopes/signatures (invalid JSON, invalid base64, verifier
    exceptions, or signatures that do not verify) always fail closed with
    `VerificationError`.

Example:

>>> import os, sys
>>> sys.path.insert(0, os.path.dirname(__file__))
>>> import ecdsa
>>> signer = ecdsa.Signer.generate(curve='P-256')
>>> verifier = ecdsa.Verifier(signer.public_key)
>>> policy = StrictVerificationPolicy(
...     verifiers=[('mykey', verifier)], threshold=1)
>>> signature_json = Sign('http://example.com/HelloWorld', b'hello', signer)
>>> result = VerifyStrict(signature_json, policy)
>>> result.recognizedSigners
['mykey']
"""

import binascii
import dataclasses
import json
from typing import Dict, List, Tuple

from signing_spec import (
    PAE,
    Sign,
    VerifiedPayload,
    Verifier,
    VerifierList,
    b64dec,
)


# Default resource budgets. Applications should tune these to their own
# threat model; the defaults only provide conservative upper bounds.
DEFAULT_MAX_ENVELOPE_BYTES = 1 * 1024 * 1024   # 1 MiB raw JSON envelope
DEFAULT_MAX_PAYLOAD_BYTES = 256 * 1024         # 256 KiB decoded payload
DEFAULT_MAX_PAE_BYTES = 2 * 1024 * 1024        # 2 MiB pre-auth encoding
DEFAULT_MAX_SIGNATURES = 100


class VerificationError(ValueError):
    """Raised whenever strict verification fails.

    Subclasses `ValueError` so callers can keep catching `ValueError`, the
    exception type used by the legacy `Verify` function.
    """


@dataclasses.dataclass(frozen=True)
class StrictVerificationPolicy:
    """Configuration for `VerifyStrict`.

    Attributes:
        verifiers: Trusted (name, verifier) pairs. Every verifier must expose
            a non-empty, unique `keyid`.
        threshold: Minimum number of distinct valid signers required.
        max_envelope_bytes: Maximum accepted size of the raw JSON envelope.
        max_payload_bytes: Maximum accepted size of the decoded payload.
        max_pae_bytes: Maximum accepted size of the PAE passed to verifiers.
        max_signatures: Maximum number of signature entries in an envelope.
    """

    verifiers: VerifierList
    threshold: int = 1
    max_envelope_bytes: int = DEFAULT_MAX_ENVELOPE_BYTES
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    max_pae_bytes: int = DEFAULT_MAX_PAE_BYTES
    max_signatures: int = DEFAULT_MAX_SIGNATURES

    def __post_init__(self) -> None:
        # `frozen=True` dataclasses need object.__setattr__ for normalization.
        object.__setattr__(self, 'verifiers', tuple(self.verifiers))

        if not self.verifiers:
            raise VerificationError('At least one verifier is required')
        if self.threshold < 1:
            raise VerificationError('threshold must be >= 1')
        if self.threshold > len(self.verifiers):
            raise VerificationError(
                    'threshold %d exceeds the number of configured '
                    'verifiers (%d)' % (self.threshold, len(self.verifiers)))
        for name, verifier in self.verifiers:
            if not isinstance(name, str) or not name:
                raise VerificationError(
                        'Verifier names must be non-empty strings')
            keyid = verifier.keyid()
            if not isinstance(keyid, str) or not keyid:
                raise VerificationError(
                        'Strict mode requires a non-empty keyid for '
                        'verifier %r' % name)
        keyids = [verifier.keyid() for _, verifier in self.verifiers]
        if len(set(keyids)) != len(keyids):
            raise VerificationError(
                    'Duplicate keyid among configured verifiers')

        for field_name in ('max_envelope_bytes', 'max_payload_bytes',
                           'max_pae_bytes', 'max_signatures'):
            if getattr(self, field_name) < 1:
                raise VerificationError(
                        '%s must be >= 1' % field_name)
        if self.max_pae_bytes < self.max_payload_bytes:
            raise VerificationError(
                    'max_pae_bytes must be >= max_payload_bytes')

    def keyid_map(self) -> Dict[str, Tuple[str, Verifier]]:
        """Returns the configured verifiers indexed by their keyid."""
        return {verifier.keyid(): (name, verifier)
                for name, verifier in self.verifiers}


def VerifyStrict(json_signature: str,
                 policy: StrictVerificationPolicy) -> VerifiedPayload:
    """Verifies a DSSE envelope under a strict, fail-closed policy.

    Raises `VerificationError` on any policy violation, malformed input,
    resource-budget overflow, or invalid signature.
    """
    raw_envelope = (json_signature.encode('utf-8')
                    if isinstance(json_signature, str)
                    else json_signature)
    if not isinstance(raw_envelope, (bytes, bytearray)):
        raise VerificationError(
                'Envelope must be a JSON string or byte sequence')
    if len(raw_envelope) > policy.max_envelope_bytes:
        raise VerificationError(
                'Envelope exceeds max_envelope_bytes budget (%d > %d)'
                % (len(raw_envelope), policy.max_envelope_bytes))

    try:
        wrapper = json.loads(json_signature)
    except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
        raise VerificationError('Malformed envelope: invalid JSON') from exc
    if not isinstance(wrapper, dict):
        raise VerificationError(
                'Malformed envelope: top-level value must be a JSON object')

    payload_type = wrapper.get('payloadType')
    if not isinstance(payload_type, str):
        raise VerificationError(
                'Malformed envelope: missing or invalid payloadType')
    encoded_payload = wrapper.get('payload')
    if not isinstance(encoded_payload, str):
        raise VerificationError(
                'Malformed envelope: missing or invalid payload')
    signatures = wrapper.get('signatures')
    if not isinstance(signatures, list) or not signatures:
        raise VerificationError(
                'Malformed envelope: signatures must be a non-empty list')
    if len(signatures) > policy.max_signatures:
        raise VerificationError(
                'Number of signatures (%d) exceeds max_signatures (%d)'
                % (len(signatures), policy.max_signatures))

    try:
        payload = b64dec(encoded_payload)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(
                'Malformed envelope: invalid payload base64 encoding'
                ) from exc
    if len(payload) > policy.max_payload_bytes:
        raise VerificationError(
                'Payload exceeds max_payload_bytes budget (%d > %d)'
                % (len(payload), policy.max_payload_bytes))

    pae = PAE(payload_type, payload)
    if len(pae) > policy.max_pae_bytes:
        raise VerificationError(
                'PAE exceeds max_pae_bytes budget (%d > %d)'
                % (len(pae), policy.max_pae_bytes))

    keyid_to_verifier = policy.keyid_map()
    seen_keyids = set()
    recognized_signers = []
    recognized_names = set()

    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            raise VerificationError(
                    'Malformed signature at index %d: not a JSON object'
                    % index)
        encoded_sig = signature.get('sig')
        if not isinstance(encoded_sig, str):
            raise VerificationError(
                    'Malformed signature at index %d: missing or invalid '
                    'sig field' % index)

        # The envelope spec treats an unset keyid and an empty keyid the
        # same; strict mode requires an explicit match, so reject both.
        keyid = signature.get('keyid')
        if not isinstance(keyid, str) or not keyid:
            raise VerificationError(
                    'Signature at index %d is missing a keyid' % index)
        if keyid in seen_keyids:
            raise VerificationError(
                    'Duplicate keyid %r in envelope' % keyid)
        seen_keyids.add(keyid)

        match = keyid_to_verifier.get(keyid)
        if match is None:
            raise VerificationError(
                    'No configured verifier matches keyid %r' % keyid)
        name, verifier = match

        try:
            raw_signature = b64dec(encoded_sig)
        except (binascii.Error, ValueError) as exc:
            raise VerificationError(
                    'Malformed signature for keyid %r: invalid base64 '
                    'encoding' % keyid) from exc

        try:
            is_valid = verifier.verify(pae, raw_signature)
        except VerificationError:
            raise
        except Exception as exc:
            raise VerificationError(
                    'Verifier for keyid %r raised an exception' % keyid
                    ) from exc
        if not is_valid:
            raise VerificationError(
                    'Signature verification failed for keyid %r' % keyid)

        # De-duplicate valid signers by signer name.
        if name not in recognized_names:
            recognized_names.add(name)
            recognized_signers.append(name)

    if len(recognized_signers) < policy.threshold:
        raise VerificationError(
                'Signature threshold not met: %d distinct valid signer(s), '
                'need %d' % (len(recognized_signers), policy.threshold))

    return VerifiedPayload(payload_type, payload, recognized_signers)
