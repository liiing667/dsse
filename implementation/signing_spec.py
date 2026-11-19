r"""Reference implementation of signing-spec.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

The following example requires `pip3 install pycryptodome` and uses ecdsa.py in
the same directory as this file.

>>> import os, sys
>>> from pprint import pprint
>>> sys.path.insert(0, os.path.dirname(__file__))
>>> import ecdsa

>>> signer = ecdsa.Signer.construct(
...     curve='P-256',
...     d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
...     point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
...     point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)
>>> verifier = ecdsa.Verifier(signer.public_key)
>>> payloadType = 'http://example.com/HelloWorld'
>>> payload = b'hello world'

Signing example:

>>> signature_json = Sign(payloadType, payload, signer)
>>> pprint(json.loads(signature_json))
{'payload': 'aGVsbG8gd29ybGQ=',
 'payloadType': 'http://example.com/HelloWorld',
 'signatures': [{'keyid': '66301bbf',
                 'sig': 'A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=='}]}

Verification example:

>>> result = Verify(signature_json, [('mykey', verifier)])
>>> print(result.payloadType)
http://example.com/HelloWorld
>>> print(result.payload)
b'hello world'
>>> signer_info = result.recognizedSigners[0]
>>> print(signer_info.source, signer_info.keyid, signer_info.envelopeKeyid)
mykey 66301bbf 66301bbf
>>> print(len(signer_info.signature), signer_info.aliases)
64 ()

The keyid in the envelope is unauthenticated. Renaming a trusted key,
registering the same key twice, or replacing the envelope keyid MUST NOT
attach a signature to a different identity or inflate the trust:

>>> result = Verify(signature_json,
...                 [('mykey', verifier), ('renamed-key', verifier)])
>>> len(result.recognizedSigners)
1
>>> print(result.recognizedSigners[0].source)
mykey
>>> print(result.recognizedSigners[0].aliases)
('renamed-key',)

>>> import json
>>> tampered = json.loads(signature_json)
>>> tampered['signatures'][0]['keyid'] = 'deadbeef'

An unknown/renamed keyid never grants trust. A mixed envelope (one trusted,
one unrecognized) still verifies, while the unrecognized signature is retained
as audit-only evidence and is excluded from recognizedSigners:

>>> mixed = json.loads(signature_json)
>>> mixed['signatures'].append(dict(tampered['signatures'][0]))
>>> mixed_result = Verify(json.dumps(mixed), [('mykey', verifier)])
>>> len(mixed_result.recognizedSigners)
1
>>> rejected = mixed_result.unrecognizedSignatures[0]
>>> print(rejected.envelopeKeyid, len(rejected.signature))
deadbeef 64
>>> print(rejected.reason)
no trusted verifier matches the envelope keyid

An envelope containing only unrecognized signatures is rejected:

>>> Verify(json.dumps(tampered), [('mykey', verifier)])
Traceback (most recent call last):
    ...
ValueError: No valid signature found

PAE:

>>> PAE(payloadType, payload)
b'DSSEv1 29 http://example.com/HelloWorld 11 hello world'
"""

import base64, binascii, dataclasses, json, struct

# Protocol requires Python 3.8+.
from typing import Iterable, List, Optional, Protocol, Tuple


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""
        ...

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""
        ...


class Verifier(Protocol):
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        ...

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""
        ...


# Collection of verifiers, each of which is associated with a name.
VerifierList = Iterable[Tuple[str, Verifier]]


@dataclasses.dataclass
class RecognizedSigner:
    """A signature that was recognized against a *trusted* verifier.

    The identity of a signer is determined jointly by four pieces of evidence:

    * ``source``: the name of the trusted (name, verifier) entry from the
      verifier list that actually verified the signature. This is the only
      trusted identity; it is never derived from the envelope.
    * ``keyid``: the keyid reported by that trusted verifier, or None for a
      verifier that does not provide a keyid.
    * ``envelopeKeyid``: the unauthenticated keyid hint carried by the
      envelope (normalized to None when unset or empty). It is retained for
      auditing only and MUST NOT be used for security decisions.
    * ``signature``: the raw signature bytes from the envelope that were
      cryptographically verified.

    Additional config entries referencing the same trusted key are recorded in
    ``aliases`` so that renames remain auditable without granting extra trust.
    """
    source: str
    keyid: Optional[str]
    envelopeKeyid: Optional[str]
    signature: bytes
    aliases: Tuple[str, ...] = ()


@dataclasses.dataclass
class UnrecognizedSignature:
    """An envelope signature that was not bound to a trusted verifier.

    These entries are audit evidence only. They are deliberately kept separate
    from ``VerifiedPayload.recognizedSigners`` so that an unknown or renamed
    signer can never elevate trust, while the historical (unauthenticated)
    keyid hint and the exact signature bytes remain available for inspection.
    """
    envelopeKeyid: Optional[str]
    signature: bytes
    reason: str


@dataclasses.dataclass
class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: List[RecognizedSigner]
    # Audit-only evidence; never used for trust/policy decisions.
    unrecognizedSignatures: List[UnrecognizedSignature] = dataclasses.field(
        default_factory=list)


def b64enc(m: bytes) -> str:
    return base64.standard_b64encode(m).decode('utf-8')


def b64dec(m: str) -> bytes:
    m = m.encode('utf-8')
    try:
        return base64.b64decode(m, validate=True)
    except binascii.Error:
        return base64.b64decode(m, altchars='-_', validate=True)


def PAE(payloadType: str, payload: bytes) -> bytes:
    return b'DSSEv1 %d %b %d %b' % (
            len(payloadType), payloadType.encode('utf-8'),
            len(payload), payload)


def Sign(payloadType: str, payload: bytes, signer: Signer) -> str:
    signature = {
        'keyid': signer.keyid(),
        'sig': b64enc(signer.sign(PAE(payloadType, payload))),
    }
    if not signature['keyid']:
        del signature['keyid']
    return json.dumps({
        'payload': b64enc(payload),
        'payloadType': payloadType,
        'signatures': [signature],
    })


def Verify(json_signature: str, verifiers: VerifierList) -> VerifiedPayload:
    wrapper = json.loads(json_signature)
    payloadType = wrapper['payloadType']
    payload = b64dec(wrapper['payload'])
    pae = PAE(payloadType, payload)

    def _envelope_keyid(signature) -> Optional[str]:
        # Per envelope.md, an unset keyid is equivalent to set-but-empty.
        keyid = signature.get('keyid')
        return keyid or None

    def _matches(verifier: Verifier, envelope_keyid: Optional[str]) -> bool:
        # The unauthenticated envelope keyid may only narrow the set of
        # candidate keys (protocol.md). An unknown/renamed keyid therefore
        # cannot match a keyed verifier, and a keyless verifier only accepts
        # signatures that carry no keyid claim.
        trusted_keyid = verifier.keyid()
        if envelope_keyid is not None:
            return trusted_keyid is not None and trusted_keyid == envelope_keyid
        return trusted_keyid is None

    recognized = {}
    unrecognized = []
    for signature in wrapper['signatures']:
        envelope_keyid = _envelope_keyid(signature)
        raw_signature = b64dec(signature['sig'])
        matched = False
        verified = False
        for name, verifier in verifiers:
            if not _matches(verifier, envelope_keyid):
                continue
            matched = True
            if not verifier.verify(pae, raw_signature):
                continue
            verified = True
            # Trust is anchored to the unique trusted key (its keyid), not to
            # the position/order of the config entry or to the unauthenticated
            # envelope hint. A keyless verifier is keyed by its config name.
            dedup_key = (verifier.keyid(), name if verifier.keyid() is None
                         else None)
            entry = recognized.get(dedup_key)
            if entry is None:
                recognized[dedup_key] = RecognizedSigner(
                    source=name,
                    keyid=verifier.keyid(),
                    envelopeKeyid=envelope_keyid,
                    signature=raw_signature)
            elif entry.signature == raw_signature:
                # Same trusted key, same signature: the duplicate/renamed
                # config entry is an alias, not an additional signer.
                entry.aliases = entry.aliases + (name,)
            else:
                # A distinct signature from the same trusted key is a separate
                # cryptographic event and stays independently auditable.
                recognized[(dedup_key, raw_signature)] = RecognizedSigner(
                    source=name,
                    keyid=verifier.keyid(),
                    envelopeKeyid=envelope_keyid,
                    signature=raw_signature)
        if not matched:
            # The keyid hint selects no trusted key (unknown or renamed).
            unrecognized.append(UnrecognizedSignature(
                envelopeKeyid=envelope_keyid,
                signature=raw_signature,
                reason='no trusted verifier matches the envelope keyid'))
        elif not verified:
            # A candidate key was selected but the signature is invalid.
            unrecognized.append(UnrecognizedSignature(
                envelopeKeyid=envelope_keyid,
                signature=raw_signature,
                reason='signature failed cryptographic verification'))
    recognizedSigners = list(recognized.values())
    if not recognizedSigners:
        raise ValueError('No valid signature found')
    return VerifiedPayload(payloadType, payload, recognizedSigners,
                           unrecognized)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
