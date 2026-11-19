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
>>> pprint(result)
VerifiedPayload(payloadType='http://example.com/HelloWorld',
                payload=b'hello world',
                recognizedSigners=['mykey'],
                rejectedSignatures=[])

Multiple distinct signers are all recognized:

>>> signer2 = ecdsa.Signer.generate(curve='P-256')
>>> verifier2 = ecdsa.Verifier(signer2.public_key)
>>> envelope = json.loads(signature_json)
>>> envelope['signatures'] += json.loads(
...     Sign(payloadType, payload, signer2))['signatures']
>>> result = Verify(json.dumps(envelope),
...                 [('mykey', verifier), ('other', verifier2)])
>>> sorted(result.recognizedSigners)
['mykey', 'other']

Signatures from unknown keys are reported as rejected evidence:

>>> result = Verify(json.dumps(envelope), [('mykey', verifier)])
>>> result.recognizedSigners
['mykey']
>>> [(r.keyid, r.reason) for r in result.rejectedSignatures
... ]  # doctest: +ELLIPSIS
[('...', 'no verifier accepted the signature')]

Duplicate records fail closed, even if they would verify:

>>> envelope = json.loads(signature_json)
>>> envelope['signatures'].append(envelope['signatures'][0])
>>> Verify(json.dumps(envelope), [('mykey', verifier)])  # doctest: +ELLIPSIS
Traceback (most recent call last):
...
ValueError: Duplicate signature record #1 ...

Ambiguous records (one signature verifying under several registered
signers, e.g. a keyid registered twice) also fail closed:

>>> Verify(signature_json, [('a', verifier), ('b', verifier)])  # doctest: +ELLIPSIS
Traceback (most recent call last):
...
ValueError: Ambiguous signature record #0 ...

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
class RejectedSignature:
    keyid: Optional[str]
    sig: str
    reason: str


@dataclasses.dataclass
class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: List[str]  # List of names of signers
    rejectedSignatures: List[RejectedSignature] = dataclasses.field(
        default_factory=list)


def b64enc(m: bytes) -> str:
    return base64.standard_b64encode(m).decode('utf-8')


def b64dec(m: str) -> bytes:
    m = m.encode('utf-8')
    try:
        return base64.b64decode(m, validate=True)
    except binascii.Error:
        return base64.b64decode(m, altchars='-_', validate=True)


def b64dec_typed(m: str) -> Tuple[bytes, str]:
    """Decodes base64, also returning which alphabet was used."""
    raw = m.encode('utf-8')
    try:
        return base64.b64decode(raw, validate=True), 'standard'
    except binascii.Error:
        return base64.b64decode(raw, altchars='-_', validate=True), 'urlsafe'


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
    verifier_list = list(verifiers)
    seen_identities = set()
    recognizedSigners = []
    rejectedSignatures = []
    signatures = wrapper['signatures']
    if not isinstance(signatures, list):
        raise ValueError('Malformed envelope: signatures is not a list')
    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            raise ValueError(
                'Malformed signature record #%d: not an object' % index)
        keyid = signature.get('keyid')
        sig = signature.get('sig')
        if keyid is not None and not isinstance(keyid, str):
            raise ValueError(
                'Malformed signature record #%d: keyid is not a string'
                % index)
        if not isinstance(sig, str):
            raise ValueError(
                'Malformed signature record #%d: sig is not a string'
                % index)
        try:
            decoded_sig, encoding = b64dec_typed(sig)
        except (binascii.Error, ValueError):
            raise ValueError(
                'Malformed signature record #%d (keyid=%r): '
                'sig is not valid base64' % (index, keyid))
        identity = (keyid, decoded_sig, encoding)
        if identity in seen_identities:
            raise ValueError(
                'Duplicate signature record #%d (keyid=%r, %s base64, '
                'sig=%r)' % (index, keyid, encoding, sig))
        seen_identities.add(identity)
        matches = []
        for name, verifier in verifier_list:
            if (keyid is not None and
                verifier.keyid() is not None and
                keyid != verifier.keyid()):
                continue
            if verifier.verify(pae, decoded_sig):
                matches.append(name)
        if len(matches) > 1:
            raise ValueError(
                'Ambiguous signature record #%d (keyid=%r): verified under '
                'multiple signers %r' % (index, keyid, matches))
        if matches:
            if matches[0] not in recognizedSigners:
                recognizedSigners.append(matches[0])
        else:
            rejectedSignatures.append(RejectedSignature(
                keyid, sig, 'no verifier accepted the signature'))
    if not recognizedSigners:
        raise ValueError(
            'No valid signature found; rejected signatures: %r'
            % (rejectedSignatures,))
    return VerifiedPayload(
        payloadType, payload, recognizedSigners, rejectedSignatures)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
