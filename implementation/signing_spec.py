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
                recognizedSigners=['mykey'])

Threshold verification with a fixed set of two signatures:

>>> signer2 = ecdsa.Signer.construct(
...     curve='P-256',
...     d=22222222222222222222222222222222222222222222222222222222222222222222222222222,
...     point_x=84242469615377490621007150110633399652221266212309677932482829513771913092404,
...     point_y=53298947259412691305666589851438561142116078896989553165381690163105754616294)
>>> verifier2 = ecdsa.Verifier(signer2.public_key)
>>> envelope = json.loads(signature_json)
>>> envelope['signatures'].append(
...     json.loads(Sign(payloadType, payload, signer2))['signatures'][0])
>>> multi_signature_json = json.dumps(envelope)
>>> pprint(json.loads(multi_signature_json))
{'payload': 'aGVsbG8gd29ybGQ=',
 'payloadType': 'http://example.com/HelloWorld',
 'signatures': [{'keyid': '66301bbf',
                 'sig': 'A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=='},
                {'keyid': 'c6a46ab4',
                 'sig': 'G52uGzMKf/3jqfgkhS6VVTyDYcCZaHNdU7Rj17FZjhCN6OZGEJKGagZcjh1LASmybDateV0rAtYAYlbJQ/PqoQ=='}]}

Both signatures verify, so a threshold of 2 is met:

>>> result = Verify(multi_signature_json,
...                 [('mykey', verifier), ('otherkey', verifier2)],
...                 threshold=2)
>>> pprint(result)
VerifiedPayload(payloadType='http://example.com/HelloWorld',
                payload=b'hello world',
                recognizedSigners=['mykey', 'otherkey'])

The same fixed signature set fails when the threshold is not met, and no
result is committed:

>>> Verify(multi_signature_json,
...        [('mykey', verifier), ('otherkey', verifier2)],
...        threshold=3)
Traceback (most recent call last):
...
ValueError: Only 2 distinct valid signature(s) found, threshold 3 not met

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
class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: List[str]  # List of names of signers


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


def Verify(json_signature: str, verifiers: VerifierList,
           threshold: int = 1) -> VerifiedPayload:
    if threshold < 1:
        raise ValueError('Threshold must be at least 1')
    wrapper = json.loads(json_signature)
    payloadType = wrapper['payloadType']
    payload = b64dec(wrapper['payload'])
    pae = PAE(payloadType, payload)
    verifier_list = list(verifiers)
    recognizedSigners = []
    # Each verifier may be recognized at most once and each signature may be
    # attributed to at most one verifier, so that the threshold counts
    # distinct signers.
    used_verifiers = set()
    for signature in wrapper['signatures']:
        for index, (name, verifier) in enumerate(verifier_list):
            if index in used_verifiers:
                continue
            if (signature.get('keyid') is not None and
                verifier.keyid() is not None and
                signature.get('keyid') != verifier.keyid()):
                continue
            if verifier.verify(pae, b64dec(signature['sig'])):
                used_verifiers.add(index)
                recognizedSigners.append(name)
                break
    if len(recognizedSigners) < threshold:
        raise ValueError(
            f'Only {len(recognizedSigners)} distinct valid signature(s) '
            f'found, threshold {threshold} not met')
    return VerifiedPayload(payloadType, payload, recognizedSigners)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
