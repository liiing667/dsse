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
VerifiedPayload(payloadType='http://example.com/HelloWorld', payload=b'hello world', recognizedSigners=['mykey'])

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


@dataclasses.dataclass(frozen=True)
class ResourceLimits:
    """Configurable budget bounding verifier resource usage.

    An envelope that exceeds any of these limits is rejected before any
    signature is verified, so an attacker cannot make the verifier burn
    memory or CPU before a conclusion is reached.
    """
    max_signatures: int = 128          # Max entries in `signatures`.
    max_payload_size: int = 16 * 1024 * 1024  # Max decoded payload bytes.
    max_payload_type_length: int = 2048  # Max payloadType bytes (UTF-8).
    max_json_depth: int = 100          # Max JSON nesting depth.


DEFAULT_LIMITS = ResourceLimits()


class ResourceLimitExceeded(ValueError):
    """Raised when an envelope exceeds the configured resource budget."""

    def __init__(self, category: str, message: str):
        self.category = category
        super().__init__('%s: %s' % (category, message))


def _json_nesting_depth(text: str) -> int:
    """Returns the maximum nesting depth of JSON arrays/objects in `text`.

    Scans the raw text so that pathologically deep input is rejected before
    `json.loads` gets a chance to recurse on it.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in '{[':
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in '}]':
            depth -= 1
    return max_depth


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
           limits: ResourceLimits = DEFAULT_LIMITS) -> VerifiedPayload:
    if isinstance(json_signature, bytes):
        json_signature = json_signature.decode('utf-8')
    if _json_nesting_depth(json_signature) > limits.max_json_depth:
        raise ResourceLimitExceeded(
            'json_depth', 'JSON nesting exceeds depth %d' % limits.max_json_depth)
    wrapper = json.loads(json_signature)
    payloadType = wrapper['payloadType']
    if len(payloadType.encode('utf-8')) > limits.max_payload_type_length:
        raise ResourceLimitExceeded(
            'payload_type_length',
            'payloadType exceeds %d bytes' % limits.max_payload_type_length)
    # Reject oversized payloads before decoding them into memory: a base64
    # string encoding more than max_payload_size bytes is itself too long.
    max_encoded_payload_length = 4 * ((limits.max_payload_size + 2) // 3)
    if len(wrapper['payload']) > max_encoded_payload_length:
        raise ResourceLimitExceeded(
            'payload_size',
            'payload exceeds %d bytes' % limits.max_payload_size)
    payload = b64dec(wrapper['payload'])
    if len(payload) > limits.max_payload_size:
        raise ResourceLimitExceeded(
            'payload_size',
            'payload exceeds %d bytes' % limits.max_payload_size)
    if len(wrapper['signatures']) > limits.max_signatures:
        raise ResourceLimitExceeded(
            'signatures',
            'more than %d signatures' % limits.max_signatures)
    pae = PAE(payloadType, payload)
    recognizedSigners = []
    for signature in wrapper['signatures']:
        for name, verifier in verifiers:
            if (signature.get('keyid') is not None and
                verifier.keyid() is not None and
                signature.get('keyid') != verifier.keyid()):
                continue
            if verifier.verify(pae, b64dec(signature['sig'])):
                recognizedSigners.append(name)
    if not recognizedSigners:
        raise ValueError('No valid signature found')
    return VerifiedPayload(payloadType, payload, recognizedSigners)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
