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


# Shared byte-domain bounds for the two PAE fields. A LEN() value is only
# meaningful inside this bounded domain: any field outside the bound is
# rejected before PAE is computed, on both signing and verification, so that
# every conforming implementation derives PAE from identical bounded byte
# strings. See protocol.md, "PAE domain bounds".
MAX_TYPE_BYTES = 1 << 20       # 1 MiB
MAX_PAYLOAD_BYTES = 1 << 20    # 1 MiB


class PAEError(ValueError):
    """Raised when an input cannot be safely encoded into a PAE byte string.

    Signing and verification MUST fail closed: callers must never swallow this
    error and fall back to a different length or text encoding.
    """


# Surface as a bare builtin-style name in tracebacks (and thus in doctest
# exception matchers), while remaining catchable as signing_spec.PAEError.
PAEError.__module__ = 'builtins'


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


def _enforce_byte_bound(field_name: str, length: int, bound: int) -> None:
    if length > bound:
        raise PAEError(
            f'{field_name} is {length} bytes, exceeding the {bound}-byte '
            f'PAE domain bound')


def _encode_payload_type(payloadType: str) -> bytes:
    """Strictly encode the type text as UTF-8, failing closed on bad text."""
    if not isinstance(payloadType, str):
        raise PAEError(
            'payloadType must be a unicode string, got '
            f'{type(payloadType).__name__}')
    try:
        # errors='strict' rejects lone surrogates and any other text that has
        # no UTF-8 representation, instead of emitting replacement bytes.
        return payloadType.encode('utf-8', errors='strict')
    except UnicodeEncodeError as exc:
        raise PAEError(
            'payloadType is not valid UTF-8 and cannot be authenticated'
        ) from None


def _pae(type_bytes: bytes, body: bytes) -> bytes:
    """PAE over raw byte fields, enforcing the shared bounded byte domain.

    Both fields live in the same domain: each is an explicit byte sequence
    with a length that must fit its bound, and the type bytes must be valid
    UTF-8. The body stays an arbitrary (including non-UTF-8) byte sequence.
    """
    if not isinstance(type_bytes, bytes):
        raise PAEError(
            f'type must be bytes, got {type(type_bytes).__name__}')
    if not isinstance(body, bytes):
        raise PAEError(
            f'body must be bytes, got {type(body).__name__}')
    try:
        # Re-check at the byte boundary so no caller can smuggle a non-UTF-8
        # type past the string entry point.
        type_bytes.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PAEError(
            'payloadType is not valid UTF-8 and cannot be authenticated'
        ) from None
    _enforce_byte_bound('payloadType', len(type_bytes), MAX_TYPE_BYTES)
    _enforce_byte_bound('payload', len(body), MAX_PAYLOAD_BYTES)
    return b'DSSEv1 %d %b %d %b' % (
            len(type_bytes), type_bytes, len(body), body)


def PAE(payloadType: str, payload: bytes) -> bytes:
    r"""Pre-Authentication Encoding, fail-closed on out-of-domain inputs.

    The type text is strictly UTF-8 encoded and both fields share the same
    bounded byte domain (MAX_TYPE_BYTES / MAX_PAYLOAD_BYTES); anything outside
    the domain raises PAEError rather than producing a divergent encoding.
    Legitimate binary payloads are untouched, and valid inputs keep the exact
    historical PAE byte layout:

    >>> PAE('http://example.com/HelloWorld', b'hello world')
    b'DSSEv1 29 http://example.com/HelloWorld 11 hello world'

    Arbitrary binary bodies remain legal; only the type is constrained to
    UTF-8 text:

    >>> PAE('application/octet-stream', bytes([0, 1, 2, 11, 255, 255, 0]))
    b'DSSEv1 24 application/octet-stream 7 \x00\x01\x02\x0b\xff\xff\x00'

    Non-UTF-8 type text (here a lone surrogate) is rejected, never encoded
    with replacement bytes:

    >>> PAE('bad\udfff surrogate', b'')
    Traceback (most recent call last):
    ...
    PAEError: payloadType is not valid UTF-8 and cannot be authenticated

    Oversized fields are rejected before any length is serialized:

    >>> PAE('a' * (MAX_TYPE_BYTES + 1), b'')
    Traceback (most recent call last):
    ...
    PAEError: payloadType is 1048577 bytes, exceeding the 1048576-byte PAE domain bound
    """
    type_bytes = _encode_payload_type(payloadType)
    if not isinstance(payload, bytes):
        raise PAEError(
            f'payload must be bytes, got {type(payload).__name__}')
    return _pae(type_bytes, payload)


def Sign(payloadType: str, payload: bytes, signer: Signer) -> str:
    # PAE() validates the shared domain and raises PAEError on bad input, so
    # an out-of-domain message is never signed.
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
    if not isinstance(payloadType, str):
        raise PAEError('envelope payloadType must be a JSON string')
    payload_field = wrapper['payload']
    if not isinstance(payload_field, str):
        raise PAEError('envelope payload must be a base64 string')
    payload = b64dec(wrapper['payload'])
    # Fail closed: a non-UTF-8 type or an out-of-bound field raises PAEError
    # before any verifier is consulted, so no signature can validate a message
    # whose PAE other implementations might compute differently.
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
