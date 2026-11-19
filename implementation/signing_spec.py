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
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Union

# Fail-closed envelope limits, enforced before any signature verification so
# that every consumer derives the same unique envelope identity.
MAX_ENVELOPE_BYTES = 8 * 1024 * 1024  # 8 MiB
MAX_SIGNATURES = 1024


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


class EnvelopeError(ValueError):
    """The envelope is malformed and MUST be rejected before verification."""


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


def _reject_duplicate_members(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """object_pairs_hook that rejects duplicate JSON object members.

    json.loads silently keeps the last duplicate, which lets two parsers
    disagree (e.g. on payloadType) about the same envelope. Reject instead.
    """
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EnvelopeError(f'duplicate JSON member: {key!r}')
        obj[key] = value
    return obj


def _require_str(obj: Dict[str, Any], field: str, where: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise EnvelopeError(f'{where}: field {field!r} must be a string')
    return value


def decode_envelope(json_signature: Union[str, bytes]) -> Tuple[str, bytes, List[Dict[str, Any]]]:
    """Parses and validates an envelope, returning (payloadType, payload, signatures).

    Validation is fail-closed: any structural ambiguity (oversized input,
    invalid JSON, duplicate members, missing or mistyped required fields, or a
    malformed signatures array) raises EnvelopeError before verification.
    """
    if isinstance(json_signature, str):
        data = json_signature.encode('utf-8')
    elif isinstance(json_signature, (bytes, bytearray)):
        data = bytes(json_signature)
    else:
        raise EnvelopeError(
            f'envelope must be str or bytes, got {type(json_signature).__name__}')
    if len(data) > MAX_ENVELOPE_BYTES:
        raise EnvelopeError(
            f'envelope too large: {len(data)} bytes > {MAX_ENVELOPE_BYTES} byte limit')
    try:
        wrapper = json.loads(data, object_pairs_hook=_reject_duplicate_members)
    except EnvelopeError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise EnvelopeError(f'invalid JSON: {e}') from e
    if not isinstance(wrapper, dict):
        raise EnvelopeError('envelope must be a JSON object')
    for field in ('payload', 'payloadType', 'signatures'):
        if field not in wrapper:
            raise EnvelopeError(f'missing required field: {field!r}')
    payloadType = _require_str(wrapper, 'payloadType', 'envelope')
    try:
        payload = b64dec(_require_str(wrapper, 'payload', 'envelope'))
    except (binascii.Error, ValueError) as e:
        raise EnvelopeError(f'payload is not valid base64: {e}') from e
    signatures = wrapper['signatures']
    if not isinstance(signatures, list) or not signatures:
        raise EnvelopeError('signatures must be a non-empty array')
    if len(signatures) > MAX_SIGNATURES:
        raise EnvelopeError(
            f'too many signatures: {len(signatures)} > {MAX_SIGNATURES} limit')
    for index, signature in enumerate(signatures):
        where = f'signatures[{index}]'
        if not isinstance(signature, dict):
            raise EnvelopeError(f'{where} must be an object')
        if 'sig' not in signature:
            raise EnvelopeError(f"{where}: missing required field: 'sig'")
        try:
            b64dec(_require_str(signature, 'sig', where))
        except (binascii.Error, ValueError) as e:
            raise EnvelopeError(f'{where}: sig is not valid base64: {e}') from e
        if 'keyid' in signature and not isinstance(signature['keyid'], str):
            raise EnvelopeError(f"{where}: field 'keyid' must be a string")
    return payloadType, payload, signatures


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
    payloadType, payload, signatures = decode_envelope(json_signature)
    pae = PAE(payloadType, payload)
    recognizedSigners = []
    for signature in signatures:
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
