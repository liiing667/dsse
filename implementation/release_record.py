r"""Release record: verification, failure isolation, and release status as one
observable chain.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

This module wraps `signing_spec.Verify` in an append-only release record.
Every submitted batch produces exactly one `ReleaseEvent`:

* verification success -> a ``verified`` event carrying the verified payload
* verification failure -> a ``failed`` event carrying the error, which
  *replaces* the previous event as the current release status, so later
  batches can never reuse stale verified evidence

Events are linked by a SHA-256 digest chain (`previousDigest` -> `digest`),
making the verification -> failure-isolation -> release-status pipeline
observable and tamper-evident. Historical events (including legitimate
verified evidence from before a failure) remain readable via `history()`
and `evidence()`.
"""

import dataclasses
import hashlib
import json
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import signing_spec

STATUS_VERIFIED = 'verified'
STATUS_FAILED = 'failed'
STATUS_EMPTY = 'empty'

GENESIS_DIGEST = hashlib.sha256(b'DSSE release record v1').hexdigest()


def _chain_digest(content: Dict) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


@dataclasses.dataclass
class ReleaseEvent:
    seq: int
    batch: str
    status: str  # STATUS_VERIFIED or STATUS_FAILED
    payloadType: Optional[str]
    payload: Optional[str]  # base64-encoded, None on failure
    recognizedSigners: List[str]
    error: Optional[str]  # None on success
    previousDigest: str
    digest: str = ''

    def __post_init__(self):
        if not self.digest:
            self.digest = _chain_digest(self._content())

    def _content(self) -> Dict:
        return {
            'seq': self.seq,
            'batch': self.batch,
            'status': self.status,
            'payloadType': self.payloadType,
            'payload': self.payload,
            'recognizedSigners': self.recognizedSigners,
            'error': self.error,
            'previousDigest': self.previousDigest,
        }

    def to_dict(self) -> Dict:
        result = self._content()
        result['digest'] = self.digest
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> 'ReleaseEvent':
        return cls(
            seq=data['seq'],
            batch=data['batch'],
            status=data['status'],
            payloadType=data['payloadType'],
            payload=data['payload'],
            recognizedSigners=list(data['recognizedSigners']),
            error=data['error'],
            previousDigest=data['previousDigest'],
            digest=data['digest'],
        )


class ReleaseRecord:
    """Append-only, hash-chained log of release events."""

    def __init__(self, events: Optional[List[ReleaseEvent]] = None):
        self._events: List[ReleaseEvent] = list(events or [])

    def submit(self, batch: str, envelope_json: str,
               verifiers: signing_spec.VerifierList) -> ReleaseEvent:
        """Verifies `envelope_json` and appends the resulting event.

        A verification failure is isolated into a ``failed`` event that
        becomes the current release status, replacing any earlier verified
        evidence so subsequent batches cannot reuse it.
        """
        previous_digest = self._events[-1].digest if self._events else GENESIS_DIGEST
        seq = len(self._events) + 1
        try:
            verified = signing_spec.Verify(envelope_json, verifiers)
        except Exception as exc:
            event = ReleaseEvent(
                seq=seq,
                batch=batch,
                status=STATUS_FAILED,
                payloadType=None,
                payload=None,
                recognizedSigners=[],
                error='%s: %s' % (type(exc).__name__, exc),
                previousDigest=previous_digest,
            )
        else:
            event = ReleaseEvent(
                seq=seq,
                batch=batch,
                status=STATUS_VERIFIED,
                payloadType=verified.payloadType,
                payload=signing_spec.b64enc(verified.payload),
                recognizedSigners=list(verified.recognizedSigners),
                error=None,
                previousDigest=previous_digest,
            )
        self._events.append(event)
        return event

    def status(self) -> Dict:
        """Returns the current release status (the latest event)."""
        if not self._events:
            return {'status': STATUS_EMPTY, 'event': None,
                    'historyLength': 0}
        return {'status': self._events[-1].status,
                'event': self._events[-1].to_dict(),
                'historyLength': len(self._events)}

    def history(self) -> List[Dict]:
        """Returns every event, oldest first."""
        return [event.to_dict() for event in self._events]

    def evidence(self, seq: int) -> Dict:
        """Returns the historical event with the given 1-based sequence
        number, so legitimate earlier evidence stays readable."""
        for event in self._events:
            if event.seq == seq:
                return event.to_dict()
        raise KeyError('no event with seq %d' % seq)

    def verify_chain(self) -> bool:
        """Recomputes the digest chain to confirm it is intact."""
        previous_digest = GENESIS_DIGEST
        for event in self._events:
            if event.previousDigest != previous_digest:
                return False
            if event.digest != _chain_digest(event._content()):
                return False
            previous_digest = event.digest
        return True

    def to_json(self) -> str:
        return json.dumps([event.to_dict() for event in self._events],
                          indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> 'ReleaseRecord':
        return cls([ReleaseEvent.from_dict(item) for item in json.loads(data)])

    def save(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> 'ReleaseRecord':
        if not os.path.exists(path):
            return cls()
        with open(path, encoding='utf-8') as handle:
            return cls.from_json(handle.read())
