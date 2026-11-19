"""Tests for the release record: verification, failure isolation, and release status as one observable chain.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

Uses the deterministic test-vector key from signing_spec.py's docstring, so
event digests are stable and pinned below as golden values.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ecdsa
import release_record
import signing_spec

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, 'release_cli.py')

PAYLOAD_TYPE = 'http://example.com/HelloWorld'

# Golden digests for the fixed batch sequence below (deterministic key and
# RFC 6979 signatures make these stable).
DIGEST_BATCH_1 = 'd5944614a31d64bc56ba5fdabf1d889e37c5ab2fb1c5a75b380d3a6cdf4ac99f'
DIGEST_BATCH_2 = '21a082fefe75bb63baf10263966b075a2e3fb482a066e61eb0cf54d2647d7940'
DIGEST_BATCH_3 = '535c1827782afbac908d2c08ec7d1d8fcfabf852c10a4e64c7e20ee568d66fdd'


def make_signer():
    return ecdsa.Signer.construct(
        curve='P-256',
        d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
        point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
        point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)


def tamper(envelope_json):
    wrapper = json.loads(envelope_json)
    wrapper['payload'] = signing_spec.b64enc(b'hello tampered')
    return json.dumps(wrapper)


class ReleaseRecordTest(unittest.TestCase):

    def setUp(self):
        self.signer = make_signer()
        self.verifiers = [('mykey', ecdsa.Verifier(self.signer.public_key))]
        self.good1 = signing_spec.Sign(PAYLOAD_TYPE, b'hello world', self.signer)
        self.bad = tamper(self.good1)
        self.good2 = signing_spec.Sign(PAYLOAD_TYPE, b'hello again', self.signer)

    def run_sequence(self, record):
        event1 = record.submit('batch-1', self.good1, self.verifiers)
        event2 = record.submit('batch-2', self.bad, self.verifiers)
        event3 = record.submit('batch-3', self.good2, self.verifiers)
        return event1, event2, event3

    def test_failure_replaces_stale_evidence_in_status(self):
        record = release_record.ReleaseRecord()
        self.run_sequence(record)

        history = record.history()
        # After the failed batch, the current status was the failure, not the
        # previously verified payload.
        failed_event = history[1]
        self.assertEqual(failed_event['status'], 'failed')
        self.assertIsNone(failed_event['payload'])
        self.assertIsNone(failed_event['payloadType'])
        self.assertEqual(failed_event['recognizedSigners'], [])
        self.assertIn('No valid signature found', failed_event['error'])

        # The next successful batch becomes the current status.
        status = record.status()
        self.assertEqual(status['status'], 'verified')
        self.assertEqual(status['event']['batch'], 'batch-3')
        self.assertEqual(status['event']['payload'],
                         signing_spec.b64enc(b'hello again'))
        self.assertEqual(status['historyLength'], 3)

    def test_historical_evidence_remains_readable(self):
        record = release_record.ReleaseRecord()
        self.run_sequence(record)

        evidence = record.evidence(1)
        self.assertEqual(evidence['status'], 'verified')
        self.assertEqual(evidence['payload'], signing_spec.b64enc(b'hello world'))
        self.assertEqual(evidence['recognizedSigners'], ['mykey'])
        with self.assertRaises(KeyError):
            record.evidence(99)

    def test_observable_chain_is_intact_and_tamper_evident(self):
        record = release_record.ReleaseRecord()
        event1, event2, event3 = self.run_sequence(record)

        self.assertTrue(record.verify_chain())
        self.assertEqual(event1.digest, DIGEST_BATCH_1)
        self.assertEqual(event2.digest, DIGEST_BATCH_2)
        self.assertEqual(event3.digest, DIGEST_BATCH_3)
        self.assertEqual(event2.previousDigest, event1.digest)
        self.assertEqual(event3.previousDigest, event2.digest)

        # Corrupting a recorded event breaks the chain.
        corrupted = release_record.ReleaseRecord.from_json(record.to_json())
        corrupted._events[0].payload = signing_spec.b64enc(b'forged')
        self.assertFalse(corrupted.verify_chain())

    def test_roundtrip_and_empty_status(self):
        record = release_record.ReleaseRecord()
        self.assertEqual(record.status(),
                         {'status': 'empty', 'event': None, 'historyLength': 0})
        self.run_sequence(record)
        restored = release_record.ReleaseRecord.from_json(record.to_json())
        self.assertEqual(restored.history(), record.history())
        self.assertTrue(restored.verify_chain())

    def test_malformed_envelope_is_isolated_as_failure(self):
        record = release_record.ReleaseRecord()
        event = record.submit('batch-x', 'not json', self.verifiers)
        self.assertEqual(event.status, 'failed')
        self.assertIsNotNone(event.error)
        self.assertEqual(record.status()['status'], 'failed')


class ReleaseCliTest(unittest.TestCase):
    """The CLI must show the same pinned results as the API: the failed
    state after a bad batch and the next success."""

    def setUp(self):
        self.signer = make_signer()
        self.tmp = tempfile.TemporaryDirectory()
        self.record_path = os.path.join(self.tmp.name, 'record.json')
        self.key_path = os.path.join(self.tmp.name, 'pub.pem')
        with open(self.key_path, 'w', encoding='utf-8') as handle:
            handle.write(self.signer.public_key.export_key(format='OpenSSH'))
        self.envelope_dir = self.tmp.name
        self.api_verifiers = [('mykey', ecdsa.Verifier(self.signer.public_key))]
        good1 = signing_spec.Sign(PAYLOAD_TYPE, b'hello world', self.signer)
        self.envelopes = {
            'good1': good1,
            'bad': tamper(good1),
            'good2': signing_spec.Sign(PAYLOAD_TYPE, b'hello again', self.signer),
        }
        self.api_record = release_record.ReleaseRecord()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        result = subprocess.run(
            [sys.executable, CLI, '--record', self.record_path] + list(args),
            capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def submit_cli(self, batch, envelope_json):
        path = os.path.join(self.envelope_dir, batch + '.json')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(envelope_json)
        return self.run_cli('submit', '--batch', batch, '--envelope', path,
                            '--verifier', 'mykey=' + self.key_path)

    def test_cli_matches_api_for_failure_then_success(self):
        for batch, key in [('batch-1', 'good1'), ('batch-2', 'bad'),
                           ('batch-3', 'good2')]:
            cli_event = self.submit_cli(batch, self.envelopes[key])
            api_event = self.api_record.submit(
                batch, self.envelopes[key], self.api_verifiers).to_dict()
            self.assertEqual(cli_event, api_event)

        # Failure isolated as its own event, replacing the old evidence.
        self.assertEqual(self.api_record.history()[1]['status'], 'failed')
        self.assertIsNone(self.api_record.history()[1]['payload'])

        # CLI status shows the next success, identical to the API status.
        self.assertEqual(self.run_cli('status'), self.api_record.status())
        self.assertEqual(self.run_cli('status')['status'], 'verified')

        # CLI history and historical evidence match the API and stay readable.
        self.assertEqual(self.run_cli('history'), self.api_record.history())
        self.assertEqual(self.run_cli('event', '1'),
                         self.api_record.evidence(1))
        self.assertEqual(self.run_cli('event', '1')['status'], 'verified')

        # The observable chain verifies end to end with pinned digests.
        self.assertEqual(self.run_cli('verify-chain'),
                         {'chainIntact': True, 'historyLength': 3})
        digests = [event['digest'] for event in self.run_cli('history')]
        self.assertEqual(digests, [DIGEST_BATCH_1, DIGEST_BATCH_2,
                                   DIGEST_BATCH_3])


if __name__ == '__main__':
    unittest.main()
