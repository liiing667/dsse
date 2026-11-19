r"""CLI for the release record: submit batches, inspect status and history.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

All commands print deterministic JSON (sorted keys) so CLI output can be
pinned and compared against the programmatic API in `release_record.py`.

Usage:
    python3 release_cli.py --record record.json submit --batch batch-1 --envelope envelope.json --verifier mykey=pub.pem
    python3 release_cli.py --record record.json status
    python3 release_cli.py --record record.json history
    python3 release_cli.py --record record.json event 1
    python3 release_cli.py --record record.json verify-chain

`--verifier NAME=PATH` maps a signer name to a file holding an ECC public
key in OpenSSH format (see `ecdsa.Verifier.keyid`).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ecdsa
import release_record

from Crypto.PublicKey import ECC


def _load_verifiers(pairs):
    verifiers = []
    for pair in pairs or []:
        name, _, path = pair.partition('=')
        if not name or not path:
            raise SystemExit('--verifier must be NAME=PATH, got %r' % pair)
        with open(path, encoding='utf-8') as handle:
            public_key = ECC.import_key(handle.read())
        verifiers.append((name, ecdsa.Verifier(public_key)))
    return verifiers


def _print(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--record', default='release-record.json',
                        help='path to the release record file')
    commands = parser.add_subparsers(dest='command', required=True)

    submit = commands.add_parser('submit', help='verify and record a batch')
    submit.add_argument('--batch', required=True, help='batch identifier')
    submit.add_argument('--envelope', required=True,
                        help='path to the DSSE envelope JSON file')
    submit.add_argument('--verifier', action='append', default=[],
                        metavar='NAME=PATH', help='named verifier public key')

    commands.add_parser('status', help='print the current release status')
    commands.add_parser('history', help='print every recorded event')

    event_cmd = commands.add_parser('event', help='print one historical event')
    event_cmd.add_argument('seq', type=int, help='1-based sequence number')

    commands.add_parser('verify-chain', help='check the digest chain')

    args = parser.parse_args(argv)
    record = release_record.ReleaseRecord.load(args.record)

    if args.command == 'submit':
        with open(args.envelope, encoding='utf-8') as handle:
            envelope_json = handle.read()
        verifiers = _load_verifiers(args.verifier)
        event = record.submit(args.batch, envelope_json, verifiers)
        record.save(args.record)
        _print(event.to_dict())
    elif args.command == 'status':
        _print(record.status())
    elif args.command == 'history':
        _print(record.history())
    elif args.command == 'event':
        try:
            _print(record.evidence(args.seq))
        except KeyError as exc:
            raise SystemExit(str(exc))
    elif args.command == 'verify-chain':
        _print({'chainIntact': record.verify_chain(),
                'historyLength': len(record.history())})


if __name__ == '__main__':
    main()
