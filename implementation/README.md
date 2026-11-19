# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

## Signer identity in Verify

The `keyid` field in an envelope is an *unauthenticated* hint, so
`Verify` never derives trust from it. A recognized signer is determined
jointly by four pieces of evidence, exposed as `RecognizedSigner`:

- `source`: the trusted `(name, verifier)` entry that actually verified the
  signature (the only trusted identity);
- `keyid`: the keyid reported by that trusted verifier;
- `envelopeKeyid`: the keyid hint carried by the envelope, retained for
  auditing only;
- `signature`: the exact signature bytes that were verified.

Consequences:

- Replacing the envelope `keyid`, or presenting an unknown/renamed keyid,
  cannot attach a signature to a different identity or grant trust.
- Registering the same trusted key under several names yields a single
  recognized signer; the extra names are kept in `aliases` for audit rather
  than counted as additional signers.
- Signatures that match no trusted key, or fail verification, are returned in
  `VerifiedPayload.unrecognizedSignatures` as audit-only evidence and never
  appear in `recognizedSigners`.

## Tests and fixed fixtures

Deterministic fixtures generated from two fixed P-256 keys live in
`fixtures/`; `fixtures/generate_fixtures.py` regenerates them byte-for-byte.
The tests compare both the trusted source and the raw signature bytes against
these fixed fixtures:

```sh
python3 -m pytest test_verify.py
python3 -m doctest signing_spec.py
```
