# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

`strict_verification.py` adds an optional strict, fail-closed verification
layer (`StrictVerificationPolicy` + `VerifyStrict`) on top of `signing_spec`.
The legacy `Verify` function is unchanged. Strict mode requires every
signature to carry a `keyid` matching a configured verifier, rejects duplicate
`keyid` values, de-duplicates valid signers and enforces a minimum threshold,
caps envelope/payload/PAE sizes and signature counts, and rejects malformed
signatures instead of skipping them.

The examples and tests require `pip3 install pycryptodome`. Run the tests
with:

```
python -m unittest discover -s implementation -p 'test_*.py' -v
```
