# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

Envelopes are validated fail-closed before verification (`decode_envelope`):
oversized input, invalid JSON, duplicate object members, missing or mistyped
required fields, and malformed `signatures` arrays are rejected with an
`EnvelopeError` stating the reason. `test_signing_spec.py` contains fixed
fixtures showing each rejection, its reason, and a normal verification
response; run it with `python3 test_signing_spec.py`.
