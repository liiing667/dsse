# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

## PAE domain hardening

`PAE()` validates a single bounded byte domain and fails closed by raising
`PAEError`:

- `payloadType` must be a Unicode string with a valid UTF-8 encoding (lone
  surrogates and non-UTF-8 bytes are rejected, never replaced or re-encoded).
- `payloadType` UTF-8 bytes and `payload` bytes must each be at most
  `MAX_TYPE_BYTES` / `MAX_PAYLOAD_BYTES` (1,048,576 bytes = 1 MiB).
- `payload` stays an arbitrary byte sequence, including non-UTF-8 binary.
- Both `Sign()` and `Verify()` run the validation before touching a signer or
  verifier, so no out-of-domain message is ever signed or accepted.

Fixed accept/reject vectors, including exact PAE bytes and rejection paths,
live in `fixtures/pae_fixtures.json`. Run the standard-library-only regression
suite with:

```sh
python3 test_pae.py
```

The module-level docstring examples additionally require
`pip3 install pycryptodome` and run via `python3 -m doctest signing_spec.py`.
