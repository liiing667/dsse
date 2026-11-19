# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

`Verify` enforces a configurable resource budget (`ResourceLimits`) bounding
the number of signatures, decoded payload size, payloadType length, and JSON
nesting depth. Envelopes that exceed the budget are rejected with
`ResourceLimitExceeded` before any signature is verified, so no partial
result is produced. `test_resource_limits.py` contains a fixed matrix of
rejection categories and pass results; run it with
`python3 test_resource_limits.py`.
