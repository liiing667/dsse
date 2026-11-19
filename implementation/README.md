# Signing-spec reference implementation

The Python module `signing_spec.py` contains a reference implementation. A test
vector is contained as a docstring at the top of the file.

## Release record

`release_record.py` builds an append-only release record on top of
`signing_spec.Verify`. Each submitted batch is verified and appended as a
hash-chained `ReleaseEvent`, so verification, failure isolation, and release
status form one observable chain:

* a verification failure is recorded as a `failed` event that replaces the
  previous event as the current release status, so later batches cannot
  reuse stale verified evidence;
* historical events (including earlier verified evidence) remain readable
  via `history()` / `evidence(seq)`;
* `verify_chain()` recomputes the SHA-256 digest chain to detect tampering.

`release_cli.py` exposes the same operations on the command line with
deterministic JSON output (`submit`, `status`, `history`, `event`,
`verify-chain`). Run `python3 -m unittest test_release_record` for tests
covering the failure-then-success sequence and CLI/API parity.
