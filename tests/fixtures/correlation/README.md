# Host/file → HTTP candidate fixtures

These are inert synthetic events authored for this repository. They are not
captured customer logs, attack executions or a representative benign dataset.
The original `webroot_request.jsonl` demonstration now includes the required
`resource.namespace`; `expected.json` declares its one evidence pair.

`cases.json` contains **40 scenarios and 88 input records**. Its semantic alert
expectations are declared independently of the evaluator. They include every
alert field except the computed `alert.id`. Separate engine tests check the
explicit JSON-tuple SHA256 identity contract; fixture tests require full SHA256
IDs and stable full alerts under reordering/redelivery. Native tests compare
full IDs between local and Basic replay as well as these manual semantic goldens.
Do not regenerate expected alerts from the implementation to make tests pass.

The corpus distinguishes:

- `candidate_positive`: the declared observable condition is satisfied; this is
  not an assertion that an attack occurred.
- `candidate_negative`: the particular condition does not hold. This does not
  establish that arbitrary similar activity is harmless.
- `benign_candidate`: a known synthetic example of legitimate activity that
  satisfies the same condition. A deployed administrative page receiving
  `cmd=refresh` deliberately remains a match.
- `invalid_input`: malformed or conflicting data must fail explicitly. These
  cases are input-contract checks, not detection misses or negative observations.

There are **33 profile-valid scenarios and 7 rejected scenarios**. The cases cover
ordinary dynamic pages after deployment, image uploads, a benign administrative
match, exact host/namespace/path identity, mapped presentation aliases, failed
writes and open intent, half-open time boundaries and microseconds, latest-write
selection, atomic ties, duplicates, request bounds with preceding file context,
exact once-decoded query keys, and repeated request evidence.

`resource.namespace` is a trusted upstream identifier for a filesystem or
workload namespace, such as a container/chroot/mount scope. It is not copied from
the HTTP Host header. Different containers can have identical host/path strings
without sharing a file. Conversely, distinct public aliases can map to one
physical resource and share a namespace if the collector explicitly establishes
that mapping. Paths are already canonical absolute POSIX paths; this corpus does
not implement URL rewriting, symlink resolution or native host-log normalization.

The selector recognizes `.php`, `.jsp` and `.aspx` suffixes without case
sensitivity while preserving the full path's case. A `.phtml` example is outside
this pilot's declared suffix set. The exact query keys `cmd`, `exec`, `command`
are recognized after one decoding pass, including empty or bare values. A match
does not establish that the value is a command or that the server executed it.
The HTTP 404 example intentionally remains a candidate; the sequence does not
prove current file existence or successful execution.

Run locally from the repository root:

```bash
.venv/bin/python -m pytest tests/test_correlation.py tests/test_correlation_fixtures.py tests/test_web_correlation_profile.py
```

With the local Basic lab running:

```bash
ELASTIC_URL=http://127.0.0.1:19200 .venv/bin/python -m pytest tests/integration/test_web_correlation_live.py
```

The native suite uses temporary concrete indices and removes only its own index
names. It checks profile rejection before ingestion, native pagination,
immutable IDs, malformed direct writes, exact microsecond context, resource
limits, long query values retained in `_source`, and CLI replay from outside the
repository. Passing fixtures does not measure deployment precision, recall,
false-positive prevalence, collection completeness or performance under load.
