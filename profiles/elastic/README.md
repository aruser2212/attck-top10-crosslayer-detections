# Elasticsearch Basic profiles

The [host/web correlation guide](../../docs/correlation.md) defines the separate normalized source contract and Basic replay. This profile does not provide a native collector or infer file paths from URLs; `resource.namespace` must come from trusted source mapping.

The auth profiles support the two Windows T1110 detections: failed logons by
account/source and password spraying by source. Each version has a manual adapter
and a separate durable file-ingestion/scheduling pipeline. They use free Basic
features of Elasticsearch 8.19.4, without Kibana alerting, machine learning,
a paid license, or a trial.

| Profile | Timestamp indexing | Runtime |
|---|---|---|
| `auth-v1` | `date`, millisecond resolution | Tumbling v1 replay and durable Windows pipeline |
| `auth-v2` | `date_nanos`, preserving normalized microseconds | Rolling v2 replay and durable Windows pipeline |
| `kerberos-v1` | `date_nanos`, preserving normalized microseconds | Finite 4769 RC4 service-account burst replay; separate strict source profile |
| `web-correlation-v1` | `date_nanos`, preserving normalized microseconds | Finite host/file + HTTP replay in one dedicated index with a trusted filesystem namespace |
| `alerts-v1` | Existing durable alert contract | Alert sink for the v1 pipeline |
| `alerts-v2` | `date_nanos` for all alert timestamps | Separate alert sink for the rolling v2 pipeline |
| `episodes-v1` | `date_nanos`, preserving anchor microseconds | Separate derived episode sink; raw rolling alerts remain available |

The sections below retain the auth-v1 workflow. The separate auth-v2 contract is
described at the end and in the [rolling guide](../../docs/rolling-windows.md).
The [episode guide](../../docs/episodes.md) describes the optional downstream
projection from rolling SQLite state into `episodes-v1`.

The [Kerberos guide](../../docs/kerberos.md) describes the separate 4769 XML
normalizer and `tools/elastic_kerberos.py` finite replay. It counts validated
service SIDs, not ServiceName strings or guessed SPNs. The continuous auth
pipelines do not ingest this dataset.

## Run the synthetic lab

From the repository root, with the project's Python dependencies installed:

```bash
make setup
docker compose up -d --wait elasticsearch
make check-elastic
```

Compose pins the image digest, binds port 19200 only on loopback and disables
authentication for the local synthetic-data lab. Do not use this lab
configuration for a production cluster. The Compose project is
`attck-detection-lab`; its `elastic-data` named volume persists across
`docker compose down` / `make lab-down`. The integration suite creates temporary
indices and deletes only its own exact indices, including on failures.

The suite requires an active **Basic** license and compares native Elasticsearch
results against hand-declared fixture expectations and the reference Hunt
evaluator. A missing `ELASTIC_URL` skips the live tests; such a run is not evidence
of backend compatibility. A supplied but unreachable endpoint fails the tests.

## Run one fixture manually

```bash
.venv/bin/python tools/elastic_adapter.py --index attck-auth-demo create-index
.venv/bin/python tools/elastic_adapter.py --index attck-auth-demo ingest tests/fixtures/hunts/brute_positive.jsonl
.venv/bin/python tools/elastic_adapter.py --index attck-auth-demo evaluate techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml --page-size 2
```

The result contains one alert for the fixture's ten failed logons. `create-index`
refuses to overwrite an existing index. Re-ingesting identical records is safe;
changing a record while retaining its event ID is an error. Use another explicit
index name for a separate experiment. All searches evaluate the complete contents
of the chosen index unless explicit event-time bounds are supplied. This manual
command returns a result; use the durable pipeline below to schedule evaluation
and persist alerts.

## Durable ingestion and scheduling

The [continuous pipeline guide](../../docs/continuous.md) contains the complete
fixture demo and supervisor instructions. `tools/run_auth_pipeline.py` accepts
`--once` or `--watch`, an existing `--spool` directory, `--state-dir`, separate
`--source-index`/`--alerts-index`, and an explicit UTC `--start`. `--initialize`
creates missing indices with the versioned profiles; it never overwrites existing
mappings. `--at` freezes the clock only for reproducible `--once` demos.

Publish unique immutable `*.ready.jsonl` or single-event `*.ready.xml` files by
atomically renaming a completed, synced temporary file in the same filesystem.
The importer does not delete input files. A `--max-files`-bounded pass with known
unacknowledged input returns `catching_up` (exit 2 in once mode); detection waits
until that backlog is drained.

`auth-v1.mapping.json` is the event index; `alerts-v1.mapping.json` is the dedicated
alert sink. SQLite WAL persists detection checkpoints and a transactional outbox.
Logical alert IDs include rule semantics, source scope, window and group, not the
metric count. Late data can update the same document. External Elasticsearch
versions prevent a delayed old write from replacing a newer revision.

The state binds concrete source/sink index UUIDs and configuration. Changing them
requires a deliberate migration or separate pipeline; an old state is not
silently reused. Local process locks protect one state database, not divergent
copies on different hosts. Use one durable local state per logical pipeline.

`ELASTIC_URL` selects the endpoint. `ELASTIC_API_KEY` or
`ELASTIC_USERNAME`/`ELASTIC_PASSWORD` can supply authentication to a configured
cluster. Values belong in environment settings; never commit credentials. HTTPS
uses standard certificate verification and the configured system trust.

## Input contract

`auth-v1.mapping.json` declares the mapping and profile metadata. Inputs are
normalized JSON objects with literal dotted keys. Unknown context fields remain
in `_source` but are not dynamically indexed.

| Field | Requirement |
|---|---|
| `@timestamp` | ISO 8601 with explicit timezone; normalized to UTC |
| `event.id` | Globally unique nonempty string, at most 512 UTF-8 bytes; used as `_id` |
| `event.dataset` | `windows.security.logons` for these two hunts |
| `event.code` | Scalar string, e.g. `4625`; no automatic numeric conversion |
| `source.ip` | Scalar string; normalize textual IP representations before ingestion |
| `target.user` | Scalar string; preserve domain/realm identity |
| `host.name` | Optional scalar string |

Use `tools/normalize_windows_auth.py` for exported Windows Security 4624/4625 XML;
it keeps subject and target identities separate, normalizes IPv4-mapped IPv6,
and canonicalizes ASCII host/account/domain casing to prevent `ALICE` and `alice`
from inflating distinct-user counts. RecordID is canonical ASCII uint64 text;
native 100ns timestamp identity is retained while normalized event time uses
microseconds. Duplicate System metadata and scoped IPv6 are rejected.
Non-ASCII identity equivalence and
UPN/domain aliases require directory-backed canonicalization.
This tool consumes XML exports, not binary EVTX.

Missing/null/empty grouping fields do not create an alert group. The importer
rejects whitespace-only strings, arrays, objects, booleans and numbers in mapped
keyword fields before writing, preventing Elasticsearch's implicit coercion from
changing detection semantics. Conflicting IDs are checked against both the batch
and existing index before bulk writes. A concurrent conflicting writer can still
cause a partial bulk failure; that error is reported and must be investigated.

Only ingest through the profile's importer: directly writing documents with a
different `_id` convention or multivalued fields violates the identity contract.

Every successful nonempty ingest includes an explicit source-index refresh with
complete shard-success validation, including retries consisting entirely of
existing IDs. Realtime `_mget` alone cannot establish visibility to PIT/search.
A failed refresh leaves the spool file pending. On a secured cluster the ingest
identity needs the source-index `maintenance` privilege (or encompassing `manage`)
alongside read, write and metadata access. The cost of refreshing each batch has
not been benchmarked for production throughput.

## Auth-v1 detection semantics and limits

- Windows are UTC epoch-aligned, half-open **tumbling** intervals, matching Hunt
  v1. Five minutes means `[00:00,00:05)`, `[00:05,00:10)`, etc. A burst straddling
  a boundary may not trigger; this is not a rolling-window detector.
- Composite aggregations enumerate all group/user buckets with pagination.
  Distinct users are counted exactly; approximate `cardinality` is not used.
- Each evaluation uses a point-in-time view. Timeouts, failed shards, malformed
  responses and non-advancing pagination fail instead of returning partial alerts.
- String `eq`/`in` with `all`/`any`/`not`, plus numeric `having`, are supported.
  Missing/null predicate fields remain unknown even under `not`. Other predicates,
  datasets, field mappings and unsupported Hunt versions are explicitly rejected.
- The durable runner evaluates only closed windows after the configured allowed
  lateness, and replays a bounded lookback. These are separate from window size.
  Arrivals older than that horizon cannot be counted without ingest timestamps;
  the runner explicitly reports that limitation rather than a zero-loss claim.
- Rolling windows, `first_seen`, event sequences, Linux Elastic support, an
  external Windows collector and multi-host state coordination are not included.
  Fixture success demonstrates the declared cases, not a production false-positive,
  true-positive or latency measurement.

## Separate auth-v2 rolling replay and pipeline

[`auth-v2.mapping.json`](auth-v2.mapping.json) and `tools/elastic_rolling.py`
support the two Windows rolling v2 Hunt rules. Create a separate index; the
adapter rejects auth-v1 mappings and does not migrate an existing index or state.
The v1 runner also rejects v2 rules before creating or changing state.

The adapter retrieves a bounded set of raw events through PIT/search_after and
executes the exact rolling algorithm in Python. It does not claim a native
Elasticsearch rolling aggregation. For eligible anchor timestamps `[A,B)`, it
reads the necessary history `(A-W,B)`. Timestamp ties are evaluated atomically;
one result is emitted per qualifying group/timestamp, without episode suppression.

Normalized input remains flat JSON with explicit stable IDs, UTC timestamps at
most six fractional digits, and scalar keyword values. The `date_nanos` mapping
preserves those microseconds; it does not restore the original Windows 100ns
event-time remainder. Auth-v2 accepts only its supported Windows authentication
dataset and rejects timestamps outside its declared date_nanos range. Linux
rolling remains offline.

Create-only ingestion checks duplicate content and requires a complete refresh
before success, including existing-ID retries. Native replay validates source
identity, full search responses, advancing pagination and event `_id` consistency.
Limits fail the entire operation rather than report partial success. The bounded
event population is evaluated in memory; production throughput has not been
benchmarked. See [rolling-windows.md](../../docs/rolling-windows.md) for commands,
default limits, exact range semantics and validation scope.

`tools/run_rolling_pipeline.py` combines that adapter with the versioned spool
importer and `RollingDetectionRunner`. It requires separate auth-v2 and
[`alerts-v2.mapping.json`](alerts-v2.mapping.json) indices and a fresh state
directory. It rejects a directory containing v1 `spool.sqlite` or
`detections.sqlite`; no automatic state or index migration is performed.
The v2 files are `rolling-spool.sqlite` and `rolling-detections.sqlite`.
Detection state uses SQLite schema 2 with exact integer microseconds.

A checkpoint C means anchors strictly before C have been evaluated. Each pass
replays anchors `[A,B)`, with `A = max(initial_start, C - lookback)` and
`B = min(now - allowed_lateness, C + max_forward_span)`, reading context
`(A-W,B)` for each rule. This also reads context before the initial start.
`--start` may contain microseconds and needs no window alignment, but must be at
least `1970-01-01T00:10:00Z` for the default rule pair so every stored window start
fits `date_nanos`. The upper time bound is `2262-04-11T23:47:16.854775Z`.

`--max-forward-seconds` defaults to 3600; progress is measured from C rather than
A, so a longer lookback does not stall history catch-up. `--max-query-events`
defaults to 100,000 per rule, including its full context and before local where
filtering. `--max-alerts` defaults to 10,000 across all candidates and retractions
in the current evaluation. Previously committed pending outbox entries drain
first and can exceed a newly lowered cap. These operational limits, page size and forward span can change on
restart without changing alert identity. A dense lookback/context can still
exceed caps even with a smaller forward span; evaluation fails completely rather
than silently dropping data or committing partial results.

All rule results, checkpoints and outbox entries commit in one local SQLite
transaction. Logical alert IDs include scope, semantic rule, canonical group and
the exact anchor, excluding metric values. A repeated anchor updates the same
document when its result changes; another qualifying anchor creates a separate
document. There is no episode suppression. Retractions apply only to stored
`window.end` anchors in `[A,B)`, retain the last confirmed metrics, and can later
reactivate the same ID with a new revision.

External versions make a repeated delivery idempotent and prevent an older
revision from overwriting a newer one. The sink UUID is checked before each write
and after acknowledgement, but Elasticsearch has no atomic UUID-conditioned
write; concurrent index replacement is not a supported operating mode. SQLite
and Elasticsearch do not share a distributed transaction.

State binds source/sink UUIDs, rule semantics, initial start, lookback and allowed
lateness. Use one durable local state per logical pipeline, without divergent
copies on other hosts. Late events older than A may still affect anchors within
`[A,B)` as window context; anchors before A are not automatically backfilled.
Without ingest timestamps, completeness and counts of all late arrivals remain
unknown.

The CLI supports `--once` and `--watch`, with explicit `--initialize` for missing
indices in a fresh pipeline. Once either v2 state file exists, missing source or
sink indices are not recreated even with `--initialize`; recovery must preserve
the bound identity. Once mode returns 2 with `status: catching_up` while input backlog or
event-time catch-up remains; complete work returns 0, runtime errors return 1.
The [continuous guide](../../docs/continuous.md#непрерывный-rolling-v2) includes an
atomic fixture publication, the expected alert, restart, watch and supervisor
instructions. Linux rolling remains offline; production accuracy and throughput
have not been measured.

## Derived episodes-v1 projection

[`episodes-v1.mapping.json`](episodes-v1.mapping.json) is a separate sink for
`tools/run_episode_pipeline.py`. The source is a complete, read-only snapshot of
rolling-v2 `rolling-detections.sqlite`; the episode process has its own SQLite
state and outbox. It preserves raw alerts in `alerts-v2` and does not collect or
re-evaluate authentication events itself.

Active raw alerts with the same source scope, semantic rule and exact group are
connected when consecutive anchors are at most `--gap-seconds` apart (300 by
default). Closure requires the source rule checkpoint to be strictly greater
than the last anchor plus that gap. A closed episode remains revisable. Its
deterministic ID stays stable for extensions and metric updates, but changes if
the earliest member changes. Retractions and `replacement_episode_ids` describe
the current relationship after merges or splits; there is no complete immutable
revision history.

The mapping indexes status, member IDs, anchor count and exact timestamp fields.
`peak_metrics` and `member_revisions` are retained in `_source` with indexing
disabled; they are not searchable numeric fields. Peak metrics are maxima of
individual rolling windows, not sums or total distinct counts for the episode.
Filter to `open` or `closed` when selecting current episodes; retracted documents
retain the last confirmed membership and metrics.

Each pass rebuilds components from the bounded full source history, including
validation of retracted raw rows. Missing history, source-file replacement,
regressing raw revisions/checkpoints, a changed sink UUID or a resource-cap breach
fails the pass. Pending raw outbox delivery postpones new projection. Changes,
source progress and the episode outbox commit atomically in episode SQLite;
external Elasticsearch revisions make delivery repeatable after a crash.

Use separate state/index names and one local writer. The
[episode guide](../../docs/episodes.md) provides a runnable three-alert example,
restart and watch commands, identity/closure boundaries and complete limits.
Incremental projection, archival, multi-host coordination and representative
operational accuracy measurements remain future work.
