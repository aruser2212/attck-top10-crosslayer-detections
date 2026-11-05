# ATT&CK Top-10 Cross-Layer Detections

[![Validate repository](https://github.com/aruser2212/attck-top10-crosslayer-detections/actions/workflows/validate.yml/badge.svg)](https://github.com/aruser2212/attck-top10-crosslayer-detections/actions/workflows/validate.yml)

Detection engineering project for a curated selection of **ten ATT&CK technique families**, with **Sigma**, **Suricata**, **YARA**, a bounded **Hunt DSL**, and a tested **free Elasticsearch Basic** Windows T1110 pipeline. Top-10 is a project selection, not an official MITRE ranking.

DetCards connect detection logic, telemetry assumptions, fixtures and declared validation scope. Native checks and positive/negative replay are kept separate from production accuracy claims.

## Current coverage

| Metric | Count |
|---|---:|
| Techniques | 10 |
| DetCards | 20 |
| Sigma rules | 20 (19 files) |
| Hunt DSL files | 25 |
| Network / IDPS rules | 9 (6 files) |
| YARA rules | 2 |
| Test plans | 10; automated suites are separate |
| Executable Hunt v1 rules | 3 T1110 hunts |
| Executable rolling v2 rules | 3 T1110 hunts and 1 T1558.003 RC4 service-account burst |
| Elastic Basic replay | 2 Windows v1 hunts and 3 Windows rolling v2 hunts; separate auth/Kerberos profiles |
| Host/web correlation | Finite Basic replay with exact host/filesystem namespace/path join and linked source evidence |
| Durable Elastic pipeline | 2 Windows hunts in each version; separate tumbling v1 and rolling v2 state |
| Episode projection | Related rolling alerts grouped by exact rule/group and inactivity gap; raw alerts retained |

See the generated [coverage matrix](docs/coverage.md) and [validation scope](docs/validation_report.md). The remaining 18 hunts are design artifacts, explicitly rejected by the executable runtimes. The v1 runner also rejects rolling v2 rules before creating state. The [detection review](docs/detection-priorities.md) ranks their semantic gaps and required evidence.

## Repository layout

```text
schema/       DetCard and executable Hunt schemas
profiles/     Elastic event/alert mappings and pinned official ATT&CK catalog
packs/        thematic detection packs
techniques/   ATT&CK technique dossiers and artifacts
docs/         methodology, coverage and validation notes
tools/        validators, replay engines, normalization, ingestion and durable runner
tests/        inert fixtures and unit/native integration checks
```

## Artifact model

Each detection is described by a **DetCard** (`DET-*.yaml`) with links to supporting artifacts:

- `sigma/` — host detection logic
- `network/` — Suricata rules where relevant; Snort compatibility is unverified
- `yara/` — AV/EDR/static detection where relevant
- `hunts/` — versioned executable subset and explicitly unimplemented design logic
- `queries/` — optional adapters for concrete platforms
- `tests/` — per-technique plans; shared runnable fixtures live in root `tests/`

## Start here

1. Read [`docs/methodology.md`](docs/methodology.md).
2. Open [`docs/coverage.md`](docs/coverage.md) for the current ATT&CK coverage table.
3. Pick a technique under `techniques/` and review its DetCards, Sigma rules, hunts and test plan.
4. Review the [telemetry contracts](docs/telemetry.md), [pinned ATT&CK mapping](docs/attack-mapping.md) and [labeled-outcome evaluation](docs/evaluation.md) before adapting detections to your environment.
5. Replay the [Kerberoasting candidate](docs/kerberos.md): successful RC4 TGS requests across distinct service SIDs, with negative cases and an explicit benign match.

## Notes

Core detection artifacts are vendor-neutral; platform-specific adapters declare their own field contracts and tested behavior.

## Attribution

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

Technique descriptions in this repository are original summaries written for detection engineering practice. Official technique definitions are referenced in each technique dossier.

## Run the checks and free Elastic lab

Requires Python 3.12, Make, and Docker/Compose v2 for native network/Elastic checks.

```bash
make setup
make check
make check-network
make lab-up
make check-elastic
```

The Basic lab uses synthetic events and binds to loopback. See [Elastic instructions](docs/elastic.md) for the adapter and Windows XML normalization, and the [durable pipeline guide](docs/continuous.md) for a complete finite demo and continuous operation. Compose uses the `attck-detection-lab` project and a persistent named volume: `make lab-down` stops the lab and preserves its data. [CONTRIBUTING](CONTRIBUTING.md) documents reproducible dependencies and review requirements.

The Windows pipeline consumes atomically published, immutable `.ready.jsonl` or `.ready.xml` files. `--once` runs a bounded pass; `--watch` repeats it. SQLite checkpoints and a transactional outbox preserve progress across restarts, while stable alert IDs and external revisions prevent duplicate logical alerts and stale overwrites. No remote Windows collector is deployed. Start with the [reproducible fixture demo](docs/continuous.md#воспроизводимый-конечный-пример); live use requires your own event delivery and OS supervisor.

The separate [rolling v2 guide](docs/rolling-windows.md) demonstrates a burst split across a fixed-window boundary. It evaluates exact event-anchored `(t-W,t]` windows, processes timestamp ties together and counts distinct accounts exactly. Windows replay reads an `auth-v2` index through PIT/search_after, then executes the rolling algorithm in Python. Its `date_nanos` mapping preserves the normalized input's microsecond precision. `tools/run_rolling_pipeline.py` adds continuous operation with exact checkpoints, bounded catch-up, late-data revisions and durable alert delivery. It requires dedicated v2 indices and state; there is no automatic v1 migration.

The [episode guide](docs/episodes.md) adds a separate view of related rolling alerts. `tools/run_episode_pipeline.py` reads a consistent snapshot of the raw detector's SQLite state and groups adjacent qualifying anchors for the same rule and group. It preserves every raw alert and records member IDs/revisions and peak window metrics. Late updates can merge, split, retract or reopen episodes; separate SQLite state and an Elasticsearch outbox preserve those changes across restart. The default incremental mode rebuilds affected groups; `--projection-mode full` retains the reference calculation with the same IDs and revisions.

[Evidence archives](docs/episode-archives.md) export coherent raw alerts and episode documents once both delivery queues are empty and the projection is current. Offline verification checks the checksum, references and full reference projection. Export preserves live history and reports which components lie beyond the configured replay horizon; it does not delete data or restore a running pipeline.

CI contains separate structural/predicate, native Suricata replay and native Elastic Basic jobs. Failures and unsupported constructs are explicit. Tests use inert data; the PCAP generator never sends traffic.

A [cross-layer candidate](docs/correlation.md) joins successful webroot file activity to a suspicious HTTP request by host, trusted filesystem namespace and canonical POSIX path. It runs offline and through a separate finite Elastic Basic adapter:

```bash
.venv/bin/python tools/correlate_webshell.py \
  tests/fixtures/correlation/webroot_request.jsonl --webroot /var/www/html
```

The source contract requires `resource.namespace` on both file and HTTP events; identical paths in different containers must remain separate. Each result links the latest eligible file event and the request. Native file/HTTP normalization is an upstream requirement. A legitimate deployment followed by administrative query keys can match; the sequence does not prove exploitation or execution.

## Project status

The [T1558.003 pilot](docs/kerberos.md) adds finite 4769 normalization and Basic replay. It detects a precise RC4 service-account burst condition; a legitimate application can satisfy the same condition. Its fixtures retain that benign match explicitly. AES and low-rate activity are outside this rule, and its threshold has not been calibrated on operational telemetry.

The repository develops the v0.2 portfolio into a reproducibly tested baseline. Changes after the v0.2 tag are documented under Unreleased; publishing source code does not create a new versioned release. Sigma predicate tests, YARA fixtures, Suricata PCAP replay and the durable Elastic T1110 pipelines cover different scopes. Continuous operation supports the two Windows T1110 hunts through separate v1 and rolling v2 commands. Linux SSH remains offline in both versions.

Operational TPR/FPR and latency remain unmeasured. The v1 pipeline's fixed tumbling windows can miss boundary-spanning activity; replay lookback covers only a configured late-event horizon. Rolling replay emits each qualifying group/timestamp; the optional episode view groups these signals without suppressing them. Episode ID follows its earliest member, so an earlier late arrival can change that ID with an explicit replacement reference. Episode projection still scans retained history for integrity and stops when declared limits are exceeded; incremental grouping does not remove that storage limit. A passing synthetic fixture is not a production guarantee. See [methodology](docs/methodology.md), [Hunt contract](docs/hunt-dsl.md), [continuous-operation limits](docs/continuous.md) and [roadmap](docs/roadmap.md).
