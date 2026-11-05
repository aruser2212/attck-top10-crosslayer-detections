# Changelog

## Unreleased — precise detection candidates and verified Basic replay

- Fix Suricata replay on fresh Docker workers: read container IDs and exit codes from stdout only, preserving stderr for diagnostics. Add cold-image-pull and error-output regressions.
- Add finite host/file-to-HTTP replay on Elasticsearch Basic with a strict shared source profile, one PIT, microsecond bounds and linked source evidence. Require a trusted filesystem namespace to prevent cross-container joins; do not infer paths from URLs or claim native source collection.
- Version the correlation as CORR-WEB-WEBROOT-REQUEST-002, use unambiguous full SHA256 identities, and reject malformed input before ingestion. Add independently specified deploy/upload/admin fixtures, including a legitimate matching sequence and explicit source-contract failures.
- Correct the legacy web selector's extension-only OR condition. Keep both T1190 Hunt artifacts design-only; the dedicated correlation runtime does not implement generic joins or first_seen.

- Migrate the Kerberoasting burst Hunt to executable rolling v2: successful RC4-HMAC only, exact requester/domain/IP grouping across DCs, and distinct service SIDs instead of mislabelled SPN names. Remove blanket machine-account and server-prefix tuning exclusions.
- Add native-shaped Security 4769 v0/v2 normalization, a strict kerberos-v1 profile and finite Elasticsearch Basic replay reusing the existing PIT/search_after transport. Preserve the auth-v2 API and continuous T1110 behavior.
- Add 44 manual scenarios, including an expected benign application match, plus normalization and native XML-to-alert tests. Keep lifecycle test, operational metrics unmeasured, and AES/slow activity outside this candidate's scope.
- Audit the 19 original legacy Hunts, complete one migration and rank the remaining detection work. Prioritize host/web, LSASS and precise session correlation; defer further storage infrastructure.

- Recompute only episode groups affected by raw revisions or checkpoint-driven closure. Keep complete integrity scans, global limits and an explicit full reference mode; preserve SQLite schema, document identities and revision behavior across mode switches.
- Add differential unit/native checks for unchanged groups, late merges/splits, rekeying, metric-only changes, closure, recovery and limits applied to cached episodes.
- Export coherent raw/episode evidence under both writer locks, with empty outboxes and exact source progress. Publish archives atomically without overwriting an existing destination and verify checksums, references and current grouping offline. Report the strict replay-stable boundary; preserve live data and make no automatic pruning or live-restore claim.

- Add a separate episode view of rolling alerts with exact inactivity-gap grouping, member IDs/revisions and peak window metrics. Preserve all raw signals; overlapping counts and distinct-user metrics are never summed.
- Recompute late merges, splits, retractions and reopening from a consistent read-only rolling SQLite snapshot. Derive canonical episode IDs from the earliest member and explicitly link replaced identities; close only after the source checkpoint strictly passes the last anchor plus gap.
- Persist episode state, source revision guards and a transactional delivery outbox for Elasticsearch Basic. Reject missing history, regressing source revisions/checkpoints, replaced databases and incompatible sinks. Bound full-history projection and gate it while raw delivery is pending; provide once/watch/status commands and native recovery checks.

- Add three separate T1110 rolling Hunt v2 rules with exact event-time `(t-W,t]` windows, atomic timestamp ties, positive integer thresholds, explicit replay context and fail-closed resource limits. Preserve all v1 rule and state semantics.
- Add an auth-v2/date_nanos Elasticsearch Basic replay adapter using PIT/search_after plus Python rolling evaluation, independent mathematical-oracle checks and hand-declared boundary fixtures.
- Add a separate durable rolling pipeline with microsecond SQLite v2 checkpoints, bounded forward progress, replay context, stable alert identities and an alerts-v2 outbox. Replay revises or retracts alerts by their event-time anchor; restarts preserve external revisions. Require dedicated indices/state and reject v1 reuse.
- Extend immutable spool ingestion with an explicit auth-v2 profile while preserving the default v1 contract. Block detection while spool backlog remains; report incomplete time catch-up separately. Resource-limit errors leave checkpoints unchanged.
- Preserve explicit fractional zeros in native range bounds: Elasticsearch rounds an exclusive `gt` timestamp without a fraction through that second, otherwise dropping microsecond context events. Verify exact lower and upper bounds on the real Basic engine.
- Add strict schema/link/identifier validation, negative validator tests and hashed development dependencies.
- Parse all Sigma rules with pySigma and check reviewed source-scoped predicate examples.
- Repair Suricata loading, HTTP directions/buffers and bounded SSH/SMB heuristics; add native offline PCAP replay.
- Define YARA input contracts and add native positive/negative matching tests.
- Implement the versioned T1110 Hunt subset with exact aggregates, typed deduplication and explicit UTC tumbling windows.
- Add Windows XML normalization and a free Elasticsearch Basic adapter with exact paginated aggregation and native integration tests.
- Add a controlled Windows auth pipeline with `--once`/`--watch`, atomic immutable ready-file ingestion, SHA256 acknowledgments, explicit quarantine errors and bounded scans. Retain input files and make redelivery safe across restart or a crash after a remote write.
- Persist closed-window checkpoints and a transactional alert outbox in SQLite. Deliver stable alert IDs with monotonic Elasticsearch external versions so delayed older revisions cannot overwrite newer alerts.
- Gate checkpoint advancement until the visible unacknowledged spool backlog is drained. Bind state to concrete source/sink index UUIDs, profiles and rule/scheduling scope; reject incompatible state reuse and concurrent use of the same state database.
- Require a successful source-index refresh before acknowledging nonempty ingestion, including existing-ID retries, so recovery cannot advance detection ahead of search-visible events.
- Support bounded late-event replay through configurable allowed lateness and lookback. Keep v1 UTC tumbling and v2 event-anchored rolling semantics explicit; automatic correction of anchors older than the replay horizon remains outside this implementation.
- Add native Elasticsearch Basic tests for spool redelivery, XML ingestion, restart/crash recovery, index replacement, durable alerts, bounded backlog and the documented pipeline subprocess/watch lifecycle.
- Add strict normalization of supported sshd records from `journalctl --output=json` and offline Linux auth replay. Do not infer missing timestamps, event identity or unimplemented source formats.
- Pin the official Enterprise ATT&CK v20.0/STIX 2.1 source, commit and checksums; lint canonical techniques/tactics and revoked/deprecated mappings offline. Migrate the revoked Linux log-clearing mapping while preserving existing artifact identifiers.
- Add a labeled-outcome evaluation calculator with explicit observation units and synthetic arithmetic tests. No representative ground-truth dataset or operational accuracy measurement is claimed.
- Add an offline host-file/HTTP correlation pilot and a dedicated Linux log-wipe DetCard.
- Generate inventory and separate lifecycle, declared evidence and operational accuracy. No existing card is promoted to stable.

This Unreleased entry describes source changes since v0.2. Local validation is recorded separately from versioned releases and GitHub Actions results. The controlled Windows pipelines have declared source, state and lateness limits; they are not evidence of a deployed Windows collector or production readiness. The remaining 18 legacy hunts, representative accuracy measurement and source/backend contracts are ranked in [the roadmap](docs/roadmap.md). Further source journals, pruning and coordination infrastructure are deferred.

## v0.2 — existing portfolio baseline

Ten technique dossiers, cross-layer artifacts, DetCards and a basic structural validator.
