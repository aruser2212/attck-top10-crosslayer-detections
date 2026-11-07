# NewCredentials manual fixtures

`cases.json` contains **40 manually declared synthetic scenarios / 98 records**.
All identifiers, hosts, accounts and timestamps are inert examples. These files
do not contain customer telemetry or code that executes an attack.

Expected session pairs, privilege event IDs, signed microsecond deltas and exact
privilege unions were specified independently of the production correlator.
The corpus contains:

- 28 evaluable scenarios: 17 candidate cases, one explicitly legitimate
  `runas /netonly` candidate and 10 nonmatches;
- four profile-valid scenarios whose correlation must fail because their
  candidate session evidence is ambiguous or contradictory;
- eight malformed/profile-conflicting scenarios rejected before ingestion.

`profile_valid` and `correlation_valid` are deliberately separate. A well-typed
record can be stored as raw evidence while its relationship with another record
remains contradictory. Such a corpus must fail evaluation, not return an empty
successful detection result.

The examples cover equal timestamps, preceding/following privilege records,
inclusive symmetric skew boundaries, microsecond near misses, exact host/boot/LUID
scope, local-token SID contradictions, repeated delivery and immutable IDs.
They also cover multiple linked 4672 records, deterministic evidence ordering,
repeated background service sessions, and optional `[start,end)` **anchor** bounds.
Source events outside those output bounds remain available for ambiguity checks
and privilege context in the complete finite input.

Account text is supplemental context, not a replacement for local-token SID.
Trusted boot identifiers are supplied explicitly; they are not guessed from
hostnames, timestamps or event record numbers. A matching NewCredentials session
with special privileges is a candidate and does not establish Pass-the-Hash.

`tests/test_newcredentials_fixtures.py` checks these expectations independently
of the Elastic transport. Native integration uses the same manual manifest and
separately tests transport behavior. `native/` contains additional synthetic XML
exports for normalization; neither corpus measures operational precision/TPR/FPR.
