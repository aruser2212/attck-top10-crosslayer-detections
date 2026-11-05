# Reviewed Kerberos RC4 burst candidates

`cases.json` contains 44 synthetic cases with 228 explicit flat input records and
manually declared expected alert lists for
`techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml`.
The manifest uses schema version 1; the executable rule uses Hunt schema version
2. Expected alerts were specified independently of the Python and Elastic
implementations. Do not regenerate them from detector output.

The rule identifies a **candidate for investigation**, not confirmed
Kerberoasting: at least five distinct service account SIDs requested successfully
with RC4 by the same requester/domain/source IP within a rolling five-minute
window. Native 4769 `ServiceName` is context; it is not a reliable count of full
requested SPNs. Distinct `ServiceSid` values determine the account count.

Each case declares `name`, `hunt`, `reason`, `outcome`, `profile_valid`, `events`,
and `expected_alerts`; optional `bounds` contains `start` and `end`.

| Outcome | Meaning |
|---|---|
| `candidate_positive` | The explicitly scoped rule must emit the declared candidate alerts. This is not an attack ground-truth label. |
| `candidate_negative` | The rule must emit no candidate for these inputs. This is not a claim that every input represents benign activity. |
| `benign_candidate` | The described authorized activity deliberately matches the rule, documenting an ambiguity requiring investigation or scoped tuning. |

`benign_legacy_application_rc4_fanout` models a legitimate legacy reporting
service obtaining five RC4 service tickets. Its expected alert is intentional:
these fields cannot distinguish that workflow from an abusive request pattern.
The fixture makes that limitation visible instead of reporting the match as a
true positive. These finite synthetic cases establish neither precision nor
TPR/FPR in a deployment. AES-only roasting, slow requests, requests from multiple
sources, and offline ticket cracking are outside this particular rule's scope.

The cases enforce these boundaries:

- Success requires integer `win.status: 0`; RC4 requires integer
  `ticket.encryption_type: 23`; the source is 4769 in
  `windows.security.kerberos_tgs`.
- Four distinct SIDs do not qualify, regardless of request count. Service-name
  aliases for one SID remain one account; identical names for different SIDs
  remain distinct accounts. A missing SID never falls back to the name.
- Groups are exactly `(user.domain, user.name, source.ip)`. Separate users,
  domains, and IPs cannot combine their requests. Domain controller `host.name`
  is optional context, so events from multiple DCs can contribute to one group.
  Machine requesters ending in `$` are not excluded automatically.
- At each eligible group timestamp `t`, membership is `(t-5m,t]`, with an
  exclusive lower bound and atomic inclusion of equal timestamps. The cases
  cover exact expiry, both sides of a microsecond boundary, and bursts spanning
  clock-aligned buckets.
- `distinct_service_accounts` counts service SIDs and `rc4_requests` counts all
  eligible requests, including repeats for an already represented service.
  Missing grouping fields or missing SID exclude the entire record from both
  metrics and from anchor creation. A valid burst followed by a SID-less record
  therefore retains five requests and emits no additional candidate.
- Immutable duplicate IDs with equivalent UTC-normalized payload count once.
  Distinct events at successive qualifying anchors produce successive alerts;
  episode suppression is not part of this finite rule.
- Optional emission bounds select anchors in `[start,end)` while retaining
  preceding history. An event exactly at `end` cannot create a result.

`profile_valid` records ingress validity separately from the expected rule
outcome. The 37 valid cases include missing/null semantic fields: the profile
preserves unknown telemetry, and the detector excludes insufficient records.
The seven invalid cases contain a wrong source dataset/code, wrong present
field types, or an empty SID. Generic offline Hunt evaluates their negative
examples, while the strict Kerberos profile must reject the whole batch before
Elastic ingestion. This distinction must not be counted as detection success.
Present user/domain names must already be ASCII-lowercase, source IPs canonical,
and service IDs canonical non-null SIDs; normalization has separate tests.

Run from the repository root:

```bash
.venv/bin/python -m pytest tests/test_kerberos_hunt.py -q
```

The same `events` and independent `expected_alerts` are used for native Elastic
Basic replay tests. Review an expectation change together with the scenario and
rule contract; a shared implementation cannot serve as its own oracle.
