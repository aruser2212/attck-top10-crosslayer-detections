# Fixture provenance and interpretation

The fixtures in this directory are synthetic, inert examples created for this repository. They are not captured customer telemetry, attack binaries or measurements of real-world prevalence. Their illustrative timestamps and identities do not describe actual incidents.

| Directory | Input and expectation | Scope |
|---|---|---|
| sigma | Source-scoped event fields and explicit match/no-match cases for each rule UUID | Bounded evaluation of native pySigma condition AST, not a SIEM backend |
| hunts | Normalized events and explicit expected alert lists | Versioned T1110 rules, thresholds, grouping, duplicates and fixed-window boundaries |
| windows | Export-shaped Windows Security XML | Field mapping, account identity, timestamps and source prerequisites |
| kerberos | Export-shaped 4769 v0/v2 XML and manual rolling expectations | Exact service SID burst semantics, profile rejection, negative cases and an explicit benign candidate match |
| linux_auth | Export-shaped journalctl JSONL from sshd/sshd-session/sshd-auth | Stable machine+cursor identity, exact UTC microseconds, anchored auth messages and offline Linux Hunt replay |
| network | Scenario manifest, expected SID counts and generated Scapy packets | Native Suricata loading and offline PCAP replay; packets are never transmitted |
| yara | Inert source fragments and expected rule names | Native libyara compilation/matching under the rule's input contract |
| correlation | Normalized host-file/web-access events and independent semantic goldens | Exact host/filesystem namespace/path, bounded latest-write correlation, explicit benign candidates and finite Basic replay |

Expected outputs must be reviewed against the intended detection behavior. Never regenerate expectations automatically from the implementation merely to obtain a green test. When changing a threshold, boolean condition, input profile or timing model, include a case that distinguishes old and new behavior.

Keep native Windows source shape (including seven fractional timestamp digits) in normalization fixtures. Windows timestamps are floored to microseconds for event time; the remaining 100ns digit stays in identity. Canonical Computer ASCII case and uint64 record IDs must deduplicate equivalent exports without merging changed payloads. Linux cursors and machine IDs must remain stable across re-delivery; Linux usernames retain case. See [telemetry contracts](../../docs/telemetry.md).

Windows normalized events feed the Elastic Basic auth-v1 adapter and [stateful pipeline](../../docs/continuous.md). Linux normalization currently feeds only the offline Linux Hunt; no Linux Elastic adapter or host collector deployment is claimed. Source-name checks validate the exported representation, not its authenticity.

Suricata manifests identify each scenario by a distinct fixture address and assert the exact observed signature counts. PCAP files and engine outputs are temporary/generated artifacts.

Passing these cases establishes regression coverage for the stated cases only. Report missing operational datasets separately; do not convert fixture pass rates into TPR/FPR or precision estimates.
