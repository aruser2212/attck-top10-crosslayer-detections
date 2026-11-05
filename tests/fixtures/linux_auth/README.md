# Synthetic journalctl JSONL

`journal.jsonl` is a hand-scoped synthetic journal export, not host telemetry.
It contains eight failed-password messages across the exact `sshd`, `sshd-session`
and `sshd-auth` sources, one accepted-password message, one
accepted-publickey message, one spoofed identifier from `_COMM=logger`, and one
unrelated sshd message. Machine IDs, cursors, hostnames and fingerprints are inert
fixture identifiers; addresses use documentation ranges.

From the repository root:

```bash
python tools/normalize_linux_auth.py tests/fixtures/linux_auth/journal.jsonl
python -m pytest tests/test_normalize_linux_auth.py -q
```

The normalized failure events produce one eight-event alert with the stored
`linux_ssh_failed_agg.hunt.yaml`. Successful authentications do not count toward
that threshold. Tests also cover seven events, grouping, UTC boundaries,
microseconds, repeated delivery, and case-sensitive Linux usernames.

Input contract: journalctl `--output=json`, one JSON object per line; a trusted
collector supplies journal `_MACHINE_ID`, `__CURSOR` and `__REALTIME_TIMESTAMP`.
`_COMM` is authoritative when present. Only exact names `sshd`, `sshd-session`
and `sshd-auth` are accepted, including the split processes of modern OpenSSH.
`SYSLOG_IDENTIFIER` may use any of these exact names as a fallback when `_COMM`
is absent; that identifier alone does not attest the
process's identity. Conflicting source fields and malformed recognized auth
events fail the complete batch. Other sources/messages are ignored and counted.

Generic yearless/zoneless syslog text, localized messages, whitespace-containing
usernames, source identifiers outside the explicit allowlist, and scoped IPv6
addresses are outside this input contract. No dates or account aliases are
guessed. The output message is a normalized action label, not the raw journal
message; public-key fingerprints and unrelated journal fields are discarded.

An empty input or batch without supported authentication events fails explicitly
instead of reporting readiness with zero normalized events. Duplicate JSON keys,
blank records and non-finite JSON values also fail. Repeated delivery of an
identical event is deduplicated by machine ID plus journal cursor; conflicting
normalized content with the same identity is an error.
