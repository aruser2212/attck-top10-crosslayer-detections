#!/usr/bin/env python3
"""Finite Sysmon 10 candidate replay for granted PROCESS_VM_READ to lsass.exe.

Every accepted event uses lsass-v1's strict source contract. A candidate has an
ASCII-case-insensitive target basename of lsass.exe and GrantedAccess bit 0x10.
This records granted read capability, not an observed memory read, credential
dump or attestation that the target is Windows LSASS. AV/EDR and diagnostic tools
can legitimately satisfy this predicate; executable basenames are not excluded.

One alert per immutable source event is emitted, with host-scoped ProcessGUIDs
and a stable source-event reference. No PID joins, first-seen suppression, generic
Hunt DSL, collection service or continuous state is implemented. Optional bounds
select [start,end) at microsecond precision. Raw-input and alert caps fail the
complete replay instead of returning partial results.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

try:
    from tools.hunt_engine import parse_timestamp
    from tools.lsass_profile import ASCII_LOWER, MAX_TIME, MIN_TIME, prepare_events
    from tools.rolling_hunt import event_time_bounds, iter_jsonl
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp
    from lsass_profile import ASCII_LOWER, MAX_TIME, MIN_TIME, prepare_events
    from rolling_hunt import event_time_bounds, iter_jsonl

RULE_ID = "LSASS-PROCESS-VM-READ-001"
PROCESS_VM_READ = 0x10
ALERT_FIELDS = (
    "@timestamp", "event.id", "host.name", "source.process.guid", "target.process.guid",
    "source.image", "target.image", "process.access_mask",
)


def evaluate_events(events, *, start: str | datetime | None = None,
                    end: str | datetime | None = None, max_events: int = 100_000,
                    max_alerts: int = 10_000) -> dict:
    for name, value in (("max_events", max_events), ("max_alerts", max_alerts)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    bounds = event_time_bounds(start, end)
    if bounds and any(not MIN_TIME <= value <= MAX_TIME for value in bounds):
        raise ValueError("lsass-v1 bounds must be inside its supported date_nanos range")
    try:
        stream = iter(events)
    except TypeError as exc:
        raise ValueError("events must be a finite iterable of normalized objects") from exc
    raw = []
    for event in stream:
        if len(raw) >= max_events:
            raise ValueError(f"max_events exceeded ({max_events}); no partial result is returned")
        raw.append(event)
    prepared, summary = prepare_events(raw)
    summary.update(filtered_events=0, out_of_range_events=0, matched_events=0, alerts=0)
    alerts = []
    for event in sorted(prepared, key=lambda row: (parse_timestamp(row["@timestamp"]), row["event.id"])):
        timestamp = parse_timestamp(event["@timestamp"])
        if bounds and not bounds[0] <= timestamp < bounds[1]:
            summary["out_of_range_events"] += 1
            continue
        if (event["target.image"].rsplit("\\", 1)[-1].translate(ASCII_LOWER) != "lsass.exe"
                or not event["process.access_mask"] & PROCESS_VM_READ):
            summary["filtered_events"] += 1
            continue
        if len(alerts) >= max_alerts:
            raise ValueError(f"max_alerts exceeded ({max_alerts}); no partial result is returned")
        identity = json.dumps(
            [RULE_ID, event["event.id"], event["host.name"], event["source.process.guid"], event["target.process.guid"]],
            ensure_ascii=False, separators=(",", ":"),
        )
        alerts.append({
            "rule.id": RULE_ID,
            "alert.id": "lsass:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            **{field: event[field] for field in ALERT_FIELDS},
        })
        summary["matched_events"] += 1
    summary["alerts"] = len(alerts)
    return {"alerts": alerts, "summary": summary}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--start", help="Inclusive timestamp bound with explicit timezone")
    parser.add_argument("--end", help="Exclusive timestamp bound with explicit timezone")
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args(argv)
    try:
        result = evaluate_events(iter_jsonl(args.events), start=args.start, end=args.end,
                                 max_events=args.max_events, max_alerts=args.max_alerts)
        if not result["summary"]["input_events"]:
            raise ValueError("no events found; an empty replay does not validate a detector")
    except (ValueError, OSError) as exc:
        print(f"LSASS replay failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
