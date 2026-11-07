#!/usr/bin/env python3
"""Finite 4624 NewCredentials / 4672 same-session privilege candidate.

The join uses host.name, trusted host.boot.id, canonical nonzero LogonId and the
local token SID. 4624 must report LogonType 9 and seclogo. A 4672 may precede or
follow the 4624 within an explicit symmetric record-time tolerance; native audit
publication order is not treated as causality. Legitimate runas /netonly can meet
the same predicate. This is neither proof of Pass-the-Hash nor a collector.

One candidate per qualifying 4624 links all qualifying 4672 records and their
privileges. Multiple distinct 4624 records for a qualifying anchor's host/boot/LUID
are ambiguous and fail the whole replay; background keys are not subject to this
guard. A different SID in the same session/time interval also fails explicitly.
Optional [start,end) bounds apply to 4624 anchors; all source records remain
available for ambiguity checks and 4672 context. Time arithmetic is microseconds.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import sys

try:
    from tools.hunt_engine import parse_timestamp
    from tools.newcredentials_profile import MAX_TIME, MIN_TIME, prepare_events
    from tools.rolling_hunt import event_time_bounds, iter_jsonl
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp
    from newcredentials_profile import MAX_TIME, MIN_TIME, prepare_events
    from rolling_hunt import event_time_bounds, iter_jsonl

RULE_ID = "CORR-WIN-NEWCREDENTIALS-PRIVILEGES-001"
MAX_SKEW_SECONDS = 86400


def correlate(events, *, max_skew_seconds: int = 30,
              start: str | datetime | None = None, end: str | datetime | None = None,
              max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    """Evaluate only complete, unambiguous source evidence; never partial alerts."""
    if type(max_skew_seconds) is not int or not 0 <= max_skew_seconds <= MAX_SKEW_SECONDS:
        raise ValueError(f"max_skew_seconds must be an integer from 0 through {MAX_SKEW_SECONDS}")
    for name, value in (("max_events", max_events), ("max_alerts", max_alerts)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    bounds = event_time_bounds(start, end)
    if bounds and any(not MIN_TIME <= value <= MAX_TIME for value in bounds):
        raise ValueError("newcredentials-v1 bounds must be inside its supported date_nanos range")
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
    ordered = sorted(prepared, key=lambda row: (parse_timestamp(row["@timestamp"]), row["event.id"]))
    logons = []
    sessions = defaultdict(list)
    privilege_groups = defaultdict(list)
    for event in ordered:
        scope = (event["host.name"], event["host.boot.id"], event["session.id"])
        if event["event.code"] == "4624":
            sessions[scope].append(event)
            logons.append(event)
        else:
            privilege_groups[scope].append(event)
    privilege_times = {
        key: [parse_timestamp(event["@timestamp"]) for event in group]
        for key, group in privilege_groups.items()
    }
    summary.update(logon_events=len(logons), privilege_events=len(ordered) - len(logons),
                   filtered_logons=0, out_of_range_logons=0, candidate_logons=0,
                   matched_privilege_events=0, alerts=0)
    alerts = []
    skew = timedelta(seconds=max_skew_seconds)
    for logon in logons:
        timestamp = parse_timestamp(logon["@timestamp"])
        if bounds and not bounds[0] <= timestamp < bounds[1]:
            summary["out_of_range_logons"] += 1
            continue
        if logon["win.logon_type"] != 9 or logon["win.logon_process"] != "seclogo":
            summary["filtered_logons"] += 1
            continue
        summary["candidate_logons"] += 1
        scope = (logon["host.name"], logon["host.boot.id"], logon["session.id"])
        if len(sessions[scope]) != 1:
            raise ValueError("ambiguous session: multiple distinct 4624 events for a candidate host/boot/LogonId")
        key = (*scope, logon["user.id"])
        times = privilege_times.get(scope, [])
        group = privilege_groups.get(scope, [])
        linked = group[bisect_left(times, timestamp - skew):bisect_right(times, timestamp + skew)]
        if any(event["user.id"] != logon["user.id"] for event in linked):
            raise ValueError("contradictory SID in the candidate host/boot/LogonId time context")
        if not linked:
            continue
        if len(alerts) >= max_alerts:
            raise ValueError(f"max_alerts exceeded ({max_alerts}); no partial result is returned")
        identity = json.dumps([RULE_ID, *key, logon["event.id"]], ensure_ascii=False, separators=(",", ":"))
        alerts.append({
            "rule.id": RULE_ID,
            "alert.id": "newcredentials:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "@timestamp": logon["@timestamp"],
            "host.name": logon["host.name"], "host.boot.id": logon["host.boot.id"],
            "session.id": logon["session.id"], "user.id": logon["user.id"],
            "logon.event.id": logon["event.id"],
            "privilege.event.ids": [event["event.id"] for event in linked],
            "privilege.time_deltas_us": [
                (parse_timestamp(event["@timestamp"]) - timestamp) // timedelta(microseconds=1)
                for event in linked
            ],
            "win.privileges": sorted({name for event in linked for name in event["win.privileges"]}),
        })
        summary["matched_privilege_events"] += len(linked)
    summary["alerts"] = len(alerts)
    return {"alerts": alerts, "summary": summary}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--max-skew-seconds", type=int, default=30)
    parser.add_argument("--start", help="Inclusive 4624 anchor bound with explicit timezone")
    parser.add_argument("--end", help="Exclusive 4624 anchor bound with explicit timezone")
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args(argv)
    try:
        result = correlate(iter_jsonl(args.events), max_skew_seconds=args.max_skew_seconds,
                           start=args.start, end=args.end,
                           max_events=args.max_events, max_alerts=args.max_alerts)
        if not result["summary"]["input_events"]:
            raise ValueError("no events found; an empty replay does not validate a detector")
    except (ValueError, OSError) as exc:
        print(f"NewCredentials correlation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
