#!/usr/bin/env python3
"""Finite, exact Hunt v2 replay with event-anchored rolling windows.

For each group, evaluate (t-W,t] at each distinct eligible event timestamp t.
Events with equal timestamps enter atomically. Every qualifying group/timestamp
produces an alert; there is no episode suppression or continuous state.

Inputs use the same normalized flat fields, ID deduplication and three-valued
predicates as v1. Groups and count_distinct values must be nonempty strings.
Optional bounds select anchors [start,end), retaining context (start-W,end).
Raw input and output caps fail the whole call; they never truncate a result.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from itertools import groupby
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

import yaml
from jsonschema import Draft202012Validator

try:
    from tools.hunt_engine import (
        HuntError, _UniqueLoader, format_timestamp, parse_timestamp,
        predicate_matches, prepare_events, window_seconds,
    )
except ModuleNotFoundError:  # Direct invocation: python tools/rolling_hunt.py
    from hunt_engine import (
        HuntError, _UniqueLoader, format_timestamp, parse_timestamp,
        predicate_matches, prepare_events, window_seconds,
    )

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema/rolling-hunt.schema.yaml"
DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_ALERTS = 10_000


def validate_hunt(rule: Mapping[str, Any]) -> None:
    """Validate only the explicit v2 rolling subset; never reinterpret v1."""
    if not isinstance(rule, dict) or type(rule.get("schema_version")) is not int or rule["schema_version"] != 2:
        raise HuntError("only explicitly versioned schema_version: 2 rolling hunts are executable here")
    try:
        json.dumps(rule, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise HuntError("Rolling Hunt values must be finite JSON-compatible values") from exc
    schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(rule), key=lambda error: str(list(error.path)))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.path) or "<root>"
        raise HuntError(f"invalid rolling Hunt at {location}: {error.message}")
    aggregate = rule["aggregate"]
    window_seconds(aggregate["window"])
    names = [metric["name"] for metric in aggregate["metrics"]]
    if len(names) != len(set(names)):
        raise HuntError("metric names must be unique")
    groups = set(aggregate["group_by"])
    reserved = {"window.start", "window.end"}
    if groups & reserved or set(names) & (groups | reserved):
        raise HuntError("group and metric names must not collide with each other or window fields")
    if set(rule["project"]) != groups | set(names) | reserved:
        raise HuntError("project must contain every group, metric and window field, and no other fields")
    for threshold in rule["having"]:
        if threshold["field"] not in names:
            raise HuntError("having may reference only named aggregate metrics")
        if type(threshold["value"]) is not int or threshold["value"] < 1:
            raise HuntError("having thresholds must be positive integers, without numeric coercion")


def load_hunt(path: str | Path) -> dict[str, Any]:
    try:
        rule = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise HuntError(f"cannot read rolling hunt {path}: {exc}") from exc
    validate_hunt(rule)
    return rule


def event_time_bounds(start: str | datetime | None,
                      end: str | datetime | None) -> tuple[datetime, datetime] | None:
    """Normalize optional anchor bounds to UTC without imposing window alignment."""
    if start is None and end is None:
        return None
    if start is None or end is None:
        raise HuntError("supply both start and end anchor bounds")

    def utc(value: str | datetime) -> datetime:
        if isinstance(value, datetime):
            try:
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("timezone missing")
                return value.astimezone(timezone.utc)
            except (ValueError, OverflowError) as exc:
                raise HuntError("anchor bounds require an explicit timezone") from exc
        return parse_timestamp(value)

    lower, upper = utc(start), utc(end)
    if upper <= lower:
        raise HuntError("end anchor bound must be later than start")
    return lower, upper


def _limit(value: int, name: str) -> int:
    if type(value) is not int or value < 1:
        raise HuntError(f"{name} must be a positive integer")
    return value


def _subtract_window(timestamp: datetime, window: timedelta) -> datetime:
    try:
        return timestamp - window
    except OverflowError as exc:
        raise HuntError("rolling interval is outside the supported datetime range") from exc


def evaluate_hunt(rule: Mapping[str, Any], events: Iterable[Mapping[str, Any]], *,
                  start: str | datetime | None = None, end: str | datetime | None = None,
                  max_events: int = DEFAULT_MAX_EVENTS,
                  max_alerts: int = DEFAULT_MAX_ALERTS) -> dict[str, Any]:
    validate_hunt(rule)
    _limit(max_events, "max_events")
    _limit(max_alerts, "max_alerts")
    bounds = event_time_bounds(start, end)
    window = timedelta(seconds=window_seconds(rule["aggregate"]["window"]))
    history_start = _subtract_window(bounds[0], window) if bounds else None

    # Bound the raw stream before deduplication or filtering; repeats and events
    # outside the requested history still consume the caller's input budget.
    raw = []
    try:
        stream = iter(events)
    except TypeError as exc:
        raise HuntError("events must be a finite iterable of normalized objects") from exc
    for event in stream:
        if len(raw) >= max_events:
            raise HuntError(f"max_events exceeded ({max_events}); no partial result is returned")
        raw.append(event)
    prepared, summary = prepare_events(raw)
    summary.update(filtered_events=0, rejected_events=0, out_of_range_events=0,
                   matched_events=0, context_events=0, anchors_evaluated=0, alerts=0)

    aggregate = rule["aggregate"]
    groups = aggregate["group_by"]
    metrics = aggregate["metrics"]
    required = set(groups) | {metric["field"] for metric in metrics if metric["fn"] == "count_distinct"}
    grouped = defaultdict(list)
    for event in prepared:
        if event["event.dataset"] != rule["dataset"]:
            summary["filtered_events"] += 1
            continue
        matched = predicate_matches(rule["where"], event)
        if matched is None:
            summary["rejected_events"] += 1
            continue
        if not matched:
            summary["filtered_events"] += 1
            continue
        if any(not isinstance(event.get(field), str) or not event[field].strip() for field in required):
            summary["rejected_events"] += 1
            continue
        timestamp = parse_timestamp(event["@timestamp"])
        if bounds and not (history_start < timestamp < bounds[1]):
            summary["out_of_range_events"] += 1
            continue
        key = tuple(event[field] for field in groups)
        grouped[key].append((timestamp, event))
        summary["matched_events"] += 1
        if bounds and timestamp < bounds[0]:
            summary["context_events"] += 1

    alerts = []
    distinct_metrics = [metric for metric in metrics if metric["fn"] == "count_distinct"]
    for group_key in sorted(grouped):
        ordered = sorted(grouped[group_key], key=lambda item: item[0])
        active = deque()
        distinct = {metric["name"]: Counter() for metric in distinct_metrics}
        for anchor, same_time in groupby(ordered, key=lambda item: item[0]):
            lower = _subtract_window(anchor, window)
            # Expire the closed lower boundary before including every tied event.
            while active and active[0][0] <= lower:
                _, removed = active.popleft()
                for metric in distinct_metrics:
                    counter = distinct[metric["name"]]
                    value = removed[metric["field"]]
                    counter[value] -= 1
                    if counter[value] == 0:
                        del counter[value]
            for item in same_time:
                active.append(item)
                for metric in distinct_metrics:
                    distinct[metric["name"]][item[1][metric["field"]]] += 1
            if bounds and anchor < bounds[0]:
                continue
            summary["anchors_evaluated"] += 1
            record = dict(zip(groups, group_key))
            record.update({"window.start": format_timestamp(lower), "window.end": format_timestamp(anchor)})
            for metric in metrics:
                record[metric["name"]] = len(active) if metric["fn"] == "count" else len(distinct[metric["name"]])
            if not all(record[term["field"]] >= term["value"] for term in rule["having"]):
                continue
            if len(alerts) >= max_alerts:
                raise HuntError(f"max_alerts exceeded ({max_alerts}); no partial result is returned")
            alerts.append({field: record[field] for field in rule["project"]})
    alerts.sort(key=lambda row: (parse_timestamp(row["window.end"]), tuple(row[field] for field in groups)))
    summary["alerts"] = len(alerts)
    return {"alerts": alerts, "summary": summary}


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HuntError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def iter_jsonl(path: str | Path) -> Iterable[dict]:
    """Stream input so the raw record cap applies before loading a whole file."""
    try:
        with Path(path).open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if line.strip():
                    try:
                        yield json.loads(line, object_pairs_hook=_json_object)
                    except json.JSONDecodeError as exc:
                        raise HuntError(f"invalid JSON on line {number} of {path}") from exc
    except OSError as exc:
        raise HuntError(f"cannot read events {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hunt", type=Path)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--start", help="Inclusive anchor bound with explicit timezone")
    parser.add_argument("--end", help="Exclusive anchor bound with explicit timezone")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    parser.add_argument("--max-alerts", type=int, default=DEFAULT_MAX_ALERTS)
    args = parser.parse_args(argv)
    try:
        result = evaluate_hunt(
            load_hunt(args.hunt), iter_jsonl(args.events), start=args.start, end=args.end,
            max_events=args.max_events, max_alerts=args.max_alerts,
        )
        if not result["summary"]["input_events"]:
            raise HuntError("no events found; an empty replay does not validate a detector")
    except HuntError as exc:
        print(f"Rolling Hunt replay failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
