#!/usr/bin/env python3
"""Replay the explicitly versioned Hunt DSL v1 subset against normalized JSONL.

Input fields use literal dotted keys (not nested objects). Every event requires
@timestamp with a timezone, globally unique event.id, and event.dataset. Duplicate
IDs with identical normalized payload are counted once; conflicting payloads fail.
Predicates are case-sensitive and do not coerce strings to numbers. Missing/null
fields have unknown truth value, including under NOT, and never match by default.
Grouping/distinct fields must be nonempty strings. Missing or incompatible values
are rejected and counted in the summary.

Windows are UTC epoch-aligned, half-open tumbling intervals, not rolling windows.
For example, 00:04:59 and 00:05:00 belong to different five-minute windows. Replay
consumes a complete finite batch; it has no watermark or persistent state, and
does not implement first_seen, sequences, joins or count_if. Unsupported rules
fail before execution. One alert is emitted per qualifying group/window, sorted
deterministically and projected as specified by the actual rule.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class HuntError(ValueError):
    """Invalid rule or event contract; replay must not be reported as successful."""


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in result:
                raise HuntError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
            result[key] = loader.construct_object(value_node, deep=deep)
        except TypeError as exc:
            raise HuntError("YAML mapping keys must be scalar") from exc
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def window_seconds(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smhd])", value)
    if match is None:
        raise HuntError("window must be a positive integer followed by s, m, h or d")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    if seconds > 31 * 86400:
        raise HuntError("v1 windows cannot exceed 31 days")
    return seconds


def validate_hunt(rule: Mapping[str, Any]) -> None:
    if not isinstance(rule, dict) or rule.get("schema_version") != 1:
        raise HuntError("only explicitly versioned schema_version: 1 hunts are executable")
    try:
        json.dumps(rule, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise HuntError("Hunt DSL values must be finite JSON-compatible values") from exc
    schema = yaml.safe_load((ROOT / "schema/hunt.schema.yaml").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(rule), key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.path) or "<root>"
        raise HuntError(f"invalid Hunt DSL at {location}: {error.message}")
    aggregate = rule["aggregate"]
    window_seconds(aggregate["window"])
    names = [metric["name"] for metric in aggregate["metrics"]]
    if len(names) != len(set(names)):
        raise HuntError("metric names must be unique")
    reserved = {"window.start", "window.end"}
    groups = set(aggregate["group_by"])
    if groups & reserved or set(names) & (groups | reserved):
        raise HuntError("group and metric names must not collide with each other or window fields")
    available = groups | set(names) | reserved
    if not set(rule["project"]) <= available:
        raise HuntError("project may contain only group fields, metric names and window.start/window.end")
    if any(term["field"] not in names for term in rule["having"]):
        raise HuntError("having may reference only named aggregate metrics")


def load_hunt(path: str | Path) -> dict[str, Any]:
    try:
        rule = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise HuntError(f"cannot read hunt {path}: {exc}") from exc
    validate_hunt(rule)
    return rule


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        raise HuntError("@timestamp must be an RFC 3339 string with timezone and at most microsecond precision")
    try:
        if not value.endswith("Z"):
            # fromisoformat normalizes e.g. +03:60 to +04:00. Reject an invalid
            # source offset rather than silently changing its representation.
            if int(value[-5:-3]) > 23 or int(value[-2:]) > 59:
                raise ValueError("timezone offset hours/minutes are outside RFC 3339 bounds")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone missing")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise HuntError(f"invalid timezone-qualified @timestamp: {value!r}") from exc


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def prepare_events(events: Iterable[Mapping[str, Any]]) -> tuple[list[dict], dict[str, int]]:
    unique: dict[str, dict] = {}
    counters = {"input_events": 0, "unique_events": 0, "duplicate_events": 0}
    for index, raw in enumerate(events, 1):
        counters["input_events"] += 1
        if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
            raise HuntError(f"event {index} must be a JSON object with string field names")
        event = dict(raw)
        for field in ("event.id", "event.dataset"):
            if not isinstance(event.get(field), str) or not event[field].strip():
                raise HuntError(f"event {index} requires nonempty {field}")
        event["@timestamp"] = format_timestamp(parse_timestamp(event.get("@timestamp")))
        try:
            json.dumps(event, allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise HuntError(f"event {index} contains non-JSON/non-finite values") from exc
        identifier = event["event.id"]
        if identifier in unique:
            if json.dumps(unique[identifier], sort_keys=True) != json.dumps(event, sort_keys=True):
                raise HuntError(f"conflicting duplicate event.id {identifier!r}")
            counters["duplicate_events"] += 1
        else:
            unique[identifier] = event
    counters["unique_events"] = len(unique)
    return list(unique.values()), counters


def _is_number(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or (
        isinstance(value, float) and math.isfinite(value)
    )


def _compatible(left: Any, right: Any) -> bool:
    return type(left) is type(right) or (_is_number(left) and _is_number(right))


def predicate_matches(predicate: Mapping[str, Any], event: Mapping[str, Any]) -> bool | None:
    """Three-valued comparison: None means unknown due to missing/incompatible data."""
    if "all" in predicate:
        results = [predicate_matches(term, event) for term in predicate["all"]]
        return False if False in results else (None if None in results else True)
    if "any" in predicate:
        results = [predicate_matches(term, event) for term in predicate["any"]]
        return True if True in results else (None if None in results else False)
    if "not" in predicate:
        value = predicate_matches(predicate["not"], event)
        return None if value is None else not value
    field, operation, expected = predicate["field"], predicate["op"], predicate["value"]
    actual = event.get(field)
    if actual is None or isinstance(actual, (list, dict)):
        return None
    if operation == "eq":
        return actual == expected if _compatible(actual, expected) else None
    if operation == "ne":
        return actual != expected if _compatible(actual, expected) else None
    if operation == "in":
        compatible = [item for item in expected if _compatible(actual, item)]
        return any(actual == item for item in compatible) if compatible else None
    if operation in ("contains", "startswith", "endswith"):
        if not isinstance(actual, str):
            return None
        if operation == "contains":
            return expected in actual
        return getattr(actual, operation)(expected)
    if not _is_number(actual) or not _is_number(expected):
        return None
    return {"gt": actual > expected, "gte": actual >= expected,
            "lt": actual < expected, "lte": actual <= expected}[operation]


def _usable_key(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def evaluate_hunt(rule: Mapping[str, Any], events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    validate_hunt(rule)
    prepared, summary = prepare_events(events)
    summary.update(filtered_events=0, rejected_events=0, matched_events=0, alerts=0)
    aggregate = rule["aggregate"]
    interval = window_seconds(aggregate["window"])
    groups = aggregate["group_by"]
    required = set(groups) | {m["field"] for m in aggregate["metrics"] if m["fn"] == "count_distinct"}
    buckets: dict[tuple, list[dict]] = defaultdict(list)
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
        if any(not _usable_key(event.get(field)) for field in required):
            summary["rejected_events"] += 1
            continue
        offset = parse_timestamp(event["@timestamp"]) - EPOCH
        # Integer microseconds avoid float rounding at exact interval boundaries.
        micros = (offset.days * 86400 + offset.seconds) * 1_000_000 + offset.microseconds
        start = EPOCH + timedelta(seconds=(micros // (interval * 1_000_000)) * interval)
        typed_keys = tuple((type(event[field]).__name__, event[field]) for field in groups)
        buckets[(start, typed_keys)].append(event)
        summary["matched_events"] += 1
    alerts = []
    for (start, keys), bucket in buckets.items():
        record = dict(zip(groups, (value for _, value in keys)))
        record.update({"window.start": format_timestamp(start),
                       "window.end": format_timestamp(start + timedelta(seconds=interval))})
        for metric in aggregate["metrics"]:
            record[metric["name"]] = (len(bucket) if metric["fn"] == "count" else
                len({(type(event[metric["field"]]).__name__, event[metric["field"]]) for event in bucket}))
        if all(predicate_matches(term, record) is True for term in rule["having"]):
            alerts.append({field: record[field] for field in rule["project"]})
    alerts.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    summary["alerts"] = len(alerts)
    return {"alerts": alerts, "summary": summary}


def read_jsonl(path: str | Path) -> list[dict]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise HuntError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        with Path(path).open(encoding="utf-8") as stream:
            return [json.loads(line, object_pairs_hook=unique_object) for line in stream if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise HuntError(f"cannot read events {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hunt", type=Path)
    parser.add_argument("--events", type=Path, required=True, help="normalized JSONL event file")
    args = parser.parse_args(argv)
    try:
        events = read_jsonl(args.events)
        if not events:
            raise HuntError("no events found; an empty replay does not validate a detector")
        result = evaluate_hunt(load_hunt(args.hunt), events)
    except HuntError as exc:
        print(f"Hunt replay failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
