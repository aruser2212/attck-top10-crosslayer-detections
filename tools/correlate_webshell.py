#!/usr/bin/env python3
"""Correlate a successful webroot write with a suspicious request to that file.

This is one offline correlation pilot, not proof that exploitation occurred.
Input is JSONL with literal dotted field names, not nested JSON objects:

* Every event: @timestamp (ISO 8601 with timezone), event.id, event.dataset.
* Both supported sources: host.id and resource.namespace (trusted filesystem scope).
* host.file: file.path, file.operation, event.success (a JSON boolean).
* web.access: web.resource_path, url.query (raw UTF-8 query, no leading ?).

Upstream normalization MUST resolve the HTTP resource to the same canonical
absolute POSIX path used by host telemetry. This tool does not guess document
roots, rewrite URLs, resolve symlinks or lowercase paths. resource.namespace must
identify the actual filesystem/workload namespace, not an untrusted HTTP Host.

Only successful create/write operations on .php/.jsp/.aspx files beneath an
explicit webroot qualify. A request must have an exact query key cmd, exec or
command, after one percent-decoding pass, and match host, namespace and exact path.
The interval is [file_timestamp, file_timestamp + window), default 300 seconds.
Out-of-order input is sorted. Identical normalized event IDs are deduplicated;
conflicting IDs fail. One alert per HTTP event links the latest eligible file
event (ties resolved by event.id). Unknown datasets are counted and ignored.
Optional request bounds [start,end) retain preceding file context. Raw input and
alert caps fail the whole replay. Extension matching identifies script-like names;
neither a filename suffix nor a request proves that a script handler executed it.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl

try:
    from tools.hunt_engine import HuntError, format_timestamp, parse_timestamp, prepare_events
    from tools.rolling_hunt import event_time_bounds
except ModuleNotFoundError:  # Direct invocation: python tools/correlate_webshell.py
    from hunt_engine import HuntError, format_timestamp, parse_timestamp, prepare_events
    from rolling_hunt import event_time_bounds


RULE_ID = "CORR-WEB-WEBROOT-REQUEST-002"
DATASETS = frozenset({"host.file", "web.access"})
EXTENSIONS = frozenset({".php", ".jsp", ".aspx"})
SUSPICIOUS_KEYS = frozenset({"cmd", "exec", "command"})


class CorrelationError(ValueError):
    """The input/configuration does not satisfy the declared pilot contract."""


def _text(event: Mapping[str, Any], field: str) -> str:
    value = event.get(field)
    if (not isinstance(value, str) or not value or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CorrelationError(f"event {event.get('event.id')!r} requires nonempty trimmed {field} without controls")
    _utf8(value, label=field)
    return value


def _utf8(value: str, *, label: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CorrelationError(f"{label} must contain valid UTF-8 text") from exc


def canonical_path(value: Any, *, label: str = "path") -> str:
    """Validate an already-normalized path; never silently rewrite a join key."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise CorrelationError(f"{label} must be an absolute canonical POSIX path")
    _utf8(value, label=label)
    path = PurePosixPath(value)
    if (value.startswith("//") or "\\" in value or ".." in path.parts
            or str(path) != value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CorrelationError(f"{label} must be an absolute canonical POSIX path")
    return value


def suspicious_query_keys(value: Any) -> list[str]:
    if (not isinstance(value, str) or value.startswith("?") or "#" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CorrelationError("url.query must be the raw query string without leading ? or fragment")
    _utf8(value, label="url.query")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise CorrelationError("url.query contains an invalid percent escape")
    try:
        pairs = parse_qsl(value, keep_blank_values=True, encoding="utf-8", errors="strict",
                          max_num_fields=1024, separator="&")
    except (ValueError, UnicodeError) as exc:
        raise CorrelationError(f"invalid UTF-8 url.query: {exc}") from exc
    return sorted({key for key, _ in pairs if key in SUSPICIOUS_KEYS})


def validate_event(event: Mapping[str, Any]) -> None:
    """Validate required fields for either supported normalized source.

    No path, namespace or identity is inferred. This validates the representation,
    not collection authenticity. Unknown datasets are an error to this helper;
    the offline correlate API explicitly counts and ignores them before calling it.
    """
    if not isinstance(event, Mapping):
        raise CorrelationError("correlation event must be an object")
    dataset = event.get("event.dataset")
    if not isinstance(dataset, str) or dataset not in DATASETS:
        raise CorrelationError("correlation requires host.file or web.access events")
    for field in ("event.id", "host.id", "resource.namespace"):
        _text(event, field)
    try:
        parse_timestamp(event.get("@timestamp"))
    except HuntError as exc:
        raise CorrelationError(str(exc)) from exc
    if dataset == "host.file":
        canonical_path(event.get("file.path"), label=f"event {event['event.id']} file.path")
        _text(event, "file.operation")
        if type(event.get("event.success")) is not bool:
            raise CorrelationError(f"event {event['event.id']!r} requires boolean event.success")
    else:
        canonical_path(event.get("web.resource_path"), label=f"event {event['event.id']} web.resource_path")
        suspicious_query_keys(event.get("url.query"))


def _under_webroot(path: str, webroots: tuple[str, ...]) -> bool:
    return any(root == "/" or path.startswith(root + "/") for root in webroots)


def correlate(events: Iterable[Mapping[str, Any]], *, webroots: list[str],
              window_seconds: int = 300,
              start: str | datetime | None = None, end: str | datetime | None = None,
              max_events: int = 100_000, max_alerts: int = 10_000) -> dict[str, Any]:
    """Return deterministic alerts and counters for this finite offline batch."""
    if not isinstance(webroots, list) or not webroots:
        raise CorrelationError("at least one explicit webroot is required")
    roots = tuple(sorted({canonical_path(root, label="webroot") for root in webroots}))
    if (isinstance(window_seconds, bool) or not isinstance(window_seconds, int)
            or not 1 <= window_seconds <= 86400):
        raise CorrelationError("window_seconds must be an integer from 1 to 86400")
    for name, limit in (("max_events", max_events), ("max_alerts", max_alerts)):
        if type(limit) is not int or limit < 1:
            raise CorrelationError(f"{name} must be a positive integer")
    try:
        bounds = event_time_bounds(start, end)
        window = timedelta(seconds=window_seconds)
        context = bounds[0] - window if bounds else None
    except (HuntError, OverflowError) as exc:
        raise CorrelationError(f"invalid correlation request bounds: {exc}") from exc
    raw = []
    try:
        stream = iter(events)
    except TypeError as exc:
        raise CorrelationError("events must be a finite iterable of normalized objects") from exc
    for event in stream:
        if len(raw) >= max_events:
            raise CorrelationError(f"max_events exceeded ({max_events}); no partial result is returned")
        raw.append(event)
    try:
        unique, summary = prepare_events(raw)
    except HuntError as exc:
        raise CorrelationError(str(exc)) from exc
    summary.update({"ignored_dataset_events": 0, "eligible_file_events": 0,
                    "suspicious_http_events": 0, "out_of_range_events": 0,
                    "context_file_events": 0, "alerts": 0})
    files: dict[tuple[str, str, str], list[tuple]] = defaultdict(list)
    requests = []
    for event in unique:
        dataset = event["event.dataset"]
        if dataset not in DATASETS:
            summary["ignored_dataset_events"] += 1
            continue
        validate_event(event)
        host, namespace = event["host.id"], event["resource.namespace"]
        timestamp = parse_timestamp(event["@timestamp"])
        if bounds:
            in_range = (context < timestamp < bounds[1] if dataset == "host.file"
                        else bounds[0] <= timestamp < bounds[1])
            if not in_range:
                summary["out_of_range_events"] += 1
                continue
        if dataset == "host.file":
            path, operation = event["file.path"], event["file.operation"]
            if (operation not in {"create", "write"} or event["event.success"] is not True
                    or PurePosixPath(path).suffix.lower() not in EXTENSIONS
                    or not _under_webroot(path, roots)):
                continue
            files[(host, namespace, path)].append((timestamp, event["event.id"], event))
            summary["eligible_file_events"] += 1
            if bounds and timestamp < bounds[0]:
                summary["context_file_events"] += 1
        else:
            path = event["web.resource_path"]
            keys = suspicious_query_keys(event.get("url.query"))
            if keys:
                requests.append((timestamp, event["event.id"], host, namespace, path, keys))
                summary["suspicious_http_events"] += 1
    for values in files.values():
        values.sort(key=lambda item: (item[0], item[1]))
    timestamps = {key: [item[0] for item in values] for key, values in files.items()}
    alerts = []
    for timestamp, request_id, host, namespace, path, keys in sorted(requests):
        key = (host, namespace, path)
        index = bisect_right(timestamps.get(key, []), timestamp) - 1
        if index < 0:
            continue
        file_timestamp, file_id, event = files[key][index]
        if timestamp - file_timestamp >= window:
            continue
        if len(alerts) >= max_alerts:
            raise CorrelationError(f"max_alerts exceeded ({max_alerts}); no partial result is returned")
        identity = json.dumps([RULE_ID, host, namespace, file_id, request_id],
                              ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        alerts.append({
            "alert.id": hashlib.sha256(identity).hexdigest(),
            "rule.id": RULE_ID,
            "classification": "corroborated_suspicious_activity",
            "@timestamp": format_timestamp(timestamp),
            "host.id": host,
            "resource.namespace": namespace,
            "file.path": path,
            "file.event.id": file_id,
            "file.operation": event["file.operation"],
            "file.timestamp": format_timestamp(file_timestamp),
            "http.event.id": request_id,
            "http.query_keys": keys,
            "elapsed_seconds": (timestamp - file_timestamp).total_seconds(),
        })
    summary["alerts"] = len(alerts)
    return {"rule_id": RULE_ID, "window_seconds": window_seconds,
            "webroots": list(roots), "alerts": alerts, "summary": summary}


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorrelationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_jsonl(path: Path) -> list[dict]:
    events = []
    try:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line, object_pairs_hook=_unique_json_object))
                except (ValueError, json.JSONDecodeError) as exc:
                    raise CorrelationError(f"{path}:{line_number}: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise CorrelationError(f"cannot read {path}: {exc}") from exc
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="normalized JSONL event file")
    parser.add_argument("--webroot", action="append", required=True,
                        help="canonical absolute webroot; repeat for multiple roots")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--start", help="inclusive request timestamp bound, paired with --end")
    parser.add_argument("--end", help="exclusive request timestamp bound, paired with --start")
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args(argv)
    try:
        events = load_jsonl(args.events)
        if not events:
            raise CorrelationError("no events found; an empty replay does not validate a correlation")
        result = correlate(events, webroots=args.webroot,
                           window_seconds=args.window_seconds, start=args.start, end=args.end,
                           max_events=args.max_events, max_alerts=args.max_alerts)
    except (CorrelationError, HuntError) as exc:
        print(f"Correlation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
