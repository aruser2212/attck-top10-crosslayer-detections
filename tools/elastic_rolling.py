#!/usr/bin/env python3
"""Finite, exact rolling Hunt v2 replay using an auth-v2 Elasticsearch index.

The separate date_nanos mapping preserves the input's microsecond timestamps.
PIT/search_after fetches complete bounded raw input; the shared rolling reference
algorithm evaluates (t-W,t] at eligible event timestamps with atomic ties. This
is not an Elasticsearch rolling histogram and does not alter the v1 scheduler.
Private profile hooks share finite transport with Kerberos and web correlation;
the public functions below continue to require the auth-v2 profile.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys

try:
    from tools.elastic_adapter import (
        ElasticClient, ElasticError, KEYWORD_FIELDS, ensure_search_visibility,
        get_index_identity, index_path,
    )
    from tools.hunt_engine import parse_timestamp, prepare_events, read_jsonl, window_seconds
    from tools.rolling_hunt import evaluate_hunt, event_time_bounds, load_hunt, validate_hunt
except ModuleNotFoundError:
    from elastic_adapter import (
        ElasticClient, ElasticError, KEYWORD_FIELDS, ensure_search_visibility,
        get_index_identity, index_path,
    )
    from hunt_engine import parse_timestamp, prepare_events, read_jsonl, window_seconds
    from rolling_hunt import evaluate_hunt, event_time_bounds, load_hunt, validate_hunt

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "attck-auth-v2"
MAPPING_PATH = ROOT / "profiles/elastic/auth-v2.mapping.json"
MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(2262, 4, 11, 23, 47, 16, 854775, tzinfo=timezone.utc)
DATASET = "windows.security.logons"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def positive_int(value, name: str, maximum: int | None = None) -> None:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ElasticError(f"{name} must be a positive integer" + (f" at most {maximum}" if maximum else ""))


def checked_time(value: str | datetime, *, label: str = "auth-v2") -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ElasticError(f"{label} timestamps require an explicit timezone")
        result = value.astimezone(timezone.utc)
    else:
        result = parse_timestamp(value)
    if not MIN_TIME <= result <= MAX_TIME:
        raise ElasticError(f"{label} date_nanos range is 1970-01-01 through 2262-04-11T23:47:16.854775Z")
    return result


def _prepare(events) -> tuple[list[dict], dict]:
    """Share canonical timestamp/duplicate validation with v1, then enforce v2."""
    unique, counters = prepare_events(events)
    for event in unique:
        checked_time(event["@timestamp"])
        if event["event.dataset"] != DATASET:
            raise ElasticError("auth-v2 supports only windows.security.logons events")
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ElasticError("event.id exceeds Elasticsearch's 512-byte _id limit")
        for field in KEYWORD_FIELDS:
            value = event.get(field)
            if value is not None and not isinstance(value, str):
                raise ElasticError(f"auth-v2 requires scalar string or null for {field}")
            if isinstance(value, str) and value and not value.strip():
                raise ElasticError(f"auth-v2 rejects whitespace-only values for {field}")
        if any(isinstance(event.get(key), dict) for key in ("event", "source", "target", "host")):
            raise ElasticError("auth-v2 uses flat dotted fields, not nested auth objects")
    return unique, counters


def create_index(client: ElasticClient, index: str) -> None:
    """Create a new v2 index; never overwrite or migrate a v1 mapping."""
    _create_index(client, index, MAPPING_PATH)


def _create_index(client: ElasticClient, index: str, mapping_path: Path) -> None:
    client.request("PUT", index_path(index), json.loads(mapping_path.read_text(encoding="utf-8")))


def check_profile(client: ElasticClient, index: str) -> None:
    _check_profile(client, index, MAPPING_PATH, "auth-v2")


def _check_profile(client: ElasticClient, index: str, mapping_path: Path, label: str) -> None:
    response = client.request("GET", index_path(index) + "/_mapping")
    expected = json.loads(mapping_path.read_text(encoding="utf-8"))["mappings"]
    if set(response) != {index} or not isinstance(response[index], dict):
        raise ElasticError(f"{label} requires one concrete index, not an alias")
    mapping = response[index].get("mappings", {})
    if (mapping.get("_meta") != expected["_meta"] or mapping.get("properties") != expected["properties"]
            or mapping.get("dynamic") not in (False, "false")):
        raise ElasticError(f"Index does not match the separate {label} date_nanos profile")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    """Create-only immutable ID ingestion followed by a checked search refresh.

    Normalization, HTTP transport, identity lookup and visibility barrier share
    the existing adapter primitives. Only v2 profile/range checks and the
    version-specific ingestion orchestration live here; v1 behavior is unchanged.
    """
    return _ingest_events(client, index, events, prepare=_prepare,
                          profile_checker=check_profile, batch_size=batch_size)


def _ingest_events(client: ElasticClient, index: str, events: list[dict], *, prepare,
                   profile_checker, batch_size: int = 500) -> dict:
    """Shared immutable ingestion; profile validation precedes all writes."""
    positive_int(batch_size, "batch_size")
    unique, counters = prepare(events)
    profile_checker(client, index)
    identity = get_index_identity(client, index)
    missing = []
    existing = 0
    for offset in range(0, len(unique), batch_size):
        batch = unique[offset:offset + batch_size]
        response = client.request("POST", index_path(index) + "/_mget", {"ids": [event["event.id"] for event in batch]})
        docs = response.get("docs")
        if not isinstance(docs, list) or len(docs) != len(batch):
            raise ElasticError("Incomplete existing-event lookup")
        for event, doc in zip(batch, docs):
            if (not isinstance(doc, dict) or doc.get("error") or doc.get("_id") != event["event.id"]
                    or doc.get("_index") != index or type(doc.get("found")) is not bool):
                raise ElasticError("Invalid existing-event lookup")
            if doc["found"]:
                if canonical(doc.get("_source")) != canonical(event):
                    raise ElasticError(f"Conflicting stored event.id: {event['event.id']}")
                existing += 1
            else:
                missing.append(event)
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced before ingestion")
    for offset in range(0, len(missing), batch_size):
        batch = missing[offset:offset + batch_size]
        lines = []
        for event in batch:
            lines.extend((canonical({"create": {"_id": event["event.id"]}}), canonical(event)))
        response = client.request("POST", index_path(index) + "/_bulk?refresh=false", "\n".join(lines) + "\n", ndjson=True)
        items = response.get("items")
        if response.get("errors") or not isinstance(items, list) or len(items) != len(batch):
            raise ElasticError("Bulk create failed; partial writes may need an idempotent retry")
        for event, item in zip(batch, items):
            result = item.get("create", {}) if isinstance(item, dict) else {}
            if result.get("status") != 201 or result.get("_id") != event["event.id"] or result.get("_index") != index:
                raise ElasticError("Bulk create acknowledgement was incomplete; retry only unchanged events")
    if unique:
        ensure_search_visibility(client, index)
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced during ingestion; acknowledgement withheld")
    return {**counters, "inserted_events": len(missing), "existing_events": existing}


def _complete_shards(response: dict) -> None:
    shards = response.get("_shards")
    if (response.get("timed_out") is not False or response.get("error") or response.get("terminated_early")
            or not isinstance(shards, dict)
            or any(type(shards.get(key)) is not int for key in ("total", "successful", "failed"))
            or shards["total"] < 1 or shards["successful"] != shards["total"]
            or shards["failed"] != 0 or shards.get("failures")):
        raise ElasticError("Rolling search was incomplete; no partial alerts are returned")


def _nanoseconds(value: datetime) -> int:
    delta = value - MIN_TIME
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _sort_timestamp(value, *, label: str = "auth-v2") -> int:
    # ES emits strict_date_optional_time_nanos strings. Only zero sub-microsecond
    # digits are valid for this profile; do not silently truncate remote values.
    if not isinstance(value, str):
        raise ElasticError("Expected a formatted date_nanos search sort value")
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", value)
    if not match:
        raise ElasticError("Malformed date_nanos search sort value")
    fraction = (match[2] or "").ljust(9, "0")
    if int(fraction[6:]):
        raise ElasticError(f"Remote timestamp has sub-microsecond precision outside {label}")
    parsed = checked_time(match[1] + "." + fraction[:6] + match[3], label=label)
    return _nanoseconds(parsed)


def _query_timestamp(value: datetime) -> str:
    # ES rounds an exclusive `gt` bound without fractional seconds up through
    # that entire second, even on date_nanos. Keep explicit microseconds when
    # they are zero so context+1us remains visible to the rolling evaluator.
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def evaluate_index(client: ElasticClient, index: str, rule: dict, *, page_size: int = 500,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None,
                   max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    return _evaluate_index(client, index, rule, dataset=DATASET, profile=PROFILE,
                           prepare=_prepare, profile_checker=check_profile,
                           page_size=page_size, start=start, end=end,
                           expected_index_uuid=expected_index_uuid,
                           max_events=max_events, max_alerts=max_alerts)


def _evaluate_index(client: ElasticClient, index: str, rule: dict, *, dataset: str,
                    profile: str, prepare, profile_checker, page_size: int = 500,
                    start: str | datetime | None = None, end: str | datetime | None = None,
                    expected_index_uuid: str | None = None,
                    max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    """Fetch complete bounded input, validate its profile, then evaluate exactly."""
    validate_hunt(rule)
    if rule["dataset"] != dataset:
        raise ElasticError(f"Elastic rolling {profile} supports only {dataset} hunts")
    positive_int(page_size, "page_size", 10_000)
    positive_int(max_events, "max_events")
    positive_int(max_alerts, "max_alerts")
    bounds = event_time_bounds(start, end)
    filters = [{"term": {"event.dataset": dataset}}]
    if bounds:
        lower, upper = (checked_time(value, label=profile) for value in bounds)
        context = lower - timedelta(seconds=window_seconds(rule["aggregate"]["window"]))
        time_range = {"lt": _query_timestamp(upper)}
        if context >= MIN_TIME:
            time_range["gt"] = _query_timestamp(context)
        # Below the profile's minimum all representable events are history;
        # omitting the lower range includes exactly the epoch event too.
        filters.append({"range": {"@timestamp": time_range}})
    events, identity, pages = _read_events(
        client, index, filters=filters, profile=profile, prepare=prepare,
        profile_checker=profile_checker, page_size=page_size,
        history_bounds=(context, upper) if bounds else None,
        expected_index_uuid=expected_index_uuid, max_events=max_events,
    )
    result = evaluate_hunt(rule, events, start=start, end=end, max_events=max_events, max_alerts=max_alerts)
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced during rolling evaluation")
    return {"alerts": result["alerts"], "summary": {**result["summary"], "fetch_pages": pages, "fetched_events": len(events)},
            "source": identity, "profile": profile}


def _read_events(client: ElasticClient, index: str, *, filters: list[dict], profile: str,
                 prepare, profile_checker, page_size: int = 500,
                 history_bounds: tuple[datetime, datetime] | None = None,
                 expected_index_uuid: str | None = None,
                 max_events: int = 100_000) -> tuple[list[dict], dict, int]:
    """Read a complete finite snapshot for a caller's declared source domain.

    The caller constructs exact filters and validates its own time/configuration
    contract first. This reader enforces source identity, profile, pagination and
    limits. The caller must recheck the returned source identity after computing
    its result so index replacement cannot be acknowledged as a valid replay.
    """
    positive_int(page_size, "page_size", 10_000)
    positive_int(max_events, "max_events")
    profile_checker(client, index)
    identity = get_index_identity(client, index)
    if expected_index_uuid is not None and expected_index_uuid != identity["uuid"]:
        raise ElasticError("Source index UUID differs from the expected binding")
    opened = client.request("POST", index_path(index) + "/_pit?keep_alive=1m&allow_partial_search_results=false")
    pit = opened.get("id")
    if not isinstance(pit, str) or not pit:
        raise ElasticError("Elasticsearch did not return a valid point-in-time ID")
    events = []
    seen_ids = set()
    previous_sort = None
    after = None
    pages = 0
    try:
        while True:
            body = {
                "size": min(page_size, max_events + 1 - len(events)),
                "track_total_hits": False,
                "_source": True,
                "pit": {"id": pit, "keep_alive": "1m"},
                "query": {"bool": {"filter": filters}},
                "sort": [{"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos", "numeric_type": "date_nanos"}}, {"_shard_doc": "asc"}],
            }
            if after is not None:
                body["search_after"] = after
            response = client.request("POST", "/_search?allow_partial_search_results=false", body)
            new_pit = response.get("pit_id", pit)
            if not isinstance(new_pit, str) or not new_pit:
                raise ElasticError("Search returned an invalid updated PIT ID")
            pit = new_pit
            _complete_shards(response)
            hits = response.get("hits", {}).get("hits") if isinstance(response.get("hits"), dict) else None
            if not isinstance(hits, list) or len(hits) > body["size"]:
                raise ElasticError("Malformed rolling search page")
            pages += 1
            if not hits:
                break
            for hit in hits:
                if not isinstance(hit, dict) or hit.get("_index") != index or not isinstance(hit.get("_source"), dict):
                    raise ElasticError("Search returned invalid source metadata")
                source = hit["_source"]
                prepared, _ = prepare([source])
                event = prepared[0]
                if canonical(event) != canonical(source):
                    raise ElasticError(f"Index contains noncanonical {profile} source events")
                if hit.get("_id") != event["event.id"] or event["event.id"] in seen_ids:
                    raise ElasticError("Search violated unique event.id/_id identity")
                sort = hit.get("sort")
                if not isinstance(sort, list) or len(sort) != 2 or type(sort[1]) is not int or sort[1] < 0:
                    raise ElasticError("Search returned an invalid stable sort key")
                sort_key = (_sort_timestamp(sort[0], label=profile), sort[1])
                event_time = checked_time(event["@timestamp"], label=profile)
                if sort_key[0] != _nanoseconds(event_time):
                    raise ElasticError("Indexed timestamp sort differs from event source precision")
                if previous_sort is not None and sort_key <= previous_sort:
                    raise ElasticError("search_after ordering did not advance")
                if history_bounds and not (history_bounds[0] < event_time < history_bounds[1]):
                    raise ElasticError("Search returned an event outside the requested history bounds")
                previous_sort = sort_key
                after = sort
                seen_ids.add(event["event.id"])
                events.append(event)
                if len(events) > max_events:
                    raise ElasticError("Rolling max_events exceeded; no partial alerts are returned")
    finally:
        # Preserve an original search error if PIT cleanup also fails.
        active_error = sys.exc_info()[0] is not None
        try:
            closed = client.request("DELETE", "/_pit", {"id": pit})
            if closed.get("succeeded") is not True:
                raise ElasticError("PIT cleanup was not acknowledged")
        except ElasticError:
            if not active_error:
                raise
    return events, identity, pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--index", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-index")
    ingest = commands.add_parser("ingest")
    ingest.add_argument("events", type=Path)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("hunt", type=Path)
    evaluate.add_argument("--start")
    evaluate.add_argument("--end")
    evaluate.add_argument("--page-size", type=int, default=500)
    evaluate.add_argument("--max-events", type=int, default=100_000)
    evaluate.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args()
    try:
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"), username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        if args.command == "create-index":
            create_index(client, args.index)
            result = {"created": args.index, "profile": PROFILE}
        elif args.command == "ingest":
            result = ingest_events(client, args.index, read_jsonl(args.events))
        else:
            result = evaluate_index(client, args.index, load_hunt(args.hunt), page_size=args.page_size, start=args.start, end=args.end, max_events=args.max_events, max_alerts=args.max_alerts)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Elastic rolling failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
