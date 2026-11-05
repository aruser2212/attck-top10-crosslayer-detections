#!/usr/bin/env python3
"""Exact T1110 aggregation on Elasticsearch Basic using the auth-v1 profile.

UTC fixed, half-open tumbling windows deliberately match Hunt v1. Composite
aggregation pagination enumerates distinct users exactly; no approximate
cardinality aggregation is used. A point-in-time search isolates each run.

Only normalized, scalar keyword fields in auth-v1 and count/count_distinct
metrics are supported. Ingest through this adapter to preserve event.id
identity. Optional aligned event-time bounds support the separate durable runner.
"""
from __future__ import annotations

import argparse
import base64
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

try:
    from tools.hunt_engine import (
        format_timestamp, load_hunt, parse_timestamp, prepare_events, read_jsonl, validate_hunt, window_seconds,
    )
except ModuleNotFoundError:  # Direct invocation: python tools/elastic_adapter.py
    from hunt_engine import (
        format_timestamp, load_hunt, parse_timestamp, prepare_events, read_jsonl, validate_hunt, window_seconds,
    )

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "profiles/elastic/auth-v1.mapping.json"
KEYWORD_FIELDS = frozenset({"event.id", "event.dataset", "event.code", "source.ip", "target.user", "host.name"})
PROFILE = "attck-auth-v1"


class ElasticError(ValueError):
    """A failed or unsupported operation; no approximate result is returned."""


class ElasticHTTPError(ElasticError):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


class ElasticClient:
    def __init__(self, url: str, *, api_key: str | None = None,
                 username: str | None = None, password: str | None = None,
                 timeout: float = 30):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ElasticError("Use an http(s) Elasticsearch URL without embedded credentials")
        if parsed.query or parsed.fragment:
            raise ElasticError("Elasticsearch URL must not contain a query or fragment")
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if api_key and username:
            raise ElasticError("Choose API key or username/password authentication")
        if api_key:
            self.headers["Authorization"] = "ApiKey " + api_key
        elif username:
            token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = "Basic " + token

    def request(self, method: str, path: str, body: Any = None, *, ndjson: bool = False) -> dict:
        headers = dict(self.headers)
        if ndjson:
            headers["Content-Type"] = "application/x-ndjson"
            data = body.encode("utf-8")
        else:
            data = None if body is None else json.dumps(body, allow_nan=False).encode("utf-8")
        request = Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.load(response)
        except HTTPError as exc:
            # Do not echo headers, credentials, or the full response body.
            raise ElasticHTTPError(exc.code, f"Elasticsearch {method} {path}: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ElasticError(f"Elasticsearch {method} {path} failed: {type(exc).__name__}") from exc
        if not isinstance(result, dict):
            raise ElasticError("Elasticsearch returned a non-object response")
        return result


def index_path(index: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,199}", index):
        raise ElasticError("Choose one explicit lowercase index name (no wildcards, aliases, or system indices)")
    return "/" + quote(index, safe="")


def create_index(client: ElasticClient, index: str) -> None:
    """Create a new named index. Existing indices are never overwritten."""
    body = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    client.request("PUT", index_path(index), body)


def check_profile(client: ElasticClient, index: str) -> None:
    result = client.request("GET", index_path(index) + "/_mapping")
    if set(result) != {index}:
        raise ElasticError("Use one concrete auth-v1 index, not an alias")
    mappings = result[index].get("mappings", {})
    expected_mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["mappings"]
    if any(mappings.get("_meta", {}).get(key) != value for key, value in expected_mapping["_meta"].items()):
        raise ElasticError("Index does not declare the attck-auth-v1 mapping profile")
    expected = expected_mapping["properties"]
    if mappings.get("properties") != expected:
        raise ElasticError("Index field mapping differs from the supported auth-v1 profile")


def get_index_identity(client: ElasticClient, index: str) -> dict[str, str]:
    """Resolve one concrete index to its immutable Elasticsearch UUID.

    A durable checkpoint must bind this UUID, not merely a reusable index name.
    Alias resolution, absent UUIDs and malformed settings fail closed.
    """
    result = client.request("GET", index_path(index) + "/_settings?flat_settings=true")
    if set(result) != {index} or not isinstance(result[index], dict):
        raise ElasticError("Source identity requires one concrete index, not an alias")
    settings = result[index].get("settings", {})
    identifier = settings.get("index.uuid") if isinstance(settings, dict) else None
    if not isinstance(identifier, str) or not identifier.strip() or identifier == "_na_":
        raise ElasticError("Elasticsearch did not return a valid source index UUID")
    return {"name": index, "uuid": identifier}


def event_time_bounds(rule: dict, start: str | datetime | None,
                      end: str | datetime | None) -> tuple[str, str] | None:
    """Return normalized [start,end) bounds covering complete tumbling windows."""
    if start is None and end is None:
        return None
    if start is None or end is None:
        raise ElasticError("Supply both start and end event-time bounds")

    def utc(value: str | datetime) -> datetime:
        try:
            if isinstance(value, datetime):
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("naive datetime")
                return value.astimezone(timezone.utc)
            return parse_timestamp(value)
        except (ValueError, OverflowError, TypeError) as exc:
            raise ElasticError("Event-time bounds require timezone-qualified RFC 3339 timestamps") from exc

    lower, upper = utc(start), utc(end)
    if upper <= lower:
        raise ElasticError("Event-time end must be later than start")
    interval = window_seconds(rule["aggregate"]["window"])
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for bound in (lower, upper):
        delta = bound - epoch
        if delta.microseconds or (delta.days * 86400 + delta.seconds) % interval:
            raise ElasticError("Event-time bounds must align to complete UTC tumbling windows")
    return format_timestamp(lower), format_timestamp(upper)


def ensure_search_visibility(client: ElasticClient, index: str) -> None:
    """Complete a synchronous refresh before acknowledging searchable input.

    Realtime _mget can see translog records that PIT/search cannot yet see.
    A retry with only existing IDs must cross this barrier too. Require a
    complete shard response rather than treating HTTP 200 as sufficient.
    """
    response = client.request("POST", index_path(index) + "/_refresh")
    shards = response.get("_shards")
    if (response.get("timed_out", False) is not False or response.get("error")
            or not isinstance(shards, dict)
            or any(type(shards.get(field)) is not int for field in ("total", "successful", "failed"))
            or shards["total"] < 1 or shards["successful"] != shards["total"]
            or shards["failed"] != 0 or shards.get("failures")):
        raise ElasticError("Search visibility refresh was incomplete; ingestion must be retried before acknowledgement")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    """Idempotent ingestion; conflicting IDs are rejected before any writes.

    Exact existing records are accepted, but an existing ID with different
    normalized content is an error. Bulk create also rejects concurrent writes
    instead of silently overwriting another event. All successful nonempty
    ingestions end with a checked synchronous refresh, including existing-only
    retries after a crash or lost response. The caller must not acknowledge its
    source queue until this search-visibility barrier succeeds.
    """
    if batch_size < 1:
        raise ElasticError("batch_size must be positive")
    unique, counters = prepare_events(events)
    for event in unique:
        for field in KEYWORD_FIELDS:
            if field in event and event[field] is not None and not isinstance(event[field], str):
                raise ElasticError(f"auth-v1 requires scalar string or null for {field}")
            if isinstance(event.get(field), str) and event[field] and not event[field].strip():
                raise ElasticError(f"auth-v1 rejects whitespace-only values for {field}; use null for missing data")
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ElasticError("event.id exceeds Elasticsearch's 512-byte _id limit")
        if any(isinstance(event.get(key), dict) for key in ("event", "source", "target", "host")):
            raise ElasticError("auth-v1 input uses flat dotted field names, not nested objects")
    check_profile(client, index)
    missing = []
    existing_count = 0
    for offset in range(0, len(unique), batch_size):
        batch = unique[offset:offset + batch_size]
        result = client.request("POST", index_path(index) + "/_mget", {"ids": [e["event.id"] for e in batch]})
        docs = result.get("docs", [])
        if len(docs) != len(batch):
            raise ElasticError("Incomplete existing-event lookup")
        for event, doc in zip(batch, docs):
            if doc.get("error") or doc.get("_id") != event["event.id"]:
                raise ElasticError("Invalid existing-event lookup")
            if doc.get("found"):
                if json.dumps(doc.get("_source"), sort_keys=True, ensure_ascii=False) != json.dumps(event, sort_keys=True, ensure_ascii=False):
                    raise ElasticError(f"Conflicting stored event.id: {event['event.id']}")
                existing_count += 1
            else:
                missing.append(event)
    for offset in range(0, len(missing), batch_size):
        lines = []
        batch = missing[offset:offset + batch_size]
        for event in batch:
            lines.extend([json.dumps({"create": {"_id": event["event.id"]}}), json.dumps(event, allow_nan=False)])
        # One explicit refresh after the whole batch also covers pre-existing
        # records and works when automatic index refreshing is disabled.
        result = client.request("POST", index_path(index) + "/_bulk?refresh=false", "\n".join(lines) + "\n", ndjson=True)
        items = result.get("items", [])
        if result.get("errors") or len(items) != len(batch) or any(i.get("create", {}).get("status") != 201 for i in items):
            raise ElasticError("Bulk create failed; inspect the index before retrying (partial writes are possible)")
    if unique:
        ensure_search_visibility(client, index)
    return {**counters, "inserted_events": len(missing), "existing_events": existing_count}


def keyword(field: str) -> str:
    if field not in KEYWORD_FIELDS:
        raise ElasticError(f"Field is not supported by auth-v1: {field}")
    return field


def predicate_queries(predicate: dict) -> tuple[dict, dict]:
    """Queries for TRUE and FALSE; missing/null remains UNKNOWN under NOT."""
    if "all" in predicate:
        parts = [predicate_queries(p) for p in predicate["all"]]
        return ({"bool": {"filter": [p[0] for p in parts]}},
                {"bool": {"should": [p[1] for p in parts], "minimum_should_match": 1}})
    if "any" in predicate:
        parts = [predicate_queries(p) for p in predicate["any"]]
        return ({"bool": {"should": [p[0] for p in parts], "minimum_should_match": 1}},
                {"bool": {"filter": [p[1] for p in parts]}})
    if "not" in predicate:
        positive, negative = predicate_queries(predicate["not"])
        return negative, positive
    field = keyword(predicate["field"])
    op, value = predicate["op"], predicate.get("value")
    if op == "eq" and isinstance(value, str):
        positive = {"term": {field: value}}
    elif op == "in" and isinstance(value, list) and all(isinstance(v, str) for v in value):
        positive = {"terms": {field: value}}
    else:
        raise ElasticError(f"Elastic auth-v1 supports only string eq/in predicates, not {op}")
    negative = {"bool": {"filter": [{"exists": {"field": field}}], "must_not": [positive]}}
    return positive, negative


def predicate_query(predicate: dict) -> dict:
    return predicate_queries(predicate)[0]


def compile_hunt(rule: dict, *, page_size: int = 500) -> tuple[dict, list[str]]:
    validate_hunt(rule)
    if rule["dataset"] != "windows.security.logons":
        raise ElasticError("auth-v1 currently supports only windows.security.logons")
    if not 1 <= page_size <= 10000:
        raise ElasticError("page_size must be between 1 and 10000")
    aggregate = rule["aggregate"]
    for clause in rule["having"]:
        if clause["op"] not in {"eq", "ne", "gt", "gte", "lt", "lte"} or type(clause["value"]) not in (int, float):
            raise ElasticError("Elastic auth-v1 having supports only numeric comparisons")
    dimensions = list(aggregate["group_by"])
    for field in dimensions:
        keyword(field)
    for metric in aggregate["metrics"]:
        if metric["fn"] == "count":
            if metric["field"] != "*":
                raise ElasticError("Elastic auth-v1 supports count only with field '*'")
        elif metric["fn"] == "count_distinct":
            field = keyword(metric["field"])
            if field not in dimensions:
                dimensions.append(field)
        else:
            raise ElasticError(f"Unsupported Elastic metric: {metric['fn']}")
    sources = [{"window": {"date_histogram": {"field": "@timestamp", "fixed_interval": f"{window_seconds(aggregate['window'])}s", "time_zone": "UTC"}}}]
    sources.extend({f"d{i}": {"terms": {"field": field}}} for i, field in enumerate(dimensions))
    filters = [{"term": {"event.dataset": rule["dataset"]}}, predicate_query(rule["where"])]
    filters.extend({"exists": {"field": field}} for field in dimensions)
    filters.extend({"bool": {"must_not": [{"term": {field: ""}}]}} for field in dimensions)
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": filters}},
        "aggs": {"events": {"composite": {"size": page_size, "sources": sources}}},
    }, dimensions


def meets_having(values: dict, clauses: list[dict]) -> bool:
    operators = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "gt": lambda a, b: a > b,
        "gte": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "lte": lambda a, b: a <= b,
    }
    for clause in clauses:
        if clause["op"] not in operators:
            raise ElasticError(f"Unsupported having operator: {clause['op']}")
        if not operators[clause["op"]](values[clause["field"]], clause["value"]):
            return False
    return True


def evaluate_index(client: ElasticClient, index: str, rule: dict, *, page_size: int = 500,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None) -> dict:
    body, dimensions = compile_hunt(rule, page_size=page_size)
    bounds = event_time_bounds(rule, start, end)
    if bounds:
        body["query"]["bool"]["filter"].append(
            {"range": {"@timestamp": {"gte": bounds[0], "lt": bounds[1]}}}
        )
    if expected_index_uuid is not None:
        if not isinstance(expected_index_uuid, str) or not expected_index_uuid.strip():
            raise ElasticError("Expected source index UUID must be a nonempty string")
        if get_index_identity(client, index)["uuid"] != expected_index_uuid:
            raise ElasticError("Source index UUID changed; refusing checkpoint reuse")
    check_profile(client, index)
    aggregate = rule["aggregate"]
    group_fields = aggregate["group_by"]
    rows: dict[tuple, dict] = {}
    distinct: dict[tuple, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    result = client.request("POST", index_path(index) + "/_pit?keep_alive=1m")
    pit = result.get("id")
    if not isinstance(pit, str) or not pit:
        raise ElasticError("Elasticsearch did not return a point-in-time ID")
    pages, bucket_count = 0, 0
    seen_after = set()
    try:
        while True:
            body["pit"] = {"id": pit, "keep_alive": "1m"}
            result = client.request("POST", "/_search?allow_partial_search_results=false", body)
            pit = result.get("pit_id", pit)
            if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
                raise ElasticError("Search was incomplete; refusing partial alert results")
            page = result.get("aggregations", {}).get("events")
            if not isinstance(page, dict) or not isinstance(page.get("buckets"), list):
                raise ElasticError("Search returned no complete composite aggregation")
            pages += 1
            for bucket in page["buckets"]:
                key = bucket["key"]
                field_values = {field: key[f"d{i}"] for i, field in enumerate(dimensions)}
                row_key = (key["window"], *(field_values[f] for f in group_fields))
                if row_key not in rows:
                    start = datetime.fromtimestamp(key["window"] / 1000, tz=timezone.utc)
                    rows[row_key] = {
                        "window.start": format_timestamp(start),
                        "window.end": format_timestamp(start + timedelta(seconds=window_seconds(aggregate["window"]))),
                        **{f: field_values[f] for f in group_fields},
                        **{m["name"]: 0 for m in aggregate["metrics"]},
                    }
                for metric in aggregate["metrics"]:
                    if metric["fn"] == "count":
                        rows[row_key][metric["name"]] += bucket["doc_count"]
                    else:
                        distinct[row_key][metric["name"]].add(field_values[metric["field"]])
                bucket_count += 1
            after = page.get("after_key")
            if not page["buckets"] or not after:
                break
            after_token = json.dumps(after, sort_keys=True)
            if after_token in seen_after:
                raise ElasticError("Composite pagination did not advance")
            seen_after.add(after_token)
            body["aggs"]["events"]["composite"]["after"] = after
    finally:
        client.request("DELETE", "/_pit", {"id": pit})
    if expected_index_uuid is not None and get_index_identity(client, index)["uuid"] != expected_index_uuid:
        raise ElasticError("Source index UUID changed during evaluation; refusing checkpoint advancement")
    alerts = []
    for key, values in rows.items():
        for name, observed in distinct[key].items():
            values[name] = len(observed)
        if meets_having(values, rule.get("having", [])):
            alerts.append({field: values[field] for field in rule["project"]})
    alerts.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return {"alerts": alerts, "summary": {"pages": pages, "composite_buckets": bucket_count, "groups": len(rows), "alerts": len(alerts)}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--index", required=True, help="One explicit auth-v1 index")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-index")
    ingest = commands.add_parser("ingest")
    ingest.add_argument("events", type=Path, help="Normalized JSONL fixture events")
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("hunt", type=Path)
    evaluate.add_argument("--page-size", type=int, default=500)
    evaluate.add_argument("--start", help="Inclusive event-time bound, aligned to UTC windows")
    evaluate.add_argument("--end", help="Exclusive event-time bound, aligned to UTC windows")
    args = parser.parse_args()
    try:
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"), username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        if args.command == "create-index":
            create_index(client, args.index)
            result = {"created": args.index, "profile": PROFILE}
        elif args.command == "ingest":
            events = read_jsonl(args.events)
            if not events:
                raise ElasticError("no events found; an empty ingestion does not validate the adapter")
            result = ingest_events(client, args.index, events)
        else:
            result = evaluate_index(client, args.index, load_hunt(args.hunt),
                                    page_size=args.page_size, start=args.start, end=args.end)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"Elastic adapter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
