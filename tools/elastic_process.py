#!/usr/bin/env python3
"""Native Elasticsearch Basic matching for the catalogued process-v1 subset.

One PIT returns every event in the dataset/time domain, including nonmatches.
Named optional queries provide native rule matches. Every source record is
validated, and native/offline predicate disagreement fails the entire replay.
This is finite replay, not a collector, scheduler or automatic incident verdict.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys

try:
    from tools.elastic_rolling import (
        ElasticClient, ElasticError, _check_profile, _create_index, _ingest_events,
        _complete_shards, _nanoseconds, _sort_timestamp, _query_timestamp,
        canonical, checked_time, get_index_identity, index_path, positive_int,
    )
    from tools.hunt_engine import read_jsonl
    from tools.process_profile import DATASET, PROFILE, MAPPING_PATH, prepare_events
    from tools.process_detection import (
        CATALOG_PATH, compile_rule, load_rules, make_alert, prepare_rules,
        rule_matchers, validate_options,
    )
except ModuleNotFoundError:
    from elastic_rolling import (
        ElasticClient, ElasticError, _check_profile, _create_index, _ingest_events,
        _complete_shards, _nanoseconds, _sort_timestamp, _query_timestamp,
        canonical, checked_time, get_index_identity, index_path, positive_int,
    )
    from hunt_engine import read_jsonl
    from process_profile import DATASET, PROFILE, MAPPING_PATH, prepare_events
    from process_detection import (
        CATALOG_PATH, compile_rule, load_rules, make_alert, prepare_rules,
        rule_matchers, validate_options,
    )


def create_index(client: ElasticClient, index: str) -> None:
    _create_index(client, index, MAPPING_PATH)


def check_profile(client: ElasticClient, index: str) -> None:
    _check_profile(client, index, MAPPING_PATH, "process-v1")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    return _ingest_events(client, index, events, prepare=prepare_events,
                          profile_checker=check_profile, batch_size=batch_size)


def evaluate_index(client: ElasticClient, index: str, *, rules=None, page_size: int = 500,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None,
                   max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    bounds = validate_options(start, end, max_events, max_alerts)
    selected = prepare_rules(rules)
    queries = {key: compile_rule(rule) for key, rule in selected.items()}
    matchers = rule_matchers(selected)
    positive_int(page_size, "page_size", 10_000)
    filters = [{"term": {"event.dataset": DATASET}}]
    if bounds:
        filters.append({"range": {"@timestamp": {
            "gte": _query_timestamp(bounds[0]), "lt": _query_timestamp(bounds[1]),
        }}})
    check_profile(client, index)
    identity = get_index_identity(client, index)
    if expected_index_uuid is not None and expected_index_uuid != identity["uuid"]:
        raise ElasticError("Source index UUID differs from the expected binding")
    opened = client.request("POST", index_path(index) + "/_pit?keep_alive=1m&allow_partial_search_results=false")
    pit = opened.get("id")
    if not isinstance(pit, str) or not pit:
        raise ElasticError("Elasticsearch did not return a valid point-in-time ID")
    events = []
    alerts = []
    seen = set()
    previous_sort = after = None
    pages = matched_events = 0
    try:
        while True:
            body = {
                "size": min(page_size, max_events + 1 - len(events)),
                "track_total_hits": False,
                "_source": True,
                "pit": {"id": pit, "keep_alive": "1m"},
                "query": {"bool": {
                    "filter": filters,
                    "should": [{"bool": {"filter": [query], "_name": key}} for key, query in queries.items()],
                    "minimum_should_match": 0,
                }},
                "sort": [{"@timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos", "numeric_type": "date_nanos"}}, {"_shard_doc": "asc"}],
            }
            if after is not None:
                body["search_after"] = after
            response = client.request("POST", "/_search?allow_partial_search_results=false", body)
            next_pit = response.get("pit_id", pit)
            if not isinstance(next_pit, str) or not next_pit:
                raise ElasticError("Search returned an invalid updated PIT ID")
            pit = next_pit
            _complete_shards(response)
            hits = response.get("hits", {}).get("hits") if isinstance(response.get("hits"), dict) else None
            if not isinstance(hits, list) or len(hits) > body["size"]:
                raise ElasticError("Malformed process search page")
            pages += 1
            if not hits:
                break
            for hit in hits:
                if not isinstance(hit, dict) or hit.get("_index") != index or not isinstance(hit.get("_source"), dict):
                    raise ElasticError("Search returned invalid source metadata")
                source = hit["_source"]
                prepared, _ = prepare_events([source])
                event = prepared[0]
                if canonical(event) != canonical(source):
                    raise ElasticError("Index contains noncanonical process-v1 source events")
                if hit.get("_id") != event["event.id"] or event["event.id"] in seen:
                    raise ElasticError("Search violated unique event.id/_id identity")
                sort = hit.get("sort")
                if not isinstance(sort, list) or len(sort) != 2 or type(sort[1]) is not int or sort[1] < 0:
                    raise ElasticError("Search returned an invalid stable sort key")
                sort_key = (_sort_timestamp(sort[0], label=PROFILE), sort[1])
                stamp = checked_time(event["@timestamp"], label=PROFILE)
                if sort_key[0] != _nanoseconds(stamp):
                    raise ElasticError("Indexed timestamp sort differs from event source precision")
                if previous_sort is not None and sort_key <= previous_sort:
                    raise ElasticError("search_after ordering did not advance")
                if bounds and not bounds[0] <= stamp < bounds[1]:
                    raise ElasticError("Search returned an event outside process [start,end) bounds")
                native = hit.get("matched_queries", [])
                if (not isinstance(native, list) or any(not isinstance(key, str) or key not in selected for key in native)
                        or len(set(native)) != len(native)):
                    raise ElasticError("Search returned invalid named process query matches")
                expected = {key for key, match in matchers.items() if match(event)}
                if set(native) != expected:
                    raise ElasticError("Native process query matches differ from the offline predicate")
                previous_sort = sort_key
                after = sort
                seen.add(event["event.id"])
                events.append(event)
                if len(events) > max_events:
                    raise ElasticError("max_events exceeded; no partial alerts are returned")
                if native:
                    matched_events += 1
                for key in sorted(native):
                    if len(alerts) >= max_alerts:
                        raise ElasticError("max_alerts exceeded; no partial alerts are returned")
                    alerts.append(make_alert(key, event))
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            closed = client.request("DELETE", "/_pit", {"id": pit})
            if closed.get("succeeded") is not True:
                raise ElasticError("PIT cleanup was not acknowledged")
        except ElasticError:
            if not active_error:
                raise
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced during process evaluation")
    alerts.sort(key=lambda row: (checked_time(row["@timestamp"], label=PROFILE), row["event.id"], row["rule.id"]))
    return {
        "alerts": alerts,
        "summary": {"input_events": len(events), "unique_events": len(events), "duplicate_events": 0,
                    "filtered_events": len(events) - matched_events, "out_of_range_events": 0,
                    "matched_events": matched_events, "alerts": len(alerts), "rules": len(selected),
                    "fetch_pages": pages, "fetched_events": len(events)},
        "source": identity, "profile": PROFILE,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--index", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-index")
    ingest = commands.add_parser("ingest")
    ingest.add_argument("events", type=Path)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    evaluate.add_argument("--start")
    evaluate.add_argument("--end")
    evaluate.add_argument("--page-size", type=int, default=500)
    evaluate.add_argument("--max-events", type=int, default=100_000)
    evaluate.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args(argv)
    try:
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        if args.command == "create-index":
            create_index(client, args.index)
            result = {"created": args.index, "profile": PROFILE}
        elif args.command == "ingest":
            result = ingest_events(client, args.index, read_jsonl(args.events))
        else:
            result = evaluate_index(client, args.index, rules=load_rules(args.catalog), page_size=args.page_size,
                                    start=args.start, end=args.end, max_events=args.max_events, max_alerts=args.max_alerts)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Elastic process replay failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
