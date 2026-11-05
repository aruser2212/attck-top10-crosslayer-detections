#!/usr/bin/env python3
"""Finite host-file/HTTP correlation replay on Elasticsearch Basic.

Both normalized source types share one strict web-correlation-v1 index and PIT.
The reader retrieves complete bounded raw context; Python joins exact host,
resource namespace and path. No native collector or continuous scheduler is
provided. A correlated request is a candidate, not proof of code execution.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sys

try:
    from tools.correlate_webshell import correlate
    from tools.elastic_rolling import (
        ElasticClient, ElasticError, MIN_TIME, _check_profile, _create_index,
        _ingest_events, _query_timestamp, _read_events, checked_time,
        get_index_identity, index_path,
    )
    from tools.hunt_engine import read_jsonl
    from tools.rolling_hunt import event_time_bounds
    from tools.web_correlation_profile import DATASETS, MAPPING_PATH, PROFILE, prepare_events
except ModuleNotFoundError:  # Direct invocation: python tools/elastic_web_correlation.py
    from correlate_webshell import correlate
    from elastic_rolling import (
        ElasticClient, ElasticError, MIN_TIME, _check_profile, _create_index,
        _ingest_events, _query_timestamp, _read_events, checked_time,
        get_index_identity, index_path,
    )
    from hunt_engine import read_jsonl
    from rolling_hunt import event_time_bounds
    from web_correlation_profile import DATASETS, MAPPING_PATH, PROFILE, prepare_events


def create_index(client: ElasticClient, index: str) -> None:
    _create_index(client, index, MAPPING_PATH)


def check_profile(client: ElasticClient, index: str) -> None:
    _check_profile(client, index, MAPPING_PATH, "web-correlation-v1")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    return _ingest_events(client, index, events, prepare=prepare_events,
                          profile_checker=check_profile, batch_size=batch_size)


def evaluate_index(client: ElasticClient, index: str, *, webroots: list[str],
                   window_seconds: int = 300, page_size: int = 500,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None,
                   max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    # Reuse the exact core configuration checks before any network side effect.
    correlate([], webroots=webroots, window_seconds=window_seconds, start=start, end=end,
              max_events=max_events, max_alerts=max_alerts)
    bounds = event_time_bounds(start, end)
    filters = [{"terms": {"event.dataset": sorted(DATASETS)}}]
    history_bounds = None
    if bounds:
        lower, upper = (checked_time(value, label=PROFILE) for value in bounds)
        context = lower - timedelta(seconds=window_seconds)
        time_range = {"lt": _query_timestamp(upper)}
        if context >= MIN_TIME:
            time_range["gt"] = _query_timestamp(context)
        filters.append({"range": {"@timestamp": time_range}})
        history_bounds = (context, upper)
    events, identity, pages = _read_events(
        client, index, filters=filters, profile=PROFILE, prepare=prepare_events,
        profile_checker=check_profile, page_size=page_size, history_bounds=history_bounds,
        expected_index_uuid=expected_index_uuid, max_events=max_events,
    )
    result = correlate(events, webroots=webroots, window_seconds=window_seconds,
                       start=start, end=end, max_events=max_events, max_alerts=max_alerts)
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced during web correlation evaluation")
    return {**result, "summary": {**result["summary"], "fetch_pages": pages,
                                  "fetched_events": len(events)},
            "source": identity, "profile": PROFILE}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--index", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-index")
    ingest = commands.add_parser("ingest")
    ingest.add_argument("events", type=Path)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--webroot", action="append", required=True)
    evaluate.add_argument("--window-seconds", type=int, default=300)
    evaluate.add_argument("--start")
    evaluate.add_argument("--end")
    evaluate.add_argument("--page-size", type=int, default=500)
    evaluate.add_argument("--max-events", type=int, default=100_000)
    evaluate.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args()
    try:
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"),
                               password=os.environ.get("ELASTIC_PASSWORD"))
        if args.command == "create-index":
            create_index(client, args.index)
            result = {"created": args.index, "profile": PROFILE}
        elif args.command == "ingest":
            result = ingest_events(client, args.index, read_jsonl(args.events))
        else:
            result = evaluate_index(client, args.index, webroots=args.webroot,
                                    window_seconds=args.window_seconds, start=args.start, end=args.end,
                                    page_size=args.page_size, max_events=args.max_events,
                                    max_alerts=args.max_alerts)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Elastic web correlation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
