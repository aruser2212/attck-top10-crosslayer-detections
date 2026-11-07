#!/usr/bin/env python3
"""Finite same-session NewCredentials/privilege replay on Elasticsearch Basic.

The complete bounded profile index is read through one PIT/search_after snapshot.
Output bounds select 4624 anchors only: other records remain necessary to reject
ambiguous sessions and retain privileges on either side of the anchor. A match
is a session candidate, not proof of Pass-the-Hash or a live collection service.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys

try:
    from tools.correlate_newcredentials import correlate
    from tools.elastic_rolling import (
        ElasticClient, ElasticError, _check_profile, _create_index,
        _ingest_events, _read_events, get_index_identity, index_path,
    )
    from tools.hunt_engine import read_jsonl
    from tools.newcredentials_profile import DATASET, MAPPING_PATH, PROFILE, prepare_events
except ModuleNotFoundError:  # Direct invocation outside the repository.
    from correlate_newcredentials import correlate
    from elastic_rolling import (
        ElasticClient, ElasticError, _check_profile, _create_index,
        _ingest_events, _read_events, get_index_identity, index_path,
    )
    from hunt_engine import read_jsonl
    from newcredentials_profile import DATASET, MAPPING_PATH, PROFILE, prepare_events


def create_index(client: ElasticClient, index: str) -> None:
    _create_index(client, index, MAPPING_PATH)


def check_profile(client: ElasticClient, index: str) -> None:
    _check_profile(client, index, MAPPING_PATH, "newcredentials-v1")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    return _ingest_events(client, index, events, prepare=prepare_events,
                          profile_checker=check_profile, batch_size=batch_size)


def evaluate_index(client: ElasticClient, index: str, *, page_size: int = 500,
                   max_skew_seconds: int = 30,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None,
                   max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    correlate([], max_skew_seconds=max_skew_seconds, start=start, end=end,
              max_events=max_events, max_alerts=max_alerts)
    # Do not time-prefilter this finite source. An out-of-bounds 4624 can still
    # make a selected session ambiguous, and 4672 evidence may precede its anchor.
    events, identity, pages = _read_events(
        client, index, filters=[{"term": {"event.dataset": DATASET}}],
        profile=PROFILE, prepare=prepare_events, profile_checker=check_profile,
        page_size=page_size, expected_index_uuid=expected_index_uuid,
        max_events=max_events,
    )
    result = correlate(events, max_skew_seconds=max_skew_seconds,
                       start=start, end=end, max_events=max_events, max_alerts=max_alerts)
    if get_index_identity(client, index) != identity:
        raise ElasticError("Source index was replaced during NewCredentials evaluation")
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
    evaluate.add_argument("--start")
    evaluate.add_argument("--end")
    evaluate.add_argument("--max-skew-seconds", type=int, default=30)
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
            result = evaluate_index(client, args.index, page_size=args.page_size,
                                    max_skew_seconds=args.max_skew_seconds,
                                    start=args.start, end=args.end,
                                    max_events=args.max_events, max_alerts=args.max_alerts)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Elastic NewCredentials replay failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
