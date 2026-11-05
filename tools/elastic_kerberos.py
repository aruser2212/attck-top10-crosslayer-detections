#!/usr/bin/env python3
"""Finite Security 4769 rolling replay on Elasticsearch Basic.

The separate kerberos-v1 profile validates native field semantics before
ingestion and after retrieval. Shared date_nanos/PIT/search_after transport
preserves exact rolling windows and distinct service SID counts. No paid
Elastic features or continuous scheduler are required.
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
        ElasticClient, ElasticError, _check_profile, _create_index,
        _evaluate_index, _ingest_events, get_index_identity, index_path,
    )
    from tools.hunt_engine import read_jsonl
    from tools.kerberos_profile import DATASET, MAPPING_PATH, PROFILE, prepare_events
    from tools.rolling_hunt import load_hunt
except ModuleNotFoundError:  # Direct invocation: python tools/elastic_kerberos.py
    from elastic_rolling import (
        ElasticClient, ElasticError, _check_profile, _create_index,
        _evaluate_index, _ingest_events, get_index_identity, index_path,
    )
    from hunt_engine import read_jsonl
    from kerberos_profile import DATASET, MAPPING_PATH, PROFILE, prepare_events
    from rolling_hunt import load_hunt

def create_index(client: ElasticClient, index: str) -> None:
    _create_index(client, index, MAPPING_PATH)


def check_profile(client: ElasticClient, index: str) -> None:
    _check_profile(client, index, MAPPING_PATH, "kerberos-v1")


def ingest_events(client: ElasticClient, index: str, events: list[dict], *, batch_size: int = 500) -> dict:
    return _ingest_events(client, index, events, prepare=prepare_events,
                          profile_checker=check_profile, batch_size=batch_size)


def evaluate_index(client: ElasticClient, index: str, rule: dict, *, page_size: int = 500,
                   start: str | datetime | None = None, end: str | datetime | None = None,
                   expected_index_uuid: str | None = None,
                   max_events: int = 100_000, max_alerts: int = 10_000) -> dict:
    return _evaluate_index(client, index, rule, dataset=DATASET, profile=PROFILE,
                           prepare=prepare_events, profile_checker=check_profile,
                           page_size=page_size, start=start, end=end,
                           expected_index_uuid=expected_index_uuid,
                           max_events=max_events, max_alerts=max_alerts)


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
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"),
                               password=os.environ.get("ELASTIC_PASSWORD"))
        if args.command == "create-index":
            create_index(client, args.index)
            result = {"created": args.index, "profile": PROFILE}
        elif args.command == "ingest":
            result = ingest_events(client, args.index, read_jsonl(args.events))
        else:
            result = evaluate_index(client, args.index, load_hunt(args.hunt), page_size=args.page_size,
                                    start=args.start, end=args.end,
                                    max_events=args.max_events, max_alerts=args.max_alerts)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Elastic Kerberos replay failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
