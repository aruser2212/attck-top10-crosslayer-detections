#!/usr/bin/env python3
"""Run bounded, durable rolling T1110 detection with the separate v2 profiles.

The producer atomically publishes immutable .ready.jsonl or .ready.xml files.
Each iteration drains a bounded ingestion scan before advancing event-time
checkpoints. Rolling evaluation advances by a bounded time span and replays the
configured anchor overlap. --once returns 2 while either input or event-time
catch-up remains; --watch repeats finite iterations until SIGINT/SIGTERM.

Use separate auth-v2 and alerts-v2 indices and a new local durable state directory.
This command neither migrates v1 state nor collects events from Windows itself.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import sys
from threading import Event

try:
    from tools.elastic_adapter import ElasticHTTPError
    from tools.elastic_rolling import ElasticClient, check_profile, checked_time, create_index, index_path
    from tools.rolling_runner import RollingDetectionRunner, check_alert_profile, create_alert_index
    from tools.hunt_engine import format_timestamp, parse_timestamp
    from tools.ingest_spool import SpoolImporter
    from tools.run_auth_pipeline import run_iteration as ingest_then_detect
except ModuleNotFoundError:
    from elastic_adapter import ElasticHTTPError
    from elastic_rolling import ElasticClient, check_profile, checked_time, create_index, index_path
    from rolling_runner import RollingDetectionRunner, check_alert_profile, create_alert_index
    from hunt_engine import format_timestamp, parse_timestamp
    from ingest_spool import SpoolImporter
    from run_auth_pipeline import run_iteration as ingest_then_detect


def ensure_indices(client, source_index: str, alerts_index: str, *, initialize: bool,
                   state_exists: bool = False) -> None:
    """Check both destinations before creating any missing, explicitly opted-in index."""
    index_path(source_index)
    index_path(alerts_index)
    if source_index == alerts_index:
        raise ValueError("source and alert indices must be different")
    missing = []
    for index, checker, creator in ((source_index, check_profile, create_index),
                                    (alerts_index, check_alert_profile, create_alert_index)):
        try:
            checker(client, index)
        except ElasticHTTPError as exc:
            if exc.status != 404 or not initialize:
                raise
            if state_exists:
                raise ValueError("Rolling state exists but a bound index is missing; restore the matching index before resuming") from exc
            missing.append((index, checker, creator))
    for index, checker, creator in missing:
        creator(client, index)
        checker(client, index)


def run_iteration(spool, runner) -> dict:
    result = ingest_then_detect(spool, runner)
    if result["ok"] and not result["detection"]["caught_up"]:
        result["ok"] = False
        result["status"] = "catching_up"
    return result


def watch(spool, runner, *, interval: float, stop: Event, emit) -> int:
    if not math.isfinite(interval) or interval < 0.1:
        raise ValueError("interval must be finite and at least 0.1 seconds")
    while not stop.is_set():
        try:
            emit(run_iteration(spool, runner))
        except (ValueError, OSError, sqlite3.Error) as exc:
            emit({"ok": False, "error_type": type(exc).__name__,
                  "action": "inspect component state and input; retrying"})
        stop.wait(interval)
    return 0


def _check_state_directory(directory: Path) -> None:
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ValueError("state-dir must be a nonsymlink local directory")
    if any(os.path.lexists(directory / name) for name in ("detections.sqlite", "spool.sqlite")):
        raise ValueError("v1 state files found; choose a separate state-dir for rolling v2")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--watch", action="store_true")
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--source-index", required=True)
    parser.add_argument("--alerts-index", required=True)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--start", required=True,
                        help="First eligible anchor (timezone required, microseconds preserved); no UTC-window alignment")
    parser.add_argument("--initialize", action="store_true", help="Create missing v2 indices; never overwrite or migrate")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--lookback-seconds", type=int, default=1800)
    parser.add_argument("--allowed-lateness-seconds", type=int, default=120)
    parser.add_argument("--max-forward-seconds", type=int, default=3600)
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--max-query-events", type=int, default=100_000)
    parser.add_argument("--max-alerts", type=int, default=10_000)
    parser.add_argument("--at", help="Fixed timezone-qualified clock for a reproducible --once run only")
    parser.add_argument("--max-files", type=int, default=100)
    parser.add_argument("--max-file-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-scan-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-ingest-events", type=int, default=100_000)
    args = parser.parse_args(argv)
    if args.at and not args.once:
        parser.error("--at is allowed only with --once")
    if not math.isfinite(args.interval) or args.interval < 0.1:
        parser.error("--interval must be finite and at least 0.1 seconds")
    if min(args.lookback_seconds, args.allowed_lateness_seconds) < 0:
        parser.error("lookback and allowed lateness must be nonnegative")
    stop = Event()
    old_handlers = {}

    def emit(result):
        print(json.dumps({"reported_at": format_timestamp(datetime.now(timezone.utc)), **result},
                         ensure_ascii=False), flush=True)

    try:
        start = parse_timestamp(args.start)
        at = checked_time(args.at) if args.at else None
        _check_state_directory(args.state_dir)
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        # Constructors validate rules, time bounds, directories and all limits
        # without writing state or making requests. Bootstrap follows validation.
        runner = RollingDetectionRunner(
            source_client=client, state_path=args.state_dir / "rolling-detections.sqlite",
            source_index=args.source_index, alerts_index=args.alerts_index, initial_start=start,
            lookback=timedelta(seconds=args.lookback_seconds),
            allowed_lateness=timedelta(seconds=args.allowed_lateness_seconds),
            max_forward_span=timedelta(seconds=args.max_forward_seconds), page_size=args.page_size,
            max_events=args.max_query_events, max_alerts=args.max_alerts,
            clock=(lambda: at) if at else None,
        )
        spool = SpoolImporter(
            client, args.source_index, args.spool, args.state_dir / "rolling-spool.sqlite",
            profile="auth-v2", max_files=args.max_files, max_file_bytes=args.max_file_bytes,
            max_scan_bytes=args.max_scan_bytes, max_events=args.max_ingest_events,
        )
        state_exists = any(os.path.lexists(args.state_dir / name)
                           for name in ("rolling-detections.sqlite", "rolling-spool.sqlite"))
        ensure_indices(client, args.source_index, args.alerts_index,
                       initialize=args.initialize, state_exists=state_exists)
        with spool:
            if args.once:
                result = run_iteration(spool, runner)
                emit(result)
                return 0 if result["ok"] else 2
            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
            return watch(spool, runner, interval=args.interval, stop=stop, emit=emit)
    except (ValueError, OverflowError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "message": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
