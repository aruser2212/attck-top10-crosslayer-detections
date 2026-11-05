#!/usr/bin/env python3
"""Run immutable Windows auth spool ingestion and durable T1110 detection.

The producer atomically publishes .ready.jsonl or .ready.xml files. This process
never deletes them. --once exits nonzero on any error; --watch reports a failed
iteration and retries without inventing a successful checkpoint. Neither mode
collects events from a Windows machine on its own.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
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
    from tools.elastic_adapter import ElasticClient, ElasticHTTPError, check_profile, create_index
    from tools.detection_runner import DetectionRunner, check_alert_profile, create_alert_index
    from tools.hunt_engine import format_timestamp, parse_timestamp
    from tools.ingest_spool import SpoolImporter
except ModuleNotFoundError:
    from elastic_adapter import ElasticClient, ElasticHTTPError, check_profile, create_index
    from detection_runner import DetectionRunner, check_alert_profile, create_alert_index
    from hunt_engine import format_timestamp, parse_timestamp
    from ingest_spool import SpoolImporter


def ensure_indices(client, source_index: str, alerts_index: str, *, initialize: bool) -> None:
    if source_index == alerts_index:
        raise ValueError("source and alert indices must be different")
    for index, checker, creator in ((source_index, check_profile, create_index),
                                    (alerts_index, check_alert_profile, create_alert_index)):
        try:
            checker(client, index)
        except ElasticHTTPError as exc:
            if exc.status != 404 or not initialize:
                raise
            creator(client, index)
            checker(client, index)


def run_iteration(spool, runner) -> dict:
    """Ingest before evaluating; a failed component cannot be reported as success."""
    ingested = spool.scan_once()
    if not ingested.get("ok", False):
        raise ValueError("spool scan has unresolved errors; detection was not advanced")
    # Scans are intentionally bounded. Advancing event-time checkpoints before
    # already-observed inputs are drained could strand older events outside the
    # replay lookback on the next iteration.
    if ingested.get("unacknowledged_files", 0):
        return {"ok": False, "status": "catching_up", "ingestion": ingested,
                "detection": {"executed": False, "reason": "unacknowledged_spool_files"}}
    detected = runner.run_once()
    return {"ok": True, "ingestion": ingested, "detection": detected}


def watch(spool, runner, *, interval: float, stop: Event, emit) -> int:
    if not math.isfinite(interval) or interval < 0.1:
        raise ValueError("interval must be finite and at least 0.1 seconds")
    while not stop.is_set():
        try:
            emit(run_iteration(spool, runner))
        except (ValueError, OSError, sqlite3.Error) as exc:
            # Do not log source file contents, event identities, or client secrets.
            emit({"ok": False, "error_type": type(exc).__name__, "action": "inspect component state and input; retrying"})
        stop.wait(interval)
    return 0


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
    parser.add_argument("--start", required=True, help="Explicit initial UTC event-time boundary, aligned to both rule windows")
    parser.add_argument("--initialize", action="store_true", help="Create missing indices with versioned profiles; never overwrite")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--lookback-seconds", type=int, default=1800)
    parser.add_argument("--allowed-lateness-seconds", type=int, default=120)
    parser.add_argument("--at", help="Fixed UTC clock for a reproducible --once run only")
    parser.add_argument("--max-files", type=int, default=100)
    parser.add_argument("--max-file-bytes", type=int, default=16 * 1024 * 1024)
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
        print(json.dumps({"reported_at": format_timestamp(datetime.now(timezone.utc)), **result}, ensure_ascii=False), flush=True)

    try:
        start = parse_timestamp(args.start)
        at = parse_timestamp(args.at) if args.at else None
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        if not args.spool.is_dir():
            raise ValueError("spool directory must already exist")
        ensure_indices(client, args.source_index, args.alerts_index, initialize=args.initialize)
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        runner = DetectionRunner(source_client=client, state_path=args.state_dir / "detections.sqlite",
                                 source_index=args.source_index, alerts_index=args.alerts_index,
                                 initial_start=start, lookback=timedelta(seconds=args.lookback_seconds),
                                 allowed_lateness=timedelta(seconds=args.allowed_lateness_seconds),
                                 clock=(lambda: at) if at else None)
        with ExitStack() as stack:
            spool = stack.enter_context(SpoolImporter(client, args.source_index, args.spool,
                                                       args.state_dir / "spool.sqlite", max_files=args.max_files,
                                                       max_file_bytes=args.max_file_bytes))
            if args.once:
                result = run_iteration(spool, runner)
                emit(result)
                return 0 if result["ok"] else 2
            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
            return watch(spool, runner, interval=args.interval, stop=stop, emit=emit)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
