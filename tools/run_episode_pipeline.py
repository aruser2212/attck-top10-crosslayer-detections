#!/usr/bin/env python3
"""Project durable rolling alerts into revisable episodes on Elasticsearch Basic.

The source is the complete, read-only rolling-v2 SQLite state. Episodes preserve
references to raw alerts and their revisions; no raw detection is suppressed.
Use a separate episode state file and a dedicated episodes-v1 index. --once
returns 2 while raw-alert delivery is pending, 1 on error and 0 on completion.
--watch repeats finite passes; SIGINT/SIGTERM finish the current pass and stop.
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
    from tools.elastic_rolling import ElasticClient, checked_time
    from tools.episode_runner import EpisodeRunner
    from tools.hunt_engine import format_timestamp
except ModuleNotFoundError:
    from elastic_rolling import ElasticClient, checked_time
    from episode_runner import EpisodeRunner
    from hunt_engine import format_timestamp


def watch(runner, *, interval: float, stop: Event, emit) -> int:
    if type(interval) not in (int, float) or not math.isfinite(interval) or interval < 0.1:
        raise ValueError("interval must be finite and at least 0.1 seconds")
    while not stop.is_set():
        try:
            emit(runner.run_once())
        except (ValueError, OSError, sqlite3.Error) as exc:
            # Report the failure class without exposing event payloads or secrets.
            emit({"ok": False, "error_type": type(exc).__name__,
                  "action": "inspect source, episode state and sink; retrying"})
        stop.wait(interval)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--watch", action="store_true")
    mode.add_argument("--status", action="store_true", help="Read local episode state without contacting Elasticsearch")
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--source-state", type=Path, required=True, help="Existing rolling-detections.sqlite, read only")
    parser.add_argument("--state", type=Path, required=True, help="Separate local durable episode SQLite file")
    parser.add_argument("--episodes-index", required=True)
    parser.add_argument("--initialize", action="store_true", help="Create a missing episodes-v1 index only before state is bound")
    parser.add_argument("--gap-seconds", type=int, default=300)
    parser.add_argument("--projection-mode", choices=("incremental", "full"), default="incremental",
                        help="Recompute changed groups, or use the complete reference projection")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--at", help="Fixed timezone-qualified clock for --once only")
    parser.add_argument("--max-source-alerts", type=int, default=100_000)
    parser.add_argument("--max-source-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-episodes", type=int, default=10_000)
    parser.add_argument("--max-members", type=int, default=10_000)
    parser.add_argument("--max-changes", type=int, default=10_000)
    args = parser.parse_args(argv)
    if args.at and not args.once:
        parser.error("--at is allowed only with --once")
    if args.initialize and args.status:
        parser.error("--initialize cannot be used with --status")
    if not math.isfinite(args.interval) or args.interval < 0.1:
        parser.error("interval must be finite and at least 0.1 seconds")
    if min(args.gap_seconds, args.max_source_alerts, args.max_source_bytes,
           args.max_episodes, args.max_members, args.max_changes) <= 0:
        parser.error("gap and resource limits must be positive")
    stop = Event()
    old_handlers = {}

    def emit(result):
        print(json.dumps({"reported_at": format_timestamp(datetime.now(timezone.utc)), **result},
                         ensure_ascii=False), flush=True)

    try:
        at = checked_time(args.at) if args.at else None
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"),
                               password=os.environ.get("ELASTIC_PASSWORD"))
        runner = EpisodeRunner(
            source_state=args.source_state, state_path=args.state,
            sink_client=client, episodes_index=args.episodes_index,
            gap=timedelta(seconds=args.gap_seconds), initialize_index=args.initialize,
            max_source_alerts=args.max_source_alerts, max_source_bytes=args.max_source_bytes,
            max_episodes=args.max_episodes, max_members=args.max_members,
            max_changes=args.max_changes, projection_mode=args.projection_mode,
            clock=(lambda: at) if at else None,
        )
        if args.status:
            emit(runner.status())
            return 0
        if args.once:
            result = runner.run_once()
            emit(result)
            return 0 if result["ok"] else 2
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
        return watch(runner, interval=args.interval, stop=stop, emit=emit)
    except (ValueError, OverflowError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "message": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
