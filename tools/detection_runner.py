#!/usr/bin/env python3
"""Durable finite-batch scheduling of the two Elastic auth-v1 detections.

Every run queries fully closed UTC tumbling windows through the adapter. Initial
history is explicitly bounded by --start; later runs replay a configurable
overlap. SQLite WAL stores checkpoints, logical alerts and a transactional
outbox. Idempotent Elasticsearch document IDs make delivery safe across a crash
after a write but before its local acknowledgement. Only one process may use a
state database at a time (OS advisory lock, automatically released on exit).

No ingest timestamp exists in auth-v1: arrivals older than the replay horizon
cannot be counted or discovered by this runner. Lookback is not unlimited late
event support. State and outbox files must live on a local durable filesystem.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
from threading import Event
from typing import Callable
from urllib.parse import quote

try:
    from tools.elastic_adapter import (
        ElasticClient, ElasticError, ElasticHTTPError, compile_hunt, evaluate_index,
        get_index_identity, index_path,
    )
    from tools.hunt_engine import format_timestamp, load_hunt, parse_timestamp, window_seconds
except ModuleNotFoundError:
    from elastic_adapter import (
        ElasticClient, ElasticError, ElasticHTTPError, compile_hunt, evaluate_index,
        get_index_identity, index_path,
    )
    from hunt_engine import format_timestamp, load_hunt, parse_timestamp, window_seconds

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "profiles/elastic/alerts-v1.mapping.json"
STATE_VERSION = 1
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SEMANTIC_FIELDS = ("schema_version", "dataset", "where", "aggregate", "having", "project")
DEFAULT_RULES = [ROOT / "techniques/T1110_Brute_Force/hunts" / name for name in (
    "win_4625_brute_agg.hunt.yaml", "win_4625_spray_agg.hunt.yaml")]


class RunnerError(ValueError):
    """Runner configuration, state, or delivery failure."""


class RunnerBusy(RunnerError):
    """Another process already holds this state's exclusive run lock."""


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def fingerprint(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise RunnerError("Runner clock/start must have an explicit timezone")
        return value.astimezone(timezone.utc)
    return parse_timestamp(value)


def epoch_seconds(value: datetime) -> int:
    delta = value - EPOCH
    return delta.days * 86400 + delta.seconds


def from_epoch(value: int) -> datetime:
    return EPOCH + timedelta(seconds=value)


def duration_seconds(value: timedelta, name: str) -> int:
    seconds = value.total_seconds()
    if seconds < 0 or not seconds.is_integer():
        raise RunnerError(f"{name} must be a nonnegative whole number of seconds")
    return int(seconds)


def create_alert_index(client: ElasticClient, index: str) -> None:
    """Explicitly create a dedicated sink; never overwrite an existing index."""
    client.request("PUT", index_path(index), json.loads(MAPPING_PATH.read_text(encoding="utf-8")))


def check_alert_profile(client: ElasticClient, index: str) -> dict:
    """Validate the sink mapping and return its concrete name/UUID identity."""
    response = client.request("GET", index_path(index) + "/_mapping")
    if set(response) != {index}:
        raise RunnerError("Alerts destination must be one concrete index")
    expected = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["mappings"]
    if response[index].get("mappings") != expected:
        raise RunnerError("Alerts destination does not match the dedicated alerts-v1 mapping")
    return get_index_identity(client, index)


@contextmanager
def transaction(connection):
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


class DetectionRunner:
    def __init__(self, *, source_client: ElasticClient, state_path: str | Path,
                 source_index: str, alerts_index: str, rule_paths=None,
                 alerts_client: ElasticClient | None = None,
                 initial_start: str | datetime | None = None,
                 lookback: timedelta = timedelta(minutes=30),
                 allowed_lateness: timedelta = timedelta(minutes=2),
                 initialize_alerts: bool = False,
                 clock: Callable[[], datetime] | None = None,
                 evaluator: Callable | None = None, fault_hook: Callable | None = None):
        index_path(source_index)
        index_path(alerts_index)
        if source_index == alerts_index and (alerts_client is None or alerts_client is source_client):
            raise RunnerError("Source and alert indices must be separate")
        self.source_client = source_client
        self.alerts_client = alerts_client or source_client
        self.state_path = Path(state_path).resolve()
        self.source_index, self.alerts_index = source_index, alerts_index
        self.initial_start = timestamp(initial_start) if initial_start is not None else None
        self.lookback = duration_seconds(lookback, "lookback")
        self.allowed_lateness = duration_seconds(allowed_lateness, "allowed_lateness")
        self.initialize_alerts = initialize_alerts
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.evaluator = evaluator or evaluate_index
        self.fault_hook = fault_hook or (lambda stage, context: None)
        self.rule_paths = [Path(path) for path in (DEFAULT_RULES if rule_paths is None else rule_paths)]
        if not self.rule_paths:
            raise RunnerError("At least one executable auth rule is required")
        self.rules = self._read_rules()

    def _read_rules(self) -> dict[str, dict]:
        rules = {}
        for path in self.rule_paths:
            rule = load_hunt(path)
            compile_hunt(rule)  # Reject unsupported adapter operations before state writes.
            required = set(rule["aggregate"]["group_by"]) | {m["name"] for m in rule["aggregate"]["metrics"]} | {"window.start", "window.end"}
            if not required <= set(rule["project"]):
                raise RunnerError("Runner rules must project all group, metric, and window fields")
            rule_id = fingerprint({key: rule[key] for key in SEMANTIC_FIELDS})
            if rule_id in rules:
                raise RunnerError("Duplicate semantic rule in runner configuration")
            rules[rule_id] = rule
        return rules

    @contextmanager
    def _state(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(self.state_path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        connection = None
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunnerBusy("Another runner is using this state database") from exc
            if not self.state_path.exists():
                os.close(os.open(self.state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            connection = sqlite3.connect(self.state_path, timeout=0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RunnerError("SQLite state integrity check failed; preserve the file for recovery")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if tables and (tables != {"metadata", "checkpoints", "alerts", "outbox"} or version != STATE_VERSION):
                raise RunnerError("Unknown SQLite state schema/version; refusing to reuse it")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise RunnerError("SQLite WAL is required on a local durable filesystem")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if not tables:
                with transaction(connection):
                    connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    connection.execute("CREATE TABLE checkpoints (rule_id TEXT PRIMARY KEY, watermark INTEGER NOT NULL)")
                    connection.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, payload TEXT NOT NULL)")
                    connection.execute("CREATE INDEX alert_windows ON alerts(rule_id, window_start, window_end)")
                    connection.execute("CREATE TABLE outbox (alert_id TEXT PRIMARY KEY REFERENCES alerts(alert_id), payload TEXT NOT NULL, revision INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)")
                    connection.execute(f"PRAGMA user_version={STATE_VERSION}")
            yield connection
        except sqlite3.DatabaseError as exc:
            raise RunnerError("SQLite state operation failed; state was not reset or discarded") from exc
        finally:
            if connection is not None:
                connection.close()
            os.close(descriptor)  # Releases the OS lock, including on faults.

    def _ensure_alert_index(self) -> dict:
        try:
            return check_alert_profile(self.alerts_client, self.alerts_index)
        except ElasticHTTPError as exc:
            if exc.status != 404 or not self.initialize_alerts:
                raise
            try:
                create_alert_index(self.alerts_client, self.alerts_index)
            except ElasticHTTPError as create_error:
                if create_error.status not in {400, 409}:
                    raise
            return check_alert_profile(self.alerts_client, self.alerts_index)

    def _binding(self, connection) -> dict:
        if set(self._read_rules()) != set(self.rules):
            raise RunnerError("Rule semantics changed while the runner was active; use separate state")
        previous_row = connection.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
        previous = json.loads(previous_row[0]) if previous_row else None
        start = self.initial_start
        if start is None:
            if previous is None:
                raise RunnerError("An explicit initial_start/--start is required for the first run")
            start = timestamp(previous["initial_start"])
        for rule in self.rules.values():
            if start.microsecond or epoch_seconds(start) % window_seconds(rule["aggregate"]["window"]):
                raise RunnerError("Initial start must align with every rule's UTC tumbling window")
        source = get_index_identity(self.source_client, self.source_index)
        sink = self._ensure_alert_index()
        if source["uuid"] == sink["uuid"]:
            raise RunnerError("Source and alerts cannot share an index UUID")
        binding = {
            "state_version": STATE_VERSION,
            "adapter_profile": "attck-auth-v1",
            "source": source, "alerts": sink,
            "rule_ids": sorted(self.rules),
            "initial_start": format_timestamp(start),
            "lookback_seconds": self.lookback,
            "allowed_lateness_seconds": self.allowed_lateness,
        }
        if previous is not None and canonical(previous) != canonical(binding):
            raise RunnerError("State scope mismatch: source, sink, rules, version, or scheduling configuration changed")
        if previous is None:
            with transaction(connection):
                connection.execute("INSERT INTO metadata VALUES ('binding', ?)", (canonical(binding),))
                connection.executemany("INSERT INTO checkpoints VALUES (?, ?)", [(rule_id, epoch_seconds(start)) for rule_id in self.rules])
        return binding

    def _deliver(self, connection, binding) -> int:
        delivered = 0
        for row in connection.execute("SELECT * FROM outbox ORDER BY alert_id").fetchall():
            with transaction(connection):
                connection.execute("UPDATE outbox SET attempts=attempts+1, last_error=NULL WHERE alert_id=?", (row["alert_id"],))
            try:
                # A timed-out request may still finish at the server. External
                # versioning prevents that older request from overwriting a
                # later revision; equal-version immutable-payload retries work.
                response = self.alerts_client.request("PUT", index_path(self.alerts_index) + "/_doc/" + quote(row["alert_id"], safe="") + f"?version={row['revision']}&version_type=external_gte&refresh=wait_for", json.loads(row["payload"]))
                if response.get("_id") != row["alert_id"] or response.get("_index") != self.alerts_index or response.get("_version") != row["revision"] or response.get("result") not in {"created", "updated"} or response.get("_shards", {}).get("failed", 0):
                    raise RunnerError("Alert write was not acknowledged completely")
                if get_index_identity(self.alerts_client, self.alerts_index) != binding["alerts"]:
                    raise RunnerError("Alerts index was replaced during delivery; acknowledgement withheld")
            except (ElasticError, RunnerError) as exc:
                with transaction(connection):
                    connection.execute("UPDATE outbox SET last_error=? WHERE alert_id=?", (type(exc).__name__, row["alert_id"]))
                detail = "; stale revision rejected, inspect state copies/restores" if isinstance(exc, ElasticHTTPError) and exc.status == 409 else ""
                raise RunnerError("Alert delivery failed; durable outbox remains pending for retry" + detail) from exc
            self.fault_hook("after_delivery", {"alert_id": row["alert_id"], "revision": row["revision"]})
            with transaction(connection):
                connection.execute("DELETE FROM outbox WHERE alert_id=? AND revision=?", (row["alert_id"], row["revision"]))
            delivered += 1
        return delivered

    def _save_alert(self, connection, payload: dict, rule_id: str, start: int, end: int):
        encoded = canonical(payload)
        connection.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?) ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload", (payload["alert_id"], rule_id, start, end, encoded))
        connection.execute("INSERT INTO outbox(alert_id,payload,revision) VALUES (?,?,?) ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload,revision=excluded.revision,attempts=0,last_error=NULL", (payload["alert_id"], encoded, payload["revision"]))

    def run_once(self) -> dict:
        now = timestamp(self.clock())
        with self._state() as connection:
            binding = self._binding(connection)
            last = connection.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()
            if last and now < timestamp(last[0]):
                raise RunnerError("Clock moved backwards; no query, delivery or checkpoint update performed")
            delivered = self._deliver(connection, binding)
            initial = epoch_seconds(timestamp(binding["initial_start"]))
            checkpoints = dict(connection.execute("SELECT rule_id,watermark FROM checkpoints"))
            evaluations = []
            for rule_id, rule in self.rules.items():
                interval = window_seconds(rule["aggregate"]["window"])
                cutoff = (epoch_seconds(now) - self.allowed_lateness) // interval * interval
                start = max(initial, (checkpoints[rule_id] - self.lookback) // interval * interval)
                if cutoff < checkpoints[rule_id]:
                    # A future initial start has no closed eligible history yet.
                    if checkpoints[rule_id] == initial:
                        continue
                    raise RunnerError("Closed-window cutoff precedes persisted checkpoint")
                if cutoff <= start:
                    continue
                result = self.evaluator(self.source_client, self.source_index, rule,
                                        start=format_timestamp(from_epoch(start)),
                                        end=format_timestamp(from_epoch(cutoff)),
                                        expected_index_uuid=binding["source"]["uuid"])
                if not isinstance(result, dict) or not isinstance(result.get("alerts"), list):
                    raise RunnerError("Evaluator did not return a complete alert list")
                evaluations.append((rule_id, rule, start, cutoff, result["alerts"]))
            scope_id = fingerprint(binding)
            counts = {"created": 0, "updated": 0, "retracted": 0, "unchanged": 0}
            ranges = []
            with transaction(connection):
                for rule_id, rule, start, cutoff, candidates in evaluations:
                    observed = set()
                    interval = window_seconds(rule["aggregate"]["window"])
                    for candidate in candidates:
                        begin = timestamp(candidate["window.start"])
                        finish = timestamp(candidate["window.end"])
                        begin_s, finish_s = epoch_seconds(begin), epoch_seconds(finish)
                        if begin.microsecond or finish.microsecond or begin_s % interval or finish_s - begin_s != interval or not (start <= begin_s < finish_s <= cutoff):
                            raise RunnerError("Evaluator returned an alert outside the requested complete windows")
                        group = {field: candidate[field] for field in rule["aggregate"]["group_by"]}
                        metrics = {metric["name"]: candidate[metric["name"]] for metric in rule["aggregate"]["metrics"]}
                        if any(not isinstance(value, str) or not value.strip() for value in group.values()) or any(type(value) is not int or value < 0 for value in metrics.values()):
                            raise RunnerError("Evaluator returned invalid group or count values")
                        alert_id = fingerprint({"scope": scope_id, "rule": rule_id, "window_start": begin_s, "window_end": finish_s, "group": group})
                        if alert_id in observed:
                            raise RunnerError("Evaluator returned duplicate logical alerts")
                        observed.add(alert_id)
                        row = connection.execute("SELECT payload FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
                        old = json.loads(row[0]) if row else None
                        if old and old["status"] == "active" and canonical(old["metrics"]) == canonical(metrics):
                            counts["unchanged"] += 1
                            continue
                        payload = {
                            "@timestamp": format_timestamp(finish), "alert_id": alert_id,
                            "scope_id": scope_id, "rule_id": rule_id, "status": "active",
                            "revision": old["revision"] + 1 if old else 1,
                            "first_detected_at": old["first_detected_at"] if old else format_timestamp(now),
                            "updated_at": format_timestamp(now),
                            "source_index": self.source_index, "source_index_uuid": binding["source"]["uuid"],
                            "window": {"start": format_timestamp(begin), "end": format_timestamp(finish)},
                            "group": group, "metrics": metrics,
                        }
                        self._save_alert(connection, payload, rule_id, begin_s, finish_s)
                        counts["updated" if old else "created"] += 1
                    # Corrections/deletions below threshold retract a prior alert in
                    # this completed replay range; previous matching metrics remain
                    # as historical evidence, with explicit retracted status.
                    existing = connection.execute("SELECT * FROM alerts WHERE rule_id=? AND window_start>=? AND window_end<=?", (rule_id, start, cutoff)).fetchall()
                    for row in existing:
                        payload = json.loads(row["payload"])
                        if row["alert_id"] not in observed and payload["status"] == "active":
                            payload.update(status="retracted", revision=payload["revision"] + 1, updated_at=format_timestamp(now))
                            self._save_alert(connection, payload, rule_id, row["window_start"], row["window_end"])
                            counts["retracted"] += 1
                    connection.execute("UPDATE checkpoints SET watermark=? WHERE rule_id=?", (cutoff, rule_id))
                    ranges.append({"rule_id": rule_id, "start": format_timestamp(from_epoch(start)), "end": format_timestamp(from_epoch(cutoff)), "overlap_windows": max(0, (checkpoints[rule_id] - start) // interval)})
                connection.execute("INSERT INTO metadata VALUES ('last_clock', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (format_timestamp(now),))
                self.fault_hook("before_commit", {"ranges": ranges, "alerts": counts})
                if get_index_identity(self.source_client, self.source_index) != binding["source"]:
                    raise RunnerError("Source index changed before checkpoint commit")
            self.fault_hook("after_commit", {"ranges": ranges, "alerts": counts})
            delivered += self._deliver(connection, binding)
            return {"evaluated_at": format_timestamp(now), "ranges": ranges, "alerts": counts,
                    "outbox_delivered": delivered,
                    "pending_outbox": connection.execute("SELECT count(*) FROM outbox").fetchone()[0],
                    "checkpoints": {row[0]: format_timestamp(from_epoch(row[1])) for row in connection.execute("SELECT rule_id,watermark FROM checkpoints")},
                    "late_arrivals_before_replay_horizon": None,
                    "late_arrivals_observable": False}

    def status(self) -> dict:
        """Read-only local status; does not contact Elasticsearch or acquire a lease."""
        if not self.state_path.exists():
            return {"initialized": False, "pending_outbox": 0, "checkpoints": {}}
        try:
            with sqlite3.connect(self.state_path.as_uri() + "?mode=ro", uri=True) as connection:
                connection.execute("BEGIN")
                if connection.execute("PRAGMA user_version").fetchone()[0] != STATE_VERSION:
                    raise RunnerError("Unknown state version")
                binding = connection.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
                last = connection.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()
                return {"initialized": binding is not None,
                        "scope_id": fingerprint(json.loads(binding[0])) if binding else None,
                        "checkpoints": {row[0]: format_timestamp(from_epoch(row[1])) for row in connection.execute("SELECT rule_id,watermark FROM checkpoints")},
                        "pending_outbox": connection.execute("SELECT count(*) FROM outbox").fetchone()[0],
                        "logical_alerts": connection.execute("SELECT count(*) FROM alerts").fetchone()[0],
                        "last_run_at": last[0] if last else None}
        except sqlite3.DatabaseError as exc:
            raise RunnerError("Cannot read SQLite state; no recovery/reset was attempted") from exc

    def watch(self, *, interval: float = 60, stop_event: Event | None = None,
              on_result: Callable | None = None, on_error: Callable | None = None) -> None:
        if type(interval) not in (int, float) or not math.isfinite(interval) or interval <= 0:
            raise RunnerError("Watch interval must be positive")
        stop = stop_event or Event()
        while not stop.is_set():
            try:
                result = self.run_once()
            except (RunnerError, ElasticError) as exc:
                if on_error:
                    on_error(exc)
                else:
                    print(f"Detection run failed: {exc}", file=sys.stderr, flush=True)
            else:
                if on_result:
                    on_result(result)
            stop.wait(interval)  # Graceful stop interrupts the wait immediately.


def parse_duration(value: str) -> timedelta:
    match = re.fullmatch(r"(0|[1-9][0-9]*)([smhd])", value)
    if not match:
        raise argparse.ArgumentTypeError("Use a nonnegative whole duration such as 0s, 5m or 1h")
    return timedelta(seconds=int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["run-once", "watch", "status"])
    parser.add_argument("--url", default=os.environ.get("ELASTIC_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--source-index", required=True)
    parser.add_argument("--alerts-index", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--rule", type=Path, action="append")
    parser.add_argument("--start", help="First-run lower event-time bound, aligned to all UTC windows")
    parser.add_argument("--initialize-alerts", action="store_true", help="Explicitly create the dedicated alerts-v1 sink if missing")
    parser.add_argument("--lookback", type=parse_duration, default=timedelta(minutes=30))
    parser.add_argument("--allowed-lateness", type=parse_duration, default=timedelta(minutes=2))
    parser.add_argument("--interval", type=float, default=60)
    args = parser.parse_args()
    try:
        client = ElasticClient(args.url, api_key=os.environ.get("ELASTIC_API_KEY"), username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
        runner = DetectionRunner(source_client=client, state_path=args.state, source_index=args.source_index, alerts_index=args.alerts_index,
                                 rule_paths=args.rule, initial_start=args.start, lookback=args.lookback, allowed_lateness=args.allowed_lateness,
                                 initialize_alerts=args.initialize_alerts)
        if args.mode == "watch":
            stop = Event()
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, lambda *_: stop.set())
            runner.watch(interval=args.interval, stop_event=stop,
                         on_result=lambda value: print(json.dumps(value, ensure_ascii=False), flush=True))
        else:
            print(json.dumps(runner.status() if args.mode == "status" else runner.run_once(), ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Detection runner failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
