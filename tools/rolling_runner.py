#!/usr/bin/env python3
"""Durable, bounded scheduling for the Windows rolling Hunt v2 adapter.

A checkpoint C means all eligible anchors before C have been evaluated. Each
pass replays [max(initial_start,C-lookback), min(now-lateness,C+forward_span)).
The adapter includes each rule's preceding context and uses exact microseconds.
SQLite schema 2 stores logical alerts and an atomic outbox; it never migrates
v1 state. Limits fail the complete pass, without advancing any checkpoint.

Lookback bounds anchor replay, not event arrival: older events may still affect
newer anchors as context. No ingest timestamp exists to measure arrivals missed
outside the replay horizon. One state database on a local durable filesystem
must serve each logical pipeline; the lock cannot coordinate separate copies.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Callable
from urllib.parse import quote

try:
    from tools.detection_runner import RunnerBusy, RunnerError, canonical, fingerprint, transaction
    from tools.elastic_adapter import ElasticHTTPError
    from tools.elastic_rolling import (
        DATASET, MIN_TIME, MAX_TIME, PROFILE, ElasticClient, ElasticError,
        check_profile, checked_time, evaluate_index, get_index_identity, index_path,
    )
    from tools.hunt_engine import format_timestamp, window_seconds
    from tools.rolling_hunt import load_hunt
except ModuleNotFoundError:  # Direct execution from another working directory.
    from detection_runner import RunnerBusy, RunnerError, canonical, fingerprint, transaction
    from elastic_adapter import ElasticHTTPError
    from elastic_rolling import (
        DATASET, MIN_TIME, MAX_TIME, PROFILE, ElasticClient, ElasticError,
        check_profile, checked_time, evaluate_index, get_index_identity, index_path,
    )
    from hunt_engine import format_timestamp, window_seconds
    from rolling_hunt import load_hunt

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "profiles/elastic/alerts-v2.mapping.json"
STATE_VERSION = 2
SEMANTIC_FIELDS = ("schema_version", "dataset", "where", "aggregate", "having", "project")
DEFAULT_RULES = [ROOT / "techniques/T1110_Brute_Force/hunts" / name for name in (
    "win_4625_brute_agg_rolling.hunt.yaml", "win_4625_spray_agg_rolling.hunt.yaml")]


def epoch_microseconds(value: datetime) -> int:
    delta = value - MIN_TIME
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds)


def from_epoch(value: int) -> datetime:
    return MIN_TIME + timedelta(microseconds=value)


def duration_microseconds(value: timedelta, name: str, *, positive: bool = False) -> int:
    if not isinstance(value, timedelta):
        raise RunnerError(f"{name} must be a timedelta")
    result = ((value.days * 86400 + value.seconds) * 1_000_000 + value.microseconds)
    if result < 0 or (positive and result == 0):
        raise RunnerError(f"{name} must be {'positive' if positive else 'nonnegative'}")
    return result


def _positive_int(value, name: str, *, maximum: int | None = None):
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise RunnerError(f"{name} must be a positive integer" + (f" at most {maximum}" if maximum else ""))


def create_alert_index(client: ElasticClient, index: str) -> None:
    """Explicitly create a separate alerts-v2 sink; never overwrite an index."""
    client.request("PUT", index_path(index), json.loads(MAPPING_PATH.read_text(encoding="utf-8")))


def check_alert_profile(client: ElasticClient, index: str) -> dict:
    response = client.request("GET", index_path(index) + "/_mapping")
    expected = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["mappings"]
    if set(response) != {index} or not isinstance(response[index], dict) or response[index].get("mappings") != expected:
        raise RunnerError("Alerts destination does not match the dedicated alerts-v2 mapping")
    return get_index_identity(client, index)


class RollingDetectionRunner:
    def __init__(self, *, source_client: ElasticClient, state_path: str | Path,
                 source_index: str, alerts_index: str, rule_paths=None,
                 alerts_client: ElasticClient | None = None,
                 initial_start: str | datetime | None = None,
                 lookback: timedelta = timedelta(minutes=30),
                 allowed_lateness: timedelta = timedelta(minutes=2),
                 max_forward_span: timedelta = timedelta(hours=1),
                 page_size: int = 500, max_events: int = 100_000,
                 max_alerts: int = 10_000, initialize_alerts: bool = False,
                 clock: Callable[[], datetime] | None = None,
                 evaluator: Callable | None = None, fault_hook: Callable | None = None):
        index_path(source_index)
        index_path(alerts_index)
        if source_index == alerts_index and (alerts_client is None or alerts_client is source_client):
            raise RunnerError("Source and alert indices must be separate")
        self.source_client = source_client
        self.alerts_client = alerts_client or source_client
        self.state_path = Path(state_path).absolute()
        if self.state_path.is_symlink():
            raise RunnerError("state_path must not be a symlink")
        self.state_path = self.state_path.resolve()
        self.source_index, self.alerts_index = source_index, alerts_index
        self.initial_start = checked_time(initial_start) if initial_start is not None else None
        self.lookback = duration_microseconds(lookback, "lookback")
        self.allowed_lateness = duration_microseconds(allowed_lateness, "allowed_lateness")
        self.max_forward_span = duration_microseconds(max_forward_span, "max_forward_span", positive=True)
        _positive_int(page_size, "page_size", maximum=10_000)
        _positive_int(max_events, "max_events")
        _positive_int(max_alerts, "max_alerts")
        if type(initialize_alerts) is not bool:
            raise RunnerError("initialize_alerts must be boolean")
        self.page_size, self.max_events, self.max_alerts = page_size, max_events, max_alerts
        self.initialize_alerts = initialize_alerts
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.evaluator = evaluator or evaluate_index
        self.fault_hook = fault_hook or (lambda stage, context: None)
        self.rule_paths = [Path(path) for path in (DEFAULT_RULES if rule_paths is None else rule_paths)]
        if not self.rule_paths:
            raise RunnerError("At least one executable Windows rolling rule is required")
        self.rules = self._read_rules()
        if self.initial_start is not None:
            self._validate_start(self.initial_start)

    def _read_rules(self) -> dict[str, dict]:
        rules = {}
        for path in self.rule_paths:
            rule = load_hunt(path)
            if rule["dataset"] != DATASET:
                raise RunnerError("Rolling runner supports only Windows logon hunts")
            rule_id = fingerprint({key: rule[key] for key in SEMANTIC_FIELDS})
            if rule_id in rules:
                raise RunnerError("Duplicate semantic rule in runner configuration")
            rules[rule_id] = rule
        return rules

    def _validate_start(self, start: datetime) -> None:
        # date_nanos cannot store a negative window.start. Reject an unsupported
        # initial range explicitly, rather than rounding or dropping alerts.
        maximum_window = max(window_seconds(rule["aggregate"]["window"]) for rule in self.rules.values())
        if epoch_microseconds(start) < maximum_window * 1_000_000:
            raise RunnerError("initial_start must be at least 1970-01-01 plus the largest rule window for alerts-v2 date_nanos")

    @contextmanager
    def _state(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(str(self.state_path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        connection = None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RunnerError("State lock must be a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunnerBusy("Another runner is using this state database") from exc
            state_fd = os.open(self.state_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(state_fd).st_mode):
                    raise RunnerError("State database must be a regular file")
            finally:
                os.close(state_fd)
            connection = sqlite3.connect(self.state_path, timeout=0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RunnerError("SQLite state integrity check failed; preserve the file for recovery")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if ((tables and tables != {"metadata", "checkpoints", "alerts", "outbox"})
                    or version not in ({STATE_VERSION} if tables else {0})):
                raise RunnerError("Unknown SQLite state schema/version; refusing to reuse or migrate it")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise RunnerError("SQLite WAL is required on a local durable filesystem")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if not tables:
                with transaction(connection):
                    connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    connection.execute("CREATE TABLE checkpoints (rule_id TEXT PRIMARY KEY, watermark INTEGER NOT NULL)")
                    connection.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, payload TEXT NOT NULL)")
                    connection.execute("CREATE INDEX alert_anchors ON alerts(rule_id, window_end)")
                    connection.execute("CREATE TABLE outbox (alert_id TEXT PRIMARY KEY REFERENCES alerts(alert_id), payload TEXT NOT NULL, revision INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)")
                    connection.execute(f"PRAGMA user_version={STATE_VERSION}")
            yield connection
        except sqlite3.DatabaseError as exc:
            raise RunnerError("SQLite state operation failed; state was not reset or discarded") from exc
        finally:
            if connection is not None:
                connection.close()
            os.close(descriptor)

    def _ensure_alert_index(self, *, allow_create: bool) -> dict:
        try:
            return check_alert_profile(self.alerts_client, self.alerts_index)
        except ElasticHTTPError as exc:
            # An existing binding must never recreate its missing destination.
            if exc.status != 404 or not (self.initialize_alerts and allow_create):
                raise
            create_alert_index(self.alerts_client, self.alerts_index)
            return check_alert_profile(self.alerts_client, self.alerts_index)

    def _binding(self, connection) -> dict:
        if set(self._read_rules()) != set(self.rules):
            raise RunnerError("Rule semantics changed while the runner was active; use separate state")
        row = connection.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
        previous = json.loads(row[0]) if row else None
        start = self.initial_start
        if start is None:
            if previous is None:
                raise RunnerError("An explicit initial_start/--start is required for the first run")
            start = checked_time(previous["initial_start"])
        self._validate_start(start)
        check_profile(self.source_client, self.source_index)
        source = get_index_identity(self.source_client, self.source_index)
        sink = self._ensure_alert_index(allow_create=previous is None)
        if source["uuid"] == sink["uuid"]:
            raise RunnerError("Source and alerts cannot share an index UUID")
        binding = {"state_version": STATE_VERSION, "time_unit": "microseconds", "adapter_profile": PROFILE,
                   "source": source, "alerts": sink, "rule_ids": sorted(self.rules),
                   "initial_start": format_timestamp(start), "lookback_microseconds": self.lookback,
                   "allowed_lateness_microseconds": self.allowed_lateness}
        if previous is not None and canonical(previous) != canonical(binding):
            raise RunnerError("State scope mismatch: source, sink, rules, version, or scheduling configuration changed")
        if previous is None:
            with transaction(connection):
                connection.execute("INSERT INTO metadata VALUES ('binding', ?)", (canonical(binding),))
                connection.executemany("INSERT INTO checkpoints VALUES (?, ?)", [(rule_id, epoch_microseconds(start)) for rule_id in self.rules])
        return binding

    def _deliver(self, connection, binding) -> int:
        delivered = 0
        while True:
            # One row at a time also bounds recovery memory if the operator
            # lowers max_alerts after a larger committed batch.
            row = connection.execute("SELECT * FROM outbox ORDER BY alert_id LIMIT 1").fetchone()
            if row is None:
                break
            with transaction(connection):
                connection.execute("UPDATE outbox SET attempts=attempts+1, last_error=NULL WHERE alert_id=?", (row["alert_id"],))
            try:
                # Detect known replacement before writing; the subsequent UUID
                # check withholds acknowledgement for a check/write race too.
                if get_index_identity(self.alerts_client, self.alerts_index) != binding["alerts"]:
                    raise RunnerError("Alerts index changed before delivery")
                response = self.alerts_client.request("PUT", index_path(self.alerts_index) + "/_doc/" + quote(row["alert_id"], safe="") + f"?version={row['revision']}&version_type=external_gte&refresh=wait_for", json.loads(row["payload"]))
                shards = response.get("_shards", {})
                if (response.get("_id") != row["alert_id"] or response.get("_index") != self.alerts_index
                        or type(response.get("_version")) is not int or response["_version"] != row["revision"]
                        or response.get("result") not in {"created", "updated"}
                        or not isinstance(shards, dict) or type(shards.get("failed")) is not int or shards["failed"] != 0):
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

    def _save_alert(self, connection, payload, rule_id, start, end):
        encoded = canonical(payload)
        connection.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?) ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload", (payload["alert_id"], rule_id, start, end, encoded))
        connection.execute("INSERT INTO outbox(alert_id,payload,revision) VALUES (?,?,?) ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload,revision=excluded.revision,attempts=0,last_error=NULL", (payload["alert_id"], encoded, payload["revision"]))

    def _candidate(self, candidate, rule, start, cutoff):
        if not isinstance(candidate, dict) or set(candidate) != set(rule["project"]):
            raise RunnerError("Evaluator returned invalid projected fields")
        begin, finish = checked_time(candidate["window.start"]), checked_time(candidate["window.end"])
        begin_us, finish_us = epoch_microseconds(begin), epoch_microseconds(finish)
        interval = window_seconds(rule["aggregate"]["window"]) * 1_000_000
        if finish_us - begin_us != interval or not (start <= finish_us < cutoff):
            raise RunnerError("Evaluator returned an alert outside the requested anchor range")
        group = {field: candidate[field] for field in rule["aggregate"]["group_by"]}
        metrics = {metric["name"]: candidate[metric["name"]] for metric in rule["aggregate"]["metrics"]}
        if (any(not isinstance(value, str) or not value.strip() for value in group.values())
                or any(type(value) is not int or value < 0 for value in metrics.values())
                or any(metrics[threshold["field"]] < threshold["value"] for threshold in rule["having"])):
            raise RunnerError("Evaluator returned invalid group or threshold/count values")
        return begin, finish, begin_us, finish_us, group, metrics

    def run_once(self) -> dict:
        now = checked_time(self.clock())
        now_us = epoch_microseconds(now)
        # Integer arithmetic cannot overflow datetime at the profile boundaries.
        cutoff = max(0, now_us - self.allowed_lateness)
        with self._state() as connection:
            binding = self._binding(connection)
            last = connection.execute("SELECT value FROM metadata WHERE key='last_clock'").fetchone()
            if last and now < checked_time(last[0]):
                raise RunnerError("Clock moved backwards; no query, delivery or checkpoint update performed")
            delivered = self._deliver(connection, binding)
            initial = epoch_microseconds(checked_time(binding["initial_start"]))
            checkpoints = dict(connection.execute("SELECT rule_id,watermark FROM checkpoints"))
            if set(checkpoints) != set(self.rules) or any(type(value) is not int or not initial <= value <= epoch_microseconds(MAX_TIME) for value in checkpoints.values()):
                raise RunnerError("State checkpoints do not match the bound rules and time range")
            evaluations = []
            total_candidates = 0
            for rule_id, rule in self.rules.items():
                checkpoint = checkpoints[rule_id]
                start = max(initial, checkpoint - self.lookback)
                end = min(cutoff, checkpoint + self.max_forward_span)
                if end < checkpoint:
                    if checkpoint == initial:  # Future start: no eligible anchors yet.
                        continue
                    raise RunnerError("Rolling cutoff precedes persisted checkpoint")
                if end <= start:
                    continue
                result = self.evaluator(self.source_client, self.source_index, rule,
                                        start=format_timestamp(from_epoch(start)), end=format_timestamp(from_epoch(end)),
                                        expected_index_uuid=binding["source"]["uuid"], page_size=self.page_size,
                                        max_events=self.max_events, max_alerts=self.max_alerts)
                if not isinstance(result, dict) or not isinstance(result.get("alerts"), list):
                    raise RunnerError("Evaluator did not return a complete alert list")
                total_candidates += len(result["alerts"])
                if total_candidates > self.max_alerts:
                    raise RunnerError("max_alerts exceeded across the complete rolling pass; no checkpoint advanced")
                evaluations.append((rule_id, rule, start, end, result["alerts"]))
            scope_id = fingerprint(binding)
            counts = {"created": 0, "updated": 0, "retracted": 0, "unchanged": 0}
            ranges = []
            processed_alerts = total_candidates
            with transaction(connection):
                for rule_id, rule, start, end, candidates in evaluations:
                    observed = set()
                    for candidate in candidates:
                        begin, finish, begin_us, finish_us, group, metrics = self._candidate(candidate, rule, start, end)
                        alert_id = fingerprint({"scope": scope_id, "rule": rule_id, "anchor_microseconds": finish_us, "group": group})
                        if alert_id in observed:
                            raise RunnerError("Evaluator returned duplicate logical alerts")
                        observed.add(alert_id)
                        row = connection.execute("SELECT payload FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
                        old = json.loads(row[0]) if row else None
                        if old and old["status"] == "active" and canonical(old["metrics"]) == canonical(metrics):
                            counts["unchanged"] += 1
                            continue
                        payload = {"@timestamp": format_timestamp(finish), "alert_id": alert_id,
                                   "scope_id": scope_id, "rule_id": rule_id, "status": "active",
                                   "revision": old["revision"] + 1 if old else 1,
                                   "first_detected_at": old["first_detected_at"] if old else format_timestamp(now),
                                   "updated_at": format_timestamp(now), "source_index": self.source_index,
                                   "source_index_uuid": binding["source"]["uuid"],
                                   "window": {"start": format_timestamp(begin), "end": format_timestamp(finish)},
                                   "group": group, "metrics": metrics}
                        self._save_alert(connection, payload, rule_id, begin_us, finish_us)
                        counts["updated" if old else "created"] += 1
                    # An anchor's window.start is normally before the replay
                    # range. Retractions must select by its end/anchor alone.
                    existing = connection.execute("SELECT * FROM alerts WHERE rule_id=? AND window_end>=? AND window_end<?", (rule_id, start, end))
                    for row in existing:
                        payload = json.loads(row["payload"])
                        if row["alert_id"] not in observed and payload["status"] == "active":
                            processed_alerts += 1
                            if processed_alerts > self.max_alerts:
                                raise RunnerError("max_alerts exceeded by candidates and retractions; no checkpoint advanced")
                            payload.update(status="retracted", revision=payload["revision"] + 1, updated_at=format_timestamp(now))
                            self._save_alert(connection, payload, rule_id, row["window_start"], row["window_end"])
                            counts["retracted"] += 1
                    connection.execute("UPDATE checkpoints SET watermark=? WHERE rule_id=?", (end, rule_id))
                    ranges.append({"rule_id": rule_id, "start": format_timestamp(from_epoch(start)),
                                   "end": format_timestamp(from_epoch(end)),
                                   "overlap_microseconds": max(0, checkpoints[rule_id] - start)})
                connection.execute("INSERT INTO metadata VALUES ('last_clock', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (format_timestamp(now),))
                self.fault_hook("before_commit", {"ranges": ranges, "alerts": counts})
                if get_index_identity(self.source_client, self.source_index) != binding["source"]:
                    raise RunnerError("Source index changed before checkpoint commit")
                if get_index_identity(self.alerts_client, self.alerts_index) != binding["alerts"]:
                    raise RunnerError("Alerts index changed before checkpoint commit")
            self.fault_hook("after_commit", {"ranges": ranges, "alerts": counts})
            delivered += self._deliver(connection, binding)
            current = dict(connection.execute("SELECT rule_id,watermark FROM checkpoints"))
            return {"evaluated_at": format_timestamp(now), "ranges": ranges, "alerts": counts,
                    "outbox_delivered": delivered,
                    "pending_outbox": connection.execute("SELECT count(*) FROM outbox").fetchone()[0],
                    "checkpoints": {key: format_timestamp(from_epoch(value)) for key, value in current.items()},
                    "caught_up": all(value >= cutoff for value in current.values()),
                    "late_arrivals_before_replay_horizon": None, "late_arrivals_observable": False}

    def status(self) -> dict:
        """Read-only local status, without network requests or state migration."""
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
