"""Read one complete, bounded snapshot of a rolling-v2 SQLite ledger.

The source is opened read-only and never migrated, repaired or initialized.
Binding, checkpoints, logical alerts and the pending outbox are observed in one
SQLite read transaction. File identity protects consumers from accepting a
replacement database at the same path; retained revisions and checkpoint
regressions across snapshots are checked by the durable episode consumer.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat

try:
    from tools.detection_runner import canonical, fingerprint
    from tools.elastic_adapter import index_path
    from tools.elastic_rolling import MAX_TIME, PROFILE, checked_time
    from tools.episode_engine import EpisodeError
    from tools.hunt_engine import format_timestamp
    from tools.rolling_runner import epoch_microseconds
except ModuleNotFoundError:  # Directly invoked tools/* scripts.
    from detection_runner import canonical, fingerprint
    from elastic_adapter import index_path
    from elastic_rolling import MAX_TIME, PROFILE, checked_time
    from episode_engine import EpisodeError
    from hunt_engine import format_timestamp
    from rolling_runner import epoch_microseconds


MAX_INTEGER = (1 << 63) - 1
_COLUMNS = {
    "metadata": {"key", "value"},
    "checkpoints": {"rule_id", "watermark"},
    "alerts": {"alert_id", "rule_id", "window_start", "window_end", "payload"},
    "outbox": {"alert_id", "payload", "revision", "attempts", "last_error"},
}
_PAYLOAD_KEYS = {"@timestamp", "alert_id", "scope_id", "rule_id", "status", "revision",
                 "first_detected_at", "updated_at", "source_index", "source_index_uuid",
                 "window", "group", "metrics"}


def _integer(value, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise EpisodeError(f"{name} must be a signed 64-bit integer at least {minimum}")
    return value


def _hash(value, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise EpisodeError(f"{name} must be a canonical SHA256 identifier")
    return value


def _time(value, name: str) -> int:
    if not isinstance(value, str):
        raise EpisodeError(f"{name} must be a canonical timestamp string")
    try:
        parsed = checked_time(value)
    except (ValueError, OverflowError) as exc:
        raise EpisodeError(f"{name} is outside the exact microsecond timestamp contract") from exc
    if value != format_timestamp(parsed):
        raise EpisodeError(f"{name} must use the source runner's canonical UTC representation")
    return epoch_microseconds(parsed)


def _json(value, name: str):
    if not isinstance(value, str):
        raise EpisodeError(f"{name} must contain JSON text")

    def pairs(items):
        result = {}
        for key, child in items:
            if key in result:
                raise EpisodeError(f"{name} contains duplicate JSON keys")
            result[key] = child
        return result

    def invalid_constant(_value):
        raise EpisodeError(f"{name} contains a nonfinite JSON value")

    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, EpisodeError):
            raise
        raise EpisodeError(f"{name} is not valid JSON") from exc


def _identity(path: str | Path) -> dict:
    source = Path(path).absolute()
    try:
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise EpisodeError("Rolling source must be an existing nonsymlink regular file")
        return {"path": str(source.resolve(strict=True)), "device": info.st_dev, "inode": info.st_ino}
    except OSError as exc:
        raise EpisodeError("Cannot inspect the existing rolling source database") from exc


def verify_identity(path: str | Path, identity: dict) -> None:
    """Reject a missing/replaced source; this function never opens it for writing."""
    if _identity(path) != identity:
        raise EpisodeError("Rolling source database was replaced or moved; episode state cannot be reused")


def _binding(value: dict) -> tuple[int, str]:
    fields = {"state_version", "time_unit", "adapter_profile", "source", "alerts", "rule_ids",
              "initial_start", "lookback_microseconds", "allowed_lateness_microseconds"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["state_version"]) is not int
            or value["state_version"] != 2 or value["time_unit"] != "microseconds"
            or value["adapter_profile"] != PROFILE):
        raise EpisodeError("Rolling source binding does not match the initialized v2 contract")
    for key in ("source", "alerts"):
        identity = value[key]
        if (not isinstance(identity, dict) or set(identity) != {"name", "uuid"}
                or not isinstance(identity["name"], str) or not isinstance(identity["uuid"], str)
                or not identity["uuid"].strip()):
            raise EpisodeError("Rolling binding requires concrete index names and UUIDs")
        try:
            index_path(identity["name"])
        except (ValueError, TypeError) as exc:
            raise EpisodeError("Rolling binding contains an unsupported index name") from exc
    if value["source"]["uuid"] == value["alerts"]["uuid"]:
        raise EpisodeError("Rolling source and alert destination cannot share a UUID")
    rules = value["rule_ids"]
    if not isinstance(rules, list) or not rules:
        raise EpisodeError("Rolling binding must contain rule identifiers")
    for rule in rules:
        _hash(rule, "rule_id")
    if rules != sorted(set(rules)):
        raise EpisodeError("Rolling binding rule identifiers must be unique and sorted")
    initial = _time(value["initial_start"], "initial_start")
    for key in ("lookback_microseconds", "allowed_lateness_microseconds"):
        # These Python timedelta-derived policy values are serialized as JSON,
        # not SQLite INTEGERs; the existing runner permits very large horizons.
        if type(value[key]) is not int or value[key] < 0:
            raise EpisodeError(f"{key} must be a nonnegative integer")
    return initial, fingerprint(value)


def _alert(row, binding, scope, checkpoints, initial, last_clock):
    alert = _json(row["payload"], "raw alert payload")
    if not isinstance(alert, dict) or set(alert) != _PAYLOAD_KEYS:
        raise EpisodeError("Raw alert payload does not match the rolling-v2 contract")
    identifier, rule_id = _hash(alert["alert_id"], "alert_id"), _hash(alert["rule_id"], "rule_id")
    if (identifier != row["alert_id"] or rule_id != row["rule_id"] or rule_id not in checkpoints
            or alert["scope_id"] != scope or alert["source_index"] != binding["source"]["name"]
            or alert["source_index_uuid"] != binding["source"]["uuid"]):
        raise EpisodeError("Raw alert identity, scope or source differs from its bound ledger")
    if alert["status"] not in ("active", "retracted"):
        raise EpisodeError("Raw alert status must be active or retracted")
    _integer(alert["revision"], "raw alert revision", minimum=1)
    window = alert["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise EpisodeError("Raw alert window must contain exact start and end")
    begin, anchor = _time(window["start"], "window.start"), _time(window["end"], "window.end")
    if (begin >= anchor or (anchor - begin) % 1_000_000
            or type(row["window_start"]) is not int or row["window_start"] != begin
            or type(row["window_end"]) is not int or row["window_end"] != anchor
            or _time(alert["@timestamp"], "@timestamp") != anchor
            or not initial <= anchor < checkpoints[rule_id]):
        raise EpisodeError("Raw alert window or anchor is inconsistent with the source checkpoint")
    first, updated = _time(alert["first_detected_at"], "first_detected_at"), _time(alert["updated_at"], "updated_at")
    if not anchor <= first <= updated <= last_clock:
        raise EpisodeError("Raw alert update times contradict the last committed source clock")
    group, metrics = alert["group"], alert["metrics"]
    if not isinstance(group, dict) or not group or not isinstance(metrics, dict) or not metrics:
        raise EpisodeError("Raw alert requires nonempty group and metrics objects")
    if any(not isinstance(key, str) or not key.strip() or not isinstance(value, str) or not value.strip()
           for key, value in group.items()):
        raise EpisodeError("Raw alert group keys and values must be nonempty strings")
    for key, value in metrics.items():
        if not isinstance(key, str) or not key.strip():
            raise EpisodeError("Raw alert metric keys must be nonempty strings")
        _integer(value, "raw alert metric")
    expected = fingerprint({"scope": scope, "rule": rule_id, "anchor_microseconds": anchor, "group": group})
    if identifier != expected:
        raise EpisodeError("Raw alert identifier does not match its semantic rolling identity")
    return alert


def read_snapshot(path: str | Path, *, max_alerts: int = 100_000,
                  max_bytes: int = 64 * 1024 * 1024) -> dict:
    """Read all logical alerts and metadata in one bounded source transaction.

    ``max_alerts`` includes retracted rows. ``max_bytes`` counts UTF-8 metadata
    and alert/outbox JSON text before decoding; pending outbox payloads count
    again because they are independently verified. A pending raw outbox is
    returned to the consumer, which decides whether projection may advance.
    """
    _integer(max_alerts, "max_alerts", minimum=1)
    _integer(max_bytes, "max_bytes", minimum=1)
    identity = _identity(path)
    connection = None
    try:
        connection = sqlite3.connect(Path(identity["path"]).as_uri() + "?mode=ro", uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        # Reading the schema establishes the same WAL snapshot used below.
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != set(_COLUMNS) or connection.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise EpisodeError("Episode source must be an existing rolling-v2 state database")
        for table, columns in _COLUMNS.items():
            schema = connection.execute(f"PRAGMA table_info({table})").fetchall()
            primary = "key" if table == "metadata" else "rule_id" if table == "checkpoints" else "alert_id"
            if {row[1] for row in schema} != columns or {row[1] for row in schema if row[5]} != {primary}:
                raise EpisodeError("Rolling source schema columns do not match v2")
        if connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
            raise EpisodeError("Rolling source SQLite integrity check failed")
        count = connection.execute("SELECT count(*) FROM alerts").fetchone()[0]
        if count > max_alerts:
            raise EpisodeError("max_alerts exceeded by retained rolling source rows")
        pending = connection.execute("SELECT count(*) FROM outbox").fetchone()[0]
        if pending > count:
            raise EpisodeError("Rolling source outbox contains orphaned rows")
        # Bound before materializing JSON strings, including metadata and retry
        # payloads. These aggregate queries are part of the same snapshot.
        payload_bytes = sum(connection.execute(query).fetchone()[0] or 0 for query in (
            "SELECT sum(length(CAST(value AS BLOB))) FROM metadata",
            "SELECT sum(length(CAST(payload AS BLOB))) FROM alerts",
            "SELECT sum(length(CAST(payload AS BLOB))) FROM outbox"))
        if payload_bytes > max_bytes:
            raise EpisodeError("max_bytes exceeded by retained rolling source payloads")
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if set(metadata) != {"binding", "last_clock"}:
            raise EpisodeError("Rolling source has no complete initialized binding and committed clock")
        binding = _json(metadata["binding"], "source binding")
        initial, scope = _binding(binding)
        last_clock = _time(metadata["last_clock"], "last_clock")
        checkpoint_rows = connection.execute("SELECT rule_id,watermark FROM checkpoints").fetchall()
        checkpoints = dict(checkpoint_rows)
        if len(checkpoint_rows) != len(checkpoints) or set(checkpoints) != set(binding["rule_ids"]):
            raise EpisodeError("Rolling source checkpoints do not match all bound rules")
        maximum = epoch_microseconds(MAX_TIME)
        cutoff = max(0, last_clock - binding["allowed_lateness_microseconds"])
        for value in checkpoints.values():
            _integer(value, "checkpoint")
            if not initial <= value <= maximum or (value != initial and value > cutoff):
                raise EpisodeError("Rolling checkpoint is outside the committed source time range")
        alerts, by_id, shapes = [], {}, {}
        for row in connection.execute("SELECT * FROM alerts ORDER BY alert_id"):
            alert = _alert(row, binding, scope, checkpoints, initial, last_clock)
            if alert["alert_id"] in by_id:
                raise EpisodeError("Rolling source contains duplicate logical alert rows")
            shape = (tuple(sorted(alert["group"])), tuple(sorted(alert["metrics"])), row["window_end"] - row["window_start"])
            if alert["rule_id"] in shapes and shapes[alert["rule_id"]] != shape:
                raise EpisodeError("Raw alerts disagree on their semantic rule's field/window shape")
            shapes[alert["rule_id"]] = shape
            alerts.append(alert)
            by_id[alert["alert_id"]] = alert
        for row in connection.execute("SELECT * FROM outbox"):
            alert = by_id.get(row["alert_id"])
            _integer(row["revision"], "outbox revision", minimum=1)
            _integer(row["attempts"], "outbox attempts")
            if row["last_error"] is not None and not isinstance(row["last_error"], str):
                raise EpisodeError("Rolling source outbox error code has an invalid type")
            if (alert is None or row["revision"] != alert["revision"]
                    or canonical(_json(row["payload"], "outbox payload")) != canonical(alert)):
                raise EpisodeError("Rolling source outbox differs from its logical alert revision")
        verify_identity(path, identity)
        return {"identity": identity, "binding": binding, "source_scope_id": scope,
                "checkpoints": checkpoints, "last_clock": metadata["last_clock"],
                "alerts": alerts, "pending_outbox": pending, "payload_bytes": payload_bytes}
    except (sqlite3.Error, OSError) as exc:
        raise EpisodeError("Cannot read a complete rolling source snapshot; no recovery or migration attempted") from exc
    finally:
        if connection is not None:
            connection.close()
