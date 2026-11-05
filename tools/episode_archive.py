#!/usr/bin/env python3
"""Export and verify coherent episode evidence without deleting live history.

The archive contains latest raw/episode documents, not an immutable revision
journal or a restorable Elasticsearch backup. Its checksum detects accidental
changes; it is not a signature or proof of the source's authenticity.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile

try:
    from tools.detection_runner import canonical, fingerprint
    from tools.elastic_adapter import index_path
    from tools.elastic_rolling import MAX_TIME, checked_time
    from tools.episode_engine import EpisodeError, POLICY_VERSION, group_episodes, policy_scope
    from tools.episode_source import (
        _alert, _binding as validate_raw_binding, _hash, _identity, _integer,
        _json, _time, read_snapshot, verify_identity,
    )
    from tools.hunt_engine import format_timestamp
    from tools.rolling_runner import epoch_microseconds
except ModuleNotFoundError:
    from detection_runner import canonical, fingerprint
    from elastic_adapter import index_path
    from elastic_rolling import MAX_TIME, checked_time
    from episode_engine import EpisodeError, POLICY_VERSION, group_episodes, policy_scope
    from episode_source import (
        _alert, _binding as validate_raw_binding, _hash, _identity, _integer,
        _json, _time, read_snapshot, verify_identity,
    )
    from hunt_engine import format_timestamp
    from rolling_runner import epoch_microseconds

FORMAT = "attck-episode-evidence"
VERSION = 1
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
EPISODE_COLUMNS = {
    "episode_meta": {"key", "value"},
    "episode_source_alerts": {"alert_id", "revision", "payload_hash"},
    "episodes": {"episode_id", "core", "payload"},
    "episode_outbox": {"episode_id", "payload", "revision", "attempts", "last_error"},
}
CORE_KEYS = {"episode_id", "scope_id", "source_scope_id", "policy_version", "gap_microseconds",
             "rule_id", "group", "status", "first_anchor", "last_anchor", "anchor_count",
             "peak_metrics", "member_alert_ids", "member_revisions", "replacement_episode_ids"}
EXTRA_KEYS = {"@timestamp", "revision", "first_detected_at", "updated_at"}


def _keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != expected:
        raise EpisodeError(f"{name} has unexpected or missing fields")


def _positive(value, name):
    return _integer(value, name, minimum=1)


def _declared_identity(identity):
    _keys(identity, {"path", "device", "inode"}, "source file identity")
    if not isinstance(identity["path"], str) or not Path(identity["path"]).is_absolute():
        raise EpisodeError("Archive source path must be absolute provenance")
    _integer(identity["device"], "source device")
    _positive(identity["inode"], "source inode")


def _manifest(alerts):
    return {alert["alert_id"]: [alert["revision"], fingerprint(alert)] for alert in alerts}


@contextmanager
def _locked_inputs(source_state, episode_state):
    source, episode = _identity(source_state), _identity(episode_state)
    if (source["device"], source["inode"]) == (episode["device"], episode["inode"]):
        raise EpisodeError("Archive inputs must be distinct state files")
    descriptors = []
    try:
        for name in sorted((source["path"], episode["path"])):
            path = Path(name + ".lock")
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError as exc:
                raise EpisodeError("Cannot lock existing archive inputs; no input was created or changed") from exc
            descriptors.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise EpisodeError("Existing state lock must be a nonsymlink regular file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EpisodeError("State writer is active; retry archive creation after its pass") from exc
            current = path.lstat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise EpisodeError("State lock was replaced while opening the archive")
        verify_identity(source_state, source)
        verify_identity(episode_state, episode)
        yield source, episode
        verify_identity(source_state, source)
        verify_identity(episode_state, episode)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _read_projection(path, snapshot, max_rows, max_bytes):
    with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != set(EPISODE_COLUMNS) or db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise EpisodeError("Archive episode source must use the initialized episode schema 1")
        for table, expected in EPISODE_COLUMNS.items():
            columns = db.execute(f"PRAGMA table_info({table})").fetchall()
            primary = "key" if table == "episode_meta" else "alert_id" if table == "episode_source_alerts" else "episode_id"
            if ({row[1] for row in columns} != expected
                    or {row[1] for row in columns if row[5]} != {primary}):
                raise EpisodeError("Episode source schema columns differ from the supported contract")
        if db.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
            raise EpisodeError("Episode source SQLite integrity check failed")
        if db.execute("SELECT count(*) FROM episode_outbox").fetchone()[0]:
            raise EpisodeError("Episode outbox must be empty before archival")
        rows = db.execute("SELECT count(*) FROM episodes").fetchone()[0]
        if rows > max_rows:
            raise EpisodeError("max_episode_rows exceeded, including retracted episodes")
        size = sum(db.execute(query).fetchone()[0] or 0 for query in (
            "SELECT sum(length(CAST(value AS BLOB))) FROM episode_meta",
            "SELECT sum(length(CAST(core AS BLOB))+length(CAST(payload AS BLOB))) FROM episodes",
            "SELECT sum(length(CAST(alert_id AS BLOB))+length(CAST(payload_hash AS BLOB))) FROM episode_source_alerts"))
        if size > max_bytes:
            raise EpisodeError("max_episode_bytes exceeded by episode metadata, documents and source manifest")
        metadata = dict(db.execute("SELECT key,value FROM episode_meta"))
        if set(metadata) != {"binding", "source_progress", "last_clock"}:
            raise EpisodeError("Episode state must contain a complete committed projection")
        projection = {key: _json(value, "episode metadata") for key, value in metadata.items()}
        observed = {row["alert_id"]: [row["revision"], row["payload_hash"]]
                    for row in db.execute("SELECT * FROM episode_source_alerts")}
        if observed != _manifest(snapshot["alerts"]):
            raise EpisodeError("Episode source manifest is stale or incomplete; run the projection first")
        projection["source_manifest_sha256"] = fingerprint(observed)
        episodes = []
        for row in db.execute("SELECT * FROM episodes ORDER BY episode_id"):
            payload = _json(row["payload"], "episode payload")
            core = _json(row["core"], "episode core")
            if (not isinstance(payload, dict) or row["episode_id"] != payload.get("episode_id")
                    or not isinstance(core, dict) or canonical(core) != canonical({key: value for key, value in payload.items() if key not in EXTRA_KEYS})):
                raise EpisodeError("Stored episode core and payload disagree")
            episodes.append(payload)
        return projection, episodes


def _validate_source(source, alerts):
    _keys(source, {"identity", "binding", "source_scope_id", "checkpoints", "last_clock"}, "archive source")
    _declared_identity(source["identity"])
    initial, scope = validate_raw_binding(source["binding"])
    if source["source_scope_id"] != scope:
        raise EpisodeError("Archive source scope differs from its binding")
    last_clock = _time(source["last_clock"], "source clock")
    checkpoints = source["checkpoints"]
    if not isinstance(checkpoints, dict) or set(checkpoints) != set(source["binding"]["rule_ids"]):
        raise EpisodeError("Archive checkpoints must cover every bound rule")
    cutoff = max(0, last_clock - source["binding"]["allowed_lateness_microseconds"])
    maximum = epoch_microseconds(MAX_TIME)
    for checkpoint in checkpoints.values():
        _integer(checkpoint, "checkpoint")
        if not initial <= checkpoint <= maximum or (checkpoint != initial and checkpoint > cutoff):
            raise EpisodeError("Archive checkpoint contradicts its committed source clock")
    if not isinstance(alerts, list):
        raise EpisodeError("Archive raw alerts must be a complete list")
    by_id = {}
    for alert in alerts:
        if not isinstance(alert, dict) or not isinstance(alert.get("window"), dict):
            raise EpisodeError("Invalid raw alert in archive")
        row = {"alert_id": alert.get("alert_id"), "rule_id": alert.get("rule_id"),
               "window_start": _time(alert["window"].get("start"), "window.start"),
               "window_end": _time(alert["window"].get("end"), "window.end"), "payload": canonical(alert)}
        checked = _alert(row, source["binding"], scope, checkpoints, initial, last_clock)
        if checked["alert_id"] in by_id:
            raise EpisodeError("Archive contains duplicate raw alert identities")
        by_id[checked["alert_id"]] = checked
    if [alert["alert_id"] for alert in alerts] != sorted(by_id):
        raise EpisodeError("Archive raw alerts must be ordered by their IDs")
    return by_id


def _validate_projection(projection, source, raw_by_id):
    _keys(projection, {"binding", "source_progress", "last_clock", "source_manifest_sha256"}, "archive projection")
    binding = projection["binding"]
    expected = {"state_version", "policy_version", "source_identity", "raw_binding", "source_scope_id", "gap_microseconds", "episodes"}
    _keys(binding, expected, "episode binding")
    if (type(binding["state_version"]) is not int or binding["state_version"] != 1
            or type(binding["policy_version"]) is not int or binding["policy_version"] != POLICY_VERSION
            or binding["source_identity"] != source["identity"] or binding["raw_binding"] != source["binding"]
            or binding["source_scope_id"] != source["source_scope_id"]):
        raise EpisodeError("Episode binding does not match the archived raw source")
    gap_us = _positive(binding["gap_microseconds"], "gap_microseconds")
    _keys(binding["episodes"], {"name", "uuid"}, "episode sink identity")
    if not isinstance(binding["episodes"]["name"], str):
        raise EpisodeError("Episode sink name must be a concrete index string")
    index_path(binding["episodes"]["name"])
    sink_uuid = binding["episodes"]["uuid"]
    if not isinstance(sink_uuid, str) or not sink_uuid.strip() or sink_uuid in {source["binding"][key]["uuid"] for key in ("source", "alerts")}:
        raise EpisodeError("Episode sink must have a separate concrete UUID")
    expected_progress = {"checkpoints": source["checkpoints"], "last_clock": source["last_clock"]}
    if projection["source_progress"] != expected_progress:
        raise EpisodeError("Projection progress is stale; source and episode snapshots must match exactly")
    _time(projection["last_clock"], "projection clock")
    if projection["source_manifest_sha256"] != fingerprint(_manifest(list(raw_by_id.values()))):
        raise EpisodeError("Archived source manifest digest does not match complete raw history")
    return timedelta(microseconds=gap_us)


def _validate_episode(payload, source, projection, raw_by_id, gap):
    _keys(payload, CORE_KEYS | EXTRA_KEYS, "episode document")
    core = {key: payload[key] for key in CORE_KEYS}
    identifier = _hash(core["episode_id"], "episode_id")
    _hash(core["rule_id"], "episode rule_id")
    scope = policy_scope(source["source_scope_id"], gap)
    if (core["source_scope_id"] != source["source_scope_id"] or core["scope_id"] != scope
            or type(core["policy_version"]) is not int or core["policy_version"] != POLICY_VERSION
            or type(core["gap_microseconds"]) is not int or core["gap_microseconds"] != projection["binding"]["gap_microseconds"]
            or core["rule_id"] not in source["checkpoints"] or core["status"] not in ("open", "closed", "retracted")):
        raise EpisodeError("Episode policy, scope, rule or status is invalid")
    members = core["member_alert_ids"]
    if not isinstance(members, list) or not members or any(not isinstance(member, str) for member in members) or len(set(members)) != len(members):
        raise EpisodeError("Episode members must be a nonempty unique ID list")
    if any(member not in raw_by_id for member in members):
        raise EpisodeError("Episode refers to missing raw history")
    selected = [raw_by_id[member] for member in members]
    expected_order = sorted(selected, key=lambda item: (_time(item["window"]["end"], "member anchor"), item["alert_id"]))
    if members != [item["alert_id"] for item in expected_order]:
        raise EpisodeError("Episode members must follow exact anchor order")
    if any(item["rule_id"] != core["rule_id"] or item["group"] != core["group"] for item in selected):
        raise EpisodeError("Episode members must have the same exact rule and group")
    revisions = core["member_revisions"]
    if not isinstance(revisions, dict) or set(revisions) != set(members):
        raise EpisodeError("Episode member revisions must cover each member")
    for member, revision in revisions.items():
        _positive(revision, "member revision")
        if revision > raw_by_id[member]["revision"]:
            raise EpisodeError("Episode member revision exceeds current raw history")
    if type(core["anchor_count"]) is not int or core["anchor_count"] != len(members):
        raise EpisodeError("Episode anchor count does not match members")
    first = _time(core["first_anchor"], "first_anchor")
    last = _time(core["last_anchor"], "last_anchor")
    if (first != _time(selected[0]["window"]["end"], "first member")
            or last != _time(selected[-1]["window"]["end"], "last member")
            or _time(payload["@timestamp"], "episode @timestamp") != last):
        raise EpisodeError("Episode first/last anchors do not match member evidence")
    gap_us = projection["binding"]["gap_microseconds"]
    if any(_time(right["window"]["end"], "member") - _time(left["window"]["end"], "member") > gap_us for left, right in zip(selected, selected[1:])):
        raise EpisodeError("Episode members do not form a connected gap component")
    if identifier != fingerprint({"scope": scope, "rule": core["rule_id"], "group": core["group"], "first_alert_id": members[0]}):
        raise EpisodeError("Episode ID does not follow its earliest member")
    peak = core["peak_metrics"]
    if not isinstance(peak, dict) or set(peak) != set(selected[0]["metrics"]):
        raise EpisodeError("Episode peak metric fields do not match the rule")
    for value in peak.values():
        _integer(value, "peak metric")
    # Retired documents may refer to earlier member revisions whose old
    # metrics are no longer retained. Exact validation remains possible when
    # every referenced revision is still the current raw revision.
    if all(revisions[item["alert_id"]] == item["revision"] for item in selected):
        if peak != {name: max(item["metrics"][name] for item in selected) for name in peak}:
            raise EpisodeError("Episode peak metrics disagree with the referenced raw revisions")
    replacements = core["replacement_episode_ids"]
    if (not isinstance(replacements, list) or any(not isinstance(item, str) for item in replacements)
            or replacements != sorted(set(replacements))):
        raise EpisodeError("Episode replacement references must be unique ordered IDs")
    _positive(payload["revision"], "episode revision")
    if not (_time(payload["first_detected_at"], "first_detected_at") <= _time(payload["updated_at"], "updated_at") <= _time(projection["last_clock"], "projection clock")):
        raise EpisodeError("Episode update times contradict committed projection time")
    return core


def _retention(source, projection, current):
    initial = _time(source["binding"]["initial_start"], "initial_start")
    floors = {rule: max(initial, checkpoint - source["binding"]["lookback_microseconds"])
              for rule, checkpoint in source["checkpoints"].items()}
    gap_us = projection["binding"]["gap_microseconds"]
    stable = sorted(core["episode_id"] for core in current.values()
                    if core["status"] == "closed" and _time(core["last_anchor"], "last anchor") + gap_us < floors[core["rule_id"]])
    return {"replay_floor_microseconds": floors, "replay_stable_episode_ids": stable,
            "scope": "current-bounded-replay-policy-only", "pruning_applied": False}


def _validate_content(content):
    _keys(content, {"created_at", "source", "projection", "raw_alerts", "episodes", "counts", "retention_plan"}, "archive content")
    _time(content["created_at"], "archive created_at")
    source, projection = content["source"], content["projection"]
    raw_by_id = _validate_source(source, content["raw_alerts"])
    gap = _validate_projection(projection, source, raw_by_id)
    documents = content["episodes"]
    if not isinstance(documents, list):
        raise EpisodeError("Archive episodes must be a complete list")
    expected = {core["episode_id"]: {**core, "replacement_episode_ids": []}
                for core in group_episodes(content["raw_alerts"], source_scope_id=source["source_scope_id"],
                                           checkpoints=source["checkpoints"], gap=gap,
                                           max_episodes=max(1, len(content["raw_alerts"])), max_members=max(1, len(content["raw_alerts"])))}
    checked = {}
    for payload in documents:
        core = _validate_episode(payload, source, projection, raw_by_id, gap)
        if core["episode_id"] in checked:
            raise EpisodeError("Archive contains duplicate episode documents")
        checked[core["episode_id"]] = core
    if [payload["episode_id"] for payload in documents] != sorted(checked):
        raise EpisodeError("Archive episode documents must be ordered by their IDs")
    current = {key: value for key, value in checked.items() if value["status"] != "retracted"}
    if current != expected:
        raise EpisodeError("Archived current episodes differ from the complete reference projection")
    membership = {member: identifier for identifier, core in current.items() for member in core["member_alert_ids"]}
    for core in checked.values():
        if core["status"] == "retracted":
            replacements = sorted({membership[member] for member in core["member_alert_ids"] if member in membership})
            if core["replacement_episode_ids"] != replacements:
                raise EpisodeError("Retracted episode replacement references are stale")
    counts = {"raw_alerts": len(raw_by_id), "episodes": len(checked)}
    if content["counts"] != counts or any(type(value) is not int for value in content["counts"].values()):
        raise EpisodeError("Archive counts do not match its complete documents")
    retention = _retention(source, projection, current)
    if content["retention_plan"] != retention:
        raise EpisodeError("Archive retention assessment does not match the strict replay boundary")
    return {"ok": True, "verified": True, **counts, "current_episodes": len(current),
            "replay_stable_episodes": len(retention["replay_stable_episode_ids"]), "pruning_applied": False}


def _publish(path, document, maximum):
    target = Path(path).absolute()
    if os.path.lexists(target):
        raise EpisodeError("Archive destination already exists; it will not be overwritten")
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise EpisodeError("Archive destination parent must be an existing nonsymlink directory")
    encoded = (canonical(document) + "\n").encode("utf-8")
    if len(encoded) > maximum:
        raise EpisodeError("max_archive_bytes exceeded; no archive was published")
    descriptor, temporary = tempfile.mkstemp(prefix=".episode-archive-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise EpisodeError("Archive destination appeared concurrently; it was not overwritten") from exc
        os.unlink(temporary)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def create_archive(source_state, episode_state, destination, *, max_source_alerts=100_000,
                   max_source_bytes=64 * 1024 * 1024, max_episode_rows=100_000,
                   max_episode_bytes=128 * 1024 * 1024, max_archive_bytes=MAX_ARCHIVE_BYTES,
                   clock=None):
    """Export coherent latest evidence; preserve all live rows and outboxes."""
    for name, value in (("max_source_alerts", max_source_alerts), ("max_source_bytes", max_source_bytes),
                        ("max_episode_rows", max_episode_rows), ("max_episode_bytes", max_episode_bytes),
                        ("max_archive_bytes", max_archive_bytes)):
        _positive(value, name)
    if os.path.lexists(destination):
        raise EpisodeError("Archive destination already exists; it will not be overwritten")
    with _locked_inputs(source_state, episode_state) as (source_identity, episode_identity):
        snapshot = read_snapshot(source_state, max_alerts=max_source_alerts, max_bytes=max_source_bytes)
        if snapshot["pending_outbox"]:
            raise EpisodeError("Raw outbox must be empty before archival")
        try:
            projection, episodes = _read_projection(episode_identity["path"], snapshot, max_episode_rows, max_episode_bytes)
        except sqlite3.Error as exc:
            raise EpisodeError("Cannot read complete episode archive evidence; no recovery attempted") from exc
        source = {key: snapshot[key] for key in ("identity", "binding", "source_scope_id", "checkpoints", "last_clock")}
        content = {"created_at": format_timestamp(checked_time((clock or (lambda: datetime.now(timezone.utc)))())),
                   "source": source, "projection": projection, "raw_alerts": snapshot["alerts"], "episodes": episodes,
                   "counts": {"raw_alerts": len(snapshot["alerts"]), "episodes": len(episodes)}}
        current = {payload["episode_id"]: payload for payload in episodes if payload["status"] != "retracted"}
        content["retention_plan"] = _retention(source, projection, current)
        report = _validate_content(content)
        checksum = fingerprint(content)
        verify_identity(source_state, source_identity)
        verify_identity(episode_state, episode_identity)
        _publish(destination, {"format": FORMAT, "version": VERSION, "sha256": checksum, "content": content}, max_archive_bytes)
        return {**report, "sha256": checksum, "archive": str(Path(destination).absolute())}


def verify_archive(path, *, max_archive_bytes=MAX_ARCHIVE_BYTES):
    """Verify bounds, checksum and semantic completeness without source access."""
    _positive(max_archive_bytes, "max_archive_bytes")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise EpisodeError("Archive must be a nonsymlink regular file")
        if info.st_size > max_archive_bytes:
            raise EpisodeError("max_archive_bytes exceeded before reading archive")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(max_archive_bytes + 1)
        after = os.fstat(descriptor)
        if len(data) != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise EpisodeError("Archive changed during verification")
        current = Path(path).lstat()
        if not stat.S_ISREG(current.st_mode) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise EpisodeError("Archive path was replaced during verification")
        if len(data) > max_archive_bytes:
            raise EpisodeError("max_archive_bytes exceeded while reading archive")
    finally:
        os.close(descriptor)
    try:
        envelope = _json(data.decode("utf-8"), "archive")
    except UnicodeError as exc:
        raise EpisodeError("Archive must be UTF-8 JSON") from exc
    _keys(envelope, {"format", "version", "sha256", "content"}, "archive envelope")
    if envelope["format"] != FORMAT or type(envelope["version"]) is not int or envelope["version"] != VERSION:
        raise EpisodeError("Unsupported episode archive format/version")
    _hash(envelope["sha256"], "archive checksum")
    if fingerprint(envelope["content"]) != envelope["sha256"]:
        raise EpisodeError("Archive checksum does not match its content")
    report = _validate_content(envelope["content"])
    return {**report, "sha256": envelope["sha256"], "archive": str(Path(path).absolute())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    create = modes.add_parser("create", help="Export coherent evidence; no deletion or restoration")
    create.add_argument("--source-state", type=Path, required=True)
    create.add_argument("--episode-state", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--max-source-alerts", type=int, default=100_000)
    create.add_argument("--max-source-bytes", type=int, default=64 * 1024 * 1024)
    create.add_argument("--max-episode-rows", type=int, default=100_000)
    create.add_argument("--max-episode-bytes", type=int, default=128 * 1024 * 1024)
    create.add_argument("--max-archive-bytes", type=int, default=MAX_ARCHIVE_BYTES)
    verify = modes.add_parser("verify", help="Check the archive offline, including reference grouping")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--max-archive-bytes", type=int, default=MAX_ARCHIVE_BYTES)
    args = parser.parse_args(argv)
    try:
        if args.mode == "create":
            report = create_archive(args.source_state, args.episode_state, args.output,
                                    max_source_alerts=args.max_source_alerts, max_source_bytes=args.max_source_bytes,
                                    max_episode_rows=args.max_episode_rows, max_episode_bytes=args.max_episode_bytes,
                                    max_archive_bytes=args.max_archive_bytes)
        else:
            report = verify_archive(args.archive, max_archive_bytes=args.max_archive_bytes)
        print(json.dumps(report, ensure_ascii=False))
        return 0
    except (ValueError, OSError, sqlite3.Error, OverflowError) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
