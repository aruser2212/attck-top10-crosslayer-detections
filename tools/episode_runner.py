#!/usr/bin/env python3
"""Durable downstream projection of rolling alerts into bounded episodes.

The source is one complete, read-only SQLite snapshot from the rolling v2
runner. Raw alerts are never modified. Every successful projection atomically
stores the observed raw revisions, episode documents and delivery outbox.
Incremental mode recomputes groups affected by raw revisions or closure; the
complete source snapshot and retained revision guards are still read each pass.
Full mode remains a reference implementation with the same document semantics.
Configured limits apply to the complete current projection in both modes.
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
    from tools.detection_runner import canonical, fingerprint, transaction
    from tools.elastic_adapter import ElasticError, ElasticHTTPError, ensure_search_visibility, get_index_identity, index_path
    from tools.elastic_rolling import checked_time
    from tools.episode_engine import EpisodeError, POLICY_VERSION, gap_microseconds, group_episodes
    from tools.episode_source import read_snapshot, verify_identity
    from tools.hunt_engine import format_timestamp
    from tools.rolling_runner import epoch_microseconds
except ModuleNotFoundError:
    from detection_runner import canonical, fingerprint, transaction
    from elastic_adapter import ElasticError, ElasticHTTPError, ensure_search_visibility, get_index_identity, index_path
    from elastic_rolling import checked_time
    from episode_engine import EpisodeError, POLICY_VERSION, gap_microseconds, group_episodes
    from episode_source import read_snapshot, verify_identity
    from hunt_engine import format_timestamp
    from rolling_runner import epoch_microseconds

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "profiles/elastic/episodes-v1.mapping.json"
STATE_VERSION = 1
TABLES = {"episode_meta", "episode_source_alerts", "episodes", "episode_outbox"}


class EpisodeBusy(EpisodeError):
    """Another process owns this episode state database."""


def _positive(value, name):
    if type(value) is not int or value < 1:
        raise EpisodeError(f"{name} must be a positive integer")


def create_episode_index(client, index: str) -> None:
    """Create an explicitly requested, dedicated sink without overwriting one."""
    client.request("PUT", index_path(index), json.loads(MAPPING_PATH.read_text(encoding="utf-8")))


def check_episode_profile(client, index: str) -> dict:
    result = client.request("GET", index_path(index) + "/_mapping")
    expected = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["mappings"]
    if (not isinstance(result, dict) or set(result) != {index}
            or not isinstance(result[index], dict) or result[index].get("mappings") != expected):
        raise EpisodeError("Episode sink does not match the dedicated episodes-v1 mapping")
    return get_index_identity(client, index)


class EpisodeRunner:
    def __init__(self, *, source_state: str | Path, state_path: str | Path,
                 sink_client, episodes_index: str,
                 gap: timedelta = timedelta(minutes=5), initialize_index: bool = False,
                 max_source_alerts: int = 100_000, max_source_bytes: int = 64 * 1024 * 1024,
                 max_episodes: int = 10_000, max_members: int = 10_000,
                 max_changes: int = 10_000, clock: Callable[[], datetime] | None = None,
                 fault_hook: Callable | None = None, projection_mode: str = "incremental"):
        index_path(episodes_index)
        self.source_state = Path(source_state).absolute()
        self.state_path = Path(state_path).absolute()
        if self.source_state.is_symlink() or self.state_path.is_symlink():
            raise EpisodeError("Source and episode state paths must not be symlinks")
        self.source_state, self.state_path = self.source_state.resolve(), self.state_path.resolve()
        if self.source_state == self.state_path:
            raise EpisodeError("Source and episode state must be different files")
        self.gap = gap
        self.gap_us = gap_microseconds(gap)
        for name, value in (("max_source_alerts", max_source_alerts), ("max_source_bytes", max_source_bytes),
                            ("max_episodes", max_episodes), ("max_members", max_members),
                            ("max_changes", max_changes)):
            _positive(value, name)
            setattr(self, name, value)
        if type(initialize_index) is not bool:
            raise EpisodeError("initialize_index must be boolean")
        if projection_mode not in ("incremental", "full"):
            raise EpisodeError("projection_mode must be incremental or full")
        self.projection_mode = projection_mode
        self.sink_client, self.episodes_index = sink_client, episodes_index
        self.initialize_index = initialize_index
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.fault_hook = fault_hook or (lambda *_: None)

    @contextmanager
    def _state(self):
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(str(self.state_path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        connection = None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise EpisodeError("Episode lock must be a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EpisodeBusy("Another process owns this episode state database") from exc
            fd = os.open(self.state_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise EpisodeError("Episode state must be a regular file")
                source_stat = self.source_state.stat()
                if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (source_stat.st_dev, source_stat.st_ino):
                    raise EpisodeError("Source and episode state must not share the same inode")
            finally:
                os.close(fd)
            connection = sqlite3.connect(self.state_path, timeout=0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise EpisodeError("Episode SQLite integrity check failed; preserve the state for recovery")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if (tables and tables != TABLES) or version not in ({STATE_VERSION} if tables else {0}):
                raise EpisodeError("Unknown episode state schema/version; refusing to modify or migrate it")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise EpisodeError("Episode state requires SQLite WAL on a local durable filesystem")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if not tables:
                with transaction(connection):
                    connection.execute("CREATE TABLE episode_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    connection.execute("CREATE TABLE episode_source_alerts (alert_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload_hash TEXT NOT NULL)")
                    connection.execute("CREATE TABLE episodes (episode_id TEXT PRIMARY KEY, core TEXT NOT NULL, payload TEXT NOT NULL)")
                    connection.execute("CREATE TABLE episode_outbox (episode_id TEXT PRIMARY KEY REFERENCES episodes(episode_id), payload TEXT NOT NULL, revision INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)")
                    connection.execute(f"PRAGMA user_version={STATE_VERSION}")
            yield connection
        except sqlite3.DatabaseError as exc:
            raise EpisodeError("Episode SQLite operation failed; no state reset was attempted") from exc
        finally:
            if connection is not None:
                connection.close()
            os.close(descriptor)

    @staticmethod
    def _meta(connection, key):
        row = connection.execute("SELECT value FROM episode_meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def _put_meta(connection, key, value):
        connection.execute("INSERT INTO episode_meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, canonical(value)))

    def _binding(self, connection, snapshot):
        previous = self._meta(connection, "binding")
        source_binding = {"state_version": STATE_VERSION, "policy_version": POLICY_VERSION,
                          "source_identity": snapshot["identity"], "raw_binding": snapshot["binding"],
                          "source_scope_id": snapshot["source_scope_id"], "gap_microseconds": self.gap_us}
        if previous is not None and {key: previous.get(key) for key in source_binding} != source_binding:
            raise EpisodeError("Episode state scope changed: source identity, raw binding or grouping policy")
        try:
            sink = check_episode_profile(self.sink_client, self.episodes_index)
        except ElasticHTTPError as exc:
            if exc.status != 404 or not self.initialize_index or previous is not None:
                raise
            create_episode_index(self.sink_client, self.episodes_index)
            sink = check_episode_profile(self.sink_client, self.episodes_index)
        if sink["uuid"] in {snapshot["binding"]["source"]["uuid"], snapshot["binding"]["alerts"]["uuid"]}:
            raise EpisodeError("Episode sink must be separate from the raw source and alert indices")
        binding = {**source_binding, "episodes": sink}
        if previous is not None and previous != binding:
            raise EpisodeError("Episode state sink changed; reuse requires the same index UUID")
        if previous is None:
            # Equal-version redelivery is safe only for immutable payloads from
            # this state. A new/reset state must not reuse populated documents
            # whose revision history it no longer knows. Refresh also exposes
            # unrefreshed writes before this first-binding guard counts them.
            ensure_search_visibility(self.sink_client, self.episodes_index)
            result = self.sink_client.request("GET", index_path(self.episodes_index) + "/_count")
            shards = result.get("_shards", {})
            if (type(result.get("count")) is not int or result["count"] < 0
                    or result.get("error") or result.get("timed_out", False) is not False
                    or not isinstance(shards, dict)
                    or any(type(shards.get(key)) is not int for key in ("total", "successful", "failed"))
                    or shards["total"] < 1 or shards["successful"] != shards["total"]
                    or shards["failed"] != 0 or shards.get("failures")):
                raise EpisodeError("Episode sink count was incomplete; first binding was not established")
            if result["count"]:
                raise EpisodeError("New episode state requires an empty dedicated sink; restore the matching state or choose a new empty index")
            if get_index_identity(self.sink_client, self.episodes_index) != sink:
                raise EpisodeError("Episode sink changed before initial binding")
            with transaction(connection):
                self._put_meta(connection, "binding", binding)
        return binding

    def _check_progress(self, connection, snapshot):
        previous = self._meta(connection, "source_progress")
        if previous is not None:
            if (set(previous["checkpoints"]) != set(snapshot["checkpoints"])
                    or any(snapshot["checkpoints"][key] < value for key, value in previous["checkpoints"].items())
                    or checked_time(snapshot["last_clock"]) < checked_time(previous["last_clock"])):
                raise EpisodeError("Rolling source checkpoint or clock regressed; refusing restored or incomplete history")
        manifest = {alert["alert_id"]: (alert["revision"], fingerprint(alert)) for alert in snapshot["alerts"]}
        for row in connection.execute("SELECT * FROM episode_source_alerts"):
            current = manifest.get(row["alert_id"])
            if current is None:
                raise EpisodeError("Rolling source lost a previously observed alert row; retractions must retain raw history")
            if current[0] < row["revision"] or (current[0] == row["revision"] and current[1] != row["payload_hash"]):
                raise EpisodeError("Rolling source revision regressed or changed without a new revision")
        return manifest

    def _deliver(self, connection, binding):
        delivered = 0
        while True:
            row = connection.execute("SELECT * FROM episode_outbox ORDER BY episode_id LIMIT 1").fetchone()
            if row is None:
                return delivered
            with transaction(connection):
                connection.execute("UPDATE episode_outbox SET attempts=attempts+1,last_error=NULL WHERE episode_id=?", (row["episode_id"],))
            try:
                verify_identity(self.source_state, binding["source_identity"])
                if get_index_identity(self.sink_client, self.episodes_index) != binding["episodes"]:
                    raise EpisodeError("Episode sink changed before delivery")
                response = self.sink_client.request(
                    "PUT", index_path(self.episodes_index) + "/_doc/" + quote(row["episode_id"], safe="")
                    + f"?version={row['revision']}&version_type=external_gte&refresh=wait_for", json.loads(row["payload"]))
                shards = response.get("_shards", {})
                if (response.get("_id") != row["episode_id"] or response.get("_index") != self.episodes_index
                        or type(response.get("_version")) is not int or response["_version"] != row["revision"]
                        or response.get("result") not in {"created", "updated"}
                        or not isinstance(shards, dict) or type(shards.get("failed")) is not int or shards["failed"] != 0):
                    raise EpisodeError("Episode write was not acknowledged completely")
                if get_index_identity(self.sink_client, self.episodes_index) != binding["episodes"]:
                    raise EpisodeError("Episode sink changed during delivery; acknowledgement withheld")
            except (ElasticError, EpisodeError) as exc:
                with transaction(connection):
                    connection.execute("UPDATE episode_outbox SET last_error=? WHERE episode_id=?", (type(exc).__name__, row["episode_id"]))
                detail = "; stale revision rejected, inspect state copies/restores" if isinstance(exc, ElasticHTTPError) and exc.status == 409 else ""
                raise EpisodeError("Episode delivery failed; durable outbox remains pending" + detail) from exc
            self.fault_hook("after_delivery", {"episode_id": row["episode_id"], "revision": row["revision"]})
            with transaction(connection):
                connection.execute("DELETE FROM episode_outbox WHERE episode_id=? AND revision=?", (row["episode_id"], row["revision"]))
            delivered += 1

    def _save(self, connection, core, old, now):
        payload = {**core, "@timestamp": core["last_anchor"],
                   "revision": old["revision"] + 1 if old else 1,
                   "first_detected_at": old["first_detected_at"] if old else format_timestamp(now),
                   "updated_at": format_timestamp(now)}
        encoded = canonical(payload)
        connection.execute("INSERT INTO episodes VALUES (?,?,?) ON CONFLICT(episode_id) DO UPDATE SET core=excluded.core,payload=excluded.payload", (core["episode_id"], canonical(core), encoded))
        connection.execute("INSERT INTO episode_outbox(episode_id,payload,revision) VALUES (?,?,?) ON CONFLICT(episode_id) DO UPDATE SET payload=excluded.payload,revision=excluded.revision,attempts=0,last_error=NULL", (core["episode_id"], encoded, payload["revision"]))

    @staticmethod
    def _group_key(value):
        return value["rule_id"], canonical(value["group"])

    def _recompute(self, connection, snapshot):
        """Rebuild complete affected groups; retain the existing state schema.

        The source reader has already validated every retained row, and
        _check_progress rejected missing rows or revision/hash regressions.
        Thus a raw ID keeps its rule/group and only new or higher revisions can
        change membership or peak metrics. Closure is the other source of change.
        Scanning source and cached cores remains O(retained history); sorting and
        component construction are restricted to affected groups in incremental
        mode. No claim of incremental source ingestion or bounded archival is made.
        """
        groups = {}
        for alert in snapshot["alerts"]:
            groups.setdefault(self._group_key(alert), []).append(alert)
        if self.projection_mode == "full" or self._meta(connection, "source_progress") is None:
            dirty = set(groups)
        else:
            revisions = dict(connection.execute("SELECT alert_id,revision FROM episode_source_alerts"))
            dirty = {self._group_key(alert) for alert in snapshot["alerts"]
                     if revisions.get(alert["alert_id"]) != alert["revision"]}
            for row in connection.execute("SELECT core FROM episodes"):
                core = json.loads(row["core"])
                key = self._group_key(core)
                if key not in groups:
                    raise EpisodeError("Cached episode group is absent from retained source history")
                if (core["status"] == "open"
                        and snapshot["checkpoints"][core["rule_id"]]
                        > epoch_microseconds(checked_time(core["last_anchor"])) + self.gap_us):
                    dirty.add(key)

        # Lowering an operational limit must also constrain untouched caches.
        # Apply it after identifying dirty groups, because their new projection
        # may legitimately be smaller than the previously stored components.
        cached_current = 0
        for row in connection.execute("SELECT core FROM episodes"):
            core = json.loads(row["core"])
            if self._group_key(core) not in dirty and core["status"] != "retracted":
                cached_current += 1
                if len(core["member_alert_ids"]) > self.max_members:
                    raise EpisodeError("max_members exceeded by an unchanged cached episode")
        selected = [alert for key in sorted(dirty) for alert in groups[key]]
        cores = group_episodes(selected, source_scope_id=snapshot["source_scope_id"],
                               checkpoints=snapshot["checkpoints"], gap=self.gap,
                               max_episodes=self.max_episodes, max_members=self.max_members) if dirty else []
        if cached_current + len(cores) > self.max_episodes:
            raise EpisodeError("max_episodes exceeded across cached and recomputed groups")
        return cores, dirty, {"mode": self.projection_mode, "groups_total": len(groups),
                              "groups_recomputed": len(dirty),
                              "source_alerts_recomputed": len(selected)}

    def run_once(self):
        now = checked_time(self.clock())
        snapshot = read_snapshot(self.source_state, max_alerts=self.max_source_alerts, max_bytes=self.max_source_bytes)
        with self._state() as connection:
            binding = self._binding(connection, snapshot)
            last_clock = self._meta(connection, "last_clock")
            if last_clock is not None and now < checked_time(last_clock):
                raise EpisodeError("Episode clock moved backwards; no delivery or projection performed")
            manifest = self._check_progress(connection, snapshot)
            delivered = self._deliver(connection, binding)
            if snapshot["pending_outbox"]:
                return {"ok": False, "status": "waiting_for_raw_delivery", "raw_pending_outbox": snapshot["pending_outbox"],
                        "outbox_delivered": delivered, "pending_outbox": connection.execute("SELECT count(*) FROM episode_outbox").fetchone()[0]}
            cores, dirty, recomputation = self._recompute(connection, snapshot)
            current_ids = {core["episode_id"] for core in cores}
            membership = {member: core["episode_id"] for core in cores for member in core["member_alert_ids"]}
            counts = {"created": 0, "updated": 0, "retracted": 0, "unchanged": 0}
            changes = 0
            with transaction(connection):
                for core in cores:
                    core = {**core, "replacement_episode_ids": []}
                    row = connection.execute("SELECT * FROM episodes WHERE episode_id=?", (core["episode_id"],)).fetchone()
                    if row is not None and row["core"] == canonical(core):
                        counts["unchanged"] += 1
                        continue
                    changes += 1
                    if changes > self.max_changes:
                        raise EpisodeError("max_changes exceeded; no episode projection or source progress committed")
                    self._save(connection, core, json.loads(row["payload"]) if row else None, now)
                    counts["updated" if row else "created"] += 1
                for row in connection.execute("SELECT * FROM episodes ORDER BY episode_id"):
                    if row["episode_id"] in current_ids:
                        continue
                    old_core = json.loads(row["core"])
                    if self._group_key(old_core) not in dirty:
                        counts["unchanged"] += 1
                        continue
                    replacements = sorted({membership[member] for member in old_core["member_alert_ids"] if member in membership})
                    core = {**old_core, "status": "retracted", "replacement_episode_ids": replacements}
                    if canonical(core) == row["core"]:
                        counts["unchanged"] += 1
                        continue
                    changes += 1
                    if changes > self.max_changes:
                        raise EpisodeError("max_changes exceeded by episode updates and retractions; no progress committed")
                    self._save(connection, core, json.loads(row["payload"]), now)
                    counts["retracted" if old_core["status"] != "retracted" else "updated"] += 1
                connection.executemany("INSERT INTO episode_source_alerts VALUES (?,?,?) ON CONFLICT(alert_id) DO UPDATE SET revision=excluded.revision,payload_hash=excluded.payload_hash", [(identifier, revision, digest) for identifier, (revision, digest) in manifest.items()])
                self._put_meta(connection, "source_progress", {"checkpoints": snapshot["checkpoints"], "last_clock": snapshot["last_clock"]})
                self._put_meta(connection, "last_clock", format_timestamp(now))
                self.fault_hook("before_commit", {"episodes": counts})
                verify_identity(self.source_state, snapshot["identity"])
                if get_index_identity(self.sink_client, self.episodes_index) != binding["episodes"]:
                    raise EpisodeError("Episode sink changed before projection commit")
            self.fault_hook("after_commit", {"episodes": counts})
            delivered += self._deliver(connection, binding)
            return {"ok": True, "status": "projected", "evaluated_at": format_timestamp(now),
                    "episodes": counts, "outbox_delivered": delivered,
                    "pending_outbox": connection.execute("SELECT count(*) FROM episode_outbox").fetchone()[0],
                    "source_checkpoints": snapshot["checkpoints"], "source_alerts": len(snapshot["alerts"]),
                    "recomputation": recomputation}

    def status(self):
        """Read-only local projection status; never contacts Elasticsearch."""
        if not self.state_path.exists():
            return {"initialized": False, "pending_outbox": 0}
        try:
            with sqlite3.connect(self.state_path.as_uri() + "?mode=ro", uri=True) as connection:
                connection.execute("BEGIN")
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables != TABLES or connection.execute("PRAGMA user_version").fetchone()[0] != STATE_VERSION:
                    raise EpisodeError("Unknown episode state schema/version")
                binding = self._meta(connection, "binding")
                return {"initialized": binding is not None,
                        "source_scope_id": binding["source_scope_id"] if binding else None,
                        "pending_outbox": connection.execute("SELECT count(*) FROM episode_outbox").fetchone()[0],
                        "episodes": connection.execute("SELECT count(*) FROM episodes").fetchone()[0],
                        "observed_source_alerts": connection.execute("SELECT count(*) FROM episode_source_alerts").fetchone()[0],
                        "source_progress": self._meta(connection, "source_progress"),
                        "last_run_at": self._meta(connection, "last_clock")}
        except sqlite3.DatabaseError as exc:
            raise EpisodeError("Cannot read episode state; no reset was attempted") from exc
