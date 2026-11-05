"""Bounded, durable Windows auth file ingestion for the local pipelines.

Publish immutable files atomically: write a .tmp file in the spool, fsync/close
it, then rename to a unique *.ready.jsonl or *.ready.xml name on the same local
filesystem. JSONL contains normalized Windows 4624/4625 events; XML is
one native Windows Event export. Files are never deleted or moved by this tool.
The default auth-v1 backend is unchanged; profile="auth-v2" explicitly selects
the separate date_nanos index and cannot reuse a ledger bound to auth-v1.

The SQLite ledger binds a source directory to one concrete index UUID and exact
mapping profile. It stores filenames, SHA256, counters and error codes, not event
payloads or credentials. A Linux flock on a sibling lock file excludes concurrent
users of this state database. Use a local filesystem with reliable flock/SQLite
semantics; coordinating different state databases is outside this lock's scope.

Only complete successful ingest_events calls are acknowledged. A crash after an
Elasticsearch write but before acknowledgment is safe to retry using event.id.
Malformed/conflicting/modified published files are quarantined in the ledger,
not moved on disk. Publish corrections under a new name and remove the bad ready
file from the input directory explicitly. Transient ingestion failures remain
pending for retry. Default fail-fast behavior raises with a structured summary;
continuation mode still returns ok=false while unresolved ready files remain.

Each scan is bounded by file count, file bytes and aggregate bytes. The persisted
round-robin filename cursor prevents retained acknowledged files from starving
new input. Acknowledged files are rehashed when visited, detecting later mutation.
No scan/watch success claims a Windows collection agent has been deployed.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
from typing import Callable
import xml.etree.ElementTree as ET

try:
    from tools.elastic_adapter import (
        ElasticClient, ElasticError, ElasticHTTPError, MAPPING_PATH, PROFILE,
        check_profile, get_index_identity, index_path, ingest_events,
    )
    from tools.hunt_engine import HuntError, prepare_events, read_jsonl
    from tools.normalize_windows_auth import normalize_event
    from tools import elastic_rolling
except ModuleNotFoundError:  # Imported by a directly invoked tools/* script.
    from elastic_adapter import (
        ElasticClient, ElasticError, ElasticHTTPError, MAPPING_PATH, PROFILE,
        check_profile, get_index_identity, index_path, ingest_events,
    )
    from hunt_engine import HuntError, prepare_events, read_jsonl
    from normalize_windows_auth import normalize_event
    import elastic_rolling


class SpoolError(ValueError):
    """Fatal configuration, state or identity error; stop claiming progress."""


class SpoolFileError(SpoolError):
    def __init__(self, summary: dict):
        self.summary = summary
        super().__init__("Spool contains failed or quarantined input; inspect failed_files and ledger error codes")


class _InvalidInput(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _ScanLimit(Exception):
    """The next immutable snapshot fits a file limit but not this scan's budget."""


def _positive_int(name: str, value: int) -> None:
    if type(value) is not int or value < 1:
        raise SpoolError(f"{name} must be a positive integer")


def _stamp(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _ready(name: str) -> bool:
    return name.endswith((".ready.jsonl", ".ready.xml"))


class SpoolImporter:
    def __init__(self, client: ElasticClient, index: str, source_dir: str | Path,
                 state_path: str | Path, *, max_files: int = 100,
                 max_file_bytes: int = 16 * 1024 * 1024,
                 max_scan_bytes: int = 64 * 1024 * 1024,
                 max_events: int = 100_000, fail_fast: bool = True,
                 profile: str = "auth-v1"):
        index_path(index)  # Reject wildcard/alias-like/system names before state changes.
        if profile not in ("auth-v1", "auth-v2"):
            raise SpoolError("profile must be auth-v1 or auth-v2")
        self.profile = profile
        for name, value in (("max_files", max_files), ("max_file_bytes", max_file_bytes),
                            ("max_scan_bytes", max_scan_bytes), ("max_events", max_events)):
            _positive_int(name, value)
        if max_scan_bytes < max_file_bytes:
            raise SpoolError("max_scan_bytes must be at least max_file_bytes")
        if type(fail_fast) is not bool:
            raise SpoolError("fail_fast must be boolean")
        source = Path(source_dir).absolute()
        if source.is_symlink() or not source.is_dir():
            raise SpoolError("source_dir must be an existing nonsymlink directory")
        self.source_dir = source.resolve()
        self.state_path = Path(state_path).absolute()
        if self.state_path.is_symlink():
            raise SpoolError("state_path must not be a symlink")
        self.state_path = self.state_path.resolve()
        self.client, self.index = client, index
        self.max_files, self.max_file_bytes = max_files, max_file_bytes
        self.max_scan_bytes, self.max_events = max_scan_bytes, max_events
        self.fail_fast = fail_fast
        self.db: sqlite3.Connection | None = None
        self._lock_fd: int | None = None
        self._source_fd: int | None = None
        self._binding: dict | None = None

    def __enter__(self) -> "SpoolImporter":
        self.open()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def open(self) -> None:
        if self.db is not None:
            raise SpoolError("SpoolImporter is already open")
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            lock_path = self.state_path.with_name(self.state_path.name + ".lock")
            self._lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            if not stat.S_ISREG(os.fstat(self._lock_fd).st_mode):
                raise SpoolError("state lock must be a regular file")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SpoolError("spool state is already locked by another importer") from exc
            # Refuse a symlink/nonregular database before SQLite can follow it.
            fd = os.open(self.state_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise SpoolError("state database must be a regular file")
            finally:
                os.close(fd)
            self.db = sqlite3.connect(self.state_path, timeout=1)
            self.db.row_factory = sqlite3.Row
            tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {"spool_meta", "spool_files"}:
                raise SpoolError("Unknown SQLite spool state schema; refusing to modify it")
            self._source_fd = os.open(self.source_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            binding = self._current_binding()
            previous = self._meta("binding") if tables else None
            if previous is not None and json.loads(previous) != binding:
                raise SpoolError("state belongs to a different source directory, index UUID or mapping profile")
            if tables and previous is None and self.db.execute("SELECT 1 FROM spool_files LIMIT 1").fetchone():
                raise SpoolError("Nonempty spool state has no binding; refusing to adopt it")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS spool_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.db.execute("""CREATE TABLE IF NOT EXISTS spool_files (
                    name TEXT PRIMARY KEY, sha256 TEXT, size_bytes INTEGER,
                    state TEXT NOT NULL CHECK(state IN ('pending','acked','quarantined')),
                    attempts INTEGER NOT NULL DEFAULT 0, error_code TEXT,
                    event_count INTEGER, inserted_events INTEGER, existing_events INTEGER,
                    file_stamp TEXT
                )""")
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(spool_files)")}
                if "file_stamp" not in columns:
                    # Earlier local spool state has no stat cache; it must be
                    # rehashed once before it can be considered fully drained.
                    self.db.execute("ALTER TABLE spool_files ADD COLUMN file_stamp TEXT")
            if previous is None:
                with self.db:
                    self.db.execute("INSERT INTO spool_meta(key,value) VALUES('binding',?)", (json.dumps(binding, sort_keys=True),))
            self._binding = binding
        except (sqlite3.Error, OSError) as exc:
            self.close()
            raise SpoolError(f"Cannot open spool state/source: {type(exc).__name__}") from exc
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._source_fd is not None:
            os.close(self._source_fd)
            self._source_fd = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # Closing releases flock, including after exceptions.
            self._lock_fd = None

    def _meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM spool_meta WHERE key=?", (key,)).fetchone()
        return None if row is None else row[0]

    def _current_binding(self) -> dict:
        # Keep the v1 module-level functions as the default integration seam;
        # choosing v2 is local to this importer, never a global adapter patch.
        checker = elastic_rolling.check_profile if self.profile == "auth-v2" else check_profile
        mapping_path = elastic_rolling.MAPPING_PATH if self.profile == "auth-v2" else MAPPING_PATH
        profile_name = elastic_rolling.PROFILE if self.profile == "auth-v2" else PROFILE
        try:
            checker(self.client, self.index)
            identity = get_index_identity(self.client, self.index)
        except ElasticError as exc:
            raise SpoolError(f"Cannot verify source index identity/profile: {type(exc).__name__}") from exc
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))["mappings"]
        return {"schema_version": 1, "source_dir": str(self.source_dir),
                "index": identity["name"], "index_uuid": identity["uuid"], "profile": profile_name,
                "profile_sha256": hashlib.sha256(json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}

    def _verify_binding(self) -> None:
        if self._current_binding() != self._binding:
            raise SpoolError("source index UUID or mapping profile changed; ingestion state cannot be reused")
        current = self.source_dir.stat()
        opened = os.fstat(self._source_fd)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise SpoolError("source directory was replaced while importer was open")

    def _read(self, name: str, summary: dict) -> tuple[bytes, tuple]:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._source_fd)
        except OSError as exc:
            raise _InvalidInput("unreadable_or_symlink") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _InvalidInput("nonregular_file")
            if info.st_size > self.max_file_bytes:
                raise _InvalidInput("file_too_large")
            if info.st_size > self.max_scan_bytes - summary["bytes_read"]:
                raise _ScanLimit
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(info.st_size)
            summary["bytes_read"] += len(data)
            if len(data) != info.st_size or _stamp(info) != _stamp(os.fstat(fd)) or not self._unchanged(name, _stamp(info)):
                raise _InvalidInput("file_changed_during_read")
            return data, _stamp(info)
        finally:
            os.close(fd)

    def _unchanged(self, name: str, expected: tuple) -> bool:
        try:
            info = os.stat(name, dir_fd=self._source_fd, follow_symlinks=False)
            return stat.S_ISREG(info.st_mode) and _stamp(info) == expected
        except OSError:
            return False

    def _decode(self, name: str, data: bytes) -> list[dict]:
        if not data.strip():
            raise _InvalidInput("empty_file")
        try:
            if name.endswith(".ready.xml"):
                events = [normalize_event(data.decode("utf-8-sig"))]
            else:
                if sum(bool(line.strip()) for line in data.splitlines()) > self.max_events:
                    raise _InvalidInput("too_many_events")
                # Parse exactly the hashed snapshot, with the shared strict reader.
                # NamedTemporaryFile is 0600 and removes this ephemeral copy on exit.
                with tempfile.NamedTemporaryFile(suffix=".jsonl") as snapshot:
                    snapshot.write(data)
                    snapshot.flush()
                    events = read_jsonl(snapshot.name)
            if not events:
                raise _InvalidInput("empty_file")
            normalized, _ = prepare_events(events)
            if any(event["event.dataset"] != "windows.security.logons" or
                   event.get("event.code") not in {"4624", "4625"} for event in normalized):
                raise _InvalidInput("unsupported_auth_source")
            return events
        except _InvalidInput:
            raise
        except (HuntError, ValueError, UnicodeError, ET.ParseError, TypeError) as exc:
            raise _InvalidInput("malformed_events") from exc

    def _error(self, name: str, code: str, *, transient: bool = False) -> None:
        state = "pending" if transient else "quarantined"
        with self.db:
            self.db.execute("""INSERT INTO spool_files(name,state,error_code) VALUES(?,?,?)
                ON CONFLICT(name) DO UPDATE SET state=excluded.state,error_code=excluded.error_code""", (name, state, code))

    def _process(self, name: str, summary: dict) -> None:
        data, stamp = self._read(name, summary)
        digest = hashlib.sha256(data).hexdigest()
        existing = self.db.execute("SELECT * FROM spool_files WHERE name=?", (name,)).fetchone()
        if existing is not None and existing["sha256"] is not None and existing["sha256"] != digest:
            raise _InvalidInput("immutable_file_changed")
        if existing is not None and existing["state"] == "acked":
            with self.db:
                self.db.execute("UPDATE spool_files SET file_stamp=? WHERE name=?", (json.dumps(stamp), name))
            summary["files_existing"] += 1
            return
        if existing is not None and existing["state"] == "quarantined":
            raise _InvalidInput(existing["error_code"] or "quarantined_file")
        with self.db:
            self.db.execute("""INSERT INTO spool_files(name,sha256,size_bytes,state,file_stamp) VALUES(?,?,?,'pending',?)
                ON CONFLICT(name) DO UPDATE SET sha256=excluded.sha256,size_bytes=excluded.size_bytes,
                file_stamp=excluded.file_stamp""", (name, digest, len(data), json.dumps(stamp)))
        events = self._decode(name, data)
        with self.db:
            self.db.execute("UPDATE spool_files SET attempts=attempts+1,error_code=NULL WHERE name=?", (name,))
        try:
            ingest = elastic_rolling.ingest_events if self.profile == "auth-v2" else ingest_events
            result = ingest(self.client, self.index, events)
        except ElasticHTTPError as exc:
            # A retried HTTP operation may have performed a partial write. IDs
            # make retry safe; HTTP authorization/availability must be repaired.
            self._error(name, f"http_{exc.status}", transient=True)
            raise _InvalidInput(f"http_{exc.status}") from exc
        except ElasticError as exc:
            if str(exc).startswith("Conflicting"):
                raise _InvalidInput("source_event_conflict") from exc
            if str(exc).startswith(("auth-v1", "auth-v2", "event.id")):
                raise _InvalidInput("invalid_auth_fields") from exc
            self._error(name, "ingest_failed", transient=True)
            raise _InvalidInput("ingest_failed") from exc
        self._verify_binding()
        if not self._unchanged(name, stamp):
            raise _InvalidInput("file_changed_during_ingest")
        # This transaction is the only acknowledgment point. It follows the
        # complete remote operation; a process death before it leaves pending.
        with self.db:
            self.db.execute("""UPDATE spool_files SET state='acked',error_code=NULL,
                event_count=?,inserted_events=?,existing_events=? WHERE name=?""",
                (result["unique_events"], result["inserted_events"], result["existing_events"], name))
        summary["files_acked"] += 1
        summary["events_inserted"] += result["inserted_events"]
        summary["events_existing"] += result["existing_events"]

    def scan_once(self) -> dict:
        """Process one bounded scan, retaining storage errors as structured failures.

        unacknowledged_files includes unvisited ready names, pending and
        quarantined files, but excludes retained acknowledged files. A caller
        that advances event-time checkpoints should drain that known backlog
        before evaluating closed windows.
        """
        try:
            return self._scan_once()
        except (sqlite3.Error, OSError) as exc:
            raise SpoolError(f"Spool state/source operation failed: {type(exc).__name__}") from exc

    def _scan_once(self) -> dict:
        if self.db is None:
            raise SpoolError("Use SpoolImporter as an open context manager")
        self._verify_binding()
        names = sorted(entry.name for entry in os.scandir(self.source_dir) if _ready(entry.name))
        cursor = self._meta("cursor") or ""
        ordered = [name for name in names if name > cursor] + [name for name in names if name <= cursor]
        summary = {"ok": True, "files_seen": len(names), "files_checked": 0,
                   "files_acked": 0, "files_existing": 0, "events_inserted": 0,
                   "events_existing": 0, "bytes_read": 0, "failed_files": [],
                   "deferred_files": 0, "unresolved_files": 0, "unacknowledged_files": 0}
        for name in ordered[:self.max_files]:
            try:
                info = os.stat(name, dir_fd=self._source_fd, follow_symlinks=False)
                anticipated = info.st_size if stat.S_ISREG(info.st_mode) else 0
                if anticipated <= self.max_file_bytes and summary["bytes_read"] + anticipated > self.max_scan_bytes:
                    break
            except OSError:
                pass  # The safe opener records an explicit failure below.
            summary["files_checked"] += 1
            advance_cursor = True
            try:
                self._process(name, summary)
            except _ScanLimit:
                advance_cursor = False
                summary["files_checked"] -= 1
                break
            except _InvalidInput as exc:
                row = self.db.execute("SELECT state,error_code FROM spool_files WHERE name=?", (name,)).fetchone()
                transient = row is not None and row["state"] == "pending" and row["error_code"] == exc.code
                self._error(name, exc.code, transient=transient)
                summary["failed_files"].append({"name": name, "code": exc.code})
            finally:
                # Do not advance past a file deferred solely by the byte limit.
                if advance_cursor:
                    with self.db:
                        self.db.execute("INSERT INTO spool_meta(key,value) VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name,))
            if summary["failed_files"] and self.fail_fast:
                break
        present = set(names)
        summary["unresolved_files"] = sum(
            row["name"] in present for row in self.db.execute("SELECT name FROM spool_files WHERE error_code IS NOT NULL")
        )
        summary["deferred_files"] = len(names) - summary["files_checked"]
        acknowledged = {row["name"]: row["file_stamp"] for row in self.db.execute(
            "SELECT name,file_stamp FROM spool_files WHERE state='acked'")}
        for name in names:
            try:
                info = os.stat(name, dir_fd=self._source_fd, follow_symlinks=False)
                unchanged_ack = (name in acknowledged and stat.S_ISREG(info.st_mode)
                                 and acknowledged[name] == json.dumps(_stamp(info)))
            except OSError:
                unchanged_ack = False
            if not unchanged_ack:
                summary["unacknowledged_files"] += 1
        summary["ok"] = not summary["failed_files"] and summary["unresolved_files"] == 0
        if not summary["ok"] and self.fail_fast:
            raise SpoolFileError(summary)
        return summary

    def watch(self, stop_event: threading.Event, *, poll_seconds: float = 5,
              on_result: Callable[[dict], None] | None = None) -> None:
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)) or not math.isfinite(poll_seconds) or poll_seconds <= 0:
            raise SpoolError("poll_seconds must be positive and finite")
        while not stop_event.is_set():
            result = self.scan_once()
            if on_result is not None:
                on_result(result)
            if stop_event.wait(poll_seconds):
                break
