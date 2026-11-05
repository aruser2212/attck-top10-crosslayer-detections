"""Durable spool tests use the real importer and ingestion code with a fake transport."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading

import pytest

from tools.elastic_adapter import ElasticError, MAPPING_PATH
from tools.ingest_spool import SpoolError, SpoolFileError, SpoolImporter

INDEX = "auth-spool-test"
XML = (Path(__file__).parent / "fixtures/windows/4625.xml").read_text()


class CrashAfterWrite(BaseException):
    pass


class FakeClient:
    """Emulate mapping/settings/mget/create; preserve actual ingestion semantics."""
    def __init__(self):
        self.uuid = "source-index-uuid"
        self.mapping = json.loads(MAPPING_PATH.read_text())["mappings"]
        self.events = {}
        self.calls = []
        self.after_write = None
        self.before_bulk = None
        self.ingest_error = None
        self.refresh_error = None

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        if path.endswith("/_mapping"):
            return {INDEX: {"mappings": deepcopy(self.mapping)}}
        if "/_settings" in path:
            return {INDEX: {"settings": {"index.uuid": self.uuid}}}
        if path.endswith("/_refresh"):
            if self.refresh_error:
                raise self.refresh_error
            return {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if path.endswith("/_mget"):
            if self.ingest_error:
                raise self.ingest_error
            return {"docs": [{"_id": identifier, "found": identifier in self.events,
                              **({"_source": deepcopy(self.events[identifier])} if identifier in self.events else {})}
                             for identifier in body["ids"]]}
        if "/_bulk" in path:
            if self.before_bulk:
                self.before_bulk()
            lines = body.splitlines()
            items = []
            for offset in range(0, len(lines), 2):
                identifier = json.loads(lines[offset])["create"]["_id"]
                status = 409 if identifier in self.events else 201
                if status == 201:
                    self.events[identifier] = json.loads(lines[offset + 1])
                items.append({"create": {"status": status}})
            if self.after_write:
                self.after_write()
            return {"errors": any(i["create"]["status"] != 201 for i in items), "items": items}
        raise AssertionError(f"Unexpected request: {method} {path}")


def event(identifier="one", **changes):
    return {"@timestamp": "2026-01-01T00:00:10Z", "event.id": identifier,
            "event.dataset": "windows.security.logons", "event.code": "4625",
            "source.ip": "192.0.2.1", "target.user": "lab\\alice", **changes}


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "inbox"
    source.mkdir()
    state = tmp_path / "state" / "spool.sqlite"
    return FakeClient(), source, state


def publish(source, name="a.ready.jsonl", events=None):
    path = source / name
    path.write_text("\n".join(json.dumps(e) for e in (events if events is not None else [event()])) + "\n")
    return path


def ledger(path):
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        return {row["name"]: dict(row) for row in db.execute("SELECT * FROM spool_files")}


def test_ingest_ack_digest_and_repeat_scan(setup):
    client, source, state = setup
    path = publish(source, events=[event(), event()])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with SpoolImporter(client, INDEX, source, state) as importer:
        first = importer.scan_once()
        second = importer.scan_once()
    assert first["ok"] and first["files_acked"] == first["events_inserted"] == 1
    assert second["files_existing"] == 1 and second["events_inserted"] == 0
    assert first["unacknowledged_files"] == second["unacknowledged_files"] == 0
    assert ledger(state)[path.name]["state"] == "acked"
    assert ledger(state)[path.name]["sha256"] == digest
    assert path.is_file()  # Retention is the producer/operator's responsibility.
    assert len(client.events) == 1


def test_second_filename_same_events_is_idempotent(setup):
    client, source, state = setup
    publish(source)
    with SpoolImporter(client, INDEX, source, state) as importer:
        importer.scan_once()
        publish(source, "b.ready.jsonl")
        result = importer.scan_once()
    assert result["events_inserted"] == 0 and result["events_existing"] == 1
    assert all(row["state"] == "acked" for row in ledger(state).values())


def test_crash_after_elastic_write_before_ack_is_safe_to_retry(setup):
    client, source, state = setup
    publish(source)
    def crash():
        raise CrashAfterWrite
    client.after_write = crash
    with pytest.raises(CrashAfterWrite):
        with SpoolImporter(client, INDEX, source, state) as importer:
            importer.scan_once()
    assert len(client.events) == 1
    assert ledger(state)["a.ready.jsonl"]["state"] == "pending"
    client.after_write = None
    with SpoolImporter(client, INDEX, source, state) as importer:
        result = importer.scan_once()
    assert result["files_acked"] == 1 and result["events_existing"] == 1
    assert len(client.events) == 1
    assert ledger(state)["a.ready.jsonl"]["attempts"] == 2


def test_modified_acknowledged_filename_is_quarantined_without_rewriting_events(setup):
    client, source, state = setup
    path = publish(source)
    with SpoolImporter(client, INDEX, source, state) as importer:
        importer.scan_once()
        original = ledger(state)[path.name]["sha256"]
        publish(source, events=[event("different")])
        with pytest.raises(SpoolFileError) as error:
            importer.scan_once()
    assert error.value.summary["failed_files"] == [{"name": path.name, "code": "immutable_file_changed"}]
    assert ledger(state)[path.name]["sha256"] == original
    assert ledger(state)[path.name]["state"] == "quarantined"
    assert set(client.events) == {"one"}


@pytest.mark.parametrize("content", [b"", b" \n", b'{"event.id":"one","event.id":"two"}\n',
                                    b'{"event.id":\n', b"\xff\n", b"[]\n"])
def test_malformed_files_are_visible_and_never_acknowledged(setup, content):
    client, source, state = setup
    path = source / "broken.ready.jsonl"
    path.write_bytes(content)
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError) as error:
            importer.scan_once()
    assert not error.value.summary["ok"]
    assert ledger(state)[path.name]["state"] == "quarantined"
    assert client.events == {}
    assert not any("_bulk" in call[1] for call in client.calls)


def test_all_events_validated_before_first_write(setup):
    client, source, state = setup
    publish(source, events=[event("good"), {**event("bad"), "target.user": 42}])
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert client.events == {}
    assert ledger(state)["a.ready.jsonl"]["error_code"] == "invalid_auth_fields"


def test_source_conflict_is_quarantined_without_partial_file_writes(setup):
    client, source, state = setup
    client.events["one"] = event("one", **{"target.user": "lab\\bob"})
    publish(source, events=[event("new"), event("one")])
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert set(client.events) == {"one"}
    assert ledger(state)["a.ready.jsonl"]["error_code"] == "source_event_conflict"


def test_transient_failure_retries_pending_file(setup):
    client, source, state = setup
    publish(source)
    client.ingest_error = ElasticError("transport unavailable")
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
        assert ledger(state)["a.ready.jsonl"]["state"] == "pending"
        client.ingest_error = None
        assert importer.scan_once()["ok"]
    assert ledger(state)["a.ready.jsonl"]["state"] == "acked"


def test_refresh_failure_after_write_keeps_file_pending_until_searchable(setup):
    client, source, state = setup
    publish(source)
    client.refresh_error = ElasticError("refresh unavailable")
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
        assert len(client.events) == 1  # The write succeeded, visibility did not.
        assert ledger(state)["a.ready.jsonl"]["state"] == "pending"
        with pytest.raises(SpoolFileError):
            importer.scan_once()  # Existing IDs must still pass the refresh barrier.
        assert ledger(state)["a.ready.jsonl"]["state"] == "pending"
        client.refresh_error = None
        result = importer.scan_once()
    assert result["ok"] and result["events_existing"] == 1
    assert ledger(state)["a.ready.jsonl"]["state"] == "acked"
    assert len(client.events) == 1


def test_continue_mode_does_not_hide_quarantined_file(setup):
    client, source, state = setup
    (source / "a.ready.jsonl").write_text("broken\n")
    publish(source, "b.ready.jsonl")
    with SpoolImporter(client, INDEX, source, state, fail_fast=False) as importer:
        result = importer.scan_once()
        again = importer.scan_once()
    assert result["files_acked"] == 1 and result["unresolved_files"] == 1
    assert not result["ok"] and not again["ok"]
    assert client.events


def test_fail_fast_does_not_ingest_later_file(setup):
    client, source, state = setup
    (source / "a.ready.jsonl").write_text("broken\n")
    publish(source, "b.ready.jsonl")
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError) as error:
            importer.scan_once()
    assert error.value.summary["deferred_files"] == 1
    assert client.events == {}


def test_windows_xml_uses_real_normalizer(setup):
    client, source, state = setup
    path = source / "windows.ready.xml"
    path.write_text(XML)
    with SpoolImporter(client, INDEX, source, state) as importer:
        result = importer.scan_once()
    assert result["events_inserted"] == 1
    normalized = next(iter(client.events.values()))
    assert normalized["target.user"] == "lab\\alice"
    assert normalized["source.ip"] == "192.0.2.10"
    assert normalized["event.id"].startswith("windows-security:")


@pytest.mark.parametrize("content", ["<Events/>\n", "<!DOCTYPE Event><Event/>\n", "<broken"])
def test_xml_must_be_one_supported_native_event(setup, content):
    client, source, state = setup
    (source / "bad.ready.xml").write_text(content)
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert client.events == {}


def test_only_atomic_ready_names_are_consumed(setup):
    client, source, state = setup
    temporary = publish(source, "events.tmp")
    publish(source, "events.jsonl")
    with SpoolImporter(client, INDEX, source, state) as importer:
        assert importer.scan_once()["files_seen"] == 0
        temporary.rename(source / "events.ready.jsonl")
        assert importer.scan_once()["files_acked"] == 1


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_nonregular_and_symlink_input_rejected(setup, kind):
    client, source, state = setup
    path = source / "unsafe.ready.jsonl"
    if kind == "symlink":
        target = publish(source, "target.tmp")
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert client.events == {}
    assert ledger(state)[path.name]["state"] == "quarantined"


def test_file_modified_during_ingest_cannot_be_acked(setup):
    client, source, state = setup
    path = publish(source)
    client.before_bulk = lambda: path.write_text("changed while published\n")
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert ledger(state)[path.name]["state"] == "quarantined"
    assert ledger(state)[path.name]["error_code"] == "file_changed_during_ingest"


def test_index_replacement_between_write_and_ack_refuses_ack(setup):
    client, source, state = setup
    publish(source)
    client.after_write = lambda: setattr(client, "uuid", "replacement-index")
    with SpoolImporter(client, INDEX, source, state) as importer:
        with pytest.raises(SpoolError, match="UUID"):
            importer.scan_once()
    assert ledger(state)["a.ready.jsonl"]["state"] == "pending"


@pytest.mark.parametrize("change", ["directory", "uuid", "profile"])
def test_state_binding_rejects_changed_source_identity(setup, change, monkeypatch):
    client, source, state = setup
    with SpoolImporter(client, INDEX, source, state):
        pass
    if change == "directory":
        source = source.parent / "other"
        source.mkdir()
    elif change == "uuid":
        client.uuid = "another-uuid"
    else:
        import tools.ingest_spool as module
        monkeypatch.setattr(module, "PROFILE", "different-profile")
    with pytest.raises(SpoolError, match="different"):
        with SpoolImporter(client, INDEX, source, state):
            pass


def test_only_one_importer_can_own_state_lock(setup):
    client, source, state = setup
    with SpoolImporter(client, INDEX, source, state):
        with pytest.raises(SpoolError, match="locked"):
            with SpoolImporter(client, INDEX, source, state):
                pass
    # Failure and normal exit both release their descriptors.
    with SpoolImporter(client, INDEX, source, state):
        pass


def test_new_state_and_lock_permissions_are_private(setup):
    client, source, state = setup
    with SpoolImporter(client, INDEX, source, state):
        assert state.stat().st_mode & 0o777 == 0o600
        assert state.parent.stat().st_mode & 0o777 == 0o700
        assert state.with_name(state.name + ".lock").stat().st_mode & 0o777 == 0o600


def test_ledger_contains_no_event_payload_or_credentials(setup):
    client, source, state = setup
    secret = "sensitive-context-value-not-for-ledger"
    publish(source, events=[event(context=secret)])
    with SpoolImporter(client, INDEX, source, state) as importer:
        importer.scan_once()
    assert secret.encode() not in state.read_bytes()
    assert b"lab\\alice" not in state.read_bytes()


def test_persisted_cursor_prevents_retained_files_starving_backlog(setup):
    client, source, state = setup
    for name in ("a", "b", "c"):
        publish(source, name + ".ready.jsonl", [event(name)])
    for number, expected in enumerate(("a", "b", "c")):
        with SpoolImporter(client, INDEX, source, state, max_files=1) as importer:
            result = importer.scan_once()
        assert result["files_checked"] == result["files_acked"] == 1
        assert result["unacknowledged_files"] == 2 - number
        assert expected in client.events
    assert len(client.events) == 3


def test_acknowledged_retention_is_not_pending_backlog(setup):
    client, source, state = setup
    for name in ("a", "b", "c"):
        publish(source, name + ".ready.jsonl", [event(name)])
    with SpoolImporter(client, INDEX, source, state) as importer:
        assert importer.scan_once()["unacknowledged_files"] == 0
    with SpoolImporter(client, INDEX, source, state, max_files=1) as importer:
        result = importer.scan_once()
    assert result["deferred_files"] == 2
    assert result["unacknowledged_files"] == 0


def test_changed_acknowledged_file_blocks_backlog_before_hash_visit(setup):
    client, source, state = setup
    for name in ("a", "b", "c"):
        publish(source, name + ".ready.jsonl", [event(name)])
    with SpoolImporter(client, INDEX, source, state) as importer:
        importer.scan_once()
    # Change a retained file with equal-length content; next scan visits only a.
    publish(source, "c.ready.jsonl", [event("z")])
    with SpoolImporter(client, INDEX, source, state, max_files=1) as importer:
        result = importer.scan_once()
    assert result["files_existing"] == 1
    assert result["unacknowledged_files"] == 1
    assert set(client.events) == {"a", "b", "c"}


def test_corrupt_database_becomes_spool_error_and_releases_lock(setup):
    client, source, state = setup
    state.parent.mkdir()
    state.write_bytes(b"not a SQLite database")
    with pytest.raises(SpoolError, match="Cannot open") as error:
        with SpoolImporter(client, INDEX, source, state):
            pass
    assert isinstance(error.value.__cause__, sqlite3.DatabaseError)
    state.unlink()  # Test-owned damaged state only.
    with SpoolImporter(client, INDEX, source, state):
        pass


def test_sqlite_lock_failure_is_structured(setup):
    client, source, state = setup
    publish(source)
    with SpoolImporter(client, INDEX, source, state) as importer:
        with sqlite3.connect(state) as other:
            other.execute("BEGIN EXCLUSIVE")
            with pytest.raises(SpoolError, match="operation failed") as error:
                importer.scan_once()
            assert isinstance(error.value.__cause__, sqlite3.OperationalError)
        assert importer.scan_once()["files_acked"] == 1


def test_sqlite_write_failure_prevents_remote_ingestion(setup):
    client, source, state = setup
    publish(source)
    with SpoolImporter(client, INDEX, source, state) as importer:
        def deny_writes(action, *_args):
            return sqlite3.SQLITE_DENY if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE) else sqlite3.SQLITE_OK
        importer.db.set_authorizer(deny_writes)
        with pytest.raises(SpoolError, match="operation failed"):
            importer.scan_once()
    assert client.events == {}


def test_file_size_limit_quarantines_before_ingestion(setup):
    client, source, state = setup
    publish(source)
    with SpoolImporter(client, INDEX, source, state, max_file_bytes=10) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert ledger(state)["a.ready.jsonl"]["error_code"] == "file_too_large"
    assert client.events == {}


def test_scan_byte_limit_defers_without_starvation(setup):
    client, source, state = setup
    a = publish(source, "a.ready.jsonl", [event("a")])
    publish(source, "b.ready.jsonl", [event("b")])
    size = a.stat().st_size
    with SpoolImporter(client, INDEX, source, state, max_file_bytes=size, max_scan_bytes=size) as importer:
        first = importer.scan_once()
        second = importer.scan_once()
    assert first["bytes_read"] == second["bytes_read"] == size
    assert first["files_acked"] == second["files_acked"] == 1
    assert len(client.events) == 2


def test_event_count_is_bounded(setup):
    client, source, state = setup
    publish(source, events=[event("a"), event("b")])
    with SpoolImporter(client, INDEX, source, state, max_events=1) as importer:
        with pytest.raises(SpoolFileError):
            importer.scan_once()
    assert ledger(state)["a.ready.jsonl"]["error_code"] == "too_many_events"


def test_watch_uses_interruptible_event_wait(setup):
    client, source, state = setup
    publish(source)
    class StopAfterWait:
        stopped = False
        waits = []
        def is_set(self):
            return self.stopped
        def wait(self, seconds):
            self.waits.append(seconds)
            self.stopped = True
            return True
    stop = StopAfterWait()
    results = []
    with SpoolImporter(client, INDEX, source, state) as importer:
        importer.watch(stop, poll_seconds=17, on_result=results.append)
    assert stop.waits == [17] and len(results) == 1


def test_already_stopped_watch_does_not_scan(setup):
    client, source, state = setup
    stop = threading.Event()
    stop.set()
    with SpoolImporter(client, INDEX, source, state) as importer:
        before = len(client.calls)
        importer.watch(stop)
        assert len(client.calls) == before


@pytest.mark.parametrize("option,value", [("max_files", 0), ("max_files", True),
    ("max_events", -1), ("max_file_bytes", 0), ("max_scan_bytes", 1), ("fail_fast", "yes")])
def test_invalid_limits_fail_before_state_creation(setup, option, value):
    client, source, state = setup
    with pytest.raises(SpoolError):
        SpoolImporter(client, INDEX, source, state, **{option: value})
    assert not state.exists()
