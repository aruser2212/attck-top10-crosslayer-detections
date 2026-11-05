"""Complete, immutable source snapshots for the episode projection."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from tools.detection_runner import canonical, fingerprint
from tools.episode_engine import EpisodeError
from tools import episode_source as source
from tools.hunt_engine import parse_timestamp
from tools.rolling_runner import epoch_microseconds


RULE = "a" * 64
INITIAL = "2026-01-01T00:00:00Z"
CLOCK = "2026-01-01T00:12:00Z"
ANCHOR = "2026-01-01T00:05:01.000001Z"


def micros(value):
    return epoch_microseconds(parse_timestamp(value))


@pytest.fixture
def ledger(tmp_path):
    path = tmp_path / "rolling.sqlite"
    binding = {"state_version": 2, "time_unit": "microseconds", "adapter_profile": "attck-auth-v2",
               "source": {"name": "auth-source", "uuid": "source-uuid"},
               "alerts": {"name": "auth-alerts", "uuid": "alerts-uuid"},
               "rule_ids": [RULE], "initial_start": INITIAL,
               "lookback_microseconds": 1_800_000_000, "allowed_lateness_microseconds": 120_000_000}
    scope = fingerprint(binding)
    group = {"source.ip": "192.0.2.1", "target.user": "домен\\alice"}
    identifier = fingerprint({"scope": scope, "rule": RULE, "anchor_microseconds": micros(ANCHOR), "group": group})
    payload = {"@timestamp": ANCHOR, "alert_id": identifier, "scope_id": scope, "rule_id": RULE,
               "status": "active", "revision": 1, "first_detected_at": CLOCK, "updated_at": CLOCK,
               "source_index": "auth-source", "source_index_uuid": "source-uuid",
               "window": {"start": "2026-01-01T00:00:01.000001Z", "end": ANCHOR},
               "group": group, "metrics": {"fails": 10}}
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            PRAGMA user_version=2;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE checkpoints (rule_id TEXT PRIMARY KEY, watermark INTEGER NOT NULL);
            CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL,
                window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE outbox (alert_id TEXT PRIMARY KEY REFERENCES alerts(alert_id),
                payload TEXT NOT NULL, revision INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT);
        """)
        db.executemany("INSERT INTO metadata VALUES (?,?)", [("binding", canonical(binding)), ("last_clock", CLOCK)])
        db.execute("INSERT INTO checkpoints VALUES (?,?)", (RULE, micros("2026-01-01T00:10:00Z")))
        db.execute("INSERT INTO alerts VALUES (?,?,?,?,?)", (identifier, RULE, micros(payload["window"]["start"]),
                   micros(ANCHOR), canonical(payload)))
    return path, binding, payload


def rewrite_alert(path, payload):
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alerts SET payload=?", (canonical(payload),))


def test_complete_snapshot_preserves_raw_precision_and_is_read_only(ledger):
    path, binding, payload = ledger
    before = path.read_bytes()
    result = source.read_snapshot(path)
    assert result["binding"] == binding
    assert result["source_scope_id"] == fingerprint(binding)
    assert result["alerts"] == [payload]
    assert result["checkpoints"] == {RULE: micros("2026-01-01T00:10:00Z")}
    assert result["last_clock"] == CLOCK and result["pending_outbox"] == 0
    assert result["identity"] == {"path": str(path), "device": path.stat().st_dev, "inode": path.stat().st_ino}
    expected = len(canonical(binding).encode()) + len(CLOCK.encode()) + len(canonical(payload).encode())
    assert result["payload_bytes"] == expected
    assert path.read_bytes() == before


def test_snapshot_includes_retracted_rows_and_consistent_pending_outbox(ledger):
    path, _, payload = ledger
    payload.update(status="retracted", revision=2)
    rewrite_alert(path, payload)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)", (payload["alert_id"], canonical(payload), 2, 3, "ElasticError"))
    result = source.read_snapshot(path)
    assert result["alerts"] == [payload]
    assert result["pending_outbox"] == 1
    # This reader returns pending state; the episode runner controls projection.


def test_row_cap_includes_retracted_history(ledger):
    path, _, payload = ledger
    other = deepcopy(payload)
    other["group"]["target.user"] = "bob"
    other["status"] = "retracted"
    other["alert_id"] = fingerprint({"scope": other["scope_id"], "rule": RULE,
                                      "anchor_microseconds": micros(ANCHOR), "group": other["group"]})
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO alerts VALUES (?,?,?,?,?)", (other["alert_id"], RULE,
                   micros(other["window"]["start"]), micros(ANCHOR), canonical(other)))
    with pytest.raises(EpisodeError, match="max_alerts"):
        source.read_snapshot(path, max_alerts=1)
    assert len(source.read_snapshot(path, max_alerts=2)["alerts"]) == 2


def test_exact_byte_cap_counts_utf8_metadata_and_pending_retry_payloads(ledger):
    path, binding, payload = ledger
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)", (payload["alert_id"], canonical(payload), 1, 0, None))
    size = len(canonical(binding).encode()) + len(CLOCK.encode()) + 2 * len(canonical(payload).encode())
    assert source.read_snapshot(path, max_bytes=size)["payload_bytes"] == size
    with pytest.raises(EpisodeError, match="max_bytes"):
        source.read_snapshot(path, max_bytes=size - 1)


@pytest.mark.parametrize("changes", [{"max_alerts": 0}, {"max_alerts": True}, {"max_bytes": 0}, {"max_bytes": 1.5}])
def test_invalid_limits_reject_before_opening_missing_source(tmp_path, changes):
    with pytest.raises(EpisodeError, match="integer"):
        source.read_snapshot(tmp_path / "absent.sqlite", **changes)
    assert not list(tmp_path.iterdir())


def test_missing_symlink_and_directory_are_not_adopted(tmp_path, ledger):
    path, _, _ = ledger
    link = tmp_path / "linked.sqlite"
    link.symlink_to(path)
    for candidate in (tmp_path / "missing.sqlite", link, tmp_path):
        with pytest.raises(EpisodeError):
            source.read_snapshot(candidate)
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.parametrize("schema", ["PRAGMA user_version=1", "CREATE TABLE extra(value TEXT)",
                                    "ALTER TABLE alerts ADD COLUMN extra TEXT"])
def test_foreign_schema_and_v1_are_preserved_without_migration(ledger, schema):
    path, _, _ = ledger
    with sqlite3.connect(path) as db:
        db.execute(schema)
    before = path.read_bytes()
    with pytest.raises(EpisodeError, match="source|schema"):
        source.read_snapshot(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("statement", ["DELETE FROM metadata WHERE key='last_clock'",
                                      "INSERT INTO metadata VALUES ('unknown','x')",
                                      "DELETE FROM checkpoints",
                                      "UPDATE checkpoints SET watermark=0"])
def test_incomplete_metadata_or_checkpoints_fail(ledger, statement):
    path, _, _ = ledger
    with sqlite3.connect(path) as db:
        db.execute(statement)
    with pytest.raises(EpisodeError):
        source.read_snapshot(path)


@pytest.mark.parametrize("field,value", [("state_version", 1), ("time_unit", "seconds"),
                                        ("adapter_profile", "attck-auth-v1"),
                                        ("rule_ids", [RULE, RULE]), ("lookback_microseconds", True),
                                        ("initial_start", "2026-01-01T01:00:00+01:00")])
def test_binding_contract_is_not_coerced(ledger, field, value):
    path, binding, _ = ledger
    binding[field] = value
    with sqlite3.connect(path) as db:
        db.execute("UPDATE metadata SET value=? WHERE key='binding'", (canonical(binding),))
    with pytest.raises(EpisodeError):
        source.read_snapshot(path)


@pytest.mark.parametrize("field,value", [("revision", True), ("revision", 0), ("status", "closed"),
                                        ("scope_id", "b" * 64), ("source_index_uuid", "wrong"),
                                        ("alert_id", "c" * 64), ("metrics", {"fails": 1.5}),
                                        ("group", {"source.ip": 1}),
                                        ("updated_at", "2026-01-01T00:13:00Z"),
                                        ("first_detected_at", "2026-01-01T00:01:00Z"),
                                        ("@timestamp", "2026-01-01T00:05:01.000002Z")])
def test_inconsistent_alert_payload_is_rejected(ledger, field, value):
    path, _, payload = ledger
    payload[field] = value
    rewrite_alert(path, payload)
    with pytest.raises(EpisodeError):
        source.read_snapshot(path)


def test_anchor_equal_to_checkpoint_is_not_claimed_processed(ledger):
    path, _, _ = ledger
    with sqlite3.connect(path) as db:
        db.execute("UPDATE checkpoints SET watermark=?", (micros(ANCHOR),))
    with pytest.raises(EpisodeError, match="anchor"):
        source.read_snapshot(path)


@pytest.mark.parametrize("field", ["window_start", "window_end"])
def test_raw_row_columns_must_match_payload_exactly(ledger, field):
    path, _, _ = ledger
    with sqlite3.connect(path) as db:
        db.execute(f"UPDATE alerts SET {field}={field}+1")
    with pytest.raises(EpisodeError, match="anchor"):
        source.read_snapshot(path)


def test_subsecond_window_duration_is_not_a_valid_rolling_rule_window(ledger):
    path, _, payload = ledger
    payload["window"]["start"] = "2026-01-01T00:00:01Z"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alerts SET window_start=?,payload=?", (micros(payload["window"]["start"]), canonical(payload)))
    with pytest.raises(EpisodeError, match="window|anchor"):
        source.read_snapshot(path)


@pytest.mark.parametrize("text", ['{"revision":1,"revision":2}', '{"revision":NaN}', '{broken'])
def test_duplicate_or_invalid_json_is_not_silently_normalized(ledger, text):
    path, _, _ = ledger
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alerts SET payload=?", (text,))
    with pytest.raises(EpisodeError, match="JSON"):
        source.read_snapshot(path)


@pytest.mark.parametrize("corruption", ["revision", "payload", "orphan", "attempts"])
def test_inconsistent_pending_outbox_fails_whole_snapshot(ledger, corruption):
    path, _, payload = ledger
    retry = deepcopy(payload)
    if corruption == "payload":
        retry["metrics"]["fails"] = 11
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO outbox VALUES (?,?,?,?,?)", (
            "f" * 64 if corruption == "orphan" else payload["alert_id"], canonical(retry),
            2 if corruption == "revision" else 1, -1 if corruption == "attempts" else 0, None))
    with pytest.raises(EpisodeError, match="outbox"):
        source.read_snapshot(path)


def test_identity_guard_rejects_replacement_at_same_path(ledger):
    path, _, _ = ledger
    identity = source.read_snapshot(path)["identity"]
    replacement = path.with_name("replacement.sqlite")
    replacement.write_bytes(path.read_bytes())
    replacement.replace(path)
    with pytest.raises(EpisodeError, match="replaced"):
        source.verify_identity(path, identity)


def test_replacement_during_snapshot_is_rejected(ledger, monkeypatch):
    path, _, _ = ledger
    verify = source.verify_identity

    def replace_then_verify(candidate, identity):
        replacement = path.with_name("replacement.sqlite")
        replacement.write_bytes(b"replacement")
        replacement.replace(path)
        verify(candidate, identity)

    monkeypatch.setattr(source, "verify_identity", replace_then_verify)
    with pytest.raises(EpisodeError, match="replaced"):
        source.read_snapshot(path)


def test_one_wal_snapshot_cannot_mix_concurrent_committed_revisions(ledger, monkeypatch):
    path, _, payload = ledger
    real_connect = sqlite3.connect
    changed = False

    class Connection:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        @property
        def row_factory(self):
            return self.wrapped.row_factory

        @row_factory.setter
        def row_factory(self, value):
            self.wrapped.row_factory = value

        def execute(self, sql, *args):
            nonlocal changed
            if sql == "SELECT count(*) FROM alerts" and not changed:
                changed = True
                revised = deepcopy(payload)
                revised.update(revision=2, status="retracted", updated_at="2026-01-01T00:13:00Z")
                with real_connect(path) as writer:
                    writer.execute("UPDATE alerts SET payload=?", (canonical(revised),))
                    writer.execute("UPDATE metadata SET value=? WHERE key='last_clock'", (revised["updated_at"],))
            return self.wrapped.execute(sql, *args)

        def close(self):
            return self.wrapped.close()

    monkeypatch.setattr(source.sqlite3, "connect", lambda *args, **kwargs: Connection(real_connect(*args, **kwargs)))
    before = source.read_snapshot(path)
    after = source.read_snapshot(path)
    assert before["last_clock"] == CLOCK and before["alerts"] == [payload]
    assert after["last_clock"] == "2026-01-01T00:13:00Z"
    assert after["alerts"][0]["revision"] == 2 and after["alerts"][0]["status"] == "retracted"


def test_actual_rolling_runner_state_is_accepted_without_network(tmp_path):
    # Produce the schema through the real runner, with deterministic transport
    # and evaluator seams; this guards against drift in the read-only adapter.
    from tools.elastic_rolling import MAPPING_PATH
    from tools.elastic_adapter import ElasticHTTPError
    from tools.rolling_runner import RollingDetectionRunner, DEFAULT_RULES

    class Transport:
        def __init__(self):
            self.mappings = {"auth-source": json.loads(MAPPING_PATH.read_text())["mappings"]}

        def request(self, method, path, body=None):
            index = path.split("/")[1]
            if path.endswith("/_mapping"):
                if index not in self.mappings:
                    raise ElasticHTTPError(404, "absent")
                return {index: {"mappings": self.mappings[index]}}
            if path.endswith("/_settings?flat_settings=true"):
                return {index: {"settings": {"index.uuid": index + "-uuid"}}}
            if method == "PUT" and "/_doc/" not in path:
                self.mappings[index] = body["mappings"]
                return {"acknowledged": True}
            if method == "PUT":
                return {"_id": body["alert_id"], "_index": index, "_version": body["revision"],
                        "result": "created", "_shards": {"failed": 0}}
            raise AssertionError((method, path))

    candidate = {"window.start": "2026-01-01T00:00:01.000001Z", "window.end": ANCHOR,
                 "source.ip": "192.0.2.1", "target.user": "alice", "fails": 10}
    runner = RollingDetectionRunner(source_client=Transport(), source_index="auth-source", alerts_index="auth-alerts",
                                    state_path=tmp_path / "real.sqlite", rule_paths=DEFAULT_RULES[:1],
                                    initial_start=INITIAL, initialize_alerts=True,
                                    clock=lambda: parse_timestamp(CLOCK), evaluator=lambda *_args, **_kwargs: {"alerts": [candidate]})
    runner.run_once()
    snapshot = source.read_snapshot(runner.state_path)
    assert len(snapshot["alerts"]) == 1 and snapshot["alerts"][0]["window"]["end"] == ANCHOR
    assert snapshot["pending_outbox"] == 0
