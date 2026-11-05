"""Coherent evidence export, corruption detection and non-destructive publication."""
from copy import deepcopy
from datetime import timedelta
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from tests.test_episode_runner import events, setup
from tools import episode_archive as implementation
from tools.detection_runner import canonical, fingerprint
from tools.episode_archive import EpisodeError, create_archive, verify_archive
from tools.hunt_engine import parse_timestamp

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def ledgers(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    runner.run_once()
    return runner, raw, evaluator, client


def export(ledgers, tmp_path, **options):
    runner, raw, _, _ = ledgers
    path = tmp_path / "evidence.json"
    report = create_archive(raw.state_path, runner.state_path, path, **options)
    return path, report


def records(path):
    with sqlite3.connect(path) as db:
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall() for name in tables}


def rewrite(path, mutate, *, checksum=True):
    envelope = json.loads(path.read_text())
    mutate(envelope["content"])
    if checksum:
        envelope["sha256"] = fingerprint(envelope["content"])
    path.write_text(canonical(envelope) + "\n")


def test_round_trip_is_offline_and_preserves_both_ledgers(ledgers, tmp_path):
    runner, raw, _, client = ledgers
    before = records(raw.state_path), records(runner.state_path), deepcopy(client.documents)
    path, report = export(ledgers, tmp_path)
    assert report["verified"] and report["raw_alerts"] == report["current_episodes"] == 1
    assert report["pruning_applied"] is False
    assert path.stat().st_mode & 0o777 == 0o600
    assert before == (records(raw.state_path), records(runner.state_path), client.documents)
    # Offline validation must not dereference source paths or contact a sink.
    raw.state_path.unlink()
    runner.state_path.unlink()
    verified = verify_archive(path)
    assert verified == report


def test_empty_successfully_projected_history_can_be_archived(tmp_path):
    ledgers = setup(tmp_path, source=[])
    ledgers[0].run_once()
    path, report = export(ledgers, tmp_path)
    assert report["raw_alerts"] == report["episodes"] == 0
    assert verify_archive(path)["verified"]


def test_archive_includes_retired_episodes_and_raw_tombstones(ledgers, tmp_path):
    runner, raw, evaluator, _ = ledgers
    evaluator.events += events("2026-01-01T00:01:30Z", count=1, prefix="extension")
    raw.run_once()
    runner.run_once()
    # Remove earliest anchor, retaining enough failures for the second anchor.
    evaluator.events = events("2026-01-01T00:01:30Z", count=10, prefix="replacement")
    raw.run_once()
    runner.run_once()
    path, report = export(ledgers, tmp_path)
    assert report["raw_alerts"] == 2 and report["episodes"] == 2 and report["current_episodes"] == 1
    content = json.loads(path.read_text())["content"]
    assert any(item["status"] == "retracted" for item in content["raw_alerts"])
    retired = next(item for item in content["episodes"] if item["status"] == "retracted")
    assert len(retired["replacement_episode_ids"]) == 1
    assert verify_archive(path)["verified"]


def test_closed_does_not_mean_replay_stable_and_boundary_is_strict(ledgers, tmp_path):
    runner, raw, _, _ = ledgers
    # Anchor 00:01 + gap1m =00:02. Source lookback=1h.
    raw.max_forward_span = 24 * 60 * 60 * 1_000_000
    raw.clock = lambda: parse_timestamp("2026-01-01T01:02:00Z")
    raw.run_once()
    runner.run_once()
    _, report = export(ledgers, tmp_path)
    assert report["current_episodes"] == 1 and report["replay_stable_episodes"] == 0
    raw.clock = lambda: parse_timestamp("2026-01-01T01:02:00.000001Z")
    raw.run_once()
    runner.run_once()
    later = tmp_path / "later.json"
    result = create_archive(raw.state_path, runner.state_path, later)
    assert result["replay_stable_episodes"] == 1
    assert verify_archive(later)["pruning_applied"] is False


def test_stale_projection_clock_or_manifest_requires_projection_first(ledgers, tmp_path):
    runner, raw, evaluator, _ = ledgers
    raw.clock = lambda: parse_timestamp("2026-01-01T00:03:00Z")
    raw.run_once()
    with pytest.raises(EpisodeError, match="progress is stale"):
        export(ledgers, tmp_path)
    assert not (tmp_path / "evidence.json").exists()
    runner.run_once()
    evaluator.events += events("2026-01-01T00:01:30Z", count=1)
    raw.run_once()
    with pytest.raises(EpisodeError, match="manifest is stale"):
        export(ledgers, tmp_path)


@pytest.mark.parametrize("which", ["raw", "episode"])
def test_pending_outbox_refuses_export_without_changing_state(ledgers, tmp_path, which):
    runner, raw, _, _ = ledgers
    path = raw.state_path if which == "raw" else runner.state_path
    with sqlite3.connect(path) as db:
        if which == "raw":
            identifier, payload = db.execute("SELECT alert_id,payload FROM alerts LIMIT 1").fetchone()
            db.execute("INSERT INTO outbox(alert_id,payload,revision) VALUES (?,?,?)", (identifier, payload, json.loads(payload)["revision"]))
        else:
            identifier, payload = db.execute("SELECT episode_id,payload FROM episodes LIMIT 1").fetchone()
            db.execute("INSERT INTO episode_outbox(episode_id,payload,revision) VALUES (?,?,?)", (identifier, payload, json.loads(payload)["revision"]))
    before = records(path)
    with pytest.raises(EpisodeError, match="outbox must be empty"):
        export(ledgers, tmp_path)
    assert records(path) == before and not (tmp_path / "evidence.json").exists()


@pytest.mark.parametrize("which", [0, 1])
def test_active_writer_is_not_interrupted(ledgers, tmp_path, which):
    runner, raw, _, _ = ledgers
    path = (raw.state_path, runner.state_path)[which]
    with open(str(path) + ".lock", "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(EpisodeError, match="writer is active"):
            export(ledgers, tmp_path)
    assert not (tmp_path / "evidence.json").exists()
    export(ledgers, tmp_path)  # Both locks were released after failure.


def test_missing_lock_is_not_created(ledgers, tmp_path):
    runner, raw, _, _ = ledgers
    lock = Path(str(raw.state_path) + ".lock")
    lock.unlink()
    with pytest.raises(EpisodeError, match="Cannot lock"):
        create_archive(raw.state_path, runner.state_path, tmp_path / "evidence.json")
    assert not lock.exists()


def test_foreign_episode_state_is_preserved(ledgers, tmp_path):
    runner, raw, _, _ = ledgers
    other = tmp_path / "foreign.sqlite"
    with sqlite3.connect(other) as db:
        db.execute("CREATE TABLE keep_me (value TEXT)")
    Path(str(other) + ".lock").touch()
    before = other.read_bytes()
    with pytest.raises(EpisodeError, match="schema 1"):
        create_archive(raw.state_path, other, tmp_path / "evidence.json")
    assert other.read_bytes() == before


@pytest.mark.parametrize("option", ["max_source_alerts", "max_source_bytes", "max_episode_rows", "max_episode_bytes", "max_archive_bytes"])
def test_invalid_limits_reject_before_input_creation(tmp_path, option):
    with pytest.raises(EpisodeError, match="integer"):
        create_archive(tmp_path / "missing-raw", tmp_path / "missing-episode", tmp_path / "out.json", **{option: 0})
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("option", ["max_source_bytes", "max_episode_bytes", "max_archive_bytes"])
def test_resource_caps_fail_without_partial_archive(ledgers, tmp_path, option):
    with pytest.raises(EpisodeError, match="exceeded"):
        export(ledgers, tmp_path, **{option: 1})
    assert not (tmp_path / "evidence.json").exists()
    assert not list(tmp_path.glob(".episode-archive-*.tmp"))


def test_row_limit_counts_retired_episode_history(ledgers, tmp_path):
    runner, raw, evaluator, _ = ledgers
    evaluator.events += events("2026-01-01T00:00:30Z", prefix="early")
    raw.run_once()
    runner.run_once()
    with pytest.raises(EpisodeError, match="max_episode_rows"):
        export(ledgers, tmp_path, max_episode_rows=1)


def test_existing_destination_and_symlink_are_not_overwritten(ledgers, tmp_path):
    path, _ = export(ledgers, tmp_path)
    original = path.read_bytes()
    with pytest.raises(EpisodeError, match="already exists"):
        export(ledgers, tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    runner, raw, _, _ = ledgers
    with pytest.raises(EpisodeError, match="already exists"):
        create_archive(raw.state_path, runner.state_path, link)
    with pytest.raises(OSError):
        verify_archive(link)
    assert path.read_bytes() == original


def test_concurrent_destination_creation_is_not_overwritten(ledgers, tmp_path, monkeypatch):
    original_link = os.link
    def race(source, target, **kwargs):
        Path(target).write_bytes(b"someone else's archive")
        return original_link(source, target, **kwargs)
    monkeypatch.setattr(implementation.os, "link", race)
    with pytest.raises(EpisodeError, match="appeared concurrently"):
        export(ledgers, tmp_path)
    assert (tmp_path / "evidence.json").read_bytes() == b"someone else's archive"
    assert not list(tmp_path.glob(".episode-archive-*.tmp"))


def test_checksum_failure_and_bounded_verification(ledgers, tmp_path):
    path, _ = export(ledgers, tmp_path)
    with pytest.raises(EpisodeError, match="before reading"):
        verify_archive(path, max_archive_bytes=path.stat().st_size - 1)
    rewrite(path, lambda content: content["episodes"][0].update(anchor_count=99), checksum=False)
    with pytest.raises(EpisodeError, match="checksum"):
        verify_archive(path)


@pytest.mark.parametrize("mutate", [
    lambda c: c["episodes"][0]["peak_metrics"].update(fails=99),
    lambda c: c["episodes"][0].update(anchor_count=99),
    lambda c: c["episodes"][0].update(status="closed"),
    lambda c: c["episodes"][0].update(member_alert_ids=["a" * 64]),
    lambda c: c["episodes"][0].update(episode_id="0" * 64),
    lambda c: c["raw_alerts"][0].update(scope_id="0" * 64),
    lambda c: c["projection"].update(source_manifest_sha256="0" * 64),
    lambda c: c["projection"]["source_progress"].update(last_clock="2026-01-01T00:00:00Z"),
    lambda c: c["counts"].update(episodes=0),
    lambda c: c["retention_plan"].update(pruning_applied=True),
    lambda c: c["episodes"].clear(),
    lambda c: c["raw_alerts"].append(deepcopy(c["raw_alerts"][0])),
])
def test_recomputed_checksum_cannot_hide_semantic_inconsistency(ledgers, tmp_path, mutate):
    path, _ = export(ledgers, tmp_path)
    rewrite(path, mutate)
    with pytest.raises(EpisodeError):
        verify_archive(path)


@pytest.mark.parametrize("data", [b'{"format":"one","format":"two"}', b'{"value":NaN}', b'\xff', b'[]'])
def test_invalid_json_and_duplicate_keys_are_rejected(tmp_path, data):
    path = tmp_path / "bad.json"
    path.write_bytes(data)
    with pytest.raises(EpisodeError):
        verify_archive(path)


def test_unknown_format_or_boolean_version_is_rejected(ledgers, tmp_path):
    path, _ = export(ledgers, tmp_path)
    envelope = json.loads(path.read_text())
    envelope["version"] = True
    path.write_text(json.dumps(envelope))
    with pytest.raises(EpisodeError, match="format/version"):
        verify_archive(path)


def test_cli_create_and_offline_verify_from_outside_repository(ledgers, tmp_path):
    runner, raw, _, _ = ledgers
    path = tmp_path / "cli.json"
    base = [sys.executable, str(ROOT / "tools/episode_archive.py")]
    result = subprocess.run(base + ["create", "--source-state", str(raw.state_path),
        "--episode-state", str(runner.state_path), "--output", str(path)], cwd=tmp_path, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verified"]
    result = subprocess.run(base + ["verify", str(path)], cwd=tmp_path, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verified"]
    result = subprocess.run(base + ["verify", str(path), "--max-archive-bytes", "1"], cwd=tmp_path, text=True, capture_output=True, timeout=20)
    assert result.returncode == 1 and json.loads(result.stderr)["ok"] is False


@pytest.mark.parametrize("mutate", [
    lambda c: c["episodes"][0].update(rule_id=[]),
    lambda c: c["episodes"][0].update(rule_id={}),
    lambda c: c["projection"]["binding"]["episodes"].update(name=123),
    lambda c: c.update(source=[]),
    lambda c: c.update(projection=None),
    lambda c: c.update(raw_alerts={}),
    lambda c: c.update(episodes={}),
    lambda c: c["episodes"][0].update(member_revisions=[]),
    lambda c: c["episodes"][0].update(member_alert_ids=[{}]),
    lambda c: c["episodes"][0].update(replacement_episode_ids=[{}]),
])
def test_malformed_valid_checksum_objects_fail_with_contract_error(ledgers, tmp_path, mutate):
    path, _ = export(ledgers, tmp_path)
    rewrite(path, mutate)
    with pytest.raises(EpisodeError):
        verify_archive(path)


@pytest.mark.parametrize("table", ["episode_meta", "episode_source_alerts", "episodes", "episode_outbox"])
def test_primary_keys_cannot_be_removed_from_compatible_named_tables(ledgers, tmp_path, table):
    runner, _, _, _ = ledgers
    with sqlite3.connect(runner.state_path) as db:
        db.execute(f"CREATE TABLE temporary AS SELECT * FROM {table}")
        db.execute(f"DROP TABLE {table}")
        db.execute(f"ALTER TABLE temporary RENAME TO {table}")
    before = records(runner.state_path)
    with pytest.raises(EpisodeError, match="schema columns"):
        export(ledgers, tmp_path)
    assert records(runner.state_path) == before
    assert not (tmp_path / "evidence.json").exists()


def test_interruption_before_publication_cleans_temporary_file_and_releases_locks(ledgers, tmp_path, monkeypatch):
    fsync = os.fsync
    def interrupted(_descriptor):
        raise OSError("injected fsync failure before publication")
    monkeypatch.setattr(implementation.os, "fsync", interrupted)
    with pytest.raises(OSError, match="injected"):
        export(ledgers, tmp_path)
    assert not (tmp_path / "evidence.json").exists()
    assert not list(tmp_path.glob(".episode-archive-*.tmp"))
    monkeypatch.setattr(implementation.os, "fsync", fsync)
    assert export(ledgers, tmp_path)[1]["verified"]
