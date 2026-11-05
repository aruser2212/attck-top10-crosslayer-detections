from threading import Event
from pathlib import Path
import subprocess
import sys
import sqlite3

import pytest

from tools.elastic_adapter import ElasticHTTPError
from tools import run_auth_pipeline as pipeline


class Spool:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = 0

    def scan_once(self):
        self.calls += 1
        if self.fail:
            raise ValueError("invalid input")
        return {"ok": True, "files_acked": 1}


class Runner:
    def __init__(self):
        self.calls = 0

    def run_once(self):
        self.calls += 1
        return {"logical_alerts": 1}


def test_failed_ingestion_does_not_advance_detection():
    runner = Runner()
    with pytest.raises(ValueError):
        pipeline.run_iteration(Spool(fail=True), runner)
    assert runner.calls == 0


def test_unresolved_scan_is_not_reported_as_success():
    spool, runner = Spool(), Runner()
    spool.scan_once = lambda: {"ok": False, "unresolved_files": 1}
    with pytest.raises(ValueError):
        pipeline.run_iteration(spool, runner)
    assert runner.calls == 0


def test_pending_bounded_batch_holds_detection_checkpoint():
    spool, runner = Spool(), Runner()
    spool.scan_once = lambda: {"ok": True, "unacknowledged_files": 1}
    result = pipeline.run_iteration(spool, runner)
    assert result["ok"] is False
    assert result["status"] == "catching_up"
    assert runner.calls == 0


def test_sqlite_failure_is_reported_by_watch():
    spool, runner, stop = Spool(), Runner(), Event()
    spool.scan_once = lambda: (_ for _ in ()).throw(sqlite3.DatabaseError("bad database"))
    results = []

    def emit(result):
        results.append(result)
        stop.set()

    pipeline.watch(spool, runner, interval=0.1, stop=stop, emit=emit)
    assert results[0]["ok"] is False
    assert results[0]["error_type"] == "DatabaseError"
    assert runner.calls == 0


def test_documented_direct_cli_imports_without_pythonpath():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "tools/run_auth_pipeline.py"), "--help"],
                            cwd=root.parent, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--watch" in result.stdout


def test_watch_retries_failure_then_stops_cleanly():
    spool, runner, stop = Spool(fail=True), Runner(), Event()
    results = []

    def emit(result):
        results.append(result)
        spool.fail = False
        if len(results) == 2:
            stop.set()

    assert pipeline.watch(spool, runner, interval=0.1, stop=stop, emit=emit) == 0
    assert [r["ok"] for r in results] == [False, True]
    assert runner.calls == 1
    assert "invalid input" not in str(results)


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_invalid_interval_does_not_enter_loop(interval):
    with pytest.raises(ValueError):
        pipeline.watch(Spool(), Runner(), interval=interval, stop=Event(), emit=lambda _: None)


def test_initialization_never_overwrites_existing_incompatible_profile(monkeypatch):
    creations = []
    monkeypatch.setattr(pipeline, "check_profile", lambda *_: (_ for _ in ()).throw(ValueError("wrong profile")))
    monkeypatch.setattr(pipeline, "create_index", lambda *_: creations.append(True))
    with pytest.raises(ValueError, match="wrong profile"):
        pipeline.ensure_indices(object(), "auth", "alerts", initialize=True)
    assert creations == []


def test_missing_index_requires_explicit_initialize(monkeypatch):
    monkeypatch.setattr(pipeline, "check_profile", lambda *_: (_ for _ in ()).throw(ElasticHTTPError(404, "missing")))
    with pytest.raises(ElasticHTTPError):
        pipeline.ensure_indices(object(), "auth", "alerts", initialize=False)


def test_cannot_use_source_as_alert_sink():
    with pytest.raises(ValueError, match="different"):
        pipeline.ensure_indices(object(), "auth", "auth", initialize=True)
