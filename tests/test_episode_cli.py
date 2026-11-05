"""CLI control flow, pending-delivery status and bounded watch error handling."""
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
from threading import Event

import pytest

from tools import run_episode_pipeline as cli

ROOT = Path(__file__).resolve().parents[1]


def arguments(tmp_path):
    return ["--source-state", str(tmp_path / "rolling.sqlite"),
            "--state", str(tmp_path / "episodes.sqlite"), "--episodes-index", "episode-test"]


@pytest.fixture
def fake_runner(monkeypatch):
    class FakeRunner:
        created = []
        result = {"ok": True, "pending_outbox": 0}

        def __init__(self, **kwargs):
            self.options = kwargs
            self.runs = 0
            self.status_reads = 0
            self.created.append(self)

        def run_once(self):
            self.runs += 1
            return self.result

        def status(self):
            self.status_reads += 1
            return {"initialized": False, "pending_outbox": 0}

    monkeypatch.setattr(cli, "EpisodeRunner", FakeRunner)
    return FakeRunner


@pytest.mark.parametrize("result,code", [({"ok": True}, 0),
                                        ({"ok": False, "status": "waiting_for_raw_delivery"}, 2)])
def test_once_preserves_pending_status_and_exact_clock(tmp_path, fake_runner, capsys, result, code):
    fake_runner.result = result
    assert cli.main(arguments(tmp_path) + ["--once", "--initialize", "--gap-seconds", "17",
        "--at", "2026-01-01T00:10:00.000001Z", "--max-source-alerts", "111",
        "--max-source-bytes", "12345", "--max-episodes", "22", "--max-members", "33",
        "--max-changes", "44", "--projection-mode", "full"]) == code
    instance = fake_runner.created[0]
    assert instance.runs == 1
    assert instance.options["gap"] == timedelta(seconds=17)
    assert instance.options["initialize_index"] is True
    assert instance.options["projection_mode"] == "full"
    assert instance.options["clock"]().microsecond == 1
    assert [instance.options[key] for key in ("max_source_alerts", "max_source_bytes",
           "max_episodes", "max_members", "max_changes")] == [111, 12345, 22, 33, 44]
    report = json.loads(capsys.readouterr().out)
    assert all(report[key] == value for key, value in result.items())


def test_status_does_not_project_or_initialize(tmp_path, fake_runner, capsys):
    assert cli.main(arguments(tmp_path) + ["--status"]) == 0
    instance = fake_runner.created[0]
    assert instance.runs == 0 and instance.status_reads == 1
    assert instance.options["initialize_index"] is False
    assert instance.options["projection_mode"] == "incremental"
    assert json.loads(capsys.readouterr().out)["initialized"] is False


@pytest.mark.parametrize("extra", [
    ["--watch", "--at", "2026-01-01T00:00:00Z"],
    ["--status", "--initialize"], ["--once", "--gap-seconds", "0"],
    ["--once", "--max-source-alerts", "0"], ["--once", "--max-source-bytes", "-1"],
    ["--once", "--max-episodes", "0"], ["--once", "--max-members", "0"],
    ["--once", "--max-changes", "0"], ["--watch", "--interval", "nan"],
    ["--watch", "--interval", "0"],
    ["--once", "--projection-mode", "unknown"],
])
def test_invalid_options_fail_before_runner_construction(tmp_path, fake_runner, extra):
    with pytest.raises(SystemExit) as exc:
        cli.main(arguments(tmp_path) + extra)
    assert exc.value.code == 2
    assert not fake_runner.created
    assert not (tmp_path / "episodes.sqlite").exists()


def test_invalid_clock_fails_before_runner_construction(tmp_path, fake_runner, capsys):
    assert cli.main(arguments(tmp_path) + ["--once", "--at", "2026-01-01T00:00:00.0000001Z"]) == 1
    assert not fake_runner.created
    assert json.loads(capsys.readouterr().err)["ok"] is False


def test_once_propagates_failed_run_as_nonzero(tmp_path, fake_runner, monkeypatch, capsys):
    def fail(self):
        raise ValueError("source history regressed")
    monkeypatch.setattr(fake_runner, "run_once", fail)
    assert cli.main(arguments(tmp_path) + ["--once"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["error_type"] == "ValueError"


def test_watch_retries_error_then_pending_then_success_without_logging_payload():
    stop = Event()
    reports = []

    class Runner:
        calls = 0

        def run_once(self):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("private raw payload")
            if self.calls == 2:
                return {"ok": False, "status": "waiting_for_raw_delivery"}
            stop.set()
            return {"ok": True}

    runner = Runner()
    assert cli.watch(runner, interval=0.1, stop=stop, emit=reports.append) == 0
    assert runner.calls == 3
    assert reports[0]["error_type"] == "ValueError"
    assert "private" not in json.dumps(reports)
    assert reports[1]["status"] == "waiting_for_raw_delivery"
    assert reports[2] == {"ok": True}


def test_pre_stopped_watch_does_not_project():
    stop = Event()
    stop.set()
    assert cli.watch(object(), interval=0.1, stop=stop, emit=lambda _: pytest.fail("unexpected output")) == 0


def test_direct_cli_imports_outside_repository(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / "tools/run_episode_pipeline.py"), "--help"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "--source-state" in result.stdout and "--max-source-bytes" in result.stdout
