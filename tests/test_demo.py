"""Smoke the documented offline entry point and prevent partial success reports."""
import json
from pathlib import Path
import subprocess
import sys

from tools import demo, hunt_engine


ROOT = Path(__file__).resolve().parents[1]


def test_all_seven_scenarios_validate_declared_candidates():
    result = demo.run_demo()
    assert result["checks_passed"] == 7
    assert [row["scenario"] for row in result["scenarios"]] == [
        "auth-v1", "rolling-v2", "kerberos", "host-web", "lsass", "newcredentials", "process",
    ]
    assert [row["input_events"] for row in result["scenarios"]] == [10, 10, 5, 5, 2, 2, 2]
    assert all(row["candidate_alerts"] == 1 and row["check"] == "passed"
               for row in result["scenarios"])
    assert result["scenarios"][1]["evidence"]["fixed_window_candidates"] == 0
    assert result["scenarios"][3]["evidence"]["source_pairs"] == [["file-create", "request-suspicious"]]
    assert result["scenarios"][5]["evidence"]["privilege.time_deltas_us"] == [0]
    assert result["scenarios"][6]["evidence"]["technique"] == "T1218.010"


def test_documented_cli_runs_outside_repository_without_writing_files(tmp_path):
    completed = subprocess.run([sys.executable, str(ROOT / "tools/demo.py")], cwd=tmp_path,
                               text=True, capture_output=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["checks_passed"] == 7
    assert list(tmp_path.iterdir()) == []


def test_selected_scenario_does_not_require_other_fixtures(monkeypatch, capsys):
    def must_not_run():
        raise AssertionError("Unselected scenario ran")

    monkeypatch.setitem(demo.SCENARIOS, "process", must_not_run)
    assert demo.main(["--scenario", "auth-v1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["checks_passed"] == 1
    assert result["scenarios"][0]["scenario"] == "auth-v1"


def test_later_failure_emits_no_partial_success_report(monkeypatch, capsys):
    def fail():
        raise demo.DemoError("fixture expectation failed")

    monkeypatch.setitem(demo.SCENARIOS, "rolling-v2", fail)
    assert demo.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "fixture expectation failed" in captured.err


def test_missing_fixture_fails_without_output(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(demo, "ROOT", tmp_path)
    assert demo.main(["--scenario", "auth-v1"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Offline demonstration failed" in captured.err


def test_broken_detector_cannot_pass_demo(monkeypatch, capsys):
    monkeypatch.setattr(hunt_engine, "evaluate_hunt", lambda *args, **kwargs: {
        "alerts": [], "summary": {"input_events": 10, "alerts": 0},
    })
    assert demo.main(["--scenario", "auth-v1"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "differs from the declared demonstration" in captured.err


def test_unknown_scenario_cli_is_an_error(tmp_path):
    completed = subprocess.run([sys.executable, str(ROOT / "tools/demo.py"), "--scenario", "unknown"],
                               cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 2
    assert completed.stdout == ""
