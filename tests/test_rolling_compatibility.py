"""Rolling v2 must never silently run as tumbling v1 or reuse v1 state."""
from pathlib import Path
import json
import subprocess
import sys

import pytest

from tools.detection_runner import DetectionRunner
from tools.elastic_adapter import compile_hunt
from tools.hunt_engine import HuntError, evaluate_hunt as evaluate_v1
from tools.rolling_hunt import load_hunt as load_v2


ROOT = Path(__file__).resolve().parents[1]
HUNTS = ROOT / "techniques/T1110_Brute_Force/hunts"
ROLLING = [HUNTS / (name + "_rolling.hunt.yaml") for name in (
    "win_4625_brute_agg", "win_4625_spray_agg", "linux_ssh_failed_agg",
)]
ROLLING.append(ROOT / "techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml")


@pytest.mark.parametrize("path", ROLLING, ids=lambda path: path.stem)
def test_v1_reference_and_adapter_reject_explicit_rolling_rules(path):
    rule = load_v2(path)
    with pytest.raises(HuntError, match="schema_version: 1"):
        evaluate_v1(rule, [])
    with pytest.raises(HuntError, match="schema_version: 1"):
        compile_hunt(rule)


@pytest.mark.parametrize("path", ROLLING, ids=lambda path: path.stem)
def test_v1_runner_rejects_rolling_before_state_or_network_changes(path, tmp_path):
    class NoNetwork:
        def request(self, *args, **kwargs):
            pytest.fail("Reject unsupported rule semantics before contacting Elasticsearch")

    state = tmp_path / "never-created" / "detections.sqlite"
    with pytest.raises(HuntError, match="schema_version: 1"):
        DetectionRunner(source_client=NoNetwork(), state_path=state,
                        source_index="auth-v1-test", alerts_index="alerts-v1-test",
                        rule_paths=[path], initial_start="2026-01-01T00:00:00Z")
    assert not state.parent.exists()


def test_v2_loader_does_not_reinterpret_existing_tumbling_or_legacy_hunts():
    legacy_and_v1 = [path for path in ROOT.glob("techniques/**/hunts/*.hunt.yaml")
                     if path not in ROLLING]
    assert len(legacy_and_v1) == 21
    for path in legacy_and_v1:
        with pytest.raises(ValueError):
            load_v2(path)


def test_linux_journal_to_rolling_cli_from_outside_repository(tmp_path):
    normalized = subprocess.run(
        [sys.executable, str(ROOT / "tools/normalize_linux_auth.py"),
         str(ROOT / "tests/fixtures/linux_auth/journal.jsonl")],
        cwd=tmp_path, capture_output=True, text=True, timeout=15,
    )
    assert normalized.returncode == 0, normalized.stderr
    events = tmp_path / "normalized.jsonl"
    events.write_text(normalized.stdout, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/rolling_hunt.py"),
         str(HUNTS / "linux_ssh_failed_agg_rolling.hunt.yaml"), "--events", str(events)],
        cwd=tmp_path, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    assert actual["alerts"] == [{
        "window.start": "2025-12-31T23:55:17Z",
        "window.end": "2026-01-01T00:00:17Z",
        "source.ip": "192.0.2.10", "user.name": "alice", "fails": 8,
    }]
    assert actual["summary"]["matched_events"] == 8  # Successful logons do not count.
