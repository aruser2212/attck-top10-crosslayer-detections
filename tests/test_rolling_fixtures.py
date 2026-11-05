"""Reviewed expectations exercise stored rolling rules, not regenerated outputs."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from tools.rolling_hunt import evaluate_hunt, load_hunt
from tools.hunt_engine import evaluate_hunt as evaluate_v1
from tools.hunt_engine import load_hunt as load_v1

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/rolling/auth_cases.json").read_text())
CASES = MANIFEST["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_reviewed_events_match_manually_declared_rolling_alerts(case):
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), case["events"], **case.get("bounds", {}))
    assert result["alerts"] == case["expected_alerts"], case["name"]
    assert result["summary"]["input_events"] == len(case["events"]) > 0
    assert result["summary"]["alerts"] == len(case["expected_alerts"])
    assert (result["summary"]["unique_events"] + result["summary"]["duplicate_events"]
            == len(case["events"]))


def test_fixture_inventory_covers_every_rolling_rule_with_positive_and_negative_cases():
    assert MANIFEST["schema_version"] == 1
    assert CASES
    assert len({case["name"] for case in CASES}) == len(CASES)
    stored = {path.relative_to(ROOT).as_posix()
              for path in ROOT.glob("techniques/**/hunts/*_rolling.hunt.yaml")}
    assert stored
    assert {case["hunt"] for case in CASES} == stored
    for path in stored:
        assert load_hunt(ROOT / path)["schema_version"] == 2
        cases = [case for case in CASES if case["hunt"] == path]
        assert any(case["expected_alerts"] for case in cases)
        assert any(not case["expected_alerts"] for case in cases)
    for case in CASES:
        assert case["events"]
        assert isinstance(case["expected_alerts"], list)
        assert ("v1_hunt" in case) == ("expected_v1_alerts" in case)
        if "bounds" in case:
            assert set(case["bounds"]) == {"start", "end"}


@pytest.mark.parametrize("case", [case for case in CASES if "v1_hunt" in case],
                         ids=lambda case: case["name"])
def test_explicit_fixed_window_comparison_keeps_legacy_behavior(case):
    fixed = evaluate_v1(load_v1(ROOT / case["v1_hunt"]), case["events"])
    assert fixed["alerts"] == case["expected_v1_alerts"]
    # This comparison is intentionally hand-reviewed: five events on each side
    # of 00:05 miss both fixed buckets, but qualify at the rolling 00:05:01 anchor.
    assert case["name"] == "brute_straddles_v1_boundary"
    assert fixed["alerts"] == []
    assert case["expected_alerts"] == [{
        "window.start": "2026-01-01T00:00:01Z",
        "window.end": "2026-01-01T00:05:01Z",
        "source.ip": "192.0.2.10", "target.user": "lab\\alice", "fails": 10,
    }]


@pytest.mark.parametrize("name", [
    "brute_each_qualifying_timestamp_emits",
    "spray_repeat_at_later_anchor_still_qualifies",
    "bounded_linux_uses_preceding_history",
])
def test_input_order_does_not_change_reviewed_expected_alerts(name):
    case = next(case for case in CASES if case["name"] == name)
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]),
                           list(reversed(deepcopy(case["events"]))), **case.get("bounds", {}))
    assert result["alerts"] == case["expected_alerts"]
