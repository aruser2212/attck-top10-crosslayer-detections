"""Manual cross-source examples test candidates, not confirmed webshell execution."""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from tools.correlate_webshell import correlate
from tools.web_correlation_profile import prepare_events

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/correlation/cases.json").read_text())
CASES = MANIFEST["cases"]


def semantic_alerts(result):
    for alert in result["alerts"]:
        assert re.fullmatch(r"[0-9a-f]{64}", alert["alert.id"])
    return [{key: value for key, value in alert.items() if key != "alert.id"}
            for alert in result["alerts"]]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manually_declared_correlation_behavior(case):
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            correlate(case["events"], **case["config"])
        return
    result = correlate(case["events"], **case["config"])
    assert semantic_alerts(result) == case["expected_alerts"], case["reason"]
    assert result["summary"]["input_events"] == len(case["events"])
    assert result["summary"]["alerts"] == len(case["expected_alerts"])


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manual_case_declares_profile_acceptance(case):
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            prepare_events(case["events"])
        return
    events, counters = prepare_events(case["events"])
    assert counters["input_events"] == len(case["events"])
    assert semantic_alerts(correlate(events, **case["config"])) == case["expected_alerts"]


@pytest.mark.parametrize("name", [
    "latest_eligible_write_is_selected", "file_timestamp_tie_uses_largest_id",
    "equivalent_timezone_redelivery", "bounded_replay_retains_file_context",
    "repeated_requests_preserve_each_evidence_pair",
])
def test_delivery_order_and_unchanged_duplicates_preserve_full_alerts(name):
    case = next(case for case in CASES if case["name"] == name)
    result = correlate(case["events"], **case["config"])
    reversed_with_duplicates = list(reversed(deepcopy(case["events"]))) + deepcopy(case["events"])
    replay = correlate(reversed_with_duplicates, **case["config"])
    assert replay["alerts"] == result["alerts"]
    assert semantic_alerts(replay) == case["expected_alerts"]


def test_fixture_labels_distinguish_known_benign_match_from_rejected_input():
    assert MANIFEST["schema_version"] == 1
    assert MANIFEST["rule_id"] == "CORR-WEB-WEBROOT-REQUEST-002"
    assert len(CASES) == len({case["name"] for case in CASES}) == 40
    assert sum(len(case["events"]) for case in CASES) == 88
    assert {case["outcome"] for case in CASES} == {
        "candidate_positive", "candidate_negative", "benign_candidate", "invalid_input",
    }
    for case in CASES:
        assert case["reason"]
        assert bool(case["expected_alerts"]) == (case["outcome"] in {"candidate_positive", "benign_candidate"})
        assert case["profile_valid"] == (case["outcome"] != "invalid_input")
    benign = next(case for case in CASES if case["name"] == "benign_admin_cmd_after_deploy")
    assert benign["outcome"] == "benign_candidate"
    assert benign["expected_alerts"][0]["classification"] == "corroborated_suspicious_activity"
