"""Independent manual expectations for finite NewCredentials session evidence."""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from tools.correlate_newcredentials import correlate
from tools.newcredentials_profile import prepare_events

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/newcredentials/cases.json").read_text())
CASES = MANIFEST["cases"]
PAIR_FIELDS = (
    "logon.event.id", "privilege.event.ids", "privilege.time_deltas_us", "win.privileges",
)
ANCHOR_FIELDS = ("@timestamp", "host.name", "host.boot.id", "session.id", "user.id")


def options(case):
    return {**case.get("bounds", {}), "max_skew_seconds": case.get("max_skew_seconds", 30)}


def pairs(result):
    return [{key: alert[key] for key in PAIR_FIELDS} for alert in result["alerts"]]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manually_declared_session_pairs_and_evidence(case):
    if not case["correlation_valid"]:
        with pytest.raises(ValueError):
            correlate(case["events"], **options(case))
        return
    result = correlate(case["events"], **options(case))
    assert pairs(result) == case["expected_pairs"], case["reason"]
    events = {event["event.id"]: event for event in case["events"]}
    for alert in result["alerts"]:
        assert alert["rule.id"] == "CORR-WIN-NEWCREDENTIALS-PRIVILEGES-001"
        assert re.fullmatch(r"newcredentials:[0-9a-f]{64}", alert["alert.id"])
        anchor = events[alert["logon.event.id"]]
        assert {key: alert[key] for key in ANCHOR_FIELDS} == {
            key: anchor[key] for key in ANCHOR_FIELDS
        }
        assert anchor["event.code"] == "4624"
        assert all(events[event_id]["event.code"] == "4672" for event_id in alert["privilege.event.ids"])
    assert len({alert["alert.id"] for alert in result["alerts"]}) == len(result["alerts"])


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_profile_invalid_and_correlated_contradiction_are_distinct(case):
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            prepare_events(case["events"])
        return
    events, counters = prepare_events(case["events"])
    assert counters["input_events"] == len(case["events"])
    if not case["correlation_valid"]:
        with pytest.raises(ValueError, match="ambiguous session|contradictory SID"):
            correlate(events, **options(case))
        return
    assert pairs(correlate(events, **options(case))) == case["expected_pairs"]


@pytest.mark.parametrize("name", [
    "multiple_privileges_sorted_evidence_and_union",
    "same_luid_on_two_boots_keeps_two_candidates",
    "same_luid_on_two_hosts_keeps_two_candidates",
    "future_privilege_context_outside_output_bounds",
    "past_privilege_context_outside_output_bounds",
    "repeated_background_session_does_not_block_other_candidate",
    "unselected_ambiguous_session_does_not_block_selected_session",
])
def test_delivery_order_and_identical_redelivery_do_not_change_manual_pairs(name):
    case = next(case for case in CASES if case["name"] == name)
    baseline = correlate(case["events"], **options(case))
    replay = correlate(
        list(reversed(deepcopy(case["events"]))) + deepcopy(case["events"]),
        **options(case),
    )
    assert pairs(replay) == case["expected_pairs"]
    assert replay["alerts"] == baseline["alerts"]


def test_fixture_labels_do_not_turn_benign_candidates_or_errors_into_negatives():
    assert MANIFEST["format_version"] == 1
    assert MANIFEST["rule_id"] == "CORR-WIN-NEWCREDENTIALS-PRIVILEGES-001"
    assert len(CASES) == len({case["name"] for case in CASES}) == 40
    assert sum(len(case["events"]) for case in CASES) == 98
    assert sum(case["profile_valid"] for case in CASES) == 32
    assert sum(case["correlation_valid"] for case in CASES) == 28
    assert {case["outcome"] for case in CASES} == {
        "candidate", "benign_candidate", "nonmatch", "invalid", "correlation_error",
    }
    for case in CASES:
        assert case["reason"]
        assert case["profile_valid"] == (case["outcome"] != "invalid")
        assert case["correlation_valid"] == (case["outcome"] not in {"invalid", "correlation_error"})
        assert bool(case["expected_pairs"]) == (case["outcome"] in {"candidate", "benign_candidate"})
    assert {case["name"] for case in CASES if case["outcome"] == "benign_candidate"} == {
        "legitimate_runas_netonly_stays_candidate",
    }
