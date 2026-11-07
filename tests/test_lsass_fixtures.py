"""Manually specified ProcessAccess examples distinguish candidates from attacks."""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from tools.detect_lsass import evaluate_events
from tools.lsass_profile import prepare_events

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/lsass/cases.json").read_text())
CASES = MANIFEST["cases"]
EVIDENCE_FIELDS = (
    "@timestamp", "event.id", "host.name", "source.process.guid",
    "target.process.guid", "source.image", "target.image", "process.access_mask",
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manually_declared_lsass_candidates_and_evidence(case):
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            evaluate_events(case["events"], **case.get("bounds", {}))
        return

    result = evaluate_events(case["events"], **case.get("bounds", {}))
    assert [alert["event.id"] for alert in result["alerts"]] == case["expected_event_ids"], case["reason"]
    source = {event["event.id"]: event for event in case["events"]}
    for alert in result["alerts"]:
        assert alert["rule.id"] == "LSASS-PROCESS-VM-READ-001"
        assert re.fullmatch(r"lsass:[0-9a-f]{64}", alert["alert.id"])
        assert {field: alert[field] for field in EVIDENCE_FIELDS} == {
            field: source[alert["event.id"]][field] for field in EVIDENCE_FIELDS
        }
    assert len({alert["alert.id"] for alert in result["alerts"]}) == len(result["alerts"])


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manual_profile_rejections_are_not_silent_negatives(case):
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            prepare_events(case["events"])
        return
    events, counters = prepare_events(case["events"])
    assert counters["input_events"] == len(case["events"])
    result = evaluate_events(events, **case.get("bounds", {}))
    assert [alert["event.id"] for alert in result["alerts"]] == case["expected_event_ids"]


@pytest.mark.parametrize("name", [
    "pid_reuse_keeps_distinct_process_guids",
    "same_guids_on_different_hosts",
    "repeated_distinct_events_are_not_first_seen_suppressed",
    "microsecond_bounds_are_start_inclusive_end_exclusive",
    "equal_timestamps_order_by_event_id",
])
def test_reordering_and_identical_redelivery_preserve_manual_evidence(name):
    case = next(case for case in CASES if case["name"] == name)
    expected = evaluate_events(case["events"], **case.get("bounds", {}))
    replay = evaluate_events(
        list(reversed(deepcopy(case["events"]))) + deepcopy(case["events"]),
        **case.get("bounds", {}),
    )
    assert [alert["event.id"] for alert in replay["alerts"]] == case["expected_event_ids"]
    assert replay["alerts"] == expected["alerts"]


def test_fixture_labels_keep_legitimate_matches_distinct_from_nonmatches():
    assert MANIFEST["format_version"] == 1
    assert MANIFEST["rule_id"] == "LSASS-PROCESS-VM-READ-001"
    assert len(CASES) == len({case["name"] for case in CASES}) == 40
    assert sum(len(case["events"]) for case in CASES) == 50
    assert sum(case["profile_valid"] for case in CASES) == 28
    assert {case["outcome"] for case in CASES} == {
        "candidate", "benign_candidate", "nonmatch", "invalid",
    }
    for case in CASES:
        assert case["reason"]
        assert case["profile_valid"] == (case["outcome"] != "invalid")
        assert bool(case["expected_event_ids"]) == (case["outcome"] in {"candidate", "benign_candidate"})
    benign = {case["name"] for case in CASES if case["outcome"] == "benign_candidate"}
    assert benign == {"legitimate_av_memory_read", "legitimate_edr_memory_read"}
