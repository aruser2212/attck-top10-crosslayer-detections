"""Independent finite examples test a candidate, not confirmed Kerberoasting."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from tools.hunt_engine import HuntError
from tools.kerberos_profile import prepare_events
from tools.rolling_hunt import evaluate_hunt, load_hunt

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/kerberos/cases.json").read_text())
CASES = MANIFEST["cases"]
RULE_PATH = "techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml"


def find_case(name):
    return next(case for case in CASES if case["name"] == name)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_reviewed_kerberos_candidate_expectations(case):
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), case["events"], **case.get("bounds", {}))
    assert result["alerts"] == case["expected_alerts"], case["reason"]
    assert result["summary"]["input_events"] == len(case["events"]) > 0
    assert result["summary"]["alerts"] == len(case["expected_alerts"])
    assert result["summary"]["unique_events"] + result["summary"]["duplicate_events"] == len(case["events"])


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_reviewed_cases_declare_strict_profile_acceptance(case):
    # A profile rejection is a malformed-input boundary, not a detection result.
    # Missing semantic telemetry is retained and independently yields no match.
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            prepare_events(case["events"])
        return
    prepared, counters = prepare_events(case["events"])
    assert counters["input_events"] == len(case["events"])
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), prepared, **case.get("bounds", {}))
    assert result["alerts"] == case["expected_alerts"]


def test_manifest_labels_candidate_outcomes_without_attack_precision_claims():
    assert MANIFEST["schema_version"] == 1
    assert len({case["name"] for case in CASES}) == len(CASES)
    assert {case["hunt"] for case in CASES} == {RULE_PATH}
    assert {case["outcome"] for case in CASES} == {
        "candidate_negative", "candidate_positive", "benign_candidate",
    }
    for case in CASES:
        assert case["reason"]
        assert type(case["profile_valid"]) is bool
        assert isinstance(case["expected_alerts"], list)
        assert bool(case["expected_alerts"]) == (case["outcome"] != "candidate_negative")
        assert set(case.get("bounds", {})) in (set(), {"start", "end"})
    benign = find_case("benign_legacy_application_rc4_fanout")
    assert benign["outcome"] == "benign_candidate"
    assert benign["profile_valid"]
    assert benign["expected_alerts"] == [{
        "window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:05:00Z",
        "user.domain": "lab.example", "user.name": "svc-legacy-report", "source.ip": "192.0.2.10",
        "distinct_service_accounts": 5, "rc4_requests": 5,
    }]


@pytest.mark.parametrize("name", [
    "same_requester_across_domain_controllers",
    "timestamp_ties_are_atomic",
    "timezone_equivalent_duplicate_id",
    "each_qualifying_anchor_emits",
    "bounded_replay_uses_history_and_excludes_end",
])
def test_order_does_not_change_independent_expected_candidates(name):
    case = find_case(name)
    events = list(reversed(deepcopy(case["events"])))
    assert evaluate_hunt(load_hunt(ROOT / case["hunt"]), events,
                         **case.get("bounds", {}))["alerts"] == case["expected_alerts"]


def test_missing_service_sid_does_not_add_requests_or_create_an_anchor():
    case = find_case("missing_sid_cannot_add_request_or_anchor")
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), case["events"])
    assert result["alerts"] == case["expected_alerts"]
    assert result["summary"]["rejected_events"] == 1
    assert result["summary"]["matched_events"] == 5
    assert result["summary"]["anchors_evaluated"] == 1


def test_identity_counter_expires_only_after_last_request_for_that_sid():
    # SID 1101 is requested twice, at 00:00 and 00:01. At 00:05 the first
    # request expires but the second still represents that same service account.
    case = find_case("five_service_accounts_threshold")
    events = deepcopy(case["events"])
    events[0]["@timestamp"] = "2026-01-01T00:00:00Z"
    repeated = deepcopy(events[0])
    repeated["@timestamp"] = "2026-01-01T00:01:00Z"
    repeated["event.id"] = "same-sid-second-request"
    events.append(repeated)
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), events)
    assert result["alerts"] == case["expected_alerts"]
    assert result["alerts"][0]["rc4_requests"] == 5


def test_conflicting_duplicate_event_id_cannot_silently_replace_service_identity():
    case = find_case("five_service_accounts_threshold")
    events = deepcopy(case["events"])
    conflict = deepcopy(events[-1])
    conflict["service.id"] = "S-1-5-21-100-200-300-9999"
    events.append(conflict)
    with pytest.raises(HuntError, match="conflicting duplicate event.id"):
        evaluate_hunt(load_hunt(ROOT / case["hunt"]), events)
    with pytest.raises(HuntError, match="conflicting duplicate event.id"):
        prepare_events(events)
