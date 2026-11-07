"""Manual expectations for the ten catalogued process candidates.

The Sigma cases independently declare matches. The normalized test envelope
supplies a synthetic host, timestamp, process GUID and explorer parent; those
values are fixture context, not values inferred by a collector or detector.
Missing Image/CommandLine is preserved as invalid input, never filled in.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
from uuid import NAMESPACE_URL, uuid5

import pytest

from tools.process_detection import evaluate_events, load_rules
from tools.process_profile import DATASET, prepare_events

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules()
MANIFEST = json.loads((ROOT / "tests/fixtures/sigma/predicates.json").read_text())
SUITES = [suite for suite in MANIFEST["rules"] if suite["rule_id"] in RULES]
CASES = [(suite["rule_id"], case) for suite in SUITES for case in suite["cases"]]


def normalized_case(case, identifier="manual-process"):
    event = {
        "@timestamp": "2026-01-01T00:00:10Z", "event.id": identifier,
        "event.dataset": DATASET, "event.code": "1", "host.name": "fixture-host",
        "process.guid": str(uuid5(NAMESPACE_URL, identifier)),
        "process.parent.guid": "10000000-0000-0000-0000-000000000001",
        "process.parent.executable": r"C:\Windows\explorer.exe",
    }
    for source, target in (("Image", "process.executable"),
                           ("CommandLine", "process.command_line"),
                           ("ParentImage", "process.parent.executable")):
        if source in case["event"]:
            event[target] = case["event"][source]
    return event


def test_all_catalogued_rules_have_manual_positive_negative_and_benign_cases():
    assert len(RULES) == 10
    assert {suite["rule_id"] for suite in SUITES} == set(RULES)
    assert len(SUITES) == len(RULES)
    for suite in SUITES:
        assert suite["source"] == {"product": "windows", "category": "process_creation"}
        cases = suite["cases"]
        assert len(cases) >= 8
        assert len({case["name"] for case in cases}) == len(cases)
        assert {case["match"] for case in cases if case["profile_valid"]} == {True, False}
        assert any(case["outcome"] == "benign_candidate" for case in cases)
        for case in cases:
            assert type(case["profile_valid"]) is bool
            assert case["outcome"] in {"candidate", "benign_candidate", "nonmatch", "invalid_profile"}
            assert case["profile_valid"] == (case["outcome"] != "invalid_profile")
            if case["profile_valid"]:
                assert case["match"] == (case["outcome"] in {"candidate", "benign_candidate"})


@pytest.mark.parametrize("rule_id,case", CASES,
                         ids=[key[:8] + "/" + case["name"] for key, case in CASES])
def test_manual_process_expectations_and_linked_source_evidence(rule_id, case):
    event = normalized_case(case)
    selected = {rule_id: RULES[rule_id]}
    if not case["profile_valid"]:
        with pytest.raises(ValueError):
            prepare_events([event])
        with pytest.raises(ValueError):
            evaluate_events([event], rules=selected)
        return
    result = evaluate_events([event], rules=selected)
    expected = [(rule_id, event["event.id"])] if case["match"] else []
    assert [(alert["rule.id"], alert["event.id"]) for alert in result["alerts"]] == expected
    assert result["summary"]["input_events"] == result["summary"]["unique_events"] == 1
    for alert in result["alerts"]:
        assert re.fullmatch(r"process:[0-9a-f]{64}", alert["alert.id"])
        for field in ("@timestamp", "event.id", "host.name", "process.guid", "process.parent.guid",
                      "process.executable", "process.parent.executable", "process.command_line"):
            assert alert[field] == event[field]


@pytest.mark.parametrize("suite", SUITES, ids=lambda suite: suite["rule_id"][:8])
def test_manual_match_survives_order_changes_and_identical_redelivery(suite):
    positive = next(case for case in suite["cases"] if case["profile_valid"] and case["match"])
    negative = next(case for case in suite["cases"] if case["profile_valid"] and not case["match"])
    events = [normalized_case(positive, "positive"), normalized_case(negative, "negative")]
    selected = {suite["rule_id"]: RULES[suite["rule_id"]]}
    baseline = evaluate_events(events, rules=selected)
    replay = evaluate_events(list(reversed(deepcopy(events))) + deepcopy(events), rules=selected)
    assert [(alert["rule.id"], alert["event.id"]) for alert in replay["alerts"]] == [
        (suite["rule_id"], "positive"),
    ]
    assert replay["alerts"] == baseline["alerts"]
    assert replay["summary"]["duplicate_events"] == 2
