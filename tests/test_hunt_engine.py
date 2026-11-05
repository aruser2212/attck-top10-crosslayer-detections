"""The same reviewed fixtures exercise stored rules and the real replay engine."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.hunt_engine import (
    HuntError, evaluate_hunt, format_timestamp, load_hunt, parse_timestamp,
    predicate_matches, prepare_events, read_jsonl, validate_hunt,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/hunts"
CASES = json.loads((FIXTURES / "auth_cases.json").read_text())["cases"]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_reviewed_fixture_against_stored_hunt(case):
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), case["events"])
    assert result["alerts"] == case["expected_alerts"]
    summary = result["summary"]
    assert summary["input_events"] == len(case["events"]) > 0
    assert summary["unique_events"] + summary["duplicate_events"] == summary["input_events"]
    assert sum(summary[key] for key in ("filtered_events", "rejected_events", "matched_events")) == summary["unique_events"]
    for name, expected in case.get("expected_summary", {}).items():
        assert summary[name] == expected


def test_fixture_inventory_exercises_every_executable_hunt():
    executable = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.glob("techniques/**/hunts/*.hunt.yaml")
        if "schema_version: 1" in path.read_text()
    }
    assert executable
    assert {case["hunt"] for case in CASES} == executable
    for hunt in executable:
        cases = [case for case in CASES if case["hunt"] == hunt]
        assert any(case["expected_alerts"] for case in cases)
        assert any(not case["expected_alerts"] for case in cases)


def test_changed_threshold_changes_real_fixture_outcome():
    case = next(case for case in CASES if case["name"] == "brute_9_below_threshold")
    rule = load_hunt(BRUTE)
    assert evaluate_hunt(rule, case["events"])["alerts"] == []
    rule["having"][0]["value"] = 9
    result = evaluate_hunt(rule, case["events"])
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["fails"] == 9


def test_conflicting_event_id_is_a_failure_not_arbitrary_deduplication():
    case = next(case for case in CASES if case["name"] == "brute_10_threshold")
    events = deepcopy(case["events"])
    conflict = dict(events[0], **{"target.user": "another-account"})
    with pytest.raises(HuntError, match="conflicting duplicate"):
        evaluate_hunt(load_hunt(BRUTE), events + [conflict])


def test_equivalent_timestamp_representation_deduplicates():
    event = deepcopy(CASES[0]["events"][0])
    duplicate = dict(event, **{"@timestamp": "2026-01-01T03:01:00+03:00"})
    events, counts = prepare_events([event, duplicate])
    assert len(events) == 1
    assert counts["duplicate_events"] == 1


@pytest.mark.parametrize("changed", [True, 1.0])
def test_different_payload_types_with_same_id_conflict(changed):
    event = dict(CASES[0]["events"][0], extra=1)
    duplicate = dict(event, extra=changed)
    with pytest.raises(HuntError, match="conflicting duplicate"):
        prepare_events([event, duplicate])


@pytest.mark.parametrize("field,value", [
    ("event.id", None), ("event.id", ""), ("event.id", " "),
    ("event.dataset", None), ("event.dataset", ""),
    ("@timestamp", "2026-01-01T00:00:00"),
    ("@timestamp", "2026-01-01T00:00:00.9999999Z"),
    ("@timestamp", "2026-01-01"), ("@timestamp", None),
    ("@timestamp", "not a timestamp"),
])
def test_invalid_envelope_fails_with_no_successful_result(field, value):
    event = dict(CASES[0]["events"][0])
    event[field] = value
    with pytest.raises(HuntError):
        evaluate_hunt(load_hunt(BRUTE), [event])


@pytest.mark.parametrize("value", [None, "", " ", [], {}, True, 123])
def test_bad_group_values_are_counted_as_rejected(value):
    event = dict(CASES[0]["events"][0], **{"target.user": value})
    result = evaluate_hunt(load_hunt(BRUTE), [event])
    assert result["summary"]["rejected_events"] == 1
    assert result["alerts"] == []


def test_missing_field_under_not_does_not_turn_into_positive_evidence():
    term = {"not": {"field": "missing", "op": "eq", "value": "trusted"}}
    assert predicate_matches(term, {}) is None
    assert predicate_matches({"any": [term, {"field": "n", "op": "eq", "value": 1}]}, {"n": 1}) is True
    assert predicate_matches({"all": [term, {"field": "n", "op": "eq", "value": 1}]}, {"n": 2}) is False


@pytest.mark.parametrize("actual,expected", [(4625, "4625"), (True, 1), (False, 0), ("0", 0)])
def test_incompatible_types_do_not_become_matches_under_negative_conditions(actual, expected):
    term = {"field": "value", "op": "eq", "value": expected}
    event = {"value": actual}
    assert predicate_matches(term, event) is None
    assert predicate_matches({"not": term}, event) is None
    assert predicate_matches(dict(term, op="ne"), event) is None
    assert predicate_matches(dict(term, op="in", value=[expected]), event) is None


def test_membership_uses_only_compatible_types():
    term = {"field": "value", "op": "in", "value": ["known", 1]}
    assert predicate_matches(term, {"value": "known"}) is True
    assert predicate_matches(term, {"value": "other"}) is False
    assert predicate_matches(term, {"value": True}) is None


@pytest.mark.parametrize("actual", [4625, True, None])
def test_event_codes_are_not_coerced(actual):
    rule = load_hunt(BRUTE)
    event = dict(CASES[0]["events"][0], **{"event.code": actual})
    assert evaluate_hunt(rule, [event])["alerts"] == []
    assert predicate_matches(rule["where"], event) is not True


def test_unsupported_legacy_hunt_fails_instead_of_ignoring_first_seen():
    path = ROOT / "techniques/T1078_Valid_Accounts/hunts/win_valid_logon_unusual_src.hunt.yaml"
    with pytest.raises(HuntError, match="explicitly versioned"):
        load_hunt(path)


@pytest.mark.parametrize("change", [
    lambda rule: rule.update(first_seen={"key": ["target.user"], "horizon": "30d"}),
    lambda rule: rule["aggregate"].update(window_type="sliding"),
    lambda rule: rule["aggregate"]["metrics"][0].update(fn="count_if"),
    lambda rule: rule["aggregate"].update(window="0m"),
    lambda rule: rule["aggregate"].update(window="32d"),
    lambda rule: rule["project"].append("ungrouped.path"),
    lambda rule: rule["having"][0].update(field="missing.metric"),
    lambda rule: rule["aggregate"]["metrics"].append(dict(rule["aggregate"]["metrics"][0])),
    lambda rule: rule["aggregate"]["metrics"][0].update(name="source.ip"),
])
def test_unsupported_or_ambiguous_rules_fail_before_execution(change):
    rule = load_hunt(BRUTE)
    change(rule)
    with pytest.raises(HuntError):
        evaluate_hunt(rule, CASES[0]["events"])


def test_duplicate_yaml_keys_fail(tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text(BRUTE.read_text() + "\ndataset: other\n")
    with pytest.raises(HuntError, match="duplicate YAML key"):
        load_hunt(path)


def test_duplicate_json_keys_fail_instead_of_reinterpreting_event(tmp_path):
    path = tmp_path / "ambiguous.jsonl"
    path.write_text('{"event.code": "4624", "event.code": "4625"}\n')
    with pytest.raises(HuntError, match="duplicate JSON key"):
        read_jsonl(path)


def test_replay_is_order_independent_and_projects_only_declared_fields():
    case = next(case for case in CASES if case["name"] == "brute_10_threshold")
    rule = load_hunt(BRUTE)
    forward = evaluate_hunt(rule, case["events"])
    reverse = evaluate_hunt(rule, reversed(case["events"]))
    assert forward == reverse
    assert set(forward["alerts"][0]) == set(rule["project"])


def test_multiple_qualifying_windows_are_not_merged():
    events = deepcopy(next(case for case in CASES if case["name"] == "brute_10_threshold")["events"])
    later = [dict(event, **{"event.id": event["event.id"] + ":later", "@timestamp": "2026-01-01T00:05:00Z"})
             for event in events]
    result = evaluate_hunt(load_hunt(BRUTE), events + later)
    assert [row["window.start"] for row in result["alerts"]] == [
        "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z"]
    assert [row["fails"] for row in result["alerts"]] == [10, 10]


def test_timezone_is_normalized_without_losing_boundary_precision():
    assert format_timestamp(parse_timestamp("2026-01-01T03:04:59.999999+03:00")) == "2026-01-01T00:04:59.999999Z"


@pytest.mark.parametrize("offset", ["+00:60", "-00:60", "+03:99", "+24:00", "-24:01"])
def test_invalid_timezone_offset_components_are_not_normalized(offset):
    with pytest.raises(HuntError, match="timestamp"):
        parse_timestamp("2026-01-02T12:00:00.123456" + offset)


@pytest.mark.parametrize("source,expected", [
    ("2026-01-02T12:00:00+23:59", "2026-01-01T12:01:00Z"),
    ("2026-01-02T12:00:00-23:59", "2026-01-03T11:59:00Z"),
    ("2026-01-02T12:00:00+00:59", "2026-01-02T11:01:00Z"),
])
def test_rfc3339_offset_component_boundaries_remain_supported(source, expected):
    assert format_timestamp(parse_timestamp(source)) == expected


def test_cli_replays_reviewed_example():
    process = subprocess.run(
        [sys.executable, "tools/hunt_engine.py", str(BRUTE), "--events", str(FIXTURES / "brute_positive.jsonl")],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["alerts"] == json.loads((FIXTURES / "brute_positive.expected.json").read_text())


def test_cli_fails_on_empty_input(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    process = subprocess.run(
        [sys.executable, "tools/hunt_engine.py", str(BRUTE), "--events", str(empty)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert process.returncode != 0
    assert "no events" in process.stderr
