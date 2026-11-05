"""Rolling v2 contract, failure boundaries and finite replay limits."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.hunt_engine import HuntError, load_hunt as load_v1
from tools.rolling_hunt import evaluate_hunt, event_time_bounds, load_hunt, validate_hunt

ROOT = Path(__file__).resolve().parents[1]
HUNTS = ROOT / "techniques/T1110_Brute_Force/hunts"
BRUTE = HUNTS / "win_4625_brute_agg_rolling.hunt.yaml"
SPRAY = HUNTS / "win_4625_spray_agg_rolling.hunt.yaml"
SSH = HUNTS / "linux_ssh_failed_agg_rolling.hunt.yaml"


def event(identifier="one", timestamp="2026-01-01T00:05:00Z", **changes):
    return {
        "@timestamp": timestamp, "event.id": identifier,
        "event.dataset": "windows.security.logons", "event.code": "4625",
        "source.ip": "192.0.2.10", "target.user": "alice", **changes,
    }


def threshold_one():
    rule = load_hunt(BRUTE)
    rule["having"][0]["value"] = 1
    return rule


@pytest.mark.parametrize("path", [BRUTE, SPRAY, SSH])
def test_new_rules_are_explicitly_v2_with_complete_projection(path):
    rule = load_hunt(path)
    assert rule["schema_version"] == 2
    assert rule["aggregate"]["window_type"] == "rolling"
    assert set(rule["project"]) == (
        set(rule["aggregate"]["group_by"]) |
        {metric["name"] for metric in rule["aggregate"]["metrics"]} |
        {"window.start", "window.end"}
    )


def test_versions_are_not_reinterpreted_by_either_engine():
    with pytest.raises(HuntError, match="schema_version: 2"):
        load_hunt(HUNTS / "win_4625_brute_agg.hunt.yaml")
    with pytest.raises(HuntError, match="schema_version: 1"):
        load_v1(BRUTE)


@pytest.mark.parametrize("value", [True, False, 1, 2.0, "2", None])
def test_version_requires_literal_integer_two(value):
    rule = load_hunt(BRUTE)
    rule["schema_version"] = value
    with pytest.raises(HuntError):
        validate_hunt(rule)


@pytest.mark.parametrize("change", [
    lambda rule: rule.update(first_seen={"key": ["source.ip"], "horizon": "30d"}),
    lambda rule: rule.update(sequence=[]),
    lambda rule: rule["aggregate"].update(window_type="tumbling"),
    lambda rule: rule["aggregate"].update(window_type="sliding"),
    lambda rule: rule["aggregate"].update(window="0m"),
    lambda rule: rule["aggregate"].update(window="32d"),
    lambda rule: rule["aggregate"]["metrics"][0].update(fn="count_if"),
    lambda rule: rule["aggregate"]["metrics"][0].update(field="target.user"),
    lambda rule: rule["aggregate"]["metrics"].append(deepcopy(rule["aggregate"]["metrics"][0])),
    lambda rule: rule["aggregate"]["metrics"][0].update(name="source.ip"),
    lambda rule: rule["aggregate"]["group_by"].append("window.start"),
    lambda rule: rule["aggregate"]["group_by"].append("source.ip"),
    lambda rule: rule["project"].remove("window.start"),
    lambda rule: rule["project"].remove("target.user"),
    lambda rule: rule["project"].remove("fails"),
    lambda rule: rule["project"].append("unknown"),
    lambda rule: rule["having"][0].update(field="unknown"),
    lambda rule: rule["where"]["all"][0].update(op="unsupported"),
])
def test_unsupported_or_ambiguous_rule_fails_before_input_consumption(change):
    rule = load_hunt(BRUTE)
    change(rule)

    def unread():
        raise AssertionError("invalid rules must fail before reading events")
        yield

    with pytest.raises(HuntError):
        evaluate_hunt(rule, unread())


@pytest.mark.parametrize("op,value", [
    ("eq", 10), ("gt", 10), ("lt", 10), ("lte", 10), ("ne", 10),
    ("gte", 0), ("gte", -1), ("gte", 1.0), ("gte", True),
    ("gte", "10"), ("gte", float("nan")), ("gte", float("inf")),
])
def test_having_is_only_positive_integer_monotonic_threshold(op, value):
    rule = load_hunt(BRUTE)
    rule["having"][0].update(op=op, value=value)
    with pytest.raises(HuntError):
        validate_hunt(rule)


@pytest.mark.parametrize("name", ["max_events", "max_alerts"])
@pytest.mark.parametrize("value", [0, -1, True, 1.0, "10", None])
def test_caps_must_be_positive_integer(name, value):
    with pytest.raises(HuntError, match=name):
        evaluate_hunt(load_hunt(BRUTE), [], **{name: value})


@pytest.mark.parametrize("events", [
    [event(), event()],
    [event("one", **{"event.dataset": "unrelated"}), event("two", **{"event.dataset": "unrelated"})],
    [event("one", timestamp="2025-01-01T00:00:00Z"), event("two", timestamp="2025-01-01T00:00:00Z")],
])
def test_raw_cap_applies_before_dedup_filtering_or_time_selection(events):
    with pytest.raises(HuntError, match="max_events exceeded"):
        evaluate_hunt(
            load_hunt(BRUTE), events, max_events=1,
            start="2026-01-01T00:00:00Z", end="2026-01-01T01:00:00Z",
        )


def test_stream_cap_does_not_read_past_first_excess_record():
    consumed = []

    def stream():
        for number in range(10):
            consumed.append(number)
            yield event(str(number))

    with pytest.raises(HuntError, match="max_events exceeded"):
        evaluate_hunt(load_hunt(BRUTE), stream(), max_events=2)
    assert consumed == [0, 1, 2]


def test_output_cap_counts_group_timestamps_not_tied_events():
    rule = threshold_one()
    events = [event(str(number)) for number in range(20)]
    result = evaluate_hunt(rule, events, max_events=20, max_alerts=1)
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["fails"] == 20
    assert result["summary"]["anchors_evaluated"] == 1
    events.append(event("later", timestamp="2026-01-01T00:05:00.000001Z"))
    with pytest.raises(HuntError, match="max_alerts exceeded"):
        evaluate_hunt(rule, events, max_alerts=1)


def test_output_cap_is_global_across_groups():
    with pytest.raises(HuntError, match="max_alerts exceeded"):
        evaluate_hunt(
            threshold_one(), [event("alice"), event("bob", **{"target.user": "bob"})],
            max_alerts=1,
        )


def test_sort_is_chronological_at_whole_second_and_microsecond_anchors():
    result = evaluate_hunt(threshold_one(), [
        event("later", "2026-01-01T00:05:00.000001Z"),
        event("earlier", "2026-01-01T00:05:00Z"),
    ])
    assert [row["window.end"] for row in result["alerts"]] == [
        "2026-01-01T00:05:00Z", "2026-01-01T00:05:00.000001Z",
    ]


def test_summary_distinguishes_context_filtered_rejected_and_outside_events():
    rule = threshold_one()
    result = evaluate_hunt(rule, [
        event("context", "2026-01-01T00:04:00Z"),
        event("anchor", "2026-01-01T00:05:00Z"),
        event("anchor", "2026-01-01T00:05:00Z"),
        event("excluded-left", "2026-01-01T00:00:00Z"),
        event("excluded-end", "2026-01-01T00:06:00Z"),
        event("other-dataset", **{"event.dataset": "other"}),
        event("wrong-code", **{"event.code": "4624"}),
        event("missing-group", **{"target.user": None}),
        event("missing-predicate", **{"event.code": None}),
    ], start="2026-01-01T00:05:00Z", end="2026-01-01T00:06:00Z")
    assert result["summary"] == {
        "input_events": 9, "unique_events": 8, "duplicate_events": 1,
        "filtered_events": 2, "rejected_events": 2, "out_of_range_events": 2,
        "matched_events": 2, "context_events": 1, "anchors_evaluated": 1, "alerts": 1,
    }
    assert result["alerts"][0]["fails"] == 2


@pytest.mark.parametrize("start,end", [
    (None, "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:00Z", None),
    ("2026-01-01T00:05:00Z", "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:06:00Z", "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:00", "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:00+03:60", "2026-01-01T00:05:00Z"),
    ("malformed", "2026-01-01T00:05:00Z"),
    (datetime(2026, 1, 1), datetime(2026, 1, 2, tzinfo=timezone.utc)),
])
def test_invalid_anchor_bounds_fail(start, end):
    with pytest.raises(HuntError):
        evaluate_hunt(load_hunt(BRUTE), [], start=start, end=end)


def test_non_aligned_microsecond_bounds_are_valid_and_normalized():
    start, end = event_time_bounds(
        "2026-01-01T03:01:02.000001+03:00", "2026-01-01T00:01:03.000002Z",
    )
    assert start == datetime(2026, 1, 1, 0, 1, 2, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 1, 1, 0, 1, 3, 2, tzinfo=timezone.utc)


def test_missing_and_nonstring_distinct_values_are_rejected_not_counted():
    rule = load_hunt(SPRAY)
    rule["having"][0]["value"] = 1
    result = evaluate_hunt(rule, [
        event("good"), event("null", **{"target.user": None}),
        event("int", **{"target.user": 7}), event("empty", **{"target.user": "  "}),
    ])
    assert result["summary"]["rejected_events"] == 3
    assert result["alerts"][0]["distinct_users"] == 1


def test_duplicate_identity_conflict_fails_whole_replay():
    with pytest.raises(HuntError, match="conflicting duplicate"):
        evaluate_hunt(threshold_one(), [event(), event(**{"target.user": "bob"})])


def test_duplicate_yaml_key_is_rejected(tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text(BRUTE.read_text() + "\nschema_version: 2\n")
    with pytest.raises(HuntError, match="duplicate YAML key"):
        load_hunt(path)


def cli(path, *extra):
    return subprocess.run(
        [sys.executable, "tools/rolling_hunt.py", str(BRUTE), "--events", str(path), *extra],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


def test_cli_replays_real_rule_with_bounds_and_limits(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(event(str(i))) + "\n" for i in range(10)))
    process = cli(path, "--start", "2026-01-01T00:05:00Z", "--end", "2026-01-01T00:05:00.000001Z",
                  "--max-events", "10", "--max-alerts", "1")
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["alerts"] == [{
        "window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:05:00Z",
        "source.ip": "192.0.2.10", "target.user": "alice", "fails": 10,
    }]


@pytest.mark.parametrize("contents,extra,error", [
    ("", [], "no events"),
    ('{"event.id":"first","event.id":"second"}\n', [], "duplicate JSON key"),
    ('{"broken":\n', [], "invalid JSON"),
    (json.dumps(event()) + "\n" + json.dumps(event()) + "\n", ["--max-events", "1"], "max_events exceeded"),
])
def test_cli_failures_never_print_partial_json(tmp_path, contents, extra, error):
    path = tmp_path / "input.jsonl"
    path.write_text(contents)
    process = cli(path, *extra)
    assert process.returncode != 0
    assert error in process.stderr
    assert process.stdout == ""
