"""Independent O(n²) rolling-window oracle for bounded deterministic event sets.

The reference uses datetime comparisons, complete list scans and set counting.
It deliberately does not reuse the production queue, predicate, grouping,
timestamp, or event-preparation helpers. Generated inputs use a simple fixed
predicate so differences measure rolling-window and observation semantics.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random

import pytest

from tools.rolling_hunt import evaluate_hunt, load_hunt


ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOW = timedelta(minutes=5)
WINDOW_US = 300_000_000
DATASET = "windows.security.logons"


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.astimezone(timezone.utc)


def text_time(value):
    return utc(value).isoformat().replace("+00:00", "Z")


def stable_rows(rows):
    return sorted(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows)


def rule_for(mode="count", *, threshold=1):
    if mode == "count":
        groups = ["source.ip", "target.user"]
        metrics = [{"name": "fails", "fn": "count", "field": "*"}]
        having = [{"field": "fails", "op": "gte", "value": threshold}]
    elif mode == "distinct":
        groups = ["source.ip"]
        metrics = [{"name": "users", "fn": "count_distinct", "field": "target.user"}]
        having = [{"field": "users", "op": "gte", "value": threshold}]
    else:
        assert mode == "both"
        groups = ["source.ip"]
        metrics = [{"name": "fails", "fn": "count", "field": "*"},
                   {"name": "users", "fn": "count_distinct", "field": "target.user"}]
        having = [{"field": "fails", "op": "gte", "value": threshold},
                  {"field": "users", "op": "gte", "value": 2}]
    return {
        "schema_version": 2, "dataset": DATASET,
        "where": {"all": [{"field": "event.code", "op": "eq", "value": "4625"}]},
        "aggregate": {"group_by": groups, "window": "5m", "window_type": "rolling", "metrics": metrics},
        "having": having,
        "project": ["window.start", "window.end", *groups, *[metric["name"] for metric in metrics]],
    }


def event(identifier, offset_us, *, user="alice", ip="192.0.2.1", base=BASE, **changes):
    return {
        "@timestamp": text_time(base + timedelta(microseconds=offset_us)),
        "event.id": str(identifier), "event.dataset": DATASET,
        "event.code": "4625", "source.ip": ip, "target.user": user,
        **changes,
    }


def oracle(rule, events, *, start=None, end=None):
    """Mathematical evaluation at each unique eligible group timestamp."""
    unique = {}
    for raw in events:
        row = deepcopy(raw)
        row["@timestamp"] = text_time(row["@timestamp"])
        identifier = row["event.id"]
        if identifier in unique:
            if json.dumps(unique[identifier], sort_keys=True) != json.dumps(row, sort_keys=True):
                raise ValueError("conflicting duplicate in oracle input")
        unique[identifier] = row

    groups = rule["aggregate"]["group_by"]
    metrics = rule["aggregate"]["metrics"]
    required_keys = set(groups) | {metric["field"] for metric in metrics if metric["fn"] == "count_distinct"}
    eligible = [row for row in unique.values()
                if row["event.dataset"] == rule["dataset"] and row.get("event.code") == "4625"
                and all(isinstance(row.get(key), str) and row[key].strip() for key in required_keys)]
    # No queue, expiry counter, or incremental state is used by this oracle.
    anchors = {(tuple(row[key] for key in groups), utc(row["@timestamp"])) for row in eligible}
    answers = []
    width = int(rule["aggregate"]["window"][:-1]) * {
        "s": timedelta(seconds=1), "m": timedelta(minutes=1),
        "h": timedelta(hours=1), "d": timedelta(days=1),
    }[rule["aggregate"]["window"][-1]]
    for group, anchor in anchors:
        if start is not None and not utc(start) <= anchor < utc(end):
            continue
        population = [row for row in eligible
                      if tuple(row[key] for key in groups) == group
                      and anchor - width < utc(row["@timestamp"]) <= anchor]
        values = {
            metric["name"]: (len(population) if metric["fn"] == "count"
                             else len({row[metric["field"]] for row in population}))
            for metric in metrics
        }
        if all(values[term["field"]] >= term["value"] for term in rule["having"]):
            full = {"window.start": text_time(anchor - width), "window.end": text_time(anchor),
                    **dict(zip(groups, group)), **values}
            answers.append({key: full[key] for key in rule["project"]})
    return answers


def assert_matches_oracle(rule, events, **bounds):
    expected = oracle(rule, events, **bounds)
    actual = evaluate_hunt(rule, events, **bounds)["alerts"]
    assert stable_rows(actual) == stable_rows(expected)
    assert actual == sorted(actual, key=lambda row: (
        utc(row["window.end"]), tuple(row[field] for field in rule["aggregate"]["group_by"])))
    return actual


def test_lower_boundary_is_exclusive_with_exact_microsecond_precision():
    rule = rule_for()
    events = [event("at-zero", 0), event("just-before", WINDOW_US - 1),
              event("at-edge", WINDOW_US), event("just-after", WINDOW_US + 1)]
    actual = assert_matches_oracle(rule, events)
    assert {row["window.end"]: row["fails"] for row in actual} == {
        text_time(BASE): 1,
        text_time(BASE + WINDOW - timedelta(microseconds=1)): 2,
        text_time(BASE + WINDOW): 2,
        text_time(BASE + WINDOW + timedelta(microseconds=1)): 3,
    }


def test_equal_timestamp_events_are_one_atomic_group_anchor():
    rule = rule_for(threshold=2)
    anchor = 123_456_789
    events = [event("same-a", anchor), event("same-b", anchor), event("same-c", anchor),
              event("other-user", anchor, user="bob"), event("other-ip", anchor, ip="192.0.2.2")]
    actual = assert_matches_oracle(rule, events)
    assert len(actual) == 1
    assert actual[0]["fails"] == 3
    assert actual[0]["target.user"] == "alice" and actual[0]["source.ip"] == "192.0.2.1"


def test_filtered_events_do_not_create_anchors_for_an_already_qualifying_group():
    events = [event("eligible", 0),
              event("successful-logon", 123_456, **{"event.code": "4624"}),
              event("other-dataset", 234_567, **{"event.dataset": "other.dataset"})]
    actual = assert_matches_oracle(rule_for(), events)
    assert len(actual) == 1 and actual[0]["window.end"] == text_time(BASE)


def test_distinct_value_survives_until_its_last_event_expires():
    rule = rule_for("distinct")
    events = [event("alice-old", 0), event("alice-recent", WINDOW_US - 1),
              event("bob", WINDOW_US, user="bob"),
              event("carol", 2 * WINDOW_US - 1, user="carol"),
              event("dave", 2 * WINDOW_US, user="dave")]
    actual = assert_matches_oracle(rule, events)
    assert {row["window.end"]: row["users"] for row in actual} == {
        text_time(BASE): 1,
        text_time(BASE + WINDOW - timedelta(microseconds=1)): 1,
        text_time(BASE + WINDOW): 2,
        text_time(BASE + 2 * WINDOW - timedelta(microseconds=1)): 2,
        text_time(BASE + 2 * WINDOW): 2,
    }


@pytest.mark.parametrize("mode", ["count", "distinct", "both"])
@pytest.mark.parametrize("seed", [3, 19, 41, 83])
def test_deterministic_generated_cases_agree_with_quadratic_oracle(mode, seed):
    rng = random.Random(seed)
    rule = rule_for(mode, threshold=3)
    edge_offsets = [-WINDOW_US - 1, -WINDOW_US, -WINDOW_US + 1, -1, 0, 1,
                    WINDOW_US - 1, WINDOW_US, WINDOW_US + 1, 2 * WINDOW_US, 3 * WINDOW_US]
    # A pre-epoch base also catches accidental epoch truncation/float rounding.
    base = datetime(1969, 12, 31, 23, 58, tzinfo=timezone.utc)
    events = [event(f"generated-{index}", rng.choice(edge_offsets) if index % 2 else
                    rng.randrange(-WINDOW_US, 3 * WINDOW_US), base=base,
                    user=rng.choice(["alice", "bob", "carol", "dave"]),
                    ip=rng.choice(["192.0.2.1", "192.0.2.2"])) for index in range(100)]
    events.extend([event("irrelevant-code", 1, base=base, **{"event.code": "4624"}),
                   event("irrelevant-dataset", 2, base=base, **{"event.dataset": "other.dataset"}),
                   event("missing-group", 3, base=base, **{"source.ip": None}),
                   event("bad-user", 4, base=base, **{"target.user": []})])
    events.extend(deepcopy(events[:7]))
    rng.shuffle(events)
    actual = assert_matches_oracle(rule, events)
    assert actual, "Generated case must exercise matching anchors"
    assert actual == evaluate_hunt(rule, list(reversed(events)))["alerts"]
    assert actual == evaluate_hunt(rule, events + deepcopy(events))["alerts"]


@pytest.mark.parametrize("mode", ["count", "distinct", "both"])
def test_partitioned_anchor_ranges_with_prior_window_context_equal_whole_run(mode):
    rng = random.Random(211)
    rule = rule_for(mode, threshold=2)
    offsets = [-WINDOW_US, -WINDOW_US + 1, -1, 0, 1, WINDOW_US - 1, WINDOW_US,
               WINDOW_US + 1, 2 * WINDOW_US - 1, 2 * WINDOW_US, 3 * WINDOW_US - 1,
               3 * WINDOW_US]
    events = [event(f"partition-{index}", offset, user=user)
              for index, (offset, user) in enumerate((offset, user) for offset in offsets for user in ("alice", "bob"))]
    events.extend(event(f"extra-{index}", rng.randrange(-WINDOW_US, 3 * WINDOW_US), user="carol")
                  for index in range(30))
    # V2 anchor bounds do not require epoch/window alignment.
    bounds = [BASE, BASE + WINDOW + timedelta(microseconds=1),
              BASE + 2 * WINDOW - timedelta(microseconds=1), BASE + 3 * WINDOW]
    whole = assert_matches_oracle(rule, events, start=text_time(bounds[0]), end=text_time(bounds[-1]))
    partitioned = []
    for lower, upper in zip(bounds, bounds[1:]):
        context = [row for row in events if lower - WINDOW < utc(row["@timestamp"]) < upper]
        rng.shuffle(context)
        partial = assert_matches_oracle(rule, context, start=lower, end=upper)
        assert all(lower <= utc(alert["window.end"]) < upper for alert in partial)
        partitioned.extend(partial)
    assert stable_rows(partitioned) == stable_rows(whole)
    assert len(stable_rows(partitioned)) == len(set(stable_rows(partitioned)))


def test_duplicate_timestamp_representations_do_not_create_extra_anchor_or_count():
    rule = rule_for(threshold=2)
    events = [event("a", 123_456), event("b", 123_456)]
    duplicate = deepcopy(events[0])
    duplicate["@timestamp"] = "2026-01-01T03:00:00.123456+03:00"
    actual = assert_matches_oracle(rule, events + [duplicate])
    assert len(actual) == 1 and actual[0]["fails"] == 2


def test_same_observation_id_with_changed_payload_is_a_failure():
    original = event("same", 0)
    changed = {**original, "target.user": "changed"}
    with pytest.raises(ValueError):
        evaluate_hunt(rule_for(), [original, changed])


@pytest.mark.parametrize("path", [
    "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml",
    "techniques/T1110_Brute_Force/hunts/win_4625_spray_agg_rolling.hunt.yaml",
])
def test_stored_windows_rules_match_independent_oracle_across_tumbling_boundary(path):
    rule = load_hunt(ROOT / path)
    # 9 failures before 00:05 and 9 after; distinct users also cross that boundary.
    events = [event(f"brute-{index}", WINDOW_US - 1 if index < 9 else WINDOW_US + 1)
              for index in range(18)]
    events.extend(event(f"spray-{index}", WINDOW_US - 1 if index < 9 else WINDOW_US + 1,
                        user=f"user-{index}", ip="192.0.2.2") for index in range(18))
    actual = assert_matches_oracle(rule, events)
    assert actual
    assert all(row["window.end"] == text_time(BASE + WINDOW + timedelta(microseconds=1)) for row in actual)
