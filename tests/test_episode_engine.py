"""Independent examples for the exact alert-anchor episode contract."""
from copy import deepcopy
from datetime import timedelta
import itertools
import json
from pathlib import Path

import pytest

from tools.episode_engine import EpisodeError, gap_microseconds, group_episodes, policy_scope
from tools.hunt_engine import format_timestamp, parse_timestamp


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/episodes/cases.json").read_text())
BASE = parse_timestamp(MANIFEST["base_timestamp"])
EPOCH = parse_timestamp("1970-01-01T00:00:00Z")
DELTA = BASE - EPOCH
BASE_US = (DELTA.days * 86400 + DELTA.seconds) * 1_000_000
SCOPE = "raw-scope"


def alert(identifier="a", offset=0, *, status="active", revision=1,
          user="alice", rule="rule-one", metrics=None):
    anchor = BASE + timedelta(microseconds=offset)
    return {"alert_id": identifier, "scope_id": SCOPE, "rule_id": rule,
            "status": status, "revision": revision,
            "group": {"source.ip": "192.0.2.1", "target.user": user},
            "metrics": {"fails": 10} if metrics is None else deepcopy(metrics),
            "@timestamp": format_timestamp(anchor),
            "window": {"start": format_timestamp(anchor - timedelta(minutes=5)),
                       "end": format_timestamp(anchor)}}


def group(alerts, *, offset=100, gap=10, checkpoints=None, **kwargs):
    checkpoints = ({"rule-one": BASE_US + offset, "rule-two": BASE_US + offset}
                   if checkpoints is None else checkpoints)
    return group_episodes(alerts, source_scope_id=SCOPE, checkpoints=checkpoints,
                          gap=timedelta(microseconds=gap), **kwargs)


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["name"])
def test_hand_declared_components(case):
    events = [alert(record["id"], **{key: value for key, value in record.items() if key != "id"})
              for record in case["alerts"]]
    original = deepcopy(events)
    result = group(events, offset=case["checkpoint_offset_microseconds"], gap=case["gap_microseconds"])
    observed = [{"members": row["member_alert_ids"], "status": row["status"],
                 "peak_metrics": row["peak_metrics"]} for row in result]
    assert observed == case["expected"]
    assert events == original
    for row in result:
        assert row["anchor_count"] == len(row["member_alert_ids"])
        assert row["member_revisions"] == {event["alert_id"]: event["revision"]
                                          for event in events if event["alert_id"] in row["member_alert_ids"]}
        assert set(row) == {"episode_id", "scope_id", "source_scope_id", "policy_version",
                            "gap_microseconds", "rule_id", "group", "status", "first_anchor",
                            "last_anchor", "anchor_count", "peak_metrics", "member_alert_ids",
                            "member_revisions"}


def test_identity_preserved_by_append_and_raw_metric_revision():
    original = alert("a")
    first = group([original])[0]
    revised = alert("a", metrics={"fails": 12}, revision=2)
    after = group([revised, alert("b", 1)])[0]
    assert first["episode_id"] == after["episode_id"]
    assert after["member_revisions"] == {"a": 2, "b": 1}
    assert after["peak_metrics"] == {"fails": 12}


def test_earlier_member_changes_identity_and_first_removal_recovers_prior_identity():
    first = group([alert("b", 1)])[0]
    with_earlier = group([alert("b", 1), alert("a", 0)])[0]
    removed = group([alert("b", 1), alert("a", 0, status="retracted", revision=2)])[0]
    assert first["episode_id"] != with_earlier["episode_id"]
    assert removed["episode_id"] == first["episode_id"]


def test_late_bridge_merge_and_retraction_split_use_deterministic_earliest_identity():
    separate = group([alert("a", 0), alert("c", 20)])
    merged = group([alert("a", 0), alert("b", 10), alert("c", 20)])
    split = group([alert("a", 0), alert("b", 10, status="retracted", revision=2), alert("c", 20)])
    assert len(separate) == len(split) == 2
    assert len(merged) == 1
    assert merged[0]["episode_id"] == separate[0]["episode_id"]
    assert [row["episode_id"] for row in separate] == [row["episode_id"] for row in split]


def test_closed_episode_can_reopen_with_late_extension():
    closed = group([alert("a", 0)], offset=12)[0]
    reopened = group([alert("a", 0), alert("b", 10)], offset=12)[0]
    assert closed["status"] == "closed"
    assert reopened["status"] == "open"
    assert closed["episode_id"] == reopened["episode_id"]


def test_each_rule_uses_its_own_checkpoint_for_closure():
    rows = group([alert("a", rule="rule-one"), alert("b", rule="rule-two")],
                 checkpoints={"rule-one": BASE_US + 10, "rule-two": BASE_US + 11})
    assert {row["rule_id"]: row["status"] for row in rows} == {"rule-one": "open", "rule-two": "closed"}


def test_advancing_checkpoint_without_closure_or_content_change_keeps_exact_core():
    events = [alert("a")]
    assert group(events, offset=1) == group(events, offset=10)
    assert group(events, offset=11) == group(events, offset=100)


def test_components_and_identity_do_not_depend_on_input_order_or_group_dict_order():
    events = [alert("a", 0), alert("b", 10), alert("c", 21), alert("d", 21, user="bob")]
    expected = group(events)
    for permuted in itertools.permutations(events):
        assert group(list(permuted)) == expected
    reordered = deepcopy(events)
    for row in reordered:
        row["group"] = dict(reversed(list(row["group"].items())))
    assert group(reordered) == expected


def test_source_rule_group_and_policy_changes_isolate_identity():
    baseline = group([alert()])[0]["episode_id"]
    assert group([alert(user="bob")])[0]["episode_id"] != baseline
    assert group([alert(rule="rule-two")])[0]["episode_id"] != baseline
    assert group([alert()], gap=11)[0]["episode_id"] != baseline
    event = alert()
    event["scope_id"] = "other-scope"
    changed = group_episodes([event], source_scope_id="other-scope",
                             checkpoints={"rule-one": BASE_US + 100}, gap=timedelta(microseconds=10))
    assert changed[0]["episode_id"] != baseline


def test_operational_caps_do_not_change_identity_or_content():
    events = [alert("a"), alert("b", 1)]
    assert group(events, max_episodes=1, max_members=2) == group(events, max_episodes=100, max_members=100)


def test_checkpoint_is_exclusive_even_for_retracted_anchors():
    for state in ("active", "retracted"):
        with pytest.raises(EpisodeError, match="exclusive checkpoint"):
            group([alert(status=state)], offset=0)


def test_timezone_equivalent_payload_normalizes_output_anchor():
    event = alert()
    event["@timestamp"] = event["window"]["end"] = "2026-01-01T01:10:00+01:00"
    event["window"]["start"] = "2026-01-01T01:05:00+01:00"
    row = group([event])[0]
    assert row["first_anchor"] == row["last_anchor"] == "2026-01-01T00:10:00Z"


@pytest.mark.parametrize("gap", [timedelta(0), timedelta(microseconds=-1), 10, True, None,
                                 timedelta(days=999999999)])
def test_gap_must_be_a_representable_positive_exact_duration(gap):
    with pytest.raises(EpisodeError):
        gap_microseconds(gap)


def test_exact_duration_and_public_policy_namespace():
    gap = timedelta(days=1, seconds=2, microseconds=3)
    assert gap_microseconds(gap) == 86_402_000_003
    assert policy_scope(SCOPE, gap) == policy_scope(SCOPE, timedelta(microseconds=86_402_000_003))
    assert len(policy_scope(SCOPE, gap)) == 64


@pytest.mark.parametrize("kwargs", [{"max_members": 0}, {"max_members": True},
                                    {"max_episodes": 0}, {"max_episodes": 1.5}])
def test_invalid_caps_fail_before_projection(kwargs):
    with pytest.raises(EpisodeError):
        group([], **kwargs)


def test_member_limit_fails_whole_projection_and_does_not_change_source():
    events = [alert("a", 0), alert("b", 1), alert("z", 30)]
    original = deepcopy(events)
    with pytest.raises(EpisodeError, match="max_members"):
        group(events, max_members=1)
    assert events == original


def test_episode_limit_fails_when_an_additional_component_is_found():
    with pytest.raises(EpisodeError, match="max_episodes"):
        group([alert("a", 0), alert("b", 11)], max_episodes=1)


@pytest.mark.parametrize("mutate", [
    lambda row: row.pop("metrics"),
    lambda row: row.update(alert_id=" "),
    lambda row: row.update(scope_id="other"),
    lambda row: row.update(rule_id="missing-rule"),
    lambda row: row.update(status="closed"),
    lambda row: row.update(revision=True),
    lambda row: row.update(revision=0),
    lambda row: row.update(group={}),
    lambda row: row.update(group={"user": 1}),
    lambda row: row.update(group={False: "alice"}),
    lambda row: row.update(metrics={}),
    lambda row: row.update(metrics={"fails": -1}),
    lambda row: row.update(metrics={"fails": True}),
    lambda row: row.update(metrics={"fails": 1.0}),
    lambda row: row.update(window={"start": row["window"]["start"]}),
    lambda row: row.update(window={"start": row["window"]["end"], "end": row["window"]["end"]}),
    lambda row: row.update({"@timestamp": "2026-01-01T00:10:01Z"}),
    lambda row: row["window"].update(end="2026-01-01T00:10:00.0000001Z"),
    lambda row: row["window"].update(start="1969-12-31T23:59:59Z"),
    lambda row: row["window"].update(end="2263-01-01T00:00:00Z"),
])
def test_malformed_active_and_retracted_rows_cannot_be_hidden(mutate):
    for status in ("active", "retracted"):
        event = alert(status=status)
        mutate(event)
        with pytest.raises(EpisodeError):
            group([event])


@pytest.mark.parametrize("checkpoints", [{}, {"rule-one": True}, {"rule-one": -1},
                                       {"rule-one": 1.2}, {"rule-one": 10**30}, {" ": 1}, []])
def test_invalid_checkpoint_contract(checkpoints):
    with pytest.raises(EpisodeError):
        group([], checkpoints=checkpoints)


def test_duplicate_ids_and_same_logical_anchor_are_rejected_even_when_retracted():
    with pytest.raises(EpisodeError, match="duplicate"):
        group([alert("a"), alert("a", 1)])
    with pytest.raises(EpisodeError, match="duplicate"):
        group([alert("a"), alert("b", status="retracted", revision=2)])


@pytest.mark.parametrize("change", [
    lambda row: row.update(metrics={"users": 15}),
    lambda row: row["group"].pop("target.user"),
    lambda row: row["window"].update(start="2026-01-01T00:00:00.000001Z"),
])
def test_rule_fields_and_window_contract_cannot_change_inside_snapshot(change):
    second = alert("b", 1)
    change(second)
    with pytest.raises(EpisodeError, match="consistent"):
        group([alert("a", 0), second])


def test_no_active_rows_returns_no_episodes_but_complete_input_is_required():
    assert group([]) == []
    with pytest.raises(EpisodeError, match="complete list"):
        group(iter([alert()]))
    with pytest.raises(EpisodeError, match="object"):
        group([None])


def test_date_nanos_upper_boundary_closure_uses_integer_arithmetic():
    # An episode's inactivity end may exceed the timestamp range. It remains
    # open; do not overflow datetime or round its last representable anchor.
    anchor = "2262-04-11T23:47:16.854774Z"
    event = alert()
    event.update({"@timestamp": anchor, "window": {
        "start": "2262-04-11T23:42:16.854774Z", "end": anchor}})
    result = group([event], checkpoints={"rule-one": 9_223_372_036_854_775})
    assert result[0]["status"] == "open"
    assert result[0]["last_anchor"] == anchor
