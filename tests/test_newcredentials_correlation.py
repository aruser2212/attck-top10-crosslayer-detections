"""Independent expected session links, including legitimate and invalid examples."""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.correlate_newcredentials import RULE_ID, correlate
from tools.newcredentials_profile import DATASET

ROOT = Path(__file__).resolve().parents[1]


def logon(identifier="logon-a", **changes):
    return {"@timestamp": "2026-01-01T00:01:00Z", "event.id": identifier,
            "event.dataset": DATASET, "event.code": "4624", "host.name": "host01",
            "host.boot.id": "trusted-boot-a", "session.id": "0x1234",
            "user.id": "S-1-5-21-100-200-300-1001", "win.logon_type": 9,
            "win.logon_process": "seclogo", **changes}


def privilege(identifier="privilege-a", **changes):
    value = logon(identifier, **{"event.code": "4672"})
    del value["win.logon_type"], value["win.logon_process"]
    return {**value, "win.privileges": ["SeDebugPrivilege"], **changes}


def ids(result):
    return [(a["logon.event.id"], a["privilege.event.ids"]) for a in result["alerts"]]


def test_legitimate_runas_netonly_remains_an_expected_candidate_with_linked_evidence():
    result = correlate([logon(), privilege()])
    assert ids(result) == [("logon-a", ["privilege-a"])]
    alert = result["alerts"][0]
    assert alert == {
        "rule.id": RULE_ID,
        "alert.id": "newcredentials:" + hashlib.sha256(json.dumps(
            [RULE_ID, "host01", "trusted-boot-a", "0x1234", "S-1-5-21-100-200-300-1001", "logon-a"],
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
        "@timestamp": "2026-01-01T00:01:00Z", "host.name": "host01",
        "host.boot.id": "trusted-boot-a", "session.id": "0x1234",
        "user.id": "S-1-5-21-100-200-300-1001", "logon.event.id": "logon-a",
        "privilege.event.ids": ["privilege-a"], "privilege.time_deltas_us": [0],
        "win.privileges": ["SeDebugPrivilege"],
    }


@pytest.mark.parametrize("timestamp,expected_delta", [
    ("2026-01-01T00:00:30Z", -30_000_000),
    ("2026-01-01T00:00:59.999999Z", -1),
    ("2026-01-01T00:01:00Z", 0),
    ("2026-01-01T00:01:00.000001Z", 1),
    ("2026-01-01T00:01:30Z", 30_000_000),
])
def test_privilege_before_equal_or_after_logon_with_inclusive_tolerance(timestamp, expected_delta):
    alert = correlate([privilege(**{"@timestamp": timestamp}), logon()])["alerts"][0]
    assert alert["privilege.time_deltas_us"] == [expected_delta]


@pytest.mark.parametrize("timestamp", ["2026-01-01T00:00:29.999999Z", "2026-01-01T00:01:30.000001Z"])
def test_one_microsecond_beyond_either_tolerance_boundary_is_not_linked(timestamp):
    assert correlate([logon(), privilege(**{"@timestamp": timestamp})])["alerts"] == []


def test_zero_tolerance_means_exact_record_time_ties():
    result = correlate([logon(), privilege(), privilege("later", **{"@timestamp": "2026-01-01T00:01:00.000001Z"})],
                       max_skew_seconds=0)
    assert ids(result) == [("logon-a", ["privilege-a"])]


@pytest.mark.parametrize("field,value", [
    ("host.name", "host02"), ("host.boot.id", "trusted-boot-b"), ("session.id", "0x1235"),
])
def test_neighboring_activity_does_not_join_across_any_session_scope_key(field, value):
    assert correlate([logon(), privilege(**{field: value})])["alerts"] == []


def test_same_user_and_host_but_another_luid_does_not_reproduce_legacy_false_join():
    rows = [logon(**{"user.name": "alice"}), privilege(**{"user.name": "alice", "session.id": "0x5678"})]
    assert correlate(rows)["alerts"] == []


def test_account_names_are_context_and_do_not_replace_sid_identity():
    result = correlate([logon(**{"user.name": "alice"}), privilege(**{"user.name": "renamed-account"})])
    assert ids(result) == [("logon-a", ["privilege-a"])]


@pytest.mark.parametrize("other_sid", ["S-1-5-18", "S-1-5-21-100-200-300-1002"])
def test_contradictory_sid_in_the_same_scoped_luid_and_tolerance_fails(other_sid):
    with pytest.raises(ValueError, match="contradictory SID"):
        correlate([logon(), privilege(), privilege("wrong-sid", **{"user.id": other_sid})])


def test_mismatched_sid_outside_tolerance_is_unrelated_evidence():
    result = correlate([logon(), privilege(), privilege("wrong-sid", **{
        "user.id": "S-1-5-18", "@timestamp": "2026-01-01T00:03:00Z"})])
    assert ids(result) == [("logon-a", ["privilege-a"])]


@pytest.mark.parametrize("changes", [{"win.logon_type": 3}, {"win.logon_type": 10}, {"win.logon_process": "user32"}])
def test_other_supported_logons_are_not_newcredentials_candidates(changes):
    assert correlate([logon(**changes), privilege()])["alerts"] == []


def test_all_matching_privileges_link_once_in_record_time_then_id_order():
    rows = [logon(), privilege("z", **{"win.privileges": ["SeTcbPrivilege"]}),
            privilege("a", **{"win.privileges": ["SeDebugPrivilege", "SeTcbPrivilege"]}),
            privilege("earlier", **{"@timestamp": "2026-01-01T00:00:59Z"})]
    result = correlate(rows)
    alert = result["alerts"][0]
    assert alert["privilege.event.ids"] == ["earlier", "a", "z"]
    assert alert["privilege.time_deltas_us"] == [-1_000_000, 0, 0]
    assert alert["win.privileges"] == ["SeDebugPrivilege", "SeTcbPrivilege"]
    assert result["summary"]["matched_privilege_events"] == 3
    assert correlate(reversed(rows))["alerts"] == result["alerts"]


def test_delivered_duplicates_deduplicate_but_distinct_records_are_retained():
    rows = [logon(), privilege(), deepcopy(logon()), deepcopy(privilege()), privilege("second")]
    result = correlate(rows)
    assert ids(result) == [("logon-a", ["privilege-a", "second"])]
    assert result["summary"]["input_events"] == 5
    assert result["summary"]["duplicate_events"] == 2


def test_conflicting_event_identity_fails_even_if_an_alert_could_be_emitted():
    with pytest.raises(ValueError, match="conflicting duplicate"):
        correlate([logon(), privilege(), privilege(**{"win.privileges": ["SeTcbPrivilege"]})])


@pytest.mark.parametrize("changes", [
    {}, {"user.id": "S-1-5-18"}, {"win.logon_type": 3},
    {"@timestamp": "2026-01-02T00:01:00Z"},
])
def test_candidate_luid_with_another_logon_is_ambiguous_even_outside_anchor_bounds(changes):
    with pytest.raises(ValueError, match="ambiguous session"):
        correlate([logon(), privilege(), logon("another-logon", **changes)],
                  start="2026-01-01T00:01:00Z", end="2026-01-01T00:01:01Z")


def test_repeated_system_background_luid_is_not_automatically_ambiguous():
    background = [logon("system-1", **{"session.id": "0x3e7", "user.id": "S-1-5-18", "win.logon_type": 5}),
                  logon("system-2", **{"session.id": "0x3e7", "user.id": "S-1-5-18", "win.logon_type": 5})]
    assert correlate(background)["alerts"] == []
    assert ids(correlate([logon(), privilege(), *background])) == [("logon-a", ["privilege-a"])]


def test_out_of_bounds_candidate_has_no_ambiguity_or_sid_guard():
    rows = [logon(), logon("duplicate-luid"), privilege(**{"user.id": "S-1-5-18"})]
    assert correlate(rows, start="2026-01-01T01:00:00Z", end="2026-01-01T01:01:00Z")["alerts"] == []


def test_boot_reuse_and_same_luid_on_two_hosts_produce_distinct_alert_identities():
    rows = []
    for index, changes in enumerate([{}, {"host.boot.id": "boot-b"}, {"host.name": "host02"}]):
        rows += [logon(f"l{index}", **changes), privilege(f"p{index}", **changes)]
    alerts = correlate(rows)["alerts"]
    assert len(alerts) == len({a["alert.id"] for a in alerts}) == 3


def test_bounds_select_logon_anchor_and_preserve_privilege_context_on_both_sides():
    rows = [logon("at-start"), privilege("before", **{"@timestamp": "2026-01-01T00:00:30Z"}),
            privilege("after", **{"@timestamp": "2026-01-01T00:01:30Z"}),
            logon("at-end", **{"@timestamp": "2026-01-01T00:01:01Z", "session.id": "0x2"}),
            privilege("end-context", **{"@timestamp": "2026-01-01T00:01:01Z", "session.id": "0x2"})]
    result = correlate(rows, start="2026-01-01T00:01:00Z", end="2026-01-01T00:01:01Z")
    assert ids(result) == [("at-start", ["before", "after"])]
    assert result["summary"]["out_of_range_logons"] == 1


def test_subsecond_bounds_and_timezone_offsets_are_exact():
    rows = [logon(**{"@timestamp": "2026-01-01T03:01:00.000001+03:00"}), privilege()]
    assert ids(correlate(rows, start="2026-01-01T00:01:00.000001Z", end="2026-01-01T00:01:00.000002Z")) == [("logon-a", ["privilege-a"])]
    assert correlate(rows, start="2026-01-01T00:01:00Z", end="2026-01-01T00:01:00.000001Z")["alerts"] == []


def test_native_tick_remainder_stays_evidence_not_extra_time_precision():
    rows = [logon(**{"win.timestamp_remainder": 9}), privilege(**{"win.timestamp_remainder": 0})]
    assert correlate(rows, max_skew_seconds=0)["alerts"][0]["privilege.time_deltas_us"] == [0]


@pytest.mark.parametrize("options", [
    {"max_skew_seconds": -1}, {"max_skew_seconds": 86401}, {"max_skew_seconds": True},
    {"max_skew_seconds": 1.0}, {"max_events": 0}, {"max_events": True},
    {"max_alerts": 0}, {"max_alerts": 1.0},
    {"start": "2026-01-01T00:00:00Z"}, {"end": "2026-01-01T00:00:00Z"},
    {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
    {"start": "1969-12-31T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
    {"start": datetime(2026, 1, 1), "end": datetime(2026, 1, 2)},
])
def test_bad_configuration_fails_before_input_is_consumed(options):
    def forbidden():
        raise AssertionError("invalid config must fail before consuming input")
        yield
    with pytest.raises(ValueError):
        correlate(forbidden(), **options)


def test_raw_event_cap_counts_duplicates_and_never_returns_partial_alerts():
    with pytest.raises(ValueError, match="max_events"):
        correlate([logon(), privilege(), deepcopy(privilege())], max_events=2)
    assert len(correlate([logon(), privilege()], max_events=2)["alerts"]) == 1


def test_alert_cap_fails_complete_result():
    rows = [logon(), privilege(), logon("l2", **{"session.id": "0x2"}), privilege("p2", **{"session.id": "0x2"})]
    with pytest.raises(ValueError, match="max_alerts"):
        correlate(rows, max_alerts=1)
    assert len(correlate(rows, max_alerts=2)["alerts"]) == 2


def test_malformed_input_outside_bounds_still_fails_the_replay():
    malformed = privilege("bad", **{"@timestamp": "2025-01-01T00:00:00Z", "session.id": None})
    with pytest.raises(ValueError):
        correlate([logon(), privilege(), malformed], start="2026-01-01T00:01:00Z", end="2026-01-01T00:01:01Z")


def test_input_order_and_data_are_not_mutated():
    rows = [privilege(), logon()]
    before = deepcopy(rows)
    first = correlate(rows)
    assert rows == before
    assert correlate(reversed(rows))["alerts"] == first["alerts"]


def test_empty_api_supports_adapter_preflight_and_noniterable_fails():
    assert correlate([])["alerts"] == []
    with pytest.raises(ValueError, match="finite iterable"):
        correlate(None)


def test_cli_works_outside_repo_and_reports_only_complete_results(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text("\n".join(json.dumps(row) for row in [privilege(), logon()]) + "\n")
    command = [sys.executable, str(ROOT / "tools/correlate_newcredentials.py"), "--events", str(source)]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=True)
    assert ids(json.loads(result.stdout)) == [("logon-a", ["privilege-a"])]
    source.write_text(source.read_text() + json.dumps({"invalid": "row"}) + "\n")
    failed = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert failed.returncode == 1 and failed.stdout == ""


@pytest.mark.parametrize("contents", ["", '{"event.id":"a","event.id":"b"}\n', '{"event.id":NaN}\n'])
def test_cli_rejects_empty_or_ambiguous_json_input(tmp_path, contents):
    source = tmp_path / "events.jsonl"
    source.write_text(contents)
    result = subprocess.run([sys.executable, str(ROOT / "tools/correlate_newcredentials.py"), "--events", str(source)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
