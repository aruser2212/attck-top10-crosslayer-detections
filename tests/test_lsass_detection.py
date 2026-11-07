"""Granted read capability is a candidate, not a memory-read or dump claim."""
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.detect_lsass import RULE_ID, evaluate_events, main

ROOT = Path(__file__).resolve().parents[1]


def event(identifier="access-1", **changes):
    return {
        "@timestamp": "2026-01-01T00:00:00Z", "event.id": identifier,
        "event.dataset": "windows.sysmon.process_access", "event.code": "10", "host.name": "host01.example",
        "source.process.guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "target.process.guid": "11111111-2222-3333-4444-555555555555",
        "source.image": "C:\\Tools\\collector.exe", "target.image": "C:\\Windows\\System32\\lsass.exe",
        "process.access_mask": 0x1010, **changes,
    }


@pytest.mark.parametrize("mask,match", [
    (0, False), (0x1, False), (0x8, False), (0x10, True), (0x11, True), (0x18, True),
    (0x1F, True), (0x20, False), (0x30, True), (0x38, True), (0x40, False),
    (0x400, False), (0x410, True), (0x1000, False), (0x1010, True),
    (0x1400, False), (0x1410, True), (0x1F0FFF, True), (0x1FFFFF, True),
    (0x80000000, False), (0x80000010, True), (0xFFFFFFFF, True),
])
def test_read_capability_uses_the_read_bit_not_an_access_mask_allowlist(mask, match):
    result = evaluate_events([event(**{"process.access_mask": mask})])
    assert bool(result["alerts"]) is match
    assert result["summary"]["matched_events"] == int(match)
    assert result["summary"]["filtered_events"] == int(not match)


@pytest.mark.parametrize("target,match", [
    ("C:\\Windows\\System32\\LSASS.EXE", True),
    ("C:\\Users\\Public\\lsass.exe", True),  # A filename is not executable attestation.
    ("C:\\Windows\\System32\\lsass.exe.backup", False),
    ("C:\\Windows\\System32\\not-lsass.exe", False),
    ("C:\\Windows\\System32\\lsass.exe\\other.exe", False),
    ("C:\\Windows\\System32\\lsaſs.exe", False),  # No Unicode-casefold confusable inference.
])
def test_target_basename_has_exact_ascii_insensitive_semantics(target, match):
    assert bool(evaluate_events([event(**{"target.image": target})])["alerts"]) is match


@pytest.mark.parametrize("source", [
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    "C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseIR.exe",
    "C:\\Windows\\System32\\winlogon.exe", "C:\\Users\\Public\\MsMpEng.exe",
])
def test_legitimate_tools_and_untrusted_security_names_remain_candidates(source):
    result = evaluate_events([event(**{"source.image": source})])
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["source.image"] == source


def test_alerts_carry_stable_host_process_identity_and_immutable_source_evidence():
    first = event()
    changed_pid = event("access-2", **{"source.process.pid": 123, "target.process.pid": 123})
    reused_pid = event("access-3", **{
        "source.process.pid": 123, "target.process.pid": 123,
        "source.process.guid": "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
    })
    other_host = event("access-4", **{"host.name": "host02.example"})
    before = deepcopy([first, changed_pid, reused_pid, other_host])
    result = evaluate_events([other_host, reused_pid, changed_pid, first, deepcopy(first)])
    alerts = result["alerts"]
    assert [row["event.id"] for row in alerts] == ["access-1", "access-2", "access-3", "access-4"]
    assert len({row["alert.id"] for row in alerts}) == 4
    assert all(len(row["alert.id"]) == len("lsass:") + 64 for row in alerts)
    assert all(row["rule.id"] == RULE_ID for row in alerts)
    assert alerts[2]["source.process.guid"] == reused_pid["source.process.guid"]
    assert alerts[3]["host.name"] == "host02.example"
    assert result["summary"]["duplicate_events"] == 1
    assert [first, changed_pid, reused_pid, other_host] == before
    assert evaluate_events(list(reversed(before)))["alerts"] == alerts
    assert evaluate_events([first])["alerts"][0] == evaluate_events([{**first, "source.process.pid": 99}])["alerts"][0]


def test_identity_serialization_has_no_delimiter_collision_and_keeps_full_digest():
    left = event("a|b", **{"host.name": "c"})
    right = event("a", **{"host.name": "b|c"})
    assert evaluate_events([left])["alerts"][0]["alert.id"] != evaluate_events([right])["alerts"][0]["alert.id"]


def test_same_process_self_access_is_not_silently_suppressed():
    item = event(**{"source.process.guid": "11111111-2222-3333-4444-555555555555"})
    assert len(evaluate_events([item])["alerts"]) == 1


def test_half_open_bounds_preserve_exact_microseconds_and_sort_chronologically():
    events = [event("upper", **{"@timestamp": "2026-01-01T00:00:01.000002Z"}),
              event("middle", **{"@timestamp": "2026-01-01T00:00:01.000001Z"}),
              event("before", **{"@timestamp": "2026-01-01T00:00:00.999999Z"}),
              event("lower", **{"@timestamp": "2026-01-01T00:00:01Z"})]
    result = evaluate_events(events, start="2026-01-01T01:00:01+01:00", end="2026-01-01T00:00:01.000002Z")
    assert [row["event.id"] for row in result["alerts"]] == ["lower", "middle"]
    assert result["summary"]["out_of_range_events"] == 2


@pytest.mark.parametrize("bounds", [
    {"start": "2026-01-01T00:00:00Z"}, {"end": "2026-01-01T00:00:01Z"},
    {"start": "2026-01-01T00:00:01Z", "end": "2026-01-01T00:00:01Z"},
    {"start": "2026-01-01T00:00:02Z", "end": "2026-01-01T00:00:01Z"},
    {"start": datetime(2026, 1, 1), "end": datetime(2026, 1, 2)},
    {"start": "1969-12-31T23:59:59Z", "end": "2026-01-01T00:00:01Z"},
])
def test_bad_configuration_fails_even_with_no_events(bounds):
    with pytest.raises(ValueError):
        evaluate_events([], **bounds)


@pytest.mark.parametrize("key", ["max_events", "max_alerts"])
@pytest.mark.parametrize("value", [0, -1, True, 1.0, "1", None])
def test_replay_limits_are_strict_positive_integers(key, value):
    with pytest.raises(ValueError, match="positive integer"):
        evaluate_events([], **{key: value})


def test_raw_cap_applies_before_dedup_and_bounds_and_stops_stream_consumption():
    consumed = []
    def stream():
        for i in range(10):
            consumed.append(i)
            yield event()
    with pytest.raises(ValueError, match="max_events exceeded"):
        evaluate_events(stream(), max_events=2, start="2026-01-02T00:00:00Z", end="2026-01-03T00:00:00Z")
    assert consumed == [0, 1, 2]


def test_alert_cap_never_returns_a_partial_result():
    assert len(evaluate_events([event("1"), event("2")], max_alerts=2)["alerts"]) == 2
    with pytest.raises(ValueError, match="max_alerts exceeded"):
        evaluate_events([event("1"), event("2")], max_alerts=1)


def test_invalid_event_outside_bounds_is_still_a_source_contract_failure():
    with pytest.raises(ValueError):
        evaluate_events([event(**{"process.access_mask": None})],
                        start="2026-02-01T00:00:00Z", end="2026-02-02T00:00:00Z")


def test_empty_api_result_is_explicitly_empty():
    result = evaluate_events([])
    assert result["alerts"] == [] and result["summary"]["input_events"] == 0


def test_direct_cli_works_outside_repository_and_returns_expected_source_evidence(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps(event()) + "\n")
    result = subprocess.run([sys.executable, str(ROOT / "tools/detect_lsass.py"), "--events", str(events)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["alerts"] == evaluate_events([event()])["alerts"]


@pytest.mark.parametrize("payload", ["", '{"event.id":"first","event.id":"second"}\n', '{"broken":\n'])
def test_bad_or_empty_cli_input_cannot_report_success_or_partial_json(tmp_path, capsys, payload):
    events = tmp_path / "events.jsonl"
    events.write_text(payload)
    assert main(["--events", str(events)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "LSASS replay failed:" in output.err
