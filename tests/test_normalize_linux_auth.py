from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.hunt_engine import evaluate_hunt, load_hunt
from tools.normalize_linux_auth import normalize_event, normalize_records, read_jsonl

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/linux_auth/journal.jsonl"
RECORDS = read_jsonl(StringIO(FIXTURE.read_text()))
BASE = RECORDS[2]
HUNT = ROOT / "techniques/T1110_Brute_Force/hunts/linux_ssh_failed_agg.hunt.yaml"


def record(**changes):
    result = deepcopy(BASE)
    result.update(changes)
    return result


def test_journal_fixture_normalizes_supported_actions_without_raw_data():
    result = normalize_records(RECORDS)
    assert result["summary"] == {
        "input_records": 12, "ignored_records": 2,
        "duplicate_records": 0, "normalized_events": 10,
    }
    assert [event["event.outcome"] for event in result["events"]] == ["failure"] * 8 + ["success"] * 2
    first, publickey = result["events"][0], result["events"][-1]
    assert first["@timestamp"] == "2026-01-01T00:00:10Z"
    assert first["source.ip"] == "192.0.2.10"
    assert first["source.port"] == 42000
    assert first["user.name"] == "alice"
    assert first["message"] == "Failed password"
    assert first["host.id"] == "0123456789abcdef0123456789abcdef"
    assert publickey["source.ip"] == "2001:db8::10"
    assert publickey["message"] == "Accepted publickey"
    output = json.dumps(result)
    assert "SHA256" not in output and "INERT_FIXTURE" not in output and "__CURSOR" not in output


@pytest.mark.parametrize("count,expected", [(7, []), (8, [{
    "window.start": "2026-01-01T00:00:00Z",
    "window.end": "2026-01-01T00:05:00Z",
    "source.ip": "192.0.2.10", "user.name": "alice", "fails": 8,
}])])
def test_normalized_events_execute_stored_linux_hunt_at_threshold(count, expected):
    # Successful authentications must not inflate the failed-password count.
    normalized = normalize_records(RECORDS[:count] + RECORDS[8:10])
    result = evaluate_hunt(load_hunt(HUNT), normalized["events"])
    assert result["alerts"] == expected
    assert result["summary"]["filtered_events"] == 2


def test_redelivery_is_stable_and_does_not_inflate_threshold():
    result = normalize_records(RECORDS[:7] * 2)
    assert result["summary"]["duplicate_records"] == 7
    assert len(result["events"]) == 7
    assert evaluate_hunt(load_hunt(HUNT), result["events"])["alerts"] == []
    formatted = json.loads(json.dumps(BASE, indent=2, sort_keys=False))
    assert normalize_event(formatted)["event.id"] == normalize_event(BASE)["event.id"]


def test_machine_namespaces_cursor_and_hostname_is_optional():
    first = normalize_event(BASE)
    assert normalize_event(record(_MACHINE_ID="f" * 32))["event.id"] != first["event.id"]
    assert normalize_event(record(__CURSOR=BASE["__CURSOR"] + ";fixture=other"))["event.id"] != first["event.id"]
    no_hostname = record()
    del no_hostname["_HOSTNAME"]
    assert "host.name" not in normalize_event(no_hostname)
    assert normalize_event(no_hostname)["event.id"] == first["event.id"]


@pytest.mark.parametrize("change", [
    {"__REALTIME_TIMESTAMP": "1767225612000001"},
    {"MESSAGE": "Failed password for bob from 192.0.2.10 port 42000 ssh2"},
])
def test_conflicting_cursor_delivery_fails_instead_of_selecting_a_version(change):
    with pytest.raises(ValueError, match="Conflicting records"):
        normalize_records([BASE, record(**change)])


@pytest.mark.parametrize("message", [
    "Failed password for Alice from 192.0.2.10 port 42000 ssh2",
    "Failed password for alice from 192.0.2.11 port 42000 ssh2",
])
def test_linux_username_case_and_source_ip_keep_groups_separate(message):
    records = deepcopy(RECORDS[:8])
    records[-1]["MESSAGE"] = message
    events = normalize_records(records)["events"]
    assert evaluate_hunt(load_hunt(HUNT), events)["alerts"] == []
    if "Alice" in message:
        assert events[-1]["user.name"] == "Alice"


def test_exact_journal_microseconds_are_utc_independent_of_local_timezone(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Moscow")
    result = normalize_event(record(__REALTIME_TIMESTAMP="1767225899999999", _SOURCE_REALTIME_TIMESTAMP="0"))
    assert result["@timestamp"] == "2026-01-01T00:04:59.999999Z"
    assert normalize_event(record(__REALTIME_TIMESTAMP="1767225900000000"))["@timestamp"] == "2026-01-01T00:05:00Z"
    assert normalize_event(record(__REALTIME_TIMESTAMP="0"))["@timestamp"] == "1970-01-01T00:00:00Z"


def test_eighth_event_at_next_window_boundary_does_not_join_previous_window():
    records = deepcopy(RECORDS[:8])
    records[-1]["__REALTIME_TIMESTAMP"] = "1767225900000000"
    assert evaluate_hunt(load_hunt(HUNT), normalize_records(records)["events"])["alerts"] == []
    records[-1]["__REALTIME_TIMESTAMP"] = "1767225899999999"
    assert evaluate_hunt(load_hunt(HUNT), normalize_records(records)["events"])["alerts"][0]["fails"] == 8


def test_authoritative_comm_prevents_spoofed_syslog_identifier_matches():
    assert normalize_event(record(_COMM="logger", SYSLOG_IDENTIFIER="sshd")) is None
    assert normalize_event(record(MESSAGE="sshd[123]: " + BASE["MESSAGE"])) is None
    assert normalize_event(record(MESSAGE="prefix " + BASE["MESSAGE"])) is None
    assert normalize_event(record(MESSAGE="Failed publickey for alice from 192.0.2.10 port 22 ssh2")) is None
    with pytest.raises(ValueError, match="Conflicting sshd source"):
        normalize_event(record(SYSLOG_IDENTIFIER="sudo"))


def test_source_fallback_and_missing_source_are_explicit():
    only_identifier = record()
    del only_identifier["_COMM"]
    assert normalize_event(only_identifier)["event.dataset"] == "linux.auth.sshd"
    del only_identifier["SYSLOG_IDENTIFIER"]
    assert normalize_event(only_identifier) is None
    only_comm = record()
    del only_comm["SYSLOG_IDENTIFIER"]
    assert normalize_event(only_comm)["message"] == "Failed password"


@pytest.mark.parametrize("source", ["sshd", "sshd-session", "sshd-auth"])
def test_exact_modern_openssh_process_names_and_identifier_fallback(source):
    event = normalize_event(record(_COMM=source, SYSLOG_IDENTIFIER="sshd"))
    assert event["message"] == "Failed password"
    assert event["event.dataset"] == "linux.auth.sshd"
    fallback = record(SYSLOG_IDENTIFIER=source)
    del fallback["_COMM"]
    assert normalize_event(fallback) == event


@pytest.mark.parametrize("source", ["fake-sshd", "sshd-helper", "sshd-session-fake", "fake-sshd-auth", "SSHD"])
def test_source_names_never_use_substring_or_case_insensitive_matching(source):
    assert normalize_event(record(_COMM=source, SYSLOG_IDENTIFIER="sshd")) is None
    fallback = record(SYSLOG_IDENTIFIER=source)
    del fallback["_COMM"]
    assert normalize_event(fallback) is None


def test_fixture_has_both_split_process_sources():
    sources = {entry["_COMM"] for entry in RECORDS[:8]}
    assert sources == {"sshd", "sshd-session", "sshd-auth"}


@pytest.mark.parametrize("account", ["-", "(unknown)", "δοκιμή", "Alice"])
def test_attempted_username_is_preserved_without_guessing_account_existence(account):
    event = normalize_event(record(MESSAGE=f"Failed password for invalid user {account} from 192.0.2.10 port 22 ssh2"))
    assert event["user.name"] == account


@pytest.mark.parametrize("port", [0, 65535])
def test_source_port_retains_valid_unsigned_16_bit_boundaries(port):
    event = normalize_event(record(MESSAGE=f"Failed password for alice from 192.0.2.10 port {port} ssh2"))
    assert event["source.port"] == port


@pytest.mark.parametrize("field,value", [
    ("_MACHINE_ID", None), ("_MACHINE_ID", "not-a-machine-id"),
    ("__CURSOR", None), ("__CURSOR", ""), ("__CURSOR", " cursor "),
    ("__REALTIME_TIMESTAMP", None), ("__REALTIME_TIMESTAMP", 1767225610000000),
    ("__REALTIME_TIMESTAMP", "2026-01-01T00:00:10Z"),
    ("__REALTIME_TIMESTAMP", "1767225610.000000"),
    ("__REALTIME_TIMESTAMP", "999999999999999999"),
    ("MESSAGE", [BASE["MESSAGE"]]), ("_COMM", ["sshd"]),
    ("_HOSTNAME", "host\ud800"), ("__CURSOR", "cursor\ud800"),
])
def test_missing_or_ambiguous_required_journal_data_fails(field, value):
    with pytest.raises(ValueError):
        normalize_event(record(**{field: value}))


@pytest.mark.parametrize("message", [
    "Failed password for alice from not-an-ip port 22 ssh2",
    "Failed password for alice from fe80::1%eth0 port 22 ssh2",
    "Failed password for alice from 192.0.2.10 port 65536 ssh2",
    "Failed password for alice from 192.0.2.10 port 22 ssh2 trailing-secret",
    "Failed password for alice from 192.0.2.10 port 22 ssh2\nsecret",
    "Failed password for alice from 192.0.2.10",
    "Failed password for  from 192.0.2.10 port 22 ssh2",
    "Accepted password for invalid user alice from 192.0.2.10 port 22 ssh2",
    "Accepted publickey for alice from 192.0.2.10 port 22 ssh2: ",
    "Failed password for user\ud800 from 192.0.2.10 port 22 ssh2",
])
def test_malformed_recognized_auth_fails_without_disclosing_message(message):
    with pytest.raises(ValueError) as caught:
        normalize_event(record(MESSAGE=message))
    assert message not in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("text", [
    "", "\n", "{}\n\n", '{"MESSAGE":"first","MESSAGE":"second"}\n',
    '{"secret":NaN}\n', '{"secret":Infinity}\n', '[]\n', 'null\n', '{broken}\n',
    'Nov 5 12:00:00 host sshd[123]: Failed password for alice from 192.0.2.10 port 22 ssh2\n',
])
def test_strict_jsonl_rejects_empty_malformed_and_duplicate_keys(text):
    with pytest.raises(ValueError):
        read_jsonl(StringIO(text))


def test_no_matching_events_cannot_masquerade_as_validated_stream():
    with pytest.raises(ValueError, match="no supported"):
        normalize_records([record(_COMM="logger")])
    with pytest.raises(ValueError, match="empty"):
        normalize_records([])


def test_cli_outputs_jsonl_and_summary_without_raw_metadata():
    result = subprocess.run([sys.executable, str(ROOT / "tools/normalize_linux_auth.py"), str(FIXTURE)],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(events) == 10
    assert json.loads(result.stderr)["ignored_records"] == 2
    assert "SHA256" not in result.stdout + result.stderr
    assert evaluate_hunt(load_hunt(HUNT), events)["alerts"][0]["fails"] == 8


def test_cli_validates_every_line_before_emitting_and_redacts_errors():
    bad = json.dumps(BASE) + '\n{"MESSAGE":"sensitive-private-value",broken}\n'
    result = subprocess.run([sys.executable, str(ROOT / "tools/normalize_linux_auth.py"), "-"],
                            input=bad, text=True, capture_output=True)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "sensitive-private-value" not in result.stderr
    assert "line 2" in result.stderr
