"""Behavioral regression fixtures for the narrowly scoped webroot correlation."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from tools.correlate_webshell import CorrelationError, correlate, load_jsonl, main, validate_event


FIXTURES = Path(__file__).parent / "fixtures" / "correlation"
WEBROOTS = ["/var/www/html"]


def file_event(**changes):
    event = {
        "@timestamp": "2026-01-01T00:00:00Z", "event.id": "file-1", "event.dataset": "host.file",
        "host.id": "web-1", "resource.namespace": "site-1", "file.path": "/var/www/html/uploads/example.php",
        "file.operation": "create", "event.success": True,
    }
    return event | changes


def request_event(seconds=30, **changes):
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    event = {
        "@timestamp": timestamp.isoformat(), "event.id": "request-1", "event.dataset": "web.access",
        "host.id": "web-1", "resource.namespace": "site-1",
        "web.resource_path": "/var/www/html/uploads/example.php", "url.query": "cmd=inert",
    }
    return event | changes


def run(events, **kwargs):
    return correlate(events, webroots=WEBROOTS, **kwargs)


def test_fixture_has_only_expected_pair():
    expected = json.loads((FIXTURES / "expected.json").read_text())
    result = correlate(load_jsonl(FIXTURES / "webroot_request.jsonl"), webroots=expected["webroots"])
    assert [[alert["file.event.id"], alert["http.event.id"]] for alert in result["alerts"]] == expected["expected_pairs"]
    assert result["summary"]["duplicate_events"] == expected["expected_duplicate_events"]
    assert result["alerts"][0]["classification"] == "corroborated_suspicious_activity"


def test_input_order_and_identical_duplicates_do_not_change_alerts():
    events = [file_event(), request_event()]
    forward = run(events)
    reverse = run(list(reversed(events)) + deepcopy(events))
    assert reverse["alerts"] == forward["alerts"]
    assert reverse["summary"]["duplicate_events"] == 2
    assert reverse["summary"]["alerts"] == 1


@pytest.mark.parametrize(("offset", "expected"), [(-1, 0), (0, 1), (299.999, 1), (300, 0), (301, 0)])
def test_window_is_half_open_and_causal(offset, expected):
    assert len(run([file_event(), request_event(offset)])["alerts"]) == expected


def test_window_is_configurable():
    assert not run([file_event(), request_event(60)], window_seconds=60)["alerts"]
    assert run([file_event(), request_event(59)], window_seconds=60)["alerts"]


@pytest.mark.parametrize("changes", [
    {"host.id": "different-host"},
    {"resource.namespace": "different-workload"},
    {"web.resource_path": "/var/www/html/uploads/different.php"},
    {"web.resource_path": "/var/www/html/uploads/Example.php"},
])
def test_host_and_canonical_path_must_both_match(changes):
    assert not run([file_event(), request_event(**changes)])["alerts"]


@pytest.mark.parametrize("changes", [
    {"file.operation": "read"},
    {"file.operation": "open"},
    {"event.success": False},
    {"file.path": "/var/www/html/uploads/example.txt"},
    {"file.path": "/var/www/html-other/example.php"},
    {"file.path": "/tmp/example.php"},
])
def test_file_event_requires_successful_write_in_webroot(changes):
    file = file_event(**changes)
    request = request_event(**{"web.resource_path": file["file.path"]})
    assert not run([file, request])["alerts"]


def test_explicit_write_operation_also_qualifies():
    assert run([file_event(**{"file.operation": "write"}), request_event()])["alerts"]


@pytest.mark.parametrize(("query", "expected"), [
    ("cmd=", True), ("exec=inert", True), ("command=inert", True),
    ("%63md=inert", True), ("cmd=x&cmd=y", True),
    ("notcmd=inert", False), ("CMD=inert", False), ("mode=cmd%3Dinert", False),
    ("%2563md=inert", False), ("", False), ("debug", False),
])
def test_query_keys_are_exact_and_decoded_once(query, expected):
    alerts = run([file_event(), request_event(**{"url.query": query})])["alerts"]
    assert bool(alerts) is expected


def test_latest_file_event_is_linked_once_per_http_request():
    first = file_event()
    later = file_event(**{"event.id": "file-2", "@timestamp": "2026-01-01T00:00:20Z"})
    result = run([request_event(), later, first])
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["file.event.id"] == "file-2"
    assert result["alerts"][0]["elapsed_seconds"] == 10


def test_same_time_file_events_use_deterministic_id_tiebreak():
    events = [file_event(**{"event.id": "file-a"}), file_event(**{"event.id": "file-z"}), request_event()]
    result = run(list(reversed(events)))
    assert result["alerts"][0]["file.event.id"] == "file-z"


def test_conflicting_duplicate_ids_are_rejected():
    with pytest.raises(CorrelationError, match="conflicting duplicate"):
        run([file_event(), file_event(**{"event.success": False}), request_event()])


def test_duplicate_payloads_cannot_hide_boolean_integer_type_conflict():
    with pytest.raises(CorrelationError, match="conflicting duplicate|boolean event.success"):
        run([file_event(), file_event(**{"event.success": 1}), request_event()])


def test_equivalent_timezone_timestamp_duplicate_is_deduplicated():
    duplicate = file_event(**{"@timestamp": "2026-01-01T03:00:00+03:00"})
    result = run([file_event(), duplicate, request_event()])
    assert result["summary"]["duplicate_events"] == 1
    assert len(result["alerts"]) == 1


@pytest.mark.parametrize("changes", [
    {"@timestamp": "2026-01-01T00:00:00"},
    {"@timestamp": "not-a-timestamp"},
    {"host.id": ""},
    {"file.operation": None},
    {"event.success": "true"},
    {"file.path": "relative/example.php"},
    {"file.path": "/var/www/html/../example.php"},
    {"file.path": "/var//www/html/example.php"},
    {"file.path": "/var/www/html/./example.php"},
    {"file.path": "/var/www/html/example.php/"},
    {"file.path": "/var/www/html/\ud800.php"},
])
def test_malformed_required_fields_fail_explicitly(changes):
    with pytest.raises(CorrelationError):
        run([file_event(**changes), request_event()])


@pytest.mark.parametrize("query", [
    "?cmd=inert", "cmd=%XX", "cmd=%FF", "cmd=x#fragment", None,
    "cmd=inert\r", "cmd=inert\x7f", "cmd=\ud800",
])
def test_malformed_query_fails(query):
    with pytest.raises(CorrelationError, match="query"):
        run([file_event(), request_event(**{"url.query": query})])


def test_unsupported_dataset_is_counted_without_global_join():
    unrelated = {"event.id": "other", "event.dataset": "other.source", "@timestamp": "2026-01-01T00:00:00Z"}
    result = run([unrelated, request_event()])
    assert not result["alerts"]
    assert result["summary"]["ignored_dataset_events"] == 1


@pytest.mark.parametrize("window", [True, 0, -1, 1.5, 86401])
def test_invalid_window_fails(window):
    with pytest.raises(CorrelationError, match="window_seconds"):
        run([], window_seconds=window)


def test_explicit_webroot_is_required():
    with pytest.raises(CorrelationError, match="webroot"):
        correlate([], webroots=[])


def test_jsonl_duplicate_keys_fail_with_line_number(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event.id":"first","event.id":"second"}\n')
    with pytest.raises(CorrelationError, match=r":1: duplicate JSON field"):
        load_jsonl(path)


def test_cli_emits_the_validated_result(capsys):
    assert main([str(FIXTURES / "webroot_request.jsonl"), "--webroot", WEBROOTS[0]]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["alerts"] == 1


def test_cli_failure_is_nonzero(tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event.id":"incomplete"}\n')
    assert main([str(path), "--webroot", WEBROOTS[0]]) == 1
    assert "Correlation failed:" in capsys.readouterr().err


@pytest.mark.parametrize("contents", ["", " \n\t\n"])
def test_cli_empty_replay_is_nonzero(tmp_path, capsys, contents):
    path = tmp_path / "events.jsonl"
    path.write_text(contents)
    assert main([str(path), "--webroot", WEBROOTS[0]]) == 1
    output = capsys.readouterr()
    assert "no events found" in output.err
    assert output.out == ""


def test_namespace_is_required_on_both_sources_without_a_default():
    for missing_from in (0, 1):
        events = [file_event(), request_event()]
        del events[missing_from]["resource.namespace"]
        with pytest.raises(CorrelationError, match="resource.namespace"):
            run(events)


def test_declared_shared_resource_can_have_different_http_aliases():
    # These aliases were resolved upstream to the same actual filesystem resource.
    events = [file_event(), request_event(**{"http.host": "public.example"}),
              request_event(40, **{"event.id": "request-alias", "http.host": "admin.example"})]
    result = run(events)
    assert len(result["alerts"]) == 2
    assert {alert["file.event.id"] for alert in result["alerts"]} == {"file-1"}
    assert {alert["resource.namespace"] for alert in result["alerts"]} == {"site-1"}
    assert {alert["rule.id"] for alert in result["alerts"]} == {"CORR-WEB-WEBROOT-REQUEST-002"}


@pytest.mark.parametrize(("field", "value"), [
    ("resource.namespace", " site-1"), ("resource.namespace", "site-1\x00other"),
    ("host.id", "web-1 "), ("host.id", "web-1\x7fother"),
    ("event.id", " file-1"), ("event.id", "a\x00b"),
    ("resource.namespace", "site-\ud800"),
])
def test_source_identities_reject_controls_and_surrounding_whitespace(field, value):
    for factory in (file_event, request_event):
        with pytest.raises(CorrelationError):
            run([factory(**{field: value})])


def test_namespace_and_host_are_part_of_alert_identity():
    default = run([file_event(), request_event()])["alerts"][0]
    # SHA256 of the explicit compact UTF-8 JSON tuple
    # ["CORR-WEB-WEBROOT-REQUEST-002","web-1","site-1","file-1","request-1"].
    # This fixes the identity protocol independently of the implementation helper.
    assert default["alert.id"] == "f13afbce8a37700514fdae28989ac13664e21afa389b90308e73e2d327a5b297"
    other_namespace = run([
        file_event(**{"resource.namespace": "site-2"}),
        request_event(**{"resource.namespace": "site-2"}),
    ])["alerts"][0]
    other_host = run([
        file_event(**{"host.id": "web-2"}), request_event(**{"host.id": "web-2"}),
    ])["alerts"][0]
    assert len({item["alert.id"] for item in (default, other_namespace, other_host)}) == 3
    assert all(len(item["alert.id"]) == 64 for item in (default, other_namespace, other_host))


@pytest.mark.parametrize(("write_timestamp", "expected"), [
    ("2026-01-01T00:00:00Z", 0),
    ("2026-01-01T00:00:00.000001Z", 1),
])
def test_bounded_replay_keeps_only_causal_context_after_the_exclusive_floor(write_timestamp, expected):
    events = [
        file_event(**{"@timestamp": write_timestamp}),
        request_event(**{"@timestamp": "2026-01-01T00:04:59.999999Z", "event.id": "before-start"}),
        request_event(**{"@timestamp": "2026-01-01T00:05:00Z", "event.id": "at-start"}),
        request_event(**{"@timestamp": "2026-01-01T00:05:00.000001Z", "event.id": "at-end"}),
    ]
    result = run(events, start="2026-01-01T00:05:00Z", end="2026-01-01T00:05:00.000001Z")
    assert len(result["alerts"]) == expected
    if expected:
        assert result["alerts"][0]["http.event.id"] == "at-start"
        assert result["alerts"][0]["elapsed_seconds"] == 299.999999


def test_bounded_requests_still_select_latest_eligible_write_from_context():
    events = [
        file_event(),
        file_event(**{"@timestamp": "2026-01-01T00:00:20Z", "event.id": "latest-write"}),
        request_event(30),
        file_event(**{"@timestamp": "2026-01-01T00:00:31Z", "event.id": "future-write"}),
    ]
    result = run(events, start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:31Z")
    assert [(a["file.event.id"], a["http.event.id"]) for a in result["alerts"]] == [
        ("latest-write", "request-1"),
    ]


@pytest.mark.parametrize("bounds", [
    {"start": "2026-01-01T00:00:00Z"},
    {"end": "2026-01-01T00:00:01Z"},
    {"start": "2026-01-01T00:00:01Z", "end": "2026-01-01T00:00:01Z"},
    {"start": "2026-01-01T00:00:02Z", "end": "2026-01-01T00:00:01Z"},
])
def test_invalid_or_partial_bounds_fail_before_returning_candidates(bounds):
    with pytest.raises(CorrelationError):
        run([file_event(), request_event()], **bounds)


@pytest.mark.parametrize("kind", ["duplicate", "unknown", "out_of_range"])
def test_max_events_counts_raw_records_before_dedup_filter_or_bounds(kind):
    first = file_event()
    if kind == "duplicate":
        second = deepcopy(first)
    elif kind == "unknown":
        second = {"@timestamp": "2026-01-01T00:00:00Z", "event.id": "other", "event.dataset": "other.source"}
    else:
        second = request_event(**{"@timestamp": "2027-01-01T00:00:00Z"})
    with pytest.raises(CorrelationError, match="max_events"):
        run(iter([first, second]), max_events=1,
            start="2026-01-01T00:00:00Z", end="2026-01-01T00:01:00Z")


def test_max_alerts_refuses_truncation_and_allows_complete_retry():
    events = [file_event(), request_event(), request_event(31, **{"event.id": "request-2"})]
    with pytest.raises(CorrelationError, match="max_alerts"):
        run(events, max_alerts=1)
    result = run(events, max_alerts=2)
    assert [a["http.event.id"] for a in result["alerts"]] == ["request-1", "request-2"]
    assert result["summary"]["alerts"] == 2


@pytest.mark.parametrize(("field", "value"), [
    ("max_events", 0), ("max_events", True), ("max_events", 2.5),
    ("max_alerts", -1), ("max_alerts", False), ("max_alerts", "2"),
])
def test_resource_limits_require_positive_exact_integers(field, value):
    with pytest.raises(CorrelationError, match=field):
        run([], **{field: value})


def test_cli_accepts_bounds_and_limits_and_emits_no_partial_json(capsys):
    path = str(FIXTURES / "webroot_request.jsonl")
    arguments = [path, "--webroot", WEBROOTS[0], "--start", "2026-01-01T00:02:00Z",
                 "--end", "2026-01-01T00:02:01Z", "--max-events", "5", "--max-alerts", "1"]
    assert main(arguments) == 0
    result = json.loads(capsys.readouterr().out)
    assert [a["http.event.id"] for a in result["alerts"]] == ["request-suspicious"]
    assert main([*arguments[:-4], "--max-events", "1", "--max-alerts", "1"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "max_events" in output.err


def test_shared_validator_accepts_both_sources_and_rejects_non_events():
    assert validate_event(file_event()) is None
    assert validate_event(request_event()) is None
    with pytest.raises(CorrelationError):
        validate_event(None)
