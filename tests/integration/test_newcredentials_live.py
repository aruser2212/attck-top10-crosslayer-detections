"""Native Basic evidence for complete same-session NewCredentials replay."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

import pytest

from tools import elastic_newcredentials as sessions
from tools import elastic_rolling as auth
from tools.correlate_newcredentials import correlate

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "tests/fixtures/newcredentials/cases.json").read_text())["cases"]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic session checks")
    result = sessions.ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                                   username=os.environ.get("ELASTIC_USERNAME"),
                                   password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def index_for(client, adapter=sessions):
    name = "attck-test-newcredentials-" + uuid4().hex
    adapter.create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", sessions.index_path(name))


def event(code="4624", **changes):
    item = {"@timestamp": "2026-01-01T00:00:30Z", "event.id": "event-" + code,
            "event.dataset": sessions.DATASET, "event.code": code,
            "host.name": "host01", "host.boot.id": "trusted-boot-1",
            "session.id": "0xabc", "user.id": "S-1-5-21-100-200-300-1001"}
    item.update({"win.logon_type": 9, "win.logon_process": "seclogo"} if code == "4624"
                else {"win.privileges": ["SeDebugPrivilege"]})
    return {**item, **changes}


def expected_pair(logon_id="event-4624", privileges=None, deltas=None, names=None):
    return {"logon.event.id": logon_id,
            "privilege.event.ids": privileges if privileges is not None else ["event-4672"],
            "privilege.time_deltas_us": deltas if deltas is not None else [0],
            "win.privileges": names if names is not None else ["SeDebugPrivilege"]}


def verify_pairs(result, events, expected):
    keys = ("logon.event.id", "privilege.event.ids", "privilege.time_deltas_us", "win.privileges")
    assert [{key: alert[key] for key in keys} for alert in result["alerts"]] == expected
    sources = {item["event.id"]: item for item in events}
    for alert in result["alerts"]:
        assert re.fullmatch(r"newcredentials:[0-9a-f]{64}", alert["alert.id"])
        assert alert["rule.id"] == "CORR-WIN-NEWCREDENTIALS-PRIVILEGES-001"
        source = sources[alert["logon.event.id"]]
        assert source["event.code"] == "4624"
        for field in ("@timestamp", "host.name", "host.boot.id", "session.id", "user.id"):
            assert alert[field] == source[field]
        for privilege_id in alert["privilege.event.ids"]:
            privilege = sources[privilege_id]
            assert privilege["event.code"] == "4672"
            for field in ("host.name", "host.boot.id", "session.id", "user.id"):
                assert privilege[field] == source[field]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manual_cases_on_real_basic(client, case):
    options = {**case.get("bounds", {}), "max_skew_seconds": case.get("max_skew_seconds", 30)}
    with index_for(client) as index:
        if not case["profile_valid"]:
            with pytest.raises(ValueError):
                sessions.ingest_events(client, index, case["events"])
            assert client.request("GET", sessions.index_path(index) + "/_count")["count"] == 0
            return
        sessions.ingest_events(client, index, case["events"])
        if not case["correlation_valid"]:
            with pytest.raises(ValueError):
                sessions.evaluate_index(client, index, page_size=1, **options)
            return
        actual = sessions.evaluate_index(client, index, page_size=1, **options)
        verify_pairs(actual, case["events"], case["expected_pairs"])
        assert actual["alerts"] == correlate(case["events"], **options)["alerts"]
        assert actual["profile"] == "attck-newcredentials-v1"


def test_native_immutable_retry_and_conflicting_session_identity(client):
    events = [event(), event("4672")]
    with index_for(client) as index:
        assert sessions.ingest_events(client, index, events)["inserted_events"] == 2
        retried = sessions.ingest_events(client, index, events + [deepcopy(events[0])])
        assert (retried["inserted_events"], retried["existing_events"], retried["duplicate_events"]) == (0, 2, 1)
        with pytest.raises(sessions.ElasticError, match="Conflicting stored"):
            sessions.ingest_events(client, index, [{**events[0], "host.boot.id": "different-boot"}])
        verify_pairs(sessions.evaluate_index(client, index, page_size=1), events, [expected_pair()])


@pytest.mark.parametrize("changes", [
    {"host.boot.id": None}, {"session.id": "0x000abc"}, {"win.logon_type": "9"},
    {"host": "parent-alias"}, {"session.id.child": "child-alias"},
])
def test_native_invalid_second_record_cannot_partially_ingest_first(client, changes):
    with index_for(client) as index:
        with pytest.raises(ValueError):
            sessions.ingest_events(client, index, [event(), event(**{"event.id": "invalid", **changes})], batch_size=1)
        client.request("POST", sessions.index_path(index) + "/_refresh")
        assert client.request("GET", sessions.index_path(index) + "/_count")["count"] == 0


@pytest.mark.parametrize("violation", [
    "wrong_document_id", "missing_boot_scope", "numeric_logon_id", "unknown_field", "privilege_string",
])
def test_native_direct_write_cannot_bypass_source_profile(client, violation):
    item = event("4672")
    identifier = item["event.id"]
    if violation == "wrong_document_id":
        identifier = "unrelated-id"
    elif violation == "missing_boot_scope":
        item.pop("host.boot.id")
    elif violation == "numeric_logon_id":
        item["session.id"] = 2748
    elif violation == "privilege_string":
        item["win.privileges"] = "SeDebugPrivilege"
    else:
        item["unsupported.context"] = "unknown"
    with index_for(client) as index:
        client.request("PUT", sessions.index_path(index) + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ValueError):
            sessions.evaluate_index(client, index, page_size=1)


def test_native_mapping_rejects_logon_type_coercion(client):
    with index_for(client) as index:
        with pytest.raises(sessions.ElasticError):
            client.request("PUT", sessions.index_path(index) + "/_doc/event-4624?refresh=true",
                           event(**{"win.logon_type": "9"}))
        assert client.request("GET", sessions.index_path(index) + "/_count")["count"] == 0


def test_native_profile_isolation_preserves_auth_index(client):
    with index_for(client, auth) as index:
        original = client.request("GET", sessions.index_path(index) + "/_mapping")
        with pytest.raises(sessions.ElasticError, match="separate newcredentials-v1"):
            sessions.ingest_events(client, index, [event()])
        with pytest.raises(sessions.ElasticError, match="separate newcredentials-v1"):
            sessions.evaluate_index(client, index)
        assert client.request("GET", sessions.index_path(index) + "/_mapping") == original
        assert client.request("GET", sessions.index_path(index) + "/_count")["count"] == 0


def test_native_full_context_preserves_inclusive_skew_and_microsecond_bounds(client):
    events = [event(),
              event("4672", **{"event.id": "lower-out", "@timestamp": "2025-12-31T23:59:59.999999Z"}),
              event("4672", **{"event.id": "lower", "@timestamp": "2026-01-01T00:00:00Z"}),
              event("4672", **{"event.id": "equal"}),
              event("4672", **{"event.id": "upper", "@timestamp": "2026-01-01T00:01:00Z"}),
              event("4672", **{"event.id": "upper-out", "@timestamp": "2026-01-01T00:01:00.000001Z"})]
    with index_for(client) as index:
        sessions.ingest_events(client, index, list(reversed(events)))
        result = sessions.evaluate_index(client, index, page_size=1,
                                         start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:30.000001Z")
        verify_pairs(result, events, [expected_pair(privileges=["lower", "equal", "upper"],
                                                    deltas=[-30_000_000, 0, 30_000_000])])
        assert result["summary"]["fetched_events"] == 6
        assert sessions.evaluate_index(client, index, page_size=1,
                                       start="2026-01-01T00:00:29Z", end="2026-01-01T00:00:30Z")["alerts"] == []


def test_native_out_of_bounds_duplicate_logon_remains_ambiguous(client):
    events = [event(), event("4672"),
              event(**{"event.id": "later-duplicate", "@timestamp": "2026-01-02T00:00:00Z"})]
    with index_for(client) as index:
        sessions.ingest_events(client, index, events)
        with pytest.raises(ValueError, match="ambiguous session"):
            sessions.evaluate_index(client, index, page_size=1,
                                    start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:31Z")


def test_native_full_source_cap_cannot_be_bypassed_by_narrow_bounds(client):
    events = [event(), event("4672"),
              event(**{"event.id": "background", "session.id": "0xdef",
                       "win.logon_type": 3, "@timestamp": "2026-01-02T00:00:00Z"})]
    with index_for(client) as index:
        sessions.ingest_events(client, index, events)
        with pytest.raises(ValueError, match="max_events"):
            sessions.evaluate_index(client, index, page_size=1, max_events=2,
                                    start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:31Z")
        verify_pairs(sessions.evaluate_index(client, index, page_size=1), events, [expected_pair()])


def test_native_max_alerts_fails_without_partial_result(client):
    events = [event(), event("4672"), event(**{"event.id": "logon-2", "session.id": "0xdef"}),
              event("4672", **{"event.id": "privilege-2", "session.id": "0xdef"})]
    with index_for(client) as index:
        sessions.ingest_events(client, index, events)
        with pytest.raises(ValueError, match="max_alerts"):
            sessions.evaluate_index(client, index, page_size=1, max_alerts=1)


def test_native_uuid_binding_rejects_replacement(client):
    with index_for(client) as index:
        sessions.ingest_events(client, index, [event()])
        prior_uuid = sessions.get_index_identity(client, index)["uuid"]
        client.request("DELETE", sessions.index_path(index))
        sessions.create_index(client, index)
        with pytest.raises(sessions.ElasticError, match="expected binding"):
            sessions.evaluate_index(client, index, expected_index_uuid=prior_uuid)


@pytest.mark.parametrize("version", [0, 2])
def test_native_xml_normalizer_cli_to_basic_outside_repository(client, tmp_path, version):
    fixtures = ROOT / "tests/fixtures/newcredentials/native"
    normalized = subprocess.run(
        [sys.executable, str(ROOT / "tools/normalize_windows_sessions.py"), "--boot-id", "trusted-lab-boot",
         str(fixtures / f"newcredentials-v{version}.xml"), str(fixtures / "special-privileges-v0.xml")],
        cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30,
    )
    events = [json.loads(line) for line in normalized.stdout.splitlines()]
    assert len(events) == 2
    logon = next(item for item in events if item["event.code"] == "4624")
    privilege = next(item for item in events if item["event.code"] == "4672")
    assert logon["session.id"] == privilege["session.id"] == "0xabcde"
    assert logon["user.id"] == privilege["user.id"] == "S-1-5-21-100-200-300-1001"
    assert logon["host.boot.id"] == "trusted-lab-boot"
    assert logon["@timestamp"] == privilege["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert logon["win.timestamp_remainder"] == privilege["win.timestamp_remainder"] == 7
    path = tmp_path / "normalized.jsonl"
    path.write_text(normalized.stdout)
    index = "attck-test-newcredentials-cli-" + uuid4().hex

    def cli(*args):
        response = subprocess.run([sys.executable, str(ROOT / "tools/elastic_newcredentials.py"),
                                   "--url", client.url, "--index", index, *map(str, args)], cwd=tmp_path,
                                  check=True, capture_output=True, text=True, timeout=60)
        return json.loads(response.stdout)

    cli("create-index")
    try:
        assert cli("ingest", path)["inserted_events"] == 2
        assert cli("ingest", path)["existing_events"] == 2
        result = cli("evaluate", "--page-size", "1", "--max-skew-seconds", "0")
        verify_pairs(result, events, [expected_pair(logon["event.id"], [privilege["event.id"]], [0],
                                                    ["SeDebugPrivilege", "SeImpersonatePrivilege"])])
        assert result["alerts"] == correlate(events, max_skew_seconds=0)["alerts"]
    finally:
        client.request("DELETE", sessions.index_path(index))
