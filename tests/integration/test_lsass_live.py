"""Real Elasticsearch Basic evidence for the finite Sysmon LSASS candidate."""
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

from tools import elastic_lsass as lsass
from tools import elastic_rolling as auth
from tools.detect_lsass import evaluate_events

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "tests/fixtures/lsass/cases.json").read_text())["cases"]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic LSASS checks")
    result = lsass.ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                                username=os.environ.get("ELASTIC_USERNAME"),
                                password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def index_for(client, adapter=lsass):
    name = "attck-test-lsass-" + uuid4().hex
    adapter.create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", lsass.index_path(name))


def event(i=1, **changes):
    return {"@timestamp": "2026-01-01T00:00:00Z", "event.id": f"access-{i}",
            "event.dataset": lsass.DATASET, "event.code": "10", "host.name": "host01",
            "source.process.guid": f"00000001-0000-0000-0000-{i:012x}",
            "target.process.guid": "00000002-0000-0000-0000-000000000002",
            "source.image": r"C:\Tools\diagnostic.exe", "target.image": r"C:\Windows\System32\lsass.exe",
            "process.access_mask": 0x10, **changes}


def verify_linked_alerts(result, events, expected_ids):
    """Manual expected event IDs remain independent of the implementation."""
    assert [a["event.id"] for a in result["alerts"]] == expected_ids
    sources = {item["event.id"]: item for item in events}
    for alert in result["alerts"]:
        assert re.fullmatch(r"lsass:[0-9a-f]{64}", alert["alert.id"])
        assert alert["rule.id"] == "LSASS-PROCESS-VM-READ-001"
        for field in ("host.name", "source.process.guid", "target.process.guid",
                      "source.image", "target.image", "process.access_mask"):
            assert alert[field] == sources[alert["event.id"]][field]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manual_cases_on_real_basic(client, case):
    with index_for(client) as index:
        if not case["profile_valid"]:
            with pytest.raises(ValueError):
                lsass.ingest_events(client, index, case["events"])
            assert client.request("GET", lsass.index_path(index) + "/_count")["count"] == 0
            return
        lsass.ingest_events(client, index, case["events"])
        actual = lsass.evaluate_index(client, index, page_size=1, **case.get("bounds", {}))
        verify_linked_alerts(actual, case["events"], case["expected_event_ids"])
        assert actual["alerts"] == evaluate_events(case["events"], **case.get("bounds", {}))["alerts"]
        assert actual["profile"] == "attck-lsass-v1"


def test_native_immutable_retry_and_conflicting_rights(client):
    events = [event(), event(2, **{"process.access_mask": 0x1000})]
    with index_for(client) as index:
        assert lsass.ingest_events(client, index, events)["inserted_events"] == 2
        retried = lsass.ingest_events(client, index, events + [deepcopy(events[0])])
        assert (retried["inserted_events"], retried["existing_events"], retried["duplicate_events"]) == (0, 2, 1)
        with pytest.raises(lsass.ElasticError, match="Conflicting stored"):
            lsass.ingest_events(client, index, [{**events[0], "process.access_mask": 0x1000}])
        verify_linked_alerts(lsass.evaluate_index(client, index, page_size=1), events, ["access-1"])


@pytest.mark.parametrize("changes", [
    {"source": "conflicting-parent"}, {"source.process.guid.child": "conflicting-child"},
    {"process.access_mask": "16"}, {"_routing": "unsupported-metadata"},
])
def test_native_invalid_second_record_cannot_partially_ingest_first(client, changes):
    with index_for(client) as index:
        with pytest.raises(ValueError):
            lsass.ingest_events(client, index, [event(), event(2, **changes)], batch_size=1)
        client.request("POST", lsass.index_path(index) + "/_refresh")
        assert client.request("GET", lsass.index_path(index) + "/_count")["count"] == 0


@pytest.mark.parametrize("violation", [
    "wrong_document_id", "numeric_guid", "missing_guid", "noncanonical_path", "unknown_field",
])
def test_native_direct_write_cannot_bypass_profile(client, violation):
    item = event()
    identifier = item["event.id"]
    if violation == "wrong_document_id":
        identifier = "unrelated-id"
    elif violation == "numeric_guid":
        item["source.process.guid"] = 123
    elif violation == "missing_guid":
        item.pop("target.process.guid")
    elif violation == "noncanonical_path":
        item["target.image"] = r"C:\Windows\System32\..\lsass.exe"
    else:
        item["unsupported.context"] = "unvalidated"
    with index_for(client) as index:
        client.request("PUT", lsass.index_path(index) + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ValueError):
            lsass.evaluate_index(client, index, page_size=1)


def test_native_integer_mapping_rejects_rights_coercion(client):
    with index_for(client) as index:
        with pytest.raises(lsass.ElasticError):
            client.request("PUT", lsass.index_path(index) + "/_doc/access-1?refresh=true",
                           event(**{"process.access_mask": "16"}))
        assert client.request("GET", lsass.index_path(index) + "/_count")["count"] == 0


def test_native_profile_isolation_does_not_mutate_auth_index(client):
    with index_for(client, auth) as index:
        mapping = client.request("GET", lsass.index_path(index) + "/_mapping")
        with pytest.raises(lsass.ElasticError, match="separate lsass-v1"):
            lsass.ingest_events(client, index, [event()])
        with pytest.raises(lsass.ElasticError, match="separate lsass-v1"):
            lsass.evaluate_index(client, index)
        assert client.request("GET", lsass.index_path(index) + "/_mapping") == mapping
        assert client.request("GET", lsass.index_path(index) + "/_count")["count"] == 0


def test_native_precise_inclusive_start_exclusive_end_and_equal_timestamps(client):
    events = [event(1, **{"@timestamp": "2025-12-31T23:59:59.999999Z"}),
              event(2), event(3),
              event(4, **{"@timestamp": "2026-01-01T00:00:00.000001Z"}),
              event(5, **{"@timestamp": "2026-01-01T00:00:00.000002Z"})]
    with index_for(client) as index:
        lsass.ingest_events(client, index, list(reversed(events)))
        result = lsass.evaluate_index(client, index, page_size=1, max_events=3,
                                      start="2026-01-01T00:00:00Z", end="2026-01-01T00:00:00.000002Z")
        verify_linked_alerts(result, events, ["access-2", "access-3", "access-4"])
        assert result["summary"]["fetched_events"] == 3


def test_native_candidate_and_noncandidate_caps_fail_before_any_result(client):
    events = [event(1), event(2, **{"process.access_mask": 0x1000}), event(3)]
    with index_for(client) as index:
        lsass.ingest_events(client, index, events)
        with pytest.raises(ValueError, match="max_events"):
            lsass.evaluate_index(client, index, page_size=1, max_events=2)
        with pytest.raises(ValueError, match="max_alerts"):
            lsass.evaluate_index(client, index, page_size=1, max_alerts=1)
        verify_linked_alerts(lsass.evaluate_index(client, index, page_size=1), events, ["access-1", "access-3"])


def test_native_uuid_binding_rejects_replacement_even_when_index_name_matches(client):
    with index_for(client) as index:
        lsass.ingest_events(client, index, [event()])
        prior_uuid = lsass.get_index_identity(client, index)["uuid"]
        client.request("DELETE", lsass.index_path(index))
        lsass.create_index(client, index)
        with pytest.raises(lsass.ElasticError, match="expected binding"):
            lsass.evaluate_index(client, index, expected_index_uuid=prior_uuid)


def test_native_xml_normalizer_cli_to_basic_outside_repository(client, tmp_path):
    fixtures = ROOT / "tests/fixtures/lsass/native"
    normalized = subprocess.run(
        [sys.executable, str(ROOT / "tools/normalize_windows_sysmon.py"),
         str(fixtures / "process-access-v3.xml"), str(fixtures / "benign-query-only-v3.xml")],
        cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30,
    )
    events = [json.loads(line) for line in normalized.stdout.splitlines()]
    assert len(events) == 2
    source = next(item for item in events if item["process.access_mask"] == 0x1010)
    assert source["source.process.guid"] == "a1b2c3d4-1111-2222-3333-444455556666"
    assert source["target.process.guid"] == "a1b2c3d4-7777-8888-9999-aaaabbbbcccc"
    assert source["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert source["win.timestamp_remainder"] == 7
    path = tmp_path / "normalized.jsonl"
    path.write_text(normalized.stdout)
    index = "attck-test-lsass-cli-" + uuid4().hex

    def cli(*args):
        result = subprocess.run([sys.executable, str(ROOT / "tools/elastic_lsass.py"),
                                 "--index", index, *map(str, args)], cwd=tmp_path,
                                check=True, capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)

    cli("create-index")
    try:
        assert cli("ingest", path)["inserted_events"] == 2
        assert cli("ingest", path)["existing_events"] == 2
        result = cli("evaluate", "--page-size", "1")
        verify_linked_alerts(result, events, [source["event.id"]])
        assert result["alerts"] == evaluate_events(events)["alerts"]
    finally:
        client.request("DELETE", lsass.index_path(index))
