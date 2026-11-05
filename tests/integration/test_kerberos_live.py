"""Real Elasticsearch Basic checks for exact 4769 service-account candidates."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from tools import elastic_kerberos as kerberos
from tools import elastic_rolling as auth
from tools.rolling_hunt import evaluate_hunt, load_hunt

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/kerberos/cases.json"
HUNT = ROOT / "techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml"
pytestmark = pytest.mark.integration


def cases():
    result = json.loads(FIXTURES.read_text(encoding="utf-8"))["cases"]
    assert len(result) >= 20, "Manual Kerberos fixture coverage must not silently disappear"
    assert any(case["outcome"] == "benign_candidate" for case in result)
    return result


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic Kerberos checks")
    result = kerberos.ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                                    username=os.environ.get("ELASTIC_USERNAME"),
                                    password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def index_for(client, adapter=kerberos):
    name = "attck-test-kerberos-" + uuid4().hex
    adapter.create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", kerberos.index_path(name))


@pytest.mark.parametrize("case", cases(), ids=lambda case: case["name"])
def test_manual_cases_on_native_basic(client, case):
    rule = load_hunt(ROOT / case["hunt"])
    bounds = case.get("bounds", {})
    assert evaluate_hunt(rule, case["events"], **bounds)["alerts"] == case["expected_alerts"]
    with index_for(client) as index:
        if not case["profile_valid"]:
            # Explicit malformed-type/source cases exercise the offline
            # selector but must not enter an index through ES type coercion.
            with pytest.raises(ValueError):
                kerberos.ingest_events(client, index, case["events"])
            assert client.request("GET", kerberos.index_path(index) + "/_count")["count"] == 0
            return
        kerberos.ingest_events(client, index, case["events"])
        actual = kerberos.evaluate_index(client, index, rule, page_size=2, **bounds)
        assert actual["alerts"] == case["expected_alerts"], case["name"]
        assert actual["profile"] == "attck-kerberos-v1"


def event(i=1, **changes):
    return {
        "@timestamp": "2026-01-01T00:05:00Z", "event.id": f"request-{i}",
        "event.dataset": kerberos.DATASET, "event.code": "4769", "win.status": 0,
        "ticket.encryption_type": 23, "user.name": "alice", "user.domain": "lab.example",
        "source.ip": "192.0.2.10", "service.id": f"S-1-5-21-100-200-300-{1000+i}",
        "service.name": "same-display-name", "host.name": "dc01.lab.example", **changes,
    }


def expected(start="2026-01-01T00:00:00Z", end="2026-01-01T00:05:00Z"):
    return [{"window.start": start, "window.end": end, "user.domain": "lab.example",
             "user.name": "alice", "source.ip": "192.0.2.10",
             "distinct_service_accounts": 5, "rc4_requests": 5}]


def test_native_immutable_retry_and_payload_conflict(client):
    events = [event(i) for i in range(1, 6)]
    with index_for(client) as index:
        assert kerberos.ingest_events(client, index, events)["inserted_events"] == 5
        retried = kerberos.ingest_events(client, index, events + [deepcopy(events[0])])
        assert retried["inserted_events"] == 0
        assert retried["existing_events"] == 5
        assert retried["duplicate_events"] == 1
        with pytest.raises(kerberos.ElasticError, match="Conflicting stored"):
            kerberos.ingest_events(client, index, [{**events[0], "win.status": 6}])
        assert kerberos.evaluate_index(client, index, load_hunt(HUNT), page_size=1)["alerts"] == expected()


@pytest.mark.parametrize("violation", ["wrong_document_id", "numeric_keyword", "numeric_string", "invalid_sid"])
def test_native_direct_write_cannot_bypass_profile(client, violation):
    item = event()
    identifier = item["event.id"]
    if violation == "wrong_document_id":
        identifier = "unrelated-id"
    elif violation == "numeric_keyword":
        item["user.name"] = 123
    elif violation == "numeric_string":
        item["win.status"] = "0"
    else:
        item["service.id"] = "invalid-sid"
    with index_for(client) as index:
        client.request("PUT", kerberos.index_path(index) + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ValueError):
            kerberos.evaluate_index(client, index, load_hunt(HUNT), page_size=1)


def test_native_profile_separation_preserves_auth_index(client):
    with index_for(client, auth) as index:
        original = client.request("GET", kerberos.index_path(index) + "/_mapping")
        with pytest.raises(kerberos.ElasticError, match="separate kerberos-v1"):
            kerberos.ingest_events(client, index, [event()])
        with pytest.raises(kerberos.ElasticError, match="separate kerberos-v1"):
            kerberos.evaluate_index(client, index, load_hunt(HUNT))
        assert client.request("GET", kerberos.index_path(index) + "/_mapping") == original
        assert client.request("GET", kerberos.index_path(index) + "/_count")["count"] == 0


def test_native_microsecond_context_excludes_floor_and_upper_bound(client):
    floor, first = "2026-01-01T00:00:00.000000Z", "2026-01-01T00:00:00.000001Z"
    start, end = "2026-01-01T00:05:00.000000Z", "2026-01-01T00:05:00.000001Z"
    events = [event(i, **{"@timestamp": first}) for i in range(1, 5)]
    events += [event(5, **{"@timestamp": start}), event(6, **{"@timestamp": floor}),
               event(7, **{"@timestamp": end})]
    with index_for(client) as index:
        kerberos.ingest_events(client, index, events)
        result = kerberos.evaluate_index(client, index, load_hunt(HUNT), start=start, end=end,
                                          page_size=2, max_events=5)
    assert result["alerts"] == expected()
    assert result["summary"]["fetched_events"] == 5
    assert result["summary"]["context_events"] == 4


def test_native_caps_fail_without_truncating_then_allow_complete_retry(client):
    events = [event(i) for i in range(1, 6)] + [event(6, **{"@timestamp": "2026-01-01T00:05:01Z"})]
    with index_for(client) as index:
        kerberos.ingest_events(client, index, events)
        with pytest.raises(ValueError, match="max_events"):
            kerberos.evaluate_index(client, index, load_hunt(HUNT), page_size=2, max_events=5)
        with pytest.raises(ValueError, match="max_alerts"):
            kerberos.evaluate_index(client, index, load_hunt(HUNT), page_size=2, max_alerts=1)
        actual = kerberos.evaluate_index(client, index, load_hunt(HUNT), page_size=2)
        assert actual["alerts"] == expected() + [{
            **expected()[0], "window.start": "2026-01-01T00:00:01Z", "window.end": "2026-01-01T00:05:01Z",
            "distinct_service_accounts": 6, "rc4_requests": 6,
        }]


def test_native_xml_to_elastic_cli_round_trip(client, tmp_path):
    template = (ROOT / "tests/fixtures/kerberos/xml/4769-v0.xml").read_text()
    paths = []
    for i in range(5):
        path = tmp_path / f"4769-{i}.xml"
        path.write_text(template.replace("<EventRecordID>1001</EventRecordID>",
                                         f"<EventRecordID>{1001+i}</EventRecordID>")
                        .replace("333333333-1101", f"333333333-{1101+i}"))
        paths.append(path)
    normalized = subprocess.run([sys.executable, str(ROOT / "tools/normalize_windows_kerberos.py"),
                                  *map(str, paths)], cwd=ROOT, check=True, capture_output=True, text=True, timeout=30)
    events_path = tmp_path / "4769.jsonl"
    events_path.write_text(normalized.stdout)
    index = "attck-test-kerberos-cli-" + uuid4().hex

    def cli(*args):
        result = subprocess.run([sys.executable, str(ROOT / "tools/elastic_kerberos.py"), "--index", index,
                                 *map(str, args)], cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)

    cli("create-index")
    try:
        assert cli("ingest", events_path)["inserted_events"] == 5
        assert cli("ingest", events_path)["existing_events"] == 5
        result = cli("evaluate", HUNT, "--page-size", "2")
        assert result["alerts"] == [{
            "window.start": "2025-12-31T23:55:10.123456Z", "window.end": "2026-01-01T00:00:10.123456Z",
            "user.domain": "lab.example", "user.name": "alice@lab.example", "source.ip": "192.0.2.10",
            "distinct_service_accounts": 5, "rc4_requests": 5,
        }]
    finally:
        client.request("DELETE", kerberos.index_path(index))
