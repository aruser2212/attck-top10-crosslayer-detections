"""Native Elasticsearch Basic replay; requires an explicitly supplied ELASTIC_URL."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticClient, ElasticError, create_index, evaluate_index, index_path, ingest_events
from tools.hunt_engine import evaluate_hunt, load_hunt
from tools.normalize_windows_auth import normalize_event

ROOT = Path(__file__).resolve().parents[2]
CASES_PATH = ROOT / "tests/fixtures/hunts/auth_cases.json"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run the real Elasticsearch integration suite")
    connection = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"), username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
    status = connection.request("GET", "/_license")["license"]
    assert status["type"] == "basic", "This suite must demonstrate free Basic compatibility"
    assert status["status"] == "active"
    return connection


@contextmanager
def fixture_index(client):
    name = "attck-test-" + uuid4().hex
    create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", index_path(name))


def auth_cases():
    # Fixtures are required; a missing/empty set must fail instead of validating zero cases.
    fixture = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases = [case for case in fixture["cases"] if Path(case["hunt"]).name.startswith("win_4625_")]
    assert len(cases) >= 2, "Expected Windows brute-force and spray fixtures"
    return cases


@pytest.mark.parametrize("case", auth_cases(), ids=lambda case: case["name"])
def test_windows_auth_fixture_matches_native_elasticsearch(client, case):
    rule = load_hunt(ROOT / case["hunt"])
    reference = evaluate_hunt(rule, case["events"])
    assert reference["alerts"] == case["expected_alerts"], case["name"]
    with fixture_index(client) as index:
        ingest_events(client, index, case["events"])
        # Tiny pages exercise exact cardinality and composite pagination.
        actual = evaluate_index(client, index, rule, page_size=2)
        assert actual["alerts"] == case["expected_alerts"], case["name"]


def test_native_ingestion_is_idempotent_and_rejects_conflicts(client):
    case = next(case for case in auth_cases() if case["expected_alerts"])
    events = deepcopy(case["events"])
    rule = load_hunt(ROOT / case["hunt"])
    with fixture_index(client) as index:
        first = ingest_events(client, index, events)
        second = ingest_events(client, index, events)
        assert first["inserted_events"] > 0
        assert second["inserted_events"] == 0
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == case["expected_alerts"]
        conflict = deepcopy(events[0])
        conflict["target.user"] = "changed-account"
        with pytest.raises(ElasticError, match="Conflicting stored"):
            ingest_events(client, index, [conflict])
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == case["expected_alerts"]


def test_native_not_does_not_match_missing_field(client):
    rule = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml")
    rule["where"] = {"not": {"field": "event.code", "op": "eq", "value": "4624"}}
    events = [{"event.id": f"missing-code-{i}", "event.dataset": rule["dataset"], "@timestamp": "2026-01-01T00:01:00Z", "source.ip": "192.0.2.1", "target.user": "alice"} for i in range(10)]
    assert evaluate_hunt(rule, events)["alerts"] == []
    with fixture_index(client) as index:
        ingest_events(client, index, events)
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == []


def test_exported_windows_xml_normalization_to_native_alert(client):
    sample = (ROOT / "tests/fixtures/windows/4625.xml").read_text(encoding="utf-8")
    events = [normalize_event(sample.replace("<EventRecordID>1001</EventRecordID>", f"<EventRecordID>{1001 + i}</EventRecordID>")) for i in range(10)]
    rule = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml")
    expected = [{"window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:05:00Z", "source.ip": "192.0.2.10", "target.user": "lab\\alice", "fails": 10}]
    assert evaluate_hunt(rule, events)["alerts"] == expected
    with fixture_index(client) as index:
        ingest_events(client, index, events)
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == expected


def test_native_whitespace_and_coerced_names_rejected_before_ingestion(client):
    base = {"event.id": "invalid-name", "event.dataset": "windows.security.logons", "@timestamp": "2026-01-01T00:01:00Z", "event.code": "4625", "source.ip": "192.0.2.1"}
    with fixture_index(client) as index:
        for name in ("   ", "\u00a0", 123, ["alice"]):
            with pytest.raises(ElasticError):
                ingest_events(client, index, [{**base, "target.user": name}])
        assert client.request("GET", index_path(index) + "/_count")["count"] == 0


def test_windows_account_case_variants_are_one_user_in_native_elasticsearch(client):
    sample = (ROOT / "tests/fixtures/windows/4625.xml").read_text(encoding="utf-8")
    variants = ["".join(character.upper() if mask & (1 << position) else character for position, character in enumerate("alice")) for mask in range(15)]
    events = []
    for number, account in enumerate(variants):
        xml = sample.replace("<EventRecordID>1001</EventRecordID>", f"<EventRecordID>{1001 + number}</EventRecordID>")
        xml = xml.replace('<Data Name="TargetUserName">alice</Data>', f'<Data Name="TargetUserName">{account}</Data>')
        events.append(normalize_event(xml))
    spray = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_spray_agg.hunt.yaml")
    brute = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml")
    expected_brute = [{"window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:05:00Z", "source.ip": "192.0.2.10", "target.user": "lab\\alice", "fails": 15}]
    assert evaluate_hunt(spray, events)["alerts"] == []
    assert evaluate_hunt(brute, events)["alerts"] == expected_brute
    with fixture_index(client) as index:
        ingest_events(client, index, events)
        assert evaluate_index(client, index, spray, page_size=2)["alerts"] == []
        assert evaluate_index(client, index, brute, page_size=2)["alerts"] == expected_brute


@pytest.mark.parametrize("prewritten_count", [10, 8], ids=["all-existing", "partial-existing"])
def test_retry_refreshes_realtime_existing_events_before_acknowledgement(client, prewritten_count):
    """A prior interrupted write can exist in the translog but remain invisible to PIT."""
    case = next(case for case in auth_cases() if case["name"] == "brute_10_threshold")
    with fixture_index(client) as index:
        client.request("PUT", index_path(index) + "/_settings", {"index": {"refresh_interval": "-1"}})
        lines = []
        for event in case["events"][:prewritten_count]:
            lines.extend([json.dumps({"create": {"_id": event["event.id"]}}), json.dumps(event)])
        written = client.request(
            "POST", index_path(index) + "/_bulk?refresh=false",
            "\n".join(lines) + "\n", ndjson=True,
        )
        assert written["errors"] is False
        assert client.request("GET", index_path(index) + "/_count")["count"] == 0
        realtime = client.request(
            "POST", index_path(index) + "/_mget",
            {"ids": [event["event.id"] for event in case["events"][:prewritten_count]]},
        )
        assert all(document["found"] for document in realtime["docs"])

        acknowledged = ingest_events(client, index, case["events"])
        assert acknowledged["existing_events"] == prewritten_count
        assert acknowledged["inserted_events"] == 10 - prewritten_count
        assert client.request("GET", index_path(index) + "/_count")["count"] == 10
        assert evaluate_index(client, index, load_hunt(ROOT / case["hunt"]))["alerts"] == case["expected_alerts"]
