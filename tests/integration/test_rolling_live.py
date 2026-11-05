"""Native auth-v2 date_nanos ingestion and exact bounded rolling replay."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tools.elastic_rolling import (
    ElasticClient, ElasticError, create_index, evaluate_index, get_index_identity,
    index_path, ingest_events,
)
from tools.hunt_engine import HuntError, prepare_events
from tools.rolling_hunt import evaluate_hunt, load_hunt

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/rolling/auth_cases.json"
pytestmark = pytest.mark.integration


def cases():
    manifest = json.loads(FIXTURES.read_text(encoding="utf-8"))
    selected = [case for case in manifest["cases"] if Path(case["hunt"]).name.startswith("win_4625_")]
    assert len(selected) >= 10, "Windows rolling fixtures must be present, not an empty test run"
    return selected


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic rolling checks")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"), username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def index_for(client):
    name = "attck-test-rolling-" + uuid4().hex
    create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", index_path(name))


@pytest.mark.parametrize("case", cases(), ids=lambda case: case["name"])
def test_shared_hand_declared_cases_on_native_date_nanos(client, case):
    rule = load_hunt(ROOT / case["hunt"])
    bounds = case.get("bounds", {})
    assert evaluate_hunt(rule, case["events"], **bounds)["alerts"] == case["expected_alerts"]
    with index_for(client) as index:
        if case["name"] == "brute_wrong_source_and_success_filtered":
            # Offline v2 can reject/filter those records individually. This
            # strict Windows index refuses a mixed source/type batch before ES
            # can coerce its keyword fields, instead of pretending native parity.
            with pytest.raises(ElasticError):
                ingest_events(client, index, case["events"])
            assert client.request("GET", index_path(index) + "/_count")["count"] == 0
            return
        ingest_events(client, index, case["events"])
        actual = evaluate_index(client, index, rule, page_size=2, **bounds)
        assert actual["alerts"] == case["expected_alerts"], case["name"]


def positive_case():
    return next(case for case in cases() if case["name"] == "brute_10_threshold")


def test_native_immutable_ids_duplicate_refresh_and_conflicts(client):
    case = positive_case()
    rule = load_hunt(ROOT / case["hunt"])
    with index_for(client) as index:
        assert ingest_events(client, index, case["events"])["inserted_events"] == 10
        assert ingest_events(client, index, case["events"])["inserted_events"] == 0
        conflict = {**case["events"][0], "target.user": "different-account"}
        with pytest.raises(ElasticError, match="Conflicting"):
            ingest_events(client, index, [conflict])
        assert evaluate_index(client, index, rule, page_size=1)["alerts"] == case["expected_alerts"]


def test_native_event_and_alert_caps_never_return_truncated_results(client):
    case = next(case for case in cases() if case["name"] == "brute_each_qualifying_timestamp_emits")
    rule = load_hunt(ROOT / case["hunt"])
    with index_for(client) as index:
        ingest_events(client, index, case["events"])
        with pytest.raises(ElasticError, match="max_events"):
            evaluate_index(client, index, rule, page_size=2, max_events=10)
        with pytest.raises(HuntError, match="max_alerts"):
            evaluate_index(client, index, rule, page_size=2, max_alerts=1)
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == case["expected_alerts"]


def test_native_source_replacement_rejects_old_uuid_binding(client):
    case = positive_case()
    rule = load_hunt(ROOT / case["hunt"])
    with index_for(client) as index:
        original = get_index_identity(client, index)
        client.request("DELETE", index_path(index))
        create_index(client, index)
        assert get_index_identity(client, index)["uuid"] != original["uuid"]
        with pytest.raises(ElasticError, match="expected binding"):
            evaluate_index(client, index, rule, expected_index_uuid=original["uuid"])


@pytest.mark.parametrize("violation", ["wrong_document_id", "coerced_keyword"])
def test_native_direct_writes_cannot_bypass_source_contract(client, violation):
    case = positive_case()
    rule = load_hunt(ROOT / case["hunt"])
    item = deepcopy(case["events"][0])
    with index_for(client) as index:
        identifier = item["event.id"]
        if violation == "wrong_document_id":
            identifier = "unrelated-document-id"
        else:
            item["event.code"] = 4625
        client.request("PUT", index_path(index) + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ElasticError):
            evaluate_index(client, index, rule, page_size=1)


def test_native_existing_only_retry_crosses_refresh_barrier(client):
    case = positive_case()
    rule = load_hunt(ROOT / case["hunt"])
    normalized, _ = prepare_events(case["events"])
    with index_for(client) as index:
        client.request("PUT", index_path(index) + "/_settings", {"index": {"refresh_interval": "-1"}})
        lines = []
        for item in normalized:
            lines.extend([json.dumps({"create": {"_id": item["event.id"]}}), json.dumps(item)])
        response = client.request("POST", index_path(index) + "/_bulk?refresh=false", "\n".join(lines) + "\n", ndjson=True)
        assert response["errors"] is False
        assert client.request("GET", index_path(index) + "/_count")["count"] == 0
        assert ingest_events(client, index, case["events"])["inserted_events"] == 0
        assert evaluate_index(client, index, rule, page_size=2)["alerts"] == case["expected_alerts"]


def test_native_subsecond_bounds_include_context_and_exclude_both_outer_edges(client):
    case = positive_case()
    rule = load_hunt(ROOT / case["hunt"])
    template = case["events"][0]
    context = "2026-01-01T00:00:00.123456Z"
    start, end = "2026-01-01T00:05:00.123456Z", "2026-01-01T00:05:00.123457Z"
    events = [{**template, "event.id": f"history-{i}", "@timestamp": "2026-01-01T00:00:00.123457Z"}
              for i in range(9)]
    events.extend([{**template, "event.id": "anchor", "@timestamp": start},
                   {**template, "event.id": "excluded-floor", "@timestamp": context},
                   {**template, "event.id": "excluded-end", "@timestamp": end}])
    with index_for(client) as index:
        ingest_events(client, index, events)
        result = evaluate_index(client, index, rule, start=start, end=end, page_size=2, max_events=10)
    assert result["alerts"] == [{
        "window.start": context, "window.end": start, "source.ip": template["source.ip"],
        "target.user": template["target.user"], "fails": 10,
    }]
    assert result["summary"]["fetched_events"] == 10
    assert result["summary"]["context_events"] == 9
