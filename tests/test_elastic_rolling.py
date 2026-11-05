from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path

import pytest

from tools.elastic_rolling import (
    ElasticError, MAPPING_PATH, MAX_TIME, MIN_TIME, checked_time,
    evaluate_index, ingest_events,
)
from tools.hunt_engine import HuntError, format_timestamp, parse_timestamp
from tools.rolling_hunt import evaluate_hunt, load_hunt

ROOT = Path(__file__).resolve().parents[1]
INDEX = "attck-test-rolling-unit"
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"


class Client:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.replies, (method, path)
        value = self.replies.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def mapping():
    return {INDEX: {"mappings": json.loads(MAPPING_PATH.read_text())["mappings"]}}


def identity(uuid="source-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def event(i=0, at="2026-01-01T00:05:00Z"):
    return {"@timestamp": at, "event.id": f"event-{i}", "event.dataset": "windows.security.logons",
            "event.code": "4625", "source.ip": "192.0.2.1", "target.user": "alice"}


def hit(item, ordinal):
    return {"_index": INDEX, "_id": item["event.id"], "_source": deepcopy(item), "sort": [item["@timestamp"], ordinal]}


def page(hits):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {"hits": hits}}


def search_client(items, size=3, *, final_uuid="source-uuid"):
    ordered = sorted(items, key=lambda item: parse_timestamp(item["@timestamp"]))
    hits = [hit(item, i) for i, item in enumerate(ordered)]
    pages = [page(hits[offset:offset + size]) for offset in range(0, len(hits), size)]
    return Client([mapping(), identity(), {"id": "pit"}, *pages, page([]), {"succeeded": True}, identity(final_uuid)])


def test_atomic_ties_cross_pages_and_match_reference():
    items = [event(i) for i in range(10)]
    client = search_client(items)
    rule = load_hunt(BRUTE)
    actual = evaluate_index(client, INDEX, rule, page_size=3)
    assert actual["alerts"] == evaluate_hunt(rule, items)["alerts"]
    assert len(actual["alerts"]) == 1
    assert actual["alerts"][0]["fails"] == 10
    searches = [body for method, path, body in client.calls if path.startswith("/_search")]
    assert searches[1]["search_after"] == [items[2]["@timestamp"], 2]
    assert searches[0]["sort"][0]["@timestamp"]["numeric_type"] == "date_nanos"
    assert client.replies == []


def test_bounds_fetch_strict_context_before_emission_start():
    items = [event(i, "2026-01-01T00:00:00.000002Z") for i in range(9)] + [event(9, "2026-01-01T00:05:00.000001Z")]
    bounds = {"start": "2026-01-01T00:05:00.000001Z", "end": "2026-01-01T00:05:00.000002Z"}
    client = search_client(items)
    result = evaluate_index(client, INDEX, load_hunt(BRUTE), page_size=3, **bounds)
    assert result["alerts"][0]["fails"] == 10
    search = next(body for _, path, body in client.calls if path.startswith("/_search"))
    assert search["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {"gt": "2026-01-01T00:00:00.000001Z", "lt": bounds["end"]}}}


def test_whole_second_query_bounds_preserve_explicit_fractional_precision():
    client = search_client([])
    evaluate_index(client, INDEX, load_hunt(BRUTE),
                   start="2026-01-01T03:10:00+03:00", end="2026-01-01T00:15:00Z")
    search = next(body for _, path, body in client.calls if path.startswith("/_search"))
    # Without the fractional zeros, native ES rounds the exclusive lower bound
    # up through the entire second and silently loses the earliest context.
    assert search["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {
        "gt": "2026-01-01T00:05:00.000000Z", "lt": "2026-01-01T00:15:00.000000Z",
    }}}


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(timed_out=True),
    lambda value: value.pop("timed_out"),
    lambda value: value["_shards"].update(failed=1),
    lambda value: value["_shards"].update(successful=0),
    lambda value: value.pop("_shards"),
    lambda value: value.update(terminated_early=True),
])
def test_partial_search_fails_and_closes_pit(mutate):
    response = page([])
    mutate(response)
    client = Client([mapping(), identity(), {"id": "pit"}, response, {"succeeded": True}])
    with pytest.raises(ElasticError, match="incomplete"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "pit"})


@pytest.mark.parametrize("mutation,match", [
    (lambda value: value.update(_id="different"), "identity"),
    (lambda value: value.update(_index="other-index"), "metadata"),
    (lambda value: value.update(sort=["2026-01-01T00:05:00.000000001Z", 1]), "sub-microsecond"),
    (lambda value: value.update(sort=["2026-01-01T00:05:00.000001Z", 1]), "differs"),
    (lambda value: value.update(sort=["2026-01-01T00:05:00Z", True]), "sort key"),
    (lambda value: value["_source"].update({"target.user": ["alice"]}), "scalar"),
])
def test_invalid_source_or_sort_never_returns_partial_results(mutation, match):
    value = hit(event(), 0)
    mutation(value)
    client = Client([mapping(), identity(), {"id": "pit"}, page([value]), {"succeeded": True}])
    with pytest.raises(ElasticError, match=match):
        evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert client.calls[-1][0] == "DELETE"


def test_search_after_requires_strict_progress():
    first = hit(event(0), 5)
    second = hit(event(1), 4)
    client = Client([mapping(), identity(), {"id": "pit"}, page([first]), page([second]), {"succeeded": True}])
    with pytest.raises(ElasticError, match="did not advance"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), page_size=1)


def test_duplicate_event_id_even_with_new_sort_is_rejected():
    client = Client([mapping(), identity(), {"id": "pit"}, page([hit(event(), 0)]), page([hit(event(), 1)]), {"succeeded": True}])
    with pytest.raises(ElasticError, match="identity"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), page_size=1)


def test_event_cap_checks_one_extra_hit_then_fails_closed():
    hits = [hit(event(i), i) for i in range(2)]
    client = Client([mapping(), identity(), {"id": "pit"}, page([hits[0]]), page([hits[1]]), {"succeeded": True}])
    with pytest.raises(ElasticError, match="max_events"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), page_size=1, max_events=1)
    assert client.calls[-1][0] == "DELETE"


def test_alert_cap_fails_after_fetch_and_pit_cleanup():
    items = [event(i, f"2026-01-01T00:05:{i:02}Z") for i in range(11)]
    client = search_client(items)
    with pytest.raises(HuntError, match="max_alerts"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), page_size=3, max_alerts=1)
    assert client.calls[-1][0] == "DELETE"


def test_uuid_replacement_is_detected_without_optional_binding():
    client = search_client([], final_uuid="replacement")
    with pytest.raises(ElasticError, match="replaced"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))


def test_explicit_wrong_uuid_fails_before_pit():
    client = Client([mapping(), identity()])
    with pytest.raises(ElasticError, match="expected binding"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), expected_index_uuid="different")
    assert all("/_pit" not in path for _, path, _ in client.calls)


def test_v1_profile_is_not_accepted_or_modified():
    value = mapping()
    value[INDEX]["mappings"]["properties"]["@timestamp"]["type"] = "date"
    client = Client([value])
    with pytest.raises(ElasticError, match="separate auth-v2"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert all(method == "GET" for method, _, _ in client.calls)


@pytest.mark.parametrize("options", [{"max_events": 0}, {"max_alerts": True}, {"page_size": 10001}, {"start": "2026-01-01T00:00:00Z"}])
def test_invalid_options_fail_before_network(options):
    client = Client([])
    with pytest.raises(ValueError):
        evaluate_index(client, INDEX, load_hunt(BRUTE), **options)
    assert client.calls == []


@pytest.mark.parametrize("value", [MIN_TIME - timedelta(microseconds=1), MAX_TIME + timedelta(microseconds=1)])
def test_date_nanos_out_of_range_input_rejected_before_network(value):
    client = Client([])
    with pytest.raises(ElasticError, match="date_nanos range"):
        ingest_events(client, INDEX, [event(at=format_timestamp(value))])
    assert client.calls == []


def test_exact_date_nanos_supported_endpoints():
    assert checked_time(format_timestamp(MIN_TIME)) == MIN_TIME
    assert checked_time(format_timestamp(MAX_TIME)) == MAX_TIME


def test_existing_only_ingestion_still_refreshes_search_visibility():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"], "found": True, "_source": item}]}, identity(),
                     {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = ingest_events(client, INDEX, [item, item])
    assert result["inserted_events"] == 0
    assert result["duplicate_events"] == 1
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)


def test_create_only_ingestion_then_complete_refresh():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"], "found": False}]}, identity(),
                     {"errors": False, "items": [{"create": {"_index": INDEX, "_id": item["event.id"], "status": 201}}]},
                     {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    assert ingest_events(client, INDEX, [item])["inserted_events"] == 1
    body = next(body for _, path, body in client.calls if "_bulk" in path)
    assert json.loads(body.splitlines()[0]) == {"create": {"_id": item["event.id"]}}


def test_conflicting_stored_payload_preserves_types_and_never_writes():
    old = {**event(), "context": True}
    incoming = {**event(), "context": 1}
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": old["event.id"], "found": True, "_source": old}]}])
    with pytest.raises(ElasticError, match="Conflicting stored"):
        ingest_events(client, INDEX, [incoming])
    assert all("_bulk" not in path for _, path, _ in client.calls)


def test_failed_refresh_never_acknowledges_existing_records():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"], "found": True, "_source": item}]}, identity(),
                     {"_shards": {"total": 1, "successful": 0, "failed": 1}}])
    with pytest.raises(ElasticError, match="refresh"):
        ingest_events(client, INDEX, [item])


def test_initial_duplicate_conflict_never_reaches_network():
    client = Client([])
    with pytest.raises(HuntError, match="conflicting"):
        ingest_events(client, INDEX, [event(), {**event(), "target.user": "bob"}])
