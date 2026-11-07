"""Profile isolation and complete finite Sysmon replay transport failures."""
from copy import deepcopy
import json

import pytest

from tools import elastic_lsass as lsass
from tools import elastic_rolling as auth

INDEX = "attck-test-lsass-unit"


class Client:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.replies, (method, path)
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def mapping(path=lsass.MAPPING_PATH):
    return {INDEX: {"mappings": json.loads(path.read_text())["mappings"]}}


def identity(uuid="lsass-source-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def event(**changes):
    return {"@timestamp": "2026-01-01T00:00:00Z", "event.id": "access-1",
            "event.dataset": lsass.DATASET, "event.code": "10", "host.name": "host01",
            "source.process.guid": "00000001-0000-0000-0000-000000000001",
            "target.process.guid": "00000002-0000-0000-0000-000000000002",
            "source.image": r"C:\Tools\diagnostic.exe", "target.image": r"C:\Windows\System32\lsass.exe",
            "process.access_mask": 0x10, **changes}


def hit(item, ordinal):
    return {"_index": INDEX, "_id": item["event.id"], "_source": deepcopy(item),
            "sort": [item["@timestamp"], ordinal]}


def page(hits):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits}}


def search_client(events, *, size=1, final_uuid="lsass-source-uuid"):
    hits = [hit(item, i) for i, item in enumerate(events)]
    pages = [page(hits[offset:offset + size]) for offset in range(0, len(hits), size)]
    return Client([mapping(), identity(), {"id": "lsass-pit"}, *pages, page([]),
                   {"succeeded": True}, identity(final_uuid)])


def test_dedicated_profile_cannot_be_used_on_auth_index():
    client = Client([mapping(auth.MAPPING_PATH)])
    with pytest.raises(lsass.ElasticError, match="separate lsass-v1"):
        lsass.ingest_events(client, INDEX, [event()])
    assert not any(method != "GET" for method, _, _ in client.calls)


def test_complete_paginated_snapshot_includes_candidates_and_noncandidates():
    events = [event(), event(**{"event.id": "query-only", "process.access_mask": 0x1000}),
              event(**{"event.id": "av-read", "@timestamp": "2026-01-01T00:00:00.000001Z",
                       "source.image": r"C:\Program Files\Defender\MsMpEng.exe", "process.access_mask": 0x1410})]
    client = search_client(events)
    result = lsass.evaluate_index(client, INDEX, page_size=1)
    assert [a["event.id"] for a in result["alerts"]] == ["access-1", "av-read"]
    assert [a["process.access_mask"] for a in result["alerts"]] == [0x10, 0x1410]
    assert result["summary"]["fetched_events"] == 3
    assert result["summary"]["fetch_pages"] == 4
    assert result["profile"] == "attck-lsass-v1"
    searches = [body for _, path, body in client.calls if path.startswith("/_search")]
    assert searches[0]["query"]["bool"]["filter"] == [{"term": {"event.dataset": lsass.DATASET}}]
    assert searches[1]["search_after"] == [events[0]["@timestamp"], 0]
    assert len([path for _, path, _ in client.calls if "/_pit?" in path]) == 1
    assert client.replies == []


def test_exact_inclusive_start_is_preserved_in_query_and_result():
    client = search_client([event()])
    result = lsass.evaluate_index(client, INDEX, page_size=1,
                                  start="2026-01-01T00:00:00Z", end="2026-01-01T00:00:00.000001Z")
    assert [a["event.id"] for a in result["alerts"]] == ["access-1"]
    query = next(body for _, path, body in client.calls if path.startswith("/_search"))
    assert query["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {
        "gte": "2026-01-01T00:00:00.000000Z", "lt": "2026-01-01T00:00:00.000001Z",
    }}}


@pytest.mark.parametrize("timestamp", ["2025-12-31T23:59:59.999999Z", "2026-01-01T00:00:00.000001Z"])
def test_backend_cannot_return_rows_outside_inclusive_exclusive_bounds(timestamp):
    client = search_client([event(**{"@timestamp": timestamp})])
    with pytest.raises(lsass.ElasticError, match="outside the requested LSASS"):
        lsass.evaluate_index(client, INDEX, start="2026-01-01T00:00:00Z",
                              end="2026-01-01T00:00:00.000001Z")
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "lsass-pit"})


@pytest.mark.parametrize("kwargs", [
    {"max_events": 0}, {"max_events": True}, {"max_alerts": 0}, {"max_alerts": False},
    {"page_size": 0}, {"page_size": 10001}, {"page_size": True},
    {"start": "2026-01-01T00:00:00Z"},
    {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
    {"start": "1969-01-01T00:00:00Z", "end": "1970-01-01T00:00:00Z"},
])
def test_invalid_configuration_fails_before_network(kwargs):
    client = Client([])
    with pytest.raises(ValueError):
        lsass.evaluate_index(client, INDEX, **kwargs)
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"process.access_mask": "0x10"}, {"source.process.guid": None},
    {"source.process.guid": "00000000-0000-0000-0000-000000000000"},
    {"event.dataset": "windows.security.logons"}, {"target.image": "lsass.exe"},
    {"source": "alias"}, {"source.process.guid.child": "alias"},
    {"host.name": "HOST01"}, {"_routing": "unsupported-metadata"},
])
def test_invalid_second_record_prevents_any_batch_write(changes):
    client = Client([])
    with pytest.raises(ValueError):
        lsass.ingest_events(client, INDEX, [event(), event(**{"event.id": "access-2", **changes})], batch_size=1)
    assert client.calls == []


@pytest.mark.parametrize("fault", ["timeout", "partial_shards", "id", "index", "sort", "source", "precision"])
def test_incomplete_or_corrupt_search_fails_and_closes_latest_pit(fault):
    response = page([hit(event(), 0)])
    response["pit_id"] = "lsass-pit-updated"
    if fault == "timeout":
        response["timed_out"] = True
    elif fault == "partial_shards":
        response["_shards"] = {"total": 2, "successful": 1, "failed": 1}
    elif fault == "id":
        response["hits"]["hits"][0]["_id"] = "different"
    elif fault == "index":
        response["hits"]["hits"][0]["_index"] = "different"
    elif fault == "sort":
        response["hits"]["hits"][0]["sort"] = ["2026-01-01T00:00:01Z", 0]
    elif fault == "source":
        response["hits"]["hits"][0]["_source"]["process.access_mask"] = True
    else:
        response["hits"]["hits"][0]["sort"] = ["2026-01-01T00:00:00.000000001Z", 0]
    client = Client([mapping(), identity(), {"id": "lsass-pit"}, response, {"succeeded": True}])
    with pytest.raises(ValueError):
        lsass.evaluate_index(client, INDEX)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "lsass-pit-updated"})


def test_uuid_binding_is_checked_before_opening_pit():
    client = Client([mapping(), identity()])
    with pytest.raises(lsass.ElasticError, match="expected binding"):
        lsass.evaluate_index(client, INDEX, expected_index_uuid="different")
    assert all("/_pit" not in path for _, path, _ in client.calls)


def test_replaced_source_prevents_successful_result():
    client = search_client([event()], final_uuid="replacement")
    with pytest.raises(lsass.ElasticError, match="replaced during LSASS"):
        lsass.evaluate_index(client, INDEX)


def test_noncandidate_rows_count_toward_complete_read_limit():
    benign = event(**{"event.id": "query-only", "process.access_mask": 0x1000})
    client = Client([mapping(), identity(), {"id": "lsass-pit"}, page([hit(event(), 0)]),
                     page([hit(benign, 1)]), {"succeeded": True}])
    with pytest.raises(lsass.ElasticError, match="max_events"):
        lsass.evaluate_index(client, INDEX, page_size=1, max_events=1)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "lsass-pit"})


def test_existing_event_conflict_does_not_overwrite_source():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                     "found": True, "_source": {**item, "process.access_mask": 0x1000}}]}])
    with pytest.raises(lsass.ElasticError, match="Conflicting stored"):
        lsass.ingest_events(client, INDEX, [item])
    assert not any("_bulk" in path for _, path, _ in client.calls)


def test_retry_refreshes_existing_events_without_rewriting():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                     "found": True, "_source": item}]}, identity(),
                     {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = lsass.ingest_events(client, INDEX, [item, deepcopy(item)])
    assert (result["inserted_events"], result["existing_events"], result["duplicate_events"]) == (0, 1, 1)
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)
    assert not any("_bulk" in path for _, path, _ in client.calls)
