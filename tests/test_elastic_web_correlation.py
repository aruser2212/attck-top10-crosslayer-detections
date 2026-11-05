"""Finite source-domain, profile and transport failures for host/HTTP replay."""
from copy import deepcopy
import json

import pytest

from tools import elastic_rolling as auth
from tools import elastic_web_correlation as web

INDEX = "attck-test-web-unit"
ROOTS = ["/var/www/html"]


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


def mapping(path=web.MAPPING_PATH):
    return {INDEX: {"mappings": json.loads(path.read_text())["mappings"]}}


def identity(uuid="web-source-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def file_event(**changes):
    return {"@timestamp": "2026-01-01T00:00:00.000001Z", "event.id": "file-1",
            "event.dataset": "host.file", "host.id": "web-1", "resource.namespace": "container-1",
            "file.path": "/var/www/html/uploads/example.php", "file.operation": "create",
            "event.success": True, **changes}


def request_event(**changes):
    return {"@timestamp": "2026-01-01T00:05:00Z", "event.id": "request-1",
            "event.dataset": "web.access", "host.id": "web-1", "resource.namespace": "container-1",
            "web.resource_path": "/var/www/html/uploads/example.php", "url.query": "cmd=inert",
            **changes}


def hit(event, ordinal):
    return {"_index": INDEX, "_id": event["event.id"], "_source": deepcopy(event),
            "sort": [event["@timestamp"], ordinal]}


def page(hits):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits}}


def search_client(events, *, size=1, final_uuid="web-source-uuid"):
    hits = [hit(event, i) for i, event in enumerate(events)]
    pages = [page(hits[offset:offset + size]) for offset in range(0, len(hits), size)]
    return Client([mapping(), identity(), {"id": "web-pit"}, *pages, page([]),
                   {"succeeded": True}, identity(final_uuid)])


def run(client, **kwargs):
    return web.evaluate_index(client, INDEX, webroots=ROOTS, **kwargs)


def test_separate_mapping_and_profile_are_used():
    client = Client([{"acknowledged": True}])
    web.create_index(client, INDEX)
    body = client.calls[0][2]
    assert body["mappings"]["_meta"]["profile"] == "attck-web-correlation-v1"
    assert body["mappings"]["properties"]["@timestamp"]["type"] == "date_nanos"
    client = Client([mapping(auth.MAPPING_PATH)])
    with pytest.raises(web.ElasticError, match="separate web-correlation-v1"):
        web.ingest_events(client, INDEX, [file_event()])
    assert not any(method != "GET" for method, _, _ in client.calls)


def test_one_pit_reads_both_sources_before_exact_join_across_pages():
    client = search_client([file_event(), request_event()])
    result = run(client, page_size=1)
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert (alert["file.event.id"], alert["http.event.id"]) == ("file-1", "request-1")
    assert alert["resource.namespace"] == "container-1"
    assert alert["elapsed_seconds"] == 299.999999
    assert result["summary"]["fetched_events"] == 2
    assert result["summary"]["fetch_pages"] == 3
    assert result["profile"] == "attck-web-correlation-v1"
    searches = [body for _, path, body in client.calls if path.startswith("/_search")]
    assert searches[0]["query"]["bool"]["filter"] == [
        {"terms": {"event.dataset": ["host.file", "web.access"]}},
    ]
    assert searches[1]["search_after"] == [file_event()["@timestamp"], 0]
    assert len([path for _, path, _ in client.calls if "/_pit?" in path]) == 1
    assert client.replies == []


def test_namespace_prevents_cross_container_join():
    client = search_client([file_event(), request_event(**{"resource.namespace": "container-2"})])
    assert run(client, page_size=1)["alerts"] == []


def test_bounded_replay_reads_precise_history_before_request_start():
    client = search_client([file_event(), request_event()])
    result = run(client, page_size=1, start="2026-01-01T00:05:00Z", end="2026-01-01T00:06:00Z")
    assert len(result["alerts"]) == 1
    query = next(body for _, path, body in client.calls if path.startswith("/_search"))
    assert query["query"]["bool"]["filter"][1] == {"range": {"@timestamp": {
        "gt": "2026-01-01T00:00:00.000000Z", "lt": "2026-01-01T00:06:00.000000Z",
    }}}


@pytest.mark.parametrize("boundary", ["2026-01-01T00:00:00Z", "2026-01-01T00:06:00Z"])
def test_backend_cannot_return_excluded_history_boundaries(boundary):
    item = file_event(**{"@timestamp": boundary})
    client = Client([mapping(), identity(), {"id": "web-pit"}, page([hit(item, 0)]), {"succeeded": True}])
    with pytest.raises(web.ElasticError, match="outside the requested history"):
        run(client, start="2026-01-01T00:05:00Z", end="2026-01-01T00:06:00Z")
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "web-pit"})


@pytest.mark.parametrize("kwargs", [
    {"window_seconds": 0}, {"window_seconds": True}, {"max_events": 0},
    {"max_alerts": False}, {"page_size": 0}, {"page_size": 10001},
    {"start": "2026-01-01T00:05:00Z"},
    {"start": "2026-01-01T00:05:00Z", "end": "2026-01-01T00:04:00Z"},
    {"start": "1969-01-01T00:00:00Z", "end": "1970-01-01T00:00:00Z"},
])
def test_invalid_configuration_is_rejected_before_network(kwargs):
    client = Client([])
    with pytest.raises(ValueError):
        run(client, **kwargs)
    assert client.calls == []


def test_invalid_webroot_is_rejected_before_network():
    client = Client([])
    with pytest.raises(ValueError):
        web.evaluate_index(client, INDEX, webroots=["../www"])
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"resource.namespace": None}, {"resource.namespace": ["container-1"]},
    {"event.success": 1}, {"file.path": "/var/www/html/../example.php"},
    {"event.dataset": "windows.security.logons"},
])
def test_invalid_source_never_reaches_ingestion_network(changes):
    client = Client([])
    with pytest.raises(ValueError):
        web.ingest_events(client, INDEX, [file_event(**changes)])
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"file": "scalar"}, {"resource": "scalar"},
    {"file.path.child": "scalar"}, {"": "invalid-field-name"},
    {"_id": "metadata"}, {"_routing": "metadata"}, {"_index": "metadata"},
    {"_ignored": "metadata"}, {"_doc_count": 1},
])
def test_invalid_second_record_prevents_any_batch_network_or_partial_write(changes):
    client = Client([])
    good = file_event()
    bad = file_event(**{"event.id": "file-2", **changes})
    with pytest.raises(ValueError):
        web.ingest_events(client, INDEX, [good, bad], batch_size=1)
    assert client.calls == []


@pytest.mark.parametrize("fault", ["timeout", "partial_shards", "id", "index", "sort", "source", "precision"])
def test_incomplete_or_corrupt_search_fails_and_closes_latest_pit(fault):
    response = page([hit(file_event(), 0)])
    response["pit_id"] = "web-pit-updated"
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
        response["hits"]["hits"][0]["_source"]["event.success"] = "true"
    else:
        response["hits"]["hits"][0]["sort"] = ["2026-01-01T00:00:00.000001001Z", 0]
    client = Client([mapping(), identity(), {"id": "web-pit"}, response, {"succeeded": True}])
    with pytest.raises(ValueError):
        run(client)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "web-pit-updated"})


def test_expected_uuid_is_checked_before_opening_pit():
    client = Client([mapping(), identity()])
    with pytest.raises(web.ElasticError, match="expected binding"):
        run(client, expected_index_uuid="different")
    assert all("/_pit" not in path for _, path, _ in client.calls)


def test_source_replacement_prevents_successful_result():
    client = search_client([file_event(), request_event()], final_uuid="replacement")
    with pytest.raises(web.ElasticError, match="replaced during web correlation"):
        run(client, page_size=1)


def test_noncandidate_rows_still_count_toward_complete_fetch_limit():
    benign = request_event(**{"url.query": "page=ordinary"})
    client = Client([mapping(), identity(), {"id": "web-pit"},
                     page([hit(file_event(), 0)]), page([hit(benign, 1)]), {"succeeded": True}])
    with pytest.raises(web.ElasticError, match="max_events"):
        run(client, page_size=1, max_events=1)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "web-pit"})


def test_existing_event_conflict_never_overwrites_source():
    item = file_event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                    "found": True, "_source": {**item, "resource.namespace": "other"}}]}])
    with pytest.raises(web.ElasticError, match="Conflicting stored"):
        web.ingest_events(client, INDEX, [item])
    assert not any("_bulk" in path for _, path, _ in client.calls)


def test_redelivery_refreshes_already_existing_events_without_another_write():
    item = file_event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                    "found": True, "_source": item}]}, identity(),
                    {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = web.ingest_events(client, INDEX, [item, deepcopy(item)])
    assert (result["inserted_events"], result["existing_events"], result["duplicate_events"]) == (0, 1, 1)
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)
    assert not any("_bulk" in path for _, path, _ in client.calls)
