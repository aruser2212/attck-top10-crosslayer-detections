"""Source admission is independent of whether a valid record is suspicious."""
from copy import deepcopy
import json

import pytest

from tools import web_correlation_profile as profile
from tools.correlate_webshell import correlate


def file_event(**changes):
    return {
        "@timestamp": "2026-01-01T00:00:00Z", "event.id": "file-1", "event.dataset": "host.file",
        "host.id": "web-1", "resource.namespace": "container-A:/srv/site",
        "file.path": "/var/www/html/admin.php", "file.operation": "write", "event.success": True,
        **changes,
    }


def request_event(**changes):
    return {
        "@timestamp": "2026-01-01T00:00:01Z", "event.id": "request-1", "event.dataset": "web.access",
        "host.id": "web-1", "resource.namespace": "container-A:/srv/site",
        "web.resource_path": "/var/www/html/admin.php", "url.query": "cmd=inert",
        **changes,
    }


def test_both_source_types_retain_exact_namespace_paths_and_input_payload():
    events = [file_event(), request_event()]
    before = deepcopy(events)
    prepared, counts = profile.prepare_events(events)
    assert prepared == before and events == before
    assert counts == {"input_events": 2, "unique_events": 2, "duplicate_events": 0}
    assert prepared[0]["resource.namespace"] == "container-A:/srv/site"
    assert len(correlate(prepared, webroots=["/var/www/html"])["alerts"]) == 1


@pytest.mark.parametrize("event", [
    file_event(**{"file.operation": "read"}),
    file_event(**{"file.operation": "open"}),
    file_event(**{"event.success": False}),
    file_event(**{"file.path": "/var/www/html/upload.txt"}),
    file_event(**{"file.path": "/tmp/admin.php"}),
    request_event(**{"url.query": ""}),
    request_event(**{"url.query": "page=help&notcmd=inert"}),
])
def test_well_formed_benign_records_are_admitted(event):
    assert profile.prepare_events([event])[0] == [event]
    assert correlate([event], webroots=["/var/www/html"])["alerts"] == []


@pytest.mark.parametrize("field", ["event.id", "host.id", "resource.namespace"])
@pytest.mark.parametrize("value", [None, "", " ", 7, False, " leading", "trailing ", "a\x00b", "a\x1fb", "a\x7fb"])
def test_identity_fields_require_exact_nonempty_strings_without_controls(field, value):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{field: value})])


@pytest.mark.parametrize("field", ["host.id", "resource.namespace", "file.path", "file.operation", "event.success"])
def test_missing_host_file_fields_are_errors_not_guessed_values(field):
    event = file_event()
    del event[field]
    with pytest.raises(ValueError):
        profile.prepare_events([event])


@pytest.mark.parametrize("field", ["host.id", "resource.namespace", "web.resource_path", "url.query"])
def test_missing_web_fields_are_errors_not_inferred_from_other_context(field):
    event = request_event(**{"url.full": "https://www.example.invalid/admin.php?cmd=inert"})
    del event[field]
    with pytest.raises(ValueError):
        profile.prepare_events([event])


@pytest.mark.parametrize("value", ["other.dataset", "Host.File", "host.file ", "", None, 42])
def test_source_dataset_is_exact(value):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{"event.dataset": value})])


@pytest.mark.parametrize("value", [1, 0, "true", "false", None])
def test_success_requires_boolean_not_elastic_coercion(value):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{"event.success": value})])


@pytest.mark.parametrize("value", ["relative/admin.php", "/var/www/../admin.php", "/var//www/admin.php", "/var/www/./admin.php", "C:\\inetpub\\wwwroot\\admin.php", ["/var/www/admin.php"], "/var/www/admin.php\x00"])
def test_paths_must_already_be_canonical_posix(value):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{"file.path": value})])
    with pytest.raises(ValueError):
        profile.prepare_events([request_event(**{"web.resource_path": value})])


@pytest.mark.parametrize("value", ["?cmd=x", "cmd=%XX", "cmd=%FF", "cmd=x#frag", 3, False, None])
def test_raw_query_errors_fail_profile_even_without_a_matching_file(value):
    with pytest.raises(ValueError):
        profile.prepare_events([request_event(**{"url.query": value})])


@pytest.mark.parametrize("value", [{"nested": "x"}, ["x"], ("x",)])
def test_context_must_also_be_flat_scalar(value):
    with pytest.raises(ValueError, match="flat"):
        profile.prepare_events([file_event(**{"collector.context": value})])


@pytest.mark.parametrize("field,value", [("event.id", "a\ud800"), ("url.query", "cmd=\ud800"), ("context", "\udfff")])
def test_all_string_fields_must_encode_as_utf8(field, value):
    with pytest.raises(ValueError, match="UTF-8"):
        profile.prepare_events([request_event(**{field: value})])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_context_is_rejected(value):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{"context.value": value})])


def test_unmapped_scalar_context_is_preserved_without_coercion():
    event = request_event(**{
        "http.response.status_code": 404, "source.ip": "192.0.2.10", "collector.offset": 1.5,
        "context": None, "process.entity_id": "proc-01", "file.hash.sha256": "inert-context",
        "resource.collector-id": "agent-01", "_collector.offset": 0,
    })
    assert profile.prepare_events([event])[0] == [event]


@pytest.mark.parametrize("field", ["file", "resource", "event", "host", "web", "url"])
def test_scalar_object_collisions_fail_before_an_elastic_batch_can_be_written(field):
    with pytest.raises(ValueError, match="mapped object path"):
        profile.prepare_events([file_event(), request_event(**{field: "scalar"})])


@pytest.mark.parametrize("field", ["file.path.child", "resource.namespace.child", "@timestamp.child", "event.success.child", "url.query.child"])
def test_mapped_scalar_fields_cannot_also_be_object_parents(field):
    with pytest.raises(ValueError, match="descends below mapped scalar"):
        profile.prepare_events([file_event(), request_event(**{field: "scalar"})])


@pytest.mark.parametrize("field", ["", ".leading", "trailing.", "empty..segment", " leading", "trailing ", "inside. spaced", "bad\x00name", "bad\x7fname", "bad\nname"])
def test_flat_field_names_must_be_unambiguous_normalized_dotted_names(field):
    with pytest.raises(ValueError, match="valid dotted field names"):
        profile.prepare_events([file_event(), request_event(**{field: "context"})])


@pytest.mark.parametrize("field", ["_id", "_routing", "_index", "_ignored", "_doc_count"])
@pytest.mark.parametrize("suffix", ["", ".context.child"])
def test_document_metadata_and_its_descendants_are_reserved(field, suffix):
    with pytest.raises(ValueError, match="reserved Elasticsearch document metadata"):
        profile.prepare_events([file_event(), request_event(**{field + suffix: "context"})])


@pytest.mark.parametrize("timestamp", ["1970-01-01T00:00:00Z", "2262-04-11T23:47:16.854775Z"])
def test_date_nanos_profile_endpoints_are_included(timestamp):
    assert profile.prepare_events([file_event(**{"@timestamp": timestamp})])[0][0]["@timestamp"] == timestamp


@pytest.mark.parametrize("timestamp", ["1969-12-31T23:59:59.999999Z", "2262-04-11T23:47:16.854776Z", "2026-01-01T00:00:00.1234567Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+03:60"])
def test_date_nanos_range_and_declared_microsecond_precision_are_strict(timestamp):
    with pytest.raises(ValueError):
        profile.prepare_events([file_event(**{"@timestamp": timestamp})])


def test_equivalent_timezones_deduplicate_without_mutating_input():
    event = file_event()
    same = file_event(**{"@timestamp": "2026-01-01T03:00:00+03:00"})
    unique, counters = profile.prepare_events([event, same])
    assert unique == [event]
    assert counters == {"input_events": 2, "unique_events": 1, "duplicate_events": 1}
    assert same["@timestamp"].endswith("+03:00")


@pytest.mark.parametrize("changes", [{"resource.namespace": "container-B:/srv/site"}, {"event.success": False}, {"event.success": 1}])
def test_conflicting_event_id_never_replaces_source_or_scope(changes):
    with pytest.raises(ValueError, match="conflicting duplicate"):
        profile.prepare_events([file_event(), file_event(**changes)])


def test_event_id_limit_is_utf8_bytes_not_character_count():
    assert profile.prepare_events([file_event(**{"event.id": "é" * 256})])[0][0]["event.id"] == "é" * 256
    with pytest.raises(ValueError, match="512-byte"):
        profile.prepare_events([file_event(**{"event.id": "é" * 257})])


def test_indexed_scope_size_is_validated_before_partial_bulk_ingestion():
    assert profile.prepare_events([file_event(**{"resource.namespace": "é" * 16383})])[0]
    with pytest.raises(ValueError, match="32766-byte"):
        profile.prepare_events([file_event(), request_event(**{"resource.namespace": "é" * 16384})])


def test_large_query_value_is_retained_as_source_without_indexed_keyword_limit():
    query = "cmd=" + "x" * 40000
    assert profile.prepare_events([request_event(**{"url.query": query})])[0][0]["url.query"] == query


@pytest.mark.parametrize("changes", [
    {"file.path": 17}, {"file.operation": True}, {"file.operation": " write "},
    {"event.success": "true"}, {"url.query": 10},
])
def test_optional_mapped_fields_cannot_be_coerced_on_other_source(changes):
    with pytest.raises(ValueError):
        profile.prepare_events([request_event(**changes)])


def test_mapping_matches_profile_and_stores_raw_query_without_indexing_values():
    mapping = json.loads(profile.MAPPING_PATH.read_text())["mappings"]
    assert mapping["_meta"]["profile"] == profile.PROFILE
    assert mapping["dynamic"] is False
    assert mapping["properties"]["@timestamp"]["type"] == "date_nanos"
    assert mapping["properties"]["resource"]["properties"]["namespace"]["type"] == "keyword"
    assert mapping["properties"]["url"]["properties"]["query"] == {
        "type": "keyword", "index": False, "doc_values": False,
    }


def test_collision_guards_cover_exactly_the_objects_and_leaves_in_mapping():
    mapping = json.loads(profile.MAPPING_PATH.read_text())["mappings"]
    objects, leaves = set(), set()

    def collect(properties, prefix=""):
        for name, definition in properties.items():
            field = prefix + name
            if "properties" in definition:
                objects.add(field)
                collect(definition["properties"], field + ".")
            else:
                leaves.add(field)

    collect(mapping["properties"])
    assert profile.MAPPED_OBJECT_FIELDS == objects
    assert profile.MAPPED_LEAF_FIELDS == leaves


def test_empty_batch_does_not_invent_events():
    assert profile.prepare_events([]) == ([], {"input_events": 0, "unique_events": 0, "duplicate_events": 0})
