"""Real Elasticsearch ingestion/restart evidence; no live Windows agent is assumed."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticClient, create_index, index_path
from tools.ingest_spool import SpoolError, SpoolFileError, SpoolImporter
import tools.ingest_spool as spool_module

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run native spool ingestion tests")
    client = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
    license = client.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return client


@contextmanager
def source_index(client):
    index = "attck-test-spool-" + uuid4().hex
    create_index(client, index)
    try:
        yield index
    finally:
        client.request("DELETE", index_path(index))


def example():
    return {"event.id": "spool-live-one", "event.dataset": "windows.security.logons",
            "@timestamp": "2026-01-01T00:00:00Z", "event.code": "4625",
            "source.ip": "192.0.2.1", "target.user": "lab\\alice"}


def paths(tmp_path):
    spool = tmp_path / "inbox"
    spool.mkdir()
    return spool, tmp_path / "state" / "spool.sqlite"


def count(client, index):
    return client.request("GET", index_path(index) + "/_count")["count"]


def test_native_spool_restart_redelivery_and_windows_xml(client, tmp_path):
    inbox, state = paths(tmp_path)
    payload = json.dumps(example()) + "\n"
    (inbox / "a.ready.jsonl").write_text(payload)
    with source_index(client) as index:
        with SpoolImporter(client, index, inbox, state) as importer:
            first = importer.scan_once()
        assert first["files_acked"] == first["events_inserted"] == count(client, index) == 1
        (inbox / "b.ready.jsonl").write_text(payload)
        (inbox / "c.ready.xml").write_text((ROOT / "tests/fixtures/windows/4625.xml").read_text())
        with SpoolImporter(client, index, inbox, state) as importer:
            second = importer.scan_once()
            third = importer.scan_once()
        assert second["files_acked"] == 2
        assert second["events_inserted"] == second["events_existing"] == 1
        assert third["files_existing"] == 3 and third["events_inserted"] == 0
        assert count(client, index) == 2
        assert all((inbox / name).exists() for name in ("a.ready.jsonl", "b.ready.jsonl", "c.ready.xml"))


@pytest.mark.parametrize("bad_line", ['{"event.id":"a","event.id":"b"}', '{"broken":', '[]'])
def test_native_spool_rejects_whole_malformed_file_before_any_write(client, tmp_path, bad_line):
    inbox, state = paths(tmp_path)
    (inbox / "bad.ready.jsonl").write_text(json.dumps(example()) + "\n" + bad_line + "\n")
    with source_index(client) as index:
        with SpoolImporter(client, index, inbox, state) as importer:
            with pytest.raises(SpoolFileError) as error:
                importer.scan_once()
            assert error.value.summary["files_acked"] == 0
        assert count(client, index) == 0


def test_native_crash_after_write_before_ack_redelivery_is_idempotent(client, tmp_path, monkeypatch):
    inbox, state = paths(tmp_path)
    (inbox / "event.ready.jsonl").write_text(json.dumps(example()) + "\n")
    real_ingest = spool_module.ingest_events
    class SimulatedProcessCrash(BaseException):
        pass
    def write_then_crash(*args, **kwargs):
        real_ingest(*args, **kwargs)
        raise SimulatedProcessCrash
    with source_index(client) as index:
        monkeypatch.setattr(spool_module, "ingest_events", write_then_crash)
        with pytest.raises(SimulatedProcessCrash):
            with SpoolImporter(client, index, inbox, state) as importer:
                importer.scan_once()
        assert count(client, index) == 1
        monkeypatch.setattr(spool_module, "ingest_events", real_ingest)
        with SpoolImporter(client, index, inbox, state) as importer:
            result = importer.scan_once()
        assert result["files_acked"] == result["events_existing"] == 1
        assert result["events_inserted"] == 0 and count(client, index) == 1


def test_native_recreated_index_cannot_reuse_old_acknowledgments(client, tmp_path):
    inbox, state = paths(tmp_path)
    (inbox / "event.ready.jsonl").write_text(json.dumps(example()) + "\n")
    with source_index(client) as index:
        with SpoolImporter(client, index, inbox, state) as importer:
            importer.scan_once()
        # Both index generations belong exclusively to this test.
        client.request("DELETE", index_path(index))
        create_index(client, index)
        with pytest.raises(SpoolError, match="different"):
            with SpoolImporter(client, index, inbox, state):
                pass
        assert count(client, index) == 0
