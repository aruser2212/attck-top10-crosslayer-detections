"""Exercise the documented subprocess CLI, including bounded backlog and SIGTERM."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticClient, ElasticHTTPError, index_path

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL for real Basic pipeline tests")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def pipeline_args(client, tmp_path, start):
    source, alerts = "attck-pipeline-test-" + uuid4().hex, "attck-pipeline-alerts-" + uuid4().hex
    spool, state = tmp_path / "spool", tmp_path / "state"
    spool.mkdir()
    args = [sys.executable, str(ROOT / "tools/run_auth_pipeline.py"),
            "--url", client.url, "--source-index", source, "--alerts-index", alerts,
            "--spool", str(spool), "--state-dir", str(state), "--start", start, "--initialize"]
    try:
        yield args, spool, state, source, alerts
    finally:
        for index in (source, alerts):
            try:
                client.request("DELETE", index_path(index))
            except ElasticHTTPError as exc:
                # An assertion before bootstrap may leave the index absent.
                if exc.status != 404:
                    raise


def write_events(path, count, *, offset=0, timestamp="2026-01-01T00:01:00Z"):
    records = [{"@timestamp": timestamp, "event.id": f"pipeline-event-{i}",
                "event.dataset": "windows.security.logons", "event.code": "4625",
                "source.ip": "192.0.2.10", "target.user": "lab\\alice"}
               for i in range(offset, offset + count)]
    temporary = path.with_suffix(".tmp")
    temporary.write_text("".join(json.dumps(event) + "\n" for event in records), encoding="utf-8")
    temporary.rename(path)


def invoke(args, *, expected=0):
    result = subprocess.run(args, cwd=ROOT.parent, capture_output=True, text=True, timeout=45)
    assert result.returncode == expected, result.stderr + result.stdout
    return json.loads(result.stdout)


def documents(client, index):
    client.request("POST", index_path(index) + "/_refresh")
    return client.request("POST", index_path(index) + "/_search", {"size": 20, "query": {"match_all": {}}})["hits"]["hits"]


def test_cli_backlog_restart_late_event_and_idempotent_revision(client, tmp_path):
    with pipeline_args(client, tmp_path, "2026-01-01T00:00:00Z") as (base, spool, state, source, alerts):
        write_events(spool / "a.ready.jsonl", 9)
        write_events(spool / "b.ready.jsonl", 1, offset=9)
        args = [*base, "--once", "--at", "2026-01-01T00:12:00Z", "--max-files", "1"]
        first = invoke(args, expected=2)
        assert first["status"] == "catching_up"
        assert first["ingestion"]["unacknowledged_files"] == 1
        assert not (state / "detections.sqlite").exists()
        assert documents(client, alerts) == []
        second = invoke(args)
        assert second["detection"]["alerts"]["created"] == 1
        assert len(documents(client, source)) == 10
        original = documents(client, alerts)
        assert len(original) == 1 and original[0]["_source"]["metrics"]["fails"] == 10
        invoke(args)
        assert documents(client, alerts)[0]["_source"]["revision"] == 1
        write_events(spool / "late.ready.jsonl", 1, offset=10)
        # Drain with a larger bound; a fresh process reuses both durable ledgers.
        later = invoke([*base, "--once", "--at", "2026-01-01T00:22:00Z"])
        assert later["detection"]["alerts"]["updated"] == 1
        current = documents(client, alerts)
        assert len(current) == 1 and current[0]["_id"] == original[0]["_id"]
        assert current[0]["_source"]["metrics"]["fails"] == 11
        assert current[0]["_source"]["revision"] == 2


def test_watch_process_stops_on_sigterm_after_successful_native_cycle(client, tmp_path):
    now = datetime.now(timezone.utc)
    closed = int((now - timedelta(minutes=2)).timestamp()) // 600 * 600
    start = datetime.fromtimestamp(closed - 600, tz=timezone.utc)
    start_text = start.isoformat().replace("+00:00", "Z")
    with pipeline_args(client, tmp_path, start_text) as (base, spool, _, _, alerts):
        write_events(spool / "events.ready.jsonl", 10,
                     timestamp=(start + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"))
        process = subprocess.Popen([*base, "--watch", "--interval", "0.1"], cwd=ROOT.parent,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            readable, _, _ = select.select([process.stdout], [], [], 40)
            assert readable, "watch did not report a native iteration"
            first = json.loads(process.stdout.readline())
            assert first["ok"], first
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
            assert len(documents(client, alerts)) == 1
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
