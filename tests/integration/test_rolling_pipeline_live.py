"""Run the rolling-v2 CLI as independent processes against Elasticsearch Basic."""
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
        pytest.skip("Set ELASTIC_URL to execute real Basic rolling pipeline checks")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"),
                           password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def pipeline(client, tmp_path, start):
    source, alerts = "attck-roll-pipeline-source-" + uuid4().hex, "attck-roll-pipeline-alerts-" + uuid4().hex
    spool, state = tmp_path / "spool", tmp_path / "state"
    spool.mkdir()
    args = [sys.executable, str(ROOT / "tools/run_rolling_pipeline.py"),
            "--url", client.url, "--source-index", source, "--alerts-index", alerts,
            "--spool", str(spool), "--state-dir", str(state), "--start", start, "--initialize"]
    try:
        yield args, spool, state, source, alerts
    finally:
        for index in (source, alerts):
            try:
                client.request("DELETE", index_path(index))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def write_events(path, count, *, offset=0, at="2026-01-01T00:05:00.123456Z"):
    records = [{"@timestamp": at, "event.id": f"rolling-pipeline-{i}",
                "event.dataset": "windows.security.logons", "event.code": "4625",
                "source.ip": "192.0.2.10", "target.user": "lab\\alice"}
               for i in range(offset, offset + count)]
    temporary = path.with_suffix(".tmp")
    temporary.write_text("".join(json.dumps(event) + "\n" for event in records), encoding="utf-8")
    temporary.rename(path)


def invoke(args, expected=0):
    result = subprocess.run(args, cwd=ROOT.parent, capture_output=True, text=True, timeout=60)
    assert result.returncode == expected, result.stderr + result.stdout
    return json.loads(result.stdout)


def documents(client, index):
    client.request("POST", index_path(index) + "/_refresh")
    result = client.request("POST", index_path(index) + "/_search", {
        "size": 100, "track_total_hits": True, "query": {"match_all": {}}})["hits"]
    assert result["total"]["value"] == len(result["hits"])
    return sorted(result["hits"], key=lambda hit: hit["_id"])


def test_cli_mixed_xml_jsonl_backlog_restart_and_exact_late_revision(client, tmp_path):
    with pipeline(client, tmp_path, "2026-01-01T00:05:00.123456Z") as (base, spool, state, source, sink):
        write_events(spool / "a.ready.jsonl", 9)
        xml = (ROOT / "tests/fixtures/windows/4625.xml").read_text(encoding="utf-8")
        xml = xml.replace("2026-01-01T00:00:10.0000000Z", "2026-01-01T00:05:00.1234567Z")
        temporary = spool / "b.xml.tmp"
        temporary.write_text(xml, encoding="utf-8")
        temporary.rename(spool / "b.ready.xml")
        once = [*base, "--once", "--at", "2026-01-01T00:05:00.123457Z",
                "--allowed-lateness-seconds", "0", "--max-files", "1"]
        first = invoke(once, expected=2)
        assert first["status"] == "catching_up"
        assert first["ingestion"]["unacknowledged_files"] == 1
        assert not (state / "rolling-detections.sqlite").exists()
        assert documents(client, sink) == []
        second = invoke(once)
        assert second["detection"]["alerts"]["created"] == 1
        assert (state / "rolling-detections.sqlite").is_file()
        assert (state / "rolling-spool.sqlite").is_file()
        assert not (state / "detections.sqlite").exists()
        assert len(documents(client, source)) == 10
        original = documents(client, sink)[0]
        assert original["_source"]["window"]["end"] == "2026-01-01T00:05:00.123456Z"
        assert original["_source"]["metrics"] == {"fails": 10}
        invoke(once)
        assert documents(client, sink) == [original]

        # New immutable input is picked up by a later independent CLI process.
        write_events(spool / "late.ready.jsonl", 1, offset=10)
        updated = invoke([*base, "--once", "--at", "2026-01-01T00:05:00.123458Z",
                          "--allowed-lateness-seconds", "0"])
        assert updated["detection"]["alerts"]["updated"] == 1
        current = documents(client, sink)[0]
        assert current["_id"] == original["_id"]
        assert current["_source"]["revision"] == 2
        assert current["_source"]["metrics"] == {"fails": 11}
        assert len(list(spool.glob("*.ready.*"))) == 3


def test_cli_forward_backlog_is_reported_until_all_anchor_chunks_are_complete(client, tmp_path):
    with pipeline(client, tmp_path, "2026-01-01T00:00:00.123456Z") as (base, spool, _, _, sink):
        write_events(spool / "events.ready.jsonl", 10, at="2026-01-01T00:00:02.123457Z")
        once = [*base, "--once", "--at", "2026-01-01T00:00:03.123456Z",
                "--allowed-lateness-seconds", "0", "--max-forward-seconds", "1"]
        for second in (1, 2, 3):
            result = invoke(once, expected=0 if second == 3 else 2)
            assert result["detection"]["caught_up"] is (second == 3)
            assert set(result["detection"]["checkpoints"].values()) == {f"2026-01-01T00:00:0{second}.123456Z"}
        assert len(documents(client, sink)) == 1


def test_watch_sigterm_finishes_native_rolling_cycle_and_releases_state(client, tmp_path):
    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    start_text = start.isoformat().replace("+00:00", "Z")
    with pipeline(client, tmp_path, start_text) as (base, spool, _, _, sink):
        write_events(spool / "events.ready.jsonl", 10,
                     at=(start + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"))
        process = subprocess.Popen([*base, "--watch", "--interval", "0.1"], cwd=ROOT.parent,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            readable, _, _ = select.select([process.stdout], [], [], 45)
            assert readable, "rolling watch did not report a native iteration"
            first = json.loads(process.stdout.readline())
            assert first["ok"], first
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr
            assert len(documents(client, sink)) == 1
            # Another process can use both ledgers after graceful shutdown.
            invoke([*base, "--once"])
            assert documents(client, sink)[0]["_source"]["revision"] == 1
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
