"""Independent subprocess lifecycle for the episode pipeline on Basic."""
from contextlib import contextmanager
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
        pytest.skip("Set ELASTIC_URL to execute real Basic episode CLI checks")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"),
                           password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


def invoke(args, expected=0):
    result = subprocess.run(args, cwd=ROOT.parent, capture_output=True, text=True, timeout=60)
    assert result.returncode == expected, result.stderr + result.stdout
    return json.loads(result.stdout)


def documents(client, index):
    result = client.request("POST", index_path(index) + "/_search", {
        "size": 100, "track_total_hits": True, "query": {"match_all": {}}})["hits"]
    assert result["total"]["relation"] == "eq"
    assert result["total"]["value"] == len(result["hits"])
    return {hit["_id"]: hit["_source"] for hit in result["hits"]}


@contextmanager
def pipeline(client, tmp_path):
    source = "attck-episode-cli-source-" + uuid4().hex
    raw_sink = "attck-episode-cli-raw-" + uuid4().hex
    sink = "attck-episode-cli-sink-" + uuid4().hex
    spool, raw_directory = tmp_path / "spool", tmp_path / "raw-state"
    source_state = raw_directory / "rolling-detections.sqlite"
    state = tmp_path / "episode-state.sqlite"
    spool.mkdir()
    rows = [{"@timestamp": "2026-01-01T00:05:00Z", "event.id": f"cli-episode-{number}",
             "event.dataset": "windows.security.logons", "event.code": "4625",
             "source.ip": "192.0.2.10", "target.user": "lab\\alice"} for number in range(10)]
    rows.append({**rows[0], "event.id": "cli-episode-later", "@timestamp": "2026-01-01T00:05:01Z"})
    temporary = spool / "events.tmp"
    temporary.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    temporary.rename(spool / "events.ready.jsonl")
    try:
        invoke([sys.executable, str(ROOT / "tools/run_rolling_pipeline.py"), "--once", "--initialize",
                "--url", client.url, "--source-index", source, "--alerts-index", raw_sink,
                "--spool", str(spool), "--state-dir", str(raw_directory),
                "--start", "2026-01-01T00:05:00Z", "--at", "2026-01-01T00:08:00Z"])
        arguments = [sys.executable, str(ROOT / "tools/run_episode_pipeline.py"),
                     "--url", client.url, "--source-state", str(source_state),
                     "--state", str(state), "--episodes-index", sink, "--gap-seconds", "10"]
        yield arguments, source_state, state, raw_sink, sink
    finally:
        for index in (source, raw_sink, sink):
            try:
                client.request("DELETE", index_path(index))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def test_cli_once_restart_and_local_status_preserve_source(client, tmp_path):
    with pipeline(client, tmp_path) as (base, source_state, state, raw_sink, sink):
        raw_bytes = source_state.read_bytes()
        raw_documents = documents(client, raw_sink)
        first = invoke([*base, "--once", "--initialize", "--at", "2026-01-01T00:10:00Z"])
        assert first["ok"] and first["episodes"]["created"] == 1
        current = documents(client, sink)
        assert len(current) == 1
        episode = next(iter(current.values()))
        assert episode["anchor_count"] == 2 and episode["peak_metrics"] == {"fails": 11}
        assert episode["status"] == "closed" and episode["revision"] == 1
        repeat = invoke([*base, "--once", "--at", "2026-01-01T00:10:00Z"])
        assert repeat["episodes"]["unchanged"] == 1
        assert documents(client, sink) == current
        # This port has no service: local --status must not send a request.
        status = invoke([*base, "--status", "--url", "http://127.0.0.1:1"])
        assert status["initialized"] and status["episodes"] == 1
        assert status["pending_outbox"] == 0 and status["observed_source_alerts"] == 2
        assert state.exists() and source_state.read_bytes() == raw_bytes
        assert documents(client, raw_sink) == raw_documents


def test_cli_watch_sigterm_releases_state_and_restart_is_idempotent(client, tmp_path):
    with pipeline(client, tmp_path) as (base, source_state, _, raw_sink, sink):
        raw_bytes = source_state.read_bytes()
        raw_documents = documents(client, raw_sink)
        process = subprocess.Popen([*base, "--watch", "--initialize", "--interval", "0.1"],
                                   cwd=ROOT.parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            readable, _, _ = select.select([process.stdout], [], [], 45)
            assert readable, "episode watch did not report its native iteration"
            first = json.loads(process.stdout.readline())
            assert first["ok"] and first["episodes"]["created"] == 1
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr
            original = documents(client, sink)
            assert len(original) == 1
            assert invoke([*base, "--once"])["ok"]
            assert documents(client, sink) == original
            assert source_state.read_bytes() == raw_bytes
            assert documents(client, raw_sink) == raw_documents
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
