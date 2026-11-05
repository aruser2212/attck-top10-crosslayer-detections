"""Archive real rolling/episode ledgers; verify evidence without source access."""
from contextlib import contextmanager
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticHTTPError
from tools.elastic_rolling import ElasticClient, create_index, index_path, ingest_events
from tools.episode_archive import create_archive, verify_archive
from tools.episode_engine import EpisodeError
from tools.episode_runner import EpisodeRunner, create_episode_index
from tools.hunt_engine import parse_timestamp
from tools.rolling_runner import RollingDetectionRunner, create_alert_index

ROOT = Path(__file__).resolve().parents[2]
RULE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL for native evidence archive checks")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


def event(number, at="2026-01-01T00:05:00Z"):
    return {"event.id": f"archive-{number}", "event.dataset": "windows.security.logons", "event.code": "4625",
            "@timestamp": at, "target.user": "lab\\alice", "source.ip": "192.0.2.14"}


@contextmanager
def pipeline(client, tmp_path):
    suffix = uuid4().hex
    source, alerts, sink = (f"attck-archive-{kind}-{suffix}" for kind in ("source", "raw", "episodes"))
    try:
        create_index(client, source)
        create_alert_index(client, alerts)
        create_episode_index(client, sink)
        ingest_events(client, source, [event(i) for i in range(10)] + [event(10, "2026-01-01T00:05:30Z")])
        raw = RollingDetectionRunner(source_client=client, source_index=source, alerts_index=alerts,
            state_path=tmp_path / "raw.sqlite", rule_paths=[RULE], initial_start="2026-01-01T00:00:00Z",
            lookback=timedelta(minutes=30), allowed_lateness=timedelta(),
            clock=lambda: parse_timestamp("2026-01-01T00:10:00Z"))
        raw.run_once()
        episodes = EpisodeRunner(source_state=raw.state_path, state_path=tmp_path / "episodes.sqlite",
            sink_client=client, episodes_index=sink, gap=timedelta(minutes=1),
            clock=lambda: parse_timestamp("2026-01-01T00:50:00Z"))
        episodes.run_once()
        yield raw, episodes, source, alerts, sink
    finally:
        for name in (source, alerts, sink):
            try:
                client.request("DELETE", index_path(name))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def test_archive_replay_stability_requires_strict_horizon_and_preserves_live_history(client, tmp_path):
    with pipeline(client, tmp_path) as (raw, episodes, _, alerts, sink):
        # A closed episode remains inside the replay horizon.
        first = create_archive(raw.state_path, episodes.state_path, tmp_path / "first.json")
        assert first["current_episodes"] == 1 and first["replay_stable_episodes"] == 0
        raw.clock = lambda: parse_timestamp("2026-01-01T00:36:30Z")
        raw.run_once()
        episodes.run_once()
        exact = create_archive(raw.state_path, episodes.state_path, tmp_path / "exact.json")
        assert exact["replay_stable_episodes"] == 0  # last+gap == C-lookback
        raw.clock = lambda: parse_timestamp("2026-01-01T00:36:30.000001Z")
        raw.run_once()
        episodes.run_once()
        raw_before, projected_before = raw.state_path.read_bytes(), episodes.state_path.read_bytes()
        final = create_archive(raw.state_path, episodes.state_path, tmp_path / "stable.json")
        assert final["replay_stable_episodes"] == 1 and final["pruning_applied"] is False
        assert verify_archive(tmp_path / "stable.json")["sha256"] == final["sha256"]
        assert raw.state_path.read_bytes() == raw_before
        assert episodes.state_path.read_bytes() == projected_before
        assert client.request("GET", index_path(alerts) + "/_count")["count"] == 2
        assert client.request("GET", index_path(sink) + "/_count")["count"] == 1


def test_archive_rejects_pending_delivery_and_stale_projection_until_recovered(client, tmp_path):
    with pipeline(client, tmp_path) as (raw, episodes, source, _, _):
        ingest_events(client, source, [event(11, "2026-01-01T00:06:00Z")])

        def fail_after_commit(stage, context):
            if stage == "after_commit":
                raise RuntimeError("simulated crash")

        raw.fault_hook = fail_after_commit
        with pytest.raises(RuntimeError):
            raw.run_once()
        target = tmp_path / "recovered.json"
        with pytest.raises(EpisodeError, match="Raw outbox"):
            create_archive(raw.state_path, episodes.state_path, target)
        assert not target.exists()
        raw.fault_hook = lambda *_: None
        raw.run_once()
        with pytest.raises(EpisodeError, match="stale|manifest"):
            create_archive(raw.state_path, episodes.state_path, target)
        episodes.fault_hook = fail_after_commit
        with pytest.raises(RuntimeError):
            episodes.run_once()
        with pytest.raises(EpisodeError, match="Episode outbox"):
            create_archive(raw.state_path, episodes.state_path, target)
        assert not target.exists()
        episodes.fault_hook = lambda *_: None
        episodes.run_once()
        assert create_archive(raw.state_path, episodes.state_path, target)["raw_alerts"] == 3


def test_archive_cli_verifies_offline_and_never_overwrites(client, tmp_path):
    with pipeline(client, tmp_path) as (raw, episodes, _, _, _):
        archive = tmp_path / "evidence.json"
        command = [sys.executable, str(ROOT / "tools/episode_archive.py")]
        result = subprocess.run(command + ["create", "--source-state", str(raw.state_path),
            "--episode-state", str(episodes.state_path), "--output", str(archive)],
            cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        created = json.loads(result.stdout)
        original = archive.read_bytes()
        repeated = subprocess.run(command + ["create", "--source-state", str(raw.state_path),
            "--episode-state", str(episodes.state_path), "--output", str(archive)],
            cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert repeated.returncode == 1 and archive.read_bytes() == original
        # The verifier must not reopen source paths or contact Elasticsearch.
        raw.state_path.rename(tmp_path / "moved-raw.sqlite")
        episodes.state_path.rename(tmp_path / "moved-episodes.sqlite")
        offline_env = {**os.environ, "ELASTIC_URL": "http://127.0.0.1:1"}
        checked = subprocess.run(command + ["verify", str(archive)], cwd=tmp_path, env=offline_env,
                                 capture_output=True, text=True, timeout=30)
        assert checked.returncode == 0, checked.stderr
        assert json.loads(checked.stdout)["sha256"] == created["sha256"]
