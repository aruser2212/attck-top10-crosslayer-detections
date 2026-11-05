"""Compare incremental projection with full reconstruction on real Basic ES.

Both projectors consume the same real rolling SQLite state and use independent
episode indices/state files. Exact payload and external-version parity checks
include retained retractions, not only currently active documents.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticHTTPError
from tools.elastic_rolling import ElasticClient, create_index, index_path, ingest_events
from tools.episode_runner import EpisodeRunner, create_episode_index
from tools.rolling_runner import RollingDetectionRunner, create_alert_index

ROOT = Path(__file__).resolve().parents[2]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"
PROJECTED_AT = "2026-01-01T01:00:00Z"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run incremental episode checks on Basic")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"),
                           password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def events(count=10, *, prefix="alice", at="2026-01-01T00:05:00Z", user="lab\\alice"):
    return [{"@timestamp": at, "event.id": f"{prefix}-{number}",
             "event.dataset": "windows.security.logons", "event.code": "4625",
             "source.ip": "192.0.2.10", "target.user": user}
            for number in range(count)]


def documents(client, index):
    result = client.request("POST", index_path(index) + "/_search", {
        "size": 100, "track_total_hits": True, "version": True,
        "query": {"match_all": {}}})["hits"]
    assert result["total"]["relation"] == "eq"
    assert result["total"]["value"] == len(result["hits"])
    return {hit["_id"]: {"payload": hit["_source"], "version": hit["_version"]}
            for hit in result["hits"]}


def state_dump(path):
    with sqlite3.connect(path) as connection:
        return "\n".join(connection.iterdump())


class Lab:
    def __init__(self, client, directory):
        self.client = client
        self.directory = directory
        token = uuid4().hex
        self.source = "attck-incremental-auth-" + token
        self.raw_sink = "attck-incremental-raw-" + token
        self.sinks = {mode: "attck-incremental-" + mode + "-" + token
                      for mode in ("incremental", "full")}
        self.raw_state = directory / "raw.sqlite"
        self.states = {mode: directory / (mode + ".sqlite") for mode in self.sinks}
        self.now = timestamp("2026-01-01T00:05:30Z")

    def ingest(self, rows):
        ingest_events(self.client, self.source, rows)

    def raw(self):
        return RollingDetectionRunner(
            source_client=self.client, source_index=self.source, alerts_index=self.raw_sink,
            state_path=self.raw_state, initial_start="2026-01-01T00:04:00Z", rule_paths=[BRUTE],
            lookback=timedelta(minutes=30), allowed_lateness=timedelta(),
            clock=lambda: self.now, page_size=2).run_once()

    def projector(self, state_mode="incremental", **overrides):
        options = dict(source_state=self.raw_state, state_path=self.states[state_mode],
                       sink_client=self.client, episodes_index=self.sinks[state_mode],
                       gap=timedelta(seconds=10), projection_mode=state_mode,
                       clock=lambda: timestamp(PROJECTED_AT))
        options.update(overrides)
        return EpisodeRunner(**options)

    def compare(self):
        incremental = self.projector().run_once()
        full = self.projector("full").run_once()
        assert incremental["ok"] and full["ok"]
        assert incremental["episodes"] == full["episodes"]
        left = documents(self.client, self.sinks["incremental"])
        assert left == documents(self.client, self.sinks["full"])
        assert all(item["version"] == item["payload"]["revision"] for item in left.values())
        return incremental, full, left


@contextmanager
def lab(client, directory):
    instance = Lab(client, directory)
    try:
        create_index(client, instance.source)
        create_alert_index(client, instance.raw_sink)
        for index in instance.sinks.values():
            create_episode_index(client, index)
        yield instance
    finally:
        for index in (instance.source, instance.raw_sink, *instance.sinks.values()):
            try:
                client.request("DELETE", index_path(index))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def test_native_late_merge_split_rekey_and_new_group_match_full_projection(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(), *events(1, prefix="later", at="2026-01-01T00:05:20Z"),
                       *events(prefix="bob", user="lab\\bob")])
        system.raw()
        first, _, initial = system.compare()
        assert first["recomputation"]["groups_recomputed"] == 2
        assert len(initial) == 3
        bob_id = next(key for key, doc in initial.items() if doc["payload"]["group"]["target.user"] == "lab\\bob")
        bob = initial[bob_id]

        unchanged, full, same = system.compare()
        assert unchanged["recomputation"]["groups_recomputed"] == 0
        assert unchanged["recomputation"]["source_alerts_recomputed"] == 0
        assert full["recomputation"]["groups_recomputed"] == 2
        assert same == initial

        system.ingest(events(1, prefix="bridge", at="2026-01-01T00:05:10Z"))
        system.raw()
        merged_run, _, merged = system.compare()
        assert merged_run["recomputation"]["groups_recomputed"] == 1
        assert merged_run["recomputation"]["source_alerts_recomputed"] == 3
        assert sum(doc["payload"]["status"] == "retracted" for doc in merged.values()) == 1
        assert merged[bob_id] == bob

        client.request("DELETE", index_path(system.source) + "/_doc/bridge-0?refresh=true")
        system.raw()
        split_run, _, split = system.compare()
        assert split_run["recomputation"]["groups_recomputed"] == 1
        assert split_run["recomputation"]["source_alerts_recomputed"] == 3  # Includes retracted bridge.
        assert all(doc["payload"]["status"] != "retracted" for doc in split.values())
        assert split[bob_id] == bob

        system.ingest(events(prefix="earlier", at="2026-01-01T00:04:59Z"))
        system.raw()
        rekey_run, _, rekeyed = system.compare()
        assert rekey_run["recomputation"]["groups_recomputed"] == 1
        assert len(rekeyed) == 4
        assert sum(doc["payload"]["status"] == "retracted" for doc in rekeyed.values()) == 1
        assert rekeyed[bob_id] == bob

        system.ingest(events(prefix="carol", user="lab\\carol"))
        system.raw()
        added, _, final = system.compare()
        assert added["recomputation"] == {"mode": "incremental", "groups_total": 3,
                                          "groups_recomputed": 1, "source_alerts_recomputed": 1}
        assert all(final[key] == value for key, value in rekeyed.items())


def test_metric_only_raw_revision_recomputes_one_group_and_preserves_other_versions(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(), *events(prefix="bob", user="lab\\bob")])
        system.raw()
        _, _, original = system.compare()
        system.ingest(events(1, prefix="extra-same-anchor"))
        system.raw()
        changed, _, updated = system.compare()
        assert changed["recomputation"]["groups_recomputed"] == 1
        assert changed["recomputation"]["source_alerts_recomputed"] == 1
        assert set(updated) == set(original)
        for identifier, entry in updated.items():
            payload = entry["payload"]
            if payload["group"]["target.user"] == "lab\\alice":
                assert payload["member_alert_ids"] == original[identifier]["payload"]["member_alert_ids"]
                assert payload["peak_metrics"] == {"fails": 11}
                assert payload["revision"] == entry["version"] == 2
            else:
                assert entry == original[identifier]


def test_checkpoint_only_closure_recomputes_only_due_group_then_late_event_reopens(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.now = timestamp("2026-01-01T00:05:10Z")
        system.ingest([*events(), *events(prefix="bob", user="lab\\bob", at="2026-01-01T00:05:05Z")])
        system.raw()
        _, _, initial = system.compare()
        assert all(doc["payload"]["status"] == "open" for doc in initial.values())
        bob_id = next(key for key, doc in initial.items() if doc["payload"]["group"]["target.user"] == "lab\\bob")
        system.now += timedelta(microseconds=1)
        system.raw()
        closure, _, closed = system.compare()
        assert closure["recomputation"]["groups_recomputed"] == 1
        assert closed[bob_id] == initial[bob_id]
        assert sum(doc["payload"]["status"] == "closed" for doc in closed.values()) == 1

        system.now = timestamp("2026-01-01T00:05:11Z")
        system.raw()
        advanced, _, stable = system.compare()
        assert advanced["recomputation"]["groups_recomputed"] == 0
        assert stable == closed
        system.ingest(events(1, prefix="late", at="2026-01-01T00:05:09Z"))
        system.raw()
        reopened, _, current = system.compare()
        assert reopened["recomputation"]["groups_recomputed"] == 1
        assert all(doc["payload"]["status"] == "open" for doc in current.values())
        assert current[bob_id] == initial[bob_id]


@pytest.mark.parametrize("limits", [{"max_episodes": 1}, {"max_members": 1}], ids=["episodes", "members"])
def test_lowered_global_limits_include_unchanged_cached_groups(client, tmp_path, limits):
    with lab(client, tmp_path) as system:
        system.ingest([*events(), *events(1, prefix="near", at="2026-01-01T00:05:01Z"),
                       *events(prefix="bob", user="lab\\bob")])
        system.raw()
        _, _, original = system.compare()
        for mode in ("incremental", "full"):
            before = state_dump(system.states[mode])
            with pytest.raises(ValueError):
                system.projector(mode, **limits).run_once()
            assert state_dump(system.states[mode]) == before
            assert documents(client, system.sinks[mode]) == original
        retried, _, same = system.compare()
        assert retried["recomputation"]["groups_recomputed"] == 0
        assert same == original


def test_projection_mode_switch_and_real_cli_preserve_bound_state_and_revisions(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(), *events(prefix="bob", user="lab\\bob")])
        system.raw()
        _, _, original = system.compare()
        arguments = [sys.executable, str(ROOT / "tools/run_episode_pipeline.py"), "--once",
                     "--url", client.url, "--source-state", str(system.raw_state),
                     "--state", str(system.states["incremental"]),
                     "--episodes-index", system.sinks["incremental"], "--gap-seconds", "10",
                     "--at", PROJECTED_AT, "--projection-mode", "full"]
        result = subprocess.run(arguments, cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["recomputation"]["mode"] == "full"
        assert report["recomputation"]["groups_recomputed"] == 2
        assert report["episodes"]["unchanged"] == 2
        assert documents(client, system.sinks["incremental"]) == original
        next_run = system.projector().run_once()
        assert next_run["recomputation"]["groups_recomputed"] == 0
        assert documents(client, system.sinks["incremental"]) == original


def test_incremental_committed_cache_recovers_outbox_without_recomputing_or_new_revision(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(), *events(prefix="bob", user="lab\\bob")])
        system.raw()
        system.compare()
        system.ingest(events(1, prefix="new-anchor", at="2026-01-01T00:05:01Z"))
        system.raw()
        system.projector("full").run_once()

        class InjectedCrash(RuntimeError):
            pass

        def fail(stage, _context):
            if stage == "after_commit":
                raise InjectedCrash(stage)

        with pytest.raises(InjectedCrash):
            system.projector(fault_hook=fail).run_once()
        assert system.projector().status()["pending_outbox"] == 1
        restored = system.projector().run_once()
        assert restored["recomputation"]["groups_recomputed"] == 0
        assert restored["outbox_delivered"] == 1 and restored["pending_outbox"] == 0
        assert documents(client, system.sinks["incremental"]) == documents(client, system.sinks["full"])
