"""Real spool/runner integration: bounded input must not strand event-time data."""
from copy import deepcopy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from tools.detection_runner import DetectionRunner, MAPPING_PATH as ALERT_MAPPING
from tools.elastic_adapter import ElasticHTTPError, MAPPING_PATH as AUTH_MAPPING
from tools.hunt_engine import evaluate_hunt, parse_timestamp
from tools.ingest_spool import SpoolImporter
from tools.run_auth_pipeline import run_iteration


SOURCE = "auth-source"
SINK = "auth-alerts"
INITIAL = "2026-01-01T00:00:00Z"


class PipelineTransport:
    """Memory Elasticsearch I/O; real ingestion validation and Hunt evaluation."""
    def __init__(self):
        self.mappings = {
            SOURCE: json.loads(AUTH_MAPPING.read_text())["mappings"],
            SINK: json.loads(ALERT_MAPPING.read_text())["mappings"],
        }
        self.events = {}
        self.alerts = {}

    def request(self, method, path, body=None, **kwargs):
        parsed = urlparse(path)
        index = parsed.path.split("/")[1]
        if parsed.path.endswith("/_mapping"):
            return {index: {"mappings": deepcopy(self.mappings[index])}}
        if parsed.path.endswith("/_settings"):
            return {index: {"settings": {"index.uuid": f"{index}-uuid"}}}
        if parsed.path.endswith("/_refresh"):
            return {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if parsed.path.endswith("/_mget"):
            return {"docs": [
                {"_id": identifier, "found": identifier in self.events,
                 **({"_source": deepcopy(self.events[identifier])} if identifier in self.events else {})}
                for identifier in body["ids"]
            ]}
        if parsed.path.endswith("/_bulk"):
            lines = body.splitlines()
            items = []
            for offset in range(0, len(lines), 2):
                identifier = json.loads(lines[offset])["create"]["_id"]
                status = 409 if identifier in self.events else 201
                if status == 201:
                    self.events[identifier] = json.loads(lines[offset + 1])
                items.append({"create": {"status": status}})
            return {"items": items, "errors": any(item["create"]["status"] != 201 for item in items)}
        if method == "PUT" and "/_doc/" in parsed.path:
            identifier = parsed.path.split("/_doc/")[1]
            query = parse_qs(parsed.query)
            old = self.alerts.get(identifier)
            if query.get("version_type") == ["external_gte"]:
                version = int(query["version"][0])
                assert version == body["revision"]
                if old and version < old["revision"]:
                    raise ElasticHTTPError(409, "stale revision")
            self.alerts[identifier] = deepcopy(body)
            return {"_id": identifier, "_index": index, "_version": body["revision"],
                    "result": "updated" if old else "created", "_shards": {"failed": 0}}
        raise AssertionError((method, path))


def publish(source: Path, name: str, ids: range):
    events = [{
        "@timestamp": "2026-01-01T00:00:10Z", "event.id": f"event-{identifier}",
        "event.dataset": "windows.security.logons", "event.code": "4625",
        "source.ip": "192.0.2.1", "target.user": "lab\\alice",
    } for identifier in ids]
    (source / name).write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def make_runner(base: Path, transport: PipelineTransport, clock: list[str]):
    def replay(client, index, rule, *, start, end, expected_index_uuid):
        assert client is transport and index == SOURCE
        assert expected_index_uuid == f"{SOURCE}-uuid"
        events = [event for event in transport.events.values()
                  if parse_timestamp(start) <= parse_timestamp(event["@timestamp"]) < parse_timestamp(end)]
        return evaluate_hunt(rule, events)

    return DetectionRunner(
        source_client=transport, state_path=base / "detection.sqlite",
        source_index=SOURCE, alerts_index=SINK, initial_start=INITIAL,
        clock=lambda: parse_timestamp(clock[0]), evaluator=replay,
    )


def test_initial_backlog_drains_before_checkpoint_with_old_event_window(tmp_path):
    source = tmp_path / "spool"
    source.mkdir()
    publish(source, "a.ready.jsonl", range(9))
    publish(source, "b.ready.jsonl", range(9, 10))
    transport = PipelineTransport()
    clock = ["2026-01-01T01:02:00Z"]  # The queued window is older than the 30m replay horizon.
    runner = make_runner(tmp_path, transport, clock)

    with SpoolImporter(transport, SOURCE, source, tmp_path / "spool.sqlite", max_files=1) as spool:
        first = run_iteration(spool, runner)
        assert first["status"] == "catching_up" and not first["ok"]
        assert first["ingestion"]["unacknowledged_files"] == 1
        assert first["detection"]["executed"] is False
        assert runner.status()["initialized"] is False
        assert len(transport.events) == 9 and transport.alerts == {}

        second = run_iteration(spool, runner)
        assert second["ok"] and second["ingestion"]["unacknowledged_files"] == 0
        assert second["ingestion"]["deferred_files"] == 1  # Retained acknowledged input is harmless.
        assert set(second["detection"]["checkpoints"].values()) == {"2026-01-01T01:00:00Z"}
        assert len(transport.events) == 10 and len(transport.alerts) == 1
        alert = next(iter(transport.alerts.values()))
        assert alert["window"] == {"start": INITIAL, "end": "2026-01-01T00:05:00Z"}
        assert alert["metrics"] == {"fails": 10}

        third = run_iteration(spool, runner)
        assert third["ok"]
        assert third["ingestion"]["files_existing"] == 1
        assert len(transport.alerts) == 1


def test_existing_checkpoint_does_not_advance_while_new_backlog_drains(tmp_path):
    source = tmp_path / "spool"
    source.mkdir()
    transport = PipelineTransport()
    clock = ["2026-01-01T00:02:00Z"]
    runner = make_runner(tmp_path, transport, clock)

    with SpoolImporter(transport, SOURCE, source, tmp_path / "spool.sqlite", max_files=1) as spool:
        assert run_iteration(spool, runner)["ok"]
        baseline = runner.status()["checkpoints"]
        assert set(baseline.values()) == {INITIAL}
        publish(source, "a.ready.jsonl", range(9))
        publish(source, "b.ready.jsonl", range(9, 10))
        clock[0] = "2026-01-01T01:02:00Z"

        assert run_iteration(spool, runner)["status"] == "catching_up"
        assert runner.status()["checkpoints"] == baseline
        assert run_iteration(spool, runner)["ok"]
        assert len(transport.alerts) == 1
        assert next(iter(transport.alerts.values()))["metrics"] == {"fails": 10}
