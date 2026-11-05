"""Version-separated spool ingestion and rolling pipeline orchestration contracts."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Event

import pytest

from tools import elastic_adapter, elastic_rolling
from tools import run_rolling_pipeline as pipeline
from tools.ingest_spool import SpoolError, SpoolFileError, SpoolImporter


class Transport:
    """Small transport double; production validation and ingestion remain in use."""
    def __init__(self, adapter=elastic_rolling):
        self.mapping = json.loads(adapter.MAPPING_PATH.read_text())["mappings"]
        self.uuid = "source-uuid"
        self.events = {}
        self.calls = []
        self.after_write = None
        self.refresh_error = None

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        index = path.split("/")[1]
        if path.endswith("/_mapping"):
            return {index: {"mappings": deepcopy(self.mapping)}}
        if "/_settings" in path:
            return {index: {"settings": {"index.uuid": self.uuid}}}
        if path.endswith("/_mget"):
            return {"docs": [{"_id": key, "_index": index, "found": key in self.events,
                              **({"_source": deepcopy(self.events[key])} if key in self.events else {})}
                             for key in body["ids"]]}
        if "/_bulk" in path:
            lines, items = body.splitlines(), []
            for offset in range(0, len(lines), 2):
                key = json.loads(lines[offset])["create"]["_id"]
                status = 409 if key in self.events else 201
                if status == 201:
                    self.events[key] = json.loads(lines[offset + 1])
                items.append({"create": {"status": status, "_id": key, "_index": index}})
            if self.after_write:
                self.after_write()
            return {"items": items, "errors": any(item["create"]["status"] != 201 for item in items)}
        if path.endswith("/_refresh"):
            if self.refresh_error:
                raise self.refresh_error
            return {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        raise AssertionError((method, path))


def event(identifier="one", **changes):
    return {"@timestamp": "2026-01-01T00:00:10.123456Z", "event.id": identifier,
            "event.dataset": "windows.security.logons", "event.code": "4625",
            "source.ip": "192.0.2.1", "target.user": "lab\\alice", **changes}


def publish(source, events=None, name="a.ready.jsonl"):
    path = source / name
    path.write_text("".join(json.dumps(item) + "\n" for item in (events or [event()])), encoding="utf-8")
    return path


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "spool"
    source.mkdir()
    return Transport(), source, tmp_path / "state" / "rolling-spool.sqlite"


def test_v2_spool_preserves_microseconds_and_repeats_without_duplicates(setup):
    client, source, state = setup
    publish(source)
    with SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        first = spool.scan_once()
        second = spool.scan_once()
        binding = json.loads(spool._meta("binding"))
    assert first["events_inserted"] == 1 and second["events_inserted"] == 0
    assert first["unacknowledged_files"] == second["unacknowledged_files"] == 0
    assert client.events["one"]["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert binding["profile"] == "attck-auth-v2"


def test_native_xml_uses_same_v2_backend(setup):
    client, source, state = setup
    xml = Path(__file__).parent / "fixtures/windows/4625.xml"
    (source / "native.ready.xml").write_bytes(xml.read_bytes())
    with SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        assert spool.scan_once()["files_acked"] == 1
    record = next(iter(client.events.values()))
    assert record["event.code"] == "4625"
    assert record["event.dataset"] == "windows.security.logons"


@pytest.mark.parametrize("changes", [{"target.user": 42}, {"@timestamp": "1969-12-31T23:59:59Z"}])
def test_invalid_v2_fields_are_quarantined_before_ingestion(setup, changes):
    client, source, state = setup
    publish(source, [event(**changes)])
    with SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        with pytest.raises(SpoolFileError) as failure:
            spool.scan_once()
        row = spool.db.execute("SELECT state,error_code FROM spool_files").fetchone()
    assert tuple(row) == ("quarantined", "invalid_auth_fields")
    assert failure.value.summary["files_acked"] == 0 and client.events == {}


def test_v2_refresh_failure_remains_pending_and_existing_only_retry_refreshes(setup):
    client, source, state = setup
    publish(source)
    client.refresh_error = elastic_adapter.ElasticError("unavailable")
    with SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        with pytest.raises(SpoolFileError):
            spool.scan_once()
        assert spool.db.execute("SELECT state FROM spool_files").fetchone()[0] == "pending"
        assert len(client.events) == 1
        client.refresh_error = None
        result = spool.scan_once()
    assert result["events_inserted"] == 0 and result["events_existing"] == result["files_acked"] == 1
    assert len([call for call in client.calls if call[1].endswith("/_refresh")]) == 2


def test_v2_crash_after_remote_write_retries_without_duplicate(setup):
    client, source, state = setup
    publish(source)

    class Crash(BaseException):
        pass

    client.after_write = lambda: (_ for _ in ()).throw(Crash())
    with pytest.raises(Crash), SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        spool.scan_once()
    client.after_write = None
    with SpoolImporter(client, "auth", source, state, profile="auth-v2") as spool:
        result = spool.scan_once()
    assert result["events_existing"] == 1 and result["events_inserted"] == 0


def test_profile_switch_rejects_existing_ledger_without_mutating_it(setup):
    _, source, state = setup
    client = Transport(elastic_adapter)
    with SpoolImporter(client, "auth", source, state):
        pass
    original = state.read_bytes()
    client.mapping = json.loads(elastic_rolling.MAPPING_PATH.read_text())["mappings"]
    with pytest.raises(SpoolError, match="different"), SpoolImporter(client, "auth", source, state, profile="auth-v2"):
        pass
    assert state.read_bytes() == original


@pytest.mark.parametrize("profile", ["auth-v1", "auth-v2"])
def test_foreign_sqlite_state_rejected_without_schema_changes(setup, profile):
    client, source, state = setup
    state.parent.mkdir()
    with sqlite3.connect(state) as db:
        db.execute("CREATE TABLE checkpoints(rule_id TEXT PRIMARY KEY, watermark INTEGER)")
        db.execute("PRAGMA user_version=2")
    original = state.read_bytes()
    with pytest.raises(SpoolError, match="schema"), SpoolImporter(client, "auth", source, state, profile=profile):
        pass
    assert state.read_bytes() == original
    assert client.calls == []


def test_profile_selection_does_not_patch_other_importers(tmp_path):
    clients = [Transport(elastic_adapter), Transport()]
    importers = []
    for number, profile in enumerate(("auth-v1", "auth-v2")):
        source = tmp_path / str(number)
        source.mkdir()
        publish(source)
        importers.append(SpoolImporter(clients[number], "auth", source, source / "spool.sqlite", profile=profile))
    with importers[0], importers[1]:
        assert importers[1].scan_once()["events_inserted"] == 1
        assert importers[0].scan_once()["events_inserted"] == 1
    assert elastic_adapter.PROFILE == "attck-auth-v1"


def test_unknown_backend_rejected_before_state_creation(setup):
    client, source, state = setup
    with pytest.raises(SpoolError, match="profile"):
        SpoolImporter(client, "auth", source, state, profile="auto")
    assert not state.parent.exists() and client.calls == []


class Spool:
    def __init__(self, result=None):
        self.result = {"ok": True, "unacknowledged_files": 0} if result is None else result

    def scan_once(self):
        return self.result


class Runner:
    def __init__(self, caught_up=True):
        self.calls = 0
        self.caught_up = caught_up

    def run_once(self):
        self.calls += 1
        return {"caught_up": self.caught_up}


def test_source_backlog_blocks_detection():
    runner = Runner()
    result = pipeline.run_iteration(Spool({"ok": True, "unacknowledged_files": 1}), runner)
    assert result["ok"] is False and result["status"] == "catching_up"
    assert runner.calls == 0


def test_event_time_catchup_is_visible_after_successful_finite_pass():
    runner = Runner(caught_up=False)
    result = pipeline.run_iteration(Spool(), runner)
    assert result["ok"] is False and result["status"] == "catching_up"
    assert runner.calls == 1 and result["detection"]["caught_up"] is False


def test_watch_retries_failures_and_stops_after_success_without_logging_inputs():
    spool, runner, stop = Spool({"ok": False}), Runner(), Event()
    outputs = []

    def emit(result):
        outputs.append(result)
        spool.result = {"ok": True}
        if len(outputs) == 2:
            stop.set()

    assert pipeline.watch(spool, runner, interval=0.1, stop=stop, emit=emit) == 0
    assert [item["ok"] for item in outputs] == [False, True]
    assert outputs[0]["error_type"] == "ValueError" and "message" not in outputs[0]


def test_initialize_checks_existing_sink_before_creating_missing_source(monkeypatch):
    creations = []
    monkeypatch.setattr(pipeline, "check_profile", lambda *_: (_ for _ in ()).throw(elastic_adapter.ElasticHTTPError(404, "missing")))
    monkeypatch.setattr(pipeline, "check_alert_profile", lambda *_: (_ for _ in ()).throw(ValueError("wrong sink profile")))
    monkeypatch.setattr(pipeline, "create_index", lambda *_: creations.append(True))
    with pytest.raises(ValueError, match="wrong sink" ):
        pipeline.ensure_indices(object(), "auth", "alerts", initialize=True)
    assert creations == []


def test_missing_index_requires_explicit_initialize(monkeypatch):
    monkeypatch.setattr(pipeline, "check_profile", lambda *_: (_ for _ in ()).throw(elastic_adapter.ElasticHTTPError(404, "missing")))
    with pytest.raises(elastic_adapter.ElasticHTTPError):
        pipeline.ensure_indices(object(), "auth", "alerts", initialize=False)


@pytest.mark.parametrize("missing_checker", ["check_profile", "check_alert_profile"])
def test_initialize_never_recreates_indices_when_bound_state_exists(monkeypatch, missing_checker):
    creations = []
    monkeypatch.setattr(pipeline, "check_profile", lambda *_: None)
    monkeypatch.setattr(pipeline, "check_alert_profile", lambda *_: None)
    monkeypatch.setattr(pipeline, missing_checker,
                        lambda *_: (_ for _ in ()).throw(elastic_adapter.ElasticHTTPError(404, "missing")))
    monkeypatch.setattr(pipeline, "create_index", lambda *_: creations.append("source"))
    monkeypatch.setattr(pipeline, "create_alert_index", lambda *_: creations.append("sink"))
    with pytest.raises(ValueError, match="state exists"):
        pipeline.ensure_indices(object(), "auth", "alerts", initialize=True, state_exists=True)
    assert creations == []


def arguments(tmp_path):
    source = tmp_path / "spool"
    source.mkdir(exist_ok=True)
    return ["--once", "--source-index", "auth", "--alerts-index", "alerts", "--spool", str(source),
            "--state-dir", str(tmp_path / "state"), "--start", "2026-01-01T00:00:00.123456Z",
            "--at", "2026-01-01T00:10:00.654321Z"]


@pytest.mark.parametrize("name", ["spool.sqlite", "detections.sqlite"])
def test_cli_rejects_v1_state_directory_before_network(tmp_path, monkeypatch, capsys, name):
    argv = arguments(tmp_path)
    (tmp_path / "state").mkdir()
    old = tmp_path / "state" / name
    old.write_bytes(b"preserve-v1-state")
    monkeypatch.setattr(pipeline, "ElasticClient", lambda *_args, **_kwargs: pytest.fail("unexpected network setup"))
    assert pipeline.main(argv) == 1
    assert "separate state-dir" in capsys.readouterr().err
    assert old.read_bytes() == b"preserve-v1-state"


@pytest.mark.parametrize("option,value", [("--max-files", "0"), ("--max-forward-seconds", "0"),
                                        ("--max-query-events", "0"), ("--page-size", "10001"),
                                        ("--max-scan-bytes", "1"), ("--max-ingest-events", "0"),
                                        ("--start", "1970-01-01T00:00:00Z")])
def test_invalid_configuration_does_not_create_indices_or_state(tmp_path, monkeypatch, capsys, option, value):
    argv = arguments(tmp_path) + [option, value, "--initialize"]
    monkeypatch.setattr(pipeline, "ensure_indices", lambda *_args, **_kwargs: pytest.fail("unexpected bootstrap"))
    assert pipeline.main(argv) == 1
    assert json.loads(capsys.readouterr().err)["ok"] is False
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("caught_up,exit_code", [(True, 0), (False, 2)])
def test_cli_wires_v2_spool_limits_and_time_catchup(tmp_path, monkeypatch, capsys, caught_up, exit_code):
    argv = arguments(tmp_path) + ["--max-forward-seconds", "17", "--max-query-events", "55", "--max-alerts", "3"]
    client = Transport()
    captured = {}

    def runner_factory(**kwargs):
        captured.update(kwargs)
        return Runner(caught_up)

    monkeypatch.setattr(pipeline, "ElasticClient", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(pipeline, "RollingDetectionRunner", runner_factory)
    monkeypatch.setattr(pipeline, "ensure_indices", lambda *_args, **_kwargs: None)
    publish(tmp_path / "spool")
    assert pipeline.main(argv) == exit_code
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is caught_up and result["ingestion"]["events_inserted"] == 1
    assert captured["state_path"].name == "rolling-detections.sqlite"
    assert captured["initial_start"].microsecond == 123456
    assert captured["clock"]().microsecond == 654321
    assert captured["max_forward_span"] == timedelta(seconds=17)
    assert (captured["max_events"], captured["max_alerts"]) == (55, 3)
    with sqlite3.connect(tmp_path / "state/rolling-spool.sqlite") as db:
        binding = json.loads(db.execute("SELECT value FROM spool_meta WHERE key='binding'").fetchone()[0])
    assert binding["profile"] == "attck-auth-v2"


def test_direct_cli_imports_outside_repository():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "tools/run_rolling_pipeline.py"), "--help"],
                            cwd=root.parent, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert "--max-forward-seconds" in result.stdout and "--watch" in result.stdout


def test_watch_rejects_fixed_clock_without_network(tmp_path, capsys):
    argv = arguments(tmp_path)
    argv[0] = "--watch"
    with pytest.raises(SystemExit) as error:
        pipeline.main(argv)
    assert error.value.code == 2
    assert "--at is allowed only with --once" in capsys.readouterr().err
