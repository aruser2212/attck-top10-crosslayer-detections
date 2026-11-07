#!/usr/bin/env python3
"""Run seven bounded, inert offline demonstrations with declared expectations.

No fixture command is executed, no network is used and no files are written.
This exercises synthetic candidate behavior, not operational detection accuracy.
The complete selected result is printed only after every expectation passes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))


class DemoError(ValueError):
    """A fixture or detector no longer satisfies the declared demonstration."""


def _expect(actual, expected, label: str) -> None:
    if actual != expected:
        raise DemoError(f"{label}: result differs from the declared demonstration")


def _json(relative: str):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def _case(relative: str, name: str) -> dict:
    cases = [case for case in _json(relative)["cases"] if case["name"] == name]
    if len(cases) != 1:
        raise DemoError(f"Expected exactly one fixture named {name}")
    return cases[0]


def _summary(scenario: str, result: dict, evidence: dict) -> dict:
    _expect(len(result["alerts"]), 1, scenario)
    _expect(result["summary"]["alerts"], 1, scenario + " summary")
    return {"scenario": scenario, "input_events": result["summary"]["input_events"],
            "candidate_alerts": 1, "check": "passed", "evidence": evidence}


def _auth_v1() -> dict:
    from tools.hunt_engine import evaluate_hunt, load_hunt, read_jsonl

    events = read_jsonl(ROOT / "tests/fixtures/hunts/brute_positive.jsonl")
    rule = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml")
    result = evaluate_hunt(rule, events)
    expected = _json("tests/fixtures/hunts/brute_positive.expected.json")
    _expect(result["alerts"], expected, "auth-v1 alerts")
    _expect(result["alerts"][0]["fails"], 10, "auth-v1 threshold")
    return _summary("auth-v1", result, {"target.user": "alice", "fails": 10})


def _rolling_v2() -> dict:
    from tools import hunt_engine, rolling_hunt

    case = _case("tests/fixtures/rolling/auth_cases.json", "brute_straddles_v1_boundary")
    result = rolling_hunt.evaluate_hunt(rolling_hunt.load_hunt(ROOT / case["hunt"]), case["events"])
    fixed = hunt_engine.evaluate_hunt(hunt_engine.load_hunt(ROOT / case["v1_hunt"]), case["events"])
    _expect(result["alerts"], case["expected_alerts"], "rolling-v2 alerts")
    _expect(fixed["alerts"], [], "fixed windows at the selected boundary")
    _expect(result["alerts"][0]["fails"], 10, "rolling-v2 threshold")
    return _summary("rolling-v2", result, {"target.user": "lab\\alice", "fails": 10,
                                          "fixed_window_candidates": 0})


def _kerberos() -> dict:
    from tools.kerberos_profile import prepare_events
    from tools.rolling_hunt import evaluate_hunt, load_hunt

    case = _case("tests/fixtures/kerberos/cases.json", "five_service_accounts_threshold")
    events, _ = prepare_events(case["events"])
    result = evaluate_hunt(load_hunt(ROOT / case["hunt"]), events)
    _expect(result["alerts"], case["expected_alerts"], "Kerberos alerts")
    _expect(result["alerts"][0]["distinct_service_accounts"], 5, "Kerberos distinct services")
    return _summary("kerberos", result, {"user.name": "alice", "distinct_service_accounts": 5})


def _host_web() -> dict:
    from tools.correlate_webshell import correlate, load_jsonl

    events = load_jsonl(ROOT / "tests/fixtures/correlation/webroot_request.jsonl")
    result = correlate(events, webroots=["/var/www/html"])
    pairs = [[alert["file.event.id"], alert["http.event.id"]] for alert in result["alerts"]]
    _expect(pairs, [["file-create", "request-suspicious"]], "host/web source pair")
    _expect(result["summary"]["duplicate_events"], 1, "host/web redelivery")
    _expect(result["alerts"][0]["elapsed_seconds"], 60, "host/web elapsed time")
    return _summary("host-web", result, {"source_pairs": pairs, "duplicate_events": 1})


def _lsass() -> dict:
    from tools.detect_lsass import evaluate_events
    from tools.normalize_windows_sysmon import normalize_event

    directory = ROOT / "tests/fixtures/lsass/native"
    events = [normalize_event((directory / filename).read_text(encoding="utf-8"))
              for filename in ("process-access-v3.xml", "benign-query-only-v3.xml")]
    result = evaluate_events(events)
    _expect([alert["event.id"] for alert in result["alerts"]], [events[0]["event.id"]],
            "LSASS selected source event")
    alert = result["alerts"][0]
    _expect(alert["source.process.guid"], "a1b2c3d4-1111-2222-3333-444455556666", "LSASS process")
    _expect(alert["process.access_mask"], 0x1010, "LSASS granted rights")
    return _summary("lsass", result, {"source.process.guid": alert["source.process.guid"],
                                     "process.access_mask": 0x1010, "query_only_candidates": 0})


def _newcredentials() -> dict:
    from tools.correlate_newcredentials import correlate
    from tools.normalize_windows_sessions import normalize_event

    directory = ROOT / "tests/fixtures/newcredentials/native"
    events = [normalize_event((directory / filename).read_text(encoding="utf-8"), boot_id="demo-boot-001")
              for filename in ("newcredentials-v2.xml", "special-privileges-v0.xml")]
    result = correlate(events)
    _expect(len(result["alerts"]), 1, "NewCredentials count")
    alert = result["alerts"][0]
    _expect(alert["logon.event.id"], events[0]["event.id"], "NewCredentials logon source")
    _expect(alert["privilege.event.ids"], [events[1]["event.id"]], "NewCredentials privilege source")
    _expect(alert["session.id"], "0xabcde", "NewCredentials session")
    _expect(alert["user.id"], "S-1-5-21-100-200-300-1001", "NewCredentials local token SID")
    _expect(alert["privilege.time_deltas_us"], [0], "NewCredentials record-time difference")
    _expect(alert["win.privileges"], ["SeDebugPrivilege", "SeImpersonatePrivilege"],
            "NewCredentials privileges")
    return _summary("newcredentials", result, {"session.id": "0xabcde", "host.boot.id": "demo-boot-001",
                                              "privilege.time_deltas_us": [0]})


def _process() -> dict:
    from tools.normalize_windows_process import normalize_event
    from tools.process_detection import evaluate_events

    directory = ROOT / "tests/fixtures/process/native"
    events = [normalize_event((directory / filename).read_text(encoding="utf-8"))
              for filename in ("process-create-v5.xml", "benign-process-v5.xml")]
    result = evaluate_events(events)
    _expect([(alert["rule.id"], alert["event.id"]) for alert in result["alerts"]],
            [("f3c2dcdc-d61b-422b-b2cc-de495e7c80ee",
              "windows-sysmon:6ea7bbc546ea8884cf18ffaae4ea54d8944e70404df89b2eabd6febace292c50")],
            "process rule and source identity")
    _expect(result["alerts"][0]["process.guid"], "a1b2c3d4-1111-2222-3333-444455556666",
            "process GUID evidence")
    return _summary("process", result, {"rule.id": "f3c2dcdc-d61b-422b-b2cc-de495e7c80ee",
                                       "technique": "T1218.010", "benign_notepad_candidates": 0})


SCENARIOS = {"auth-v1": _auth_v1, "rolling-v2": _rolling_v2, "kerberos": _kerberos,
             "host-web": _host_web, "lsass": _lsass, "newcredentials": _newcredentials,
             "process": _process}


def run_demo(scenario: str = "all") -> dict:
    if scenario != "all" and scenario not in SCENARIOS:
        raise DemoError(f"Unknown demonstration scenario: {scenario}")
    selected = SCENARIOS if scenario == "all" else {scenario: SCENARIOS[scenario]}
    results = [run() for run in selected.values()]
    return {"scope": "inert synthetic offline candidate replay; not operational accuracy",
            "checks_passed": len(results), "scenarios": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    args = parser.parse_args(argv)
    try:
        report = run_demo(args.scenario)
    except (ValueError, OSError, KeyError, IndexError, ImportError, ET.ParseError) as exc:
        print(f"Offline demonstration failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
