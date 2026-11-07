#!/usr/bin/env python3
"""Finite replay of the catalogued ASCII Windows process Sigma subset.

Only named, explicitly catalogued process_creation rules and their three source
fields are supported. This is raw command-line matching, not argv parsing,
maliciousness classification, executable attestation or successful execution of
the requested operation. Unsupported input or rules fail the complete replay.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SigmaCasedString, SpecialChars

try:
    from tools.hunt_engine import parse_timestamp
    from tools.process_profile import MIN_TIME, MAX_TIME, prepare_events
    from tools.rolling_hunt import event_time_bounds, iter_jsonl
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp
    from process_profile import MIN_TIME, MAX_TIME, prepare_events
    from rolling_hunt import event_time_bounds, iter_jsonl

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "profiles/elastic/process-rules.json"
FIELD_MAP = {
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "CommandLine": "process.command_line",
}
ALERT_FIELDS = (
    "@timestamp", "event.id", "host.name", "process.guid", "process.parent.guid",
    "process.executable", "process.parent.executable", "process.command_line",
)
MAX_RULES = 32


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate process catalog key: {key}")
        result[key] = value
    return result


def _validate_node(node):
    if type(node) in (ConditionAND, ConditionOR, ConditionNOT):
        if not node.args or (type(node) is ConditionNOT and len(node.args) != 1):
            raise ValueError("Process predicates require nonempty boolean operands")
        for child in node.args:
            _validate_node(child)
    elif type(node) is ConditionFieldEqualsValueExpression:
        if node.field not in FIELD_MAP:
            raise ValueError(f"Unsupported process Sigma field: {node.field}")
        if type(node.value) not in (SigmaString, SigmaCasedString):
            raise ValueError("Process predicates support only string values")
        for part in node.value.s:
            if isinstance(part, str):
                if not part.isascii() or any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in part):
                    raise ValueError("Process Sigma literals require ASCII text without controls except tab")
            elif part not in (SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE):
                raise ValueError("Unsupported process Sigma placeholder or value")
    else:
        raise ValueError(f"Unsupported process Sigma operator: {type(node).__name__}")


def _trees(rule):
    if not isinstance(rule, SigmaRule) or rule.id is None:
        raise ValueError("Expected an identified Sigma rule")
    source = rule.logsource
    if source.product != "windows" or source.category != "process_creation" or source.service is not None:
        raise ValueError("Process backend requires windows/process_creation logsource without a service")
    trees = [condition.parsed for condition in rule.detection.parsed_condition]
    if not trees:
        raise ValueError("Process rule requires a condition")
    for tree in trees:
        _validate_node(tree)
    return trees


def _compile_node(node):
    if type(node) is ConditionAND:
        return {"bool": {"filter": [_compile_node(child) for child in node.args]}}
    if type(node) is ConditionOR:
        return {"bool": {"should": [_compile_node(child) for child in node.args], "minimum_should_match": 1}}
    if type(node) is ConditionNOT:
        return {"bool": {"must_not": [_compile_node(node.args[0])]}}
    pattern = node.value.convert(escape_char="\\", wildcard_multi="*", wildcard_single="?", add_escaped="\\")
    return {"wildcard": {FIELD_MAP[node.field]: {
        "value": pattern, "case_insensitive": type(node.value) is SigmaString,
    }}}


def compile_rule(rule: SigmaRule) -> dict:
    """Compile the entire supported AST, preserving literal wildcard escapes."""
    queries = [_compile_node(tree) for tree in _trees(rule)]
    return queries[0] if len(queries) == 1 else {"bool": {"should": queries, "minimum_should_match": 1}}


def load_rules(catalog: Path = CATALOG_PATH) -> dict[str, SigmaRule]:
    """Load only files explicitly listed in a repository-relative catalog."""
    data = json.loads(Path(catalog).read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or set(data) != {"schema_version", "rules"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported process rule catalog")
    paths = data["rules"]
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_RULES:
        raise ValueError(f"Process catalog requires 1..{MAX_RULES} rule paths")
    rules = {}
    seen_paths = set()
    for name in paths:
        if not isinstance(name, str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("Process catalog requires repository-relative Sigma paths")
        path = (ROOT / name).resolve()
        if not path.is_relative_to((ROOT / "techniques").resolve()) or path.parent.name != "sigma" or path.suffix not in {".yml", ".yaml"}:
            raise ValueError("Process catalog path must reference a technique Sigma file")
        if path in seen_paths:
            raise ValueError("Duplicate process catalog path")
        seen_paths.add(path)
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        if len(collection.rules) != 1:
            raise ValueError("Each process catalog file must contain exactly one rule")
        rule = collection.rules[0]
        compile_rule(rule)
        key = str(rule.id)
        if key in rules:
            raise ValueError("Duplicate process Sigma rule ID")
        rules[key] = rule
    return dict(sorted(rules.items()))


def prepare_rules(rules=None) -> dict[str, SigmaRule]:
    selected = load_rules() if rules is None else rules
    if not isinstance(selected, dict) or not 1 <= len(selected) <= MAX_RULES:
        raise ValueError(f"Expected a nonempty mapping of at most {MAX_RULES} process rules")
    for key, rule in selected.items():
        compile_rule(rule)
        if not isinstance(key, str) or key != str(rule.id):
            raise ValueError("Process rule mapping keys must equal their Sigma IDs")
    return dict(sorted(selected.items()))


def _matcher(node):
    if type(node) is ConditionAND:
        children = [_matcher(child) for child in node.args]
        return lambda event: all(child(event) for child in children)
    if type(node) is ConditionOR:
        children = [_matcher(child) for child in node.args]
        return lambda event: any(child(event) for child in children)
    if type(node) is ConditionNOT:
        child = _matcher(node.args[0])
        return lambda event: not child(event)
    pattern = node.value.convert(escape_char="\\", wildcard_multi=".*", wildcard_single=".", add_escaped="\\.^$+{}[]()|?")
    flags = re.DOTALL | (re.IGNORECASE | re.ASCII if type(node.value) is SigmaString else 0)
    expression = re.compile(pattern, flags)
    field = FIELD_MAP[node.field]
    return lambda event: expression.fullmatch(event[field]) is not None


def rule_matchers(rules: dict[str, SigmaRule]) -> dict:
    """Build reusable matchers for already validated normalized source events."""
    result = {}
    for identifier, rule in prepare_rules(rules).items():
        matchers = [_matcher(tree) for tree in _trees(rule)]
        result[identifier] = lambda event, parts=matchers: any(match(event) for match in parts)
    return result


def validate_options(start, end, max_events, max_alerts):
    for name, value in (("max_events", max_events), ("max_alerts", max_alerts)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    bounds = event_time_bounds(start, end)
    if bounds and any(not MIN_TIME <= value <= MAX_TIME for value in bounds):
        raise ValueError("process-v1 bounds must fit its date_nanos range")
    return bounds


def make_alert(identifier: str, event: dict) -> dict:
    identity = json.dumps([identifier, event["event.id"], event["host.name"], event["process.guid"]],
                          ensure_ascii=False, separators=(",", ":"))
    return {"rule.id": identifier, "alert.id": "process:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            **{field: event[field] for field in ALERT_FIELDS}}


def evaluate_events(events, *, rules=None, start: str | datetime | None = None,
                    end: str | datetime | None = None, max_events: int = 100_000,
                    max_alerts: int = 10_000) -> dict:
    bounds = validate_options(start, end, max_events, max_alerts)
    selected = prepare_rules(rules)
    matchers = rule_matchers(selected)
    raw = []
    try:
        stream = iter(events)
    except TypeError as exc:
        raise ValueError("events must be a finite iterable of normalized objects") from exc
    for event in stream:
        if len(raw) >= max_events:
            raise ValueError("max_events exceeded; no partial result is returned")
        raw.append(event)
    prepared, summary = prepare_events(raw)
    summary.update(filtered_events=0, out_of_range_events=0, matched_events=0, alerts=0, rules=len(selected))
    alerts = []
    for event in sorted(prepared, key=lambda row: (parse_timestamp(row["@timestamp"]), row["event.id"])):
        stamp = parse_timestamp(event["@timestamp"])
        if bounds and not bounds[0] <= stamp < bounds[1]:
            summary["out_of_range_events"] += 1
            continue
        matches = [key for key, match in matchers.items() if match(event)]
        if not matches:
            summary["filtered_events"] += 1
            continue
        summary["matched_events"] += 1
        for identifier in matches:
            if len(alerts) >= max_alerts:
                raise ValueError("max_alerts exceeded; no partial result is returned")
            alerts.append(make_alert(identifier, event))
    summary["alerts"] = len(alerts)
    return {"alerts": alerts, "summary": summary}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--max-events", type=int, default=100_000)
    parser.add_argument("--max-alerts", type=int, default=10_000)
    args = parser.parse_args(argv)
    try:
        result = evaluate_events(iter_jsonl(args.events), rules=load_rules(args.catalog), start=args.start,
                                 end=args.end, max_events=args.max_events, max_alerts=args.max_alerts)
        if not result["summary"]["input_events"]:
            raise ValueError("no events found; an empty replay does not validate a detector")
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"Process replay failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
