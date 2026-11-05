#!/usr/bin/env python3
"""Parse Sigma natively and exercise a deliberately small predicate test subset.

This is a regression oracle for source-scoped, typed synthetic events, not a
Sigma backend or a SIEM execution engine. pySigma parses conditions and applies
modifiers. Only boolean combinations of scalar equality/string wildcards are
supported; all other AST nodes and value types fail explicitly. Logsource
routing, ingestion/normalization, aggregation, timing and production efficacy
are outside this check.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaBool, SigmaCasedString, SigmaNumber, SigmaString

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sigma" / "predicates.json"


class UnsupportedPredicate(ValueError):
    """A condition cannot be tested by this bounded predicate oracle."""


def _check_node(node: object) -> None:
    # Validate the *entire* tree before evaluation: short-circuit evaluation must
    # not silently hide an unsupported operator in a later branch.
    if type(node) in (ConditionAND, ConditionOR, ConditionNOT):
        if not node.args or (type(node) is ConditionNOT and len(node.args) != 1):
            raise UnsupportedPredicate("Invalid boolean operand count")
        for child in node.args:
            _check_node(child)
    elif type(node) is ConditionFieldEqualsValueExpression:
        if type(node.value) not in (SigmaString, SigmaCasedString, SigmaNumber, SigmaBool):
            raise UnsupportedPredicate(f"Unsupported Sigma value: {type(node.value).__name__}")
        if type(node.value) in (SigmaString, SigmaCasedString):
            # Native conversion also rejects unresolved placeholders.
            _string_pattern(node.value)
    else:
        raise UnsupportedPredicate(f"Unsupported Sigma AST node: {type(node).__name__}")


def _string_pattern(value: SigmaString) -> str:
    return value.convert(
        escape_char="\\",
        wildcard_multi=".*",
        wildcard_single=".",
        add_escaped="\\.^$+{}[]()|?",
    )


def _evaluate(node: object, event: dict) -> bool:
    if type(node) is ConditionAND:
        return all(_evaluate(child, event) for child in node.args)
    if type(node) is ConditionOR:
        return any(_evaluate(child, event) for child in node.args)
    if type(node) is ConditionNOT:
        return not _evaluate(node.args[0], event)
    if node.field not in event or event[node.field] is None:
        return False
    actual = event[node.field]
    if isinstance(actual, (dict, list)):
        raise UnsupportedPredicate(f"Field {node.field!r} must be a scalar")
    value = node.value
    if type(value) is SigmaNumber:
        return type(actual) in (int, float) and actual == value.number
    if type(value) is SigmaBool:
        return type(actual) is bool and actual == value.boolean
    if type(actual) is not str:
        return False
    flags = re.DOTALL if type(value) is SigmaCasedString else re.DOTALL | re.IGNORECASE
    return re.fullmatch(_string_pattern(value), actual, flags=flags) is not None


def predicate_matches(rule: SigmaRule, event: dict) -> bool:
    """Evaluate a supported rule predicate on an event from its declared source.

    JSON numeric event fields must be numbers, not strings. Strings use Sigma's
    default case-insensitive matching unless the parsed value is SigmaCasedString.
    The caller is responsible for logsource selection; run_fixtures checks its
    declared source contract before invoking this function.
    """
    if not isinstance(event, dict):
        raise ValueError("Fixture event must be an object")
    trees = [condition.parsed for condition in rule.detection.parsed_condition]
    if not trees:
        raise ValueError(f"Rule {rule.id} has no parsed conditions")
    for tree in trees:
        _check_node(tree)
    return any(_evaluate(tree, event) for tree in trees)


def load_rules(root: Path = ROOT) -> dict[str, SigmaRule]:
    rules: dict[str, SigmaRule] = {}
    paths = sorted(path for path in (root / "techniques").glob("*/sigma/*")
                   if path.suffix in {".yml", ".yaml"})
    for path in paths:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        if not collection.rules:
            raise ValueError(f"No rules parsed from {path}")
        for rule in collection.rules:
            if not isinstance(rule, SigmaRule) or rule.id is None:
                raise ValueError(f"Expected an identified Sigma detection rule in {path}")
            rule_id = str(rule.id)
            if rule_id in rules:
                raise ValueError(f"Duplicate Sigma ID: {rule_id}")
            for condition in rule.detection.parsed_condition:
                _check_node(condition.parsed)
            rules[rule_id] = rule
    if not rules:
        raise ValueError("No Sigma rules found")
    return rules


def run_fixtures(rules: dict[str, SigmaRule], manifest: dict) -> int:
    if manifest.get("format_version") != 1:
        raise ValueError("Unsupported Sigma fixture format")
    suites = manifest.get("rules", [])
    suite_ids = [suite["rule_id"] for suite in suites]
    if len(suite_ids) != len(set(suite_ids)) or set(suite_ids) != set(rules):
        raise ValueError("Fixture suites must cover every rule ID exactly once")
    count = 0
    for suite in suites:
        rule = rules[suite["rule_id"]]
        expected_source = {
            key: getattr(rule.logsource, key)
            for key in ("product", "service", "category")
            if getattr(rule.logsource, key) is not None
        }
        if suite.get("source") != expected_source:
            raise ValueError(f"Fixture logsource differs from rule {rule.id}")
        cases = suite.get("cases", [])
        if not cases or not all(type(case.get("match")) is bool for case in cases):
            raise ValueError(f"Rule {rule.id} requires cases with boolean expectations")
        if {case["match"] for case in cases} != {True, False}:
            raise ValueError(f"Rule {rule.id} requires both matching and nonmatching cases")
        if len({case["name"] for case in cases}) != len(cases):
            raise ValueError(f"Duplicate fixture names for rule {rule.id}")
        for case in cases:
            actual = predicate_matches(rule, case["event"])
            if actual is not case["match"]:
                raise AssertionError(
                    f"{rule.id}/{case['name']}: expected {case['match']}, got {actual}"
                )
            count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    rules = load_rules(args.root)
    fixtures = args.root / "tests" / "fixtures" / "sigma" / "predicates.json"
    count = run_fixtures(rules, json.loads(fixtures.read_text(encoding="utf-8")))
    print(f"OK: {len(rules)} Sigma rules parsed; {count} source-scoped predicate fixtures passed.")
    print("Scope: synthetic predicate regression; SIEM backend execution and efficacy are not measured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
