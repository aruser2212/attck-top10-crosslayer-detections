"""Native Sigma parsing and bounded source-scoped predicate regressions."""

import copy
import json
import shutil

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaLogsourceError

from tools.check_sigma import (
    FIXTURES,
    UnsupportedPredicate,
    load_rules,
    predicate_matches,
    run_fixtures,
)
from tools.generate_coverage import inventory

MANIFEST = json.loads(FIXTURES.read_text(encoding="utf-8"))
CASES = [
    pytest.param(suite["rule_id"], case, id=f"{suite['rule_id']}/{case['name']}")
    for suite in MANIFEST["rules"]
    for case in suite["cases"]
]


@pytest.fixture(scope="module")
def rules():
    return load_rules()


@pytest.mark.parametrize("rule_id,case", CASES)
def test_source_scoped_predicates(rules, rule_id, case):
    assert predicate_matches(rules[rule_id], case["event"]) is case["match"]


def test_every_parsed_rule_has_positive_and_negative_fixtures(rules):
    assert run_fixtures(rules, MANIFEST) == len(CASES)


def test_missing_fixture_suite_is_failure(rules):
    incomplete = copy.deepcopy(MANIFEST)
    incomplete["rules"].pop()
    with pytest.raises(ValueError, match="every rule ID"):
        run_fixtures(rules, incomplete)


def test_logsource_mismatch_is_failure(rules):
    wrong_source = copy.deepcopy(MANIFEST)
    wrong_source["rules"][0]["source"]["product"] = "wrong_product"
    with pytest.raises(ValueError, match="logsource"):
        run_fixtures(rules, wrong_source)


def make_rule(detection):
    return SigmaCollection.from_dicts([{
        "title": "Oracle contract example",
        "id": "402e8ac0-2fa5-4c6d-94a9-b87c3f655eaf",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": detection,
    }]).rules[0]


@pytest.mark.parametrize("field,value,event,expected", [
    ("Image|endswith", r"\file.exe", {"Image": r"C:\Temp\FILE.EXE"}, True),
    ("Image|endswith", r"\file.exe", {"Image": r"C:\Temp\fileXexe"}, False),
    ("CommandLine|contains", "(sample)+[x]", {"CommandLine": "run (sample)+[x] now"}, True),
    ("CommandLine|contains", "(sample)+[x]", {"CommandLine": "samplex"}, False),
    ("path|cased", "/etc/crontab", {"path": "/etc/CRONTAB"}, False),
    ("EventID", 1, {"EventID": True}, False),
    ("EventID", 1, {"EventID": "1"}, False),
])
def test_oracle_string_escaping_and_type_contract(field, value, event, expected):
    rule = make_rule({"selection": {field: value}, "condition": "selection"})
    assert predicate_matches(rule, event) is expected


def test_unsupported_regex_is_not_hidden_by_true_or_branch():
    rule = make_rule({
        "simple": {"EventID": 1},
        "unsupported": {"CommandLine|re": "a+"},
        "condition": "simple or unsupported",
    })
    with pytest.raises(UnsupportedPredicate, match="SigmaRegularExpression"):
        predicate_matches(rule, {"EventID": 1})


def test_unsupported_event_array_is_rejected():
    rule = make_rule({"selection": {"EventID": 1}, "condition": "selection"})
    with pytest.raises(UnsupportedPredicate, match="scalar"):
        predicate_matches(rule, {"EventID": [1]})


def test_boolean_not_missing_field_contract():
    rule = make_rule({"selection": {"Image|endswith": r"\trusted.exe"}, "condition": "not selection"})
    assert predicate_matches(rule, {}) is True
    assert predicate_matches(rule, {"Image": r"C:\trusted.exe"}) is False


@pytest.mark.parametrize("extension", [".yml", ".yaml"])
def test_native_parsing_and_coverage_include_both_yaml_extensions(tmp_path, extension):
    source = FIXTURES.parents[3] / "techniques/T1110_Brute_Force/sigma/win_4625_base.yml"
    destination = tmp_path / "techniques/T1110_Test/sigma" / ("rule" + extension)
    destination.parent.mkdir(parents=True)
    shutil.copyfile(source, destination)
    rules = load_rules(tmp_path)
    assert set(rules) == {"8a4a044c-8e1c-477a-bccf-ec709dc3714d"}
    counts = inventory(tmp_path)["totals"]
    assert counts["sigma_files"] == counts["sigma_rules"] == 1


def test_invalid_yaml_extension_rule_is_not_silently_omitted(tmp_path):
    path = tmp_path / "techniques/T1110_Test/sigma/invalid.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("title: Rule without detection\n")
    with pytest.raises(SigmaLogsourceError):
        load_rules(tmp_path)
