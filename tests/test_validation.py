"""Regression tests for the repository quality gate, using isolated fixtures."""
from copy import deepcopy
import shutil

import pytest
import yaml

from tools.validate_repo import ROOT, main, strict_load_all, validate_repository


CARD_ID = "DET-WIN-T1110-TEST-001"
RULE_ID = "69cda7bf-e781-47c6-9a61-a40612c17aff"


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    technique = root / "techniques" / "T1110_Test"
    (technique / "sigma").mkdir(parents=True)
    (technique / "tests").mkdir()
    (root / "schema").mkdir()
    (root / "packs").mkdir()
    shutil.copyfile(ROOT / "schema" / "detcard.schema.yaml", root / "schema" / "detcard.schema.yaml")
    (technique / "README.md").write_text("# Test technique\n")
    (technique / "tests" / "plan.md").write_text("Test expected alerts.\n")
    card = {
        "id": CARD_ID, "title": "Test detection", "version": "1.0.0", "status": "test",
        "tactics": ["credential-access"], "techniques": ["T1110"],
        "platforms": ["windows"], "datasources": ["windows:security:4625"],
        "detections": {"sigma": ["sigma/rule.yml"]},
        "tests": {"datasets": []},
        "validation": {"status": "not_tested", "tpr": None, "fpr": None, "latency_ms": None},
    }
    rule = {
        "id": RULE_ID, "title": "Failed logon", "logsource": {"product": "windows", "service": "security"},
        "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
    }
    card_path = technique / f"{CARD_ID}.yaml"
    card_path.write_text(yaml.safe_dump(card))
    (technique / "sigma" / "rule.yml").write_text(yaml.safe_dump(rule))
    (root / "packs" / "test.yml").write_text(yaml.safe_dump({"name": "Test pack", "includes": [CARD_ID]}))
    return root, card_path, card, rule


def write_card(repository, card):
    root, path, *_ = repository
    path.write_text(yaml.safe_dump(card))
    return validate_repository(root)


def test_valid_repository_and_cli(repository, capsys):
    root, *_ = repository
    report = validate_repository(root)
    assert report.ok, report.errors
    assert (report.detcard_count, report.technique_count, report.sigma_rule_count) == (1, 1, 1)
    assert main(["--root", str(root)]) == 0
    assert "1 Sigma rule documents" in capsys.readouterr().out


@pytest.mark.parametrize(("field", "value"), [
    ("status", "definitely_invalid_status"),
    ("title", "  "),
    ("id", ""),
    ("version", "latest"),
    ("techniques", ["not-an-attack-id"]),
    ("datasources", []),
    ("platforms", "windows"),
    ("detections", ["sigma/rule.yml"]),
    ("validation", {"status": "not_tested", "fpr": 1.1}),
    ("validation", {"status": "not_tested", "latency_ms": -1}),
])
def test_schema_rejects_invalid_card_fields(repository, field, value):
    card = deepcopy(repository[2])
    card[field] = value
    report = write_card(repository, card)
    assert not report.ok
    assert any(field in error for error in report.errors)


def test_schema_is_required(repository):
    root, *_ = repository
    (root / "schema" / "detcard.schema.yaml").unlink()
    assert any("schema is missing" in error for error in validate_repository(root).errors)


def test_invalid_schema_is_reported(repository):
    root, *_ = repository
    (root / "schema" / "detcard.schema.yaml").write_text("type: impossible\n")
    assert any("invalid JSON Schema" in error for error in validate_repository(root).errors)


def test_missing_required_field_is_reported(repository):
    card = deepcopy(repository[2])
    del card["title"]
    assert any("title" in error for error in write_card(repository, card).errors)


@pytest.mark.parametrize("text", ["null\n", "[]\n", "text\n", "---\n{}\n---\n{}\n"])
def test_malformed_card_structure_does_not_crash(repository, text):
    root, path, *_ = repository
    path.write_text(text)
    assert any("mapping document" in error for error in validate_repository(root).errors)


def test_duplicate_yaml_key_is_rejected(repository):
    root, path, *_ = repository
    path.write_text(path.read_text() + "status: stable\n")
    assert any("duplicate key 'status'" in error for error in validate_repository(root).errors)


def test_yaml_boolean_spelling_preserves_github_on():
    data = strict_load_all("on: [push]\nflag: true\nword: yes\n")[0]
    assert data == {"on": ["push"], "flag": True, "word": "yes"}


def test_yaml_loader_does_not_change_pyyaml_global_behavior():
    assert yaml.safe_load("on: yes") == {True: True}


def test_yaml_does_not_execute_arbitrary_tags():
    with pytest.raises(ValueError, match="could not determine a constructor"):
        strict_load_all("!!python/object/apply:builtins.eval ['1 + 1']")


@pytest.mark.parametrize("target", ["sigma/missing.yml", "sigma", "/etc/passwd", "../../../outside.yml"])
def test_unsafe_missing_and_directory_references_fail(repository, target):
    card = deepcopy(repository[2])
    card["detections"]["sigma"] = [target]
    assert any("sigma" in error for error in write_card(repository, card).errors)


def test_reference_symlink_cannot_escape_repository(repository):
    root, path, card, _ = repository
    outside = root.parent / "outside.yml"
    outside.write_text("{}\n")
    (path.parent / "sigma" / "escape.yml").symlink_to(outside)
    card["detections"]["sigma"] = ["sigma/escape.yml"]
    assert any("escapes repository" in error for error in write_card(repository, card).errors)


def test_wrong_reference_type_fails(repository):
    root, path, card, _ = repository
    (path.parent / "sigma" / "wrong.txt").write_text("text\n")
    card["detections"]["sigma"] = ["sigma/wrong.txt"]
    assert any("wrong file type" in error for error in write_card(repository, card).errors)


def test_empty_artifact_collection_fails(repository):
    card = deepcopy(repository[2])
    card["detections"] = {"sigma": [], "queries": {}}
    assert any("at least one artifact" in error for error in write_card(repository, card).errors)


def test_dataset_references_are_checked(repository):
    card = deepcopy(repository[2])
    card["tests"]["datasets"] = ["tests/missing.json"]
    assert any("dataset" in error for error in write_card(repository, card).errors)


def test_tested_status_requires_dataset(repository):
    card = deepcopy(repository[2])
    card["validation"]["status"] = "tested"
    assert any("requires referenced datasets" in error for error in write_card(repository, card).errors)


def test_partial_validation_with_internal_dataset_is_allowed(repository):
    root, path, card, _ = repository
    (root / "tests").mkdir()
    (root / "tests" / "events.json").write_text("[]\n")
    card["tests"]["datasets"] = ["../../tests/events.json"]
    card["validation"]["status"] = "partial"
    assert write_card(repository, card).ok


def test_not_tested_card_must_not_claim_metrics(repository):
    card = deepcopy(repository[2])
    card["validation"]["tpr"] = 0.99
    assert any("must not contain measured metrics" in error for error in write_card(repository, card).errors)


def test_stable_requires_tested_validation(repository):
    card = deepcopy(repository[2])
    card["status"] = "stable"
    report = write_card(repository, card)
    assert not report.ok
    assert any("stable lifecycle requires tested validation" in error for error in report.errors)


def test_nan_is_not_a_valid_measurement(repository):
    root, path, card, _ = repository
    (path.parent / "tests" / "events.json").write_text("[]\n")
    card["tests"]["datasets"] = ["tests/events.json"]
    card["validation"] = {"status": "partial", "tpr": float("nan")}
    assert any("tpr must be finite" in error for error in write_card(repository, card).errors)


def test_duplicate_card_id_fails(repository):
    root, path, *_ = repository
    duplicate = root / "techniques" / "T1110_Other"
    duplicate.mkdir()
    (duplicate / path.name).write_text(path.read_text())
    assert any("duplicate DetCard ID" in error for error in validate_repository(root).errors)


def test_sigma_duplicate_ids_across_documents_fail(repository):
    root, path, _, rule = repository
    (path.parent / "sigma" / "rule.yml").write_text(yaml.safe_dump_all([rule, rule]))
    report = validate_repository(root)
    assert report.sigma_rule_count == 2
    assert any("duplicate Sigma ID" in error for error in report.errors)


@pytest.mark.parametrize("rule", [None, [], "not-a-rule", {"id": "bad-id"}])
def test_malformed_sigma_is_not_silently_skipped(repository, rule):
    root, path, *_ = repository
    (path.parent / "sigma" / "rule.yml").write_text(yaml.safe_dump(rule))
    assert not validate_repository(root).ok


@pytest.mark.parametrize("text", ["", " \n", "# No rule documents here\n"])
def test_empty_sigma_file_never_passes(repository, text):
    root, path, *_ = repository
    (path.parent / "sigma" / "rule.yml").write_text(text)
    report = validate_repository(root)
    assert not report.ok
    assert report.sigma_rule_count == 0
    assert any("at least one rule document" in error for error in report.errors)


@pytest.mark.parametrize("includes", [[], "not-a-list", [CARD_ID, CARD_ID], ["DET-WIN-MISSING-001"]])
def test_invalid_packs_fail(repository, includes):
    root, *_ = repository
    (root / "packs" / "test.yml").write_text(yaml.safe_dump({"name": "Test", "includes": includes}))
    assert any("packs/test.yml" in error for error in validate_repository(root).errors)


def test_caches_and_negative_test_fixtures_are_not_repository_sources(repository):
    root, *_ = repository
    for directory in (root / ".venv", root / "build", root / "tests" / "fixtures"):
        directory.mkdir(parents=True)
        (directory / "intentional-invalid.yaml").write_text("[\n")
    assert validate_repository(root).ok


def test_zero_artifacts_never_pass(tmp_path):
    report = validate_repository(tmp_path)
    assert not report.ok
    for expected in ("No DetCards", "No Sigma", "No detection packs"):
        assert any(expected in error for error in report.errors)


def test_cli_preserves_failure_exit_status(repository, capsys):
    root, path, *_ = repository
    path.write_text("status: wrong\n")
    assert main(["--root", str(root)]) == 1
    assert "Validation failed:" in capsys.readouterr().out
