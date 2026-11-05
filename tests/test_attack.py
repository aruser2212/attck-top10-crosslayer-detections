"""Offline ATT&CK provenance, identity lifecycle and mapping regressions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import socket

import pytest
import yaml

from tools.check_attack import (
    AttackError, CATALOG_NAME, METADATA_NAME, PROFILE, ROOT,
    build_snapshot, check_attack, load_catalog, main,
)


@pytest.fixture
def profile(tmp_path):
    path = tmp_path / "profile"
    shutil.copytree(PROFILE, path)
    return path


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repository"
    technique = root / "techniques" / "T1110_Test"
    (technique / "sigma").mkdir(parents=True)
    card_path = technique / "DET-WIN-T1110-TEST-001.yaml"
    sigma_path = technique / "sigma" / "test.yml"
    card = {"id": card_path.stem, "status": "test", "techniques": ["T1110"], "tactics": ["credential-access"],
            "detections": {"sigma": ["sigma/test.yml"]}}
    rule = {"title": "Test", "status": "test", "tags": ["attack.t1110", "attack.credential-access"]}
    card_path.write_text(yaml.safe_dump(card))
    sigma_path.write_text(yaml.safe_dump(rule))
    return root, card_path, sigma_path, card, rule


def write_data(repository, profile, *, card=None, rule=None):
    root, card_path, sigma_path, *_ = repository
    if card is not None:
        card_path.write_text(yaml.safe_dump(card))
    if rule is not None:
        sigma_path.write_text(yaml.safe_dump(rule))
    return check_attack(root, profile)


def rewrite_catalog_with_checksum(profile, data):
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    (profile / CATALOG_NAME).write_bytes(raw)
    metadata = json.loads((profile / METADATA_NAME).read_text())
    metadata["catalog_sha256"] = hashlib.sha256(raw).hexdigest()
    (profile / METADATA_NAME).write_text(json.dumps(metadata))


def test_pinned_official_catalog_is_complete_and_offline():
    metadata, records, tactics = load_catalog()
    assert metadata["source"]["git_tag"] == "v20.0"
    assert metadata["source"]["git_commit"] == "20664a889568dce884a1dac0ec7b12ae3a199f51"
    assert metadata["source"]["stix_spec_version"] == "2.1"
    assert len(records) == 867
    assert records["T1110.001"]["parent_ids"] == ["T1110"]
    assert records["T1070.002"]["revoked"] is True
    assert records["T1070.002"]["replacement_ids"] == ["T1685.006"]
    assert len(tactics) == 15
    assert tactics["stealth"]["id"] == "TA0005"
    assert tactics["defense-impairment"]["id"] == "TA0112"
    assert "defense-evasion" not in tactics
    assert records["T1070"]["tactics"] == ["stealth"]
    assert records["T1685.006"]["tactics"] == ["defense-impairment"]


def test_current_corpus_has_no_unknown_or_retired_active_references(monkeypatch):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("ATT&CK runtime lint must remain offline")

    monkeypatch.setattr(socket.socket, "connect", network_forbidden)
    result = check_attack(ROOT)
    assert result["detcards_checked"] > 0
    assert result["sigma_rules_checked"] > 0
    assert not result["errors"], result["errors"]


def test_catalog_tampering_without_matching_checksum_fails(profile):
    path = profile / CATALOG_NAME
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(AttackError, match="SHA256 mismatch"):
        load_catalog(profile)


def test_duplicate_catalog_technique_id_is_rejected_even_with_matching_hash(profile):
    data = json.loads((profile / CATALOG_NAME).read_text())
    data["techniques"].append(deepcopy(data["techniques"][0]))
    rewrite_catalog_with_checksum(profile, data)
    with pytest.raises(AttackError, match="duplicate technique/STIX ID"):
        load_catalog(profile)


def test_duplicate_catalog_stix_id_is_rejected(profile):
    data = json.loads((profile / CATALOG_NAME).read_text())
    data["techniques"][1]["stix_id"] = data["techniques"][0]["stix_id"]
    rewrite_catalog_with_checksum(profile, data)
    with pytest.raises(AttackError, match="duplicate technique/STIX ID"):
        load_catalog(profile)


def test_broken_replacement_relationship_fails(profile):
    data = json.loads((profile / CATALOG_NAME).read_text())
    data["techniques"][0]["replacement_ids"] = ["T9999"]
    rewrite_catalog_with_checksum(profile, data)
    with pytest.raises(AttackError, match="relationship target"):
        load_catalog(profile)


def test_provenance_cannot_point_to_mutable_branch(profile):
    path = profile / METADATA_NAME
    metadata = json.loads(path.read_text())
    metadata["source"]["url"] = metadata["source"]["url"].replace(metadata["source"]["git_commit"], "master")
    path.write_text(json.dumps(metadata))
    with pytest.raises(AttackError, match="provenance"):
        load_catalog(profile)


def test_valid_card_and_sigma_reference_pass(repository, profile):
    report = check_attack(repository[0], profile)
    assert report["errors"] == []
    assert report["warnings"] == []
    assert report["technique_references_checked"] == 2


@pytest.mark.parametrize(("identifier", "message"), [
    ("T9999", "unknown ATT&CK ID"),
    ("T1002", "revoked; replacement: T1560"),
    ("T1053.004", "deprecated; replacement: no replacement declared"),
    ("T111", "malformed ATT&CK technique ID"),
])
def test_active_card_unknown_revoked_deprecated_and_malformed_ids_fail(repository, profile, identifier, message):
    card = deepcopy(repository[3])
    card["techniques"] = [identifier]
    assert any(message in error for error in write_data(repository, profile, card=card)["errors"])


def test_active_sigma_revoked_tag_fails_with_successor(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1070.002"]
    assert any("replacement: T1685.006" in error for error in write_data(repository, profile, rule=rule)["errors"])


def test_deprecated_artifact_references_are_reported_as_warnings(repository, profile):
    card, rule = deepcopy(repository[3]), deepcopy(repository[4])
    card.update(status="deprecated", techniques=["T1002"])
    rule.update(status="deprecated", tags=["attack.t1002"])
    report = write_data(repository, profile, card=card, rule=rule)
    assert not report["errors"]
    assert len(report["warnings"]) == 2
    assert all("revoked" in warning for warning in report["warnings"])


def test_duplicate_card_ids_are_not_hidden_by_set_conversion(repository, profile):
    card = deepcopy(repository[3])
    card["techniques"] = ["T1110", "T1110"]
    assert any("duplicate ATT&CK technique IDs" in error for error in write_data(repository, profile, card=card)["errors"])


def test_duplicate_sigma_tags_are_rejected(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1110", "attack.T1110"]
    assert any("duplicate ATT&CK technique tags" in error for error in write_data(repository, profile, rule=rule)["errors"])


def test_parent_and_subtechnique_mapping_are_related(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1110.001"]
    report = write_data(repository, profile, rule=rule)
    assert not report["errors"]
    assert not report["warnings"]


def test_different_subtechniques_are_not_silently_equated(repository, profile):
    card, rule = deepcopy(repository[3]), deepcopy(repository[4])
    card["techniques"] = ["T1110.001"]
    rule["tags"] = ["attack.t1110.003"]
    report = write_data(repository, profile, card=card, rule=rule)
    assert not report["errors"]
    assert any("contextual mapping review" in warning for warning in report["warnings"])


def test_contextual_mismatch_warns_without_rewriting_sources(repository, profile):
    card, rule = deepcopy(repository[3]), deepcopy(repository[4])
    card["techniques"] = ["T1190", "T1505.003"]
    rule["tags"] = ["attack.t1505.003"]
    report = write_data(repository, profile, card=card, rule=rule)
    assert not report["errors"]
    assert any("only in DetCard: ['T1190']" in warning for warning in report["warnings"])
    assert yaml.safe_load(repository[1].read_text()) == card


@pytest.mark.parametrize("contents", ["", "# only a comment\n", "[]\n"])
def test_empty_or_nonmapping_sigma_never_passes(repository, profile, contents):
    repository[2].write_text(contents)
    assert check_attack(repository[0], profile)["errors"]


def test_no_reference_sources_never_passes(tmp_path, profile):
    report = check_attack(tmp_path, profile)
    assert any("No DetCards" in error for error in report["errors"])
    assert any("No Sigma" in error for error in report["errors"])


def test_all_sigma_documents_are_checked(repository, profile):
    root, _, path, _, rule = repository
    second = deepcopy(rule)
    second["tags"] = ["attack.t9999"]
    path.write_text(yaml.safe_dump_all([rule, second]))
    report = check_attack(root, profile)
    assert report["sigma_rules_checked"] == 2
    assert any("document 2" in error and "T9999" in error for error in report["errors"])


def test_malformed_card_technique_list_reports_error(repository, profile):
    card = deepcopy(repository[3])
    card["techniques"] = "T1110"
    assert any("techniques list" in error for error in write_data(repository, profile, card=card)["errors"])


@pytest.mark.parametrize("tactic", ["not-a-tactic", "defense-evasion"])
def test_unknown_or_obsolete_card_tactic_fails(repository, profile, tactic):
    card = deepcopy(repository[3])
    card["tactics"] = [tactic]
    report = write_data(repository, profile, card=card)
    assert any(f"unknown ATT&CK tactic '{tactic}'" in error for error in report["errors"])


def test_deprecated_canonical_tactic_fails_for_active_artifact(repository, profile):
    data = json.loads((profile / CATALOG_NAME).read_text())
    next(tactic for tactic in data["tactics"] if tactic["shortname"] == "credential-access")["deprecated"] = True
    rewrite_catalog_with_checksum(profile, data)
    report = check_attack(repository[0], profile)
    assert any("tactic 'credential-access' (TA0006) is deprecated" in error for error in report["errors"])


def test_duplicate_tactic_identity_rejected_even_with_matching_checksum(profile):
    data = json.loads((profile / CATALOG_NAME).read_text())
    data["tactics"].append(deepcopy(data["tactics"][0]))
    rewrite_catalog_with_checksum(profile, data)
    with pytest.raises(AttackError, match="duplicate tactic identity"):
        load_catalog(profile)


def test_canonical_replacement_phase_matches_updated_technique(repository, profile):
    card, rule = deepcopy(repository[3]), deepcopy(repository[4])
    card.update(techniques=["T1685.006"], tactics=["defense-impairment"])
    rule["tags"] = ["attack.t1685.006", "attack.defense-impairment"]
    report = write_data(repository, profile, card=card, rule=rule)
    assert not report["errors"]
    assert not report["warnings"]


def test_valid_but_contextual_tactic_is_warning_only(repository, profile):
    card = deepcopy(repository[3])
    card["tactics"] = ["initial-access"]
    report = write_data(repository, profile, card=card)
    assert not report["errors"]
    assert any("contextual tactic review" in warning for warning in report["warnings"])


def test_unknown_sigma_tactic_fails(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1110", "attack.defense_evasion"]
    report = write_data(repository, profile, rule=rule)
    assert any("unknown ATT&CK tactic 'defense-evasion'" in error for error in report["errors"])


def test_malformed_sigma_tactic_id_is_not_silently_ignored(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1110", "attack.ta12"]
    report = write_data(repository, profile, rule=rule)
    assert any("unknown ATT&CK tactic 'ta12'" in error for error in report["errors"])


@pytest.mark.parametrize("tag", ["attack.credential_access", "attack.credential-access", "attack.ta0006"])
def test_supported_sigma_tactic_spellings_and_id(repository, profile, tag):
    rule = deepcopy(repository[4])
    rule["tags"] = ["attack.t1110", tag]
    report = write_data(repository, profile, rule=rule)
    assert not report["errors"]
    assert not report["warnings"]


def test_other_attack_object_namespaces_are_not_misread_as_tactics(repository, profile):
    rule = deepcopy(repository[4])
    rule["tags"] += ["attack.g0001", "attack.s0001", "attack.m1001", "attack.c0001", "attack.ds0017", "attack.dc0086"]
    report = write_data(repository, profile, rule=rule)
    assert not report["errors"]
    assert not report["warnings"]


def test_cli_error_exit_status(repository, profile, capsys):
    card = deepcopy(repository[3])
    card["techniques"] = ["T9999"]
    write_data(repository, profile, card=card)
    assert main(["check", "--root", str(repository[0]), "--profile", str(profile)]) == 1
    assert "T9999" in capsys.readouterr().out


def source_bundle():
    return {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--test",
         "name": "Enterprise ATT&CK", "spec_version": "2.1", "x_mitre_version": "20.0"},
        {"type": "attack-pattern", "id": "attack-pattern--test-parent", "name": "Brute Force",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}]},
        {"type": "attack-pattern", "id": "attack-pattern--test-child", "name": "Password Guessing",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.001"}]},
        {"type": "relationship", "relationship_type": "subtechnique-of",
         "source_ref": "attack-pattern--test-child", "target_ref": "attack-pattern--test-parent"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--test", "name": "Credential Access",
         "x_mitre_shortname": "credential-access",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}]},
    ]}


def build_test_snapshot(tmp_path, bundle=None, expected_hash=None):
    raw = json.dumps(bundle or source_bundle()).encode()
    source = tmp_path / "source.json"
    source.write_bytes(raw)
    output = tmp_path / "output"
    metadata = build_snapshot(source, output, attack_tag="v20.0", commit="a" * 40,
                              source_sha256=expected_hash or hashlib.sha256(raw).hexdigest())
    return source, output, metadata


def test_deterministic_snapshot_generation_and_relationships(tmp_path):
    source, output, metadata = build_test_snapshot(tmp_path)
    original = {name: (output / name).read_bytes() for name in (CATALOG_NAME, METADATA_NAME)}
    build_snapshot(source, output, attack_tag="v20.0", commit="a" * 40,
                   source_sha256=metadata["source"]["sha256"])
    assert {name: (output / name).read_bytes() for name in original} == original
    _, catalog, tactics = load_catalog(output)
    assert catalog["T1110.001"]["parent_ids"] == ["T1110"]
    assert catalog["T1110.001"]["tactics"] == ["credential-access"]
    assert tactics["credential-access"]["id"] == "TA0006"


def test_generator_rejects_wrong_source_checksum(tmp_path):
    with pytest.raises(AttackError, match="source SHA256 mismatch"):
        build_test_snapshot(tmp_path, expected_hash="0" * 64)


def test_generator_rejects_duplicate_external_ids(tmp_path):
    bundle = source_bundle()
    duplicate = deepcopy(bundle["objects"][1])
    duplicate["id"] = "attack-pattern--other"
    bundle["objects"].append(duplicate)
    with pytest.raises(AttackError, match="duplicate technique/STIX ID"):
        build_test_snapshot(tmp_path, bundle)


def test_generator_rejects_invented_version_label(tmp_path):
    bundle = source_bundle()
    bundle["objects"][0]["x_mitre_version"] = "19.2"
    with pytest.raises(AttackError, match="does not match"):
        build_test_snapshot(tmp_path, bundle)
