#!/usr/bin/env python3
"""Offline ATT&CK technique/tactic lint backed by a pinned official STIX snapshot.

`check` never performs network I/O. `build` accepts an already-downloaded official
enterprise bundle and its expected SHA256, producing a deterministic compact
identity catalog. The source commit, tag, version and byte checksum remain in
metadata; the full STIX bundle is not required by CI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

try:
    from tools.validate_repo import strict_load_all
except ModuleNotFoundError:
    from validate_repo import strict_load_all


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles" / "attack"
REPOSITORY = "https://github.com/mitre-attack/attack-stix-data"
SOURCE_PATH = "enterprise-attack/enterprise-attack.json"
CATALOG_NAME = "enterprise-techniques.json"
METADATA_NAME = "metadata.json"
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
TACTIC_ID = re.compile(r"TA\d{4}")
TACTIC_SHORTNAME = re.compile(r"[a-z]+(?:-[a-z]+)*")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TAG = re.compile(r"v\d+\.\d+(?:\.\d+)?")


class AttackError(ValueError):
    """Invalid pinned data or an unsupported catalog contract."""


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AttackError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json)
    except (ValueError, UnicodeError) as exc:
        raise AttackError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AttackError(f"{label}: expected JSON object")
    return value


def _source_url(commit: str) -> str:
    return f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{commit}/{SOURCE_PATH}"


def build_snapshot(source: Path, output: Path, *, attack_tag: str, commit: str,
                   source_sha256: str, tag_object: str | None = None) -> dict:
    """Reduce verified local STIX bytes without fetching or inventing identities."""
    if not TAG.fullmatch(attack_tag) or not COMMIT.fullmatch(commit):
        raise AttackError("Provide an explicit vX.Y tag and full lowercase Git commit SHA")
    if not SHA256.fullmatch(source_sha256):
        raise AttackError("Expected source SHA256 must contain 64 lowercase hex characters")
    if tag_object is not None and not COMMIT.fullmatch(tag_object):
        raise AttackError("Tag object must be a full lowercase Git SHA")
    raw = Path(source).read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != source_sha256:
        raise AttackError(f"source SHA256 mismatch: expected {source_sha256}, got {actual}")
    bundle = _read_json(raw, "source STIX")
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise AttackError("source must be a STIX bundle with an objects list")
    objects = bundle["objects"]
    if any(not isinstance(item, dict) for item in objects):
        raise AttackError("every STIX object must be a mapping")
    collections = [obj for obj in objects if obj.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise AttackError("expected exactly one MITRE collection object")
    collection = collections[0]
    if (collection.get("name") != "Enterprise ATT&CK" or collection.get("spec_version") != "2.1"
            or collection.get("x_mitre_version") != attack_tag.removeprefix("v")):
        raise AttackError("STIX collection name/spec/version does not match the pinned Enterprise ATT&CK tag")
    if not isinstance(collection.get("id"), str) or not collection["id"].startswith("x-mitre-collection--"):
        raise AttackError("STIX collection identity is missing")
    tactics = {}
    tactic_ids, tactic_stix_ids = set(), set()
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        refs = obj.get("external_references", [])
        if not isinstance(refs, list) or any(not isinstance(ref, dict) for ref in refs):
            raise AttackError("tactic external_references must be a list of objects")
        external_ids = [ref.get("external_id") for ref in refs if ref.get("source_name") == "mitre-attack"]
        shortname, stix_id = obj.get("x_mitre_shortname"), obj.get("id")
        if (len(external_ids) != 1 or not isinstance(external_ids[0], str) or not TACTIC_ID.fullmatch(external_ids[0])
                or not isinstance(shortname, str) or not TACTIC_SHORTNAME.fullmatch(shortname)
                or not isinstance(stix_id, str) or not stix_id.startswith("x-mitre-tactic--")
                or not isinstance(obj.get("name"), str) or not obj["name"].strip()):
            raise AttackError("MITRE tactic needs canonical TA ID, shortname, name and STIX identity")
        if shortname in tactics or external_ids[0] in tactic_ids or stix_id in tactic_stix_ids:
            raise AttackError(f"duplicate tactic identity in source: {shortname}")
        if any(not isinstance(obj.get(field, False), bool) for field in ("revoked", "x_mitre_deprecated")):
            raise AttackError(f"{shortname}: tactic revoked/deprecated must be booleans")
        tactics[shortname] = {
            "id": external_ids[0], "shortname": shortname, "name": obj["name"], "stix_id": stix_id,
            "revoked": obj.get("revoked", False), "deprecated": obj.get("x_mitre_deprecated", False),
        }
        tactic_ids.add(external_ids[0])
        tactic_stix_ids.add(stix_id)
    if not tactics:
        raise AttackError("source contains no tactic identities")
    records = {}
    stix_ids = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        if not isinstance(refs, list) or any(not isinstance(ref, dict) for ref in refs):
            raise AttackError("attack-pattern external_references must be a list of objects")
        external_ids = [ref.get("external_id") for ref in refs if ref.get("source_name") == "mitre-attack"]
        if len(external_ids) != 1 or not isinstance(external_ids[0], str) or not TECHNIQUE_ID.fullmatch(external_ids[0]):
            raise AttackError(f"attack-pattern {obj.get('id')!r} needs one canonical MITRE technique ID")
        external_id = external_ids[0]
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--"):
            raise AttackError(f"{external_id}: missing STIX attack-pattern identity")
        if external_id in records or stix_id in stix_ids:
            raise AttackError(f"duplicate technique/STIX ID in source: {external_id} / {stix_id}")
        for field in ("revoked", "x_mitre_deprecated"):
            if not isinstance(obj.get(field, False), bool):
                raise AttackError(f"{external_id}: {field} must be boolean")
        if not isinstance(obj.get("name"), str) or not obj["name"].strip():
            raise AttackError(f"{external_id}: technique name is missing")
        phases = obj.get("kill_chain_phases")
        if not isinstance(phases, list) or any(not isinstance(phase, dict) for phase in phases):
            raise AttackError(f"{external_id}: kill_chain_phases must be a list of objects")
        technique_tactics = [phase.get("phase_name") for phase in phases if phase.get("kill_chain_name") == "mitre-attack"]
        if not technique_tactics or any(not isinstance(phase, str) or phase not in tactics for phase in technique_tactics):
            raise AttackError(f"{external_id}: technique phases must reference canonical tactic shortnames")
        records[external_id] = {
            "id": external_id, "name": obj["name"], "stix_id": stix_id,
            "revoked": obj.get("revoked", False), "deprecated": obj.get("x_mitre_deprecated", False),
            "object_version": obj.get("x_mitre_version"), "parent_ids": [], "replacement_ids": [],
            "tactics": sorted(set(technique_tactics)),
        }
        stix_ids[stix_id] = external_id
    if not records:
        raise AttackError("source contains no technique identities")
    for obj in objects:
        relation = obj.get("relationship_type")
        if (obj.get("type") != "relationship" or relation not in {"subtechnique-of", "revoked-by"}
                or obj.get("revoked", False) or obj.get("x_mitre_deprecated", False)):
            continue
        if obj.get("source_ref") not in stix_ids:
            continue  # Replacement relationships for groups/software are outside this catalog.
        if obj.get("target_ref") not in stix_ids:
            raise AttackError(f"technique relationship target missing from catalog: {obj.get('target_ref')}")
        source_id, target_id = stix_ids[obj["source_ref"]], stix_ids[obj["target_ref"]]
        field = "parent_ids" if relation == "subtechnique-of" else "replacement_ids"
        records[source_id][field].append(target_id)
    for record in records.values():
        for field in ("parent_ids", "replacement_ids"):
            record[field] = sorted(set(record[field]))
    catalog = {
        "schema_version": 2, "domain": "enterprise-attack", "attack_version": collection["x_mitre_version"],
        "techniques": [records[key] for key in sorted(records)],
        "tactics": [tactics[key] for key in sorted(tactics)],
    }
    catalog_bytes = _json_bytes(catalog)
    metadata = {
        "schema_version": 2, "catalog_file": CATALOG_NAME,
        "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
        "generator": "tools/check_attack.py build (catalog schema 2)",
        "source": {
            "repository": REPOSITORY, "git_tag": attack_tag, "git_tag_object": tag_object,
            "git_commit": commit, "url": _source_url(commit), "path": SOURCE_PATH,
            "sha256": actual, "bytes": len(raw), "stix_spec_version": collection["spec_version"],
            "attack_version": collection["x_mitre_version"], "collection_id": collection["id"],
        },
    }
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / CATALOG_NAME).write_bytes(catalog_bytes)
    (output / METADATA_NAME).write_bytes(_json_bytes(metadata))
    return metadata


def load_catalog(profile: Path = PROFILE) -> tuple[dict, dict[str, dict], dict[str, dict]]:
    """Verify stored provenance and checksum before using the offline catalog."""
    profile = Path(profile)
    try:
        metadata = _read_json((profile / METADATA_NAME).read_bytes(), METADATA_NAME)
        raw = (profile / CATALOG_NAME).read_bytes()
    except OSError as exc:
        raise AttackError(f"cannot read ATT&CK snapshot: {exc}") from exc
    if metadata.get("schema_version") != 2 or metadata.get("catalog_file") != CATALOG_NAME:
        raise AttackError("unsupported ATT&CK metadata schema/catalog filename")
    if hashlib.sha256(raw).hexdigest() != metadata.get("catalog_sha256"):
        raise AttackError("ATT&CK catalog SHA256 mismatch; restore or regenerate the pinned snapshot")
    source = metadata.get("source")
    if not isinstance(source, dict):
        raise AttackError("ATT&CK source provenance is missing")
    commit, tag, source_hash = source.get("git_commit", ""), source.get("git_tag", ""), source.get("sha256", "")
    if (not isinstance(commit, str) or not COMMIT.fullmatch(commit)
            or not isinstance(tag, str) or not TAG.fullmatch(tag)
            or not isinstance(source_hash, str) or not SHA256.fullmatch(source_hash)
            or source.get("repository") != REPOSITORY or source.get("url") != _source_url(commit)
            or source.get("path") != SOURCE_PATH or source.get("stix_spec_version") != "2.1"):
        raise AttackError("ATT&CK provenance must pin official source, full commit, version and SHA256")
    tag_object, byte_count = source.get("git_tag_object"), source.get("bytes")
    if (tag_object is not None and (not isinstance(tag_object, str) or not COMMIT.fullmatch(tag_object))
            or isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count <= 0
            or not isinstance(source.get("collection_id"), str)
            or not source["collection_id"].startswith("x-mitre-collection--")):
        raise AttackError("ATT&CK provenance has invalid tag object, source byte count or collection ID")
    catalog = _read_json(raw, CATALOG_NAME)
    if (catalog.get("schema_version") != 2 or catalog.get("domain") != "enterprise-attack"
            or catalog.get("attack_version") != source.get("attack_version")
            or catalog.get("attack_version") != tag.removeprefix("v")):
        raise AttackError("ATT&CK catalog domain/version does not match source provenance")
    tactic_entries = catalog.get("tactics")
    if not isinstance(tactic_entries, list) or not tactic_entries:
        raise AttackError("ATT&CK tactic registry must not be empty")
    tactics, tactic_ids, tactic_stix_ids = {}, set(), set()
    for entry in tactic_entries:
        if not isinstance(entry, dict):
            raise AttackError("catalog tactic must be an object")
        identifier, shortname, stix_id = entry.get("id"), entry.get("shortname"), entry.get("stix_id")
        if (not isinstance(identifier, str) or not TACTIC_ID.fullmatch(identifier)
                or not isinstance(shortname, str) or not TACTIC_SHORTNAME.fullmatch(shortname)
                or not isinstance(stix_id, str) or not stix_id.startswith("x-mitre-tactic--")
                or not isinstance(entry.get("name"), str) or not entry["name"].strip()
                or any(not isinstance(entry.get(field), bool) for field in ("revoked", "deprecated"))):
            raise AttackError("invalid canonical tactic identity or lifecycle")
        if shortname in tactics or identifier in tactic_ids or stix_id in tactic_stix_ids:
            raise AttackError(f"duplicate tactic identity in catalog: {shortname}")
        tactics[shortname] = entry
        tactic_ids.add(identifier)
        tactic_stix_ids.add(stix_id)
    entries = catalog.get("techniques")
    if not isinstance(entries, list) or not entries:
        raise AttackError("ATT&CK technique catalog must not be empty")
    records, stix_ids = {}, set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise AttackError("catalog technique must be an object")
        identifier, stix_id = entry.get("id"), entry.get("stix_id")
        if not isinstance(identifier, str) or not TECHNIQUE_ID.fullmatch(identifier):
            raise AttackError(f"invalid catalog technique ID: {identifier!r}")
        if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--"):
            raise AttackError(f"{identifier}: invalid STIX identity")
        if identifier in records or stix_id in stix_ids:
            raise AttackError(f"duplicate technique/STIX ID in catalog: {identifier} / {stix_id}")
        if not isinstance(entry.get("name"), str) or not entry["name"].strip():
            raise AttackError(f"{identifier}: missing technique name")
        if any(not isinstance(entry.get(field), bool) for field in ("revoked", "deprecated")):
            raise AttackError(f"{identifier}: revoked/deprecated must be booleans")
        for field in ("parent_ids", "replacement_ids"):
            values = entry.get(field)
            if (not isinstance(values, list) or any(not isinstance(v, str) or not TECHNIQUE_ID.fullmatch(v) for v in values)
                    or len(values) != len(set(values))):
                raise AttackError(f"{identifier}: invalid {field}")
        phases = entry.get("tactics")
        if (not isinstance(phases, list) or not phases
                or any(not isinstance(phase, str) or phase not in tactics for phase in phases)
                or len(phases) != len(set(phases))):
            raise AttackError(f"{identifier}: tactics must be unique canonical shortnames")
        records[identifier] = entry
        stix_ids.add(stix_id)
    for identifier, entry in records.items():
        for target in entry["parent_ids"] + entry["replacement_ids"]:
            if target not in records or target == identifier:
                raise AttackError(f"{identifier}: relationship target is unknown or self-referential: {target}")
    return metadata, records, tactics


def check_attack(root: Path = ROOT, profile: Path | None = None) -> dict:
    """Lint all card IDs and Sigma technique tags; mappings remain unchanged."""
    root = Path(root).resolve()
    metadata, catalog, tactics = load_catalog(profile or root / "profiles" / "attack")
    errors, warnings = [], []
    cards, sigma = [], {}
    references = 0
    tactic_references = 0

    def load(path: Path) -> list:
        try:
            if not path.resolve().is_relative_to(root) or not path.is_file():
                raise ValueError("source must be a regular file inside the repository")
            return strict_load_all(path.read_text(encoding="utf-8"), str(path.relative_to(root)))
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(str(exc))
            return []

    def check(identifier: Any, label: str, active: bool) -> str | None:
        nonlocal references
        if not isinstance(identifier, str) or not TECHNIQUE_ID.fullmatch(identifier):
            errors.append(f"{label}: malformed ATT&CK technique ID {identifier!r}")
            return None
        references += 1
        entry = catalog.get(identifier)
        issue = None
        if entry is None:
            issue = f"unknown ATT&CK ID {identifier}; review the mapping or explicitly update the pinned catalog"
        elif entry["revoked"] or entry["deprecated"]:
            status = "/".join(key for key in ("revoked", "deprecated") if entry[key])
            replacement = ", ".join(entry["replacement_ids"]) or "no replacement declared; review official technique"
            issue = f"{identifier} ({entry['name']}) is {status}; replacement: {replacement}"
        if issue:
            (errors if active else warnings).append(f"{label}: {issue}")
        return identifier

    def check_tactics(values: Any, techniques: list[str], label: str, active: bool) -> None:
        nonlocal tactic_references
        if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
            errors.append(f"{label}: nonempty list of canonical tactic shortnames is required")
            return
        if len(values) != len(set(values)):
            errors.append(f"{label}: duplicate ATT&CK tactics")
        assigned = {phase for technique in techniques for phase in catalog.get(technique, {}).get("tactics", [])}
        for value in values:
            tactic_references += 1
            entry = tactics.get(value)
            issue = None
            if entry is None:
                issue = (f"unknown ATT&CK tactic {value!r} in v{metadata['source']['attack_version']}; "
                         "review the selected technique phases in the pinned catalog")
            elif entry["revoked"] or entry["deprecated"]:
                status = "/".join(key for key in ("revoked", "deprecated") if entry[key])
                issue = f"ATT&CK tactic {value!r} ({entry['id']}) is {status}; review the pinned tactic registry"
            if issue:
                (errors if active else warnings).append(f"{label}: {issue}")
            elif active and assigned and value not in assigned:
                warnings.append(f"{label}: contextual tactic review; {value!r} is not assigned to the selected techniques; "
                                f"canonical phases: {sorted(assigned)}")

    card_paths = sorted((root / "techniques").glob("**/DET-*.yaml"))
    if not card_paths:
        errors.append("No DetCards found for ATT&CK lint")
    for path in card_paths:
        documents = load(path)
        label = path.relative_to(root).as_posix()
        if len(documents) != 1 or not isinstance(documents[0], dict):
            errors.append(f"{label}: expected one DetCard mapping")
            continue
        card = documents[0]
        identifiers = card.get("techniques")
        if not isinstance(identifiers, list) or not identifiers:
            errors.append(f"{label}: nonempty techniques list is required")
            continue
        checked = [check(identifier, label, card.get("status") != "deprecated") for identifier in identifiers]
        checked = [identifier for identifier in checked if identifier is not None]
        if len(checked) != len(set(checked)):
            errors.append(f"{label}: duplicate ATT&CK technique IDs")
        check_tactics(card.get("tactics"), checked, label, card.get("status") != "deprecated")
        cards.append((path, card, set(checked)))
    sigma_paths = sorted(set((root / "techniques").glob("**/sigma/*.yml"))
                         | set((root / "techniques").glob("**/sigma/*.yaml")))
    if not sigma_paths:
        errors.append("No Sigma rules found for ATT&CK lint")
    sigma_count = 0
    for path in sigma_paths:
        documents = load(path)
        if not documents:
            errors.append(f"{path.relative_to(root)}: no Sigma documents")
        file_ids = set()
        for index, rule in enumerate(documents, 1):
            label = f"{path.relative_to(root)} document {index}"
            if not isinstance(rule, dict):
                errors.append(f"{label}: Sigma rule must be a mapping")
                continue
            sigma_count += 1
            tags = rule.get("tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                errors.append(f"{label}: tags must be a list of strings")
                continue
            ids = []
            rule_tactics = []
            for tag in tags:
                lowered = tag.lower()
                body = lowered.removeprefix("attack.")
                if lowered.startswith("attack.t") and not lowered.startswith("attack.ta") and re.match(r"t\d", body):
                    identifier = check(tag[7:].upper(), label, rule.get("status") != "deprecated")
                    if identifier is not None:
                        ids.append(identifier)
                elif lowered.startswith("attack."):
                    if re.fullmatch(r"(?:g|s|c|m|ds|dc)\d+(?:\.\d+)?", body):
                        continue  # Other MITRE object namespaces are outside tactic lint.
                    if TACTIC_ID.fullmatch(body.upper()):
                        name = next((name for name, entry in tactics.items() if entry["id"] == body.upper()), body)
                        rule_tactics.append(name)
                    elif re.match(r"ta\d", body):
                        rule_tactics.append(body)  # Clearly a tactic ID, but malformed/unknown.
                    elif re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", body):
                        rule_tactics.append(body.replace("_", "-"))
            if not ids:
                errors.append(f"{label}: at least one ATT&CK technique tag is required")
            if len(ids) != len(set(ids)):
                errors.append(f"{label}: duplicate ATT&CK technique tags")
            # Tactic tags are optional in Sigma; whenever supplied, they must be canonical.
            if rule_tactics:
                check_tactics(rule_tactics, ids, label, rule.get("status") != "deprecated")
            file_ids.update(ids)
        sigma[path.resolve()] = file_ids

    def related(left: str, right: str) -> bool:
        return (left == right or left in catalog.get(right, {}).get("parent_ids", [])
                or right in catalog.get(left, {}).get("parent_ids", []))

    for path, card, card_ids in cards:
        detections = card.get("detections", {})
        links = detections.get("sigma", []) if isinstance(detections, dict) else []
        if not isinstance(links, list) or any(not isinstance(link, str) for link in links):
            errors.append(f"{path.relative_to(root)}: detections.sigma must be a list of relative paths")
            continue
        linked = set()
        for link in links:
            try:
                target = (path.parent / link).resolve()
            except (OSError, RuntimeError, ValueError) as exc:
                errors.append(f"{path.relative_to(root)}: cannot resolve linked Sigma {link!r}: {exc}")
                continue
            if Path(link).is_absolute() or not target.is_relative_to(root) or target not in sigma:
                errors.append(f"{path.relative_to(root)}: linked Sigma source missing or outside repository: {link}")
                continue
            linked.update(sigma[target])
        if not linked:
            continue
        card_only = sorted(identifier for identifier in card_ids if not any(related(identifier, tag) for tag in linked))
        sigma_only = sorted(identifier for identifier in linked if not any(related(identifier, tag) for tag in card_ids))
        if card_only or sigma_only:
            warnings.append(f"{path.relative_to(root)}: contextual mapping review; only in DetCard: {card_only}; "
                            f"only in linked Sigma: {sigma_only}. Confirm observed technique versus attack-chain context.")
    return {"attack_version": metadata["source"]["attack_version"],
            "source_commit": metadata["source"]["git_commit"], "catalog_techniques": len(catalog),
            "catalog_tactics": len(tactics),
            "detcards_checked": len(cards), "sigma_rules_checked": sigma_count,
            "technique_references_checked": references, "tactic_references_checked": tactic_references,
            "errors": sorted(errors), "warnings": sorted(warnings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    check = commands.add_parser("check", help="lint the repository using the offline catalog")
    check.add_argument("--root", type=Path, default=ROOT)
    check.add_argument("--profile", type=Path)
    build = commands.add_parser("build", help="derive catalog from an already downloaded official bundle")
    build.add_argument("source", type=Path)
    build.add_argument("--output", type=Path, default=PROFILE)
    build.add_argument("--attack-tag", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--source-sha256", required=True)
    build.add_argument("--tag-object")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_snapshot(args.source, args.output, attack_tag=args.attack_tag, commit=args.commit,
                                    source_sha256=args.source_sha256, tag_object=args.tag_object)
        else:
            result = check_attack(getattr(args, "root", ROOT), getattr(args, "profile", None))
    except (AttackError, OSError) as exc:
        print(f"ATT&CK check failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(bool(result.get("errors")))


if __name__ == "__main__":
    raise SystemExit(main())
