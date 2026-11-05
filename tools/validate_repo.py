#!/usr/bin/env python3
"""Validate repository contracts; native engine and replay checks are separate.

References, including datasets, are relative to their DetCard and must be regular
files inside the repository. Importing this module does not run validation.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
import math
import re
from typing import Any
import uuid

import yaml
from jsonschema import Draft202012Validator, SchemaError

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = ("techniques", "packs", "schema", "profiles", ".github")
IGNORED_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules"}


class StrictLoader(yaml.SafeLoader):
    """Safe YAML, rejecting duplicate keys and using true/false boolean spelling."""


StrictLoader.yaml_implicit_resolvers = deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for initial, resolvers in StrictLoader.yaml_implicit_resolvers.items():
    StrictLoader.yaml_implicit_resolvers[initial] = [
        (tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"
    ]
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def _unique_mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            exists = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "unhashable mapping key", key_node.start_mark,
            ) from exc
        if exists:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate key {key!r}", key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def strict_load_all(text: str, source: str = "<string>") -> list[Any]:
    """Return all safe YAML documents, raising ValueError with source/line details.

    Duplicate mapping keys are rejected. Only true/false spellings are implicitly
    boolean, so workflow keys such as ``on`` remain strings. No global PyYAML
    loader configuration is modified.
    """
    try:
        return list(yaml.load_all(text, Loader=StrictLoader))
    except yaml.YAMLError as exc:
        raise ValueError(f"{source}: {exc}") from exc


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    detcard_count: int = 0
    technique_count: int = 0
    sigma_rule_count: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def _source_files(root: Path) -> list[Path]:
    """Only authored YAML sources, never dependency caches or negative fixtures."""
    files = [p for p in root.iterdir() if p.suffix in {".yaml", ".yml"}]
    for directory in SOURCE_DIRECTORIES:
        base = root / directory
        if base.is_dir():
            files.extend(
                p for p in base.rglob("*")
                if p.suffix in {".yaml", ".yml"}
                and not (set(p.relative_to(base).parts) & IGNORED_DIRECTORIES)
            )
    return sorted(set(files))


def validate_repository(root: Path = ROOT) -> ValidationReport:
    """Return deterministic structural diagnostics without printing or exiting."""
    root = Path(root).resolve()
    report = ValidationReport()
    if not root.is_dir():
        report.errors.append(f"Repository directory does not exist: {root}")
        return report
    documents: dict[Path, list[Any]] = {}
    try:
        paths = _source_files(root)
    except OSError as exc:
        report.errors.append(f"Cannot discover repository YAML: {exc}")
        return report
    for path in paths:
        name = path.relative_to(root).as_posix()
        try:
            if not path.resolve().is_relative_to(root) or not path.is_file():
                report.errors.append(f"{name}: YAML source must be a regular file inside the repository")
                continue
            documents[path] = strict_load_all(path.read_text(encoding="utf-8"), name)
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            report.errors.append(f"YAML error: {exc}")

    def single_mapping(path: Path) -> dict | None:
        docs = documents.get(path)
        if docs is None:
            return None  # Already reported in the generic YAML pass.
        if len(docs) != 1 or not isinstance(docs[0], dict):
            report.errors.append(f"{path.relative_to(root)}: expected one non-null mapping document")
            return None
        return docs[0]

    schema_path = root / "schema" / "detcard.schema.yaml"
    card_schema = single_mapping(schema_path)
    validator = None
    if schema_path not in documents and not any(schema_path.name in e for e in report.errors):
        report.errors.append("schema/detcard.schema.yaml: schema is missing")
    if card_schema is not None:
        try:
            Draft202012Validator.check_schema(card_schema)
            validator = Draft202012Validator(card_schema)
        except SchemaError as exc:
            report.errors.append(f"schema/detcard.schema.yaml: invalid JSON Schema: {exc.message}")

    def reference(card: Path, rel: str, kind: str, suffixes: set[str] | None = None) -> None:
        name = card.relative_to(root)
        if Path(rel).is_absolute():
            report.errors.append(f"{name}: {kind} reference must be relative: {rel}")
            return
        try:
            target = (card.parent / rel).resolve()
            if not target.is_relative_to(root):
                report.errors.append(f"{name}: {kind} reference escapes repository: {rel}")
            elif not target.is_file():
                report.errors.append(f"{name}: missing referenced {kind} file: {rel}")
            elif suffixes and target.suffix.lower() not in suffixes:
                report.errors.append(f"{name}: wrong file type for {kind}: {rel}")
        except (OSError, RuntimeError, ValueError) as exc:
            report.errors.append(f"{name}: cannot resolve {kind} reference {rel!r}: {exc}")

    cards = sorted((root / "techniques").glob("**/DET-*.yaml"))
    if not cards:
        report.errors.append("No DetCards found under techniques/")
    ids: dict[str, list[Path]] = defaultdict(list)
    card_directories = set()
    for path in cards:
        data = single_mapping(path)
        if data is None:
            continue
        report.detcard_count += 1
        card_directories.add(path.parent)
        if validator is None:
            continue
        errors = sorted(validator.iter_errors(data), key=lambda e: str(list(e.absolute_path)))
        for error in errors:
            location = ".".join(map(str, error.absolute_path)) or "<root>"
            report.errors.append(f"{path.relative_to(root)}: {location}: {error.message}")
        if errors:
            continue  # Malformed data must produce diagnostics, not exceptions.
        ids[data["id"]].append(path)
        if path.stem != data["id"]:
            report.errors.append(f"{path.relative_to(root)}: filename must match DetCard id {data['id']}")
        detections = data["detections"]
        artifact_count = 0
        for kind, extensions in {
            "sigma": {".yml", ".yaml"}, "network_rules": {".rules"},
            "yara": {".yara", ".yar"}, "hunts": {".yaml", ".yml"},
        }.items():
            for rel in detections.get(kind, []):
                artifact_count += 1
                reference(path, rel, kind, extensions)
        for platform, query_files in detections.get("queries", {}).items():
            for rel in query_files:
                artifact_count += 1
                reference(path, rel, f"query for {platform}")
        if artifact_count == 0:
            report.errors.append(f"{path.relative_to(root)}: detections must reference at least one artifact")
        datasets = data.get("tests", {}).get("datasets", [])
        for rel in datasets:
            reference(path, rel, "dataset")
        validation = data.get("validation", {})
        if validation.get("status") in {"tested", "partial"} and not datasets:
            report.errors.append(f"{path.relative_to(root)}: validation status requires referenced datasets")
        if data["status"] == "stable" and validation.get("status") != "tested":
            report.errors.append(f"{path.relative_to(root)}: stable lifecycle requires tested validation")
        if validation.get("status") == "not_tested" and any(
            validation.get(metric) is not None for metric in ("tpr", "fpr", "latency_ms")
        ):
            report.errors.append(f"{path.relative_to(root)}: not_tested validation must not contain measured metrics")
        for metric in ("tpr", "fpr", "latency_ms"):
            value = validation.get(metric)
            if isinstance(value, (int, float)) and not math.isfinite(value):
                report.errors.append(f"{path.relative_to(root)}: {metric} must be finite")
    report.technique_count = len(card_directories)
    for card_id, occurrences in ids.items():
        if len(occurrences) > 1:
            report.errors.append(f"duplicate DetCard ID: {card_id}")

    sigma_paths = sorted(p for p in paths if "sigma" in p.relative_to(root).parts
                         and p.is_relative_to(root / "techniques"))
    if not sigma_paths:
        report.errors.append("No Sigma rule files found under techniques/")
    sigma_ids: dict[str, list[str]] = defaultdict(list)
    for path in sigma_paths:
        rule_documents = documents.get(path)
        if rule_documents is None:
            continue  # The generic YAML pass has already reported the failure.
        if not rule_documents:
            report.errors.append(f"{path.relative_to(root)}: Sigma file must contain at least one rule document")
        for index, rule in enumerate(rule_documents, start=1):
            label = f"{path.relative_to(root)} document {index}"
            if not isinstance(rule, dict) or not rule:
                report.errors.append(f"{label}: Sigma rule must be a nonempty mapping")
                continue
            report.sigma_rule_count += 1
            rule_id = rule.get("id")
            try:
                parsed = uuid.UUID(rule_id) if isinstance(rule_id, str) else None
                if parsed is None or parsed.version != 4 or str(parsed) != rule_id.lower():
                    raise ValueError("not a canonical UUIDv4")
                sigma_ids[str(parsed)].append(label)
            except (ValueError, AttributeError):
                report.errors.append(f"{label}: Sigma id is not UUIDv4: {rule_id!r}")
            for key in ("title", "logsource", "detection"):
                expected = str if key == "title" else dict
                if not isinstance(rule.get(key), expected) or not rule[key]:
                    report.errors.append(f"{label}: {key} must be a nonempty {expected.__name__}")
    for sigma_id, locations in sigma_ids.items():
        if len(locations) > 1:
            report.errors.append(f"duplicate Sigma ID: {sigma_id} ({'; '.join(locations)})")

    packs = sorted((root / "packs").glob("*.y*ml"))
    if not packs:
        report.errors.append("No detection packs found under packs/")
    for path in packs:
        data = single_mapping(path)
        if data is None:
            continue
        if not isinstance(data.get("name"), str) or not data["name"].strip():
            report.errors.append(f"{path.relative_to(root)}: pack name must be a nonempty string")
        included = data.get("includes")
        if not isinstance(included, list) or not included or any(
            not isinstance(item, str) or not item.strip() for item in included
        ):
            report.errors.append(f"{path.relative_to(root)}: includes must be a nonempty list of DetCard IDs")
            continue
        if len(set(included)) != len(included):
            report.errors.append(f"{path.relative_to(root)}: duplicate IDs in includes")
        for card_id in included:
            if card_id not in ids:
                report.errors.append(f"{path.relative_to(root)}: unknown DetCard ID {card_id}")

    tech_root = root / "techniques"
    for directory in sorted(tech_root.iterdir() if tech_root.is_dir() else []):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        for rel in ("README.md", "tests/plan.md"):
            if not (directory / rel).is_file():
                report.errors.append(f"{directory.relative_to(root)}: missing {rel}")
        if directory not in card_directories:
            report.warnings.append(f"{directory.relative_to(root)}: no DetCards found")
    report.errors.sort()
    report.warnings.sort()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (default: this checkout)")
    report = validate_repository(parser.parse_args(argv).root)
    if report.errors:
        print("Validation failed:")
        for error in report.errors:
            print(f"- {error}")
    else:
        print(f"OK: {report.detcard_count} DetCards validated.")
        print(f"OK: {report.technique_count} technique folders with DetCards.")
        print(f"OK: {report.sigma_rule_count} Sigma rule documents checked (structural checks only).")
    if report.warnings:
        print("Warnings:")
        for warning in report.warnings:
            print(f"- {warning}")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
