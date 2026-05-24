#!/usr/bin/env python3
"""Validate DetCards, pack references, artifact links and YAML syntax."""
from pathlib import Path
from collections import Counter, defaultdict
import sys
import yaml
import re

ROOT = Path(__file__).resolve().parents[1]
TECH = ROOT / "techniques"
PACKS = ROOT / "packs"

errors = []
warnings = []
detcards = []
UUID4_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

# 1) Parse all YAML files, not only DetCards. Hunt DSL files are YAML too.
for path in sorted(ROOT.glob("**/*.yml")) + sorted(ROOT.glob("**/*.yaml")):
    if ".git" in path.parts:
        continue
    try:
        with path.open("r", encoding="utf-8") as f:
            list(yaml.safe_load_all(f))
    except Exception as exc:
        errors.append(f"YAML error in {path.relative_to(ROOT)}: {exc}")


# 1b) Sigma rule IDs should be UUIDv4. This keeps generated rules compatible with common Sigma tooling.
for path in sorted(ROOT.glob("techniques/**/sigma/*.yml")):
    try:
        with path.open("r", encoding="utf-8") as f:
            for i, doc in enumerate(yaml.safe_load_all(f), start=1):
                if not doc:
                    continue
                rule_id = str(doc.get("id", ""))
                if not UUID4_RE.match(rule_id):
                    errors.append(f"{path.relative_to(ROOT)} document {i}: Sigma id is not UUIDv4: {rule_id}")
    except Exception:
        # YAML parse error is already reported in the generic YAML pass.
        pass

# 2) Validate DetCards and links to referenced artifacts.
for path in sorted(TECH.glob("**/DET-*.yaml")):
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"DetCard YAML error in {path.relative_to(ROOT)}: {exc}")
        continue

    detcards.append((path, data))
    for field in ["id", "title", "version", "status", "tactics", "techniques", "platforms", "datasources", "detections"]:
        if field not in data:
            errors.append(f"{path.relative_to(ROOT)}: missing required field {field}")

    validation = data.get("validation") or {}
    if validation.get("status") != "not_tested" and not data.get("tests", {}).get("datasets"):
        warnings.append(f"{path.relative_to(ROOT)}: validation status is not 'not_tested' but no datasets are attached")


    det = data.get("detections") or {}
    for key in ["sigma", "network_rules", "yara", "hunts"]:
        for rel in det.get(key) or []:
            target = path.parent / rel
            if not target.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing referenced {key} artifact: {rel}")

    for platform, query_files in (det.get("queries") or {}).items():
        for rel in query_files or []:
            target = path.parent / rel
            if not target.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing referenced query artifact for {platform}: {rel}")

ids = [data.get("id") for _, data in detcards]
for det_id, count in Counter(ids).items():
    if count > 1:
        errors.append(f"duplicate DetCard ID: {det_id}")

known_ids = set(ids)
for pack in sorted(PACKS.glob("*.yml")):
    try:
        data = yaml.safe_load(pack.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        errors.append(f"Pack YAML error in {pack.relative_to(ROOT)}: {exc}")
        continue
    for det_id in data.get("includes") or []:
        if det_id not in known_ids:
            errors.append(f"{pack.relative_to(ROOT)}: unknown DetCard ID {det_id}")

# 3) Basic structure checks.
for technique_dir in sorted(p for p in TECH.iterdir() if p.is_dir()):
    if not (technique_dir / "README.md").exists():
        errors.append(f"{technique_dir.relative_to(ROOT)}: missing README.md")
    if not (technique_dir / "tests" / "plan.md").exists():
        errors.append(f"{technique_dir.relative_to(ROOT)}: missing tests/plan.md")
    if not list(technique_dir.glob("DET-*.yaml")):
        warnings.append(f"{technique_dir.relative_to(ROOT)}: no DetCards found")

# 4) Coverage summary.
technique_counts = defaultdict(int)
for path, _ in detcards:
    technique_counts[path.parent.name] += 1

if errors:
    print("Validation failed:")
    for err in errors:
        print(f"- {err}")
    sys.exit(1)

print(f"OK: {len(detcards)} DetCards validated.")
print(f"OK: {len(technique_counts)} technique folders with DetCards.")
if warnings:
    print("Warnings:")
    for warning in warnings:
        print(f"- {warning}")
