"""Prepare the 70 Python targets from PatchEval's dataset.

Keeps what the prompts and patch building need, and drops reference fixes and
tests. No API calls. Writes targets.json and evaluation_instances.json.
"""
import json
import re

from . import common

TARGET_IDS = common.BRIDGE / "data" / "patcheval_dynamic_230_Python.json"
DATASET = common.PATCHEVAL / "patcheval" / "datasets" / "patcheval_dataset.json"

# Fields that could reveal a fix or a test.
FORBIDDEN = {"fix_func", "vul_patch", "poc_patch", "unit_test_cmd", "modification", "one_shot",
             "patch_url"}


def _cwe_ids(value) -> list[str]:
    """Return unique CWE identifiers in their original order."""
    values = [value] if isinstance(value, str) else list(value or [])
    ids: list[str] = []
    for item in values:
        match = re.search(r"CWE-\d+", str(item or ""), flags=re.IGNORECASE)
        if match and match.group(0).upper() not in ids:
            ids.append(match.group(0).upper())
    return ids


def _target(row: dict) -> dict:
    info = row.get("cwe_info") or {}
    ids = _cwe_ids(info)
    names, descriptions = [], []
    for cwe in ids:
        detail = info.get(cwe) or {}
        if detail.get("name"):
            names.append(f"{cwe}: {detail['name']}")
        if detail.get("description"):
            descriptions.append(f"{cwe}: {detail['description']}")
    return {
        "cve_id": row["cve_id"],
        "cwe_ids": ids,
        "cwe_name": "\n".join(names),
        "cwe_description": "\n".join(descriptions),
        "cve_description": row.get("cve_description") or "",
        "repo": row["repo"],
        "programming_language": row["programming_language"],
        "vul_func": [{
            "id": f["id"],
            "file_path": f["file_path"],
            "start_line": int(f["start_line"]),
            "end_line": int(f["end_line"]),
            "commit": f["commit"],
            "snippet": f["snippet"],
        } for f in row.get("vul_func") or []],
    }


def _write(path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build() -> list[dict]:
    """Build the 70 targets, in the order of the target list."""
    ids = [row["cve_id"] for row in json.loads(TARGET_IDS.read_text())]
    if len(ids) != 70 or len(set(ids)) != 70:
        raise SystemExit("the target list must contain 70 unique CVEs")

    by_cve = {row["cve_id"]: row for row in json.loads(DATASET.read_text())}
    missing = [cve for cve in ids if cve not in by_cve]
    if missing:
        raise SystemExit(f"targets missing from PatchEval's dataset: {missing}")

    targets = [_target(by_cve[cve]) for cve in ids]
    if any(t["programming_language"] != "Python" for t in targets):
        raise SystemExit("the target list contains a non-Python record")
    if any(FORBIDDEN & set(t) for t in targets):
        raise SystemExit("a reference-fix or test field reached a target")
    return targets


def run() -> None:
    targets = build()
    common.DATA.mkdir(parents=True, exist_ok=True)
    _write(common.TARGETS, targets)
    _write(common.INSTANCES, [{"cve_id": t["cve_id"], "programming_language": t["programming_language"]}
                              for t in targets])
    functions = sum(len(t["vul_func"]) for t in targets)
    print(f"prepare: {len(targets)} targets, {functions} vulnerable functions -> {common.DATA}")
