"""Evaluate both arms with PatchEval's Docker evaluator, in batches.

Reads strict and PoC-only success from each case's log, and marks missing or
undefined runs as infrastructure errors.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

from . import common

EVALUATOR = common.PATCHEVAL / "patcheval" / "evaluation" / "run_evaluation.py"
EVAL_OUT = common.HERE / "evaluation_output"
RUN_LOGS = common.HERE / "logs"


def _parse_case(output_dir, cve: str) -> dict:
    """Read one case result from PatchEval's log."""
    log_dir = output_dir / "logs" / cve.lower()
    log_path = next((p for p in (log_dir / "success_output.log", log_dir / "error_output.log")
                     if p.exists()), None)
    if log_path is None:
        return {"strict": False, "poc": False, "unit_test": None, "validation_type": None,
                "infrastructure_error": True, "reason": "missing_case_log"}
    text = log_path.read_text(encoding="utf-8", errors="replace")
    poc = re.search(r"\[PoC RESULT\]:\s*(True|False|None)", text)
    unit = re.search(r"\[UnitTest RESULT\]:\s*(True|False|None)", text)
    validation = re.search(r"\[Validation TYPE\]:\s*([^\r\n]+)", text)
    poc_value = poc.group(1) if poc else None
    return {
        "strict": bool(validation) and validation.group(1).strip() == "Repair Success",
        "poc": poc_value == "True",
        "unit_test": unit.group(1) if unit else None,
        "validation_type": validation.group(1).strip() if validation else None,
        "infrastructure_error": (poc_value in (None, "None")
                                 or "Failed to start container" in text
                                 or "RUN ERROR" in text),
        "reason": None,
    }


def _evaluate_arm(cfg, arm: str) -> dict[str, dict]:
    patch_file = common.run_dir() / f"patches_arm_{arm}.json"
    if not patch_file.exists():
        raise SystemExit(f"no patches for arm {arm}; run generate first")

    rows = json.loads(patch_file.read_text())
    size = cfg["evaluation_batch_size"]
    batches = [rows[i:i + size] for i in range(0, len(rows), size)]
    RUN_LOGS.mkdir(parents=True, exist_ok=True)
    print(f"=== {common.model_key()} arm {arm}: {len(rows)} patches in "
          f"{len(batches)} batch(es) of {size} ===")

    results: dict[str, dict] = {}
    for index, batch in enumerate(batches):
        name = f"arm_{arm}_{common.model_key()}_batch_{index:02d}"
        out_dir = EVAL_OUT / name
        batch_file = common.run_dir() / f"_{name}.json"
        payload = json.dumps(batch, indent=2)
        patches_hash = hashlib.sha256(payload.encode()).hexdigest()
        hash_file = out_dir / "patches.sha256"

        summary = out_dir / "summary.json"
        if summary.exists() and int(json.loads(summary.read_text())
                                    .get("strict_evaluation", {})
                                    .get("total_cases", -1)) == len(batch):
            # Never reuse a score from a different set of patches.
            if not hash_file.exists() or hash_file.read_text().strip() != patches_hash:
                raise SystemExit(f"{out_dir} was not scored from the current patches; "
                                 "remove it and rerun")
            print(f"=== {name}: reusing completed output ===", flush=True)
        else:
            if summary.exists():
                raise SystemExit(f"incomplete evaluator output at {summary}; remove it and rerun")
            print(f"=== {name}: {len(batch)} patches ===", flush=True)
            batch_file.write_text(payload)
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                [sys.executable, str(EVALUATOR),
                 "--output", name,
                 "--patch_file", str(batch_file.resolve()),
                 "--input_file", str(common.INSTANCES.resolve()),
                 "--max_workers", "4",
                 "--log_level", "INFO"],
                cwd=str(common.HERE), env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (RUN_LOGS / f"{name}.log").write_text(result.stdout or "")
            if result.returncode != 0 or not summary.exists():
                raise SystemExit(f"evaluator failed for {name}; see logs/{name}.log")
            hash_file.write_text(patches_hash)

        for row in batch:
            results[row["cve"].upper()] = _parse_case(out_dir, row["cve"])
        done = [results[r["cve"].upper()] for r in batch]
        print(f"  strict {sum(v['strict'] for v in done)}/{len(batch)}"
              f"   PoC-only {sum(v['poc'] for v in done)}/{len(batch)}"
              f"   infra errors {sum(v['infrastructure_error'] for v in done)}", flush=True)
        batch_file.unlink(missing_ok=True)

    common.write_run(f"evaluation_arm_{arm}.json", results)
    return results


def run() -> None:
    cfg = common.config()
    print(f"model {common.model_key()}")
    for arm in common.ARMS:
        if not (common.run_dir() / f"patches_arm_{arm}.json").exists():
            print(f"arm {arm}: not generated yet, skipping")
            continue
        results = _evaluate_arm(cfg, arm)
        strict = sum(v["strict"] for v in results.values())
        poc = sum(v["poc"] for v in results.values())
        infra = sum(v["infrastructure_error"] for v in results.values())
        print(f"{common.model_key()} arm {arm}   strict {strict}/{len(results)}"
              f"   PoC-only {poc}/{len(results)}"
              f"   infrastructure errors {infra}\n")
