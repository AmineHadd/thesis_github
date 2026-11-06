"""Check the claims the experiment rests on.

Rebuilds the targets, compares CodeGuarder's functions with their source, checks
the knowledge block against construct_prompt, recomputes every selection by
brute force, and checks the template and both prompts.

Uses FAISS without PyTorch. Writes artifacts/verification.json.
"""
import hashlib
import json
from string import Template

import numpy as np

from . import common, generate, prepare

DEFAULT_TEMPLATE = common.PATCHEVAL / "patcheval" / "exp_llm" / "prompt_templates" / "Default.txt"

# Expected edits to PatchEval's template. Each must occur once.
TEMPLATE_EDITS = (
    ("4. Example: Sample code fix for similar vulnerabilities",
     "4. External Repair Evidence: [Optional] Automatically retrieved evidence from a historical repair"),
    ("# Example:\n${one_shot_example}", "${external_knowledge}"),
    ("### 2. Plan Fix Steps \n", "### 2. Plan Fix Steps\n"),
    ("JSON-escaped  (e.g., tab → \\t, newlines → \\n, \" → \\\")",
     "JSON-escaped (e.g., tab -> \\t, newlines -> \\n, \" -> \\\")"),
)
TEMPLATE_TAIL = "\n\n"      # ours ends with two newlines


def _check(results: list[dict], name: str, passed: bool, detail: str) -> None:
    results.append({"check": name, "passed": bool(passed), "detail": detail})
    print(f"  [{'ok' if passed else 'FAIL'}] {name}: {detail}", flush=True)


def run() -> None:
    from langchain_community.vectorstores import FAISS

    cfg = common.config()
    rows = common.targets()
    retrieval = common.read("retrieval.json")
    provenance = common.read("retrieval_provenance.json")
    queries = json.loads((common.CACHE / "query_embeddings.json").read_text())
    results: list[dict] = []

    print("targets")
    rebuilt = prepare.build()
    _check(results, "targets are PatchEval's records without the answer", rebuilt == rows,
           f"{sum(a == b for a, b in zip(rebuilt, rows))}/{len(rows)} equal a fresh build from "
           f"{prepare.DATASET.name}; no reference fix, PoC or test field")

    print("CodeGuarder's code")
    ds = common.CODEGUARDER / "src" / "Defense_Standard.py"
    ut = common.CODEGUARDER / "src" / "utils.py"
    for name, path in (("find_root_causes", ds), ("remove_duplicates_preserve_order", ut)):
        _, source = common.verbatim(path, name)
        recorded = provenance["codeguarder_functions"][name]["sha256"]
        digest = hashlib.sha256(source.encode()).hexdigest()
        _check(results, f"{name} is verbatim",
               source in path.read_text() and digest == recorded,
               f"found in {path.name}, sha256 {digest[:12]} matches retrieval record")

    construct_prompt, _ = common.verbatim(ds, "construct_prompt")
    mismatched = [cve for cve, row in retrieval.items()
                  if generate._knowledge_block([s["record"] for s in row["selected"]])
                  not in construct_prompt([s["record"] for s in row["selected"]], "x", [])]
    _check(results, "knowledge block matches construct_prompt", not mismatched,
           f"{len(retrieval) - len(mismatched)}/{len(retrieval)} blocks appear verbatim "
           f"in their construct_prompt output")

    print("retrieval")
    vector_db = FAISS.load_local(str(common.VECTOR_DB), lambda text: [0.0],
                                 allow_dangerous_deserialization=True)
    stored = vector_db.index.reconstruct_n(0, vector_db.index.ntotal)
    texts = [vector_db.docstore.search(vector_db.index_to_docstore_id[i]).page_content
             for i in range(vector_db.index.ntotal)]
    _check(results, "index unchanged",
           vector_db.index.ntotal == provenance["index_records"]
           and vector_db.index.d == provenance["index_dim"],
           f"{vector_db.index.ntotal} records, dim {vector_db.index.d}")

    wrong = []
    for cve, row in retrieval.items():
        vector = np.asarray(queries[cve]["vector"], dtype=np.float32)
        distances = ((stored - vector) ** 2).sum(1)            # exact squared L2
        top = [texts[i] for i in np.argsort(distances, kind="stable")[: cfg["root_cause_num"]]]
        seen, deduped = set(), []
        for text in top:
            if text not in seen:
                seen.add(text)
                deduped.append(text)
        expected = [hashlib.md5(t.encode()).hexdigest()[:12]
                    for t in deduped[: cfg["root_cause_per_module"]]]
        if expected != [s["id"] for s in row["selected"]]:
            wrong.append(cve)
    _check(results, "selection equals brute-force nearest neighbours", not wrong,
           f"{len(retrieval) - len(wrong)}/{len(retrieval)} targets reproduced exactly")

    _check(results, "two records per target",
           all(len(r["selected"]) == cfg["root_cause_per_module"] for r in retrieval.values()),
           f"all {len(retrieval)} targets carry {cfg['root_cause_per_module']} records")

    print("prompts")
    text = common.TEMPLATE.read_text(encoding="utf-8")
    expected, applied = DEFAULT_TEMPLATE.read_text(encoding="utf-8"), 0
    for old, new in TEMPLATE_EDITS:
        if expected.count(old) == 1:
            expected, applied = expected.replace(old, new), applied + 1
    _check(results, "template is PatchEval's Default.txt with the documented edits",
           applied == len(TEMPLATE_EDITS) and expected + TEMPLATE_TAIL == text,
           f"{applied}/{len(TEMPLATE_EDITS)} edits apply once each and nothing else differs")

    if not (common.ARTIFACTS / "prompts_B.json").exists():
        raise SystemExit("no prompts yet; run generate first")
    _, validators, _ = generate._helpers()
    template = Template(text)
    prompts_b, prompts_g = common.read("prompts_B.json"), common.read("prompts_G.json")
    empty_slot, isolated = 0, 0
    for target in rows:
        cve = target["cve_id"]
        base = dict(
            cve_description=target.get("cve_description") or "",
            cwe_name=target.get("cwe_name") or "",
            cwe_description=target.get("cwe_description") or "",
            function_content=generate._function_content(target, validators))
        empty = template.substitute(**base, external_knowledge="")
        empty_slot += prompts_b.get(cve) == empty
        block = generate._knowledge_block([s["record"] for s in retrieval[cve]["selected"]])
        if prompts_g.get(cve) and prompts_g[cve].replace(block, "", 1) == empty:
            isolated += 1
    _check(results, "arm B is the template with an empty knowledge slot", empty_slot == len(rows),
           f"{empty_slot}/{len(rows)} arm-B prompts byte-identical to the template rendered "
           f"without knowledge")
    _check(results, "knowledge block is the only difference", isolated == len(rows),
           f"{isolated}/{len(rows)} arm-G prompts reduce to arm B when the block is removed")

    path = common.write("verification.json", {
        "checks": results,
        "passed": sum(r["passed"] for r in results),
        "total": len(results),
    })
    failed = [r["check"] for r in results if not r["passed"]]
    print(f"\n{sum(r['passed'] for r in results)}/{len(results)} checks passed -> {path}")
    if failed:
        raise SystemExit("failed: " + ", ".join(failed))
