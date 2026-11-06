"""Get the models' answers and build patches for both arms.

B leaves the knowledge slot empty; G fills it with CodeGuarder's retrieved
block. Both use the same PatchEval-based repair template.

An answer is saved as soon as it arrives and is never resampled, even if it is
malformed or a refusal. Only failed requests and empty answers are retried.
Saved answers can be turned into patches again without a model call.
"""
import json
import os
import random
import sys

from . import common


def _knowledge_block(records: list[str]) -> str:
    """Format records using CodeGuarder's knowledge-section layout."""
    return "### Security Knowledge:\n" + "\n".join(records) + "\n---\n\n"


def _helpers():
    sys.path.insert(0, str(common.BRIDGE / "scripts"))
    sys.path.insert(0, str(common.PATCHEVAL / "patcheval" / "exp_llm" / "helper"))
    from llm_suite import PatchParser, Validators
    import repo_patch

    common.CACHE.mkdir(parents=True, exist_ok=True)
    repo_patch.PROJECTS_DIR = common.CACHE / "repositories"
    repo_patch.WORKTREES_DIR = common.CACHE / "worktrees"
    # Stops before any model call if a commit ID is missing or wrong.
    repo_patch.load_commit_shas(common.DATA / "commit_shas.json", common.targets())

    class _Log:
        def bind_current_task(self, cve): pass
        def get_current_logger(self):
            import logging
            return logging.getLogger("armG")

    return PatchParser(log_manager=_Log()), Validators(), repo_patch


def _function_content(target: dict, validators) -> str:
    parts = []
    for f in sorted(target["vul_func"], key=lambda f: int(f["start_line"]), reverse=True):
        parts.append(
            f"### Function {f['id']}\n"
            f"#### Last Round Feedback: \n\n"
            f"#### Vulnerable Code:\n{validators.process_original_code(f['snippet'])}"
        )
    return "\n\n".join(parts)


def build_prompts(rows: list[dict], retrieval: dict, validators) -> dict[str, dict[str, str]]:
    """Build both prompts; only the knowledge slot differs."""
    from string import Template
    template = Template(common.TEMPLATE.read_text())
    prompts: dict[str, dict[str, str]] = {arm: {} for arm in common.ARMS}
    for target in rows:
        cve = target["cve_id"]
        base = dict(
            cve_description=target.get("cve_description") or "",
            cwe_name=target.get("cwe_name") or "",
            cwe_description=target.get("cwe_description") or "",
            function_content=_function_content(target, validators))
        block = _knowledge_block([s["record"] for s in retrieval[cve]["selected"]])
        prompts["B"][cve] = template.substitute(**base, external_knowledge="")
        prompts["G"][cve] = template.substitute(**base, external_knowledge=block)
    return prompts


def _sample(cfg, client, arm: str, prompts: dict[str, str]) -> dict[str, str]:
    raw_path = common.run_dir() / f"responses_{arm}.json"
    meta_path = common.run_dir() / f"serving_{arm}.json"
    raws = json.loads(raw_path.read_text()) if raw_path.exists() else {}
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    extra = _extra_body()

    order = sorted(prompts)                      # same shuffled order for both arms
    random.Random(cfg["generation_seed"]).shuffle(order)
    # Skip targets that already have an answer.
    todo = [c for c in order if not (raws.get(c) or "").strip()]
    if not todo:
        print(f"arm {arm}: all {len(prompts)} responses already archived")
        return raws
    print(f"arm {arm}: sampling {len(todo)} of {len(prompts)}")

    for i, cve in enumerate(todo, 1):
        text, deliveries = None, 0
        for attempt in range(cfg["api_transport_attempts"]):
            try:
                r = client.chat.completions.create(
                    model=common.model_spec()["id"],
                    messages=[{"role": "system", "content": cfg["system_message"]},
                              {"role": "user", "content": prompts[cve]}],
                    temperature=cfg["temperature"],
                    max_tokens=common.model_spec().get("max_tokens", cfg["max_tokens"]),
                    timeout=cfg["api_timeout_seconds"],
                    **({"extra_body": extra} if extra else {}))
                text = r.choices[0].message.content
                if not (text or "").strip():      # no response text
                    deliveries += 1
                    text = None
                    usage = getattr(r, "usage", None)
                    detail = getattr(usage, "completion_tokens_details", None)
                    print(f"  [{cve}] empty completion, retrying ({deliveries}) "
                          f"finish={r.choices[0].finish_reason} "
                          f"completion={getattr(usage, 'completion_tokens', '?')} "
                          f"reasoning={getattr(detail, 'reasoning_tokens', '?')}",
                          flush=True)
                    continue
                usage = getattr(r, "usage", None)
                detail = getattr(usage, "completion_tokens_details", None)
                meta[cve] = {"provider": getattr(r, "provider", None),
                             "served_model": getattr(r, "model", None),
                             "response_id": getattr(r, "id", None),
                             "finish_reason": r.choices[0].finish_reason,
                             "completion_tokens": getattr(usage, "completion_tokens", None),
                             # Reasoning can use up the budget and leave no answer.
                             "reasoning_tokens": getattr(detail, "reasoning_tokens", None),
                             "empty_completions_before_delivery": deliveries}
                break
            except Exception as exc:                      # request failure
                print(f"  [{cve}] {type(exc).__name__}, attempt {attempt+1}", flush=True)
        raws[cve] = text or ""
        raw_path.write_text(json.dumps(raws, indent=2))   # save after every target
        meta_path.write_text(json.dumps(meta, indent=2))
        print(f"  {i}/{len(todo)} {cve}", flush=True)

    served = {m.get("provider") for m in meta.values() if m.get("provider")}
    if served:
        print(f"arm {arm}: served by {sorted(served)}")
    retried = sum(m.get("empty_completions_before_delivery", 0) for m in meta.values())
    still_empty = [c for c, v in raws.items() if not (v or "").strip()]
    print(f"arm {arm}: {retried} empty completion(s) retried, "
          f"{len(still_empty)} still empty after {cfg['api_transport_attempts']} attempts"
          + (f" -> {still_empty}" if still_empty else ""))
    return raws


def _patches(arm: str, rows: list[dict], raws: dict, parser, repo_patch) -> None:
    by_cve = {t["cve_id"]: t for t in rows}
    patches, empty = [], []
    for cve in sorted(by_cve):
        target = by_cve[cve]
        results = parser.parse(raws.get(cve) or "", cve) if raws.get(cve) else {}
        funcs = []
        for f in target["vul_func"]:
            fixed = results.get(f["id"]) or results.get(f["id"].replace("vul", "fix"))
            if fixed is None:
                continue
            funcs.append({"file_path": f["file_path"], "start_line": f["start_line"],
                          "end_line": f["end_line"], "fixed_code": fixed})
        try:
            diff = repo_patch.generate_real_diff_multi(
                target["repo"], target["vul_func"][0].get("commit"), funcs,
                target.get("programming_language") or "Python") if funcs else ""
        except Exception as exc:
            print(f"  [{cve}] diff {type(exc).__name__}")
            diff = ""
        if not diff.strip():
            empty.append(cve)
        patches.append({"cve": cve.lower(), "fix_patch": diff, "language": "Python"})

    common.write_run(f"patches_arm_{arm}.json", patches)
    print(f"arm {arm}: {len(patches)} patches, {len(empty)} empty"
          + (f" -> {empty}" if empty else ""))


def _client(cfg):
    """Create a client for the selected endpoint with explicit timeouts."""
    import httpx
    from openai import OpenAI

    spec = common.model_spec()
    key = os.environ.get(spec["api_key_env"])
    if not key:
        raise SystemExit(f"{spec['api_key_env']} is not set (looked in ../.env too)")
    seconds = cfg["api_timeout_seconds"]
    return OpenAI(
        api_key=key,
        base_url=spec["base_url"] or None,
        timeout=httpx.Timeout(seconds, connect=30.0, read=seconds, write=60.0, pool=30.0))


def _extra_body() -> dict:
    """Pin OpenRouter calls to the configured host."""
    preferences = common.model_spec().get("provider_preferences")
    return {"provider": preferences} if preferences else {}


def run() -> None:
    common.load_env()
    cfg = common.config()
    spec = common.model_spec()
    rows = common.targets()
    retrieval = common.read("retrieval.json")
    parser, validators, repo_patch = _helpers()

    # Prompts don't depend on the model, so build them once.
    prompts = build_prompts(rows, retrieval, validators)
    for arm in common.ARMS:
        common.write(f"prompts_{arm}.json", prompts[arm])

    print(f"model {common.model_key()}  ->  {spec['id']}"
          f"{' via ' + spec['base_url'] if spec['base_url'] else ''}")
    client = _client(cfg)
    for arm in common.ARMS:
        raws = _sample(cfg, client, arm, prompts[arm])
        _patches(arm, rows, raws, parser, repo_patch)
