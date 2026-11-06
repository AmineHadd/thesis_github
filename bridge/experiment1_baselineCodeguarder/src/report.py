"""Report the results for arms B and G.

G is B plus CodeGuarder's retrieved block, so comparing them measures adding
that block. The PatchEval authors' epoch-1 results are shown for context; their
10-epoch results are not compared.

Includes strict and PoC-only rates, 95% Wilson intervals and exact McNemar tests.

    run.py report <model>     one model in full
    run.py report all         every model with results, one row each
"""
from __future__ import annotations

import json
from math import comb, sqrt

from . import common

Z = 1.959963984540054
ORDER = ("authors", "B", "G")
LABEL = {"authors": "PatchEval authors, epoch 1", "B": "this folder, baseline",
         "G": "this folder, CodeGuarder"}


def mcnemar(b: int, c: int) -> float:
    """Two-sided exact test on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)


def wilson(successes: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    d = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / d
    half = Z * sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def collect(model: str) -> dict:
    """Collect the available results for one model."""
    common.set_model(model)
    strict: dict[str, dict[str, bool]] = {}
    poc: dict[str, dict[str, bool]] = {}
    infra: dict[str, int] = {}

    for arm in common.ARMS:
        path = common.run_dir() / f"evaluation_arm_{arm}.json"
        if not path.exists():
            continue
        rows = json.loads(path.read_text())
        strict[arm] = {c.upper(): bool(v["strict"]) for c, v in rows.items()}
        poc[arm] = {c.upper(): bool(v["poc"]) for c, v in rows.items()}
        infra[arm] = sum(bool(v.get("infrastructure_error")) for v in rows.values())

    authors_final = None
    reference = common.authors_reference()
    if reference:
        ref = json.loads(reference.read_text())
        strict["authors"] = {c.upper(): v["epoch1_status"] == "success" for c, v in ref.items()}
        poc["authors"] = {c.upper(): bool(v.get("epoch1_poc")) for c, v in ref.items()}
        authors_final = sum(v["final_status"] == "success" for v in ref.values())

    return {"model": model, "spec": common.model_spec(), "strict": strict,
            "poc": poc, "infra": infra, "authors_final": authors_final}


def _table(title: str, arms: dict[str, dict[str, bool]]) -> None:
    print(f"\n{title}")
    print(f"{'arm':9s} {'what it is':32s} {'passed':>9s} {'rate':>7s}  {'95% Wilson':>16s}")
    print("-" * 80)
    for name in ORDER:
        if name not in arms:
            continue
        k, n = sum(arms[name].values()), len(arms[name])
        low, high = wilson(k, n)
        print(f"{name:9s} {LABEL[name]:32s} {k:5d}/{n:<3d} {k / n:6.1%}  [{low:5.1%}, {high:5.1%}]")


def _delta(arms, x: str, y: str):
    """Compare two arms, or return None if either arm is missing."""
    if x not in arms or y not in arms:
        return None
    shared = sorted(set(arms[x]) & set(arms[y]))
    gained = sum(1 for c in shared if arms[y][c] and not arms[x][c])
    lost = sum(1 for c in shared if arms[x][c] and not arms[y][c])
    return (sum(arms[x][c] for c in shared), sum(arms[y][c] for c in shared),
            gained, lost, sum(1 for c in shared if arms[x][c] == arms[y][c]),
            len(shared), mcnemar(lost, gained))


def _contrasts(arms) -> None:
    for label, x, y in (("authors epoch-1 -> this baseline", "authors", "B"),
                        ("B -> G   adapted CodeGuarder knowledge block", "B", "G")):
        d = _delta(arms, x, y)
        if d:
            sx, sy, gained, lost, agree, n, p = d
            print(f"  {label:44s} {sx:2d} -> {sy:2d} ({sy - sx:+d})  gained {gained} lost {lost}"
                  f"  agree {agree}/{n}  p={p:.4f}")


def run() -> None:
    data = collect(common.model_key())
    spec = data["spec"]
    print(f"model {data['model']}  ->  {spec['id']}"
          f"{'' if spec.get('pinned') else '   (not a pinned snapshot)'}")
    if not any(a in data["strict"] for a in common.ARMS):
        raise SystemExit("no evaluation results for this model yet; run evaluate first")

    _table("strict repair success (PoC blocked AND functionality test passes)", data["strict"])
    _table("PoC-only success (PoC blocked, functionality not required)", data["poc"])
    if data["authors_final"] is not None:
        n = len(data["strict"]["authors"])
        f = data["authors_final"]
        print(f"\nfor context, the authors' headline configuration — up to 10 feedback "
              f"epochs — reaches {f}/{n} ({f / n:.1%}). Not comparable with one sample "
              f"per target.")

    print("\ninfrastructure errors (cases the harness could not run)")
    print("-" * 44)
    for name in ORDER:
        if name in data["infra"]:
            print(f"{name:9s} {data['infra'][name]:5d}")

    print("\ncontrasts, strict (exact McNemar on discordant pairs)")
    print("-" * 96)
    _contrasts(data["strict"])
    print("\ncontrasts, PoC-only")
    print("-" * 96)
    _contrasts(data["poc"])

    common.write_run("report.json", {
        "model": data["model"], "model_id": spec["id"],
        "strict": {a: {"passed": sum(r.values()), "n": len(r)}
                   for a, r in data["strict"].items()},
        "poc_only": {a: {"passed": sum(r.values()), "n": len(r)}
                     for a, r in data["poc"].items()},
        "infrastructure_errors": data["infra"],
        "authors_ten_epoch": data["authors_final"],
    })


def run_all() -> None:
    """Summarize B against G for every evaluated model."""
    cfg = common.config()
    rows = [collect(m) for m in cfg["models"]]
    rows = [r for r in rows if any(a in r["strict"] for a in common.ARMS)]
    if not rows:
        raise SystemExit("no model has evaluation results yet")

    for title, field in (("strict repair success", "strict"), ("PoC-only success", "poc")):
        print(f"\n{title} out of 70, one sample per target")
        print(f"{'model':16s} {'authors ep1':>12s} {'baseline B':>11s} {'CodeGuarder G':>14s}"
              f" {'B -> G':>8s} {'gained':>7s} {'lost':>5s} {'p':>7s}")
        print("-" * 86)
        for r in rows:
            arms = r[field]
            a = f"{sum(arms['authors'].values())}/70" if "authors" in arms else "-"
            b = f"{sum(arms['B'].values())}/70" if "B" in arms else "-"
            g = f"{sum(arms['G'].values())}/70" if "G" in arms else "-"
            d = _delta(arms, "B", "G")
            if d:
                _, _, gained, lost, _, _, p = d
                print(f"{r['model']:16s} {a:>12s} {b:>11s} {g:>14s} "
                      f"{sum(arms['G'].values()) - sum(arms['B'].values()):+8d} "
                      f"{gained:>7d} {lost:>5d} {p:>7.4f}")
            else:
                print(f"{r['model']:16s} {a:>12s} {b:>11s} {g:>14s} {'-':>8s}")

    print("\nwhether arm G ever repairs something arm B could not")
    print("-" * 64)
    for r in rows:
        arms = r["strict"]
        if "B" not in arms or "G" not in arms:
            continue
        sb = {c for c, v in arms["B"].items() if v}
        sg = {c for c, v in arms["G"].items() if v}
        extra = sorted(sg - sb)
        print(f"  {r['model']:16s} G \\ B = {extra if extra else 'empty (G is a subset of B)'}")

    common.write("report_all_models.json", [
        {"model": r["model"], "model_id": r["spec"]["id"],
         "strict": {a: sum(v.values()) for a, v in r["strict"].items()},
         "poc_only": {a: sum(v.values()) for a, v in r["poc"].items()},
         "authors_ten_epoch": r["authors_final"]} for r in rows])
