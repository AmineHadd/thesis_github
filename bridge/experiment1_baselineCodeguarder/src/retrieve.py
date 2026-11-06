"""Find the knowledge records for each target, with no API calls.

PyTorch and FAISS each bundle OpenMP and crash when loaded together. The known
workaround can give silently wrong results, so this stage runs two processes:

    step 1  src/embed_queries.py   PyTorch  -> cache/query_embeddings.json
    step 2  src/search.py          FAISS    -> artifacts/retrieval.json

Step 2 uses the exact vectors from step 1, so the split changes nothing.
"""

import subprocess
import sys

from . import common

STEPS = ("src.embed_queries", "src.search")


def run() -> None:
    for module in STEPS:
        print(f"--- {module} ---", flush=True)
        result = subprocess.run([sys.executable, "-u", "-m", module], cwd=str(common.HERE))
        if result.returncode != 0:
            raise SystemExit(f"{module} exited with code {result.returncode}")

    out = common.read("retrieval.json")
    unique = {s["id"] for v in out.values() for s in v["selected"]}
    duplicates = sum(v["retrieved"] - v["after_dedup"] for v in out.values())
    print(f"\nDone: {len(out)} targets, {len(unique)} different knowledge records used, "
          f"{duplicates} duplicates removed.")
