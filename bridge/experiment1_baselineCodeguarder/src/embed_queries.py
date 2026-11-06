"""Embed the retrieval queries with CodeGuarder's model.

This stage uses PyTorch but not FAISS. It writes the vectors to
cache/query_embeddings.json for the search stage.
"""

import json
import sys

from . import common


def query_for(target: dict) -> str:
    """Build a query from the target's CWE and CVE descriptions."""
    return f"{target.get('cwe_description') or ''}\n{target.get('cve_description') or ''}".strip()


def main() -> None:
    sys.path.insert(0, str(common.CODEGUARDER / "src"))
    from Defense_Standard import load_local_model

    cfg = common.config()
    rows = common.targets()
    print(f"embedding model {cfg['embedding_model']}", flush=True)
    _, model = load_local_model(cfg["embedding_model"])

    out: dict[str, dict] = {}
    for i, target in enumerate(rows, 1):
        query = query_for(target)
        vector = model.encode(query)          # Same embedding call as CodeGuarder.
        out[target["cve_id"]] = {"query": query, "vector": [float(x) for x in vector]}
        if i % 10 == 0 or i == len(rows):
            print(f"  {i}/{len(rows)}", flush=True)

    common.CACHE.mkdir(parents=True, exist_ok=True)
    path = common.CACHE / "query_embeddings.json"
    path.write_text(json.dumps(out))
    # search.py records this; it cannot load the model itself.
    (common.CACHE / "query_embeddings_meta.json").write_text(json.dumps(
        {"model_revision": getattr(model.config, "_commit_hash", None)}))
    dims = {len(v["vector"]) for v in out.values()}
    print(f"wrote {len(out)} query vectors, dim {sorted(dims)} -> {path}")


if __name__ == "__main__":
    main()
