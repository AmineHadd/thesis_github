"""Search CodeGuarder's FAISS index with the saved query vectors.

Runs without PyTorch (see retrieve.py). CodeGuarder's own selection functions do
the work, and their source and hashes are saved with the results.

There is one query per target. Duplicates are removed first, then the first two
records are kept. CodeGuarder keeps first and removes duplicates after, which
differs for 13 of the 70 targets (see the README).
"""
import hashlib
import json

from . import common


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    from langchain_community.vectorstores import FAISS

    cfg = common.config()
    cache_path = common.CACHE / "query_embeddings.json"
    if not cache_path.exists():
        raise SystemExit(f"missing {cache_path}; run step 1 first")
    queries = json.loads(cache_path.read_text())
    meta_path = common.CACHE / "query_embeddings_meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    find_root_causes, src_find = common.verbatim(
        common.CODEGUARDER / "src" / "Defense_Standard.py", "find_root_causes")
    remove_duplicates_preserve_order, src_dedup = common.verbatim(
        common.CODEGUARDER / "src" / "utils.py", "remove_duplicates_preserve_order")

    if not common.VECTOR_DB.exists():
        raise SystemExit(
            f"missing FAISS index at {common.VECTOR_DB}\n"
            "Build it with the command in README.md, under 'Running it'.")

    table = {v["query"]: v["vector"] for v in queries.values()}
    vector_db = FAISS.load_local(str(common.VECTOR_DB), lambda text: table[text],
                                 allow_dangerous_deserialization=True)
    print(f"index {vector_db.index.ntotal} records, dim {vector_db.index.d}", flush=True)

    out: dict[str, dict] = {}
    for i, cve in enumerate(sorted(queries), 1):
        query = queries[cve]["query"]
        docs = find_root_causes(vector_db, query, top_k=cfg["root_cause_num"])
        contents = [d.page_content for d in docs]
        deduped = remove_duplicates_preserve_order(contents)
        selected = deduped[: cfg["root_cause_per_module"]]
        out[cve] = {
            "query": query,
            "retrieved": len(contents),
            "after_dedup": len(deduped),
            "selected": [{"id": _md5(c)[:12], "record": c} for c in selected],
        }
        if i % 10 == 0 or i == len(queries):
            print(f"  {i}/{len(queries)}", flush=True)

    common.write("retrieval.json", out)
    common.write("retrieval_provenance.json", {
        "embedding_model": cfg["embedding_model"],
        "embedding_model_revision": meta.get("model_revision"),
        "root_cause_num": cfg["root_cause_num"],
        "root_cause_per_module": cfg["root_cause_per_module"],
        "vector_db": str(common.VECTOR_DB.relative_to(common.REPO)),
        "index_records": vector_db.index.ntotal,
        "index_dim": vector_db.index.d,
        "sha256": {
            "corpus": _sha256(common.CODEGUARDER / "dataset" / "Root_Causes.json"),
            "index_faiss": _sha256(common.VECTOR_DB / "index.faiss"),
            "index_pkl": _sha256(common.VECTOR_DB / "index.pkl"),
            "query_embeddings": _sha256(cache_path),
        },
        "codeguarder_functions": {
            "find_root_causes": {"sha256": hashlib.sha256(src_find.encode()).hexdigest(),
                                 "source": src_find},
            "remove_duplicates_preserve_order": {
                "sha256": hashlib.sha256(src_dedup.encode()).hexdigest(),
                "source": src_dedup},
        },
    })
    print(f"wrote retrieval for {len(out)} targets")


if __name__ == "__main__":
    main()
