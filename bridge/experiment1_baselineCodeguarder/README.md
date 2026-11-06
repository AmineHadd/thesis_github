# Experiment 1: baseline vs. CodeGuarder's retrieved knowledge

Each repair model answers two prompts for the same 70 Python vulnerabilities
from PatchEval:

    arm B   PatchEval's repair prompt with no retrieved knowledge   (baseline)
    arm G   the same prompt plus CodeGuarder's security-knowledge block
            (their knowledge, not their full prompt)

Models: GPT-4.1 (2025-04-14), DeepSeek-V3 (0324), DeepSeek-R1 (0528) and
Gemini 2.5 Pro. `config.json` holds their ids, hosts and token budgets.

## Why B and G are comparable

Both arms use one template, `prompts/repair_template.txt`, and differ only in
what fills `${external_knowledge}`: nothing in B, the security-knowledge block
of CodeGuarder's `construct_prompt` in G. `run.py verify` checks this: every
B prompt equals the template with an empty slot, and removing the knowledge
block from a G prompt gives back exactly that B prompt. B → G therefore measures
adding the retrieved block as a whole, including its content and prompt-length
effects (G is 1.36× longer than B).

Everything else is also fixed per model: the same 70 targets, temperature 0,
the same `max_tokens`, the same serving host, the same Pass@1 policy, the same
patch construction (PatchEval's `PatchParser` and `FuncReplacer`) and the same
scoring (PatchEval's `run_evaluation.py` on `data/evaluation_instances.json`).
We changed only its Docker handling: a longer client timeout, keeping the patch
file until the container is removed, clearer start-up errors, and an optional
image-removal setting we do not use. The scoring logic is unchanged.

`max_tokens` is 16384 for every model except Gemini 2.5 Pro, whose reasoning
and answer share one budget; it runs at the endpoint's maximum of 65536, and
all 140 of its answers end with `finish_reason` "stop". Each OpenRouter model
is pinned to one host, recorded in `artifacts/runs/<model>/serving_<arm>.json`.

## Targets

`run.py prepare` builds the 70 targets from PatchEval's
`datasets/patcheval_dataset.json`, for the CVEs in
`../data/patcheval_dynamic_230_Python.json` (the Python vulnerabilities with a
Docker sandbox). A target keeps only what the prompt may show: the CVE and CWE
descriptions and the vulnerable functions. The reference fix, proof-of-concept
and functionality tests are dropped. Output: `data/targets.json` and
`data/evaluation_instances.json`.

`data/commit_shas.json` holds the full ID of each of the 63 short commit IDs in
those targets. They were resolved once through GitHub's API, so building patches
needs no further lookups.

## Pass@1 policy

One sample per target and arm. A received answer is final: malformed JSON, a
wrong format or a refusal all count as the model's attempt and score as
failures.


## The template vs. PatchEval's `Default.txt`

The template is `exp_llm/prompt_templates/Default.txt` with four edits:

  1. The `# Example:` header and `${one_shot_example}` slot are replaced by
     `${external_knowledge}`.
  2. The input-specification line describing the example now describes the
     knowledge slot.
  3. A trailing space after "Plan Fix Steps" is removed.
  4. In the JSON-escaping note, Unicode arrows become `->` and a doubled space
     becomes single.


Only the first two edits matter. PatchEval's released one-shot examples are in
`datasets/input.json` (60 CVEs, 9 of them among our 70); `patcheval_dataset.json`
has no one-shot field. So a worked example was released for 9 of our targets, and
the released files do not show what the authors' prompts held for the other 61.
The baseline keeps none: adding one for 9 of 70 would make it non-uniform, and a
worked example is itself injected knowledge, which is what arm G measures.

## Comparison with the PatchEval authors

The authors' per-CVE results are in `../data/authors_*_reference.json`. Their
`epoch1` column (one sample per target) is the comparable one; their headline
figure uses up to 10 feedback epochs and is shown for context only. Because
any change in prompt, host or sample can shift an output, we report agreement,
not replication: B agrees with their epoch 1 on 67/70 (GPT-4.1), 63/70
(DeepSeek-V3), 67/70 (DeepSeek-R1) and 61/70 (Gemini 2.5 Pro) targets. Of the
3, 7, 3 and 9 disagreements, 1, 2, 1 and 1 are among the 9 example targets.

## Reused from CodeGuarder, unmodified

From `CodeGuarder/src/Defense_Standard.py` and `utils.py`:

    build_vector_database(root_causes, model)   functionality-indexed FAISS store
    find_root_causes(vector_db, query, top_k)   dense retrieval
    load_local_model(model_path)                jina-embeddings-v3
    remove_duplicates_preserve_order(lst)       deduplication
    construct_prompt(...)                       security-knowledge section only

Defaults kept: `root_cause_num=5`, `root_cause_per_module=2`. Each selected
knowledge record is injected in full, including its vulnerable and fixing
examples. The corpus is CodeGuarder's `Root_Causes.json`, all 16,141 records in
all languages, unfiltered.

## Where the transfer differs from CodeGuarder

  * One query per target instead of one per sub-task. Repair has no task
    decomposition (`broken_instructions`).
  * The query is the CWE description followed by the CVE description, the only
    text in a repair input that describes the affected component.
  * Deduplication order. CodeGuarder keeps ranks 0 and 1, then removes
    duplicates; here duplicates are removed among the top 5 first, then two
    records are kept. For 13 of the 70 targets this injects a second record
    that CodeGuarder's order would not.
  * Only the security-knowledge section of `construct_prompt` is used. Its
    generation instructions, reference code and "review and use the knowledge"
    instruction are left out so that B and G differ by the knowledge alone.

The first two are forced by the task; the last two are our choices.

## Two processes

PyTorch and FAISS each bundle their own OpenMP runtime; loaded together, FAISS
segfaults in `index.search`, and OpenMP's documented workaround can give
silently wrong results. Retrieval therefore runs in two steps:

    src/embed_queries.py   PyTorch, no FAISS   -> cache/query_embeddings.json
    src/search.py          FAISS, no PyTorch   -> artifacts/retrieval.json

Step 1 stores the exact vector from `model.encode(query)`; step 2 passes it to
CodeGuarder's `find_root_causes`. Since importing their modules would load
PyTorch, `find_root_causes` and `remove_duplicates_preserve_order` are read
from their source files and executed verbatim; `verify` compares the hashes.
`IndexFlatL2` is exact brute force, so `verify` also recomputes every
selection with NumPy and requires all 70 to match.

## Running it

Once, on a fresh clone, starting from the repository root:

    # Python 3.12 and the pinned packages
    python3.12 -m venv .venv
    .venv/bin/pip install -r bridge/experiment1_baselineCodeguarder/requirements.txt

    # FAISS index (80 MB, not in the repo)
    cd CodeGuarder/src
    ../../.venv/bin/python -c "import json; from Defense_Standard import build_vector_database, load_local_model; _, m = load_local_model('jinaai/jina-embeddings-v3'); build_vector_database(json.load(open('../dataset/Root_Causes.json')), m).save_local('../../bridge/data/vector_db')"
    cd ../..

    # Docker images for evaluation (230 images, 70 used)
    cd PatchEval/scripts
    ../../.venv/bin/python download_images.py
    cd ../..

`verify` checks the index (16,141 records, dimension 1,024). The selections
are kept in `artifacts/retrieval.json`, so results can be checked without the
index; after `retrieve`, `git diff artifacts/retrieval.json` shows whether it
was reproduced. `artifacts/retrieval_provenance.json` records the model revision
and the hashes of the corpus, index and query vectors used here; a rebuilt index
need not match those hashes byte for byte.

Then, from `bridge/experiment1_baselineCodeguarder/`:

    PY=../../.venv/bin/python

    $PY run.py prepare             # the 70 targets, no API calls
    $PY run.py retrieve            # CodeGuarder's retrieval, no API calls
    $PY run.py generate <model>    # both prompts, one sample each, patches
    $PY run.py verify              # the ten checks below
    $PY run.py evaluate <model>    # PatchEval's Docker evaluator, both arms
    $PY run.py report all          # B and G beside the authors' results

`<model>` is a key of `config.json` (default `gpt-4.1`). `generate` reads
`OPENAI_API_KEY` or `OPENROUTER_API_KEY` from `../.env`. Nothing here writes
outside this folder; `../data/`, `../scripts/`, `PatchEval/` and `CodeGuarder/`
are read-only.

`generate` resumes from archived non-empty responses, while `evaluate` reuses
only complete batches whose patch hash matches; after an interruption, the same
command can safely be run again. If `evaluate` is interrupted, delete the
unfinished batch folder first.

## What `verify` checks

Ten checks, in six groups, recorded in `artifacts/verification.json`:

  1. The targets equal a fresh build from PatchEval's dataset and carry no
     reference fix, proof-of-concept or test.
  2. `find_root_causes` and `remove_duplicates_preserve_order` are
     byte-identical to CodeGuarder's source.
  3. Every injected block appears verbatim in the output of their
     `construct_prompt`.
  4. The index has the recorded size, and each target's two records are the
     exact nearest neighbours, recomputed by brute force.
  5. The template is `Default.txt` with the four edits above and nothing else.
  6. Every B prompt is the template with an empty slot, and every G prompt
     reduces to its B prompt when the block is removed.
