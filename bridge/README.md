# Bridge Experiment

## Overview

`experiment1_baselineCodeguarder/` compares PatchEval's baseline (B) with CodeGuarder's knowledge-enhanced approach (G) using four LLMs on 70 Python vulnerabilities.

Both approaches use the same repair prompt, except for the injected knowledge. Patches are evaluated using PatchEval's `run_evaluation.py`.

## Shared Files


- `scripts/repo_patch.py`: Generates patches from repaired functions.
- `data/vector_db/`: FAISS index containing CodeGuarder's 16,141 knowledge records. It is not in the repository; `experiment1_baselineCodeguarder/README.md` explains how to build it.
- `data/authors_*_reference.json`: Original PatchEval results for comparison.
- `data/patcheval_dynamic_230_Python.json`: The 70 selected Python targets.

## Results

Strict repair requires blocking the exploit while preserving program functionality.

| Model | PatchEval authors | Baseline (B) | CodeGuarder (G) |
|---|---:|---:|---:|
| GPT-4.1 | 6/70 | 7/70 | 6/70 |
| DeepSeek-V3 | 5/70 | 8/70 | 5/70 |
| DeepSeek-R1 | 10/70 | 11/70 | 7/70 |
| Gemini 2.5 Pro | 9/70 | 10/70 | 10/70 |

Full results are available in `experiment1_baselineCodeguarder/RESULTS.md` or can be generated using `run.py report all`.
