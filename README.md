# Adapting Knowledge-Injected Prompting for Automated Vulnerability Repair

Bachelor's thesis in Informatics, CIT, Technical University of Munich. 
Author: Amine Haddad. 
Supervisor: Prof. Dr. Chunyang Chen;
Host supervisor: Prof. Jinqiu Yang (Concordia University).

## The study

CodeGuarder pulls security knowledge out of past vulnerability fixes and adds it
to the prompt, which makes LLMs write more secure code. Here we ask a different
question: does the same knowledge help an LLM repair vulnerable code?

We take the 70 Python vulnerabilities in PatchEval that come with an executable
exploit and functionality tests, and give each one to four models (GPT-4.1,
DeepSeek-V3, DeepSeek-R1, Gemini 2.5 Pro) under two prompts:

- **B** : PatchEval's repair prompt without the historical example
- **G** : the same prompt plus the knowledge block CodeGuarder's retrieval picks.

Each prompt is answered once at temperature 0, and PatchEval's evaluator scores
the patch. A patch counts as repaired only when it blocks the exploit and the
project's tests still pass.

| Model          | Repaired with B | Repaired with G |
|----------------|-----------------|-----------------|
| GPT-4.1        | 7/70            | 6/70            |
| DeepSeek-V3    | 8/70            | 5/70            |
| DeepSeek-R1    | 11/70           | 7/70            |
| Gemini 2.5 Pro | 10/70           | 10/70           |


## Layout

```text
.
├── README.md                     current file
├── bridge/
│   ├── data/                     the 70 Python targets and the PatchEval authors' released results
│   ├── scripts/repo_patch.py     builds a patch by splicing fixed functions into the project
│   └── experiment1_baselineCodeguarder/
│       ├── README.md             design, setup, run order
│       ├── RESULTS.md             result tables
│       ├── run.py, src/          running the full pipeline
│       ├── config.json           models, hosts, retrieval parameters
│       ├── prompts/              the repair prompt of both arms
│       ├── data/                 the 70 python targets
│       └── artifacts/            everything the results are computed from
├── CodeGuarder/                  copy of CodeGuarder's code and knowledge base
└── PatchEval/                    copy of PatchEval: dataset, evaluator, image list
```
