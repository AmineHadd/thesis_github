#  Results : baseline B and the adapted CodeGuarder knowledge block G

One sample per target at temperature 0, on the 70 Python targets from
PatchEval's Docker-backed set, scored by PatchEval's evaluator (Docker handling
adjusted, scoring unchanged).
No case hit an infrastructure error, so all 70 are decided in every arm.
The same numbers, with every contrast, come from `run.py report all`.

## Strict repair success (PoC blocked AND functionality test passes)

| model | PatchEval authors, epoch 1 | baseline B | CodeGuarder G | G − B | G gains | G loses | exact McNemar p |
|---|---|---|---|---|---|---|---|
| GPT-4.1 | 6/70 | 7/70 | 6/70 | -1 | 1 | 2 | 1.000 |
| DeepSeek-V3 | 5/70 | 8/70 | 5/70 | -3 | 1 | 4 | 0.375 |
| DeepSeek-R1 | 10/70 | 11/70 | 7/70 | -4 | 1 | 5 | 0.219 |
| Gemini 2.5 Pro | 9/70 | 10/70 | 10/70 | +0 | 4 | 4 | 1.000 |




## What changes between B and G

| model | repaired by G only | repaired by B only |
|---|---|---|
| GPT-4.1 | CVE-2022-21683 | CVE-2017-0360, CVE-2024-3571 |
| DeepSeek-V3 | CVE-2022-21683 | CVE-2022-21699, CVE-2023-29159, CVE-2023-45809, CVE-2024-3571 |
| DeepSeek-R1 | CVE-2025-23042 | CVE-2020-26215, CVE-2022-36087, CVE-2023-29159, CVE-2023-40267, CVE-2024-3571 |
| Gemini 2.5 Pro | CVE-2020-26215, CVE-2023-40267, CVE-2024-3571, CVE-2024-39877 | CVE-2021-21354, CVE-2022-36087, CVE-2023-29159, CVE-2025-27154 |


