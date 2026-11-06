#!/usr/bin/env python3
"""Experiment 1: repair with and without CodeGuarder's knowledge.

    python3 run.py <stage> [model]

    prepare     build the 70 targets from PatchEval's dataset
    retrieve    find the knowledge records for each target
    generate    build both prompts, ask the model, build the patches
    verify      run the ten checks
    evaluate    score the patches with PatchEval's Docker evaluator
    report      show the results next to the PatchEval authors'

[model] is a name from config.json; without it the default model is used.

    python3 run.py generate deepseek-v3
    python3 run.py report all
"""
import sys

STAGES = ("prepare", "retrieve", "generate", "verify", "evaluate", "report")


def main() -> None:
    if not 2 <= len(sys.argv) <= 3 or sys.argv[1] not in STAGES:
        raise SystemExit(__doc__)
    stage, model = sys.argv[1], (sys.argv[2] if len(sys.argv) == 3 else None)

    from src import common, evaluate, generate, prepare, report, retrieve, verify

    if stage == "report" and model == "all":
        report.run_all()
        return
    common.set_model(model)
    {"prepare": prepare, "retrieve": retrieve, "generate": generate, "verify": verify,
     "evaluate": evaluate, "report": report}[stage].run()


if __name__ == "__main__":
    main()
