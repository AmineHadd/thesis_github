"""Shared paths and file helpers for the experiment."""

import ast
import json
import os
from pathlib import Path
from typing import Any, List

HERE = Path(__file__).resolve().parent.parent
BRIDGE = HERE.parent
REPO = BRIDGE.parent
CODEGUARDER = REPO / "CodeGuarder"
PATCHEVAL = REPO / "PatchEval"

# Files created by the prepare stage.
DATA = HERE / "data"
TARGETS = DATA / "targets.json"
INSTANCES = DATA / "evaluation_instances.json"
TEMPLATE = HERE / "prompts" / "repair_template.txt"

# FAISS index over CodeGuarder's knowledge base.
VECTOR_DB = BRIDGE / "data" / "vector_db"

# PatchEval authors' results for the same 70 CVEs.
AUTHORS_DIR = BRIDGE / "data"

ARMS = ("B", "G")

ARTIFACTS = HERE / "artifacts"          # shared artifacts
RUNS = ARTIFACTS / "runs"               # model-specific artifacts
CACHE = HERE / "cache"

_MODEL: str | None = None


def set_model(key: str | None = None) -> str:
    """Select the model used by this process."""
    global _MODEL
    cfg = config()
    key = key or cfg["default_model"]
    if key not in cfg["models"]:
        raise SystemExit(f"unknown model '{key}'; available: {', '.join(cfg['models'])}")
    _MODEL = key
    return key


def model_key() -> str:
    return _MODEL or set_model()


def model_spec() -> dict[str, Any]:
    """Return the selected model's configuration."""
    return config()["models"][model_key()]


def authors_reference() -> Path | None:
    name = model_spec().get("authors_reference")
    path = AUTHORS_DIR / name if name else None
    return path if path and path.exists() else None


def run_dir() -> Path:
    path = RUNS / model_key()
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_env() -> None:
    """Load bridge/.env without replacing existing environment variables."""
    env = BRIDGE / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def config() -> dict[str, Any]:
    return json.loads((HERE / "config.json").read_text())


def targets() -> list[dict[str, Any]]:
    rows = json.loads(TARGETS.read_text())
    if len(rows) != 70:
        raise SystemExit(f"expected 70 targets, found {len(rows)}")
    return rows


def write(name: str, payload: Any) -> Path:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    path = ARTIFACTS / name
    path.write_text(json.dumps(payload, indent=2))
    return path


def read(name: str) -> Any:
    return json.loads((ARTIFACTS / name).read_text())


def write_run(name: str, payload: Any) -> Path:
    """Write an artifact for the selected model."""
    path = run_dir() / name
    path.write_text(json.dumps(payload, indent=2))
    return path


def verbatim(path: Path, name: str) -> tuple[Any, str]:
    """Load one function from a source file, without importing that file.

    Importing would load PyTorch next to FAISS. The source is returned too, so
    it can be hashed.
    """
    source = path.read_text()
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            segment = ast.get_source_segment(source, node)
            # CodeGuarder's functions use List in their type hints.
            namespace: dict[str, Any] = {"List": List}
            exec(compile(segment, f"{path.name}::{name}", "exec"), namespace)
            return namespace[name], segment
    raise SystemExit(f"{name} not found in {path}")
