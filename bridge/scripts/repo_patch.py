"""Build Git patches from the models' repaired functions.

Checks out the vulnerable project at its original commit, inserts the fixed
functions with PatchEval's FuncReplacer, and takes a `git diff`.

Fetches only the commits it needs and reuses local copies. Short commit IDs
become full ones through data/commit_shas.json.
"""

import json
import logging
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

# PatchEval's code and the local working folders.
REPO_ROOT = Path(__file__).resolve().parents[2]
PATCHEVAL_HELPER_DIR = REPO_ROOT / "PatchEval" / "patcheval" / "exp_llm" / "helper"
PROJECTS_DIR = REPO_ROOT / "PatchEval" / "patcheval" / "exp_llm" / "projects"
WORKTREES_DIR = REPO_ROOT / "bridge" / "data" / "worktrees"

# PatchEval's own code replaces functions and builds diffs.
sys.path.insert(0, str(PATCHEVAL_HELPER_DIR))
from func_replacer import FuncReplacer 


class _LogManagerShim:
    # The logger interface FuncReplacer expects.

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def get_current_logger(self) -> logging.Logger:
        return self._logger


_logger = logging.getLogger("repo_patch")
_replacer = FuncReplacer(_LogManagerShim(_logger))

# Extract the repository name from its URL.
def _repo_dir_name(repo_url: str) -> str:
    return repo_url.rstrip("/").split("/")[-1]


# Full commit IDs from data/commit_shas.json, filled by load_commit_shas.
FULL_SHAS: dict[str, str] = {}


def load_commit_shas(path: Path, targets: list[dict]) -> None:
    """Load the commit table and stop if it does not match the targets."""
    table = json.loads(path.read_text())
    problems = [key for key, full_sha in table.items()
                if not re.fullmatch(r"[0-9a-f]{40}", full_sha)
                or not full_sha.startswith(key.rsplit("@", 1)[-1])]
    for target in targets:
        short_sha = target["vul_func"][0]["commit"]
        key = f"{target['repo']}@{short_sha}"
        if len(short_sha) < 40 and key not in table:
            problems.append(key)
    if problems:
        raise SystemExit(f"missing or wrong commit IDs in {path}: {problems}")
    FULL_SHAS.update(table)


def resolve_full_sha(repo_url: str, short_sha: str) -> str:
    # The shallow fetch by ID only works with the full ID.
    if len(short_sha) == 40:
        return short_sha
    return FULL_SHAS[f"{repo_url}@{short_sha}"]


def ensure_repo_initialized(repo_url: str) -> Path:
    repo_dir = PROJECTS_DIR / _repo_dir_name(repo_url)
    if not (repo_dir / ".git").exists():
        PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(repo_dir)], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "remote", "add", "origin", repo_url], check=True)
    return repo_dir


def _commit_present(repo_dir: Path, full_sha: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "cat-file", "-e", f"{full_sha}^{{commit}}"],
        capture_output=True,
    )
    return result.returncode == 0


def ensure_commit_fetched(repo_dir: Path, full_sha: str) -> None:
    if _commit_present(repo_dir, full_sha):
        return
    subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", full_sha],
        check=True,
    )


def generate_real_diff_multi(
    repo_url: str,
    commit: str,
    functions: list[dict],
    language: str = "Python",
) -> str:
    """Build one patch for a vulnerability from the model's fixed functions.

    `functions` holds file_path, start_line, end_line and fixed_code; entries
    with empty fixed_code are skipped. Functions are replaced bottom-up, so line
    numbers stay valid. If a replacement fails, the error is raised and the
    vulnerability gets no patch. This follows PatchEval's own flow.
    """
    todo = [f for f in functions if (f.get("fixed_code") or "").strip()]
    if not todo:
        return ""

    repo_dir = ensure_repo_initialized(repo_url)
    full_sha = resolve_full_sha(repo_url, commit)
    ensure_commit_fetched(repo_dir, full_sha)

    dest_path = WORKTREES_DIR / f"{_repo_dir_name(repo_url)}-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(dest_path), full_sha],
        check=True, capture_output=True,
    )

    try:
        touched_files: list[str] = []
        for func in sorted(todo, key=lambda f: int(f["start_line"]), reverse=True):
            target_file = dest_path / func["file_path"]
            _replacer.replace(
                str(target_file),
                int(func["start_line"]),
                int(func["end_line"]),
                func["fixed_code"],
                language,
            )
            if func["file_path"] not in touched_files:
                touched_files.append(func["file_path"])
        return "\n".join(
            _replacer.generate_diff(str(dest_path), file_path)
            for file_path in touched_files
        )
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest_path)],
            cwd=str(repo_dir), capture_output=True,
        )
        if dest_path.exists():
            shutil.rmtree(dest_path, ignore_errors=True)
