# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: customer-derived Iris eval cases never enter the repository
(tracker 337 N-H3).

`iriseval field-import` files questions operators really asked into the
per-install field-eval store (internal/fieldeval, default data/iris-eval/).
Those questions are customer data. The store refuses a root inside the work
tree unless the path passes through data/; this suite is the backstop in
tests/, which CI never skips:

  * no stored field-eval file (it carries the store's notice line) exists
    anywhere in the tree outside data/ — committed or not;
  * the store's default home is gitignored;
  * negative control: the same scan catches a planted file.
"""

from __future__ import annotations

from pathlib import Path

PROJ = Path(__file__).resolve().parents[1]
# The first words of fieldeval.Notice, the line every stored file carries.
MARKER = "Customer-derived Iris eval cases. Never commit this file."
# Where the marker legitimately appears: the code that writes it, and this guard.
ALLOWED = {
    "src/backend/internal/fieldeval/fieldeval.go",
    "tests/test_iris_field_eval_store.py",
}
SKIP_DIRS = {".git", "node_modules", "data", "dist", "build", "vendor", ".venv", "__pycache__"}


def stored_files_outside_data(root: Path) -> list[str]:
    """Every *.json under root (outside skipped dirs) that is a stored field-eval file."""
    out = []
    stack = [root]
    while stack:
        d = stack.pop()
        for p in d.iterdir():
            if p.is_dir():
                if p.name not in SKIP_DIRS and not p.is_symlink():
                    stack.append(p)
                continue
            if p.suffix != ".json":
                continue
            rel = p.relative_to(root).as_posix()
            if rel in ALLOWED:
                continue
            try:
                if MARKER in p.read_text(encoding="utf-8", errors="ignore"):
                    out.append(rel)
            except OSError:
                continue
    return sorted(out)


def test_no_field_eval_file_lives_in_the_repository():
    bad = stored_files_outside_data(PROJ)
    assert not bad, (
        f"customer-derived Iris eval files inside the repository: {bad}. "
        "They belong in the per-install store (data/iris-eval/), never in the tree."
    )


def test_the_marker_still_matches_the_writer():
    src = (PROJ / "src/backend/internal/fieldeval/fieldeval.go").read_text(encoding="utf-8")
    assert MARKER in src, "fieldeval.Notice changed: update MARKER so this guard keeps looking"


def test_the_store_home_is_ignored():
    lines = [ln.strip() for ln in (PROJ / ".gitignore").read_text(encoding="utf-8").splitlines()]
    assert "data/" in lines or "data/iris-eval/" in lines, "data/iris-eval/ must be gitignored: field cases live there"


def test_guard_catches_a_planted_file(tmp_path):
    (tmp_path / "src/backend/ai/testdata").mkdir(parents=True)
    planted = tmp_path / "src/backend/ai/testdata/field-20261115-000000.json"
    planted.write_text('{"notice": "' + MARKER + ' Held out."}', encoding="utf-8")
    (tmp_path / "data/iris-eval/acme").mkdir(parents=True)
    (tmp_path / "data/iris-eval/acme/field-20261115-000000.json").write_text('{"notice": "' + MARKER + '"}', encoding="utf-8")
    assert stored_files_outside_data(tmp_path) == ["src/backend/ai/testdata/field-20261115-000000.json"]
