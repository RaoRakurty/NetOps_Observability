# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: Iris replay cases in the repository are synthetic, and a captured case
has nowhere to be committed (tracker 337 N-H2).

GET /api/ai/replay/export/{id} hands an operator one incident as a frozen case.
That is customer data, even after redaction: device names, topology, change
history. Captures belong under `data/iris-replay/`, which `data/` keeps out of
git. This suite is in `tests/`, which CI never skips.

  * no `*.replay.json` under `src/` outside `testdata/golden_incidents`;
  * every case in the committed corpus is synthetic, never a field capture.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJ = Path(__file__).resolve().parents[1]
CORPUS = "src/backend/ai/testdata/golden_incidents"


def misplaced_replay_files(root: Path) -> list[str]:
    """The `*.replay.json` files under src/ that are outside the corpus."""
    out = []
    for path in (root / "src").rglob("*.replay.json"):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(CORPUS + "/"):
            out.append(rel)
    return sorted(out)


def field_cases(corpus: Path) -> list[str]:
    """The corpus entries that are field captures, as `file: id`."""
    out = []
    for path in sorted(corpus.glob("*.json")):
        for case in json.loads(path.read_text(encoding="utf-8")):
            if case.get("source", "synthetic") != "synthetic" or case.get("category") == "field_capture":
                out.append(f"{path.name}: {case.get('id')}")
    return out


def test_no_replay_case_is_committed_under_src():
    bad = misplaced_replay_files(PROJ)
    assert not bad, (
        f"replay cases under src/ outside {CORPUS}: {bad}. A captured case is customer data; keep it in data/iris-replay/."
    )


def test_the_committed_corpus_is_synthetic_only():
    corpus = PROJ / CORPUS
    assert sorted(corpus.glob("*.json")), f"no cases in {corpus}: the guard is not looking"
    bad = field_cases(corpus)
    assert not bad, f"field captures in the committed corpus: {bad}"


def test_captures_directory_is_ignored():
    lines = [ln.strip() for ln in (PROJ / ".gitignore").read_text(encoding="utf-8").splitlines()]
    assert "data/" in lines or "data/iris-replay/" in lines, "data/iris-replay/ must be gitignored: captures live there"


def test_guard_catches_a_planted_case(tmp_path):
    """Negative control: the same checks, on a tree holding the violations."""
    (tmp_path / "src/backend/internal/x").mkdir(parents=True)
    planted = tmp_path / "src/backend/internal/x/customer.replay.json"
    planted.write_text("[]", encoding="utf-8")
    (tmp_path / CORPUS).mkdir(parents=True)
    allowed = tmp_path / CORPUS / "synthetic.replay.json"
    allowed.write_text('[{"id": "a-field-case", "source": "field", "category": "dual_failure"}]', encoding="utf-8")
    assert misplaced_replay_files(tmp_path) == ["src/backend/internal/x/customer.replay.json"]
    assert field_cases(tmp_path / CORPUS) == ["synthetic.replay.json: a-field-case"]
    allowed.write_text('[{"id": "a-capture", "category": "field_capture"}]', encoding="utf-8")
    assert field_cases(tmp_path / CORPUS) == ["synthetic.replay.json: a-capture"]
    allowed.write_text('[{"id": "fine", "category": "dual_failure"}]', encoding="utf-8")
    assert field_cases(tmp_path / CORPUS) == []
