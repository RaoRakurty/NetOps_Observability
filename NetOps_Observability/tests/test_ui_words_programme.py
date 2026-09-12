# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: the "fewer words, Iris explains" debt list stays empty (tracker 270).

WHY THIS EXISTS. The programme
(`docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md`) paid off a real debt: 92
files and 401 word-budget breaches, cleared over six sweeps, with every removed
explanation rewritten as an authored `src/backend/ai/skills/explain/<topic>.md`
answer reachable from an `<AskIris topic=…/>`. `wordBudget.allow.json` is the
ledger of what is still owed, and it is now `{}`.

An allowlist that shrank to nothing is exactly the kind of thing that grows back:
the next author under time pressure adds one line to the JSON and the guard goes
quiet again for that file. So the empty state is asserted from OUTSIDE the
frontend test suite, in the cheap lane, on the JSON itself — a file the frontend
tests could be edited to stop reading, but that this test reads directly.

THE FIX WHEN THIS FAILS IS NEVER TO EDIT THE JSON. Shorten the copy to the
design doc's budget, or move the explanation into
`src/backend/ai/skills/explain/<topic>.md` and put the `(i)` where it was. The
debt is paid; it is not a line of credit.

Deliberately NOT asserted here: the budgets themselves. `wordBudget.test.ts`
owns counting words — this file owns the one fact that survives it being edited.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW = ROOT / "src" / "frontend" / "src" / "wordBudget.allow.json"
GUARD = ROOT / "src" / "frontend" / "src" / "wordBudget.test.ts"
EXPLAIN = ROOT / "src" / "backend" / "ai" / "skills" / "explain"


def test_allowlist_file_exists_and_is_an_object() -> None:
    """A deleted or renamed ledger must fail loudly, not pass by absence."""
    assert ALLOW.is_file(), f"{ALLOW} is missing — the word-budget ledger may not be deleted"
    data = json.loads(ALLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{ALLOW} must be a JSON object of file -> breach count"


def test_word_budget_allowlist_is_empty() -> None:
    """The debt is paid and must stay paid."""
    data = json.loads(ALLOW.read_text(encoding="utf-8"))
    assert data == {}, (
        "wordBudget.allow.json must stay empty (tracker 270 is closed; the six sweeps "
        f"cleared 92 files / 401 breaches). Re-admitted debt: {sorted(data)}. "
        "Shorten the copy to the budgets in docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md, "
        "or move the explanation into src/backend/ai/skills/explain/<topic>.md and put an "
        "<AskIris topic=…/> where it was."
    )


def test_the_guard_that_reads_the_allowlist_still_exists() -> None:
    """The ledger being empty means nothing if nothing counts words any more."""
    assert GUARD.is_file(), f"{GUARD} is missing — the word-budget guard may not be deleted"
    src = GUARD.read_text(encoding="utf-8")
    assert "wordBudget.allow.json" in src, "the guard no longer reads the ledger it ratchets"
    assert "stays swept" in src, "the per-file 'stays swept' pins were removed from the guard"


def test_the_explanations_the_sweeps_moved_off_screen_are_still_there() -> None:
    """Words removed from a screen were moved, not deleted.

    The corpus is what makes "the screen does not teach" honest: an operator who
    needs the definition asks Iris and gets the authored file back, cited. An
    empty (or gutted) corpus would mean the sweeps simply deleted the answers.
    """
    assert EXPLAIN.is_dir(), f"{EXPLAIN} is missing — the explain corpus is where the words went"
    topics = sorted(p.name for p in EXPLAIN.glob("*.md"))
    assert len(topics) >= 300, (
        f"the explain corpus holds only {len(topics)} files; the six sweeps authored 327 of them "
        "and the screens they were removed from now point at nothing"
    )
