# History notes — commits that must not be rewritten

Notes about **git history itself**: commits whose recorded shape is misleading,
and the reason the history is nevertheless left exactly as it is. These are not
open work items — they are permanent facts about the repository that anyone
bisecting, blaming or archaeology-ing across the named range needs.

Rules for this file:

* A note lands here when the history it describes is **settled**. Nothing here
  is a task; nothing here is ever "closed".
* **Never** rebase, amend, cherry-pick-replace or `filter-branch` a range a note
  on this page names. Rewriting it would destroy the only record that the
  anomaly existed, and every sha quoted in the tracker, the audit docs and the
  commit messages that reference it.
* Move the note here **verbatim** from wherever it was first recorded, so the
  wording that was reviewed is the wording that survives.

---

## `0882f5f8` carries engine changes it does not describe (2026-09-02)

Moved verbatim from `docs/TRACKER.md` row 219 (2026-09-06), where it had been
filed as an open item. It never was one: it is a recorded decision.

> **History note (do not rewrite): commit `0882f5f8` carries engine changes it
> does not describe.** `0882f5f8` is titled as the design-partner pilot playbook
> (docs), but a **stash incident** left another agent's index staged when it was
> made, so the tracker-184 parser branches and catalog rows reached history
> inside it; `61928aeb` completes them and says so in its own message. The
> history is **recorded, not to be rewritten** — no rebase, no amend, no
> filter-branch on this range. Anyone bisecting parser behaviour across
> 2026-09-02 must read `0882f5f8` as a mixed commit.
