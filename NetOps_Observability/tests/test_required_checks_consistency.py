# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: the required-check list is ONE list.

WHY THIS EXISTS. Three places have to agree about which CI jobs block a ship, and
until 2026-09-04 nothing made them:

  1. `docs/runbooks/ci-branch-protection.md` §1 — the human list, copied by hand
     into GitHub's branch ruleset (which is NOT in the repo, so it is the one half
     no test can reach).
  2. the workflows' real job `name:` fields — the actual check names GitHub
     reports. A required check naming a job that does not exist pins every PR at
     "Expected — Waiting for status to be reported" forever; a blocking job that
     nobody requires runs, goes green, and enforces nothing.
  3. `.github/workflows/release-gate.yml` — the TAG gate. Branch protection does
     not exist on tags, so this is the only thing standing between a `v*.*.*` tag
     and a GHCR push / a release asset. Before it existed, `publish-images.yml`
     and `release-bundle.yml` had no `needs:` on any test job at all.

The runbook has drifted twice already (it once required a job name that no job
carried, and it once listed 5 of 16 checks). This file makes the drift fail the
build instead of the release.

The runbook is the SOURCE: these tests read its §1.1 / §1.2 / §1.3 tables and hold
the workflows to them. Fix the doc and the workflow together, never the test.

Deliberately NOT asserted: whether GitHub's live ruleset matches §4's payload.
That lives outside the repository; §4 stays the manual half.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "runbooks" / "ci-branch-protection.md"
CHECKLIST = Path(__file__).resolve().parents[1] / "docs" / "RELEASE_CHECKLIST.md"
# The rc1 release PROCEDURE reproduces the same payload a third time, because it
# is the page an owner reads at the moment of authorizing the ruleset change. A
# third hand-copied list with no guard is exactly the drift this file exists to
# stop, so it is parsed too.
RC1_PROCEDURE = (
    Path(__file__).resolve().parents[1] / "docs" / "runbooks" / "rc1-release-procedure.md"
)

RELEASE_GATE = "release-gate.yml"
# The workflows that publish something a customer can consume. Every job in them
# must be gated.
PUBLISHING_WORKFLOWS = ("publish-images.yml", "release-bundle.yml")


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------
def _load(name: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{name}: not a YAML mapping"
    return doc


def _triggers(doc: dict) -> dict:
    """Return the `on:` block.

    PyYAML resolves the bare key `on` to the boolean True (YAML 1.1), so both
    spellings have to be tried — a silent miss here would make every trigger
    assertion below vacuous.
    """
    for key in ("on", True):
        if key in doc:
            block = doc[key]
            return block if isinstance(block, dict) else {}
    raise AssertionError("workflow has no `on:` block")


def _jobs(doc: dict) -> dict[str, dict]:
    jobs = doc.get("jobs") or {}
    assert isinstance(jobs, dict) and jobs, "workflow declares no jobs"
    return jobs


def _check_names(name: str) -> set[str]:
    """The check names GitHub will report for a workflow.

    A job's `name:` if it has one, else its job id — the same rule the runbook
    states for `fresh-install-integrity` · `integrity`.
    """
    return {(job.get("name") or job_id) for job_id, job in _jobs(_load(name)).items()}


def _workflow_files() -> list[str]:
    return sorted(p.name for p in WORKFLOWS.glob("*.yml"))


_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|")


def _runbook_section(heading_prefix: str) -> str:
    """The body of a `### <prefix> …` subsection of the runbook."""
    text = RUNBOOK.read_text(encoding="utf-8")
    m = re.search(rf"^### {re.escape(heading_prefix)}[^\n]*\n(.*?)(?=^#{{2,3}} )", text, re.MULTILINE | re.DOTALL)
    assert m, f"runbook has no `### {heading_prefix}` section — the doc layout moved"
    return m.group(1)


def _table(heading_prefix: str) -> list[tuple[str, str]]:
    """`(workflow, check name)` rows of the table in a runbook subsection."""
    rows = [
        (m.group(1), m.group(2))
        for line in _runbook_section(heading_prefix).splitlines()
        if (m := _ROW.match(line.strip()))
    ]
    assert rows, f"runbook §{heading_prefix}: parsed zero table rows"
    return rows


def _required() -> list[tuple[str, str]]:
    return _table("1.1")


def _optional() -> list[tuple[str, str]]:
    return _table("1.2")


def _excluded() -> list[tuple[str, str]]:
    return _table("1.3")


def _gh_api_contexts(doc: Path) -> list[str]:
    """The `checks:` contexts inside a `gh api ... --input - <<'JSON'` payload.

    Two documents carry this payload — the runbook (§4) and the release checklist
    (👤 §6.2, the one the owner actually runs on ship day). Both are parsed.
    """
    m = re.search(r"--input - <<'JSON'\n(.*?)\nJSON\n", doc.read_text(encoding="utf-8"), re.DOTALL)
    assert m, f"{doc.name}: no `gh api` JSON heredoc found"
    payload = json.loads(m.group(1))
    return [c["context"] for c in payload["required_status_checks"]["checks"]]


def _gate_calls() -> dict[str, str]:
    """`{job id: called workflow filename}` for release-gate.yml."""
    calls = {}
    for job_id, job in _jobs(_load(RELEASE_GATE)).items():
        uses = job.get("uses")
        assert uses, f"{RELEASE_GATE}: job `{job_id}` is not a reusable-workflow call"
        calls[job_id] = uses
    return calls


# --------------------------------------------------------------------------
# sanity — these globs and regexes must never go vacuously empty
# --------------------------------------------------------------------------
def test_harness_is_aimed_at_something_real() -> None:
    assert WORKFLOWS.is_dir(), f"workflow dir not found at {WORKFLOWS}"
    assert RUNBOOK.is_file(), f"runbook not found at {RUNBOOK}"
    assert CHECKLIST.is_file(), f"release checklist not found at {CHECKLIST}"
    assert RC1_PROCEDURE.is_file(), f"rc1 procedure not found at {RC1_PROCEDURE}"
    assert len(_workflow_files()) >= 10, "workflow discovery collapsed"
    assert len(_required()) >= 16, "runbook §1.1 shrank unexpectedly"
    assert _optional() and _excluded()


# --------------------------------------------------------------------------
# 1. the runbook's names must be real job names
# --------------------------------------------------------------------------
def test_every_runbook_check_names_a_real_job() -> None:
    """A required check that matches no job pins every PR at "Expected" forever."""
    missing = []
    for workflow, check in _required() + _optional() + _excluded():
        file = f"{workflow}.yml"
        if not (WORKFLOWS / file).is_file():
            missing.append(f"{workflow}: no such workflow file")
            continue
        if check not in _check_names(file):
            missing.append(f"{file}: no job named {check!r}")
    assert not missing, (
        "docs/runbooks/ci-branch-protection.md §1 names checks that do not exist:\n  "
        + "\n  ".join(missing)
    )


def test_gh_api_payload_matches_the_required_table() -> None:
    """The payloads are copy-pasted into a live ruleset — they must not drift.

    Order matters here on purpose: a diff of two ordered lists points straight at
    the row that moved, and there is no reason for these to be sorted differently.
    """
    expected = [check for _, check in _required()]
    assert _gh_api_contexts(RUNBOOK) == expected, (
        "runbook §4's `gh api` payload and §1.1's table disagree. They are the same "
        "list; §4 is what an admin actually runs."
    )
    assert _gh_api_contexts(CHECKLIST) == expected, (
        "docs/RELEASE_CHECKLIST.md §6.2's `gh api` payload has drifted from the "
        "runbook's §1.1 table. §6.2 is the command the owner runs on ship day."
    )
    assert _gh_api_contexts(RC1_PROCEDURE) == expected, (
        "docs/runbooks/rc1-release-procedure.md step 1's `gh api` payload has "
        "drifted from the runbook's §1.1 table. That page is what the owner reads "
        "when authorizing the ruleset change."
    )


# --------------------------------------------------------------------------
# 2. every blocking job must be accounted for by the runbook
# --------------------------------------------------------------------------
def test_no_blocking_job_is_unaccounted_for() -> None:
    """A job that says "blocking" must be required, optional-with-reason, or
    explicitly excluded-with-reason. Silence is the failure mode."""
    accounted = {(w, c) for w, c in _required() + _optional() + _excluded()}
    orphans = []
    for file in _workflow_files():
        if file == RELEASE_GATE:
            continue
        for check in _check_names(file):
            if "blocking" in check.lower() and (file[:-4], check) not in accounted:
                orphans.append(f"{file} · {check}")
    assert not orphans, (
        "blocking job(s) in no runbook table — they run, go green and enforce "
        "nothing. Add to §1.1 (required), §1.2 (optional) or §1.3 (excluded, with "
        "the reason):\n  " + "\n  ".join(sorted(orphans))
    )


# --------------------------------------------------------------------------
# 3. path filters must not be able to skip a required check
# --------------------------------------------------------------------------
def _gate_workflow_files() -> set[str]:
    return {f"{w}.yml" for w, _ in _required() + _optional()}


def test_required_workflows_do_not_filter_pull_request() -> None:
    """§2: `paths:` belongs on `push` only. A path-skipped required workflow
    leaves the PR stuck at "Expected"."""
    offenders = []
    for file in sorted(_gate_workflow_files()):
        pr = _triggers(_load(file)).get("pull_request")
        if isinstance(pr, dict) and ("paths" in pr or "paths-ignore" in pr):
            offenders.append(file)
    assert not offenders, (
        "required workflow(s) filter `pull_request` by path: " + ", ".join(offenders)
    )


def test_release_gate_covers_every_gate_workflow() -> None:
    """The tag path must run ALL gates — including the path-filtered ones.

    This is the assertion that keeps the per-workflow `push` `paths:` filters
    honest: they are allowed to skip work on a branch precisely because a tag
    reaches every gate through `workflow_call`, which takes no path filter.
    """
    called = {Path(u).name for u in _gate_calls().values()}
    expected = _gate_workflow_files()
    assert called == expected, (
        "release-gate.yml and runbook §1.1+§1.2 disagree about the gate set.\n"
        f"  missing from release-gate.yml: {sorted(expected - called) or 'none'}\n"
        f"  called but not in the runbook: {sorted(called - expected) or 'none'}"
    )


def test_gate_calls_are_local_and_callable() -> None:
    """Every gate call is an in-repo path (no third-party reusable workflow), and
    the callee really declares `workflow_call` — otherwise the tag run errors and
    the gate never proves anything."""
    problems = []
    for job_id, uses in _gate_calls().items():
        if not uses.startswith("./.github/workflows/"):
            problems.append(f"{job_id}: `uses: {uses}` is not a local workflow")
            continue
        file = Path(uses).name
        if not (WORKFLOWS / file).is_file():
            problems.append(f"{job_id}: {file} does not exist")
            continue
        triggers = _triggers(_load(file))
        if "workflow_call" not in triggers:
            problems.append(f"{file}: no `workflow_call:` trigger")
        for keep in ("push", "pull_request"):
            if keep not in triggers:
                problems.append(f"{file}: lost its `{keep}:` trigger")
    assert not problems, "release-gate.yml call problems:\n  " + "\n  ".join(problems)


def test_workflow_call_trigger_carries_no_path_filter() -> None:
    """Belt and braces: a `paths:` under `workflow_call` would re-open the hole
    the tag gate closes (GitHub ignores it today; the intent must stay visible)."""
    for file in sorted(_gate_workflow_files()):
        call = _triggers(_load(file)).get("workflow_call")
        assert not isinstance(call, dict) or not (
            set(call) & {"paths", "paths-ignore"}
        ), f"{file}: `workflow_call` must not carry a path filter"


# --------------------------------------------------------------------------
# 4. nothing publishes without the gate
# --------------------------------------------------------------------------
def test_publishing_workflows_are_fail_closed_on_the_gate() -> None:
    """Exactly one job calls the gate, and every other job `needs:` it.

    `needs:` is what makes this fail closed: Actions skips a dependent job when
    its dependency fails, is cancelled, or is itself skipped.
    """
    for file in PUBLISHING_WORKFLOWS:
        jobs = _jobs(_load(file))
        gate_ids = [
            job_id
            for job_id, job in jobs.items()
            if str(job.get("uses", "")).endswith(f"/{RELEASE_GATE}")
        ]
        assert len(gate_ids) == 1, (
            f"{file}: expected exactly one job calling {RELEASE_GATE}, found {gate_ids}"
        )
        gate = gate_ids[0]
        for job_id, job in jobs.items():
            if job_id == gate:
                continue
            needs = job.get("needs")
            needs = [needs] if isinstance(needs, str) else list(needs or [])
            assert gate in needs, (
                f"{file}: job `{job_id}` does not `needs: {gate}` — it can publish "
                "an artifact that passed no test gate"
            )


def test_publishing_workflows_still_fire_on_a_version_tag() -> None:
    """The gate is worthless if the workflow stopped triggering on the tag."""
    for file in PUBLISHING_WORKFLOWS:
        push = _triggers(_load(file)).get("push") or {}
        assert "v*.*.*" in (push.get("tags") or []), (
            f"{file}: no `push: tags: ['v*.*.*']` trigger"
        )
