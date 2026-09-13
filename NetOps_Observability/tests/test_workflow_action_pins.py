# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: every third-party GitHub Action is pinned to an immutable commit SHA.

WHY THIS EXISTS. RC1 governance directive Decision 10
(`docs/release/RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`): "Pin third-party
actions to immutable SHAs; no floating `@main` on release-critical workflows."

A tag is not a pin. `actions/checkout@v4` resolves to whatever commit the `v4`
branch-style tag points at *at run time*, and the publisher can move it. The
action runs with the workflow's token and sees the workflow's secrets, so a moved
tag is remote code execution inside the release pipeline — and it leaves no trace
in this repository's history, because nothing here changed.

Most workflows were already pinned. Two were not, and both are release-relevant:
`fresh-install-integrity.yml` (a Tier-B release gate: the ruff gate, the install
integrity layers, the two-phase TLS boot, the Helm chart job) and
`scale-miniladder-nightly.yml`. Nothing mechanical stopped the next unpinned
`uses:` from landing, so this file does.

Also asserted, and the reason this is not just a regex in CI:

  * **One SHA per action.** Two pins of `actions/checkout` at different commits
    means Renovate tracks two versions and a bump lands in half the pipeline.
  * **The `# vX.Y.Z` comment survives.** A bare 40-hex SHA is unreviewable and
    un-bumpable by a human; the comment is what makes `v4.3.1` legible and is
    what Renovate rewrites alongside the SHA.

Local reusable workflows (`uses: ./.github/workflows/...`) are exempt: they are
this repository's own committed code, already fixed by the checked-out SHA.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# `uses: owner/repo@ref` or `uses: owner/repo/sub@ref`, with the trailing
# `# vX.Y.Z` comment if present. Text-level, because yaml drops comments.
USES_LINE_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<spec>[^\s#]+)\s*(?:#\s*(?P<comment>.*?))?\s*$"
)
VERSION_COMMENT_RE = re.compile(r"v\d+(?:\.\d+)*")


def workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def is_local(spec: str) -> bool:
    return spec.startswith(("./", "docker://"))


def uses_from_yaml(path: Path) -> list[str]:
    """Every `uses:` value a runner would act on: step uses and reusable-workflow
    calls. Read through the YAML parser so a `uses:` this file's regex would miss
    — a folded block, an unusual indentation — is still caught."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "uses" and isinstance(value, str):
                    found.append(value.strip())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return found


def uses_lines(path: Path) -> list[tuple[int, str, str | None]]:
    """(line number, spec, trailing comment) for every textual `uses:` line."""
    out: list[tuple[int, str, str | None]] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = USES_LINE_RE.match(raw)
        if m:
            out.append((n, m.group("spec"), m.group("comment")))
    return out


# ── sanity: this suite must never go vacuously empty ─────────────────────────
def test_the_workflow_directory_is_where_this_test_thinks_it_is():
    assert WORKFLOWS.is_dir(), f"workflow dir not found at {WORKFLOWS}"
    files = workflow_files()
    assert len(files) >= 10, (
        f"only {len(files)} workflow(s) found — this suite is probably pointed "
        f"at the wrong directory and would pass by finding nothing"
    )


def test_both_parsers_see_the_same_third_party_actions():
    """If the YAML walk finds a `uses:` the line scan does not, the comment
    assertions below would skip it silently."""
    for path in workflow_files():
        from_yaml = {u for u in uses_from_yaml(path) if not is_local(u)}
        from_text = {spec for _n, spec, _c in uses_lines(path) if not is_local(spec)}
        assert from_yaml == from_text, (
            f"{path.name}: the YAML parser and the line scanner disagree about "
            f"its `uses:` values.\n  yaml only: {sorted(from_yaml - from_text)}\n"
            f"  text only: {sorted(from_text - from_yaml)}"
        )


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_every_third_party_action_is_pinned_to_a_commit_sha(path):
    unpinned: list[str] = []
    for n, spec, _comment in uses_lines(path):
        if is_local(spec):
            continue
        if "@" not in spec:
            unpinned.append(f"line {n}: {spec} (no ref at all)")
            continue
        action, _, ref = spec.rpartition("@")
        if not SHA_RE.match(ref):
            unpinned.append(f"line {n}: {action}@{ref}")
    assert not unpinned, (
        f"{path.name} uses third-party action(s) pinned to a MUTABLE ref — the "
        f"publisher can move a tag or a branch under us, and the action runs "
        f"with this workflow's token and secrets. Pin to the full 40-character "
        f"commit SHA and keep a `# vX.Y.Z` comment:\n  "
        + "\n  ".join(unpinned)
    )


@pytest.mark.parametrize("path", workflow_files(), ids=lambda p: p.name)
def test_every_pin_carries_a_human_readable_version_comment(path):
    missing: list[str] = []
    for n, spec, comment in uses_lines(path):
        if is_local(spec) or "@" not in spec:
            continue
        action, _, ref = spec.rpartition("@")
        if not SHA_RE.match(ref):
            continue  # the pin test above owns that failure
        if not comment or not VERSION_COMMENT_RE.search(comment):
            missing.append(f"line {n}: {action}@{ref[:12]}… ({comment or 'no comment'})")
    assert not missing, (
        f"{path.name}: a bare SHA is unreviewable and nobody can tell whether it "
        f"is current. Append the release it pins, e.g. `# v4.3.1`:\n  "
        + "\n  ".join(missing)
    )


def test_each_action_is_pinned_to_exactly_one_sha_across_all_workflows():
    """One version per action, so Renovate opens one bump PR that updates the
    whole pipeline instead of leaving half of it behind."""
    pins: dict[str, dict[str, list[str]]] = {}
    for path in workflow_files():
        for n, spec, _comment in uses_lines(path):
            if is_local(spec) or "@" not in spec:
                continue
            action, _, ref = spec.rpartition("@")
            if not SHA_RE.match(ref):
                continue
            pins.setdefault(action, {}).setdefault(ref, []).append(f"{path.name}:{n}")

    assert pins, "no pinned third-party actions found at all — suite is vacuous"
    split = {a: v for a, v in pins.items() if len(v) > 1}
    assert not split, (
        "these actions are pinned to more than one SHA; reuse a single SHA per "
        "action so one Renovate bump moves the whole pipeline: "
        + "; ".join(
            f"{action} -> "
            + ", ".join(f"{ref[:12]}… at {sorted(where)}" for ref, where in refs.items())
            for action, refs in sorted(split.items())
        )
    )


def test_the_two_workflows_fixed_by_decision_10_stay_pinned():
    """A named regression guard. These two carried `actions/checkout@v4` (×4 and
    ×1) and `actions/upload-artifact@v4` until 2026-09-13; both are
    release-relevant, so name them rather than rely on the sweep above."""
    for name in ("fresh-install-integrity.yml", "scale-miniladder-nightly.yml"):
        path = WORKFLOWS / name
        assert path.is_file(), f"{name} has been renamed or removed; update this test"
        body = path.read_text(encoding="utf-8")
        assert "@v4" not in body, (
            f"{name} has regressed to a floating `@v4` tag"
        )
        specs = [spec for _n, spec, _c in uses_lines(path) if not is_local(spec)]
        assert specs, f"{name} calls no third-party action; is this still the right file?"
