# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: `backend-ci.yml`'s scanners cannot pass without scanning.

WHY THIS EXISTS. `gosec -quiet` EXITS 0 after failing to load every package.
Proved on 2026-09-13 while building `scripts/release-gate.py`: on a host whose
toolchain could not load the module, `gosec -quiet ./tlsconfig/...` returned 0 in
0.2 s having analysed **0 files** — and with `-quiet` there was not even a summary
in the log to notice it by. The required check `staticcheck + gosec (crypto/trust
packages, blocking)` would have been green over the crypto and trust packages
while reading none of them.

Exit 0 is not evidence of a scan. The step now reads gosec's own `Files:` summary
and fails on zero, and this file holds that guard in place — the hole is invisible
in a green run, which is exactly the kind of regression a test has to own.

The job NAME is asserted byte-for-byte too: it is a required status check on
`main` (docs/runbooks/ci-branch-protection.md §1.1), so renaming it silently
un-requires it and every PR sits at "Expected — Waiting for status to be
reported".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "backend-ci.yml"
JOB_ID = "security-lint"
JOB_NAME = "staticcheck + gosec (crypto/trust packages, blocking)"


@pytest.fixture(scope="module")
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def gosec_step(doc: dict) -> dict:
    job = doc["jobs"][JOB_ID]
    steps = [s for s in job["steps"] if "gosec" in str(s.get("name", ""))
             and "staticcheck" not in str(s.get("name", ""))]
    assert len(steps) == 1, f"expected exactly one gosec step, found {len(steps)}"
    return steps[0]


def test_the_required_job_name_is_unchanged(doc: dict):
    assert doc["jobs"][JOB_ID]["name"] == JOB_NAME


def test_gosec_is_not_run_quiet(gosec_step: dict):
    """`-quiet` suppresses the summary the zero-files guard reads AND is the flag
    under which gosec returns 0 having loaded nothing."""
    body = gosec_step["run"]
    assert "gosec" in body
    assert "-quiet" not in body, (
        "-quiet hides the 'Files:' summary; a zero-file run becomes invisible"
    )


def test_the_step_fails_when_gosec_analysed_zero_files(gosec_step: dict):
    body = gosec_step["run"]
    assert "set -euo pipefail" in body, "scripts/CLAUDE.md §16.3"
    # It must READ the count…
    assert re.search(r"Files\[\[:space:\]\]\*:", body) or "Files" in body
    # …compare it against zero…
    assert re.search(r'"\$files"\s+-eq\s+0', body), (
        "no zero-file comparison — the guard is the comparison"
    )
    # …and FAIL, not warn.
    fails = re.findall(r"exit 1", body)
    assert len(fails) >= 2, (
        "both the no-summary and the zero-files paths must exit non-zero"
    )
    assert "|| true" not in body, "scripts/CLAUDE.md §16.1"


def test_a_missing_summary_is_also_a_failure(gosec_step: dict):
    """No summary means the output was not gosec's, or gosec did not get that far.
    Either way it is not a scan."""
    body = gosec_step["run"]
    assert re.search(r'if \[ -z "\$files" \]', body)


def test_the_pipe_does_not_swallow_gosecs_own_exit_code(gosec_step: dict):
    """`gosec … | tee log` reports tee's status without pipefail, which would turn
    every finding into a pass — the defect the tee was introduced to avoid."""
    body = gosec_step["run"]
    assert "| tee" in body
    assert "pipefail" in body


def test_the_guard_matches_the_one_in_the_release_gate(gosec_step: dict):
    """The gate script and the CI job assert the same property; a reader who finds
    one should find the other."""
    body = gosec_step["run"]
    assert "release-gate.py" in WORKFLOW.read_text(encoding="utf-8"), (
        "the step's comment should point at the gate that shares this guard"
    )
    assert "analysed 0 files" in body


def test_staticcheck_still_runs_over_the_three_trust_packages(doc: dict):
    """The zero-files work must not have narrowed the scope it guards."""
    body = "\n".join(str(s.get("run", "")) for s in doc["jobs"][JOB_ID]["steps"])
    for pkg in ("./tlsconfig/...", "./internalca/...", "./sealing/..."):
        assert body.count(pkg) >= 2, f"{pkg} is no longer covered by both scanners"
