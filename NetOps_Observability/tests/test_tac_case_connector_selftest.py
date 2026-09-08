# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The TAC case-connector SELF-TEST, run from the platform test suite.

Owner's proof standard (2026-09-07): "I don't have vendor smart contracts to
login. If there is any way to ensure API calls work that should be good for
now."

The Go tests in ``internal/ticketing`` drive the REAL connector code end to end
against contract fakes built from the vendors' documented request and response
shapes — authenticate, create, attach, read the status back — plus the dry run
that proves a customer's setup without creating anything.  This file is the
harness that runs them from ``tests/``, so the proof is part of the platform's
own suite rather than something a person has to remember to invoke.

WHY A PYTHON WRAPPER AT ALL.  ``tests/`` is what the release gate runs, and it
runs a great deal that is not Go: compose overlays, alert rules, install
scripts.  A vendor-integration claim that only ever ran under ``go test`` would
be one command away from being silently dropped from the gate.  This is that
command, with the selection pinned and a floor on how many cases must run — so a
rename that quietly stops matching fails here instead of passing vacuously.

WHAT IT DOES NOT DO.  It contacts no vendor.  Every endpoint is an
``httptest.Server`` on localhost; the file that owns those fakes states the same
limitation and cites the documentation each shape came from.
"""

import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "src", "backend")

# The selection.  `EndToEnd` is the whole-flow suite; `DryRun` is the
# prove-your-setup suite.  Both are named rather than globbed so a new test file
# has to be added here deliberately.
SELFTEST_RUN = "TestEndToEnd|TestDryRun"

# The floor.  A `-run` pattern that stops matching returns exit 0 with no tests,
# which is exactly the silent-pass this floor exists to refuse.  It is the count
# at the time of writing minus a small margin, so adding tests never breaks it
# and deleting most of them does.
MIN_CASES = 10

needs_go = pytest.mark.skipif(
    shutil.which("go") is None, reason="the Go toolchain is unavailable"
)


def _run_selftest(extra_env=None):
    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    # The fakes are httptest servers on 127.0.0.1, and the connectors' SSRF
    # guard refuses private addresses by default — correctly, in production.
    env["SSRF_ALLOW_PRIVATE"] = "true"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["go", "test", "./internal/ticketing/", "-count=1", "-v", "-run", SELFTEST_RUN],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
        check=False,
    )


@needs_go
def test_case_connector_selftest_passes_against_the_contract_fakes():
    res = _run_selftest()
    assert res.returncode == 0, (
        "the TAC case-connector self-test failed. This is the only proof the "
        "platform has that the requests Correlix builds are the requests the "
        "vendors document.\n\n" + res.stdout[-8000:] + "\n" + res.stderr[-4000:]
    )


@needs_go
def test_case_connector_selftest_actually_runs_its_cases():
    """A green run that ran nothing is not a green run."""
    res = _run_selftest()
    passed = re.findall(r"^--- PASS: (Test\w+)", res.stdout, re.M)
    skipped = re.findall(r"^--- SKIP: (Test\w+)", res.stdout, re.M)
    assert len(passed) >= MIN_CASES, (
        f"the self-test selection {SELFTEST_RUN!r} matched only {len(passed)} "
        f"passing case(s) (floor {MIN_CASES}); it has stopped covering the "
        f"connectors.\npassed={passed}\nskipped={skipped}"
    )
    # Every vendor path the product claims must be among them, by name. A vendor
    # whose case disappears must fail here rather than quietly stop being proven.
    joined = " ".join(passed)
    for vendor in ("Cisco", "Juniper", "ServiceNow"):
        assert vendor in joined, (
            f"no self-test case covers {vendor} any more: {passed}"
        )


@needs_go
def test_the_selftest_creates_nothing_at_a_vendor():
    """The dry run's central claim, asserted from outside the Go suite too.

    The Go cases assert it against their own fakes (a create counter that must
    stay at zero).  This asserts the weaker but independent property that the
    dry-run cases exist and pass at all — so the claim on the confirmation
    screen is never the only place the behaviour is described.
    """
    res = _run_selftest()
    passed = re.findall(r"^--- PASS: (Test\w+)", res.stdout, re.M)
    creates_nothing = [n for n in passed if "CreatesNothing" in n]
    assert creates_nothing, (
        "the dry run's 'creates nothing' case is not running. A dry run that "
        "opened a case would be the worst bug this feature could have, so its "
        "test may never silently stop running.\npassed=" + str(passed)
    )
