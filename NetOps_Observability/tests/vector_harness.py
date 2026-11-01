# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The one way the pytest suites run `vector test` (tracker 350).

WHY THIS EXISTS: an upstream race, proven, not assumed.

`vector test` on the pinned timberio/vector:0.40.0 occasionally reports one case
as

    checks for transforms ["<t>"] failed: no events received. Topology may be
    disconnected or transform is missing inputs.

for a case whose VRL is deterministic and whose neighbours, which have exactly
the same shape, pass. Seen on CI three times (PR #24 run 39041076150, fixture 14
of syslog-admission.yaml; train PR #38 run 39049371440 and PR #88 run
40142538158, "flows: protocol PIM is 103" of the router parse-trace suite).

The cause is in Vector's in-memory buffer, not in our config or VRL. In 0.40,
`LimitedReceiver::next` (lib/vector-buffers/src/topology/channel/
limited_queue.rs) does

    if let Some(item) = self.inner.data.pop() { return Some(item) }   // (1)
    if self.inner.limiter.is_closed() { return None }                 // (2)

with nothing tying (1) to (2). If, between them, the LAST sender pushes its
item and drops (the drop closes the semaphore), the receiver sees "closed" and
ends the stream with the item still in the queue. A unit-test case is exactly
that shape: the injected batch is ONE event array, and every sender drops right
after the one push (the test source finishes, `UnitTest::run` calls
`topology.stop()`, the transform's input ends and its fanout drops). Lose that
one array and the test sink receives nothing, which is the message above, word
for word. The window is a few instructions wide, so it needs a loaded runner and
a sink task being polled on another worker thread at that instant; that is why
it is rare, why it moves between cases, and why a rerun passes.

Upstream fixed it in vectordotdev/vector#24695 ("fix(buffers): Fix race
draining a memory buffer", merged 2026-02-20, first released in v0.54.0): the
receiver now returns None only when the channel is closed AND every permit is
back. The changelog fragment calls it "a hard-to-trigger race between closing a
memory buffer and outstanding sends that could rarely cause a lost event array
at shutdown." Nothing between 0.40 and 0.53 has the fix.

Reproduced locally (2026-10-25) with NO project code at all: a 400-case suite
whose only transform is `.x = 1`, run with `--cpus=1 -e VECTOR_THREADS=16` (many
tokio workers on one CPU, so a worker is preempted mid-poll): 0.40.0 lost 2 of
19 200 cases and 0.53.0 lost 1 of 12 800, each with exactly the message above;
0.54.0 lost 0 of 12 800. Unamplified runs (and any `--cpus` below 1, which
leaves a single worker thread and so no race) lost nothing, which is why a
plain local rerun always passes.

WHAT THIS MODULE DOES ABOUT IT, and the bounds on it:

  * A run is retried AT MOST ONCE, and only when EVERY failed case failed with
    that exact message and nothing else (no failed condition, no "expected no
    outputs", no build error), and at most MAX_RACE_CASES cases failed. A real
    VRL regression fails a condition and is never retried. A genuinely
    disconnected topology fails the same way on every run, so the retry fails
    too and the test reports both attempts.
  * The retry is never silent: it raises a `VectorHarnessRaceRetry` warning,
    which pytest prints in its warnings summary on a green run, and, on GitHub
    Actions, appends a line to the job's step summary.
  * `tests/test_vector_harness.py` fails the moment the shipped Vector image is
    v0.54.0 or later, so the retry is deleted, not carried, once the runtime
    has the upstream fix.

The real fix is upgrading the shipped Vector (upstream: the race "could rarely
cause a lost event array at shutdown" of a real memory buffer too); that is a
runtime upgrade, tracker 350, not a test change.

On "why PIM twice": nothing case-specific was found. The PIM case's input has
the same fields, timestamp and sampler as its OSPFIGP/VRRP neighbours, every
case runs in its own topology (the shared component names are by Vector's
design, one UUID per run), and the synthetic repro loses arbitrary cases (133,
261, ...). Two hits on one of the ~74 cases these suites run is a coincidence
of a rare, position-independent race, not a second cause.
"""

from __future__ import annotations

import os
import re
import subprocess
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

# The exact sentence UnitTestSink emits (src/config/unit_test/
# unit_test_components.rs, v0.40.0) when its input stream ended empty.
RACE_SIGNATURE = re.compile(
    r'^checks for transforms \[.*\] failed: no events received\. '
    r'Topology may be disconnected or transform is missing inputs\.$')

# The upstream fix (vectordotdev/vector#24695) shipped in this release.
UPSTREAM_FIX_VERSION = (0, 54, 0)
UPSTREAM_FIX = "vectordotdev/vector#24695 (fixed in v0.54.0)"

# The race is rare and independent per case. Two cases losing it in one run is
# already unlikely; more than that is a wiring problem, not this race, and must
# fail at once rather than burn a second run.
MAX_RACE_CASES = 2

_CASE_RESULT = re.compile(r"^test (?P<name>.+) \.\.\. (?P<verdict>passed|failed)$")
_LOG_LINE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s")


class VectorHarnessRaceRetry(UserWarning):
    """A `vector test` run was retried because of the upstream buffer race."""


@dataclass(frozen=True)
class Diagnosis:
    """What one `vector test` output says about its failures."""

    failed: tuple[str, ...]
    # failed case -> its failure body (stripped lines, Vector log lines removed)
    bodies: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def race_only(self) -> bool:
        """True when every failed case failed ONLY with the race signature."""
        if not self.failed or len(self.failed) > MAX_RACE_CASES:
            return False
        for name in self.failed:
            body = self.bodies.get(name, ())
            if len(body) != 1 or not RACE_SIGNATURE.match(body[0]):
                return False
        return True


def diagnose(output: str) -> Diagnosis:
    """Parse `vector test` output into failed cases and their failure bodies.

    The format (src/unit_test.rs, v0.40.0): one `test <name> ... passed|failed`
    line per case, then `failures:` and, for every failed case, a `test <name>:`
    header followed by its error lines. Vector's own WARN/INFO log lines can be
    interleaved anywhere and are not part of a body."""
    lines = [ln.strip() for ln in output.splitlines()]
    failed = tuple(m.group("name") for m in map(_CASE_RESULT.match, lines)
                   if m and m.group("verdict") == "failed")
    bodies: dict[str, list[str]] = {}
    try:
        start = lines.index("failures:") + 1
    except ValueError:
        return Diagnosis(failed=failed, bodies={})
    headers = {f"test {name}:": name for name in failed}
    current: str | None = None
    for ln in lines[start:]:
        if ln in headers:
            current = headers[ln]
            bodies.setdefault(current, [])
            continue
        if current is None or not ln or _LOG_LINE.match(ln):
            continue
        bodies[current].append(ln)
    return Diagnosis(failed=failed,
                     bodies={k: tuple(v) for k, v in bodies.items()})


Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class VectorTestRun:
    """The result a test asserts on, plus what happened on the way there."""

    final: subprocess.CompletedProcess
    retried: bool
    first_attempt_output: str = ""
    race_cases: tuple[str, ...] = ()

    @property
    def output(self) -> str:
        return (self.final.stdout or "") + (self.final.stderr or "")

    def report(self) -> str:
        """The full story for an assertion message: both attempts if retried."""
        if not self.retried:
            return self.output
        return ("ATTEMPT 1 (lost to the upstream buffer race, "
                f"{UPSTREAM_FIX}; cases: {', '.join(self.race_cases)}):\n"
                f"{self.first_attempt_output}\n"
                "ATTEMPT 2 (the verdict):\n" + self.output)


def _record_retry(label: str, cases: Sequence[str]) -> str:
    message = (
        f"vector test [{label}]: attempt 1 lost {len(cases)} case(s) "
        f"({'; '.join(cases)}) with 'no events received' and nothing else: the "
        "Vector 0.40 LimitedReceiver close race "
        f"({UPSTREAM_FIX}). Re-ran ONCE; attempt 2 is the verdict. "
        "Tracker 350.")
    warnings.warn(message, VectorHarnessRaceRetry, stacklevel=3)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(f"- :warning: {message}\n")
        except OSError as exc:  # the warning above still carries the record
            warnings.warn(f"could not append to GITHUB_STEP_SUMMARY: {exc}",
                          VectorHarnessRaceRetry, stacklevel=3)
    return message


def run_vector_test(cmd: Sequence[str], *, label: str, timeout: float,
                    runner: Runner = subprocess.run) -> VectorTestRun:
    """Run a `vector test` command, retrying once ONLY for the upstream race.

    `cmd` is the full argv (docker run ... vector test ...). The returned run's
    `final` is what the caller asserts on; a retried run's first attempt is kept
    for the failure message."""
    first = runner(list(cmd), capture_output=True, text=True,
                   timeout=timeout, check=False)
    first_out = (first.stdout or "") + (first.stderr or "")
    if first.returncode == 0:
        return VectorTestRun(final=first, retried=False)
    diag = diagnose(first_out)
    if not diag.race_only:
        return VectorTestRun(final=first, retried=False)
    _record_retry(label, diag.failed)
    second = runner(list(cmd), capture_output=True, text=True,
                    timeout=timeout, check=False)
    return VectorTestRun(final=second, retried=True,
                         first_attempt_output=first_out,
                         race_cases=diag.failed)


def image_version(image: str) -> tuple[int, int, int] | None:
    """`timberio/vector:0.40.0-alpine@sha256:...` -> (0, 40, 0)."""
    m = re.search(r"timberio/vector:(\d+)\.(\d+)\.(\d+)", image)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None
