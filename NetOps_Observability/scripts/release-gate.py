#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""release-gate.py — THE one fail-closed release gate (RC1 directive, Decision 8).

WHY THIS EXISTS
---------------
Every ingredient of a releasable Correlix build already had a gate somewhere: a
workflow job, a pytest file, a `--release` flag on a licensing script, a signing
step inside `release-bundle.yml`. What did not exist was a single place that says
whether ALL of them hold for the commit in front of you. "Releasable" was
therefore something a human assembled from fifteen separate answers, which is the
same as saying nobody held it — and the RC1 governance directive
(`docs/release/RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`, Decision 8) asks for one
entry point instead:

    Fail-closed release gate. One entry point (e.g. `make release-gate`)
    aggregating: tests, build, offline build, dependency lock, copyleft gate,
    SPDX gate, enterprise licence validity, generated-code cleanliness,
    security scans, SBOM, checksums, signature, signature verification,
    release metadata, source/tag consistency. Any failure fails the release.

This is that entry point. `make release-check` runs it.

NAME COLLISION, ON PURPOSE AVOIDED
----------------------------------
`make release-gate` / `make release-gate-live` already exist and mean something
ELSE: the #101 storm-SLO lane contract (write budget, blast radius, RCA integrity
under damping). They are not repurposed or renamed — a tracker-referenced target
that quietly changes meaning is worse than a second name. This one is
`make release-check`.

RUN-ALL, REPORT-ALL, THEN FAIL
------------------------------
It does not stop at the first failure. A release owner needs the whole blocker
matrix from one run, not a bisect through fifteen runs, so every check executes
and the verdict comes at the end. Fail-closed is preserved by the exit code, not
by stopping early.

THE FOUR RESULTS
----------------
    PASS           proven here, now, on this tree.
    FAIL           an engineering failure. Somebody on the engineering side can
                   fix it. A MISSING TOOL IS A FAIL, never a skip — "the scanner
                   was not installed" has to read the same as "the scanner found
                   something", or the gate degrades silently (scripts/CLAUDE.md
                   §16.1).
    BLOCKED-HUMAN  the check fails only because a human-controlled input does not
                   exist yet: counsel's licence text, the CLA mechanism, the
                   distribution signing key, custody, the owner's tag signature.
                   Engineering cannot clear these and MUST NOT pretend to. They
                   still fail the release (exit non-zero) — they are labelled so
                   the report separates a bug from a blocker.
    CI-ONLY        cannot be run on a developer host at all (it needs a clean
                   runner, a network vulnerability feed, or built images). The row
                   names the workflow and job that DOES run it on the tag. It is
                   NEVER counted as a pass: an unverified check is not a green one.

EXIT CODES
----------
    0   every check PASSed. The only exit code that means "releasable".
    1   at least one FAIL or BLOCKED-HUMAN.
    2   the gate itself could not run (bad usage, unreadable repository).
    3   no FAIL and no BLOCKED-HUMAN, but CI-ONLY rows are still unverified here,
        or the run was filtered with --only. Not a release verdict.

Standard library only. Every subprocess call is bounded by an explicit timeout
(CLAUDE.md §9), and no failure is swallowed: a non-zero exit, a timeout and a
missing executable all surface as a row you can read.

Usage
    python3 scripts/release-gate.py                  # the table
    python3 scripts/release-gate.py --json           # the same, machine-readable
    python3 scripts/release-gate.py --bundle dist/correlix-…  # grade an artifact
    python3 scripts/release-gate.py --run-tests      # also run the long suites
    python3 scripts/release-gate.py --only spdx      # debugging; never a verdict
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)          # NetOps_Observability/
REPO = os.path.dirname(PROJ)          # the git root (one level up)
BACKEND = os.path.join(PROJ, "src", "backend")
WORKFLOWS = os.path.join(REPO, ".github", "workflows")

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED-HUMAN"
CI_ONLY = "CI-ONLY"
STATUSES = (PASS, FAIL, BLOCKED, CI_ONLY)

# The fifteen items Decision 8 names, in its order and its words. The directive
# is the authority: tests/test_release_gate_entrypoint.py parses the sentence out
# of the doc and fails if this tuple drifts from it, so the aggregate cannot
# silently shrink to the checks that happen to be green.
DECISION8_ITEMS = (
    "tests",
    "build",
    "offline build",
    "dependency lock",
    "copyleft gate",
    "SPDX gate",
    "enterprise licence validity",
    "generated-code cleanliness",
    "security scans",
    "SBOM",
    "checksums",
    "signature",
    "signature verification",
    "release metadata",
    "source/tag consistency",
)

# Go checks set NO GOTOOLCHAIN. Normal toolchain selection is the intended path:
# `go` on PATH may be older than go.mod's `go` directive, and the `toolchain
# go1.26.8` line is what resolves the real compiler — from the module cache when it
# is already there. Pinning GOTOOLCHAIN=local would fail every Go row on a host
# whose PATH `go` is older, which reports that host's PATH rather than the
# release's buildability. (GOTOOLCHAIN=local belongs to the docker lint container,
# where the image's own toolchain is the thing under test.)
#
# The OFFLINE row keeps GOPROXY=off, and that is where the toolchain question gets
# its honest answer: with the proxy off an uncached `toolchain go1.x` cannot be
# fetched and the row FAILS — correctly, because a clean offline build implies a
# cached toolchain, and a host that must reach the network for its compiler cannot
# build air-gapped.
GO_OFFLINE_ENV = {"GOFLAGS": "-mod=vendor", "GOPROXY": "off"}


# ── process plumbing ─────────────────────────────────────────────────────────
@dataclass
class Proc:
    """The outcome of one bounded subprocess call. `missing` and `timed_out` are
    carried explicitly because both are real failures that a bare return code
    cannot express."""

    rc: int
    out: str = ""
    err: str = ""
    missing: bool = False
    timed_out: bool = False
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.missing and not self.timed_out

    @property
    def tail(self) -> str:
        """The best single evidence line this call produced.

        A verdict-bearing line from EITHER stream beats the last line of stderr —
        gosec, for one, ends stderr with a timestamped "Import directory: …"
        progress log while the actual error sits on stdout, and a row whose
        evidence is a path tells the reader nothing.
        """
        return (verdict_line(self.err) or verdict_line(self.out)
                or one_line(self.err) or one_line(self.out))


def run_process(
    argv: list[str],
    cwd: str,
    timeout: float,
    env_overrides: dict[str, str] | None = None,
) -> Proc:
    """Run `argv`, bounded by `timeout` (CLAUDE.md §9 — all IO has a timeout).

    The single funnel every command-shaped check goes through, which is also what
    makes the gate testable: tests/test_release_gate_entrypoint.py replaces this
    function with a stub that passes, fails, or is missing, and every mapped check
    is exercised through it.
    """
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    started = time.monotonic()
    try:
        done = subprocess.run(
            argv,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        return Proc(rc=127, err=f"{argv[0]}: not found ({exc.strerror})",
                    missing=True, seconds=time.monotonic() - started)
    except PermissionError as exc:
        return Proc(rc=126, err=f"{argv[0]}: not executable ({exc.strerror})",
                    missing=True, seconds=time.monotonic() - started)
    except OSError as exc:  # a broken interpreter, ENOMEM, …: never swallowed
        return Proc(rc=125, err=f"{argv[0]}: {exc}", missing=True,
                    seconds=time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        partial = one_line(_text(exc.stderr)) or one_line(_text(exc.stdout))
        return Proc(rc=124, err=f"timed out after {timeout:g}s: {partial}".strip(),
                    timed_out=True, seconds=time.monotonic() - started)
    return Proc(rc=done.returncode, out=done.stdout, err=done.stderr,
                seconds=time.monotonic() - started)


def _text(raw: object) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw if isinstance(raw, str) else ""


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# The vocabulary a gate tool uses when it is telling you the answer, as opposed to
# telling you what it is doing. `err:` earns its place: Go tooling reports the real
# cause as `err: exit status 1: stderr: …` on stdout while stderr ends with a
# timestamped progress line.
VERDICT_WORD = re.compile(
    r"(\b(FAIL|FAILED|BLOCKED|blocked|refus|error|ERROR|Error|not found|cannot|"
    r"PASS|OK|current|violation)|err:)"
)


def _clean(line: str, limit: int) -> str:
    """One report-safe line: no ANSI, no control characters, bounded length.

    The table is a report, not a log — the command printed beside each row
    reproduces the full output.
    """
    out = CTRL.sub(" ", line).strip()
    return out if len(out) <= limit else out[: limit - 1] + "…"


def _lines(text: str) -> list[str]:
    flat = ANSI.sub("", _text(text)).replace("\r", "\n")
    return [ln.strip() for ln in flat.split("\n") if ln.strip()]


def verdict_line(text: str, limit: int = 220) -> str:
    """The last line that names a verdict, or "" if none does.

    A scanner's verdict is what belongs in the table; its final progress line
    usually is not.
    """
    for candidate in reversed(_lines(text)):
        if VERDICT_WORD.search(candidate):
            return _clean(candidate, limit)
    return ""


def one_line(text: str, limit: int = 220) -> str:
    """Reduce a command's output to ONE evidence line: its verdict if it named
    one, otherwise its last line."""
    lines = _lines(text)
    if not lines:
        return ""
    return verdict_line(text, limit) or _clean(lines[-1], limit)


def resolve_tool(name: str) -> str | None:
    """Find a gate tool on PATH, then in the Go bin directories.

    The Go-installed gate tools (govulncheck, staticcheck, gosec, gitleaks) land
    in $GOBIN or $GOPATH/bin, which is NOT on a default or a cron PATH
    (scripts/CLAUDE.md §16.2) — a gate that reports "not installed" for a tool
    sitting in the default GOPATH would be answering the wrong question. Nothing
    is guessed beyond the documented Go locations; anything still unfound is a
    FAIL, never a skip.
    """
    found = shutil.which(name)
    if found:
        return found
    candidates = []
    if os.environ.get("GOBIN"):
        candidates.append(os.environ["GOBIN"])
    if os.environ.get("GOPATH"):
        candidates.extend(
            os.path.join(part, "bin") for part in os.environ["GOPATH"].split(os.pathsep) if part
        )
    candidates.append(os.path.join(os.path.expanduser("~"), "go", "bin"))
    for directory in candidates:
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


# ── results ──────────────────────────────────────────────────────────────────
@dataclass
class Result:
    check: str
    item: str
    title: str
    status: str
    evidence: str
    command: str
    workflow: str = ""
    job: str = ""
    human_action: str = ""
    seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "check": self.check,
            "item": self.item,
            "title": self.title,
            "status": self.status,
            "evidence": self.evidence,
            "command": self.command,
            "seconds": round(self.seconds, 3),
        }
        if self.workflow:
            out["workflow"] = self.workflow
            out["job"] = self.job
        if self.human_action:
            out["human_action"] = self.human_action
        return out


@dataclass
class Ctx:
    """Everything the checks share. Resolved once, before any check runs."""

    bundle: str | None
    bundle_why: str
    run_tests: bool
    signing_fpr: str | None = None
    signing_why: str = ""
    head: str = ""
    tag: str = ""


def display(argv: list[str], cwd: str, env_overrides: dict[str, str] | None = None) -> str:
    """The exact command, as a human would retype it from the repository root."""
    where = os.path.relpath(cwd, REPO)
    prefix = "" if where == "." else f"cd {where} && "
    envs = "".join(f"{k}={v} " for k, v in sorted((env_overrides or {}).items()))
    # sys.executable is an absolute path; the table is meant to be retyped, and
    # `python3` is what the runbooks and the Makefile say.
    shown = ["python3" if arg == PY else arg for arg in argv]
    return prefix + envs + " ".join(shown)


def cmd_result(
    check: str,
    item: str,
    title: str,
    argv: list[str],
    cwd: str,
    timeout: float,
    *,
    env_overrides: dict[str, str] | None = None,
    ok_evidence: str = "",
    human_action: str = "",
    human_when: str = "",
    tool: str = "",
) -> Result:
    """Run one command and grade it.

    `human_when` is a regex: when the command fails AND its output matches, the
    failure is a human blocker (counsel's text, a key nobody has minted) rather
    than an engineering defect, so it is labelled BLOCKED-HUMAN. It still fails
    the release.

    `tool` is the resolved path of a binary found OFF the default PATH (the Go gate
    tools live in GOBIN/GOPATH/bin). It goes in the evidence, because "staticcheck
    passed" and "THIS staticcheck passed" are different claims when two versions
    can be installed.
    """
    proc = run_process(argv, cwd, timeout, env_overrides)
    cmd = display(argv, cwd, env_overrides)
    note = f" · via {tool}" if tool else ""
    if proc.ok:
        return Result(check, item, title, PASS,
                      (ok_evidence or proc.tail or f"exit 0 in {proc.seconds:.1f}s")
                      + note,
                      cmd, seconds=proc.seconds)
    if proc.missing:
        return Result(check, item, title, FAIL,
                      f"{proc.err} — a gate tool that is not installed has proven "
                      f"nothing; install it or run this check in CI",
                      cmd, seconds=proc.seconds)
    blob = f"{proc.out}\n{proc.err}"
    if human_when and re.search(human_when, blob):
        return Result(check, item, title, BLOCKED, proc.tail + note, cmd,
                      human_action=human_action, seconds=proc.seconds)
    return Result(check, item, title, FAIL,
                  (proc.tail or f"exit {proc.rc}") + note, cmd,
                  human_action=human_action, seconds=proc.seconds)


def workflow_job_exists(workflow: str, job: str) -> bool:
    """Does `.github/workflows/<workflow>` really contain that job?

    A job's check-run name is its `name:` when it has one and its job KEY when it
    does not, so both shapes count. No YAML parser: the gate is stdlib-only, and a
    substring/anchored-key match is enough to catch the case that matters — a job
    that was renamed or deleted.
    """
    path = os.path.join(WORKFLOWS, workflow)
    try:
        with open(path, encoding="utf-8") as handle:
            body = handle.read()
    except OSError:
        return False
    if f"name: {job}" in body:
        return True
    return re.search(rf"(?m)^  {re.escape(job)}:\s*$", body) is not None


def ci_only(check: str, item: str, title: str, workflow: str, job: str, why: str) -> Result:
    """A check that genuinely cannot run here. Named, never counted as a pass.

    The row is a PROMISE that something else checks this on the tag, so the promise
    is verified: if the named workflow or job is gone, the row is a FAIL, not a
    reassuring reference to a gate that no longer exists.
    """
    if not workflow_job_exists(workflow, job):
        return Result(check, item, title, FAIL,
                      f"this check is delegated to {workflow} job '{job}', which no "
                      f"longer exists — nothing is checking it",
                      f"grep -n \"{job}\" .github/workflows/{workflow}",
                      workflow=workflow, job=job)
    return Result(check, item, title, CI_ONLY, why,
                  f"gh workflow run {workflow} (job: {job})",
                  workflow=workflow, job=job)


# ── the checks ───────────────────────────────────────────────────────────────
PY = sys.executable or "python3"


def check_tests_gate_machinery(ctx: Ctx) -> Result:
    """The gate machinery's OWN tests. Fast, offline, and the part of the test
    estate that is about releasability rather than about features."""
    files = [
        "tests/test_release_gate_entrypoint.py",
        "tests/test_required_checks_consistency.py",
        "tests/test_release_signing.py",
        "tests/test_release_bundle_signing_workflow.py",
        "tests/test_publish_images_signing_workflow.py",
        "tests/test_licensing_consistency.py",
        "tests/test_sbom.py",
        "tests/test_license_audit.py",
    ]
    return cmd_result(
        "tests.gate-machinery", "tests",
        "release-machinery tests (signing, licensing, SBOM, required checks)",
        [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", *files],
        PROJ, 900.0,
    )


def check_tests_python_suite(ctx: Ctx) -> Result:
    """The repository test suite. ~2700 tests; ~100 minutes on a developer box,
    which is why it is CI-ONLY unless --run-tests is given."""
    if not ctx.run_tests:
        return ci_only(
            "tests.python-suite", "tests", "full pytest suite (tests/ + correlation)",
            "ingest-contract-ci.yml", "ingest + storage contracts (blocking)",
            "~2700 tests, ~100 min locally — run with --run-tests, or take the tag "
            "run (also correlation-ci.yml · pytest (blocking))",
        )
    return cmd_result(
        "tests.python-suite", "tests", "full pytest suite (tests/ + correlation)",
        [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/"],
        PROJ, 9000.0,
    )


def check_tests_go_suite(ctx: Ctx) -> Result:
    if not ctx.run_tests:
        return ci_only(
            "tests.go-suite", "tests", "go test + go test -race",
            "backend-ci.yml", "build · vet · test · race",
            "the -race leg needs a clean runner and ~30 min — run with --run-tests "
            "for the non-race leg, or take the tag run",
        )
    return cmd_result(
        "tests.go-suite", "tests", "go test + go test -race",
        ["go", "test", "./...", "-count=1"], BACKEND, 5400.0,
    )


def check_tests_install_boot(ctx: Ctx) -> Result:
    return ci_only(
        "tests.install-boot", "tests", "clean-host install + two-phase TLS boot",
        "fresh-install-integrity.yml", "install.py --tls=yes two-phase boot (blocking)",
        "needs a scratch host: a full install.py --tls=yes, then post-conditions "
        "(exit 0 cannot see a service that crash-loops after phase B)",
    )


def check_build_go(ctx: Ctx) -> Result:
    return cmd_result(
        "build.go", "build", "go build ./... (backend)",
        ["go", "build", "./..."], BACKEND, 1800.0,
        ok_evidence="the backend module compiles (go.mod's `toolchain` line selects "
                    "the compiler)",
    )


def check_build_frontend(ctx: Ctx) -> Result:
    return ci_only(
        "build.frontend", "build", "tsc -b && vite build (SPA + docs portal)",
        "frontend-ci.yml", "tsc -b && vite build (blocking)",
        "needs npm ci against the lockfile on a clean runner; the images COPY the "
        "built dist/, so the tag run is the artifact's provenance",
    )


TOOLCHAIN_FETCH = re.compile(r"toolchain|GOPROXY=off|module lookup disabled")


def check_offline_build(ctx: Ctx) -> Result:
    """CLAUDE.md §6 gate 2, enforced rather than asserted: the whole reason the tree
    vendors its modules is that `go build` must work with no network.

    The toolchain is part of that claim. With GOPROXY=off an uncached
    `toolchain go1.x` cannot be fetched, so the row fails — and it says which
    problem it is, because "vendor/ is incomplete" and "this host would have to
    download its compiler" have different fixes.
    """
    result = cmd_result(
        "offline-build.go-vendor", "offline build",
        "vendor-only, network-off build (GOFLAGS=-mod=vendor GOPROXY=off)",
        ["go", "build", "./..."], BACKEND, 1800.0, env_overrides=GO_OFFLINE_ENV,
        ok_evidence="builds from vendor/ with GOPROXY=off — the air-gapped host path",
    )
    if result.status != PASS and TOOLCHAIN_FETCH.search(result.evidence):
        result.evidence += (" — the Go TOOLCHAIN itself is not in the module cache, "
                            "and a clean offline build implies a cached toolchain: "
                            "warm it once where there is network, or build where it "
                            "is already cached")
    return result


# ── dependency lock ──────────────────────────────────────────────────────────
GOMOD_REQUIRE_BLOCK = re.compile(r"^require\s*\(([^)]*)\)", re.MULTILINE | re.DOTALL)
GOMOD_REQUIRE_LINE = re.compile(r"^require\s+(\S+)\s+(\S+)\s*(//\s*indirect)?\s*$", re.MULTILINE)
MODULES_TXT_MODULE = re.compile(r"^#\s+(\S+)\s+(\S+)")


def parse_go_mod(path: str) -> dict[str, tuple[str, bool]]:
    """module path -> (version, indirect). Stdlib parse: this check must work with
    no Go toolchain at all, because "is the lock consistent" is a question about
    two committed files, not about a compiler."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    out: dict[str, tuple[str, bool]] = {}
    for block in GOMOD_REQUIRE_BLOCK.findall(text):
        for raw in block.splitlines():
            line = raw.split("//")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                out[parts[0]] = (parts[1], "indirect" in raw)
    for mod, ver, indirect in GOMOD_REQUIRE_LINE.findall(text):
        out[mod] = (ver, bool(indirect))
    return out


def parse_modules_txt(path: str) -> dict[str, tuple[str, bool]]:
    """module path -> (version, explicit)."""
    out: dict[str, tuple[str, bool]] = {}
    current: str | None = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            match = MODULES_TXT_MODULE.match(line)
            if match:
                current = match.group(1)
                out[current] = (match.group(2), False)
            elif line.startswith("## ") and current:
                version, _ = out[current]
                out[current] = (version, "explicit" in line)
    return out


def check_dependency_lock_vendor(ctx: Ctx) -> Result:
    """go.mod and vendor/modules.txt must agree, module for module and version for
    version. A `go get` without a follow-up `go mod vendor` builds fine on a warm
    cache and fails on a customer's air-gapped host; the two files are the lock."""
    cmd = "python3 scripts/release-gate.py --only dependency-lock.go-vendor"
    gomod = os.path.join(BACKEND, "go.mod")
    modules = os.path.join(BACKEND, "vendor", "modules.txt")
    title = "go.mod ↔ vendor/modules.txt agree (module + version)"
    for path in (gomod, modules):
        if not os.path.isfile(path):
            return Result("dependency-lock.go-vendor", "dependency lock", title, FAIL,
                          f"{os.path.relpath(path, REPO)} is missing", cmd)
    required = parse_go_mod(gomod)
    vendored = parse_modules_txt(modules)
    problems: list[str] = []
    for mod, (version, indirect) in sorted(required.items()):
        if mod not in vendored:
            problems.append(f"{mod}@{version} required but not vendored")
        elif vendored[mod][0] != version:
            problems.append(f"{mod}: go.mod {version} vs vendor {vendored[mod][0]}")
        elif not indirect and not vendored[mod][1]:
            problems.append(f"{mod}: a direct require not marked '## explicit' in vendor")
    for mod, (version, _explicit) in sorted(vendored.items()):
        if mod not in required:
            problems.append(f"{mod}@{version} vendored but absent from go.mod")
    if problems:
        return Result("dependency-lock.go-vendor", "dependency lock", title, FAIL,
                      f"{len(problems)} drift(s): " + "; ".join(problems[:3]), cmd)
    return Result("dependency-lock.go-vendor", "dependency lock", title, PASS,
                  f"{len(required)} module(s) locked, versions identical in both files", cmd)


ALLOWLIST_ROW = re.compile(r"^\|\s*`([^`]+)`")


def parse_dependency_allowlist(path: str) -> list[str]:
    """The §6 allowlist table in CLAUDE.md, read rather than remembered.

    A second hand-maintained copy of the allowlist would drift from the one the
    reviewer reads, so this parses the table itself: the first backticked cell of
    every row inside the "### Allowlist" section.
    """
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    start = text.find("### Allowlist")
    if start < 0:
        return []
    section = text[start:]
    end = section.find("\nAnything not in this table")
    if end > 0:
        section = section[:end]
    modules: list[str] = []
    for line in section.splitlines():
        match = ALLOWLIST_ROW.match(line.strip())
        if not match:
            continue
        token = match.group(1).strip()
        if "/" in token:                      # `sqlc` is build-time, not an import
            modules.append(token)
    return modules


def check_dependency_lock_allowlist(ctx: Ctx) -> Result:
    """Every DIRECT go.mod require must be on the CLAUDE.md §6 allowlist.

    RELEASE_CHECKLIST.md §1.18 records this as 🔴 MISSING — "human review only".
    It is mechanical, so it is mechanised here: the allowlist exists to keep the
    offline build clean and the attack surface small, and a dependency that
    arrived without amending the table is exactly what it is meant to stop.
    """
    cmd = "python3 scripts/release-gate.py --only dependency-lock.allowlist"
    title = "go.mod direct requires ⊆ the CLAUDE.md §6 allowlist"
    claude_md = os.path.join(REPO, "CLAUDE.md")
    if not os.path.isfile(claude_md):
        return Result("dependency-lock.allowlist", "dependency lock", title, FAIL,
                      "CLAUDE.md is missing — the allowlist has no authority to read", cmd)
    allowed = parse_dependency_allowlist(claude_md)
    if not allowed:
        return Result("dependency-lock.allowlist", "dependency lock", title, FAIL,
                      "the §6 allowlist table parsed as empty — the gate would "
                      "otherwise pass by accident", cmd)
    direct = [m for m, (_v, indirect) in parse_go_mod(os.path.join(BACKEND, "go.mod")).items()
              if not indirect]
    offenders = []
    for mod in sorted(direct):
        # A row may name a SUBPACKAGE (golang.org/x/crypto/ssh) of the module that
        # go.mod requires (golang.org/x/crypto); either direction of prefix is a
        # match, nothing else is.
        if not any(mod == tok or mod.startswith(tok + "/") or tok.startswith(mod + "/")
                   for tok in allowed):
            offenders.append(mod)
    if offenders:
        return Result("dependency-lock.allowlist", "dependency lock", title, FAIL,
                      f"not on the allowlist: {', '.join(offenders)} — amend CLAUDE.md §6 "
                      f"or drop the dependency", cmd)
    return Result("dependency-lock.allowlist", "dependency lock", title, PASS,
                  f"{len(direct)} direct require(s) all covered by {len(allowed)} "
                  f"allowlist entr(ies)", cmd)


def check_dependency_lock_pip(ctx: Ctx) -> Result:
    """The correlation service's requirements must be hash-locked, or `pip install`
    on a customer host is resolving from whatever PyPI serves that day."""
    cmd = "python3 scripts/release-gate.py --only dependency-lock.pip-hashes"
    title = "correlation requirements.txt fully hash-pinned"
    path = os.path.join(PROJ, "src", "correlation", "requirements.txt")
    if not os.path.isfile(path):
        return Result("dependency-lock.pip-hashes", "dependency lock", title, FAIL,
                      "src/correlation/requirements.txt is missing", cmd)
    with open(path, encoding="utf-8") as handle:
        body = handle.read()
    # Continuations (`\` + newline) join a pin to its --hash lines.
    joined = body.replace("\\\n", " ")
    pins = 0
    unhashed: list[str] = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):              # -r / --index-url / bare flags
            continue
        pins += 1
        if "--hash=" not in line:
            unhashed.append(line.split()[0])
        elif "==" not in line:
            unhashed.append(line.split()[0] + " (not pinned with ==)")
    if not pins:
        return Result("dependency-lock.pip-hashes", "dependency lock", title, FAIL,
                      "no pins found — an empty requirements file locks nothing", cmd)
    if unhashed:
        return Result("dependency-lock.pip-hashes", "dependency lock", title, FAIL,
                      f"{len(unhashed)} pin(s) without --hash: {', '.join(unhashed[:4])}", cmd)
    return Result("dependency-lock.pip-hashes", "dependency lock", title, PASS,
                  f"{pins} pin(s), every one == pinned and hash-locked", cmd)


def check_dependency_lock_npm(ctx: Ctx) -> Result:
    """Both npm trees must carry a lockfile the image build can install from."""
    cmd = "python3 scripts/release-gate.py --only dependency-lock.npm"
    title = "npm lockfiles present and resolved (frontend + docs portal)"
    problems: list[str] = []
    counted = 0
    for rel in ("src/frontend", "docs-portal"):
        lock = os.path.join(PROJ, rel, "package-lock.json")
        if not os.path.isfile(lock):
            problems.append(f"{rel}/package-lock.json is missing")
            continue
        try:
            with open(lock, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            problems.append(f"{rel}/package-lock.json unreadable: {exc}")
            continue
        version = data.get("lockfileVersion")
        if not isinstance(version, int) or version < 2:
            problems.append(f"{rel}: lockfileVersion {version!r} < 2 (no integrity tree)")
        packages = data.get("packages") or {}
        loose = [
            name for name, meta in packages.items()
            if name and isinstance(meta, dict) and meta.get("version")
            and not meta.get("resolved") and not meta.get("link")
        ]
        if loose:
            problems.append(f"{rel}: {len(loose)} entr(ies) with no resolved URL")
        counted += len(packages)
    if problems:
        return Result("dependency-lock.npm", "dependency lock", title, FAIL,
                      "; ".join(problems[:3]), cmd)
    return Result("dependency-lock.npm", "dependency lock", title, PASS,
                  f"2 lockfiles, lockfileVersion 3, {counted} resolved package entr(ies)", cmd)


# ── copyleft / licensing ─────────────────────────────────────────────────────
def check_copyleft_third_party(ctx: Ctx) -> Result:
    return cmd_result(
        "copyleft.third-party", "copyleft gate",
        "third-party licence inventory (strong copyleft needs a reviewed exception)",
        [PY, "scripts/license-audit.py", "--check"], PROJ, 300.0,
    )


def check_copyleft_source_obligation(ctx: Ctx) -> Result:
    """oci-compliance's release mode needs the pushed image digests, so what runs
    locally is its own regression suite — the policy and its fail-closed paths."""
    return cmd_result(
        "copyleft.source-obligation", "copyleft gate",
        "corresponding-source policy engine (fixtures + fail-closed paths)",
        [PY, "scripts/oci-compliance.py", "--selftest"], PROJ, 300.0,
    )


def check_copyleft_image_release(ctx: Ctx) -> Result:
    return ci_only(
        "copyleft.image-release", "copyleft gate",
        "oci-compliance --release against every pushed image digest",
        "publish-images.yml", "publish",
        "needs the built images and their immutable digests; runs per digest and is "
        "needs:-gated by release-gate.yml",
    )


def check_copyleft_source_reviews(ctx: Ctx) -> Result:
    """The written licence determinations under the owner's signature. A signature
    is worth what the evidence under it is worth, so it is re-verified."""
    return cmd_result(
        "copyleft.source-reviews", "copyleft gate",
        "licence review table verified mechanically (7 conditions per entry)",
        [PY, "scripts/verify-source-reviews.py", "--check"], PROJ, 600.0,
        human_action="entries marked needs_human/unclear are a human licence "
                     "determination, not an engineering fix",
    )


def check_signature_image(ctx: Ctx) -> Result:
    """The IMAGE signature — the second artifact trust domain (owner Decision 4,
    2026-09-13; tracker 313). Keyless Cosign against the Actions OIDC identity, so
    unlike the bundle's GPG signature there is no key on this host that could
    reproduce it and no local dry run that could stand in for it: a Fulcio
    certificate is only issuable inside a GitHub-hosted run. The row exists
    because "the release is signed" was, until 2026-09-13, true of the bundle and
    false of the four images, and an aggregate gate that names only the bundle
    lets that asymmetry back in. The SHAPE of the workflow is verified offline by
    tests/test_publish_images_signing_workflow.py, which `tests.gate-machinery`
    runs.
    """
    return ci_only(
        "signature.image", "signature",
        "each image digest signed with Cosign keyless (no stored key)",
        "publish-images.yml", "publish",
        "keyless signing needs the Actions OIDC token, which exists only inside a "
        "GitHub-hosted run; signs IMAGE@sha256:<digest>, never a tag",
    )


def check_signature_image_verification(ctx: Ctx) -> Result:
    """Verification is its own row for the images too, and for the same reason it
    is for the bundle: "we signed it" and "the signature verifies" are different
    claims. The identity is pinned to this repository and this workflow file, and
    the release TAGS are applied only after it passes — so an unverified digest
    stays unreachable by name.
    """
    return ci_only(
        "signature.image-verify", "signature verification",
        "identity-pinned `cosign verify` gates the release tags",
        "publish-images.yml", "publish",
        "runs in the tag job before the provenance attestation and before any tag "
        "is applied; pins --certificate-oidc-issuer + --certificate-identity",
    )


def check_spdx_headers(ctx: Ctx) -> Result:
    return cmd_result(
        "spdx.headers", "SPDX gate", "every source file carries its SPDX header",
        [PY, "scripts/spdx-headers.py", "--check"], PROJ, 300.0,
    )


def check_spdx_boundary(ctx: Ctx) -> Result:
    return cmd_result(
        "spdx.boundary", "SPDX gate",
        "open-core boundary: headers, notices, imports, image metadata",
        [PY, "scripts/licensing-gate.py"], PROJ, 300.0,
    )


ENTERPRISE_MARKER = "CORRELIX-ENTERPRISE-TEXT-PLACEHOLDER"
CLA_MARKER = "CLA-PROCESS-TBD"


def _release_blockers() -> tuple[Proc, list[dict[str, str]]]:
    proc = run_process([PY, "scripts/licensing-gate.py", "--release", "--json"],
                       PROJ, 300.0)
    failures: list[dict[str, str]] = []
    if proc.out.strip():
        try:
            payload = json.loads(proc.out)
        except ValueError:
            return proc, []
        raw = payload.get("failures")
        if isinstance(raw, list):
            failures = [f for f in raw if isinstance(f, dict)]
    return proc, failures


def _blocker_row(check: str, title: str, blocker_file: str, marker: str,
                 human_action: str) -> Result:
    cmd = display([PY, "scripts/licensing-gate.py", "--release"], PROJ)
    proc, failures = _release_blockers()
    if proc.missing or proc.timed_out:
        return Result(check, "enterprise licence validity", title, FAIL,
                      proc.tail or f"exit {proc.rc}", cmd, seconds=proc.seconds)
    # Key on the blocker's FILE (licensing-policy.json's `file`, reported as
    # `where`), not on the marker text: licensing-gate's message carries the
    # policy's prose, and only one of the two entries happens to name its marker
    # there. Matching prose would have passed a row whose blocker was open.
    hits = [f for f in failures
            if str(f.get("where", "")).endswith(blocker_file)
            or marker in str(f.get("message", ""))]
    if hits:
        where = ", ".join(sorted({str(f.get("where", "?")) for f in hits}))
        return Result(check, "enterprise licence validity", title, BLOCKED,
                      f"{where}: {marker} still present", cmd,
                      human_action=human_action, seconds=proc.seconds)
    if not proc.ok and not failures:
        return Result(check, "enterprise licence validity", title, FAIL,
                      proc.tail or f"licensing-gate --release exited {proc.rc} with no "
                                   f"parseable verdict", cmd, seconds=proc.seconds)
    other = len(failures)
    if other:
        # Some OTHER release blocker is open. This row's own condition is clear;
        # the sibling row reports the rest.
        return Result(check, "enterprise licence validity", title, PASS,
                      f"{marker} is gone ({other} other release blocker(s) open — "
                      f"see the sibling row)", cmd, seconds=proc.seconds)
    return Result(check, "enterprise licence validity", title, PASS,
                  "licensing-gate --release is clean", cmd, seconds=proc.seconds)


def check_enterprise_licence_text(ctx: Ctx) -> Result:
    """Decision 1: a commercial marking whose licence text does not exist grants
    nothing. Engineering MUST NOT draft, paraphrase or adapt the terms."""
    return _blocker_row(
        "enterprise-licence.text", "Correlix Enterprise licence text is real",
        "LICENSES/LicenseRef-Correlix-Enterprise.txt", ENTERPRISE_MARKER,
        "BLOCKED: final Correlix Enterprise licence text required from counsel — "
        "replace LICENSES/LicenseRef-Correlix-Enterprise.txt (RC1 blocker A)",
    )


def check_enterprise_licence_cla(ctx: Ctx) -> Result:
    """Decision 2: a stated CLA with no signing process confers no relicensing
    right. The plumbing is built (cla-check.yml); the terms and the mechanism are
    counsel's and the owner's."""
    return _blocker_row(
        "enterprise-licence.cla", "CLA has a named signing mechanism",
        "CONTRIBUTING.md", CLA_MARKER,
        "BLOCKED: owner + counsel must choose the CLA mechanism and record it in "
        "CONTRIBUTING.md §1, then enable cla-check.yml (RC1 blocker B)",
    )


# ── generated-code cleanliness ───────────────────────────────────────────────
def check_generated_licensing_map(ctx: Ctx) -> Result:
    return cmd_result(
        "generated.licensing-map", "generated-code cleanliness",
        "LICENSING.md regenerates identically at both roots",
        [PY, "scripts/gen-licensing-map.py", "--check"], PROJ, 300.0,
    )


def check_generated_worktree_clean(ctx: Ctx) -> Result:
    """A release is built from a commit, so anything uncommitted — generated or
    not — is not in the release. Untracked source is the worse half: it builds
    here and is absent from the customer's tree."""
    cmd = display(["git", "status", "--porcelain"], REPO)
    proc = run_process(["git", "status", "--porcelain"], REPO, 120.0)
    title = "working tree clean (nothing generated, edited or untracked outside git)"
    if not proc.ok:
        return Result("generated.worktree-clean", "generated-code cleanliness", title,
                      FAIL, proc.tail or f"git exited {proc.rc}", cmd, seconds=proc.seconds)
    dirty = [ln for ln in proc.out.splitlines() if ln.strip()]
    if dirty:
        return Result("generated.worktree-clean", "generated-code cleanliness", title,
                      FAIL, f"{len(dirty)} path(s) not committed: "
                            f"{', '.join(ln[3:] for ln in dirty[:3])}", cmd,
                      seconds=proc.seconds)
    return Result("generated.worktree-clean", "generated-code cleanliness", title, PASS,
                  "git status --porcelain is empty", cmd, seconds=proc.seconds)


# ── security scans ───────────────────────────────────────────────────────────
def check_security_secrets(ctx: Ctx) -> Result:
    tool = resolve_tool("gitleaks") or "gitleaks"
    return cmd_result(
        "security.secrets-history", "security scans",
        "gitleaks over the FULL git history (not just the tip)",
        [tool, "detect", "--source", ".", "--redact", "--exit-code", "1",
         "--log-opts=--all"], REPO, 1800.0, tool=tool,
    )


def check_security_govulncheck(ctx: Ctx) -> Result:
    tool = resolve_tool("govulncheck") or "govulncheck"
    return cmd_result(
        "security.go-vuln", "security scans", "govulncheck ./... (backend)",
        [tool, "./..."], BACKEND, 1800.0, tool=tool,
    )


def check_security_staticcheck(ctx: Ctx) -> Result:
    tool = resolve_tool("staticcheck") or "staticcheck"
    return cmd_result(
        "security.staticcheck", "security scans",
        "staticcheck on the crypto/trust packages",
        [tool, "./tlsconfig/...", "./internalca/...", "./sealing/..."],
        BACKEND, 1800.0, tool=tool,
    )


GOSEC_FILES = re.compile(r"Files\s*:\s*(\d+)")


def check_security_gosec(ctx: Ctx) -> Result:
    """gosec, and then a check that gosec actually read something.

    Found while building this gate: `gosec -quiet` (the flag backend-ci uses)
    EXITS 0 after failing to load every package — on this host it "passed" in
    0.2 s having analysed 0 files, because the toolchain could not load the
    module. That is the green-run-that-checked-nothing defect in its purest form,
    so the flag is dropped (it also suppresses the summary this reads) and the
    file count is asserted: a scan of zero files is a FAIL, exactly like a
    finding.
    """
    tool = resolve_tool("gosec") or "gosec"
    title = "gosec on the crypto/trust packages (and it analysed something)"
    argv = [tool, "./tlsconfig/...", "./internalca/...", "./sealing/..."]
    cmd = display(argv, BACKEND)
    proc = run_process(argv, BACKEND, 1800.0)
    if proc.missing:
        return Result("security.gosec", "security scans", title, FAIL,
                      f"{proc.err} — a gate tool that is not installed has proven "
                      f"nothing; install it or run this check in CI", cmd,
                      seconds=proc.seconds)
    if not proc.ok:
        return Result("security.gosec", "security scans", title, FAIL,
                      proc.tail or f"exit {proc.rc}", cmd, seconds=proc.seconds)
    match = GOSEC_FILES.search(f"{proc.out}\n{proc.err}")
    if not match:
        return Result("security.gosec", "security scans", title, FAIL,
                      "gosec exited 0 but printed no 'Files:' summary — refusing "
                      "to read that as a scan", cmd, seconds=proc.seconds)
    if int(match.group(1)) == 0:
        return Result("security.gosec", "security scans", title, FAIL,
                      "gosec exited 0 having analysed 0 files — a green run that "
                      "checked nothing (package loading failed)", cmd,
                      seconds=proc.seconds)
    return Result("security.gosec", "security scans", title, PASS,
                  f"gosec: no findings across {match.group(1)} file(s) · via {tool}",
                  cmd, seconds=proc.seconds)


def check_security_cis_docker(ctx: Ctx) -> Result:
    return cmd_result(
        "security.cis-docker", "security scans",
        "CIS-Docker policy (non-root, digest pins, cap_drop ALL, no-new-privileges)",
        [PY, "scripts/audits/cis_docker.py", "--selftest"], PROJ, 300.0,
    )


def check_security_no_pe(ctx: Ctx) -> Result:
    return cmd_result(
        "security.no-pe-binaries", "security scans",
        "no Windows PE binaries in the source tree or the owned Dockerfiles",
        [PY, "scripts/check-no-pe-binaries.py", "--selftest"], PROJ, 300.0,
    )


def check_security_trivy(ctx: Ctx) -> Result:
    return ci_only(
        "security.trivy-fs", "security scans",
        "Trivy filesystem scan (vuln + secret + misconfig, CRITICAL/HIGH)",
        "supply-chain.yml", "Trivy filesystem scan (blocking)",
        "needs a freshly downloaded vulnerability database; a release gate must not "
        "depend on a network feed it cannot pin",
    )


def check_security_npm_audit(ctx: Ctx) -> Result:
    return ci_only(
        "security.npm-audit", "security scans", "npm audit --audit-level=high",
        "frontend-ci.yml", "npm audit (blocking)",
        "queries the npm advisory service against an installed lockfile tree",
    )


# ── SBOM ─────────────────────────────────────────────────────────────────────
def check_sbom_committed(ctx: Ctx) -> Result:
    """The committed SBOM is what makes "what shipped in this tag" answerable from
    the tag alone; the CI artifact expires with the run."""
    return cmd_result(
        "sbom.committed", "SBOM", "committed CycloneDX SBOM matches the tree",
        [PY, "scripts/sbom.py", "--check"], PROJ, 600.0,
    )


def check_sbom_images(ctx: Ctx) -> Result:
    return ci_only(
        "sbom.images", "SBOM", "per-image CycloneDX SBOM (Syft/Trivy) + attestation",
        "supply-chain.yml", "SBOM (CycloneDX)",
        "scans the built images; publish-images.yml attaches the per-digest SBOM to "
        "the pushed artifact",
    )


# ── the artifact: checksums, signature, verification, metadata ───────────────
BUNDLE_GLOB_PREFIX = "correlix-"
MANIFEST_KEYS = ("product", "version", "git_sha", "profile", "built")


def find_bundle(explicit: str | None) -> tuple[str | None, str]:
    """Resolve the bundle to grade: --bundle, else the newest dist/correlix-* that
    has a MANIFEST. Returns (path, why-not)."""
    if explicit:
        path = os.path.abspath(explicit)
        if not os.path.isdir(path):
            return None, f"--bundle {explicit} is not a directory"
        if not os.path.isfile(os.path.join(path, "MANIFEST")):
            return None, f"--bundle {explicit} has no MANIFEST — not a built bundle"
        return path, ""
    dist = os.path.join(PROJ, "dist")
    if not os.path.isdir(dist):
        return None, "no dist/ directory — nothing has been packaged from this tree"
    found = [
        os.path.join(dist, name) for name in sorted(os.listdir(dist))
        if name.startswith(BUNDLE_GLOB_PREFIX)
        and os.path.isfile(os.path.join(dist, name, "MANIFEST"))
    ]
    if not found:
        return None, "no dist/correlix-*/ bundle with a MANIFEST"
    found.sort(key=lambda p: os.path.getmtime(p))
    return found[-1], ""


def _no_bundle(check: str, item: str, title: str, ctx: Ctx) -> Result:
    return Result(check, item, title, FAIL,
                  f"{ctx.bundle_why} — build it (`make bundle`, or the tag's "
                  f"release-bundle.yml run) and re-run with --bundle DIR",
                  "make bundle && python3 scripts/release-gate.py --bundle dist/correlix-…")


def read_manifest(bundle: str) -> dict[str, str]:
    """MANIFEST as key -> value.

    Two line shapes, both real: `key:  value` for the build facts
    make-installer.sh writes in its heredoc, and `signing-key <fpr>` (no colon)
    for the block --sign-only appends — which is also the shape release-bundle.yml
    greps for before it publishes. Indented lines are list members (`  - image`).
    """
    out: dict[str, str] = {}
    with open(os.path.join(bundle, "MANIFEST"), encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line.strip() or line.startswith((" ", "\t", "-")):
                continue
            head = line.split(None, 1)[0]
            if head.endswith(":"):
                out[head[:-1]] = line[len(head):].strip()
            elif ":" in head:
                key, _, value = line.partition(":")
                out[key.strip()] = value.strip()
            else:
                parts = line.split(None, 1)
                out[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
    return out


def check_checksums(ctx: Ctx) -> Result:
    """SHA256SUMS must exist, cover every shipped file, and still match the bytes.

    Coverage is the half that is easy to lose: a signature over a partial manifest
    is a signature that says nothing about the file somebody added afterwards.
    """
    title = "SHA256SUMS covers every shipped file and matches the bytes"
    if not ctx.bundle:
        return _no_bundle("checksums.bundle", "checksums", title, ctx)
    sums = os.path.join(ctx.bundle, "SHA256SUMS")
    rel = os.path.relpath(ctx.bundle, REPO)
    cmd = f"cd {rel} && sha256sum -c --ignore-missing SHA256SUMS"
    if not os.path.isfile(sums):
        return Result("checksums.bundle", "checksums", title, FAIL,
                      "SHA256SUMS is missing from the bundle", cmd)
    listed: dict[str, str] = {}
    with open(sums, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            digest, _, name = line.partition("  ")
            name = name.strip().lstrip("./")
            if len(digest) == 64 and name:
                listed[name] = digest
    present: set[str] = set()
    for root, _dirs, files in os.walk(ctx.bundle):
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                continue
            relname = os.path.relpath(full, ctx.bundle)
            if relname in ("SHA256SUMS", "SHA256SUMS.asc"):
                continue
            present.add(relname)
    uncovered = sorted(present - set(listed))
    if uncovered:
        return Result("checksums.bundle", "checksums", title, FAIL,
                      f"{len(uncovered)} shipped file(s) outside SHA256SUMS: "
                      f"{', '.join(uncovered[:3])}", cmd)
    bad: list[str] = []
    checked = 0
    for name, digest in sorted(listed.items()):
        full = os.path.join(ctx.bundle, name)
        if not os.path.isfile(full):
            # A >1900 MiB member is split into .partNN for upload; the joined file
            # is intentionally absent (release-bundle.yml uses --ignore-missing).
            continue
        digester = hashlib.sha256()
        with open(full, "rb") as handle:
            for block in iter(lambda h=handle: h.read(1 << 20), b""):
                digester.update(block)
        checked += 1
        if digester.hexdigest() != digest:
            bad.append(name)
    if bad:
        return Result("checksums.bundle", "checksums", title, FAIL,
                      f"{len(bad)} checksum mismatch(es): {', '.join(bad[:3])}", cmd)
    if not checked:
        return Result("checksums.bundle", "checksums", title, FAIL,
                      "SHA256SUMS lists files but none of them are present", cmd)
    return Result("checksums.bundle", "checksums", title, PASS,
                  f"{checked} file(s) verified, {len(listed)} listed, none uncovered", cmd)


def check_signature(ctx: Ctx) -> Result:
    """Decision 3B: a release bundle is signed in full or it is not a release.

    An absent distribution key is a human blocker (nobody may mint one here), not
    an engineering defect — and it still fails the release.
    """
    title = "the bundle is signed (SHA256SUMS.asc + signer fingerprint in MANIFEST)"
    human = ("HUMAN ACTION: the owner mints/holds the DISTRIBUTION signing key "
             "(different from the tag key and the licence key), exports it as the "
             "CORRELIX_DIST_SIGNING_KEY repository secret; custody per tracker 259 "
             "(RC1 blockers D/F)")
    cmd = ("CORRELIX_RELEASE_BUILD=1 CORRELIX_SIGNING_KEY=<fpr> "
           "bash scripts/make-installer.sh --sign-only dist/correlix-…")
    if not ctx.signing_fpr:
        return Result("signature.bundle", "signature", title, BLOCKED,
                      f"no distribution signing key available: {ctx.signing_why}",
                      cmd, human_action=human)
    if not ctx.bundle:
        return _no_bundle("signature.bundle", "signature", title, ctx)
    asc = os.path.join(ctx.bundle, "SHA256SUMS.asc")
    if not os.path.isfile(asc):
        return Result("signature.bundle", "signature", title, FAIL,
                      "SHA256SUMS.asc is missing — an unsigned bundle is never "
                      "published (Decision 3B)", cmd)
    manifest = read_manifest(ctx.bundle)
    if not manifest.get("signing-key"):
        return Result("signature.bundle", "signature", title, FAIL,
                      "MANIFEST records no signing-key fingerprint", cmd)
    return Result("signature.bundle", "signature", title, PASS,
                  f"SHA256SUMS.asc present, MANIFEST signer "
                  f"{manifest['signing-key'][-16:]}", cmd)


def check_signature_verification(ctx: Ctx) -> Result:
    """Verification is its own check, because "we signed it" and "the signature
    verifies over the manifest we are publishing" are different claims."""
    title = "the signature verifies over SHA256SUMS"
    rel = os.path.relpath(ctx.bundle, REPO) if ctx.bundle else "dist/correlix-…"
    cmd = f"cd {rel} && gpg --batch --verify SHA256SUMS.asc SHA256SUMS"
    if not ctx.bundle:
        if not ctx.signing_fpr:
            return Result("signature.verify", "signature verification", title, BLOCKED,
                          f"nothing to verify: {ctx.bundle_why}; and no distribution "
                          f"key exists ({ctx.signing_why})", cmd,
                          human_action="HUMAN ACTION: distribution signing key + a "
                                       "signed bundle (RC1 blockers D/F)")
        return _no_bundle("signature.verify", "signature verification", title, ctx)
    if not os.path.isfile(os.path.join(ctx.bundle, "SHA256SUMS.asc")):
        status = BLOCKED if not ctx.signing_fpr else FAIL
        return Result("signature.verify", "signature verification", title, status,
                      "SHA256SUMS.asc is absent, so there is no signature to verify",
                      cmd,
                      human_action="HUMAN ACTION: distribution signing key (RC1 "
                                   "blockers D/F)" if status == BLOCKED else "")
    gpg = resolve_tool("gpg")
    if not gpg:
        return Result("signature.verify", "signature verification", title, FAIL,
                      "gpg is not installed — the signature cannot be verified here",
                      cmd)
    return cmd_result(
        "signature.verify", "signature verification", title,
        [gpg, "--batch", "--quiet", "--verify", "SHA256SUMS.asc", "SHA256SUMS"],
        ctx.bundle, 600.0, ok_evidence="gpg verified the detached signature",
    )


def check_release_metadata(ctx: Ctx) -> Result:
    """Decision 7: one immutable commit, and the artifact says which one."""
    title = "MANIFEST records version, commit, build time, profile, images, signer"
    if not ctx.bundle:
        return _no_bundle("release-metadata.manifest", "release metadata", title, ctx)
    rel = os.path.relpath(ctx.bundle, REPO)
    cmd = f"cat {rel}/MANIFEST"
    manifest = read_manifest(ctx.bundle)
    missing = [key for key in MANIFEST_KEYS if not manifest.get(key)]
    if missing:
        return Result("release-metadata.manifest", "release metadata", title, FAIL,
                      f"MANIFEST omits {', '.join(missing)}", cmd)
    with open(os.path.join(ctx.bundle, "MANIFEST"), encoding="utf-8") as handle:
        body = handle.read()
    if "images:" not in body:
        return Result("release-metadata.manifest", "release metadata", title, FAIL,
                      "MANIFEST lists no images — provenance must name what shipped",
                      cmd)
    if not manifest.get("signing-key"):
        return Result("release-metadata.manifest", "release metadata", title, FAIL,
                      "MANIFEST has no signing-key line — the signer is part of the "
                      "release metadata (Decision 7)", cmd)
    return Result("release-metadata.manifest", "release metadata", title, PASS,
                  f"version {manifest['version']}, commit {manifest['git_sha']}, "
                  f"built {manifest['built']}", cmd)


# ── source / tag consistency ─────────────────────────────────────────────────
def check_source_tag_exact(ctx: Ctx) -> Result:
    """Decision 9: tag → exact commit → build. HEAD must BE a tag, not be near one."""
    title = "HEAD is an exact release tag (v*)"
    cmd = display(["git", "describe", "--exact-match", "--tags", "HEAD"], REPO)
    proc = run_process(["git", "describe", "--exact-match", "--tags", "HEAD"],
                       REPO, 120.0)
    human = ("HUMAN ACTION: the owner creates the annotated, signed release tag on "
             "the reviewed commit of protected main (RC1 blocker C)")
    if not proc.ok:
        return Result("source-tag.exact-tag", "source/tag consistency", title, BLOCKED,
                      f"HEAD ({ctx.head[:12]}) is not an exact tag: "
                      f"{proc.tail or 'no tag points at HEAD'}", cmd,
                      human_action=human, seconds=proc.seconds)
    tag = proc.out.strip()
    if not re.match(r"^v\d+\.\d+\.\d+", tag):
        return Result("source-tag.exact-tag", "source/tag consistency", title, BLOCKED,
                      f"HEAD is tagged '{tag}', which is not a release tag (v*)", cmd,
                      human_action=human, seconds=proc.seconds)
    return Result("source-tag.exact-tag", "source/tag consistency", title, PASS,
                  f"HEAD is exactly {tag} ({ctx.head[:12]})", cmd, seconds=proc.seconds)


def check_source_tag_signed(ctx: Ctx) -> Result:
    """Decision 3A: the source/tag signature is verified BEFORE artifacts are built."""
    title = "the release tag is annotated and its signature verifies"
    human = ("HUMAN ACTION: `git tag -s v0.9.0-rc1` with the SOURCE/TAG key (a "
             "different key from the distribution key), then verify it (RC1 blocker C)")
    if not ctx.tag:
        return Result("source-tag.signed-tag", "source/tag consistency", title, BLOCKED,
                      "no release tag points at HEAD, so there is no tag signature",
                      "git tag -s v0.9.0-rc1 && git verify-tag v0.9.0-rc1",
                      human_action=human)
    cmd = display(["git", "verify-tag", ctx.tag], REPO)
    proc = run_process(["git", "verify-tag", ctx.tag], REPO, 120.0)
    if not proc.ok:
        return Result("source-tag.signed-tag", "source/tag consistency", title, BLOCKED,
                      f"{ctx.tag}: {proc.tail or 'no valid signature'}", cmd,
                      human_action=human, seconds=proc.seconds)
    return Result("source-tag.signed-tag", "source/tag consistency", title, PASS,
                  f"{ctx.tag}: {proc.tail}", cmd, seconds=proc.seconds)


def check_source_tag_bundle(ctx: Ctx) -> Result:
    """The artifact must name the commit that is being released, not a near-by one."""
    title = "the bundle was built from this commit"
    if not ctx.bundle:
        return _no_bundle("source-tag.bundle-commit", "source/tag consistency", title, ctx)
    rel = os.path.relpath(ctx.bundle, REPO)
    cmd = f"grep '^git_sha' {rel}/MANIFEST && git rev-parse --short HEAD"
    manifest = read_manifest(ctx.bundle)
    built_sha = manifest.get("git_sha", "")
    if not built_sha:
        return Result("source-tag.bundle-commit", "source/tag consistency", title, FAIL,
                      "MANIFEST records no git_sha", cmd)
    if not ctx.head:
        return Result("source-tag.bundle-commit", "source/tag consistency", title, FAIL,
                      "could not resolve HEAD to compare against the bundle", cmd)
    if not (ctx.head.startswith(built_sha) or built_sha.startswith(ctx.head[:8])):
        return Result("source-tag.bundle-commit", "source/tag consistency", title, FAIL,
                      f"bundle was built from {built_sha}, HEAD is {ctx.head[:12]} — "
                      f"a release artifact must come from the released commit", cmd)
    return Result("source-tag.bundle-commit", "source/tag consistency", title, PASS,
                  f"bundle git_sha {built_sha} == HEAD", cmd)


# The registry. Order is the report's order: the tree first, then the artifact,
# then the tag — the order a release actually happens in.
CHECKS: tuple[tuple[str, str, object], ...] = (
    ("tests.gate-machinery", "tests", check_tests_gate_machinery),
    ("tests.python-suite", "tests", check_tests_python_suite),
    ("tests.go-suite", "tests", check_tests_go_suite),
    ("tests.install-boot", "tests", check_tests_install_boot),
    ("build.go", "build", check_build_go),
    ("build.frontend", "build", check_build_frontend),
    ("offline-build.go-vendor", "offline build", check_offline_build),
    ("dependency-lock.go-vendor", "dependency lock", check_dependency_lock_vendor),
    ("dependency-lock.allowlist", "dependency lock", check_dependency_lock_allowlist),
    ("dependency-lock.pip-hashes", "dependency lock", check_dependency_lock_pip),
    ("dependency-lock.npm", "dependency lock", check_dependency_lock_npm),
    ("copyleft.third-party", "copyleft gate", check_copyleft_third_party),
    ("copyleft.source-obligation", "copyleft gate", check_copyleft_source_obligation),
    ("copyleft.source-reviews", "copyleft gate", check_copyleft_source_reviews),
    ("copyleft.image-release", "copyleft gate", check_copyleft_image_release),
    ("spdx.headers", "SPDX gate", check_spdx_headers),
    ("spdx.boundary", "SPDX gate", check_spdx_boundary),
    ("enterprise-licence.text", "enterprise licence validity", check_enterprise_licence_text),
    ("enterprise-licence.cla", "enterprise licence validity", check_enterprise_licence_cla),
    ("generated.licensing-map", "generated-code cleanliness", check_generated_licensing_map),
    ("generated.worktree-clean", "generated-code cleanliness", check_generated_worktree_clean),
    ("security.secrets-history", "security scans", check_security_secrets),
    ("security.go-vuln", "security scans", check_security_govulncheck),
    ("security.staticcheck", "security scans", check_security_staticcheck),
    ("security.gosec", "security scans", check_security_gosec),
    ("security.cis-docker", "security scans", check_security_cis_docker),
    ("security.no-pe-binaries", "security scans", check_security_no_pe),
    ("security.trivy-fs", "security scans", check_security_trivy),
    ("security.npm-audit", "security scans", check_security_npm_audit),
    ("sbom.committed", "SBOM", check_sbom_committed),
    ("sbom.images", "SBOM", check_sbom_images),
    ("checksums.bundle", "checksums", check_checksums),
    ("signature.bundle", "signature", check_signature),
    ("signature.verify", "signature verification", check_signature_verification),
    ("signature.image", "signature", check_signature_image),
    ("signature.image-verify", "signature verification",
     check_signature_image_verification),
    ("release-metadata.manifest", "release metadata", check_release_metadata),
    ("source-tag.exact-tag", "source/tag consistency", check_source_tag_exact),
    ("source-tag.signed-tag", "source/tag consistency", check_source_tag_signed),
    ("source-tag.bundle-commit", "source/tag consistency", check_source_tag_bundle),
)


# ── context resolution ───────────────────────────────────────────────────────
def signing_key() -> tuple[str | None, str]:
    """The DISTRIBUTION signing key's fingerprint, or why there is none.

    Only fingerprints are ever read or printed — never key material (CLAUDE.md
    §8, Decision 10).
    """
    key = os.environ.get("CORRELIX_SIGNING_KEY", "").strip()
    if not key:
        return None, "CORRELIX_SIGNING_KEY is unset on this host"
    gpg = resolve_tool("gpg")
    if not gpg:
        return None, "CORRELIX_SIGNING_KEY is set but gpg is not installed"
    proc = run_process([gpg, "--batch", "--with-colons", "--list-secret-keys", key],
                       PROJ, 120.0)
    if not proc.ok:
        return None, f"CORRELIX_SIGNING_KEY has no secret key in this keyring ({proc.tail})"
    for line in proc.out.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            return parts[9], ""
    return None, "gpg listed no fingerprint for CORRELIX_SIGNING_KEY"


def build_ctx(args: argparse.Namespace) -> Ctx:
    bundle, why = find_bundle(args.bundle)
    fpr, key_why = signing_key()
    head_proc = run_process(["git", "rev-parse", "HEAD"], REPO, 120.0)
    head = head_proc.out.strip() if head_proc.ok else ""
    tag_proc = run_process(["git", "describe", "--exact-match", "--tags", "HEAD"],
                           REPO, 120.0)
    tag = tag_proc.out.strip() if tag_proc.ok else ""
    return Ctx(bundle=bundle, bundle_why=why, run_tests=args.run_tests,
               signing_fpr=fpr, signing_why=key_why, head=head, tag=tag)


# ── reporting ────────────────────────────────────────────────────────────────
@dataclass
class Report:
    results: list[Result] = field(default_factory=list)
    filtered: bool = False
    head: str = ""
    bundle: str = ""

    @property
    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(STATUSES, 0)
        for result in self.results:
            out[result.status] = out.get(result.status, 0) + 1
        return out

    @property
    def item_rollup(self) -> dict[str, str]:
        """Worst status per Decision-8 item. FAIL beats BLOCKED-HUMAN beats
        CI-ONLY beats PASS: an item is only clean when every one of its checks is."""
        rank = {PASS: 0, CI_ONLY: 1, BLOCKED: 2, FAIL: 3}
        worst: dict[str, str] = {}
        for item in DECISION8_ITEMS:
            statuses = [r.status for r in self.results if r.item == item]
            if not statuses:
                worst[item] = "NOT CHECKED"
                continue
            worst[item] = max(statuses, key=lambda s: rank.get(s, 3))
        return worst

    @property
    def exit_code(self) -> int:
        counts = self.counts
        if counts[FAIL] or counts[BLOCKED]:
            return 1
        if counts[CI_ONLY] or self.filtered:
            return 3
        return 0

    @property
    def verdict(self) -> str:
        return "GO" if self.exit_code == 0 else "NO-GO"

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "correlix.release-gate/1",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commit": self.head,
            "bundle": self.bundle,
            "partial_run": self.filtered,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "counts": self.counts,
            "decision8_items": self.item_rollup,
            "checks": [r.as_dict() for r in self.results],
        }


def print_table(report: Report, stream) -> None:
    width_check = max([len(r.check) for r in report.results] + [5])
    width_status = max(len(s) for s in STATUSES)
    print("Correlix release gate — RC1 governance directive, Decision 8", file=stream)
    print(f"commit {report.head or '(unknown)'}   "
          f"bundle {report.bundle or '(none built)'}", file=stream)
    print(file=stream)
    header = (f"{'CHECK'.ljust(width_check)}  {'RESULT'.ljust(width_status)}  "
              f"WHAT IT PROVES   (→ evidence · $ the exact command)")
    print(header, file=stream)
    print("-" * len(header), file=stream)
    current_item = ""
    for result in report.results:
        if result.item != current_item:
            current_item = result.item
            print(f"\n[{current_item}]", file=stream)
        print(f"{result.check.ljust(width_check)}  "
              f"{result.status.ljust(width_status)}  {result.title}", file=stream)
        print(f"{' ' * width_check}  {' ' * width_status}  → {result.evidence}",
              file=stream)
        if result.workflow:
            print(f"{' ' * width_check}  {' ' * width_status}  "
                  f"→ runs in: {result.workflow} · job '{result.job}'", file=stream)
        if result.human_action:
            print(f"{' ' * width_check}  {' ' * width_status}  "
                  f"→ {result.human_action}", file=stream)
        print(f"{' ' * width_check}  {' ' * width_status}  $ {result.command}",
              file=stream)

    counts = report.counts
    print(file=stream)
    print("Decision-8 items:", file=stream)
    for item, status in report.item_rollup.items():
        print(f"  {item.ljust(30)} {status}", file=stream)
    print(file=stream)
    print(f"{counts[PASS]} PASS · {counts[FAIL]} FAIL · {counts[BLOCKED]} "
          f"BLOCKED-HUMAN · {counts[CI_ONLY]} CI-ONLY (never counted as a pass)",
          file=stream)
    if report.filtered:
        print("PARTIAL RUN (--only): a filtered run is never a release verdict.",
              file=stream)
    print(f"VERDICT: {report.verdict}  (exit {report.exit_code})", file=stream)
    if counts[BLOCKED]:
        print(file=stream)
        print("Human blockers — engineering cannot clear these and must not "
              "pretend to:", file=stream)
        for result in report.results:
            if result.status == BLOCKED:
                print(f"  {result.check}: {result.human_action or result.evidence}",
                      file=stream)
    if counts[FAIL]:
        print(file=stream)
        print("Engineering failures:", file=stream)
        for result in report.results:
            if result.status == FAIL:
                print(f"  {result.check}: {result.evidence}", file=stream)


# ── entry point ──────────────────────────────────────────────────────────────
def run_checks(ctx: Ctx, only: str = "") -> Report:
    report = Report(filtered=bool(only), head=ctx.head,
                    bundle=os.path.relpath(ctx.bundle, REPO) if ctx.bundle else "")
    for check_id, item, fn in CHECKS:
        if only and only not in check_id and only not in item:
            continue
        started = time.monotonic()
        try:
            result = fn(ctx)
        except Exception as exc:  # noqa: BLE001 - see below
            # Run-all-report-all only holds if one broken check cannot take the
            # report with it — and a check that crashed proved nothing, so it is a
            # FAIL, never a skip and never silence (scripts/CLAUDE.md §16.1).
            result = Result(
                check_id, item, f"{check_id} (the check itself raised)", FAIL,
                f"{type(exc).__name__}: {exc}",
                f"python3 scripts/release-gate.py --only {check_id}",
                seconds=time.monotonic() - started,
            )
        if not result.seconds:
            result.seconds = time.monotonic() - started
        # A check that reports a status this gate does not understand is a gate
        # defect, and a gate defect must not read as a pass.
        if result.status not in STATUSES:
            result.evidence = f"unknown status {result.status!r}: {result.evidence}"
            result.status = FAIL
        report.results.append(result)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true",
                        help="emit the same report as JSON (for the RC1 report)")
    parser.add_argument("--bundle", default=None,
                        help="grade this built bundle directory (default: the newest "
                             "dist/correlix-*/ with a MANIFEST)")
    parser.add_argument("--run-tests", action="store_true",
                        help="also run the long local suites instead of citing the "
                             "CI job that runs them")
    parser.add_argument("--only", default="",
                        help="run only checks whose id or Decision-8 item contains "
                             "this substring. Debugging aid: a filtered run can "
                             "never return the GO exit code")
    parser.add_argument("--list", action="store_true",
                        help="list the checks and their Decision-8 items, run nothing")
    args = parser.parse_args(argv)

    if args.list:
        for check_id, item, _fn in CHECKS:
            print(f"{check_id.ljust(30)} {item}")
        return 0

    if not os.path.isdir(os.path.join(REPO, ".git")) and not os.path.isfile(
            os.path.join(REPO, ".git")):
        print("release-gate: not a git checkout — the gate needs the repository to "
              f"resolve HEAD, tags and cleanliness (looked at {REPO})",
              file=sys.stderr)
        return 2

    ctx = build_ctx(args)
    report = run_checks(ctx, args.only)
    if not report.results:
        print(f"release-gate: --only {args.only!r} matched no check", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print_table(report, sys.stdout)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
