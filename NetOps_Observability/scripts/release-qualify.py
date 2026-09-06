#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""release-qualify.py — rerun the CORRELIX REFERENCE CAPACITY V1 qualification
on the currently deployed build and grade every V1 clause (tracker 203).

WHAT THIS IS
------------
`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` pins a permanent qualification
profile: workload (`t-storm-2.5k`, 2,500 devices, 15 min @ 1,000 eps), seed
(20260829), two digests, the memory-cap table, scorer v2, the aggregation-plane
default, and the nine harness gates. It says, in its versioning rule, that any
future build MUST be able to rerun that exact qualification and be compared
against the baseline run of record (`storm-s11`, run `090121382mk4`).

This script is that one command. It does NOT define, weaken or reinterpret a
single V1 clause: every gate it reports is graded by the instrument V1 already
names (the harness's own nine phases, the twin scorer, the plane's own
counters). What it adds is (a) an environment refusal V1 §8(e) requires but no
tool enforced, (b) a single machine-readable record of the whole qualification,
and (c) a diff against the extracted `storm-s11` baseline.

**V1 SEMANTICS ARE FROZEN.** A different workload, seed, digest, device count,
rate, cap, gate clause, scorer or plane configuration is a V2 profile
(`CORRELIX_REFERENCE_CAPACITY_V2.md`), never a flag on this script. That is why
the leg is launched with the profile and NOTHING else: the harness defaults ARE
the V1 gates, so a tuning flag here would silently re-base the qualification.

THREE-VALUED HONESTY
--------------------
Every stage records PASS / FAIL / SKIPPED / INVALID.

  PASS     the clause was measured and met.
  FAIL     the clause was measured and missed. Overall FAIL, exit 1.
  SKIPPED  the clause was NOT measured, with the reason recorded. A SKIPPED
           stage never fails the run and never counts as evidence — it is the
           honest third value that keeps "we did not measure it" distinct from
           "it passed". Two stages are structurally SKIPPED today: `rebalance`
           (the 155/199 disturbance clauses are a separate arc — see
           `docs/scale/OWNERSHIP_155_VALIDATION_2026-08-31.md`; the ownership
           judge has no CLI yet) and `aggregation` when grading a historical
           leg for which no PRE-run counter capture exists.
  INVALID  the measurement itself cannot be trusted (unquiet host, a replica
           restarted mid-run so its counter delta is not a delta). Overall
           INVALID, exit 2 — never a PASS, never a FAIL.

STAGES, IN ORDER
----------------
  environment  V1 section 8(e): >= 10 GiB free on the run root's filesystem AND
               on the docker data root, host load1 <= --max-load1. Refuses
               BEFORE anything else runs. `--allow-unquiet` downgrades the
               refusal to a recorded WARN and marks the whole result
               `qualification_grade: false` — a non-qualification run.
  pins         V1 section 3: `tests/test_storm_scenario_profile.py` and
               `tests/test_workload_profiles.py` must both be green on the
               build under qualification (they carry the two pinned digests).
  candidate    what is actually deployed: every correlation replica's image id
               + started_at, the api image id + OCI revision + build time, the
               git HEAD and whether the tree is dirty, and the resolved
               aggregation-plane arm. Plus the PRE-run /metrics scrape, so the
               plane's accounting can be asserted on a DELTA instead of a
               cumulative counter (the caveat storm-s11 had to carry).
  leg          `scale-miniladder.py --profile t-storm-2.5k --devices 2500
               --eps 1000`; all nine phases must PASS (V1 section 8(a)).
  accuracy     the twin scorer, `scorer_version == 2`, accuracy >= 0.93
               (V1 sections 4 + 5).
  aggregation  V1 section 7: per replica AND summed, delta-observed ==
               sum(delta-forwarded{class}) + delta-suppressed, exactly.
  ttur         V1 section 8(b): the clean-scope SQL, verbatim, reused from
               `scale-ab-driver.py`. T1 p50/p95/p99 are PUBLISHED, NEVER GATED.
               T1 = time to first correlated version, an engineering lifecycle
               metric — it is not TTUR proper (tracker 205).
  rebalance    SKIPPED, see above.
  baseline     diff against `docs/scale/baselines/storm-s11.v1.json`. Gated
               clauses must be PASS on both. Informational numbers (completion,
               T1, memory ratios, accuracy, suppressed share, corr_signals) are
               PRINTED as a table and REPORTED when they regress — never gated,
               because the gates are the harness's own and V1 says so for T1.

SELF-TEST (no rig, no stack, no docker)
---------------------------------------
`--self-test` re-grades the CHECKED-IN `storm-s11` leg fixture
(`tests/fixtures/storm-s11/`) through the real stages and asserts both
directions: the leg of record grades PASS, and each mutated copy of it — a
regressed harness gate, accuracy under the floor, a scorer-v1 report,
aggregation that does not close, a replica that restarted mid-run, an unquiet
host — produces the FAIL or INVALID it must. It proves THE SUITE'S OWN LOGIC,
never the build; it touches no stack, issues no docker command beyond the
stubbed `inspect` the baseline extractor asks for, and needs no `.env`. That is
what makes it runnable in CI, where the rig does not exist. It is NOT
qualification evidence and never prints a qualification verdict.

USAGE
-----
    python3 scripts/release-qualify.py                       # full rerun
    python3 scripts/release-qualify.py --self-test           # CI: prove the suite
    python3 scripts/release-qualify.py --dry-run             # plan + env only
    python3 scripts/release-qualify.py --skip-leg RUN_DIR    # re-grade a leg
    python3 scripts/release-qualify.py --extract-baseline RUN_DIR

EXIT CODES
----------
0 = QUALIFICATION PASS; 1 = FAIL (a measured clause missed); 2 = INVALID, a
usage error, or an environment refusal. An empty or unreadable measurement is
an ERROR, never a silent zero (CLAUDE.md 16.1).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import types
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

# Cron-proof PATH (CLAUDE.md 16.2). Applied in main(), NOT at import: as
# module-scope code it leaks into every process that merely imports this file
# for its helpers (the lesson scale-miniladder.py records, and the one the
# sibling test suites assert).
CRON_PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
HARNESS = os.path.join(SCRIPT_DIR, "scale-miniladder.py")
AB_DRIVER = os.path.join(SCRIPT_DIR, "scale-ab-driver.py")
TWIN = os.path.join(SCRIPT_DIR, "lab", "twin", "twin.py")
DEFAULT_BASELINE = os.path.join(REPO_ROOT, "docs", "scale", "baselines",
                                "storm-s11.v1.json")
DEFAULT_ENV_FILE = os.path.join(REPO_ROOT, "deployment", "docker", ".env")
DEFAULT_RUN_ROOT = "/var/tmp/scale-runs"

# --- the V1 pins. Changing any of these is a V2 profile, not an edit here. ---
V1_PROFILE = "t-storm-2.5k"
V1_DEVICES = 2500
V1_EPS = 1000
V1_SEED = 20260829
V1_MIN_ACCURACY = 0.93          # V1 section 4 (SLO, Option A verbatim)
V1_SCORER_VERSION = 2           # V1 section 5 (twin scorer v2, 06450430)
V1_MIN_FREE_GIB = 10.0          # V1 section 8(e)
V1_PER_LEG_OBSERVED = 54767     # V1 section 7 (deterministic per-leg count)
V1_PIN_TESTS = ("tests/test_storm_scenario_profile.py",
                "tests/test_workload_profiles.py")
V1_PHASES = ("preflight", "onboard", "burst", "drain", "correlation_completion",
             "accounting", "memflat", "stability", "cleanup")

DEFAULT_MAX_LOAD1 = 6.0         # storm-s11 launched at 2.9; storm-s10 at 16-38
DEFAULT_TENANT = "global"

# Every subprocess is bounded (CLAUDE.md 16.3). A wedged dockerd, a hung
# pytest or a stuck harness must not hang the qualification forever.
DOCKER_TIMEOUT = 60
METRICS_TIMEOUT = 60
PYTEST_TIMEOUT = 1800
TWIN_TIMEOUT = 3600
CH_TIMEOUT = 900
GIT_TIMEOUT = 30
LEG_TIMEOUT = 21600             # 6 h; a clean 2.5k leg is ~60 min end to end
LEG_READ_TIMEOUT = 30.0         # select() slice while relaying the leg's output

GIB = 1024 ** 3

PASS, FAIL, SKIPPED, INVALID = "PASS", "FAIL", "SKIPPED", "INVALID"

# A labelled Prometheus sample: `name{label="value",...} 123`. `prom_value`
# in scale-ab-driver.py deliberately matches UNLABELLED samples only, so the
# per-class `corr_agg_forwarded_total{class="..."}` family needs its own
# parse — a different function, not a copy of that one.
LABELLED_RE = re.compile(r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<labels>[^}]*)\}"
                         r"\s+(?P<value>[-+0-9.eE]+|NaN|\+Inf|-Inf)$")


class QualifyError(RuntimeError):
    """A refusal. Carries the reason; never a bare exit."""


def log(msg: str) -> None:
    print(f"release-qualify: {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"release-qualify: WARNING: {msg}", file=sys.stderr, flush=True)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on a non-zero exit — callers look at rc
    and REPORT stderr (CLAUDE.md 16.1: no swallowed errors)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False, cwd=cwd)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:6])}"
    except (OSError, ValueError) as exc:
        return 127, "", f"cannot execute {cmd[0]!r}: {exc}"


def load_ab_driver(path: str = AB_DRIVER) -> types.ModuleType:
    """Import `scale-ab-driver.py` for the pieces V1 section 8(b) is defined by.

    The clean-scope TTUR SQL, the burst-window derivation, the storm-aggregate
    cid and the mTLS /metrics probe are the A/B driver's, and they are what the
    V1 document cites. Importing them keeps ONE definition: a copy here would
    be a second SQL string that could drift from the one V1 points at, which is
    exactly the class of divergence the frozen profile exists to prevent.

    The driver applies its cron PATH in main(), so a bare import is side-effect
    free — asserted by the test suite.
    """
    spec = importlib.util.spec_from_file_location("scale_ab_driver", path)
    if spec is None or spec.loader is None:
        raise QualifyError(f"cannot import {path} — the V1 section 8(b) TTUR "
                           f"definition lives there and is not reimplemented here")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("scale_ab_driver", mod)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        raise QualifyError(f"importing {path} failed: {exc!r}") from exc
    return mod


# ---------------------------------------------------------------------------
# pure helpers (all unit-tested; no subprocess, no filesystem)
# ---------------------------------------------------------------------------
def parse_loadavg(text: str) -> float:
    """load1 from /proc/loadavg contents. Unparsable is fatal — an unread load
    must never look quiet (CLAUDE.md 16.1)."""
    parts = (text or "").split()
    if not parts:
        raise QualifyError("/proc/loadavg is empty — host quiet-ness is UNKNOWN, "
                           "and an unknown host is not a quiet one")
    try:
        return float(parts[0])
    except ValueError as exc:
        raise QualifyError(f"/proc/loadavg first field {parts[0]!r} is not a "
                           f"number ({exc})") from exc


def parse_meminfo_total_kib(text: str) -> int:
    """MemTotal in kB from /proc/meminfo, or -1 when absent (informational
    only — it is recorded, never gated)."""
    for line in (text or "").splitlines():
        if line.startswith("MemTotal:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                return int(fields[1])
    return -1


def environment_violations(filesystems: list[dict], load1: float,
                           min_free_gib: float, max_load1: float) -> list[str]:
    """V1 section 8(e) as a list of violations (empty = quiet host).

    `filesystems` carries one entry per DISTINCT filesystem that must hold
    headroom: {"path", "free_gib", "error"}. A filesystem whose free space
    could not be read is a violation, not a pass — storm-s10 lost 291,296
    evidence docs to a disk gate nobody was measuring.
    """
    problems: list[str] = []
    for fs in filesystems:
        if fs.get("error"):
            problems.append(f"free space on {fs.get('path')!r} is UNKNOWN "
                            f"({fs['error']}) — an unmeasured filesystem is not "
                            f"a headroom guarantee")
            continue
        free = float(fs.get("free_gib", -1.0))
        if free < min_free_gib:
            problems.append(f"{fs.get('path')} has {free:.1f} GiB free, below the "
                            f"{min_free_gib:.0f} GiB V1 section 8(e) floor "
                            f"(storm-s10 crossed OpenSearch's flood-stage "
                            f"watermark mid-burst and lost 291,296 evidence docs)")
    if load1 > max_load1:
        problems.append(f"host load1 {load1:.2f} exceeds the {max_load1:.2f} bound "
                        f"— storm-s11 launched at 2.9, storm-s10 (excluded for "
                        f"environment violation) at 16-38")
    return problems


def labelled_samples(text: str, name: str) -> dict[str, float]:
    """{label-value: sample} for a single-label Prometheus family.

    Used for `corr_agg_forwarded_total{class="..."}`. Deliberately strict: a
    sample whose value does not parse is dropped from the map AND the caller
    sees a short map, so the accounting identity fails loudly rather than
    balancing against a silently-missing class.
    """
    out: dict[str, float] = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LABELLED_RE.match(stripped)
        if not match or match.group("name") != name:
            continue
        labels = match.group("labels")
        key = labels
        parts = labels.split("=", 1)
        if len(parts) == 2:
            key = parts[1].strip().strip('"')
        try:
            out[key] = float(match.group("value"))
        except ValueError:
            continue
    return out


def agg_counters(metrics_text: str, prom_value: Callable[[str, str], float | None]
                 ) -> dict[str, Any]:
    """The plane's V1 section 7 counters out of one replica's /metrics body."""
    forwarded = labelled_samples(metrics_text, "corr_agg_forwarded_total")
    return {
        "enabled": prom_value(metrics_text, "corr_agg_enabled"),
        "observed": prom_value(metrics_text, "corr_agg_observed_total"),
        "suppressed": prom_value(metrics_text, "corr_agg_suppressed_total"),
        "forwarded_by_class": dict(sorted(forwarded.items())),
        "forwarded_total": sum(forwarded.values()) if forwarded else None,
    }


def split_metrics_by_replica(text: str) -> dict[str, str]:
    """`metrics-final.txt` -> {container-short-id: body}.

    The file is the A/B driver's concatenation, one `# ==== replica <name>
    (<short>) ip <ip> started_at <ts> ...` banner per replica.
    """
    out: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    banner = re.compile(r"^# ==== replica (?P<name>\S+) \((?P<short>[0-9a-f]+)\)")
    for line in (text or "").splitlines():
        match = banner.match(line)
        if match:
            if current is not None:
                out[current] = "\n".join(buf)
            current = match.group("short")
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        out[current] = "\n".join(buf)
    return out


def agg_delta(pre: dict[str, Any], post: dict[str, Any]) -> dict[str, Any]:
    """One replica's V1 section 7 accounting on the DELTA between two scrapes.

    Returns {"status", "reason", ...numbers}. A replica whose `started_at`
    moved between the two scrapes restarted mid-run: its counters reset, so
    post-minus-pre is not a delta at all and could balance by coincidence.
    That is INVALID — never a PASS, and never a FAIL either, because nothing
    about the plane was actually measured.
    """
    if pre.get("started_at") != post.get("started_at"):
        return {"status": INVALID,
                "reason": f"replica restarted mid-run (started_at "
                          f"{pre.get('started_at')} -> {post.get('started_at')}): "
                          f"its counters reset, so post-minus-pre is not a delta"}
    numbers: dict[str, Any] = {}
    for key in ("observed", "suppressed", "forwarded_total"):
        before, after = pre.get(key), post.get(key)
        if before is None or after is None:
            return {"status": INVALID,
                    "reason": f"counter {key!r} unreadable in the "
                              f"{'pre' if before is None else 'post'}-run scrape "
                              f"— the accounting identity cannot be evaluated"}
        delta = float(after) - float(before)
        if delta < 0:
            return {"status": INVALID,
                    "reason": f"counter {key!r} went BACKWARDS "
                              f"({before} -> {after}) on an unchanged container "
                              f"— a monotonic counter cannot do that"}
        numbers[key] = delta
    classes_pre = pre.get("forwarded_by_class") or {}
    classes_post = post.get("forwarded_by_class") or {}
    if set(classes_pre) != set(classes_post):
        return {"status": INVALID,
                "reason": f"the forwarded class set changed between scrapes "
                          f"({sorted(classes_pre)} -> {sorted(classes_post)}) — "
                          f"the sum would silently omit a class"}
    numbers["forwarded_by_class"] = {
        cls: float(classes_post[cls]) - float(classes_pre[cls])
        for cls in sorted(classes_post)}
    balance = numbers["forwarded_total"] + numbers["suppressed"]
    numbers["expected_observed"] = balance
    numbers["exact"] = numbers["observed"] == balance
    numbers["suppressed_share"] = (
        round(100.0 * numbers["suppressed"] / numbers["observed"], 2)
        if numbers["observed"] else 0.0)
    numbers["status"] = PASS if numbers["exact"] else FAIL
    if not numbers["exact"]:
        numbers["reason"] = (f"observed {numbers['observed']:.0f} != forwarded "
                             f"{numbers['forwarded_total']:.0f} + suppressed "
                             f"{numbers['suppressed']:.0f} "
                             f"({balance:.0f}) — V1 section 7 requires exactness")
    return numbers


def grade_accuracy(report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """V1 sections 4 + 5 against an `accuracy-report.json`."""
    scorer = report.get("scorer_version")
    total = report.get("stories_total")
    passed = report.get("stories_passed")
    accuracy = report.get("accuracy_slo")
    evidence: dict[str, Any] = {
        "scorer_version": scorer, "stories_passed": passed,
        "stories_total": total, "accuracy": accuracy,
        "required_scorer_version": V1_SCORER_VERSION,
        "required_accuracy": V1_MIN_ACCURACY,
        "detection_rate": report.get("detection_rate"),
        "specificity": report.get("specificity"),
    }
    if scorer != V1_SCORER_VERSION:
        evidence["reason"] = (
            f"scorer_version {scorer!r} is not {V1_SCORER_VERSION} — V1 section 5 "
            f"pins the v2 scorer (06450430); a number from any other scorer is "
            f"not a V1 accuracy number")
        return FAIL, evidence
    if not isinstance(accuracy, (int, float)):
        evidence["reason"] = (f"accuracy_slo {accuracy!r} is not a number — an "
                              f"unread accuracy is not a passing one")
        return FAIL, evidence
    if float(accuracy) < V1_MIN_ACCURACY:
        evidence["reason"] = (f"accuracy {float(accuracy):.4f} is below the V1 "
                              f"section 4 floor {V1_MIN_ACCURACY}")
        return FAIL, evidence
    return PASS, evidence


def grade_phases(report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """V1 section 8(a): all nine harness gates PASS, carried into the record."""
    phases = report.get("phases")
    if not isinstance(phases, list) or not phases:
        return INVALID, {"reason": "report.json carries no phases[] — the leg "
                                   "produced no gradable evidence"}
    statuses: dict[str, Any] = {str(p.get("phase")): p.get("status")
                                for p in phases
                                if isinstance(p, dict) and p.get("phase")}
    missing = [name for name in V1_PHASES if name not in statuses]
    failed = sorted(name for name, status in statuses.items() if status != "PASS")
    evidence: dict[str, Any] = {
        "runid": report.get("runid"),
        "overall": report.get("overall"),
        "phases": dict(sorted(statuses.items())),
        "phases_passed": sum(1 for s in statuses.values() if s == "PASS"),
        "phases_total": len(statuses),
        "required_phases": list(V1_PHASES),
        "missing_phases": missing,
        "failed_phases": failed,
        "parameters": report.get("parameters"),
    }
    if missing:
        evidence["reason"] = (f"phases {missing} never ran — a V1 leg is graded "
                              f"on all {len(V1_PHASES)}")
        return INVALID, evidence
    if failed:
        evidence["reason"] = f"harness gate(s) {failed} did not PASS"
        return FAIL, evidence
    return PASS, evidence


def overall_verdict(records: Iterable[dict[str, Any]]) -> str:
    """PASS only if every non-SKIPPED stage is PASS. INVALID beats FAIL: a
    measurement we cannot trust is not a failure we can report."""
    statuses = [r.get("status") for r in records]
    if INVALID in statuses:
        return INVALID
    if FAIL in statuses:
        return FAIL
    graded = [s for s in statuses if s != SKIPPED]
    if not graded:
        return INVALID
    return PASS if all(s == PASS for s in graded) else FAIL


def parse_ttur_tsv(text: str) -> dict[str, str]:
    """The clean-scope query's single data row as {column: value}."""
    rows = [ln for ln in (text or "").splitlines() if ln.strip()]
    if len(rows) < 2:
        raise QualifyError(
            f"the T1 query returned no data row (output {text.strip()[:200]!r}) "
            f"— an empty scope is an ERROR, never a silent zero (16.1)")
    header = rows[0].split("\t")
    values = rows[1].split("\t")
    if len(header) != len(values):
        raise QualifyError(f"T1 row has {len(values)} field(s) against "
                           f"{len(header)} header(s) — refusing to align them")
    return dict(zip(header, values))


def phase_evidence(report: dict[str, Any], phase: str) -> dict[str, Any]:
    for entry in report.get("phases") or []:
        if isinstance(entry, dict) and entry.get("phase") == phase:
            ev = entry.get("evidence")
            return ev if isinstance(ev, dict) else {}
    return {}


def informational_rows(candidate: dict[str, Any], baseline: dict[str, Any]
                       ) -> list[dict[str, Any]]:
    """The V1 numbers that are REPORTED, not gated. A regression here is news,
    not a verdict: the gates are the harness's own, and V1 says so explicitly
    for T1 p95. Completion, memory and suppressed share follow the same rule so
    that a slower-but-still-inside-budget build is described, never blocked.
    """
    rows: list[dict[str, Any]] = []

    def add(metric: str, now: Any, then: Any, unit: str = "",
            lower_is_better: bool = True) -> None:
        delta: Any = ""
        note = ""
        if isinstance(now, (int, float)) and isinstance(then, (int, float)):
            delta = round(float(now) - float(then), 3)
            if then:
                pct = 100.0 * (float(now) - float(then)) / abs(float(then))
                note = f"{pct:+.1f}%"
                worse = pct > 0 if lower_is_better else pct < 0
                if abs(pct) >= 10.0 and worse:
                    note += " REGRESSION (informational)"
        rows.append({"metric": metric, "candidate": now, "baseline": then,
                     "delta": delta, "unit": unit, "note": note})

    add("engine completion", candidate.get("completion_s"),
        baseline.get("completion_s"), "s")
    add("T1 p50 (published, not gated)", candidate.get("t1_p50"),
        baseline.get("t1_p50"), "s")
    add("T1 p95 (published, not gated)", candidate.get("t1_p95"),
        baseline.get("t1_p95"), "s")
    add("T1 p99 (published, not gated)", candidate.get("t1_p99"),
        baseline.get("t1_p99"), "s")
    add("accuracy", candidate.get("accuracy"), baseline.get("accuracy"), "",
        lower_is_better=False)
    add("suppressed share", candidate.get("suppressed_share"),
        baseline.get("suppressed_share"), "%", lower_is_better=False)
    add("corr_signals rows", candidate.get("corr_signal_rows"),
        baseline.get("corr_signal_rows"), "rows", lower_is_better=False)
    cand_mem = candidate.get("memory") or {}
    base_mem = baseline.get("memory") or {}
    for service in sorted(set(cand_mem) | set(base_mem)):
        now = cand_mem.get(service) or {}
        then = base_mem.get(service) or {}
        add(f"memory {service} ratio", now.get("ratio_vs_anchor"),
            then.get("ratio_vs_anchor"), "x")
        add(f"memory {service} % of cap", now.get("pct_of_limit"),
            then.get("pct_of_limit"), "%")
    return rows


# ---------------------------------------------------------------------------
# baseline extraction
# ---------------------------------------------------------------------------
def extract_baseline(run_dir: str, runner: Callable[..., tuple[int, str, str]] = run,
                     driver: types.ModuleType | None = None) -> dict[str, Any]:
    """Build the machine-readable V1 baseline from a finished run dir.

    NEVER hand-typed: every number here is read out of the leg's own artifacts
    (`report.json`, `accuracy-report.json`, `metrics-final.txt`, `ttur.tsv`), so
    the checked-in baseline cannot drift from the run it claims to describe.
    Re-runnable and byte-stable: the output is `json.dumps(..., sort_keys=True,
    indent=1)` over values that are pure functions of the run dir, with the ONE
    exception named in `images.source` — image ids are not recorded in the run
    dir by any harness, so they are resolved by `docker inspect` of the
    container ids that ARE recorded there, and are null (with the reason) when
    those containers are gone.
    """
    drv = driver or load_ab_driver()
    report = read_json(os.path.join(run_dir, "report.json"))
    accuracy = read_json(os.path.join(run_dir, "accuracy-report.json"))
    metrics_text = read_text(os.path.join(run_dir, "metrics-final.txt"))
    ttur = parse_ttur_tsv(read_text(os.path.join(run_dir, "ttur.tsv")))

    burst = phase_evidence(report, "burst")
    scenario = burst.get("scenario") or {}
    ground_truth = burst.get("ground_truth") or {}
    completion = phase_evidence(report, "correlation_completion")
    accounting = phase_evidence(report, "accounting")
    memflat = phase_evidence(report, "memflat")
    stability = phase_evidence(report, "stability")
    cleanup = phase_evidence(report, "cleanup")

    replicas = split_metrics_by_replica(metrics_text)
    banner = re.compile(r"^# ==== replica (?P<name>\S+) \((?P<short>[0-9a-f]+)\) "
                        r"ip (?P<ip>\S+) started_at (?P<started>\S+)")
    replica_meta: list[dict[str, Any]] = []
    for line in metrics_text.splitlines():
        match = banner.match(line)
        if match:
            replica_meta.append({"container": match.group("short"),
                                 "name": match.group("name"),
                                 "started_at": match.group("started")})

    images = resolve_images(replica_meta, runner)

    agg_by_replica = {}
    for short, body in sorted(replicas.items()):
        agg_by_replica[short] = agg_counters(body, drv.prom_value)
    observed = sum(float(c["observed"] or 0.0) for c in agg_by_replica.values())
    forwarded = sum(float(c["forwarded_total"] or 0.0) for c in agg_by_replica.values())
    suppressed = sum(float(c["suppressed"] or 0.0) for c in agg_by_replica.values())

    containers = {}
    for entry in memflat.get("containers") or []:
        if not isinstance(entry, dict):
            continue
        containers[str(entry.get("container"))] = {
            "service": entry.get("service"),
            "instrument": entry.get("instrument"),
            "warm_bytes": entry.get("warm_bytes"),
            "end_bytes": entry.get("end_bytes"),
            "limit_bytes": entry.get("limit_bytes"),
            "ratio_vs_anchor": entry.get("ratio_vs_anchor"),
            "pct_of_limit": entry.get("pct_of_limit"),
            "verdict": entry.get("verdict"),
        }

    return {
        "schema": "correlix.release-qualify.baseline/1",
        "profile_version": "CORRELIX_REFERENCE_CAPACITY_V1",
        "leg": leg_label(run_dir),
        "run_dir_basename": os.path.basename(os.path.normpath(run_dir)),
        "run_dir": os.path.normpath(run_dir),
        "runid": report.get("runid"),
        "generated_from": "docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md sections 3-9",
        "extractor": "scripts/release-qualify.py --extract-baseline",
        "workload": {
            "profile": (report.get("parameters") or {}).get("profile"),
            "workload_class": (report.get("parameters") or {}).get("workload_class"),
            "devices": (report.get("parameters") or {}).get("devices"),
            "eps": (report.get("parameters") or {}).get("eps"),
            "burst_minutes": (report.get("parameters") or {}).get("burst_minutes"),
            "producer_key": (report.get("parameters") or {}).get("producer_key"),
            "seed": scenario.get("seed", ground_truth.get("seed")),
            "scenario": scenario.get("name"),
            "scenario_digest": scenario.get("digest"),
            "shape_digest": scenario.get("shape_digest"),
            "incidents": ground_truth.get("incidents"),
            "scenario_events_planned": scenario.get("planned"),
            "storm_share_target": scenario.get("storm_share_target"),
            "storm_share_achieved": scenario.get("storm_share_achieved"),
            "scenario_events_injected": scenario.get("injected"),
            "background_injected": scenario.get("background_injected"),
        },
        "images": images,
        "phases": {name: status for name, status in sorted(
            (p.get("phase"), p.get("status")) for p in report.get("phases") or []
             if isinstance(p, dict) and p.get("phase"))},
        "overall": report.get("overall"),
        "harness": {
            "completion_s": completion.get("completed_at_s"),
            "completion_budget_s": completion.get("budget_s"),
            "injected_total": accounting.get("injected_total"),
            "os_persisted_run_docs": accounting.get("os_persisted_run_docs"),
            "dlq_run_lines": accounting.get("dlq_run_lines"),
            "unexplained_missing": accounting.get("unexplained_missing"),
            "corr_signal_rows_run": accounting.get("corr_signal_rows_run"),
            "corr_entities_covered": accounting.get("corr_entities_covered"),
            "devices_expected": accounting.get("devices_expected"),
            "memory": containers,
            "clickhouse": {
                "cap_bytes": (memflat.get("clickhouse") or {}).get("cap_bytes"),
                "p99_memory_tracking_bytes":
                    (memflat.get("clickhouse") or {}).get("p99_memory_tracking_bytes"),
                "peak_memory_tracking_bytes":
                    (memflat.get("clickhouse") or {}).get("peak_memory_tracking_bytes"),
            },
            "stability": {
                "commit_failed": stability.get("commit_failed"),
                "unknown_member": stability.get("unknown_member"),
                "consumer_restarts": stability.get("consumer_restarts"),
                "rebalances": stability.get("rebalances"),
                "observation_window_s": stability.get("observation_window_s"),
                "worst_loop_lag_ms": stability.get("worst_loop_lag_ms"),
                "session_timeout_ms": stability.get("session_timeout_ms"),
            },
            "cleanup": {
                "devices_deleted": cleanup.get("devices_deleted"),
                "devices_remaining": cleanup.get("devices_remaining"),
                "final_residue_devices": cleanup.get("final_residue_devices"),
                "os_deleted": cleanup.get("os_deleted"),
                "os_docs_left": cleanup.get("os_docs_left"),
                "ch_signals_left": cleanup.get("ch_signals_left"),
            },
        },
        "accuracy": {
            "scorer_version": accuracy.get("scorer_version"),
            "stories_passed": accuracy.get("stories_passed"),
            "stories_total": accuracy.get("stories_total"),
            "accuracy": accuracy.get("accuracy_slo"),
            "detection_rate": accuracy.get("detection_rate"),
            "specificity": accuracy.get("specificity"),
        },
        "aggregation": {
            "scope": "cumulative_s10_s11",
            "scope_note":
                "storm-s11's correlation containers were started 2026-09-01T19:31Z "
                "and were NOT recreated between storm-s10 (environment-invalidated) "
                "and storm-s11, so these *_total values are CUMULATIVE across both "
                "legs (metrics-final.txt carries the same note). They are recorded "
                "for DISPLAY only; a candidate leg is graded on its own PRE/POST "
                "delta, which is what release-qualify.py captures.",
            "observed": observed,
            "forwarded_total": forwarded,
            "suppressed": suppressed,
            "exact": observed == forwarded + suppressed,
            "suppressed_share_pct": (round(100.0 * suppressed / observed, 2)
                                     if observed else 0.0),
            "per_leg_observed_expected": V1_PER_LEG_OBSERVED,
            "per_replica": agg_by_replica,
        },
        "t1": {
            "note": "T1 = time to first correlated version (V1 section 8(b)); "
                    "PUBLISHED, NEVER GATED. Not TTUR proper (tracker 205).",
            "incidents": ttur.get("inc"),
            "versions": ttur.get("versions"),
            "signals": ttur.get("sigs"),
            "p50_s": ttur.get("t1p50"),
            "p95_s": ttur.get("t1p95"),
            "p99_s": ttur.get("t1p99"),
            "max_s": ttur.get("t1max"),
            "tlast_p95_s": ttur.get("tlast95"),
        },
    }


def resolve_images(replica_meta: list[dict[str, Any]],
                   runner: Callable[..., tuple[int, str, str]]) -> dict[str, Any]:
    """Image ids for the containers a run dir names. See `extract_baseline`."""
    out: dict[str, Any] = {
        "source": "docker inspect of the container ids recorded in "
                  "metrics-final.txt; null when the container is no longer "
                  "present (no harness records image ids in the run dir)",
        "correlation": [],
    }
    for rep in replica_meta:
        entry: dict[str, Any] = {"container": rep["container"], "name": rep["name"],
                                 "started_at": rep["started_at"], "image": None,
                                 "error": ""}
        rc, sout, serr = runner(["docker", "inspect", rep["container"],
                                 "--format", "{{.Image}}"], DOCKER_TIMEOUT)
        if rc != 0:
            entry["error"] = (serr or sout).strip()[:200] or f"rc={rc}"
        else:
            entry["image"] = short_image(sout.strip())
        out["correlation"].append(entry)
    out["correlation"].sort(key=lambda e: str(e.get("name")))
    # The api image is NOT recoverable from a run dir: no harness records the
    # api container id, and looking up the CURRENT api container would stamp
    # today's image onto a historical leg. V1 section 9 quotes it from the
    # deploy record; the qualification run captures its own in candidate.json.
    out["api"] = {
        "image": None,
        "note": "not recorded in the run dir by any harness — see V1 section 9 "
                "for the leg-of-record's api image; a qualification run records "
                "the candidate's own api image in candidate.json",
    }
    return out


def leg_label(run_dir: str) -> str:
    """`storm-s11-09012138` -> `storm-s11`: the leg NAME, without the run dir's
    MMDDHHMM stamp. Deterministic, and it is what V1 section 9 calls the leg."""
    base = os.path.basename(os.path.normpath(run_dir))
    return re.sub(r"-\d{8}$", "", base)


def short_image(image: str) -> str:
    """`sha256:23dc2b88e966…` -> `23dc2b88e966` (the form V1 section 9 quotes)."""
    value = (image or "").strip()
    value = value.removeprefix("sha256:")
    return value[:12]


def read_json(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise QualifyError(f"cannot read {path} ({exc})") from exc
    if not isinstance(data, dict):
        raise QualifyError(f"{path} is not a JSON object")
    return data


def stat_device(path: str) -> int:
    """`st_dev` for `path`, or a REFUSAL.

    §16.1: an unstattable path is not a measurement. The OSError is escalated
    as QualifyError; `read_environment` records it as a filesystem whose
    headroom is UNKNOWN, which `environment_violations` turns into a V1
    section 8(e) violation and `stage_environment` records as INVALID.
    """
    try:
        return os.stat(path).st_dev
    except OSError as exc:
        raise QualifyError(f"cannot stat {path} ({exc})") from exc


def disk_headroom(path: str) -> tuple[float, float]:
    """(free GiB, total GiB) for the filesystem holding `path`, or a REFUSAL.

    Same escalation as `stat_device`: storm-s10 lost 291,296 evidence docs to a
    disk gate nobody was measuring, so free space that could not be READ must
    never read as free space that is FINE.
    """
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        raise QualifyError(f"cannot read free space on {path} ({exc})") from exc
    return round(usage.free / GIB, 2), round(usage.total / GIB, 2)


def read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise QualifyError(f"cannot read {path} ({exc})") from exc


def write_text(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        raise QualifyError(f"cannot write {path} ({exc})") from exc


def dump_baseline(doc: dict[str, Any]) -> str:
    """Byte-stable serialization: sorted keys, fixed indent, trailing newline."""
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# the qualifier
# ---------------------------------------------------------------------------
class Qualifier:
    """Runs the stages in order and records one three-valued verdict each."""

    def __init__(self, args: argparse.Namespace,
                 runner: Callable[..., tuple[int, str, str]] = run,
                 driver: types.ModuleType | None = None,
                 streamer: Callable[..., tuple[int, str]] | None = None) -> None:
        self.args = args
        self.runner = runner
        self._driver = driver
        self.streamer = streamer or stream_process
        self.records: list[dict[str, Any]] = []
        self.qualification_grade = True
        self.leg_dir: str = args.skip_leg or ""
        self.report: dict[str, Any] = {}
        self.pre_metrics: dict[str, dict[str, Any]] = {}
        self.candidate: dict[str, Any] = {}
        self.summary: dict[str, Any] = {}

    @property
    def driver(self) -> types.ModuleType:
        if self._driver is None:
            self._driver = load_ab_driver()
        return self._driver

    # -- plumbing ---------------------------------------------------------
    def record(self, stage: str, status: str, evidence: dict[str, Any],
               warn_flag: bool = False) -> str:
        entry: dict[str, Any] = {"stage": stage, "status": status,
                                 "evidence": evidence, "at": utcnow()}
        if warn_flag:
            entry["warn"] = True
        self.records.append(entry)
        suffix = " (WARN)" if warn_flag else ""
        reason = evidence.get("reason") if isinstance(evidence, dict) else None
        log(f"[{status}{suffix}] {stage}" + (f" — {reason}" if reason else ""))
        return status

    def evidence_of(self, stage: str) -> dict[str, Any]:
        for entry in self.records:
            if entry["stage"] == stage:
                ev = entry.get("evidence")
                return ev if isinstance(ev, dict) else {}
        return {}

    def status_of(self, stage: str) -> str:
        for entry in self.records:
            if entry["stage"] == stage:
                return str(entry["status"])
        return ""

    # -- stage a: environment (V1 section 8(e)) ---------------------------
    def read_environment(self) -> dict[str, Any]:
        paths = ["/", nearest_existing(self.args.run_dir)]
        rc, dout, derr = self.runner(
            ["docker", "info", "--format", "{{.DockerRootDir}}"], DOCKER_TIMEOUT)
        docker_root = dout.strip() if rc == 0 else ""
        docker_error = "" if rc == 0 else ((derr or dout).strip()[:200] or f"rc={rc}")
        if docker_root:
            paths.append(docker_root)
        filesystems: list[dict[str, Any]] = []
        seen: set[Any] = set()
        for path in paths:
            if not path:
                continue
            try:
                dev = stat_device(path)
            except QualifyError as exc:
                filesystems.append({"path": path, "error": str(exc)})
                continue
            if dev in seen:
                continue
            seen.add(dev)
            try:
                free_gib, total_gib = disk_headroom(path)
            except QualifyError as exc:
                filesystems.append({"path": path, "error": str(exc)})
                continue
            filesystems.append({"path": path, "device": dev,
                                "free_gib": free_gib,
                                "total_gib": total_gib})
        if docker_error:
            filesystems.append({"path": "docker data root",
                                "error": f"docker info failed: {docker_error}"})
        try:
            load1 = parse_loadavg(read_text("/proc/loadavg"))
            load_error = ""
        except QualifyError as exc:
            load1, load_error = -1.0, str(exc)
        try:
            mem_kib = parse_meminfo_total_kib(read_text("/proc/meminfo"))
        except QualifyError:
            mem_kib = -1
        return {
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 8(e)",
            "filesystems": filesystems,
            "docker_root": docker_root or None,
            "load1": load1,
            "load1_error": load_error,
            "max_load1": self.args.max_load1,
            "min_free_gib": V1_MIN_FREE_GIB,
            "nproc": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity")
                     else (os.cpu_count() or -1),
            "mem_total_kib": mem_kib,
        }

    def stage_environment(self) -> str:
        ev = self.read_environment()
        problems = environment_violations(
            ev["filesystems"],
            ev["load1"] if not ev["load1_error"] else float("inf"),
            V1_MIN_FREE_GIB, self.args.max_load1)
        if ev["load1_error"]:
            problems.append(ev["load1_error"])
        ev["violations"] = problems
        if not problems:
            return self.record("environment", PASS, ev)
        if self.args.allow_unquiet:
            self.qualification_grade = False
            ev["downgraded_by"] = "--allow-unquiet"
            ev["verdict"] = "WARN"
            ev["reason"] = ("; ".join(problems) +
                            " — DOWNGRADED to WARN by --allow-unquiet; this run "
                            "is NOT V1 qualification evidence "
                            "(qualification_grade: false)")
            for problem in problems:
                warn(f"environment: {problem}")
            return self.record("environment", PASS, ev, warn_flag=True)
        ev["reason"] = ("; ".join(problems) + " — V1 section 8(e) refuses a graded "
                        "leg on an unquiet host (--allow-unquiet to proceed "
                        "ungraded)")
        return self.record("environment", INVALID, ev)

    # -- stage b: pins (V1 section 3) -------------------------------------
    def stage_pins(self) -> str:
        argv = [sys.executable, "-m", "pytest", "-q", *V1_PIN_TESTS]
        log(f"pins: {' '.join(argv)}")
        rc, sout, serr = self.runner(argv, PYTEST_TIMEOUT, cwd=REPO_ROOT)
        tail = "\n".join((sout + serr).strip().splitlines()[-8:])
        ev: dict[str, Any] = {
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 3 (pinned digests)",
            "command": " ".join(argv), "returncode": rc, "tail": tail,
            "tests": list(V1_PIN_TESTS)}
        if rc != 0:
            ev["reason"] = (f"the V1 digest pins are not green (rc={rc}) — a "
                            f"changed scenario or profile registry re-bases every "
                            f"recorded number, so this build cannot be graded "
                            f"against V1")
            return self.record("pins", FAIL, ev)
        return self.record("pins", PASS, ev)

    # -- stage c: candidate ------------------------------------------------
    def replica_meta(self) -> list[dict[str, Any]]:
        rc, sout, serr = self.runner(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={self.args.project}",
             "--filter", "label=com.docker.compose.service=correlation"],
            DOCKER_TIMEOUT)
        if rc != 0:
            raise QualifyError(f"docker ps for correlation failed (rc={rc}): "
                               f"{(serr or sout).strip()[:300]}")
        reps: list[dict[str, Any]] = []
        for cid in sout.split():
            rc, insp, err = self.runner(
                ["docker", "inspect", cid, "--format",
                 ("{{.Name}}|{{.Image}}|{{.State.StartedAt}}|{{.State.Running}}|"
                  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")],
                DOCKER_TIMEOUT)
            if rc != 0 or "|" not in insp:
                raise QualifyError(f"docker inspect {cid[:12]} failed (rc={rc}): "
                                   f"{(err or insp).strip()[:200]}")
            name, image, started, running, ip = (insp.strip().split("|") + [""] * 5)[:5]
            reps.append({"container": cid, "short": cid[:12],
                         "name": name.lstrip("/"), "image": short_image(image),
                         "started_at": started, "running": running == "true",
                         "ip": ip})
        reps.sort(key=lambda r: str(r["name"]))
        return reps

    def api_meta(self) -> dict[str, Any]:
        rc, sout, serr = self.runner(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={self.args.project}",
             "--filter", "label=com.docker.compose.service=api"], DOCKER_TIMEOUT)
        if rc != 0 or not sout.split():
            return {"error": f"no api container in compose project "
                             f"{self.args.project!r} (rc={rc}): "
                             f"{(serr or sout).strip()[:200]}"}
        cid = sout.split()[0]
        rc, insp, err = self.runner(
            ["docker", "inspect", cid, "--format",
             ('{{.Image}}|{{index .Config.Labels '
              '"org.opencontainers.image.revision"}}|{{.State.StartedAt}}')],
            DOCKER_TIMEOUT)
        if rc != 0 or "|" not in insp:
            return {"error": f"docker inspect api failed (rc={rc}): "
                             f"{(err or insp).strip()[:200]}"}
        image, revision, started = (insp.strip().split("|") + [""] * 3)[:3]
        meta: dict[str, Any] = {"container": cid[:12], "image": short_image(image),
                                "oci_revision": revision or None,
                                "started_at": started, "built_at": None}
        rc, created, err = self.runner(
            ["docker", "image", "inspect", image.strip(), "--format", "{{.Created}}"],
            DOCKER_TIMEOUT)
        if rc == 0:
            meta["built_at"] = created.strip()
        else:
            meta["built_at_error"] = (err or created).strip()[:200]
        return meta

    def scrape_replica(self, rep: dict[str, Any]) -> tuple[str, str]:
        """One replica's /metrics over mTLS on :8443 — the A/B driver's probe,
        imported rather than copied so there is one transport definition."""
        probe = self.driver.Driver.METRICS_PROBE.format(ip=rep["ip"])
        rc, body, err = self.runner(
            ["docker", "exec", rep["container"], "python", "-c", probe],
            METRICS_TIMEOUT)
        if rc != 0:
            return "", (f"mTLS /metrics scrape of {rep['name']} at "
                        f"{rep['ip']}:8443 failed (rc={rc}): "
                        f"{self.driver.last_error_line(err)}")
        return body, ""

    def stage_candidate(self) -> str:
        ev: dict[str, Any] = {"project": self.args.project}
        try:
            reps = self.replica_meta()
        except QualifyError as exc:
            ev["reason"] = str(exc)
            return self.record("candidate", INVALID, ev)
        ev["correlation"] = [{k: v for k, v in rep.items() if k != "container"}
                             for rep in reps]
        ev["correlation_replicas"] = len(reps)
        ev["api"] = self.api_meta()

        rc, head, err = self.runner(["git", "rev-parse", "HEAD"], GIT_TIMEOUT,
                                    cwd=REPO_ROOT)
        ev["git_head"] = head.strip() if rc == 0 else None
        if rc != 0:
            ev["git_error"] = (err or head).strip()[:200]
        rc, porcelain, err = self.runner(["git", "status", "--porcelain"],
                                         GIT_TIMEOUT, cwd=REPO_ROOT)
        ev["git_dirty"] = bool(porcelain.strip()) if rc == 0 else None
        if rc == 0 and porcelain.strip():
            ev["git_dirty_files"] = len(porcelain.strip().splitlines())

        plane = env_value(self.args.env_file, "CORR_AGGREGATION_PLANE")
        ev["agg_plane"] = {
            "env_file": self.args.env_file,
            "value": plane,
            "resolved": plane if plane is not None else "1",
            "source": ("deployment/docker/.env" if plane is not None else
                       "unset in .env -> docker-compose.yml default "
                       "${CORR_AGGREGATION_PLANE:-1} (ON, a9d9a10c)"),
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 7 (plane ON)",
        }

        if self.args.skip_leg:
            ev["pre_run_metrics"] = None
            ev["pre_run_metrics_note"] = (
                "no PRE-run scrape: --skip-leg grades an already-completed leg, "
                "whose pre-run counters were never captured")
        else:
            errors = []
            for rep in reps:
                body, error = self.scrape_replica(rep)
                if error:
                    errors.append(error)
                    continue
                counters = agg_counters(body, self.driver.prom_value)
                counters["started_at"] = rep["started_at"]
                counters["name"] = rep["name"]
                self.pre_metrics[rep["short"]] = counters
            ev["pre_run_metrics"] = {k: dict(v) for k, v in self.pre_metrics.items()}
            if errors:
                ev["reason"] = ("; ".join(errors) + " — without a PRE-run capture "
                                "the V1 section 7 accounting can only be read "
                                "cumulatively, which is the caveat this stage "
                                "exists to remove")
                return self.record("candidate", INVALID, ev)

        self.candidate = ev
        write_text(os.path.join(self.args.run_dir, "candidate.json"),
                   json.dumps(ev, indent=1, sort_keys=True) + "\n")
        if len(reps) != 2:
            ev["reason"] = (f"{len(reps)} correlation replica(s) deployed; V1 "
                            f"section 2 qualifies 2 (one carrier + one idle)")
            return self.record("candidate", INVALID, ev)
        return self.record("candidate", PASS, ev)

    # -- stage d: the leg (V1 section 8(a)) -------------------------------
    def stage_leg(self) -> str:
        if self.args.skip_leg:
            self.leg_dir = self.args.skip_leg
            try:
                self.report = read_json(os.path.join(self.leg_dir, "report.json"))
            except QualifyError as exc:
                return self.record("leg", INVALID, {"reason": str(exc),
                                                    "run_dir": self.leg_dir})
            status, graded = grade_phases(self.report)
            graded["run_dir"] = self.leg_dir
            graded["source"] = "--skip-leg: graded from an already-completed leg"
            return self.record("leg", status, graded)

        self.leg_dir = self.args.run_dir
        argv = [sys.executable, HARNESS, "--profile", V1_PROFILE,
                "--devices", str(V1_DEVICES), "--eps", str(V1_EPS),
                "--run-dir", self.leg_dir]
        log_path = os.path.join(self.args.run_dir, "leg.log")
        log(f"leg: {' '.join(argv)} (streaming to {log_path}, bound {LEG_TIMEOUT}s)")
        rc, note = self.streamer(argv, log_path, LEG_TIMEOUT, REPO_ROOT)
        ev: dict[str, Any] = {"command": " ".join(argv), "returncode": rc,
                              "log": log_path, "run_dir": self.leg_dir,
                              "note": note,
                              "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md "
                                        "section 8(a) — all nine harness gates"}
        try:
            self.report = read_json(os.path.join(self.leg_dir, "report.json"))
        except QualifyError as exc:
            ev["reason"] = f"{exc} (harness rc={rc}, note={note})"
            return self.record("leg", INVALID, ev)
        status, graded = grade_phases(self.report)
        ev.update(graded)
        return self.record("leg", status, ev)

    # -- stage e: accuracy (V1 sections 4 + 5) ----------------------------
    def stage_accuracy(self) -> str:
        if not self.leg_dir or not self.report:
            return self.record("accuracy", SKIPPED,
                               {"reason": "no leg to score (the leg stage did "
                                          "not produce a report)"})
        path = os.path.join(self.leg_dir, "accuracy-report.json")
        ev: dict[str, Any] = {
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md sections 4 + 5",
            "report": path}
        if self.args.skip_leg and os.path.exists(path):
            ev["source"] = ("existing accuracy-report.json — a re-grade does NOT "
                            "re-score: the leg's ClickHouse corpus was purged by "
                            "its own cleanup phase, so a fresh scorer pass would "
                            "measure an empty store, not the leg")
        else:
            runid = str(self.report.get("runid") or "")
            if not runid:
                ev["reason"] = "report.json carries no runid — cannot score"
                return self.record("accuracy", INVALID, ev)
            link_err = self.ensure_runid_symlink(runid, self.leg_dir)
            if link_err:
                ev["reason"] = link_err
                return self.record("accuracy", INVALID, ev)
            run_root = os.path.dirname(os.path.normpath(self.leg_dir))
            argv = [sys.executable, TWIN, "--run-root", run_root,
                    "score", "--runid", runid]
            ev["command"] = " ".join(argv)
            log(f"accuracy: {' '.join(argv)}")
            rc, sout, serr = self.runner(argv, TWIN_TIMEOUT, cwd=REPO_ROOT)
            write_text(os.path.join(self.leg_dir, "twin-score.log"),
                       (sout or "") + (serr or ""))
            ev["returncode"] = rc
            if rc != 0:
                ev["reason"] = (f"twin scorer FAILED (rc={rc}): "
                                f"{(serr or sout).strip()[-400:]}")
                return self.record("accuracy", FAIL, ev)
        try:
            report = read_json(path)
        except QualifyError as exc:
            ev["reason"] = str(exc)
            return self.record("accuracy", INVALID, ev)
        status, graded = grade_accuracy(report)
        ev.update(graded)
        return self.record("accuracy", status, ev)

    def ensure_runid_symlink(self, runid: str, run_dir: str) -> str:
        """`<run-root>/x-<runid>` -> run dir; the scorer globs `*-<runid>` and a
        qualification run dir is named after the qualification, not the run id.
        Returns "" on success, or the reason it refuses."""
        root = os.path.dirname(os.path.normpath(run_dir))
        link = os.path.join(root, f"x-{runid}")
        target = os.path.realpath(run_dir)
        if os.path.islink(link):
            if os.path.realpath(link) != target:
                return (f"{link} already points at {os.path.realpath(link)}, not "
                        f"{target} — refusing to repoint another leg's scorer "
                        f"symlink")
            return ""
        if os.path.exists(link):
            return f"{link} exists and is not a symlink — refusing"
        try:
            os.symlink(target, link)
        except OSError as exc:
            return f"cannot create {link} -> {target} ({exc})"
        return ""

    # -- stage f: aggregation (V1 section 7) ------------------------------
    def stage_aggregation(self) -> str:
        ev: dict[str, Any] = {
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 7 "
                      "(observed == sum(forwarded{class}) + suppressed, exactly)",
            "per_leg_observed_expected": V1_PER_LEG_OBSERVED}
        if not self.pre_metrics:
            ev["reason"] = ("no PRE-run capture — this leg's counters can only be "
                            "read cumulatively since container start, which is "
                            "not a per-leg accounting. The baseline's cumulative "
                            "numbers are displayed for reference and graded on "
                            "nothing")
            ev["baseline_display_only"] = True
            return self.record("aggregation", SKIPPED, ev)
        try:
            reps = self.replica_meta()
        except QualifyError as exc:
            ev["reason"] = str(exc)
            return self.record("aggregation", INVALID, ev)
        per_replica: dict[str, Any] = {}
        errors: list[str] = []
        for rep in reps:
            body, error = self.scrape_replica(rep)
            if error:
                errors.append(error)
                continue
            post = agg_counters(body, self.driver.prom_value)
            post["started_at"] = rep["started_at"]
            post["name"] = rep["name"]
            pre = self.pre_metrics.get(rep["short"])
            if pre is None:
                per_replica[rep["short"]] = {
                    "status": INVALID,
                    "reason": f"replica {rep['name']} has no PRE-run capture "
                              f"(it appeared during the leg) — no delta exists"}
                continue
            per_replica[rep["short"]] = agg_delta(pre, post)
            per_replica[rep["short"]]["name"] = rep["name"]
        ev["per_replica"] = per_replica
        if errors:
            ev["scrape_errors"] = errors
            ev["reason"] = "; ".join(errors)
            return self.record("aggregation", INVALID, ev)
        statuses = {entry.get("status") for entry in per_replica.values()}
        if INVALID in statuses or not per_replica:
            ev["reason"] = "; ".join(
                str(entry.get("reason")) for entry in per_replica.values()
                if entry.get("status") == INVALID) or "no replica produced a delta"
            return self.record("aggregation", INVALID, ev)
        totals = {key: sum(float(entry.get(key, 0.0))
                           for entry in per_replica.values())
                  for key in ("observed", "forwarded_total", "suppressed")}
        totals["expected_observed"] = (totals["forwarded_total"] +
                                       totals["suppressed"])
        totals["exact"] = totals["observed"] == totals["expected_observed"]
        totals["suppressed_share_pct"] = (
            round(100.0 * totals["suppressed"] / totals["observed"], 2)
            if totals["observed"] else 0.0)
        ev["summed"] = totals
        if FAIL in statuses or not totals["exact"]:
            ev["reason"] = (f"summed observed {totals['observed']:.0f} != forwarded "
                            f"{totals['forwarded_total']:.0f} + suppressed "
                            f"{totals['suppressed']:.0f}"
                            if not totals["exact"] else
                            "; ".join(str(entry.get("reason"))
                                      for entry in per_replica.values()
                                      if entry.get("status") == FAIL))
            return self.record("aggregation", FAIL, ev)
        return self.record("aggregation", PASS, ev)

    # -- stage g: T1 (V1 section 8(b)) — published, never gated -----------
    def stage_ttur(self) -> str:
        ev: dict[str, Any] = {
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 8(b)",
            "metric": "T1 = time to first correlated version",
            "gated": False,
            "note": "PUBLISHED, NEVER GATED (V1 section 4 SLO). Not TTUR proper "
                    "— see tracker 205."}
        if not self.leg_dir or not self.report:
            ev["reason"] = "no leg to scope the query against"
            return self.record("ttur", SKIPPED, ev)
        tsv_path = os.path.join(self.leg_dir, "ttur.tsv")
        scope_path = os.path.join(self.leg_dir, "ttur-scope.json")
        if self.args.skip_leg and os.path.exists(tsv_path):
            ev["source"] = ("existing ttur.tsv — a re-grade does NOT re-query: "
                            "the leg's corpus was purged by its cleanup phase")
            try:
                ev["row"] = parse_ttur_tsv(read_text(tsv_path))
                if os.path.exists(scope_path):
                    ev["scope"] = read_json(scope_path).get("scope")
            except QualifyError as exc:
                ev["reason"] = str(exc)
                return self.record("ttur", SKIPPED, ev)
            self.publish_t1(ev)
            return self.record("ttur", PASS, ev)
        try:
            scope = self.driver.burst_scope(self.report)
            cid = self.driver.agg_cid(self.args.tenant)
            sql = self.driver.ttur_sql(scope, cid)
        except Exception as exc:      # noqa: BLE001 — DriverAbort or ValueError
            ev["reason"] = (f"cannot derive the V1 section 8(b) scope: {exc} — T1 "
                            f"is not published for this leg (it is not a gate)")
            return self.record("ttur", SKIPPED, ev)
        ev["scope"] = scope
        ev["excluded_agg_cid"] = cid
        rc, cids, err = self.runner(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={self.args.project}",
             "--filter", "label=com.docker.compose.service=clickhouse"],
            DOCKER_TIMEOUT)
        ids = cids.split() if rc == 0 else []
        if not ids:
            ev["reason"] = (f"no clickhouse container in project "
                            f"{self.args.project!r} (rc={rc}: "
                            f"{(err or cids).strip()[:200]}) — T1 not published")
            return self.record("ttur", SKIPPED, ev)
        rc, out, err = self.runner(
            ["docker", "exec", ids[0], "clickhouse-client", "--query", sql],
            CH_TIMEOUT)
        if rc != 0:
            ev["reason"] = f"clean-scope T1 query FAILED (rc={rc}): {err.strip()[:600]}"
            return self.record("ttur", SKIPPED, ev)
        try:
            ev["row"] = parse_ttur_tsv(out)
        except QualifyError as exc:
            ev["reason"] = str(exc)
            return self.record("ttur", SKIPPED, ev)
        write_text(tsv_path, out if out.endswith("\n") else out + "\n")
        write_text(scope_path, json.dumps(
            {"leg": os.path.basename(os.path.normpath(self.leg_dir)),
             "profile": V1_PROFILE, "arm": "ON", "tenant": self.args.tenant,
             "excluded_agg_cid": cid, "scope": scope, "sql": sql,
             "captured": utcnow()}, indent=1, sort_keys=True) + "\n")
        self.publish_t1(ev)
        return self.record("ttur", PASS, ev)

    def publish_t1(self, ev: dict[str, Any]) -> None:
        row = ev.get("row") or {}
        log(f"T1 (published, NOT gated): p50 {row.get('t1p50')}s / p95 "
            f"{row.get('t1p95')}s / p99 {row.get('t1p99')}s over "
            f"{row.get('inc')} incident(s)")

    # -- stage h: rebalance (a separate arc) ------------------------------
    def stage_rebalance(self) -> str:
        return self.record("rebalance", SKIPPED, {
            "reason": "the 155/199 disturbance clauses are a SEPARATE validation "
                      "arc (docs/scale/OWNERSHIP_155_VALIDATION_2026-08-31.md) "
                      "and scripts/lab/twin/ownership_runner.py exposes no CLI, "
                      "so nothing here can run them. V1 section 8(d) requires "
                      "only 'no unexpected replica ejection or restart', which "
                      "the harness `stability` gate already grades (0 "
                      "CommitFailed / 0 UnknownMember / 0 restarts / 0 "
                      "rebalances) and which is carried in the `leg` stage.",
            "clause": "CORRELIX_REFERENCE_CAPACITY_V1.md section 8(d)",
            "graded_elsewhere": "leg.phases.stability"})

    # -- stage i: baseline diff -------------------------------------------
    def candidate_numbers(self) -> dict[str, Any]:
        completion = phase_evidence(self.report, "correlation_completion")
        accounting = phase_evidence(self.report, "accounting")
        memflat = phase_evidence(self.report, "memflat")
        memory: dict[str, Any] = {}
        for entry in memflat.get("containers") or []:
            if isinstance(entry, dict) and entry.get("container"):
                memory[str(entry["container"])] = {
                    "ratio_vs_anchor": entry.get("ratio_vs_anchor"),
                    "pct_of_limit": entry.get("pct_of_limit")}
        accuracy_ev = self.evidence_of("accuracy")
        ttur_row = self.evidence_of("ttur").get("row") or {}
        agg_ev = self.evidence_of("aggregation")
        summed = agg_ev.get("summed") or {}
        return {
            "completion_s": completion.get("completed_at_s"),
            "corr_signal_rows": accounting.get("corr_signal_rows_run"),
            "memory": memory,
            "accuracy": accuracy_ev.get("accuracy"),
            "suppressed_share": summed.get("suppressed_share_pct"),
            "t1_p50": to_number(ttur_row.get("t1p50")),
            "t1_p95": to_number(ttur_row.get("t1p95")),
            "t1_p99": to_number(ttur_row.get("t1p99")),
        }

    def stage_baseline(self) -> str:
        ev: dict[str, Any] = {"baseline_path": self.args.baseline}
        try:
            baseline = read_json(self.args.baseline)
        except QualifyError as exc:
            ev["reason"] = (f"{exc} — regenerate it with --extract-baseline "
                            f"<run-dir>; it is never hand-typed")
            return self.record("baseline", INVALID, ev)
        ev["baseline_leg"] = baseline.get("leg")
        ev["baseline_runid"] = baseline.get("runid")
        ev["baseline_profile_version"] = baseline.get("profile_version")

        base_phases = baseline.get("phases") or {}
        cand_phases = self.evidence_of("leg").get("phases") or {}
        gated: list[dict[str, Any]] = []
        for name in V1_PHASES:
            gated.append({"clause": f"harness gate `{name}`",
                          "baseline": base_phases.get(name),
                          "candidate": cand_phases.get(name)})
        gated.append({"clause": "accuracy >= 0.93 on scorer v2",
                      "baseline": self.status_from_accuracy(baseline),
                      "candidate": self.status_of("accuracy")})
        ev["gated"] = gated
        regressions = [row for row in gated
                       if row["baseline"] == "PASS" and row["candidate"] != "PASS"]
        ev["gated_regressions"] = regressions

        base_numbers = {
            "completion_s": (baseline.get("harness") or {}).get("completion_s"),
            "corr_signal_rows": (baseline.get("harness") or {}).get(
                "corr_signal_rows_run"),
            "memory": (baseline.get("harness") or {}).get("memory") or {},
            "accuracy": (baseline.get("accuracy") or {}).get("accuracy"),
            "suppressed_share": (baseline.get("aggregation") or {}).get(
                "suppressed_share_pct"),
            "t1_p50": to_number((baseline.get("t1") or {}).get("p50_s")),
            "t1_p95": to_number((baseline.get("t1") or {}).get("p95_s")),
            "t1_p99": to_number((baseline.get("t1") or {}).get("p99_s")),
        }
        ev["informational"] = informational_rows(self.candidate_numbers(),
                                                 base_numbers)
        ev["informational_note"] = (
            "REPORTED, NEVER GATED. V1 says so for T1 p95; completion, memory "
            "and the suppressed share follow the same rule because the gates "
            "are the harness's own clauses, already graded in `leg`.")
        if self.status_of("aggregation") == SKIPPED:
            ev["aggregation_display_only"] = baseline.get("aggregation")
        if regressions:
            ev["reason"] = ("gated clause(s) that PASS on the baseline do not on "
                            "this candidate: " +
                            ", ".join(f"{r['clause']} ({r['candidate'] or 'n/a'})"
                                      for r in regressions))
            return self.record("baseline", FAIL, ev)
        return self.record("baseline", PASS, ev)

    @staticmethod
    def status_from_accuracy(baseline: dict[str, Any]) -> str:
        acc = (baseline.get("accuracy") or {})
        try:
            ok = (int(acc.get("scorer_version", -1)) == V1_SCORER_VERSION and
                  float(acc.get("accuracy", -1.0)) >= V1_MIN_ACCURACY)
        except (TypeError, ValueError):
            return INVALID
        return PASS if ok else FAIL

    # -- stage j: verdict --------------------------------------------------
    def stage_verdict(self) -> str:
        verdict = overall_verdict(self.records)
        corr_images = [r.get("image") for r in
                       (self.candidate.get("correlation") or [])]
        # Two replicas of ONE image is the V1 deployment contract, so the
        # summary names the image once; a MIXED pair is a real condition and is
        # printed in full rather than collapsed.
        distinct = sorted({str(i) for i in corr_images if i})
        corr_short = "/".join(distinct) or "unknown"
        api_short = str((self.candidate.get("api") or {}).get("image") or "unknown")
        runid = str(self.report.get("runid") or "unknown")
        doc = {
            "schema": "correlix.release-qualify/1",
            "profile_version": "CORRELIX_REFERENCE_CAPACITY_V1",
            "profile_document": "docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md",
            "generated": utcnow(),
            "verdict": verdict,
            "qualification_grade": self.qualification_grade,
            "runid": runid,
            "run_dir": self.args.run_dir,
            "leg_dir": self.leg_dir,
            "baseline": self.args.baseline,
            "candidate": {"correlation": corr_images,
                          "correlation_distinct": distinct, "api": api_short,
                          "git_head": self.candidate.get("git_head"),
                          "git_dirty": self.candidate.get("git_dirty")},
            "stages": self.records,
        }
        write_text(os.path.join(self.args.run_dir, "qualification.json"),
                   json.dumps(doc, indent=1, sort_keys=True) + "\n")
        write_text(os.path.join(self.args.run_dir, "qualification.md"),
                   render_markdown(doc, self.records))
        self.summary = doc
        baseline_leg = (self.evidence_of("baseline").get("baseline_leg") or
                        os.path.basename(self.args.baseline))
        print(f"QUALIFICATION {verdict} run {runid} candidate "
              f"{corr_short}/{api_short} baseline {baseline_leg}", flush=True)
        if not self.qualification_grade:
            warn("qualification_grade: false — the environment clause was "
                 "downgraded by --allow-unquiet; this result is NOT V1 "
                 "qualification evidence")
        return verdict

    # -- the run -----------------------------------------------------------
    def execute(self) -> int:
        os.makedirs(self.args.run_dir, exist_ok=True)
        if self.stage_environment() == INVALID:
            self.finish_early()
            return 2
        for stage in (self.stage_pins, self.stage_candidate):
            if stage() == INVALID:
                self.finish_early()
                return 2
        if self.status_of("pins") != PASS:
            # A red digest pin means the candidate is not comparable to V1 at
            # all; running an hour-long leg against a moved scenario would
            # produce numbers that mean nothing. Stop, report, exit FAIL.
            self.stage_rebalance()
            self.stage_verdict()
            return 1
        self.stage_leg()
        self.stage_accuracy()
        self.stage_aggregation()
        self.stage_ttur()
        self.stage_rebalance()
        self.stage_baseline()
        verdict = self.stage_verdict()
        return {PASS: 0, FAIL: 1}.get(verdict, 2)

    def finish_early(self) -> None:
        """A short-circuit still writes the record: an INVALID that leaves no
        artifact is indistinguishable from a run that never happened."""
        self.stage_verdict()


def to_number(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return value


def env_value(env_file: str, key: str) -> str | None:
    """First `KEY=` value in the compose .env, or None when the key is unset.

    THREE-VALUED, and only three-valued. A MISSING .env is meaningful (compose
    supplies its own default) and reads as None, which the caller reports
    together with the resolved value and its source — that is a read, not a
    swallowed error. An .env that EXISTS and cannot be READ is a different
    thing entirely: reporting a permission error as "unset -> compose default"
    would publish a default the file may well contradict, on the very clause
    (V1 section 7, aggregation plane ON) the evidence is meant to prove. So it
    escalates (16.1) — `main` turns the QualifyError into a rc-2 refusal.
    """
    try:
        with open(env_file, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(key + "="):
                    return line.rstrip("\n").split("=", 1)[1]
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise QualifyError(f"cannot read {env_file} for {key} ({exc}) — an "
                           f"unreadable .env is not an unset key") from exc
    return None


def nearest_existing(path: str) -> str:
    """The closest existing ancestor of `path` — a run dir that does not exist
    yet still has a filesystem whose headroom must be measured."""
    current = os.path.abspath(path)
    while current and not os.path.exists(current):
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return current or "/"


def stream_process(argv: list[str], log_path: str, timeout: int,
                   cwd: str) -> tuple[int, str]:
    """Run `argv`, relaying its output to stdout AND `log_path`, bounded.

    The leg is an hour of unattended work, so its output must be visible while
    it runs, not only after. The deadline is enforced on the read loop (a child
    that goes silent is still bounded) and the child is terminated, then killed,
    never `pkill`-ed by pattern.
    """
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                text=True, bufsize=1, cwd=cwd)
    except (OSError, ValueError) as exc:
        return 127, f"cannot execute {argv[0]!r}: {exc}"
    note = "completed"
    try:
        with open(log_path, "w", encoding="utf-8") as fh:
            assert proc.stdout is not None
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    note = f"TIMEOUT after {timeout}s — child terminated"
                    break
                ready, _, _ = select.select([proc.stdout], [], [],
                                            min(LEG_READ_TIMEOUT, remaining))
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                line = proc.stdout.readline()
                if not line:
                    break
                fh.write(line)
                fh.flush()
                sys.stdout.write(line)
                sys.stdout.flush()
    except OSError as exc:
        # BEST-EFFORT, deliberately, and LOUD (16.1). The child is an hour of
        # unattended work that is already running and whose real evidence is
        # its own report.json, not this relay — killing it because the log
        # sink broke would destroy more than it protects. So the relay stops,
        # the reason is warned to stderr AND returned as the leg's `note`,
        # which lands in the evidence record beside the return code.
        note = f"log relay failed: {exc} — leg.log is TRUNCATED from here"
        warn(f"leg: {note}")
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)
    return proc.returncode if proc.returncode is not None else 124, note


def render_markdown(doc: dict[str, Any], records: list[dict[str, Any]]) -> str:
    lines = [
        f"# CORRELIX REFERENCE CAPACITY V1 — qualification {doc['verdict']}",
        "",
        (f"- **Verdict: {doc['verdict']}** "
         f"(qualification_grade: `{doc['qualification_grade']}`)"),
        f"- Generated: {doc['generated']}",
        f"- Profile: `{doc['profile_version']}` ({doc['profile_document']})",
        f"- Run: `{doc['runid']}` — leg dir `{doc['leg_dir']}`",
        (f"- Candidate: correlation "
         f"`{'/'.join(doc['candidate']['correlation_distinct'])}`, "
         f"api `{doc['candidate']['api']}`, git `{doc['candidate']['git_head']}` "
         f"(dirty: `{doc['candidate']['git_dirty']}`)"),
        f"- Baseline: `{doc['baseline']}`",
        "",
        "## Stages",
        "",
        "| Stage | Status | Note |",
        "|---|---|---|",
    ]
    for entry in records:
        status = entry["status"] + (" ⚠ WARN" if entry.get("warn") else "")
        ev = entry.get("evidence") or {}
        note = str(ev.get("reason") or ev.get("source") or ev.get("clause") or "")
        lines.append(f"| `{entry['stage']}` | {status} | {note.replace('|', '/')} |")
    lines += ["",
              ("SKIPPED means NOT MEASURED, with the reason above — it never "
               "counts as evidence and never fails the run. INVALID means the "
               "measurement itself cannot be trusted."), ""]

    baseline: dict[str, Any] = next(
        (r["evidence"] for r in records if r["stage"] == "baseline"), {})
    gated = baseline.get("gated") or []
    if gated:
        lines += [(f"## Gated clauses vs the V1 reference "
                   f"(`{baseline.get('baseline_leg') or '?'}`, run "
                   f"`{baseline.get('baseline_runid') or '?'}`)"), "",
                  "| Clause | V1 reference | This candidate | |", "|---|---|---|---|"]
        for row in gated:
            same = row.get("baseline") == row.get("candidate")
            mark = ("=" if same else
                    ("REGRESSION" if row.get("baseline") == PASS else "differs"))
            lines.append(f"| {row['clause']} | {row.get('baseline') or 'n/a'} "
                         f"| {row.get('candidate') or 'n/a'} | {mark} |")
        lines += ["", ("A clause that PASSES on the V1 reference and does not "
                       "here is a REGRESSION and fails the qualification."), ""]
    rows = baseline.get("informational") or []
    if rows:
        lines += ["## Informational deltas (REPORTED, NEVER GATED)", "",
                  "| Metric | Candidate | Baseline | Δ | Note |", "|---|--:|--:|--:|---|"]
        for row in rows:
            lines.append(
                f"| {row['metric']}{(' (' + row['unit'] + ')') if row['unit'] else ''} "
                f"| {row['candidate']} | {row['baseline']} | {row['delta']} "
                f"| {row['note']} |")
        lines += ["", str(baseline.get("informational_note") or ""), ""]

    ttur: dict[str, Any] = next(
        (r["evidence"] for r in records if r["stage"] == "ttur"), {})
    row = ttur.get("row") or {}
    if row:
        lines += ["## T1 — time to first correlated version (published, not gated)",
                  "",
                  (f"- p50 **{row.get('t1p50')} s**, p95 "
                   f"**{row.get('t1p95')} s**, p99 **{row.get('t1p99')} s**, "
                   f"max {row.get('t1max')} s over {row.get('inc')} incident(s), "
                   f"{row.get('versions')} version(s), {row.get('sigs')} "
                   f"signal(s)"),
                  ("- V1 section 4: T1 p95 is measured and published every run "
                   "but is NOT a pass/fail gate. T1 is an engineering lifecycle "
                   "metric, not TTUR proper (tracker 205)."), ""]
    lines += ["",
              ("Semantic changes to any V1 clause require a **V2 profile** "
               "(`CORRELIX_REFERENCE_CAPACITY_V2.md`), never an edit to V1 or a "
               "flag on `release-qualify.py`."), ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# self-test — the suite proving its OWN logic, with no rig in the room
# ---------------------------------------------------------------------------
# WHY THIS EXISTS. The qualification itself needs an hour of exclusive rig time
# and is owner-gated, so between rig legs there is nothing to tell a change
# that broke this grader from one that did not. The self-test closes that gap:
# it re-grades the CHECKED-IN `storm-s11` leg — the V1 baseline of record — and
# then re-grades MUTATED copies of it, asserting BOTH directions. A grader that
# has stopped detecting a regressed gate, an accuracy miss, a scorer downgrade,
# an aggregation that does not close or a replica that restarted mid-run fails
# here, in CI, on a laptop, in seconds.
#
# WHAT IT IS NOT: qualification evidence. It measures a fixture, not a build.
SELF_TEST_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "storm-s11")
SELF_TEST_IMAGE = "sha256:23dc2b88e966f000988a9d04be1f88d385b6aa9866045d"


def self_test_docker(cmd: list[str], timeout: int,
                     cwd: str | None = None) -> tuple[int, str, str]:
    """The ONLY command the graded path may shell out to is the baseline
    extractor's `docker inspect` for a replica's image id. Anything else is a
    self-test failure, not a silent fallback: it would mean the grader reaches
    for a stack that CI does not have."""
    if cmd[:2] == ["docker", "inspect"]:
        return 0, SELF_TEST_IMAGE + "\n", ""
    return 127, "", f"self-test: the grading path must not run {' '.join(cmd)!r}"


def self_test_args(args: argparse.Namespace, **over: Any) -> argparse.Namespace:
    """The SAME namespace shape a real run carries — copied from the parsed
    args so a new flag cannot leave the self-test grading a different object."""
    ns = argparse.Namespace(**vars(args))
    ns.self_test = False
    ns.dry_run = False
    for key, value in over.items():
        setattr(ns, key, value)
    return ns


class SelfTestLog:
    """Ordered checks with a one-line reason each. No check is allowed to be
    silent: an exception is recorded as a failure, never swallowed."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""), flush=True)
        return bool(ok)

    @property
    def failures(self) -> list[tuple[str, bool, str]]:
        return [r for r in self.rows if not r[1]]


def self_test(args: argparse.Namespace) -> int:
    """Exit 0 when every check holds, 1 when one does not, 2 when the fixture
    the self-test needs is missing (an unrunnable self-test is never a pass)."""
    if not os.path.isdir(SELF_TEST_FIXTURE):
        print(f"release-qualify: ERROR: self-test fixture missing: "
              f"{SELF_TEST_FIXTURE}", file=sys.stderr, flush=True)
        return 2
    try:
        driver = load_ab_driver()
    except QualifyError as exc:
        print(f"release-qualify: ERROR: {exc}", file=sys.stderr, flush=True)
        return 2

    log_ = SelfTestLog()
    print(f"release-qualify SELF-TEST — grading the checked-in "
          f"{os.path.basename(SELF_TEST_FIXTURE)} fixture and mutations of it. "
          f"No stack, no rig, no .env.", flush=True)
    with tempfile.TemporaryDirectory(prefix="release-qualify-selftest-") as tmp:
        leg = os.path.join(tmp, "leg")
        shutil.copytree(SELF_TEST_FIXTURE, leg)
        base_path = os.path.join(tmp, "baseline.json")
        fresh = extract_baseline(leg, runner=self_test_docker, driver=driver)
        write_text(base_path, dump_baseline(fresh))

        # ── the shipped V1 reference numbers are the fixture's own ──────────
        try:
            shipped = read_json(args.baseline)
        except QualifyError as exc:
            shipped = {}
            log_.check("shipped V1 baseline is readable", False, str(exc))
        if shipped:
            drift = [key for key in ("runid", "workload", "phases", "overall",
                                     "accuracy", "t1", "harness", "aggregation")
                     if shipped.get(key) != fresh.get(key)]
            log_.check("shipped V1 baseline == a fresh extraction of the leg "
                       "of record (never hand-typed)", not drift,
                       f"{os.path.basename(args.baseline)}"
                       + (f"; drifted: {', '.join(drift)}" if drift else ""))
            log_.check("extraction is byte-stable (a re-run diffs clean)",
                       dump_baseline(fresh) == dump_baseline(
                           extract_baseline(leg, runner=self_test_docker,
                                            driver=driver)))

        # ── direction 1: the leg of record grades PASS ──────────────────────
        run_dir = os.path.join(tmp, "qualify")
        os.makedirs(run_dir, exist_ok=True)
        good = Qualifier(self_test_args(args, run_dir=run_dir, skip_leg=leg,
                                        baseline=base_path, allow_unquiet=True),
                         runner=self_test_docker, driver=driver)
        leg_status = good.stage_leg()
        leg_ev = good.evidence_of("leg")
        log_.check("leg: all nine V1 harness gates PASS",
                   leg_status == PASS and
                   (leg_ev.get("phases_passed"), leg_ev.get("phases_total"))
                   == (len(V1_PHASES), len(V1_PHASES)),
                   f"{leg_ev.get('phases_passed')}/{leg_ev.get('phases_total')} "
                   f"run {leg_ev.get('runid')}")
        acc_status = good.stage_accuracy()
        acc_ev = good.evidence_of("accuracy")
        log_.check(f"accuracy: >= {V1_MIN_ACCURACY} on scorer v{V1_SCORER_VERSION}",
                   acc_status == PASS and
                   acc_ev.get("scorer_version") == V1_SCORER_VERSION,
                   f"{acc_ev.get('stories_passed')}/{acc_ev.get('stories_total')}")
        agg_status = good.stage_aggregation()
        log_.check("aggregation: SKIPPED (no PRE-run capture for a historical "
                   "leg) — not measured is not passed", agg_status == SKIPPED,
                   str(good.evidence_of("aggregation").get("reason", ""))[:90])
        ttur_status = good.stage_ttur()
        log_.check("T1: published, never gated",
                   ttur_status == PASS and
                   bool((good.evidence_of("ttur").get("row") or {}).get("t1p95")),
                   f"p95 {(good.evidence_of('ttur').get('row') or {}).get('t1p95')} s")
        log_.check("rebalance: SKIPPED with the 155/199 reason recorded",
                   good.stage_rebalance() == SKIPPED,
                   str(good.evidence_of("rebalance").get("reason", ""))[:90])
        base_status = good.stage_baseline()
        log_.check("baseline diff: no gated regression against the V1 reference",
                   base_status == PASS and
                   good.evidence_of("baseline").get("gated_regressions") == [])
        good.candidate = {"correlation": [{"image": short_image(SELF_TEST_IMAGE)}],
                          "api": {"image": "selftest"}}
        verdict = good.stage_verdict()
        report_md = os.path.join(run_dir, "qualification.md")
        report_json = os.path.join(run_dir, "qualification.json")
        md = read_text(report_md) if os.path.exists(report_md) else ""
        log_.check("verdict: PASS on the leg of record", verdict == PASS)
        log_.check("a dated report is written (json + md), per-clause against "
                   "the V1 reference",
                   os.path.exists(report_json) and "Generated:" in md and
                   "Gated clauses vs the V1 reference" in md and
                   "NOT a pass/fail gate" in md)

        # ── direction 2: each mutation must be CAUGHT ───────────────────────
        bad_leg = os.path.join(tmp, "leg-regressed")
        shutil.copytree(SELF_TEST_FIXTURE, bad_leg)
        report = read_json(os.path.join(bad_leg, "report.json"))
        for phase in report.get("phases", []):
            if phase.get("phase") == "memflat":
                phase["status"] = FAIL
        write_text(os.path.join(bad_leg, "report.json"), json.dumps(report))
        bad_dir = os.path.join(tmp, "qualify-regressed")
        os.makedirs(bad_dir, exist_ok=True)
        bad = Qualifier(self_test_args(args, run_dir=bad_dir, skip_leg=bad_leg,
                                       baseline=base_path, allow_unquiet=True),
                        runner=self_test_docker, driver=driver)
        bad_leg_status = bad.stage_leg()
        bad.stage_accuracy()
        bad_base_status = bad.stage_baseline()
        regressed = [r["clause"] for r in
                     bad.evidence_of("baseline").get("gated_regressions", [])]
        log_.check("MUTATION a regressed harness gate fails the leg AND the "
                   "baseline diff",
                   bad_leg_status == FAIL and bad_base_status == FAIL and
                   regressed == ["harness gate `memflat`"], ", ".join(regressed))
        bad.candidate = {"correlation": [], "api": {}}
        log_.check("a failed clause makes the whole verdict FAIL (exit 1)",
                   bad.stage_verdict() == FAIL)

        acc_doc = read_json(os.path.join(leg, "accuracy-report.json"))
        under = dict(acc_doc, accuracy_slo=V1_MIN_ACCURACY - 0.01)
        v1_scorer = dict(acc_doc, scorer_version=1, accuracy_slo=1.0)
        no_acc = {k: v for k, v in acc_doc.items() if k != "accuracy_slo"}
        log_.check(f"MUTATION accuracy {under['accuracy_slo']:.2f} < "
                   f"{V1_MIN_ACCURACY} is a FAIL",
                   grade_accuracy(under)[0] == FAIL)
        log_.check("MUTATION a perfect score on scorer v1 is still a FAIL "
                   "(V1 pins the scorer, not just the number)",
                   grade_accuracy(v1_scorer)[0] == FAIL)
        log_.check("MUTATION a missing accuracy is a FAIL, never a silent zero",
                   grade_accuracy(no_acc)[0] == FAIL)

        closed = {"enabled": 1.0, "observed": 100.0, "suppressed": 30.0,
                  "forwarded_by_class": {"first": 60.0, "repeat": 10.0},
                  "forwarded_total": 70.0, "started_at": "T0", "name": "rep"}
        pre = dict(closed, observed=0.0, suppressed=0.0, forwarded_total=0.0,
                   forwarded_by_class={"first": 0.0, "repeat": 0.0})
        open_ = dict(closed, suppressed=29.0)
        restarted = dict(closed, started_at="T1")
        log_.check("aggregation accounting closes exactly on a good delta",
                   agg_delta(pre, closed)["status"] == PASS)
        log_.check("MUTATION a delta that does not close is a FAIL",
                   agg_delta(pre, open_)["status"] == FAIL)
        log_.check("MUTATION a replica that restarted mid-run is INVALID, "
                   "never a false PASS",
                   agg_delta(pre, restarted)["status"] == INVALID)

        quiet_fs = [{"path": "/", "free_gib": V1_MIN_FREE_GIB + 5, "error": ""}]
        small_fs = [{"path": "/", "free_gib": V1_MIN_FREE_GIB - 1, "error": ""}]
        blind_fs = [{"path": "/", "free_gib": None, "error": "statvfs failed"}]
        log_.check("environment: a quiet host has no violation",
                   environment_violations(quiet_fs, 1.0, V1_MIN_FREE_GIB, 6.0) == [])
        log_.check("MUTATION too little disk refuses the run",
                   bool(environment_violations(small_fs, 1.0, V1_MIN_FREE_GIB, 6.0)))
        log_.check("MUTATION an unquiet host refuses the run",
                   bool(environment_violations(quiet_fs, 9.9, V1_MIN_FREE_GIB, 6.0)))
        log_.check("MUTATION an UNREADABLE filesystem is a violation, not a pass",
                   bool(environment_violations(blind_fs, 1.0, V1_MIN_FREE_GIB, 6.0)))

        rec = [{"stage": "a", "status": PASS}, {"stage": "b", "status": SKIPPED}]
        log_.check("SKIPPED never fails a run and never counts as evidence",
                   overall_verdict(rec) == PASS)
        log_.check("one FAIL fails the run",
                   overall_verdict(rec + [{"stage": "c", "status": FAIL}]) == FAIL)
        log_.check("INVALID beats FAIL — an untrusted measurement is not a verdict",
                   overall_verdict(rec + [{"stage": "c", "status": FAIL},
                                          {"stage": "d", "status": INVALID}])
                   == INVALID)
        log_.check("an all-SKIPPED run is INVALID, never PASS",
                   overall_verdict([{"stage": "a", "status": SKIPPED}]) == INVALID)

        seen: dict[str, Any] = {}

        def capture(argv: list[str], log_path: str, timeout: int,
                    cwd: str | None = None) -> tuple[int, str]:
            seen["argv"] = list(argv)
            return 0, "captured"

        frozen_dir = os.path.join(tmp, "qualify-argv")
        os.makedirs(frozen_dir, exist_ok=True)
        Qualifier(self_test_args(args, run_dir=frozen_dir, skip_leg="",
                                 baseline=base_path),
                  runner=self_test_docker, driver=driver,
                  streamer=capture).stage_leg()
        expected = ["--profile", V1_PROFILE, "--devices", str(V1_DEVICES),
                    "--eps", str(V1_EPS)]
        argv = seen.get("argv") or []
        log_.check("the leg is launched with the FROZEN V1 parameters and "
                   "nothing else (no flag can silently re-base V1)",
                   argv[2:2 + len(expected)] == expected and
                   argv[1].endswith("scale-miniladder.py"),
                   " ".join(argv[2:]) if argv else "no argv captured")

    total = len(log_.rows)
    bad_rows = log_.failures
    print(flush=True)
    if bad_rows:
        print(f"SELF-TEST FAIL — {len(bad_rows)} of {total} checks failed: "
              + "; ".join(name for name, _ok, _d in bad_rows), flush=True)
        return 1
    print(f"SELF-TEST PASS — {total}/{total} checks. The SUITE's logic is "
          f"proven; this is not qualification evidence and grades no build.",
          flush=True)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def default_run_dir() -> str:
    return os.path.join(DEFAULT_RUN_ROOT,
                        "qualify-" + datetime.now(timezone.utc).strftime("%m%d%H%M"))


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="release-qualify.py",
        description="Rerun the CORRELIX REFERENCE CAPACITY V1 qualification on "
                    "the deployed build and grade every clause.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="V1 semantics are FROZEN: a different workload, seed, digest, "
               "cap, gate or scorer is a V2 profile, never a flag here.")
    ap.add_argument("--run-dir", default="",
                    help="where qualification.{json,md} land (default "
                         "/var/tmp/scale-runs/qualify-<UTC stamp>)")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help=f"the V1 baseline JSON (default {DEFAULT_BASELINE})")
    ap.add_argument("--max-load1", type=float, default=DEFAULT_MAX_LOAD1,
                    help=f"host load1 bound for the V1 section 8(e) quiet-host "
                         f"clause (default {DEFAULT_MAX_LOAD1})")
    ap.add_argument("--allow-unquiet", action="store_true",
                    help="downgrade the section 8(e) refusal to a recorded WARN "
                         "and mark the result qualification_grade: false")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and the environment reading; run nothing")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the SUITE's own logic against the checked-in "
                         "storm-s11 leg fixture and mutations of it — no stack, "
                         "no rig, no .env (CI runs this). Never qualification "
                         "evidence")
    ap.add_argument("--extract-baseline", metavar="RUN_DIR", default="",
                    help="write the machine-readable baseline for a finished run "
                         "dir to --baseline and exit")
    ap.add_argument("--skip-leg", metavar="RUN_DIR", default="",
                    help="grade an already-completed leg's run dir instead of "
                         "running one")
    ap.add_argument("--project", default="",
                    help="compose project (default COMPOSE_PROJECT_NAME from "
                         "the env file, else 'netops')")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE,
                    help=f"compose env file (default {DEFAULT_ENV_FILE})")
    ap.add_argument("--tenant", default=DEFAULT_TENANT,
                    help=f"tenant whose storm-aggregate cid the T1 query excludes "
                         f"(default {DEFAULT_TENANT!r})")
    args = ap.parse_args(argv)
    if args.extract_baseline and args.skip_leg:
        ap.error("--extract-baseline and --skip-leg are different jobs; pass one")
    if args.self_test and (args.dry_run or args.skip_leg or args.extract_baseline):
        ap.error("--self-test grades a fixture; it takes no leg, plan or "
                 "extraction job")
    if not args.run_dir:
        args.run_dir = default_run_dir()
    args.run_dir = os.path.abspath(args.run_dir)
    if args.skip_leg:
        args.skip_leg = os.path.abspath(args.skip_leg)
        if not os.path.isdir(args.skip_leg):
            ap.error(f"--skip-leg {args.skip_leg!r} is not a directory")
    if args.extract_baseline:
        args.extract_baseline = os.path.abspath(args.extract_baseline)
        if not os.path.isdir(args.extract_baseline):
            ap.error(f"--extract-baseline {args.extract_baseline!r} is not a "
                     f"directory")
    if not args.project and args.self_test:
        # The self-test issues no docker command that a project scopes, and CI
        # has no .env at all (it is generated at install and gitignored). A
        # missing file must not make the suite's own proof unrunnable.
        args.project = "self-test"
    if not args.project:
        # An unreadable .env must not silently become the default project name:
        # every docker command this tool issues is scoped by it, so guessing
        # would point the whole qualification at the wrong compose project.
        try:
            args.project = env_value(
                args.env_file, "COMPOSE_PROJECT_NAME") or "netops"
        except QualifyError as exc:
            ap.error(str(exc))
    return args


def print_plan(args: argparse.Namespace, env: dict[str, Any]) -> None:
    print("release-qualify DRY RUN — nothing will be touched")
    print(f"  profile        : {V1_PROFILE} (frozen V1: {V1_DEVICES} devices, "
          f"{V1_EPS} eps, 15 min burst, seed {V1_SEED})")
    print(f"  run dir        : {args.run_dir}")
    print(f"  baseline       : {args.baseline}")
    print(f"  compose project: {args.project} (env {args.env_file})")
    print(f"  leg            : {'GRADE ' + args.skip_leg if args.skip_leg else 'RUN'}"
          f" — python3 scripts/scale-miniladder.py --profile {V1_PROFILE} "
          f"--devices {V1_DEVICES} --eps {V1_EPS} --run-dir <run-dir>")
    print("  stages         : environment(8e) -> pins(3) -> candidate -> leg(8a) "
          "-> accuracy(4,5) -> aggregation(7) -> ttur(8b, published not gated) "
          "-> rebalance(SKIPPED) -> baseline -> verdict")
    print("  environment reading (V1 section 8(e)):")
    for fs in env["filesystems"]:
        if fs.get("error"):
            print(f"    {fs['path']:<24} UNREADABLE: {fs['error']}")
        else:
            print(f"    {fs['path']:<24} {fs['free_gib']:.1f} GiB free of "
                  f"{fs['total_gib']:.1f} GiB")
    print(f"    load1                    {env['load1']} (bound {env['max_load1']})")
    print(f"    nproc                    {env['nproc']}")
    print(f"    MemTotal                 {env['mem_total_kib']} kB")
    problems = environment_violations(env["filesystems"], env["load1"],
                                      V1_MIN_FREE_GIB, env["max_load1"])
    print(f"    verdict                  "
          f"{'QUIET (would proceed)' if not problems else 'REFUSE: ' + '; '.join(problems)}")
    print("  V1 semantics are FROZEN — a semantic change needs a V2 profile.")


def main(argv: list[str]) -> int:
    os.environ["PATH"] = CRON_PATH          # see CRON_PATH: process-entry only
    args = parse_args(argv)

    if args.extract_baseline:
        try:
            doc = extract_baseline(args.extract_baseline)
        except QualifyError as exc:
            print(f"release-qualify: ERROR: {exc}", file=sys.stderr, flush=True)
            return 2
        os.makedirs(os.path.dirname(os.path.abspath(args.baseline)), exist_ok=True)
        write_text(args.baseline, dump_baseline(doc))
        log(f"baseline written: {args.baseline} (leg {doc.get('leg')}, run "
            f"{doc.get('runid')})")
        return 0

    if args.self_test:
        return self_test(args)

    qualifier = Qualifier(args)
    if args.dry_run:
        print_plan(args, qualifier.read_environment())
        return 0
    try:
        return qualifier.execute()
    except QualifyError as exc:
        print(f"release-qualify: ERROR: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
