# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stability gate for a compose stack: success means STABLE, not sampled.

Installer self-healing FMEA 2026-09-15 §4.7 / §2 #5. A single `docker compose ps`
sample reads `running` for a JVM that restarts every 20 s (Keycloak on .123 had
RestartCount=106 and still said "Up 17 seconds"). This gate records every
container of the project twice, W seconds apart, and fails when, inside that
window, any long-running container:

  * restarted (RestartCount grew),
  * (re)started at all (StartedAt falls inside the window),
  * was created, recreated or removed (its container id appeared/vanished),
  * is not `running`, is `restarting`, or reports health `unhealthy` at the end.

One-shot containers (compose service `*-init`, or restart policy `no`) must
instead have EXITED with code 0 by the end of the window.

A health status still `starting` at the end is reported as a warning, not a
failure: it is not evidence of a crash, and failing on it would make the gate
flaky on a slow runner. An empty project is a failure — a gate that inspected
nothing proved nothing.

Exit codes: 0 stable · 1 not stable · 2 could not assess (docker unreachable,
unparseable output).

Usage (CI):
  python3 stack_stability.py --project netops --window 60 \\
      [--save-services FILE] [--baseline-services FILE]

`--save-services` records the long-running / one-shot service sets seen at the
end; `--baseline-services` asserts that no service in a previously saved set
went missing (a re-run must not lose a service).

Standard library only. Docker sits behind an injected runner so the policy is
tested with fake `docker inspect` JSON (tests/test_ci_stack_stability.py).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

SERVICE_LABEL = "com.docker.compose.service"
PROJECT_LABEL = "com.docker.compose.project"
DOCKER_TIMEOUT_S = 60
# Docker's zero time for a container that never started.
_ZERO_TIME_PREFIX = "0001-01-01"


class AssessError(Exception):
    """The gate could not observe the stack (exit code 2)."""


@dataclass(frozen=True)
class Container:
    id: str
    name: str
    service: str
    status: str
    restarting: bool
    exit_code: int
    restart_count: int
    started_at: datetime | None
    health: str
    restart_policy: str

    @property
    def one_shot(self) -> bool:
        return self.service.endswith("-init") or self.restart_policy == "no"


@dataclass(frozen=True)
class Verdict:
    problems: list[str]
    warnings: list[str]
    long_running: list[str]
    one_shots: list[str]

    @property
    def stable(self) -> bool:
        return not self.problems


def parse_docker_time(raw: str) -> datetime | None:
    """Parse Docker's RFC 3339 timestamps (nanosecond precision, `Z` or offset).

    Returns None for Docker's zero time (never started). Raises ValueError on
    anything else it cannot read — a timestamp we cannot parse must not be
    silently treated as "outside the window"."""
    if not isinstance(raw, str) or not raw or raw.startswith(_ZERO_TIME_PREFIX):
        return None
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    tz = ""
    for i in range(len(s) - 1, 9, -1):
        if s[i] in "+-":
            s, tz = s[:i], s[i:]
            break
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{(frac + '000000')[:6]}"
    dt = datetime.fromisoformat(s + tz)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_inspect(docs: object) -> dict[str, Container]:
    """`docker inspect` JSON (a list of container objects) → {id: Container}."""
    if not isinstance(docs, list):
        raise AssessError("docker inspect output is not a JSON list")
    out: dict[str, Container] = {}
    for d in docs:
        if not isinstance(d, dict):
            raise AssessError("docker inspect entry is not an object")
        state = d.get("State") or {}
        config = d.get("Config") or {}
        labels = config.get("Labels") or {}
        host = d.get("HostConfig") or {}
        cid = str(d.get("Id") or "")
        if not cid:
            raise AssessError("docker inspect entry has no Id")
        try:
            started = parse_docker_time(state.get("StartedAt", ""))
        except ValueError as e:
            raise AssessError(f"unparseable StartedAt for {d.get('Name')}: {e}") from e
        out[cid] = Container(
            id=cid,
            name=str(d.get("Name") or cid[:12]).lstrip("/"),
            service=str(labels.get(SERVICE_LABEL) or ""),
            status=str(state.get("Status") or ""),
            restarting=bool(state.get("Restarting")),
            exit_code=int(state.get("ExitCode") or 0),
            restart_count=int(d.get("RestartCount") or 0),
            started_at=started,
            health=str((state.get("Health") or {}).get("Status") or ""),
            restart_policy=str((host.get("RestartPolicy") or {}).get("Name") or "no"),
        )
    return out


def evaluate(before: dict[str, Container], after: dict[str, Container],
             window_start: datetime) -> Verdict:
    """The stability policy. Pure: no docker, no clock."""
    problems: list[str] = []
    warnings: list[str] = []
    if not after:
        problems.append("no containers found for the project at the end of the "
                        "window — the gate observed nothing, so it proves nothing")

    for cid, b in sorted(before.items(), key=lambda kv: kv[1].name):
        if cid not in after and not b.one_shot:
            problems.append(f"{b.name}: container removed or recreated during the "
                            "window")

    long_running: list[str] = []
    one_shots: list[str] = []
    for cid, a in sorted(after.items(), key=lambda kv: kv[1].name):
        if a.one_shot:
            one_shots.append(a.service or a.name)
            if a.status != "exited":
                problems.append(f"{a.name}: one-shot is '{a.status}', expected it to "
                                "have exited 0")
            elif a.exit_code != 0:
                problems.append(f"{a.name}: one-shot exited with code {a.exit_code}")
            continue
        long_running.append(a.service or a.name)
        b = before.get(cid)
        if b is None:
            problems.append(f"{a.name}: container created or recreated during the "
                            "window")
        elif a.restart_count > b.restart_count:
            problems.append(f"{a.name}: restarted {a.restart_count - b.restart_count} "
                            f"time(s) during the window (RestartCount "
                            f"{b.restart_count} -> {a.restart_count})")
        if a.started_at is not None and a.started_at >= window_start:
            problems.append(f"{a.name}: started at {a.started_at.isoformat()}, inside "
                            f"the window that began {window_start.isoformat()}")
        if a.restarting:
            problems.append(f"{a.name}: is restarting (crash loop)")
        elif a.status != "running":
            problems.append(f"{a.name}: state is '{a.status}' (exit code "
                            f"{a.exit_code}), expected running")
        if a.health == "unhealthy":
            problems.append(f"{a.name}: health is unhealthy")
        elif a.health == "starting":
            warnings.append(f"{a.name}: health still 'starting' at the end of the "
                            "window")
    return Verdict(problems, warnings, sorted(set(long_running)), sorted(set(one_shots)))


def compare_baseline(baseline: dict, verdict: Verdict) -> list[str]:
    """Every service a previous gate saw must still be there, in the same role."""
    problems: list[str] = []
    for svc in baseline.get("long_running", []):
        if svc not in verdict.long_running:
            problems.append(f"{svc}: was a running service before, is missing now")
    for svc in baseline.get("one_shots", []):
        if svc not in verdict.one_shots:
            problems.append(f"{svc}: one-shot seen before is missing now")
    return problems


# ── docker seam ──────────────────────────────────────────────────────────────

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=DOCKER_TIMEOUT_S, check=False)


def snapshot(project: str, run: Runner) -> dict[str, Container]:
    """Inspect every container (any state) of a compose project."""
    try:
        ps = run(["docker", "ps", "-aq", "--no-trunc",
                  "--filter", f"label={PROJECT_LABEL}={project}"])
    except (OSError, subprocess.SubprocessError) as e:
        raise AssessError(f"docker ps failed: {e}") from e
    if ps.returncode != 0:
        raise AssessError(f"docker ps exited {ps.returncode}: {ps.stderr.strip()}")
    ids = ps.stdout.split()
    if not ids:
        return {}
    try:
        ins = run(["docker", "inspect", *ids])
    except (OSError, subprocess.SubprocessError) as e:
        raise AssessError(f"docker inspect failed: {e}") from e
    # A container removed between ps and inspect makes inspect exit 1 while
    # still printing the rest — that removal is exactly what the gate reports,
    # so a partial result is used rather than refused.
    if ins.returncode != 0 and not ins.stdout.strip().startswith("["):
        raise AssessError(f"docker inspect exited {ins.returncode}: "
                          f"{ins.stderr.strip()}")
    try:
        return parse_inspect(json.loads(ins.stdout))
    except ValueError as e:
        raise AssessError(f"docker inspect output is not JSON: {e}") from e


def run_gate(project: str, window_s: float, *, run: Runner = _default_runner,
             sleep: Callable[[float], None] = time.sleep,
             now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> Verdict:
    # The window starts BEFORE the first inspect: a container that (re)starts
    # while that inspect is in flight is inside the window, not before it.
    window_start = now()
    before = snapshot(project, run)
    sleep(window_s)
    after = snapshot(project, run)
    return evaluate(before, after, window_start)


def _report(verdict: Verdict, window_s: float, out=None) -> None:
    out = sys.stdout if out is None else out
    print(f"stability window: {window_s:g}s", file=out)
    print(f"long-running ({len(verdict.long_running)}): "
          f"{' '.join(verdict.long_running)}", file=out)
    print(f"one-shot ({len(verdict.one_shots)}): {' '.join(verdict.one_shots)}", file=out)
    for w in verdict.warnings:
        print(f"WARN  {w}", file=out)
    for p in verdict.problems:
        print(f"FAIL  {p}", file=out)
    print("STABLE" if verdict.stable else "NOT STABLE", file=out)


def main(argv: Sequence[str] | None = None, *, run: Runner = _default_runner,
         sleep: Callable[[float], None] = time.sleep) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--project", default="netops")
    ap.add_argument("--window", type=float, default=60.0, metavar="SECONDS")
    ap.add_argument("--save-services", metavar="FILE")
    ap.add_argument("--baseline-services", metavar="FILE")
    args = ap.parse_args(argv)
    if not 1 <= args.window <= 3600:
        print("--window must be between 1 and 3600 seconds", file=sys.stderr)
        return 2
    baseline = None
    if args.baseline_services:
        try:
            with open(args.baseline_services, encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"could not read baseline {args.baseline_services}: {e}",
                  file=sys.stderr)
            return 2
    try:
        verdict = run_gate(args.project, args.window, run=run, sleep=sleep)
    except AssessError as e:
        print(f"could not assess stack stability: {e}", file=sys.stderr)
        return 2
    if baseline is not None:
        verdict = Verdict(verdict.problems + compare_baseline(baseline, verdict),
                          verdict.warnings, verdict.long_running, verdict.one_shots)
    _report(verdict, args.window)
    if args.save_services:
        try:
            with open(args.save_services, "w", encoding="utf-8") as fh:
                json.dump({"long_running": verdict.long_running,
                           "one_shots": verdict.one_shots}, fh, indent=2)
        except OSError as e:
            print(f"could not write {args.save_services}: {e}", file=sys.stderr)
            return 2
    return 0 if verdict.stable else 1


if __name__ == "__main__":
    sys.exit(main())
