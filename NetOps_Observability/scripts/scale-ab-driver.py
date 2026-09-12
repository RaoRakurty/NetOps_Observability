#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""scale-ab-driver.py — unattended, resumable driver for the P3 aggregation-plane A/B.

Executes the six-leg wave of `docs/scale/RUN_PLAN_P3_AB_2026-08-29.md` end to
end without a human in the loop, and records enough evidence per leg that the
arm a number came from is recoverable from the run dir alone.

WHAT IT DRIVES (plan section 1; arms amended 2026-08-31, ultra #35). L0a/L0b
are already run and are NEVER touched:

    L1  t-storm-10-2.5k   OFF   agg-10-off-<MMDDHHMM>
    L2  t-storm-25-2.5k   OFF   agg-25-off-<MMDDHHMM>
    -- redeploy: arm ON (deployment/docker/compose.agg.yml) --
    L3  t-storm-10-2.5k   ON    agg-10-on-<MMDDHHMM>
    L4  t-storm-25-2.5k   ON    agg-25-on-<MMDDHHMM>
    L5  t-storm-2.5k      ON    agg-2p5k-on-<MMDDHHMM>   (neutrality guard)
    -- redeploy: NEITHER overlay (the deployed default — ON since 2026-08-30) --

Each arm is pinned by exactly ONE one-variable overlay: compose.agg.yml sets
CORR_AGGREGATION_PLANE=1 (ON), compose.agg-off.yml sets it to 0 (OFF).
docker-compose.yml itself defaults the flag ON (owner-ratified 2026-08-30), so
the OFF arm is NOT "deploy without compose.agg.yml" any more — the absence of
both pins is the DEPLOYED DEFAULT, which only the end-of-wave restore deploys.
Two redeploys total, exactly as the plan requires: the arm is switched only when
the next leg needs a different one, never per leg.

PER LEG, IN ORDER (every step is a gate; the first failure stops the driver):
  1. cron window     refuses to START a leg between 03:10 and 04:40 UTC unless
                     --ignore-cron-window. The host 1K canary (03:17 UTC
                     t-nominal, Sun 04:17 s1) is DISABLED as of 2026-08-29
                     (crontab commented out), but a re-enabled canary onboards
                     1000 devices into the same 198.18/15 space and the leg's
                     creates get absorbed by dedupe (attempt
                     p2-s012b-08290322). The driver reads `crontab -l` and says
                     loudly whether the canary is live; the window refusal does
                     not depend on that read succeeding.
  2. idle            no `scale-miniladder.py` process anywhere on the host AND
                     the run lock (/var/tmp/scale-runs/.lock) free. Polled with
                     a bounded wait (--wait-lock-seconds) and a loud line every
                     --wait-log-seconds naming the pid/runid that holds it. The
                     lock is never stolen, never forced (plan section 2).
  3. residue         `scale-miniladder.py --cleanup-only mlx-`, which exits 0
                     ONLY on verified zero. Non-zero = residue or an
                     unreachable stack; either way the leg does not start.
  4. clickhouse      `SELECT 1` through clickhouse-client in the compose
                     container. ClickHouse is NEVER restarted by this driver
                     (a restart wipes the system-log history memflat reads).
  5. replicas        exactly --replicas correlation containers, running and
                     (where a healthcheck exists) healthy.
  6. arm             both replicas' `env` and both replicas' `corr_agg_enabled`
                     must agree with the leg's arm. `corr_agg_enabled` is read
                     from the MAIN /metrics endpoint over mTLS — a `docker exec`
                     python client to the replica's OWN container IP on 8443
                     with /certs/svid/correlation.{crt,key}, verified against the
                     `correlation` SPIFFE name — the same way the harness and
                     every collector read this stack. (The :8094 health sidecar
                     is NOT plain HTTP on this deployment: a plaintext GET is
                     reset, ECONNRESET, 2026-08-29 22:43 — so the driver does not
                     use it anywhere.) A half-flagged pair (MIXED ARM) aborts the
                     driver: no metric in the run output reveals it, so the leg
                     would be silently unusable.
  7. launch          `setsid nohup python3 scripts/scale-miniladder.py …`,
                     detached, output to <run-dir>/launcher.log. The driver then
                     waits for the VERDICT line AND for the harness process to
                     exit — a FAIL line does not mean the process is done.
  8. collect         symlink x-<runid>, twin scorer, per-replica /metrics
                     (mTLS, from inside the container) -> metrics-final.txt,
                     and the plan's clean-scope TTUR SQL for THIS leg's burst
                     window -> ttur.tsv. Plus ab-leg.json: arm, replica ids and
                     started_at, the derived scope, the verification evidence.

RESUMABLE. Every transition is written to /var/tmp/scale-runs/ab-state.json
(atomic replace). Re-running the driver skips legs already complete AND
collected; a leg that ran but whose collection failed is re-collected without
re-running it; a leg the driver was killed during is re-attached to if its
harness process is still alive. `--from L3` starts at a named leg regardless.

REFUSES TO GUESS. Everything it cannot prove is a refusal, not an assumption
(CLAUDE.md 16.1): an unreadable lock, a `pgrep` that errors, an arm it cannot
read from both replicas, a report.json without a burst phase, a ClickHouse that
does not answer. None of those are "probably fine".

NOT ONLY THIS WAVE. `--legs ID:PROFILE:ARM:DIR_PREFIX,...` replaces the table
above for one invocation (the arm-switch, gate, launch and collection logic is
identical), `--state-file` keeps that wave's progress out of the six-leg wave's
`ab-state.json`, and `--fresh-containers` force-recreates the correlation
replicas before EVERY leg — even when the arm does not change — so each leg
starts on cold containers and its counters are leg-scoped. That combination is
what the matched OFF/ON `t-storm-2.5k` pair of
`docs/scale/RUN_PLAN_P3_PAIR_2026-08-30.md` needs (P3 verdict section 3.6).

USAGE
  python3 scripts/scale-ab-driver.py --dry-run          # print the plan, touch nothing
  python3 scripts/scale-ab-driver.py                    # run the wave (L1..L5 + restore)
  python3 scripts/scale-ab-driver.py --from L3          # resume at L3
  python3 scripts/scale-ab-driver.py \
      --legs P1:t-storm-2.5k:off:pair-2p5k-off,P2:t-storm-2.5k:on:pair-2p5k-on \
      --fresh-containers --state-file /var/tmp/scale-runs/ab-pair-state.json
Logs to /var/tmp/scale-runs/ab-driver.log (and stdout).

EXIT CODES
  0 = every planned leg complete and collected, stack restored to the deployed
      default (redeployed with neither A/B pin overlay)
  1 = a gate, a launch, a verification or a collection failed (stack left in the
      state named in the final STOP block, which is also written to the state
      file)
  2 = usage / a refusal before anything was touched
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import NoReturn

# Cron-proof PATH (CLAUDE.md 16.2): docker lives in /usr/bin or /usr/local/bin
# on supported hosts; an interactive profile is never sourced. Applied in
# main(), never at import — as module-scope code it clobbers the PATH of any
# process that merely imports this file for its parser (the lesson
# scale-miniladder.py records in its own header).
CRON_PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
COMPOSE_DIR = os.path.join(REPO_ROOT, "deployment", "docker")
HARNESS = os.path.join(SCRIPT_DIR, "scale-miniladder.py")
TWIN = os.path.join(SCRIPT_DIR, "lab", "twin", "twin.py")

# The deployed overlay set (plan section 3; arms amended 2026-08-31, ultra
# #35). docker-compose.yml itself defaults CORR_AGGREGATION_PLANE ON
# (owner-ratified 2026-08-30), so the ABSENCE of an overlay yields the deployed
# default, not the OFF arm. Each A/B arm therefore appends exactly ONE
# one-variable pin overlay — agg.yml (=1, ON) or agg-off.yml (=0, OFF) — and
# nothing else: one variable is still the whole experiment.
COMPOSE_FILES = ("docker-compose.yml", "compose.offline-images.yml",
                 "compose.tls.yml", "compose.mem125.yml", "compose.lab.yml",
                 "compose.profile.yml")
AGG_OVERLAY = "compose.agg.yml"          # ON arm pin (CORR_AGGREGATION_PLANE=1)
AGG_OFF_OVERLAY = "compose.agg-off.yml"  # OFF arm pin (CORR_AGGREGATION_PLANE=0)

DEFAULT_RUN_ROOT = "/var/tmp/scale-runs"
STATE_BASENAME = "ab-state.json"
LOG_BASENAME = "ab-driver.log"
LOCK_BASENAME = ".lock"
STATE_SCHEMA = "correlix.scale.ab-state/1"

# The 03:17 UTC canary window (plan section 2). 03:10 gives the refusal a margin
# on the driver's own clock; 04:40 covers the Sunday 04:17 `s1` run's onboard.
CRON_WINDOW_START = (3, 10)
CRON_WINDOW_END = (4, 40)
CANARY_CRON_RE = re.compile(r"^\s*[^#\s].*scale-miniladder\.py")

# A REAL harness process, as opposed to any command line that merely mentions
# the harness. `pgrep -af scale-miniladder.py` also matches an interactive
# `grep`, an editor, or a tool wrapper whose own argv quotes the name (observed:
# an agent shell whose `bash -c \'…pgrep -af scale-miniladder.py…\'` matched
# itself). Waiting on one of those would stall the wave for its whole lock
# budget and then abort, so the match is narrowed to "an interpreter running the
# harness file", which is what every real invocation looks like after
# `setsid nohup` execs (cron\'s included).
HARNESS_PROC_RE = re.compile(
    r"(^|/|\s)(python[0-9.]*)\s+\S*scale-miniladder\.py(\s|$)")

DOCKER_TIMEOUT = 30          # bound EVERY docker call (16.3) — a wedged dockerd
COMPOSE_UP_TIMEOUT = 600     # force-recreate of two replicas on a loaded box
CH_TIMEOUT = 900             # the TTUR scan is a full corr_objects group-by
TWIN_TIMEOUT = 3600          # scorer is ~46 s warm; the bound is for a cold box
CLEANUP_TIMEOUT = 3600       # --cleanup-only page-loops the device store
METRICS_TIMEOUT = 60
DEFAULT_LEG_TIMEOUT = 5 * 3600      # ~15 min burst + 45 min drain, x tolerance
DEFAULT_WAIT_LOCK = 4 * 3600        # bounded wait for a live run to finish
DEFAULT_WAIT_LOG = 300              # say something every 5 min while waiting
POLL_SECONDS = 30
REPLICA_SETTLE_TIMEOUT = 420        # after a force-recreate

# `uuid5(SIGNAL_NS, "corrobj|<tenant>|storm-noise")` — the tenant-constant
# storm-aggregate id (src/correlation/engine.py ~3279, SIGNAL_NS from
# src/correlation/signals.py:31). It is shared by EVERY leg, so the clean-scope
# TTUR query excludes it; a naive per-leg scope attributes it to whichever leg
# happens to be queried.
SIGNAL_NS = uuid.UUID("6e1f8c3a-67aa-5b9e-9d40-8a52c0de0001")
DEFAULT_TENANT = "global"

# ClickHouse literals are validated, never escaped-and-hoped-for: they are
# interpolated into SQL (zero trust at every boundary, CLAUDE.md section 3).
CH_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class Leg:
    """One leg of the wave. Immutable by convention: the table below IS the plan."""

    def __init__(self, leg_id: str, profile: str, arm: str, dir_prefix: str) -> None:
        self.id = leg_id
        self.profile = profile
        self.arm = arm
        self.dir_prefix = dir_prefix

    def __repr__(self) -> str:      # pragma: no cover - debugging aid only
        return f"Leg({self.id}, {self.profile}, {self.arm})"


# The `--legs` grammar. Every field is validated before anything is touched
# (zero trust at the boundary, CLAUDE.md section 3): the id keys the state file,
# the dir prefix becomes a directory name AND the leg's label in every later
# document, and the profile is checked against the harness's OWN table rather
# than trusted — an unknown profile would otherwise only be discovered by
# argparse inside the harness, an hour of gates later.
LEG_SPEC_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,15}$")
LEG_SPEC_DIR_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
LEG_ARMS = ("off", "on")

LEGS = (
    Leg("L1", "t-storm-10-2.5k", "off", "agg-10-off"),
    Leg("L2", "t-storm-25-2.5k", "off", "agg-25-off"),
    Leg("L3", "t-storm-10-2.5k", "on", "agg-10-on"),
    Leg("L4", "t-storm-25-2.5k", "on", "agg-25-on"),
    Leg("L5", "t-storm-2.5k", "on", "agg-2p5k-on"),
)
LEG_IDS = tuple(leg.id for leg in LEGS)


class DriverAbort(RuntimeError):
    """A gate refused, or something could not be proven. Always loud, never swallowed."""


# ---------------------------------------------------------------------------
# logging — stdout AND an append-only file, both timestamped
# ---------------------------------------------------------------------------
_LOG_PATH = ""


def set_log_path(path: str) -> None:
    global _LOG_PATH
    _LOG_PATH = path


def _emit(level: str, msg: str) -> None:
    line = f"{utcnow()} ab-driver: {level}{msg}"
    stream = sys.stderr if level else sys.stdout
    print(line, file=stream, flush=True)
    if not _LOG_PATH:
        return
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        # Never silent, and never fatal: losing the LOG must not lose the run
        # (the durable record is the state file, which escalates on failure),
        # but it must be visible on stderr, with the errno and the path, that
        # the narration channel is broken. Escalating here would also recurse:
        # the reporting channel cannot report its own death through itself.
        print(f"{utcnow()} ab-driver: WARNING: cannot append to {_LOG_PATH} "
              f"(errno {exc.errno}: {exc.strerror or exc}) — the run continues "
              f"and stdout/stderr still carry every line",
              file=sys.stderr, flush=True)


def log(msg: str) -> None:
    _emit("", msg)


def warn(msg: str) -> None:
    _emit("WARNING: ", msg)


def error(msg: str) -> None:
    _emit("ERROR: ", msg)


def die(msg: str, code: int = 2) -> NoReturn:
    error(msg)
    sys.exit(code)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str], timeout: int, cwd: str | None = None,
        env: dict | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on a non-zero exit — callers look at rc
    and REPORT stderr (CLAUDE.md 16.1: no swallowed errors)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False, cwd=cwd, env=env)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:6])}"
    except (OSError, ValueError) as exc:
        return 127, "", f"cannot execute {cmd[0]!r}: {exc}"


# ---------------------------------------------------------------------------
# pure helpers (all unit-tested)
# ---------------------------------------------------------------------------
def in_cron_window(now: datetime) -> bool:
    """True inside the 1K-canary window (03:10-04:40 UTC), where a leg's onboard
    would be absorbed by the canary's own 198.18/15 fleet."""
    aware = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    utc = aware.astimezone(timezone.utc)
    minutes = utc.hour * 60 + utc.minute
    return (CRON_WINDOW_START[0] * 60 + CRON_WINDOW_START[1]) <= minutes < \
           (CRON_WINDOW_END[0] * 60 + CRON_WINDOW_END[1])


def canary_enabled(crontab_text: str) -> bool:
    """True when an UNCOMMENTED miniladder cron line exists."""
    return any(CANARY_CRON_RE.match(line) for line in crontab_text.splitlines())


def leg_by_id(leg_id: str, legs: tuple = LEGS) -> Leg:
    for leg in legs:
        if leg.id == leg_id:
            return leg
    raise DriverAbort(f"unknown leg {leg_id!r} — legs are "
                      f"{', '.join(leg.id for leg in legs)}")


def harness_profiles() -> tuple[str, ...]:
    """The workload profile names the HARNESS accepts, read from the harness.

    Imported by path (the file is hyphen-named), exactly as the test suites
    import it, and never guessed: a hard-coded copy of the list here would rot
    silently and a leg would then die at the harness's own argparse, after the
    driver had already waited for the lock and cleaned the fleet. Import failure
    is a refusal, not a fallback — a profile we cannot prove exists is not a
    profile we start an hour-long leg on.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("scale_miniladder_profiles",
                                                  HARNESS)
    if spec is None or spec.loader is None:
        raise DriverAbort(f"cannot load {HARNESS} to read its workload "
                          f"profiles — refusing to validate --legs against a "
                          f"guess")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        profiles = tuple(sorted(module.WORKLOAD_PROFILES))
    except (OSError, ImportError, AttributeError, SyntaxError, ValueError) as exc:
        raise DriverAbort(
            f"cannot read WORKLOAD_PROFILES from {HARNESS} ({type(exc).__name__}: "
            f"{exc}) — refusing to accept a --legs profile the harness has not "
            f"been shown to know") from exc
    if not profiles:
        raise DriverAbort(f"{HARNESS} declares no workload profiles — refusing")
    return profiles


def parse_legs(spec: str, profiles: tuple[str, ...]) -> tuple[Leg, ...]:
    """`ID:PROFILE:ARM:DIR_PREFIX,...` -> the leg table for THIS invocation.

    Order is the order given (it IS the execution order). Every refusal names
    the offending entry: this string decides which workloads run for the next
    several hours of lab time, so nothing about it is inferred.
    """
    entries = [part.strip() for part in (spec or "").split(",") if part.strip()]
    if not entries:
        raise DriverAbort("--legs is empty — give at least one "
                          "ID:PROFILE:ARM:DIR_PREFIX entry")
    legs: list[Leg] = []
    seen_ids: set[str] = set()
    seen_dirs: set[str] = set()
    for entry in entries:
        fields = entry.split(":")
        if len(fields) != 4:
            raise DriverAbort(
                f"--legs entry {entry!r} has {len(fields)} field(s), not 4 — "
                f"the form is ID:PROFILE:ARM:DIR_PREFIX")
        leg_id, profile, arm, dir_prefix = (f.strip() for f in fields)
        if not LEG_SPEC_ID_RE.match(leg_id):
            raise DriverAbort(
                f"--legs entry {entry!r}: leg id {leg_id!r} must match "
                f"{LEG_SPEC_ID_RE.pattern} — it keys the state file")
        if leg_id in seen_ids:
            raise DriverAbort(
                f"--legs names leg id {leg_id!r} twice — ids key the state "
                f"file, so a duplicate would make two legs share one record")
        arm_l = arm.lower()
        if arm_l not in LEG_ARMS:
            raise DriverAbort(
                f"--legs entry {entry!r}: arm {arm!r} is not one of "
                f"{', '.join(LEG_ARMS)}")
        if profile not in profiles:
            raise DriverAbort(
                f"--legs entry {entry!r}: profile {profile!r} is not a harness "
                f"workload profile ({', '.join(profiles)})")
        if not LEG_SPEC_DIR_RE.match(dir_prefix):
            raise DriverAbort(
                f"--legs entry {entry!r}: dir prefix {dir_prefix!r} must match "
                f"{LEG_SPEC_DIR_RE.pattern} — it becomes a directory name under "
                f"the run root and the leg's label in every later document")
        if dir_prefix in seen_dirs:
            raise DriverAbort(
                f"--legs names dir prefix {dir_prefix!r} twice — the directory "
                f"name IS the leg label (plan section 4) and must be unique")
        seen_ids.add(leg_id)
        seen_dirs.add(dir_prefix)
        legs.append(Leg(leg_id, profile, arm_l, dir_prefix))
    return tuple(legs)


def resolve_legs(spec: str) -> tuple[Leg, ...]:
    """The built-in P3 wave when --legs is absent, the parsed table otherwise."""
    if not (spec or "").strip():
        return LEGS
    return parse_legs(spec, harness_profiles())


def describe_legs(legs: tuple[Leg, ...], run_root: str) -> list[str]:
    """The resolved leg table, one line per leg, for the log and the dry run."""
    return [f"  {leg.id:<6} profile {leg.profile:<18} arm {leg.arm.upper():<3} "
            f"run dir {os.path.join(run_root, leg.dir_prefix)}-<MMDDHHMM>"
            for leg in legs]


def legs_to_run(state: dict, from_leg: str = "",
                legs: tuple = LEGS) -> list[Leg]:
    """The legs this invocation must still act on, in plan order.

    A leg is skipped ONLY when it both ran and was collected. A leg that ran but
    whose collection failed comes back (collection re-runs, the leg does not).
    `--from` overrides the state: it starts at that leg and drops everything
    before it, so an operator can deliberately redo a tail.
    """
    leg_ids = tuple(leg.id for leg in legs)
    if from_leg:
        if from_leg not in leg_ids:
            raise DriverAbort(f"--from {from_leg!r} is not a leg id "
                              f"({', '.join(leg_ids)})")
        start = leg_ids.index(from_leg)
        return list(legs[start:])
    todo = []
    for leg in legs:
        entry = (state.get("legs") or {}).get(leg.id) or {}
        if entry.get("status") == "complete" and entry.get("collected"):
            continue
        todo.append(leg)
    return todo


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError:
        return {"schema": STATE_SCHEMA, "created": utcnow(), "legs": {}}
    except (OSError, json.JSONDecodeError) as exc:
        # A corrupt state file is a real condition: refusing costs a restart,
        # guessing costs a re-run of legs that already happened.
        raise DriverAbort(
            f"state file {path} is unreadable ({exc}) — refusing to start a "
            f"wave that cannot know which legs already ran. Inspect it, fix or "
            f"move it aside, then re-run") from exc
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise DriverAbort(f"state file {path} is not {STATE_SCHEMA} — refusing")
    state.setdefault("legs", {})
    return state


def save_state(path: str, state: dict) -> None:
    """Atomic write: a driver killed mid-save must never leave a half-state."""
    state["updated"] = utcnow()
    tmp = f"{path}.tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        raise DriverAbort(f"cannot write state file {path} ({exc}) — a wave "
                          f"whose progress cannot be recorded is not resumable, "
                          f"so it does not start") from exc


def last_error_line(text: str, limit: int = 220) -> str:
    """The LAST non-empty line of a captured stderr, bounded.

    A `docker exec python -c` failure returns a multi-line traceback whose FIRST
    lines are frame noise ("Traceback (most recent call last):", the urllib
    frame) and whose LAST line is the actual condition
    ("ConnectionResetError: [Errno 104] Connection reset by peer"). Truncating
    the head printed the noise twice per replica and hid the diagnosis
    (2026-08-29 22:43). Report the diagnosis.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return "(no stderr)"
    last = lines[-1]
    if len(lines) > 1:
        last = f"{last} [+{len(lines) - 1} earlier traceback line(s)]"
    return last[:limit]


def prom_value(text: str, name: str) -> float | None:
    """Value of an unlabelled Prometheus sample, or None when absent/unparsable."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == name:
            try:
                return float(parts[1])
            except ValueError:
                return None
    return None


def env_flag(env_text: str, key: str) -> str | None:
    """Value of KEY in `docker exec … env` output, or None when unset."""
    for line in env_text.splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None


def classify_arm(readings: list[dict]) -> str:
    """'on' | 'off' | 'mixed' | 'unknown' from per-replica (env, metric) readings.

    Each reading: {"env": str|None, "metric": float|None, "error": str}. ANY
    unreadable replica is 'unknown' (never "probably the same as the other"),
    any disagreement — between replicas, or between a replica's env and its own
    engine — is 'mixed'. A mixed arm is unusable and must abort the wave.
    """
    if not readings:
        return "unknown"
    arms = set()
    for reading in readings:
        if reading.get("error") or reading.get("metric") is None:
            return "unknown"
        env_val = reading.get("env")
        env_arm = "on" if (env_val or "0").strip() not in ("", "0", "false",
                                                           "False") else "off"
        metric_arm = "on" if float(reading["metric"]) >= 1.0 else "off"
        if env_arm != metric_arm:
            return "mixed"
        arms.add(env_arm)
    if len(arms) > 1:
        return "mixed"
    return arms.pop()


def parse_iso_z(text: str) -> datetime:
    value = (text or "").strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)      # raises ValueError — callers report it
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def ch_literal(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def burst_scope(report: dict) -> dict:
    """The leg's TTUR scope, derived from its OWN report.json phase stamps.

    `burst.at` is the phase's completion stamp and `evidence.burst_seconds` its
    measured duration, so the burst window is [at - burst_seconds, at]. The
    convergence cutoff is the correlation_completion stamp when the phase ran
    (it is the moment the engine was declared done with this workload) and the
    last phase stamp otherwise. Anything missing is fatal: a TTUR number over a
    guessed window is worse than no number.
    """
    phases = report.get("phases")
    if not isinstance(phases, list) or not phases:
        raise DriverAbort("report.json carries no phases[] — cannot derive the "
                          "burst window for the TTUR scope")
    by_name = {}
    for phase in phases:
        if isinstance(phase, dict) and phase.get("phase"):
            by_name[phase["phase"]] = phase
    burst = by_name.get("burst")
    if not burst:
        raise DriverAbort("report.json has no `burst` phase — cannot derive the "
                          "TTUR scope (did the leg fail before injecting?)")
    try:
        burst_end = parse_iso_z(burst.get("at", ""))
    except ValueError as exc:
        raise DriverAbort(f"burst phase stamp {burst.get('at')!r} is not "
                          f"ISO-8601 ({exc})") from exc
    seconds = ((burst.get("evidence") or {}).get("burst_seconds"))
    if not isinstance(seconds, (int, float)) or seconds <= 0:
        raise DriverAbort(f"burst evidence has no usable burst_seconds "
                          f"({seconds!r}) — cannot bound the burst window")
    burst_start = burst_end - timedelta(seconds=float(seconds))
    converged_phase = by_name.get("correlation_completion")
    if converged_phase is None:
        stamps = [p.get("at", "") for p in phases if isinstance(p, dict)]
        converged_at = max(s for s in stamps if s)
    else:
        converged_at = converged_phase.get("at", "")
    try:
        converged = parse_iso_z(converged_at)
    except ValueError as exc:
        raise DriverAbort(f"convergence stamp {converged_at!r} is not "
                          f"ISO-8601 ({exc})") from exc
    if converged <= burst_end:
        raise DriverAbort(
            f"convergence stamp {converged_at} is not after the burst end "
            f"{ch_literal(burst_end)} — the scope would be empty; refusing to "
            f"emit a TTUR row from it")
    return {
        "burst_start": ch_literal(burst_start),
        "burst_end": ch_literal(burst_end),
        "converged": ch_literal(converged),
        "burst_seconds": float(seconds),
        "source": "report.json phases[burst].at - burst_seconds .. "
                  "phases[correlation_completion].at",
    }


def agg_cid(tenant: str) -> str:
    """The tenant-constant storm-aggregate correlation id excluded from the scope."""
    return str(uuid.uuid5(SIGNAL_NS, f"corrobj|{tenant}|storm-noise"))


def ttur_sql(scope: dict, cid: str) -> str:
    """The plan's section 5.3 clean-scope TTUR query, verbatim in shape.

    Every interpolated value is validated first — these strings reach a database
    (CLAUDE.md section 3: validate at every boundary, escape nothing on trust).
    """
    for key in ("burst_start", "burst_end", "converged"):
        if not CH_DATETIME_RE.match(scope.get(key, "")):
            raise DriverAbort(f"TTUR scope {key}={scope.get(key)!r} is not a "
                              f"'YYYY-MM-DD HH:MM:SS' literal — refusing to "
                              f"build SQL from it")
    if not UUID_RE.match(cid):
        raise DriverAbort(f"storm-aggregate cid {cid!r} is not a UUID — refusing")
    return (
        "WITH inc AS (\n"
        "  SELECT correlation_id,\n"
        "         min(window_start) t0, min(created_at) t1, max(created_at) tlast,"
        " count() nv,\n"
        "         argMax(state, (created_at, version)) fstate,\n"
        "         argMax(verdict_tier, (created_at, version)) ftier,\n"
        "         max(signal_count) ms\n"
        "  FROM netops.corr_objects\n"
        f"  WHERE created_at < '{scope['converged']}'\n"
        f"    AND correlation_id != toUUID('{cid}')\n"
        "  GROUP BY correlation_id\n"
        f"  HAVING t0 >= '{scope['burst_start']}' AND t0 < '{scope['burst_end']}')\n"
        "SELECT count() inc, sum(nv) versions, round(sum(nv)/count(),2) vpi,"
        " sum(ms) sigs,\n"
        "       round(quantile(0.5)(dateDiff('second',t0,t1)),0) t1p50,\n"
        "       round(quantile(0.95)(dateDiff('second',t0,t1)),0) t1p95,\n"
        "       round(quantile(0.99)(dateDiff('second',t0,t1)),0) t1p99,\n"
        "       max(dateDiff('second',t0,t1)) t1max,\n"
        "       round(quantile(0.95)(dateDiff('second',t0,tlast)),0) tlast95,\n"
        "       countIf(fstate='merged') merged, countIf(ftier='undetermined') undet,\n"
        "       countIf(ftier='confirmed') confirmed\n"
        "FROM inc\n"
        "SETTINGS tenant_scope='__all__'\n"
        "FORMAT TSVWithNames"
    )


def lock_status(text: str, alive: bool | None) -> tuple[str, str]:
    """Classify the run lock's contents. `alive` is the caller's pid probe result
    (None = the probe itself failed).

    Never steals: a lock naming a LIVE pid is busy, a lock naming a dead pid is
    reported STALE (the harness reclaims its own stale locks — this driver does
    not), and an unreadable lock is 'unknown' and refuses.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return "unknown", f"lock file is not JSON: {str(text)[:120]!r}"
    if not isinstance(data, dict) or not data.get("pid"):
        return "unknown", f"lock file names no pid: {str(text)[:120]!r}"
    who = f"pid {data.get('pid')} runid {data.get('runid')} since {data.get('started')}"
    if alive is None:
        return "unknown", f"could not probe {who}"
    if alive:
        return "busy", who
    return "stale", who


# ---------------------------------------------------------------------------
# the driver
# ---------------------------------------------------------------------------
class LaunchHandle:
    """A launched harness process. `pid` is the setsid'd harness itself."""

    def __init__(self, pid: int, proc: subprocess.Popen | None = None) -> None:
        self.pid = pid
        self.proc = proc

    def reap(self) -> None:
        if self.proc is not None:
            self.proc.poll()


def default_launcher(argv: list[str], log_path: str, cwd: str) -> LaunchHandle:
    """`setsid nohup python3 scale-miniladder.py …`, output appended to log_path.

    NOT `start_new_session=True`: that would make the child a process-group
    leader, `setsid(2)` would then fail and setsid(1) would FORK — the pid we
    hold would exit immediately and every liveness check on it would lie. Let
    `setsid` do the detaching (it execs in place from a non-leader child), so
    the pid we return is the harness. Liveness is still cross-checked against
    the run dir in the process table, never on this pid alone.
    """
    fh = open(log_path, "ab", buffering=0)      # noqa: SIM115 — closed below
    try:
        proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=cwd,
                                env=dict(os.environ))
    finally:
        fh.close()
    return LaunchHandle(proc.pid, proc)


class Driver:
    def __init__(self, args: argparse.Namespace, runner=run, sleeper=time.sleep,
                 clock=None, launcher=default_launcher) -> None:
        self.args = args
        self.runner = runner
        self.sleep = sleeper
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.launcher = launcher
        self.run_root = args.run_root
        # The leg table for THIS invocation: the built-in P3 wave unless --legs
        # replaced it. Resolved here (before any gate) so a bad spec is a
        # refusal that has touched nothing.
        self.legs = resolve_legs(args.legs)
        self.leg_ids = tuple(leg.id for leg in self.legs)
        if args.from_leg and args.from_leg not in self.leg_ids:
            raise DriverAbort(f"--from {args.from_leg!r} is not a leg id "
                              f"({', '.join(self.leg_ids)})")
        # A custom wave keeps its own state file: reusing ab-state.json would
        # read the SIX-leg wave's L1..L5 records as this wave's progress.
        self.state_path = (args.state_file or
                           os.path.join(self.run_root, STATE_BASENAME))
        self.lock_path = args.lock_file
        self.state: dict = {}
        self.stack_note = "untouched"

    # -- state ------------------------------------------------------------
    def save(self) -> None:
        save_state(self.state_path, self.state)

    def leg_state(self, leg: Leg) -> dict:
        legs = self.state.setdefault("legs", {})
        entry = legs.setdefault(leg.id, {"leg": leg.id, "profile": leg.profile,
                                         "arm": leg.arm, "status": "planned",
                                         "collected": False, "problems": []})
        entry.setdefault("problems", [])
        return entry

    # -- primitives -------------------------------------------------------
    def docker_ids(self, service: str) -> list[str]:
        rc, out, err = self.runner(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={self.args.project}",
             "--filter", f"label=com.docker.compose.service={service}"],
            DOCKER_TIMEOUT)
        if rc != 0:
            raise DriverAbort(f"docker ps for service {service!r} failed "
                              f"(rc={rc}): {err.strip()[:300]}")
        return out.split()

    def compose_argv(self, arm: str, tail: list[str]) -> list[str]:
        """The deploy command for an arm. 'on' and 'off' each append their ONE
        one-variable pin overlay; 'default' appends NEITHER, leaving
        docker-compose.yml's own CORR_AGGREGATION_PLANE default in charge (ON
        since 2026-08-30, .env-overridable) — that is what the end-of-wave
        restore deploys (ultra #35)."""
        argv = ["docker", "compose"]
        for name in COMPOSE_FILES:
            argv += ["-f", name]
        if arm == "on":
            argv += ["-f", AGG_OVERLAY]
        elif arm == "off":
            argv += ["-f", AGG_OFF_OVERLAY]
        return argv + tail

    def pid_alive(self, pid: int) -> bool | None:
        """None when the probe itself failed — an unprobeable pid is treated as
        ALIVE by the caller (refusing costs minutes, stealing a live run costs
        the run)."""
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True          # someone else's process: alive, not ours
        except OSError as exc:
            warn(f"pid liveness probe for {pid} failed (errno {exc.errno}: "
                 f"{exc.strerror or exc}) — answering UNKNOWN, which the lock "
                 f"reader turns into 'unknown' and the idle gate refuses on; a "
                 f"lock is never stolen on an unprobeable pid")
            return None

    def harness_processes(self) -> list[str]:
        """Every live `scale-miniladder.py` command line on the host."""
        rc, out, err = self.runner(["pgrep", "-af", "scale-miniladder.py"],
                                   DOCKER_TIMEOUT)
        if rc == 1:
            return []
        if rc != 0:
            raise DriverAbort(
                f"pgrep for the harness failed (rc={rc}): {err.strip()[:300]} — "
                f"cannot prove the host is idle, so no leg starts")
        return [line for line in out.splitlines()
                if line.strip() and HARNESS_PROC_RE.search(line)]

    def read_lock(self) -> tuple[str, str]:
        try:
            with open(self.lock_path, encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            return "free", "no lock file"
        except OSError as exc:
            return "unknown", (f"cannot read {self.lock_path} (errno "
                               f"{exc.errno}: {exc.strerror or exc})")
        alive: bool | None = None
        try:
            pid = int(json.loads(text).get("pid"))
            alive = self.pid_alive(pid)
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
            alive = None
        return lock_status(text, alive)

    # -- gates ------------------------------------------------------------
    def check_cron_window(self, leg: Leg) -> None:
        now = self.clock()
        rc, out, err = self.runner(["crontab", "-l"], DOCKER_TIMEOUT)
        if rc != 0:
            warn(f"crontab -l failed (rc={rc}): {err.strip()[:200]} — the canary's "
                 f"state is UNKNOWN; the window refusal below still applies")
        elif canary_enabled(out):
            warn("the 1K canary cron is ENABLED (an uncommented "
                 "scale-miniladder.py line) — it onboards 1000 devices into the "
                 "same 198.18/15 space at 03:17 UTC and will absorb a leg's "
                 "creates. Disable it or accept the collision knowingly")
        else:
            log("canary cron: no uncommented scale-miniladder.py line (disabled) — "
                "as expected for the P2-P4 programme")
        if not in_cron_window(now):
            return
        if self.args.ignore_cron_window:
            warn(f"{leg.id} starts INSIDE the {CRON_WINDOW_START[0]:02d}:"
                 f"{CRON_WINDOW_START[1]:02d}-{CRON_WINDOW_END[0]:02d}:"
                 f"{CRON_WINDOW_END[1]:02d} UTC canary window because "
                 f"--ignore-cron-window was given — say so on every number this "
                 f"leg produces")
            return
        raise DriverAbort(
            f"{leg.id} would start at {now.strftime('%H:%M')} UTC, inside the "
            f"{CRON_WINDOW_START[0]:02d}:{CRON_WINDOW_START[1]:02d}-"
            f"{CRON_WINDOW_END[0]:02d}:{CRON_WINDOW_END[1]:02d} UTC canary "
            f"window (attempt p2-s012b-08290322 collided with it and failed "
            f"onboard). Wait for the window to pass, or pass "
            f"--ignore-cron-window deliberately")

    def wait_for_idle(self, leg: Leg) -> None:
        """Poll until no harness runs and the run lock is free. Never forces."""
        deadline = time.monotonic() + self.args.wait_lock_seconds
        said = 0.0
        first = True
        while True:
            procs = self.harness_processes()
            lock_state, detail = self.read_lock()
            if not procs and lock_state in ("free", "stale"):
                if lock_state == "stale":
                    warn(f"run lock {self.lock_path} is STALE ({detail}) — the "
                         f"harness reclaims its own stale locks; this driver "
                         f"never removes one")
                if not first:
                    log(f"{leg.id}: host is idle, lock free — proceeding")
                return
            left = deadline - time.monotonic()
            if left <= 0:
                raise DriverAbort(
                    f"{leg.id}: waited {self.args.wait_lock_seconds}s and the "
                    f"host is still busy (harness processes: "
                    f"{procs or 'none'}; lock: {lock_state} — {detail}). NOT "
                    f"forcing past a live run (plan section 2): a lock refusal "
                    f"means a run is live. Re-run the driver when it lands")
            if first or (time.monotonic() - said) >= self.args.wait_log_seconds:
                log(f"{leg.id}: WAITING for the host to go idle "
                    f"({int(left)}s of budget left) — lock: {lock_state} "
                    f"({detail}); processes: {'; '.join(procs) or 'none'}")
                said = time.monotonic()
            first = False
            self.sleep(min(POLL_SECONDS, max(1, int(left))))

    def residue_check(self, leg: Leg) -> None:
        """`--cleanup-only mlx-` exits 0 ONLY on verified zero residue."""
        argv = [self.args.python, HARNESS, "--cleanup-only", "mlx-",
                "--env-file", self.args.env_file]
        log(f"{leg.id}: residue check — {' '.join(argv)}")
        rc, out, err = self.runner(argv, CLEANUP_TIMEOUT, cwd=REPO_ROOT)
        tail = "\n".join((out + err).strip().splitlines()[-8:])
        if rc != 0:
            raise DriverAbort(
                f"{leg.id}: residue check FAILED (rc={rc}) — `mlx-` devices "
                f"remain, or the stack is unreachable. A leg started on residue "
                f"has its creates absorbed by dedupe and produces "
                f"unattributable numbers. Last lines:\n{tail}")
        log(f"{leg.id}: residue verified 0. Last lines:\n{tail}")

    def clickhouse_ok(self, leg: Leg) -> None:
        ids = self.docker_ids("clickhouse")
        if not ids:
            raise DriverAbort(f"{leg.id}: no running clickhouse container in "
                              f"compose project {self.args.project!r}")
        rc, out, err = self.runner(
            ["docker", "exec", ids[0], "clickhouse-client", "--query", "SELECT 1"],
            DOCKER_TIMEOUT)
        if rc != 0 or out.strip() != "1":
            raise DriverAbort(
                f"{leg.id}: ClickHouse did not answer SELECT 1 (rc={rc}, "
                f"out={out.strip()[:80]!r}, err={err.strip()[:200]!r}). NOT "
                f"restarting it — a restart wipes the system-log history the "
                f"memflat clause reads (s05/s06 lesson)")
        log(f"{leg.id}: ClickHouse healthy ({ids[0][:12]})")

    def replicas(self) -> list[dict]:
        out = []
        for cid in self.docker_ids("correlation"):
            rc, insp, err = self.runner(
                ["docker", "inspect", cid, "--format",
                 ("{{.Name}}|{{.State.Running}}|{{if .State.Health}}"
                  "{{.State.Health.Status}}{{else}}none{{end}}|"
                  "{{.State.StartedAt}}|"
                  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")],
                DOCKER_TIMEOUT)
            if rc != 0 or "|" not in insp:
                raise DriverAbort(f"docker inspect {cid[:12]} failed (rc={rc}): "
                                  f"{last_error_line(err)}")
            name, running, health, started, ip = (insp.strip().split("|") + [""] * 5)[:5]
            out.append({"container": cid, "short": cid[:12], "name": name.lstrip("/"),
                        "running": running == "true", "health": health,
                        "started_at": started, "ip": ip})
        return out

    def replicas_healthy(self, leg: Leg) -> list[dict]:
        reps = self.replicas()
        if len(reps) != self.args.replicas:
            raise DriverAbort(
                f"{leg.id}: expected {self.args.replicas} correlation replicas, "
                f"found {len(reps)} ({[r['short'] for r in reps]}) — losing a "
                f"replica silently halves ingest and the leg is not comparable")
        for rep in reps:
            if not rep["running"] or rep["health"] in ("unhealthy", "starting"):
                raise DriverAbort(
                    f"{leg.id}: replica {rep['name']} ({rep['short']}) is "
                    f"running={rep['running']} health={rep['health']!r}")
            if not rep["ip"]:
                raise DriverAbort(f"{leg.id}: replica {rep['name']} has no "
                                  f"container IP — cannot scrape it")
        log(f"{leg.id}: {len(reps)} correlation replicas healthy: " +
            ", ".join(f"{r['name']}({r['short']}, up {r['started_at']})" for r in reps))
        return reps

    # -- the arm ----------------------------------------------------------
    def read_arm(self) -> tuple[str, list[dict]]:
        """(arm, per-replica readings). Reads BOTH the env and the engine's own
        `corr_agg_enabled`, on EVERY replica (plan section 3.3).

        The metric comes from the MAIN mTLS endpoint (:8443) on the replica's own
        address, exactly as `metrics_final()` collects it. The plan suggested the
        :8094 health sidecar; on this deployment that port is not plain HTTP and
        a plaintext GET is reset (ECONNRESET on both replicas, 2026-08-29 22:43),
        which read as "arm UNKNOWN" and stopped the wave. One probe, one
        transport, used for both verification and collection.
        """
        readings = []
        for rep in self.replicas():
            reading = {"container": rep["short"], "name": rep["name"],
                       "started_at": rep["started_at"], "error": "",
                       "env": None, "metric": None}
            rc, out, err = self.runner(
                ["docker", "exec", rep["container"], "env"], DOCKER_TIMEOUT)
            if rc != 0:
                reading["error"] = f"env failed (rc={rc}): {last_error_line(err)}"
                readings.append(reading)
                continue
            reading["env"] = env_flag(out, "CORR_AGGREGATION_PLANE")
            rc, out, err = self.runner(
                ["docker", "exec", rep["container"], "python", "-c",
                 self.METRICS_PROBE.format(ip=rep["ip"])], METRICS_TIMEOUT)
            if rc != 0:
                reading["error"] = (f"mTLS /metrics probe to {rep['ip']}:8443 "
                                    f"failed (rc={rc}): {last_error_line(err)}")
                readings.append(reading)
                continue
            reading["metric"] = prom_value(out, "corr_agg_enabled")
            if reading["metric"] is None:
                reading["error"] = (f"no corr_agg_enabled sample in "
                                    f"{rep['ip']}:8443/metrics")
            readings.append(reading)
        return classify_arm(readings), readings

    def describe_readings(self, readings: list[dict]) -> str:
        return "; ".join(
            f"{r['name']}({r['container']}) env="
            f"{r['env'] if r['env'] is not None else 'unset'} "
            f"corr_agg_enabled={r['metric']}"
            + (f" ERROR={r['error']}" if r["error"] else "")
            for r in readings) or "no replicas"

    def switch_arm(self, arm: str) -> None:
        rc, sha, err = self.runner(["git", "rev-parse", "HEAD"], DOCKER_TIMEOUT,
                                   cwd=REPO_ROOT)
        if rc != 0:
            raise DriverAbort(f"git rev-parse HEAD failed (rc={rc}): "
                              f"{err.strip()[:200]} — GIT_SHA must be explicit "
                              f"for the redeploy")
        env = dict(os.environ)
        env["GIT_SHA"] = sha.strip()
        argv = self.compose_argv(arm, ["up", "-d", "--no-deps", "--force-recreate",
                                       "--scale", f"correlation={self.args.replicas}",
                                       "correlation"])
        log(f"arm switch -> {arm.upper()} (GIT_SHA={sha.strip()[:12]}): "
            f"{' '.join(argv)}  [cwd {COMPOSE_DIR}]")
        self.stack_note = f"redeploying correlation to arm {arm.upper()}"
        rc, out, err = self.runner(argv, COMPOSE_UP_TIMEOUT, cwd=COMPOSE_DIR, env=env)
        if rc != 0:
            raise DriverAbort(f"compose up for arm {arm.upper()} FAILED (rc={rc}): "
                              f"{(err or out).strip()[-600:]}")
        self.stack_note = f"correlation redeployed to arm {arm.upper()} (unverified)"
        deadline = time.monotonic() + REPLICA_SETTLE_TIMEOUT
        while True:
            reps = None
            try:
                reps = self.replicas()
            except DriverAbort as exc:
                warn(f"post-redeploy replica probe failed ({exc}) — retrying "
                     f"until the settle deadline")
            ready = False
            if reps is not None:
                # ── ultra #41 (2026-08-31): the pre-redeploy gate
                # (replicas_healthy) refuses 'unhealthy', but this settle loop
                # accepted it — only 'starting' was excluded — so a
                # --fresh-containers leg could launch on a replica whose OWN
                # healthcheck says it is broken. 'unhealthy' is terminal for
                # the leg: abort and name the container. Ready requires
                # healthy, or explicitly no-healthcheck ('none'), the same
                # standard replicas_healthy() applies.
                sick = [r for r in reps if r["health"] == "unhealthy"]
                if sick:
                    raise DriverAbort(
                        f"after the arm-{arm.upper()} redeploy, correlation "
                        f"replica(s) "
                        + ", ".join(f"{r['name']} ({r['short']})" for r in sick)
                        + " report UNHEALTHY — a leg must never launch on a "
                        "broken arm. Inspect the replica (docker logs / "
                        "compose ps) and fix it before re-running")
                ready = (len(reps) == self.args.replicas and
                         all(r["running"] and r["health"] in ("healthy", "none")
                             and r["ip"] for r in reps))
            if ready:
                return
            if time.monotonic() >= deadline:
                raise DriverAbort(
                    f"after the arm-{arm.upper()} redeploy, "
                    f"{self.args.replicas} healthy correlation replicas did not "
                    f"appear within {REPLICA_SETTLE_TIMEOUT}s")
            self.sleep(min(POLL_SECONDS, 10))

    def ensure_arm(self, arm: str, label: str, fresh: bool = False) -> list[dict]:
        """Verify the arm; redeploy once if it is the other one; abort on mixed.

        `fresh` (per-leg, from --fresh-containers) forces the SAME redeploy even
        when the arm already matches, so the leg starts on cold containers: the
        P3 verdict section 3.6 confound is a leg inheriting a previous leg's
        resident set and counters. The redeploy path, its post-recreate arm
        verification and its settle wait are the ones below, unchanged — there
        is no second way to recreate a replica in this driver.
        """
        current, readings = self.read_arm()
        log(f"{label}: arm reads {current.upper()} — {self.describe_readings(readings)}")
        if current == "mixed":
            raise DriverAbort(
                f"{label}: MIXED ARM — {self.describe_readings(readings)}. One "
                f"replica flagged and the other not is invisible in every run "
                f"metric, so the leg would be unusable. Redeploy correlation "
                f"deliberately and re-run the driver")
        if current == arm and not fresh:
            self.stack_note = f"arm {arm.upper()}, verified on both replicas"
            return readings
        if current == arm:
            log(f"{label}: arm is already {arm.upper()}, but --fresh-containers "
                f"was given — force-recreating the correlation replicas anyway "
                f"so this leg starts cold (P3 verdict section 3.6: a leg must "
                f"not inherit the previous leg's resident set or counters)")
        elif current == "unknown":
            warn(f"{label}: the arm could not be read from every replica "
                 f"({self.describe_readings(readings)}) — redeploying to "
                 f"{arm.upper()} and re-verifying rather than guessing")
        self.switch_arm(arm)
        current, readings = self.read_arm()
        log(f"{label}: post-redeploy arm reads {current.upper()} — "
            f"{self.describe_readings(readings)}")
        if current != arm:
            raise DriverAbort(
                f"{label}: after redeploying to {arm.upper()} the replicas read "
                f"{current.upper()} — {self.describe_readings(readings)}. The "
                f"stack is in an UNVERIFIED arm; fix it by hand before any leg")
        self.stack_note = f"arm {arm.upper()}, verified on both replicas"
        return readings

    def restore_deployed_default(self) -> None:
        """End-of-wave restore (amended 2026-08-31, ultra #35): redeploy with
        NEITHER A/B pin overlay. docker-compose.yml itself defaults
        CORR_AGGREGATION_PLANE ON since 2026-08-30 (.env can override), so
        "the deployed default" is whatever the base compose set yields —
        currently ON — and it is restored by the ABSENCE of both pin files,
        never by guessing which arm the default happens to equal today. The
        arm is re-read afterwards and recorded; a mixed or unreadable result
        still aborts."""
        self.switch_arm("default")
        current, readings = self.read_arm()
        log(f"restore: with neither A/B overlay the deployed default reads "
            f"{current.upper()} — {self.describe_readings(readings)}")
        if current not in ("on", "off"):
            raise DriverAbort(
                f"restore: after redeploying with neither A/B overlay the "
                f"replicas read {current.upper()} — "
                f"{self.describe_readings(readings)}. The stack is in an "
                f"UNVERIFIED state; fix it by hand")
        self.state["final_deployed_default"] = current
        self.stack_note = (f"deployed default restored (no A/B overlay; arm "
                           f"reads {current.upper()})")

    # -- the run ----------------------------------------------------------
    def run_dir_for(self, leg: Leg) -> str:
        stamp = self.clock().strftime("%m%d%H%M")
        return os.path.join(self.run_root, f"{leg.dir_prefix}-{stamp}")

    def harness_argv(self, leg: Leg, run_dir: str) -> list[str]:
        return ["setsid", "nohup", self.args.python, HARNESS,
                "--profile", leg.profile,
                "--devices", str(self.args.devices),
                "--eps", str(self.args.eps),
                "--run-dir", run_dir]

    def launch(self, leg: Leg) -> tuple[str, LaunchHandle]:
        run_dir = self.run_dir_for(leg)
        if os.path.exists(run_dir):
            raise DriverAbort(f"{leg.id}: run dir {run_dir} already exists — the "
                              f"directory name IS the leg label (plan section 4), "
                              f"so it is never reused. Wait a minute and re-run")
        try:
            os.makedirs(run_dir)
        except OSError as exc:
            raise DriverAbort(f"{leg.id}: cannot create {run_dir} ({exc})") from exc
        argv = self.harness_argv(leg, run_dir)
        log_path = os.path.join(run_dir, "launcher.log")
        log(f"{leg.id}: LAUNCH {' '.join(argv)}  (log {log_path})")
        handle = self.launcher(argv, log_path, REPO_ROOT)
        self.stack_note = (f"{leg.id} harness LIVE (pid {handle.pid}, {run_dir}) — "
                           f"arm {leg.arm.upper()}")
        return run_dir, handle

    def leg_running(self, run_dir: str, tolerant: bool = False) -> list[str]:
        """Harness command lines that name this run dir.

        `tolerant` is for the wait loop of a LIVE leg: a transient `pgrep`
        failure there must not tear down a wave whose run is still going. It is
        reported, treated as "still running" (the safe direction — the leg then
        ends at its own timeout, loudly), and never treated as "finished".
        """
        try:
            return [p for p in self.harness_processes() if run_dir in p]
        except DriverAbort as exc:
            if not tolerant:
                raise
            warn(f"{exc} — treating the leg as STILL RUNNING (the safe "
                 f"direction); it will end at --leg-timeout if this persists")
            return [f"(process table unreadable: {exc})"]

    def wait_for_leg(self, leg: Leg, run_dir: str,
                     handle: LaunchHandle | None) -> str:
        """Wait for the VERDICT line AND for the harness process to exit.

        A FAIL line does not mean the process is done (plan section 2): cleanup
        runs after it, and cleanup is what leaves the lab usable for the next
        leg. Returns the verdict word.
        """
        log_path = os.path.join(run_dir, "launcher.log")
        deadline = time.monotonic() + self.args.leg_timeout
        said = 0.0
        started = time.monotonic()
        while True:
            if handle is not None:
                handle.reap()
            verdict, verdict_line = self.read_verdict(log_path)
            alive = self.leg_running(run_dir, tolerant=True)
            if not alive:
                if verdict:
                    log(f"{leg.id}: harness exited, verdict line: {verdict_line}")
                    return verdict
                raise DriverAbort(
                    f"{leg.id}: the harness process for {run_dir} is GONE and no "
                    f"VERDICT line was written — it died or was killed. Last "
                    f"lines of launcher.log:\n{self.tail(log_path, 15)}")
            if time.monotonic() >= deadline:
                raise DriverAbort(
                    f"{leg.id}: still running after {self.args.leg_timeout}s "
                    f"({'; '.join(alive)}). The driver STOPS; the harness is "
                    f"deliberately left alive (killing it mid-cleanup leaves "
                    f"residue). Investigate, then re-run the driver")
            if (time.monotonic() - said) >= self.args.wait_log_seconds:
                log(f"{leg.id}: running {int(time.monotonic() - started)}s — "
                    f"last: {self.tail(log_path, 1) or '(no output yet)'}")
                said = time.monotonic()
            self.sleep(POLL_SECONDS)

    def read_verdict(self, log_path: str) -> tuple[str, str]:
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    match = re.search(r"VERDICT (PASS|FAIL) run (\S+)", line)
                    if match:
                        return match.group(1), line.strip()
        except FileNotFoundError:
            return "", ""
        except OSError as exc:
            warn(f"cannot read {log_path} (errno {exc.errno}: "
                 f"{exc.strerror or exc}) — this poll reports NO verdict, which "
                 f"is the safe direction: the leg is only declared finished when "
                 f"a verdict is READ and the process is gone")
        return "", ""

    def tail(self, path: str, lines: int) -> str:
        """Last `lines` non-empty lines of a log, for quoting in a message.

        Diagnostic narration only — never a verdict input. An unreadable file is
        REPORTED by name (it used to return "" silently) and quoted as nothing;
        the caller's own gate still fails on its own evidence.
        """
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                kept = [ln.rstrip() for ln in fh if ln.strip()]
        except FileNotFoundError:
            return ""            # not written yet: the caller prints its own "(no output yet)"
        except OSError as exc:
            warn(f"cannot read {path} for its last {lines} line(s) (errno "
                 f"{exc.errno}: {exc.strerror or exc}) — the quote below is "
                 f"empty; the verdict does not depend on it")
            return ""
        return "\n".join(kept[-lines:])

    # -- collection -------------------------------------------------------
    METRICS_PROBE = (
        "import socket,ssl,sys\n"
        "ctx=ssl.create_default_context(cafile='/certs/ca.pem')\n"
        "ctx.load_cert_chain('/certs/svid/correlation.crt',"
        "'/certs/svid/correlation.key')\n"
        "s=ctx.wrap_socket(socket.create_connection(('{ip}',8443),timeout=8),"
        "server_hostname='correlation')\n"
        "s.sendall(b'GET /metrics HTTP/1.1\\r\\nHost: correlation\\r\\n"
        "Connection: close\\r\\n\\r\\n')\n"
        "b=b''\n"
        "while True:\n"
        "    d=s.recv(65536)\n"
        "    if not d: break\n"
        "    b+=d\n"
        "sys.stdout.write(b.split(b'\\r\\n\\r\\n',1)[1].decode('utf-8','replace'))\n"
    )

    def read_report(self, run_dir: str) -> dict:
        path = os.path.join(run_dir, "report.json")
        try:
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise DriverAbort(f"cannot read {path} ({exc}) — the leg produced no "
                              f"machine-readable report") from exc
        if not report.get("runid"):
            raise DriverAbort(f"{path} carries no runid")
        return report

    def symlink_runid(self, runid: str, run_dir: str) -> str:
        """`x-<runid>` -> run dir. twin.find_run_dir globs `*-<runid>`, and the
        leg's own directory name encodes the ARM, not the run id."""
        link = os.path.join(self.run_root, f"x-{runid}")
        if os.path.islink(link):
            target = os.path.realpath(link)
            if target != os.path.realpath(run_dir):
                raise DriverAbort(f"{link} already points at {target}, not "
                                  f"{run_dir} — refusing to repoint another "
                                  f"leg's scorer symlink")
            return link
        if os.path.exists(link):
            raise DriverAbort(f"{link} exists and is not a symlink — refusing")
        existing = [p for p in glob.glob(os.path.join(self.run_root, f"*-{runid}"))
                    if os.path.realpath(p) != os.path.realpath(run_dir)]
        if existing:
            raise DriverAbort(f"another path already globs as *-{runid} "
                              f"({existing}) — the scorer would pick the wrong "
                              f"run dir")
        try:
            os.symlink(run_dir, link)
        except OSError as exc:
            raise DriverAbort(f"cannot create {link} -> {run_dir} ({exc})") from exc
        log(f"symlink {link} -> {run_dir}")
        return link

    def twin_score(self, leg: Leg, runid: str, run_dir: str) -> None:
        argv = [self.args.python, TWIN, "--run-root", self.run_root,
                "score", "--runid", runid]
        log(f"{leg.id}: twin score — {' '.join(argv)}")
        rc, out, err = self.runner(argv, TWIN_TIMEOUT, cwd=REPO_ROOT)
        out_path = os.path.join(run_dir, "twin-score.log")
        self.write_file(out_path, (out or "") + (err or ""))
        if rc != 0:
            raise DriverAbort(f"{leg.id}: twin scorer FAILED (rc={rc}) — see "
                              f"{out_path}. Last lines:\n"
                              f"{self.tail(out_path, 12)}")
        log(f"{leg.id}: twin score written to {out_path}")

    def write_file(self, path: str, text: str) -> None:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            raise DriverAbort(f"cannot write {path} ({exc})") from exc

    def metrics_final(self, leg: Leg, run_dir: str) -> list[dict]:
        """Per-replica /metrics at convergence, into <run-dir>/metrics-final.txt.

        The source is the replica's OWN address on the mTLS app port (8443),
        verified against the `correlation` SPIFFE name — the IP is the routing
        target, never a verification bypass. There is no second transport to
        fall back to: :8094 is not plain HTTP on this deployment (ECONNRESET,
        2026-08-29), and a leg whose engine evidence cannot be read is a leg
        without evidence, which is a stop, not a degraded pass.
        """
        reps = self.replicas()
        chunks = [(f"# metrics-final for {leg.id} ({leg.profile}, arm "
                   f"{leg.arm.upper()}) captured {utcnow()}")]
        captured = []
        for rep in reps:
            probe = self.METRICS_PROBE.format(ip=rep["ip"])
            rc, body, err = self.runner(
                ["docker", "exec", rep["container"], "python", "-c", probe],
                METRICS_TIMEOUT)
            source = f"mtls https://{rep['ip']}:8443/metrics"
            if rc != 0:
                raise DriverAbort(
                    f"{leg.id}: could not scrape /metrics from {rep['name']} at "
                    f"{rep['ip']}:8443 (rc={rc}): {last_error_line(err)} — the "
                    f"leg's engine evidence would be missing")
            chunks.append(
                f"\n# ==== replica {rep['name']} ({rep['short']}) ip {rep['ip']} "
                f"started_at {rep['started_at']} source {source} ====")
            chunks.append(body)
            captured.append({"name": rep["name"], "container": rep["short"],
                             "ip": rep["ip"], "started_at": rep["started_at"],
                             "source": source,
                             "corr_agg_enabled": prom_value(body, "corr_agg_enabled"),
                             "corr_agg_observed_total":
                                 prom_value(body, "corr_agg_observed_total"),
                             "corr_agg_suppressed_total":
                                 prom_value(body, "corr_agg_suppressed_total")})
        path = os.path.join(run_dir, "metrics-final.txt")
        self.write_file(path, "\n".join(chunks) + "\n")
        log(f"{leg.id}: metrics-final.txt written ({len(reps)} replicas) — " +
            "; ".join(f"{c['name']} corr_agg_enabled={c['corr_agg_enabled']} "
                      f"observed={c['corr_agg_observed_total']}" for c in captured))
        # Say, at the moment of capture, what the counters in that file MEAN.
        # Every `*_total` is cumulative since the container started; whether the
        # analyst must subtract the previous leg's file is decided by whether
        # this leg got fresh containers, and that fact is not visible in the
        # file itself.
        if self.args.fresh_containers:
            log(f"{leg.id}: counter scope — the correlation containers were "
                f"force-recreated before this leg (--fresh-containers), so every "
                f"*_total in metrics-final.txt is LEG-SCOPED: read it as-is, do "
                f"NOT subtract a previous leg's file")
        else:
            log(f"{leg.id}: counter scope — the containers were NOT recreated for "
                f"this leg, so every *_total in metrics-final.txt is CUMULATIVE "
                f"since the replica started: subtract the previous leg's file to "
                f"get this leg's counts")
        return captured

    def ttur(self, leg: Leg, run_dir: str, report: dict) -> dict:
        scope = burst_scope(report)
        cid = agg_cid(self.args.tenant)
        sql = ttur_sql(scope, cid)
        ids = self.docker_ids("clickhouse")
        if not ids:
            raise DriverAbort(f"{leg.id}: no clickhouse container for the TTUR query")
        log(f"{leg.id}: TTUR scope burst [{scope['burst_start']} .. "
            f"{scope['burst_end']}) converged < {scope['converged']}, "
            f"excluding storm-aggregate cid {cid} (tenant {self.args.tenant!r})")
        rc, out, err = self.runner(
            ["docker", "exec", ids[0], "clickhouse-client", "--query", sql],
            CH_TIMEOUT)
        if rc != 0:
            raise DriverAbort(f"{leg.id}: clean-scope TTUR query FAILED (rc={rc}): "
                              f"{err.strip()[:600]}")
        rows = [ln for ln in out.splitlines() if ln.strip()]
        if len(rows) < 2:
            raise DriverAbort(
                f"{leg.id}: the TTUR query returned no data row (output "
                f"{out.strip()[:200]!r}) — an empty scope is an ERROR, never a "
                f"silent zero (CLAUDE.md 16.1)")
        path = os.path.join(run_dir, "ttur.tsv")
        self.write_file(path, out if out.endswith("\n") else out + "\n")
        scope_path = os.path.join(run_dir, "ttur-scope.json")
        self.write_file(scope_path, json.dumps(
            {"leg": leg.id, "profile": leg.profile, "arm": leg.arm,
             "tenant": self.args.tenant, "excluded_agg_cid": cid,
             "scope": scope, "sql": sql, "captured": utcnow()},
            indent=1, sort_keys=True) + "\n")
        log(f"{leg.id}: ttur.tsv written — {rows[0]} | {rows[1]}")
        return {"scope": scope, "agg_cid": cid,
                "header": rows[0].split("\t"), "row": rows[1].split("\t")}

    def collect(self, leg: Leg, run_dir: str, entry: dict) -> None:
        report = self.read_report(run_dir)
        runid = report["runid"]
        entry["runid"] = runid
        entry["overall"] = report.get("overall", "")
        entry["phases"] = {p.get("phase"): p.get("status")
                           for p in report.get("phases", []) if isinstance(p, dict)}
        self.save()
        entry["symlink"] = self.symlink_runid(runid, run_dir)
        self.save()
        self.twin_score(leg, runid, run_dir)
        entry["twin_scored"] = True
        self.save()
        entry["metrics"] = self.metrics_final(leg, run_dir)
        self.save()
        entry["ttur"] = self.ttur(leg, run_dir, report)
        entry["collected"] = True
        self.save()
        leg_path = os.path.join(run_dir, "ab-leg.json")
        self.write_file(leg_path, json.dumps(entry, indent=1, sort_keys=True) + "\n")
        log(f"{leg.id}: COLLECTED — {run_dir} (runid {runid}, harness "
            f"{entry.get('verdict', '?')}/{entry.get('overall', '?')})")

    # -- one leg ----------------------------------------------------------
    def run_leg(self, leg: Leg) -> None:
        entry = self.leg_state(leg)
        if entry.get("status") == "complete" and entry.get("collected"):
            log(f"{leg.id}: already complete and collected ({entry.get('run_dir')}) "
                f"— skipping")
            return
        if entry.get("status") == "complete" and entry.get("run_dir"):
            log(f"{leg.id}: ran already ({entry['run_dir']}) but collection is "
                f"incomplete — re-collecting only, NOT re-running")
            self.collect(leg, entry["run_dir"], entry)
            return
        if entry.get("status") == "running" and entry.get("run_dir"):
            run_dir = entry["run_dir"]
            if self.leg_running(run_dir):
                log(f"{leg.id}: harness for {run_dir} is still alive — "
                    f"re-attaching instead of starting a second run")
                entry["verdict"] = self.wait_for_leg(leg, run_dir, None)
                entry["status"] = "complete"
                entry["finished"] = utcnow()
                self.save()
                self.collect(leg, run_dir, entry)
                return
            verdict, line = self.read_verdict(os.path.join(run_dir, "launcher.log"))
            if verdict:
                log(f"{leg.id}: a previous invocation's run finished ({line}) — "
                    f"collecting it")
                entry["verdict"] = verdict
                entry["status"] = "complete"
                entry["finished"] = entry.get("finished") or utcnow()
                self.save()
                self.collect(leg, run_dir, entry)
                return
            raise DriverAbort(
                f"{leg.id}: state says a run was launched into {run_dir} but no "
                f"harness is alive and no VERDICT line exists. That run died. "
                f"Record it, clean up, and re-run with the leg's state cleared — "
                f"the driver will not silently start a second run into a new "
                f"directory for the same leg")

        log(f"===== {leg.id}: profile {leg.profile}, arm {leg.arm.upper()} =====")
        self.check_cron_window(leg)
        self.wait_for_idle(leg)
        self.residue_check(leg)
        self.clickhouse_ok(leg)
        self.replicas_healthy(leg)
        entry["arm_verification"] = self.ensure_arm(
            leg.arm, leg.id, fresh=self.args.fresh_containers)
        entry["fresh_containers"] = bool(self.args.fresh_containers)
        entry["status"] = "armed"
        self.save()
        # The arm is verified; from here the only thing between us and data is
        # the harness itself.
        run_dir, handle = self.launch(leg)
        entry.update({"run_dir": run_dir, "status": "running",
                      "launched": utcnow(), "pid": handle.pid,
                      "argv": self.harness_argv(leg, run_dir)})
        self.save()
        entry["verdict"] = self.wait_for_leg(leg, run_dir, handle)
        entry["status"] = "complete"
        entry["finished"] = utcnow()
        self.stack_note = f"idle, arm {leg.arm.upper()} (last leg {leg.id} done)"
        self.save()
        self.collect(leg, run_dir, entry)

    # -- the wave ---------------------------------------------------------
    def run(self) -> int:
        self.state = load_state(self.state_path)
        self.state.setdefault("plan", "docs/scale/RUN_PLAN_P3_AB_2026-08-29.md")
        self.state.setdefault("created", utcnow())
        for stale in ("stop_reason", "stopped_at", "stack_state"):
            # A previous stop's diagnosis must never be mistaken for this run's.
            self.state.pop(stale, None)
        self.check_state_legs()
        self.state["leg_table"] = [{"leg": leg.id, "profile": leg.profile,
                                    "arm": leg.arm, "dir_prefix": leg.dir_prefix}
                                   for leg in self.legs]
        self.state["fresh_containers"] = bool(self.args.fresh_containers)
        todo = legs_to_run(self.state, self.args.from_leg, self.legs)
        if not todo:
            log("every leg is complete and collected — nothing to do")
        log(f"wave: {len(todo)} leg(s) to run: " +
            ", ".join(f"{leg.id}({leg.arm})" for leg in todo))
        self.save()
        try:
            for leg in todo:
                self.run_leg(leg)
            if self.args.restore_arm:
                log("wave complete — restoring the deployed default (redeploy "
                    "with NEITHER A/B overlay; docker-compose.yml owns "
                    "CORR_AGGREGATION_PLANE's default, ON since 2026-08-30)")
                self.restore_deployed_default()
                self.state["final_arm_restored"] = True
                self.save()
        except DriverAbort as exc:
            error(str(exc))
            self.state["stopped_at"] = utcnow()
            self.state["stop_reason"] = str(exc)
            self.state["stack_state"] = self.stack_note
            try:
                self.save()
            except DriverAbort as save_exc:      # pragma: no cover - disk failure
                error(f"and the state file could not be updated: {save_exc}")
            error(f"STOP. Stack state: {self.stack_note}. State file: "
                  f"{self.state_path}. Log: {self.args.log_file}. Nothing was "
                  f"forced and no run was killed; fix the named condition and "
                  f"re-run (add --from <LEG> to skip ahead deliberately)")
            return 1
        log(f"WAVE COMPLETE — state {self.state_path}")
        for leg in self.legs:
            entry = (self.state.get("legs") or {}).get(leg.id) or {}
            log(f"  {leg.id} {leg.profile:<18} arm {leg.arm.upper():<3} "
                f"{entry.get('status', 'not run'):<9} "
                f"{entry.get('verdict', '-'):<5} {entry.get('run_dir', '-')}")
        return 0

    # -- state vs leg table -----------------------------------------------
    def check_state_legs(self) -> None:
        """Refuse a state file recorded for a DIFFERENT leg table.

        `--state-file` is the separation; this is the proof. A custom wave whose
        ids collide with the six-leg wave's (L1..L5) would otherwise read that
        wave's records as its own progress and skip a leg that never ran, or
        judge one workload's numbers under another's label.
        """
        recorded = (self.state.get("legs") or {})
        for leg in self.legs:
            entry = recorded.get(leg.id) or {}
            if not entry:
                continue
            was = (entry.get("profile"), entry.get("arm"))
            if was == (None, None):
                continue
            if was != (leg.profile, leg.arm):
                raise DriverAbort(
                    f"state file {self.state_path} already records leg "
                    f"{leg.id} as profile {entry.get('profile')!r} arm "
                    f"{entry.get('arm')!r}, but this invocation defines it as "
                    f"{leg.profile!r}/{leg.arm!r} — that state belongs to a "
                    f"different wave. Point --state-file at a fresh path (or "
                    f"move this one aside); the driver will not resume one "
                    f"wave's progress into another's leg table")

    # -- dry run ----------------------------------------------------------
    def dry_run(self) -> int:
        self.state = load_state(self.state_path)
        self.check_state_legs()
        todo = legs_to_run(self.state, self.args.from_leg, self.legs)
        now = self.clock()
        print(f"PLAN — {len(todo)} leg(s), state {self.state_path}")
        print(f"  resolved leg table ({len(self.legs)} leg(s), source "
              f"{'--legs' if self.args.legs else 'built-in P3 wave'}"
              f"{', --fresh-containers' if self.args.fresh_containers else ''}):")
        for line in describe_legs(self.legs, self.run_root):
            print(f"  {line}")
        print(f"  now {now.strftime('%Y-%m-%dT%H:%MZ')} — cron window "
              f"{CRON_WINDOW_START[0]:02d}:{CRON_WINDOW_START[1]:02d}-"
              f"{CRON_WINDOW_END[0]:02d}:{CRON_WINDOW_END[1]:02d} UTC: "
              f"{'INSIDE (a leg would refuse to start)' if in_cron_window(now) else 'outside'}"
              + (" [--ignore-cron-window given]" if self.args.ignore_cron_window else ""))
        arm = None
        for leg in self.legs:
            entry = (self.state.get("legs") or {}).get(leg.id) or {}
            planned = leg in todo
            mark = "RUN " if planned else "skip"
            print(f"\n[{mark}] {leg.id}  profile {leg.profile}  arm {leg.arm.upper()}"
                  f"  state={entry.get('status', 'not run')}"
                  f" collected={bool(entry.get('collected'))}")
            if not planned:
                continue
            if arm != leg.arm or self.args.fresh_containers:
                redeploy = " ".join(self.compose_argv(leg.arm, [
                    "up", "-d", "--no-deps", "--force-recreate",
                    "--scale", f"correlation={self.args.replicas}",
                    "correlation"]))
                if self.args.fresh_containers:
                    print(f"       arm     : ensure {leg.arm.upper()} and "
                          f"force-recreate ALWAYS (--fresh-containers), so this "
                          f"leg starts on cold containers:")
                else:
                    print(f"       arm     : ensure {leg.arm.upper()} — the live "
                          f"arm is READ first and this redeploy runs only if it "
                          f"differs:")
                print(f"                 {redeploy}")
                print(f"                 [cwd {COMPOSE_DIR}, GIT_SHA exported]")
                arm = leg.arm
            print("       verify  : CORR_AGGREGATION_PLANE + corr_agg_enabled == "
                  f"{1 if leg.arm == 'on' else 0} on BOTH replicas "
                  f"(mTLS /metrics on each replica's own ip:8443)")
            residue = f"{self.args.python} {HARNESS} --cleanup-only mlx-"
            print(f"       residue : {residue}")
            launch = " ".join(self.harness_argv(leg, os.path.join(
                self.run_root, f"{leg.dir_prefix}-<MMDDHHMM>")))
            print(f"       run     : {launch}")
            print("       collect : x-<runid> symlink · twin score · "
                  "metrics-final.txt (mTLS :8443) · ttur.tsv (clean scope)")
            if self.args.fresh_containers:
                print("       counters: LEG-SCOPED (fresh containers) — "
                      "metrics-final.txt needs no subtraction")
        if self.args.restore_arm and todo:
            print("\n[RUN ] restore: redeploy with NEITHER A/B overlay "
                  "(compose.agg.yml and compose.agg-off.yml both dropped) — "
                  "docker-compose.yml's own CORR_AGGREGATION_PLANE default "
                  "(ON since 2026-08-30) then applies; the arm is re-read on "
                  "both replicas and recorded")
        print("\nNothing was touched (--dry-run).")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def env_get(path: str, key: str) -> str:
    """One key out of a compose .env. A missing file is not fatal (the caller
    has a default); an unreadable one is reported, never swallowed."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        warn(f"cannot read {path} (errno {exc.errno}: {exc.strerror or exc}) — "
             f"falling back to the documented default; pass --project/--env-file "
             f"explicitly if that default is wrong for this host")
    return ""


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="scale-ab-driver.py",
        description="Unattended, resumable driver for the P3 aggregation-plane "
                    "A/B wave (docs/scale/RUN_PLAN_P3_AB_2026-08-29.md). "
                    "Runs L1..L5 in order, switches the arm exactly twice, and "
                    "collects the evidence each leg is judged on.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan (legs, arm switches, exact commands) "
                         "and exit; touches nothing")
    ap.add_argument("--legs", default="", metavar="SPEC",
                    help="replace the built-in L1..L5 table for THIS invocation "
                         "with a comma-separated list of "
                         "ID:PROFILE:ARM:DIR_PREFIX entries, run in the order "
                         "given (e.g. "
                         "P1:t-storm-2.5k:off:pair-2p5k-off,"
                         "P2:t-storm-2.5k:on:pair-2p5k-on). Ids and dir "
                         "prefixes must be unique, ARM is on|off, and PROFILE "
                         "is checked against the harness's own WORKLOAD_PROFILES "
                         "before anything is touched. Pair it with --state-file: "
                         "the default state file holds the six-leg wave")
    ap.add_argument("--fresh-containers", action="store_true",
                    help="force-recreate the correlation replicas before EVERY "
                         "leg, even when the arm is unchanged, so each leg "
                         "starts on cold containers and its metrics-final.txt "
                         "counters are leg-scoped (P3 verdict section 3.6). "
                         "Without it the arm is switched only when the next leg "
                         "needs the other one")
    ap.add_argument("--from", dest="from_leg", default="", metavar="LEG",
                    help=f"start at this leg regardless of recorded state "
                         f"({', '.join(LEG_IDS)}, or an id from --legs)")
    ap.add_argument("--ignore-cron-window", action="store_true",
                    help="allow a leg to START inside the 03:10-04:40 UTC canary "
                         "window. The 1K canary is disabled as of 2026-08-29; "
                         "if it is re-enabled its onboard absorbs the leg's "
                         "devices, so this flag must be a deliberate choice and "
                         "is stamped on the run's log")
    ap.add_argument("--run-root", default=DEFAULT_RUN_ROOT,
                    help=f"where run dirs, the state file and the scorer "
                         f"symlinks live (default {DEFAULT_RUN_ROOT})")
    ap.add_argument("--lock-file", default="",
                    help="harness run lock (default <run-root>/.lock; the "
                         "harness honours MLX_RUN_LOCK the same way)")
    ap.add_argument("--log-file", default="",
                    help=f"driver log (default <run-root>/{LOG_BASENAME})")
    ap.add_argument("--state-file", default="",
                    help=f"resumable wave state (default "
                         f"<run-root>/{STATE_BASENAME}). A wave run with --legs "
                         f"MUST get its own path: the default file already "
                         f"records another wave's legs, and a leg id that "
                         f"collides with one of them is refused")
    ap.add_argument("--devices", type=int, default=2500,
                    help="devices per leg (default 2500 — the plan's fleet)")
    ap.add_argument("--eps", type=int, default=1000,
                    help="target events/second per leg (default 1000)")
    ap.add_argument("--replicas", type=int, default=2,
                    help="correlation replicas the deployment runs (default 2). "
                         "Losing one mid-redeploy silently halves ingest")
    ap.add_argument("--tenant", default=DEFAULT_TENANT,
                    help=f"tenant whose storm-aggregate cid the clean-scope TTUR "
                         f"query excludes (default {DEFAULT_TENANT!r})")
    ap.add_argument("--project", default="",
                    help="compose project name (default COMPOSE_PROJECT_NAME "
                         "from --env-file, else 'netops')")
    ap.add_argument("--env-file",
                    default=os.path.join(COMPOSE_DIR, ".env"),
                    help="compose .env (default the repo's)")
    ap.add_argument("--python", default=sys.executable or "python3",
                    help="interpreter used for the harness, the twin scorer and "
                         "the cleanup (default: this one)")
    ap.add_argument("--leg-timeout", type=int, default=DEFAULT_LEG_TIMEOUT,
                    help=f"per-leg wall-clock bound in seconds (default "
                         f"{DEFAULT_LEG_TIMEOUT}); on expiry the driver stops "
                         f"and LEAVES the harness running")
    ap.add_argument("--wait-lock-seconds", type=int, default=DEFAULT_WAIT_LOCK,
                    help=f"bounded wait for a live run to finish and the run "
                         f"lock to clear (default {DEFAULT_WAIT_LOCK})")
    ap.add_argument("--wait-log-seconds", type=int, default=DEFAULT_WAIT_LOG,
                    help=f"how often to say what it is waiting on (default "
                         f"{DEFAULT_WAIT_LOG})")
    ap.add_argument("--no-restore-arm", dest="restore_arm", action="store_false",
                    help="do NOT redeploy back to the deployed default (neither "
                         "A/B overlay; docker-compose.yml's own flag default, "
                         "ON since 2026-08-30) after the last leg. The plan's "
                         "section 3.4 restore is on by default")
    ap.set_defaults(restore_arm=True)
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    # Cron-proof PATH (16.2), applied here and not at import.
    os.environ["PATH"] = CRON_PATH + os.pathsep + os.environ.get("PATH", "")
    if not args.project:
        args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"
    if not args.lock_file:
        args.lock_file = os.path.join(args.run_root, LOCK_BASENAME)
    if not args.log_file:
        args.log_file = os.path.join(args.run_root, LOG_BASENAME)
    for path, what in ((HARNESS, "harness"), (TWIN, "twin scorer")):
        if not os.path.exists(path):
            die(f"{what} not found at {path}")
    if not os.path.isdir(COMPOSE_DIR):
        die(f"compose dir not found at {COMPOSE_DIR}")
    for name in COMPOSE_FILES + (AGG_OVERLAY, AGG_OFF_OVERLAY):
        if not os.path.exists(os.path.join(COMPOSE_DIR, name)):
            die(f"compose file {name} missing from {COMPOSE_DIR} — the six-file "
                f"overlay set and BOTH A/B arm pin overlays must exist before "
                f"a wave starts")
    # Constructing the Driver resolves --legs and validates --from against the
    # resolved table. Both are refusals BEFORE anything is touched (exit 2).
    try:
        driver = Driver(args)
    except DriverAbort as exc:
        die(str(exc))
    if args.dry_run:
        try:
            return driver.dry_run()
        except DriverAbort as exc:
            die(str(exc))
    try:
        os.makedirs(args.run_root, exist_ok=True)
    except OSError as exc:
        die(f"cannot create run root {args.run_root} ({exc})")
    set_log_path(args.log_file)
    log(f"start: project={args.project} run_root={args.run_root} "
        f"from={args.from_leg or '(state)'} devices={args.devices} eps={args.eps} "
        f"replicas={args.replicas} tenant={args.tenant} "
        f"state={driver.state_path} fresh_containers={args.fresh_containers}")
    log(f"resolved leg table ({len(driver.legs)} leg(s), source "
        f"{'--legs' if args.legs else 'built-in P3 wave (L1..L5)'}):")
    for line in describe_legs(driver.legs, args.run_root):
        log(line)
    try:
        return driver.run()
    except DriverAbort as exc:
        error(str(exc))
        return 1
    except KeyboardInterrupt:
        error("interrupted — nothing was killed; a launched harness keeps "
              "running under setsid. Re-run the driver to re-attach")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
