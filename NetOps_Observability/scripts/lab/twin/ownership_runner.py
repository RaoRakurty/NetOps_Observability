# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Orchestration for the tracker-155 ownership-movement scenarios.

Pairs with ownership.py, which holds the PASS/FAIL/INVALID judge. This module
does the moving and the measuring; it decides nothing. Every mutation is
declared as an `Action` first and executed second, so a dry run is the same code
path as a live run minus the execution — not a separate, less-tested branch.

SAFETY MODEL (three independent interlocks, all default-closed)
---------------------------------------------------------------
1. DRY RUN IS THE DEFAULT. `execute()` performs nothing unless explicitly told
   `dry_run=False`. A caller that forgets the flag gets a plan, not a restart.
2. SOAK INTERLOCK. These scenarios are deliberate replica restarts, which
   reset the RSS and uptime an appliance soak exists to measure.
   `soak_interlock()` REFUSES every mutating action until the window has
   elapsed AND the soak's subject is provably the same set of containers it
   started with. This is a hard guard in code, not a note in a runbook,
   because a convention that depends on remembering is not an interlock.

   It checks IDENTITY, not just the clock (tracker 158). The first version
   compared wall time to start+72h and nothing else. On 2026-08-19 that proved
   insufficient in the worst way: both correlation replicas had been recreated
   16h35m into the window (deploying 94e8561d), the soak had been measuring
   nothing since, and the interlock would still have opened on schedule and
   called it "soak complete". Elapsed time cannot tell you the subject
   survived. A gate that cannot go red for the failure that actually occurred
   is not a gate — it is defect class 2b wearing a gate's clothes, which is
   exactly what this module was built to prevent elsewhere.
3. LAB PREFLIGHT. `preflight()` proves the target is the lab stack before
   anything mutates: compose project, loopback base URL, expected services, and
   an explicit refusal on any non-loopback host.

`partition_raise` carries a FOURTH interlock of its own (`allow_partition_raise`)
because it is the one scenario that CANNOT be undone: Kafka partitions are
raise-only and `kafka-init` only ALTERs upward, so `restore()` can return the
replica count but can never return the partition count. Grouping an irreversible
action behind the same switch as five reversible ones would be a trap.

WHY EVERY MOVE CAPTURES BEFORE AND AFTER
-----------------------------------------
The judge needs proof the run was not vacuous. A move performed while the
in-flight window is empty exercises nothing, so `Snapshot.open_objects` at the
moment of the move is the precondition that decides PASS vs INVALID — see
ownership.verdict().
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys as _sys
from dataclasses import dataclass, field

from ownership import MOVES

SOAK_HOURS = 72.0
CORR = "correlation"
GROUP = "netops-correlation"

# A lab stack answers on loopback. Anything else is refused outright rather
# than probed — a preflight that tries to identify production by fingerprinting
# it has already connected to it.
LAB_HOSTS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")


@dataclass(frozen=True)
class Action:
    """One intended mutation. `cmd` is argv, never a shell string."""
    kind: str
    describe: str
    cmd: tuple[str, ...] = ()
    settle_s: float = 0.0
    irreversible: bool = False


@dataclass
class Snapshot:
    """Everything the judge and the report need, captured at one instant."""
    at: str = ""
    assignment: dict = field(default_factory=dict)     # replica -> partitions
    consumer_state: dict = field(default_factory=dict)  # replica -> state enum
    open_objects: int = 0
    cold_partitions: dict = field(default_factory=dict)
    lag_total: int = 0
    lag_partitions: int = 0
    replicas: int = 0
    rca: dict = field(default_factory=dict)            # matched/total
    isolation_violations: tuple = ()

    def to_dict(self) -> dict:
        return {
            "at": self.at, "assignment": self.assignment,
            "consumer_state": self.consumer_state,
            "open_objects": self.open_objects,
            "cold_partitions": self.cold_partitions,
            "lag_total": self.lag_total, "lag_partitions": self.lag_partitions,
            "replicas": self.replicas, "rca": self.rca,
            "isolation_violations": list(self.isolation_violations),
        }


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def capture(stack, at: str, rca: dict | None = None,
            isolation_violations: tuple = ()) -> Snapshot:
    """Read-only snapshot of everything the judge and the report need.

    Field names are read from the LIVE Phase 1 contract (`/healthz.consumer`:
    state · owned_partition_count · cold_partitions · assignment ·
    partition_totals · rebalances · zero_assignments · revoke_*; and
    `engine_v2.open_objects`), verified against a running replica rather than
    taken from a design note — all three names assumed before Phase 1 landed
    turned out to be wrong.
    """
    hz = stack.corr_healthz_all() or {}
    assignment: dict = {}
    states: dict = {}
    cold: dict = {}
    open_objects = 0
    for cid, doc in hz.items():
        short = cid[:12]
        c = (doc or {}).get("consumer") or {}
        e = (doc or {}).get("engine_v2") or {}
        assignment[short] = {
            "owned": c.get("owned_partition_count", 0),
            "topics": c.get("assignment", {}),
        }
        states[short] = c.get("state", "unknown")
        cold[short] = c.get("cold_partitions", [])
        open_objects += int(e.get("open_objects") or 0)

    lag_total, lag_parts = (0, 0)
    try:
        lag_total, lag_parts = stack.group_lag_total(GROUP)
    except Exception:  # noqa: BLE001 — a lag read failure must not be silent
        lag_total, lag_parts = (-1, -1)

    return Snapshot(
        at=at, assignment=assignment, consumer_state=states,
        open_objects=open_objects, cold_partitions=cold,
        lag_total=lag_total, lag_partitions=lag_parts,
        replicas=len(stack.cids(CORR)), rca=rca or {},
        isolation_violations=tuple(isolation_violations),
    )


def in_flight_ready(snap: Snapshot) -> tuple[bool, str]:
    """Is there anything to lose if ownership moves right now?

    THE IDLE LAB ANSWERS NO. Measured 2026-08-18 on the live stack:
    engine_v2.open_objects == 0 with the twin idle. So a scenario fired against
    a quiet stack moves partitions with an EMPTY window, loses nothing, scores
    identically, and would be reported as PASS by any two-outcome harness. It
    is the exact trap that made the P1 giant-object burst prove nothing about
    its own hypothesis (the ladder cleanup had emptied the tenant registry).

    Callers MUST drive a twin story and wait for this to go true BEFORE
    executing a move; if it is still false at move time, ownership.verdict()
    returns INVALID rather than PASS.
    """
    if snap.open_objects > 0:
        return True, f"{snap.open_objects} correlation object(s) in flight"
    return False, ("no in-flight correlation state (open_objects=0) — a move "
                   "now would exercise nothing; drive a twin story first")


# --------------------------------------------------------------------------
# Interlocks
# --------------------------------------------------------------------------

SOAK_NONE = "NO_SOAK"        # no baseline on disk — nothing to protect
SOAK_RUNNING = "RUNNING"     # inside the 72h window
SOAK_COMPLETE = "COMPLETE"   # window elapsed AND the subject is provably intact
SOAK_INVALID = "INVALID"     # subject replaced, or continuity unprovable

# Only these two permit mutation. INVALID does NOT — an invalid soak has
# already lost its evidence, but silently proceeding would let the next report
# inherit the word "complete" for a measurement that never happened.
_MUTATION_OK = (SOAK_NONE, SOAK_COMPLETE)

_IDENTITY_TIMEOUT = 30


def _sh(cmd: tuple[str, ...], timeout: int = _IDENTITY_TIMEOUT):
    """Bounded subprocess -> (rc, out, err). Never raises; never swallows."""
    import subprocess
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:4])} ..."
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)


def subject_identity(project: str = "netops", service: str = CORR,
                     runner=None) -> list[dict]:
    """Live identity of the soak subject: id + started_at + image per replica.

    Returns [] on ANY failure. This function never decides what that means —
    the caller treats an empty probe as *unverifiable*, which is INVALID, not
    "fine". A probe that cannot see the subject must never read as intact.
    """
    run = runner or _sh
    rc, out, err = run(("docker", "ps", "-q",
                        "--filter", f"label=com.docker.compose.project={project}",
                        "--filter", f"label=com.docker.compose.service={service}"))
    if rc != 0:
        print(f"twin: WARNING: subject probe (docker ps) failed rc={rc}: "
              f"{(err or out).strip()}", file=_sys.stderr, flush=True)
        return []
    ids = out.split()
    if not ids:
        return []
    rc, out, err = run(("docker", "inspect", "-f",
                        "{{.Id}}\t{{.State.StartedAt}}\t{{.Image}}\t{{.Name}}",
                        *ids))
    if rc != 0:
        print(f"twin: WARNING: subject probe (docker inspect) failed rc={rc}: "
              f"{(err or out).strip()}", file=_sys.stderr, flush=True)
        return []
    found = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 4:
            continue
        cid, started, image, name = parts
        found.append({"id": cid[:12], "started_at": started,
                      "image": image[:19], "name": name.lstrip("/")})
    return sorted(found, key=lambda c: c["id"])


def _identity_map(entries) -> dict:
    """{short id: (started_at, image)} — the tuple that must not drift."""
    out = {}
    for c in entries or ():
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", ""))[:12]
        if cid:
            out[cid] = (c.get("started_at"), c.get("image"))
    return out


def soak_state(now: _dt.datetime, baseline_path: str,
               soak_hours: float = SOAK_HOURS,
               identity_probe=None) -> tuple[str, str]:
    """(state, reason) — the tri-state the clock alone cannot produce.

    THE BUG THIS EXISTS TO CLOSE (tracker 158, found 2026-08-19): the previous
    version compared wall clock to start+72h and nothing else, so it returned
    "soak complete" for a soak whose two correlation replicas had been
    RECREATED 16h35m into the window (deploying 94e8561d). The window elapsing
    says nothing about whether the thing being measured survived it. A gate
    that cannot go red for the failure that actually happened is not a gate.
    """
    if not os.path.exists(baseline_path):
        return SOAK_NONE, (
            f"no soak baseline found — no soak in progress ({baseline_path}). "
            "DELIBERATE (tracker 158): absence means there is no soak to "
            "protect, so this opens the gate. The consequence is accepted "
            "with eyes open — deleting the baseline opens it too — because "
            "the alternative blocks the harness forever on any host that "
            "never ran a soak. The baseline is a generated artifact of "
            "soak_baseline.py, never a hand-edit.")
    try:
        with open(baseline_path) as fh:
            data = json.load(fh)
        start = _dt.datetime.fromisoformat(data["soak_start_utc"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return SOAK_INVALID, (
            f"soak baseline unreadable ({type(exc).__name__}) — REFUSING to "
            "mutate. Cannot prove the soak is finished, and 'unknown' is not "
            "'clear'.")

    end = start + _dt.timedelta(hours=soak_hours)
    if now < end:
        left = (end - now).total_seconds() / 3600.0
        return SOAK_RUNNING, (
            f"72h soak in progress: started {start.isoformat()}, ends "
            f"{end.isoformat()} ({left:.1f}h remaining). These scenarios "
            "restart correlation, which resets the RSS and uptime the soak "
            "measures. REFUSING.")

    # The window has elapsed. Everything above here the old clock could do;
    # everything below is the half it could not.
    recorded = data.get("subject")
    if not recorded:
        return SOAK_INVALID, (
            f"72h elapsed (ended {end.isoformat()}) but this baseline records "
            "NO subject identity, so nothing in it can prove the measured "
            "containers survived the window. Unverifiable is INVALID, not "
            "complete — re-baseline with soak_baseline.py. REFUSING. (Every "
            "baseline written before 2026-08-19 is in this state, including "
            "the one whose subject was in fact replaced 16h35m in.)")

    if isinstance(recorded, dict):
        recorded = recorded.get("containers")
    if not recorded:
        return SOAK_INVALID, (
            "72h elapsed but the baseline's subject block records no "
            "containers. Unverifiable is INVALID — REFUSING.")

    live = (identity_probe or subject_identity)()
    if not live:
        return SOAK_INVALID, (
            "72h elapsed but the live subject could not be identified (probe "
            "returned nothing). Unverified is not intact — REFUSING.")

    want, have = _identity_map(recorded), _identity_map(live)
    if not want:
        return SOAK_INVALID, (
            "72h elapsed but the recorded subject identity is malformed (no "
            "usable container ids). REFUSING.")
    if want.keys() != have.keys():
        gone = sorted(set(want) - set(have))
        added = sorted(set(have) - set(want))
        return SOAK_INVALID, (
            f"SUBJECT REPLACED: {len(want)} container(s) baselined, "
            f"{len(have)} live. Gone: {gone or 'none'}; new: {added or 'none'}. "
            "The soak stopped measuring its subject at that point — its RSS "
            "arm is void regardless of what the clock says. REFUSING; "
            "re-baseline from a known-green build.")
    drift = sorted(cid for cid in want if want[cid] != have[cid])
    if drift:
        detail = "; ".join(
            f"{cid}: baselined started={want[cid][0]} image={want[cid][1]} "
            f"-> live started={have[cid][0]} image={have[cid][1]}"
            for cid in drift)
        return SOAK_INVALID, (
            f"SUBJECT RESTARTED OR REBUILT: {detail}. A container that kept "
            "its id but restarted has still reset the RSS the soak measures. "
            "REFUSING; re-baseline from a known-green build.")

    return SOAK_COMPLETE, (
        f"soak complete (ended {end.isoformat()}) and all {len(want)} subject "
        "container(s) are the ones baselined, same start time and same image "
        "— the measurement covers the whole window.")


def soak_interlock(now: _dt.datetime, baseline_path: str,
                   soak_hours: float = SOAK_HOURS,
                   identity_probe=None) -> tuple[bool, str]:
    """(allowed, reason). Default-CLOSED on every ambiguity.

    Thin policy layer over `soak_state()`: mutation is permitted only when
    there is no soak, or when the soak both finished AND provably measured the
    same containers throughout. INVALID never reads as PASS — it blocks, and
    it says why.
    """
    state, reason = soak_state(now, baseline_path, soak_hours=soak_hours,
                               identity_probe=identity_probe)
    return state in _MUTATION_OK, f"[{state}] {reason}"


def preflight(stack, expect_project: str = "netops") -> tuple[bool, list[str]]:
    """Prove we are pointed at the lab stack. (ok, findings)."""
    findings: list[str] = []
    ok = True

    host = (stack.base_url.split("//")[-1].split(":")[0].split("/")[0]
            if stack.base_url else "")
    if host not in LAB_HOSTS:
        ok = False
        findings.append(
            f"REFUSED: base_url host {host!r} is not loopback. This harness "
            "restarts containers and is lab-only; it must never be aimed at a "
            "remote stack.")
    else:
        findings.append(f"base_url host {host} is loopback")

    if stack.project != expect_project:
        ok = False
        findings.append(f"REFUSED: compose project {stack.project!r} != "
                        f"expected lab project {expect_project!r}")
    else:
        findings.append(f"compose project {stack.project}")

    cids = stack.cids(CORR)
    if not cids:
        ok = False
        findings.append("REFUSED: no correlation containers found")
    else:
        findings.append(f"{len(cids)} correlation replica(s) present")
        if len(cids) < 2:
            ok = False
            findings.append(
                "REFUSED: ownership movement needs >=2 replicas; with one "
                "member partitions never move between members and every "
                "scenario would be vacuous")
    return ok, findings


# --------------------------------------------------------------------------
# Plans — pure, no I/O
# --------------------------------------------------------------------------

def plan_move(move: str, replicas: int, project: str,
              env_file: str) -> list[Action]:
    """The ordered mutations for one scenario. Pure: builds argv, runs nothing."""
    if move not in MOVES:
        raise ValueError(f"unknown move {move!r}")
    base = ("docker", "compose", "--project-name", project,
            "--env-file", env_file)

    def scale(n: int) -> Action:
        return Action("scale", f"scale {CORR} to {n}",
                      base + ("up", "-d", "--no-recreate",
                              "--scale", f"{CORR}={n}"), settle_s=45.0)

    if move == "restart_one":
        return [Action("restart", f"restart one {CORR} replica",
                       base + ("restart", "--timeout", "30", CORR),
                       settle_s=45.0)]
    if move == "scale_up":
        return [scale(replicas + 1)]
    if move == "scale_down":
        return [scale(max(2, replicas - 1))]
    if move == "rolling_restart":
        return [Action("restart", f"rolling restart pass {i + 1}/{replicas}",
                       base + ("restart", "--timeout", "30", CORR),
                       settle_s=45.0)
                for i in range(replicas)]
    if move == "rapid_rebalance":
        # Deliberately does NOT settle between steps — the point is churn.
        return [scale(replicas + 1), scale(replicas), scale(replicas + 1),
                scale(replicas)]
    # partition_raise
    return [Action(
        "partitions",
        "raise BUS_PARTITIONS and re-run kafka-init (IRREVERSIBLE)",
        base + ("--profile", "embedded-bus", "up", "kafka-init"),
        settle_s=60.0, irreversible=True)]


def restore_plan(original_replicas: int, project: str,
                 env_file: str) -> list[Action]:
    """Return the fleet to its pre-run shape.

    NOTE what this deliberately does NOT do: it cannot restore BUS_PARTITIONS.
    Kafka partitions are raise-only, so `partition_raise` permanently changes
    the lab broker and no cleanup can undo it.
    """
    base = ("docker", "compose", "--project-name", project,
            "--env-file", env_file)
    return [Action("scale", f"restore {CORR} to {original_replicas}",
                   base + ("up", "-d", "--no-recreate",
                           "--scale", f"{CORR}={original_replicas}"),
                   settle_s=45.0)]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def execute(actions: list[Action], *, dry_run: bool = True,
            interlock: tuple[bool, str] = (False, "interlock not evaluated"),
            preflight_ok: bool = False,
            allow_partition_raise: bool = False,
            runner=None, sleeper=None) -> dict:
    """Run (or narrate) a list of Actions. Default-closed on every gate.

    `runner(cmd) -> (rc, out, err)` and `sleeper(seconds)` are injected so the
    unit tests can prove exactly which commands WOULD run without a stack, and
    prove that the interlocks actually block.
    """
    performed: list[dict] = []
    allowed, reason = interlock

    for a in actions:
        record = {"kind": a.kind, "describe": a.describe,
                  "cmd": list(a.cmd), "irreversible": a.irreversible}
        if dry_run:
            record["status"] = "DRY-RUN (not executed)"
            performed.append(record)
            continue
        if not preflight_ok:
            record["status"] = "REFUSED: preflight did not pass"
            performed.append(record)
            return {"executed": False, "reason": record["status"],
                    "actions": performed}
        if not allowed:
            record["status"] = f"REFUSED: {reason}"
            performed.append(record)
            return {"executed": False, "reason": reason, "actions": performed}
        if a.irreversible and not allow_partition_raise:
            record["status"] = ("REFUSED: irreversible action needs explicit "
                                "allow_partition_raise (partitions cannot be "
                                "lowered; restore() cannot undo this)")
            performed.append(record)
            return {"executed": False, "reason": record["status"],
                    "actions": performed}

        rc, out, err = runner(list(a.cmd))
        record["rc"] = rc
        if rc == 0:
            record["status"] = "ok"
        else:
            # docker compose writes plenty of diagnostics to STDOUT, so a
            # failure report that keeps only stderr often keeps the empty half.
            detail = (err or "").strip() or (out or "").strip()
            record["status"] = f"FAILED rc={rc}: {detail[:200]}"
        performed.append(record)
        if rc != 0:
            return {"executed": False, "reason": record["status"],
                    "actions": performed}
        if a.settle_s and sleeper:
            sleeper(a.settle_s)

    return {"executed": not dry_run, "reason": reason if not dry_run else
            "dry run", "actions": performed}
