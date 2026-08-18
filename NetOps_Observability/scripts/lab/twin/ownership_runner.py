"""Orchestration for the tracker-155 ownership-movement scenarios.

Pairs with ownership.py, which holds the PASS/FAIL/INVALID judge. This module
does the moving and the measuring; it decides nothing. Every mutation is
declared as an `Action` first and executed second, so a dry run is the same code
path as a live run minus the execution — not a separate, less-tested branch.

SAFETY MODEL (three independent interlocks, all default-closed)
---------------------------------------------------------------
1. DRY RUN IS THE DEFAULT. `execute()` performs nothing unless explicitly told
   `dry_run=False`. A caller that forgets the flag gets a plan, not a restart.
2. SOAK INTERLOCK. The 72h appliance soak baselined correlation RSS at
   2026-08-16T23:14; these scenarios are deliberate replica restarts, which
   reset the RSS and uptime the soak exists to measure. `soak_interlock()`
   reads the baseline and REFUSES every mutating action until 72h have elapsed.
   This is a hard guard in code, not a note in a runbook, because a convention
   that depends on remembering is not an interlock.
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

def soak_interlock(now: _dt.datetime, baseline_path: str,
                   soak_hours: float = SOAK_HOURS) -> tuple[bool, str]:
    """(allowed, reason). Default-CLOSED on every ambiguity.

    An unreadable or malformed baseline BLOCKS rather than allows: "I could not
    tell whether the soak is running" must never resolve to "go ahead". That is
    the same rule the twin scorer learned the hard way — a lost measurement is
    not a negative result.
    """
    if not os.path.exists(baseline_path):
        return True, ("no soak baseline found — no soak in progress "
                      f"({baseline_path})")
    try:
        with open(baseline_path) as fh:
            data = json.load(fh)
        start = _dt.datetime.fromisoformat(data["soak_start_utc"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, (f"soak baseline unreadable ({type(exc).__name__}) — "
                       "REFUSING to mutate. Cannot prove the soak is finished, "
                       "and 'unknown' is not 'clear'.")
    end = start + _dt.timedelta(hours=soak_hours)
    if now < end:
        left = (end - now).total_seconds() / 3600.0
        return False, (
            f"72h soak in progress: started {start.isoformat()}, ends "
            f"{end.isoformat()} ({left:.1f}h remaining). These scenarios "
            "restart correlation, which resets the RSS and uptime the soak "
            "measures. REFUSING.")
    return True, (f"soak complete (ended {end.isoformat()})")


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
