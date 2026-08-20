"""Opt-in memory + stall forensics for correlation. Dormant unless enabled.

WHY THIS EXISTS. Correlation sits at ~99.7% of its cgroup cap during a 1k drain
and has been observed stalling its event loop for 112,802 ms — far past the 30 s
Kafka session timeout, so the member is ejected and pending commits fail. Two
questions could not be answered from the metrics the service already emits:

  * what owns the resident memory, and
  * what code is executing during the stall.

The second one is why this module does not live in the event loop. The existing
`loop_lag_watchdog` is an asyncio task: it cannot run *during* a stall, only
notice one afterwards, so it can report that 112 s passed and nothing about
what was running. Stack capture therefore runs on a separate OS thread, with
faulthandler's C-level watchdog armed underneath it as the backstop for the case
where the loop is inside a C call holding the GIL and no Python thread gets
scheduled at all.

CONTRACT WHEN DISABLED (the default): `start()` returns immediately, no thread
is created, no snapshot is taken, tracemalloc is never started, and no file is
written. Nothing in this module is on any hot path.

Enable with CORR_DIAG_MEMORY=true. Intended for diagnostic runs only —
tracemalloc costs real CPU and memory of its own, which is reported in every
snapshot so it can be subtracted rather than confused with the subject.
"""
from __future__ import annotations

import faulthandler
import gc
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

# ── configuration (all dormant by default) ──────────────────────────────────
DIAG_ENABLED = os.environ.get("CORR_DIAG_MEMORY", "").lower() in ("1", "true", "yes")
DIAG_DIR = os.environ.get("CORR_DIAG_DIR", "/data/diagnostics")
# tracemalloc frame depth: deeper is more useful and more expensive.
# tracemalloc frame depth. Cost scales with the number of DISTINCT tracebacks,
# and statistics()/compare_to() walk all of them: at 12 frames those calls took
# 39-96 SECONDS on this workload and were themselves the event-loop stalls the
# first forensic run recorded (2026-08-20). 4 is deep enough to attribute an
# allocation to its call site without making the profiler the top suspect.
DIAG_TM_FRAMES = int(os.environ.get("CORR_DIAG_TM_FRAMES", "4"))
# Heartbeat staleness that triggers a stack dump, in seconds. Two tiers so a
# long stall yields more than one sample and the progression is visible.
DIAG_STALL_WARN_S = float(os.environ.get("CORR_DIAG_STALL_WARN_S", "5"))
DIAG_STALL_DEEP_S = float(os.environ.get("CORR_DIAG_STALL_DEEP_S", "15"))
DIAG_POLL_S = float(os.environ.get("CORR_DIAG_POLL_S", "1.0"))

_started = False
_heartbeat = [0.0]          # mutable cell written by the loop, read by the thread
_stack_dumps = [0]
_snapshots = [0]
_baseline = [None]          # tracemalloc baseline snapshot for diffs


def enabled() -> bool:
    return DIAG_ENABLED


def _path(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def heartbeat() -> None:
    """Called from the event loop. A no-op when diagnostics are off.

    The stall detector watches this value from another thread: if it stops
    advancing, the loop is blocked, and whatever is blocking it is on the stack
    we dump.
    """
    if DIAG_ENABLED:
        _heartbeat[0] = time.monotonic()


# ── plane 1: what the process itself can see ────────────────────────────────

def _proc_memory() -> dict:
    """RSS and the smaps_rollup breakdown. Read from /proc, so it stays true
    even when the interpreter is busy."""
    out: dict = {}
    try:
        with open("/proc/self/statm") as fh:
            parts = fh.read().split()
        out["rss_bytes"] = int(parts[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, IndexError, ValueError) as exc:
        out["rss_error"] = type(exc).__name__
    try:
        with open("/proc/self/smaps_rollup") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                v = v.strip()
                if v.endswith("kB"):
                    out["smaps_" + k.strip().lower()] = int(v[:-2].strip()) * 1024
    except OSError as exc:
        out["smaps_error"] = type(exc).__name__
    return out


def _gc_stats() -> dict:
    counts = gc.get_count()
    stats = gc.get_stats()
    return {
        "gc_enabled": gc.isenabled(),
        "gc_counts": list(counts),
        "gc_threshold": list(gc.get_threshold()),
        "gc_objects": len(gc.get_objects()),
        "gc_collections": [s.get("collections", 0) for s in stats],
        "gc_collected": [s.get("collected", 0) for s in stats],
        "gc_uncollectable": [s.get("uncollectable", 0) for s in stats],
        "gc_garbage": len(gc.garbage),
    }


def _tracemalloc_stats(top_n: int = 15, heavy: bool = True) -> dict:
    """Traced-heap numbers. `heavy` controls the EXPENSIVE half.

    get_traced_memory() is O(1). take_snapshot() + statistics() + compare_to()
    walk every distinct traceback and were measured at 39-96s on this workload,
    which is why they are opt-in per call and must never run on the event loop
    (see the note in `snapshot`).
    """
    import tracemalloc
    if not tracemalloc.is_tracing():
        return {"tracing": False}
    cur, peak = tracemalloc.get_traced_memory()
    out: dict = {
        "tracing": True,
        "traced_current_bytes": cur,
        "traced_peak_bytes": peak,
        # tracemalloc's own overhead, so it can be SUBTRACTED rather than
        # mistaken for the subject's growth.
        "tracemalloc_overhead_bytes": tracemalloc.get_tracemalloc_memory(),
        "heavy": heavy,
    }
    if not heavy:
        return out
    snap = tracemalloc.take_snapshot()
    by_size = snap.statistics("lineno")[:top_n]
    out["top_by_bytes"] = [
        {"file": os.path.basename(st.traceback[0].filename),
         "line": st.traceback[0].lineno,
         "bytes": st.size, "blocks": st.count}
        for st in by_size
    ]
    out["top_by_count"] = [
        {"file": os.path.basename(st.traceback[0].filename),
         "line": st.traceback[0].lineno,
         "bytes": st.size, "blocks": st.count}
        for st in sorted(snap.statistics("lineno"), key=lambda s: -s.count)[:top_n]
    ]
    if _baseline[0] is not None:
        diff = snap.compare_to(_baseline[0], "lineno")[:top_n]
        out["growth_since_baseline"] = [
            {"file": os.path.basename(st.traceback[0].filename),
             "line": st.traceback[0].lineno,
             "bytes_delta": st.size_diff, "blocks_delta": st.count_diff}
            for st in diff
        ]
    return out


def set_baseline() -> None:
    """Pin the snapshot later diffs are measured against."""
    if not DIAG_ENABLED:
        return
    import tracemalloc
    if tracemalloc.is_tracing():
        _baseline[0] = tracemalloc.take_snapshot()


def snapshot(label: str, app_state: dict | None = None,
             heavy: bool = False) -> dict:
    """One synchronized sample. Returns {} when diagnostics are disabled.

    MUST NOT BE CALLED INLINE ON THE EVENT LOOP when `heavy` is set. The first
    forensic run (2026-08-20) recorded six event-loop stalls of 5-96 seconds and
    every single captured stack showed the loop inside
    tracemalloc.statistics()/compare_to() — called from this function by the
    snapshot task. The profiler was the stall. Callers on the loop offload via
    asyncio.to_thread; `heavy` is reserved for the samples that justify the cost
    (threshold crossings), not every periodic tick.
    """
    if not DIAG_ENABLED:
        return {}
    snap = {
        "label": label,
        "ts": datetime.now(timezone.utc).isoformat(),
        "monotonic": time.monotonic(),
        "pid": os.getpid(),
        "process": _proc_memory(),
        "gc": _gc_stats(),
        "python": _tracemalloc_stats(heavy=heavy),
        "app": app_state or {},
        "threads": threading.active_count(),
    }
    _snapshots[0] += 1
    try:
        os.makedirs(DIAG_DIR, exist_ok=True)
        with open(_path("memory-snapshots.jsonl"), "a") as fh:
            fh.write(json.dumps(snap, default=str) + "\n")
    except OSError as exc:
        print(f"diag: snapshot write failed: {type(exc).__name__}", file=sys.stderr)
    return snap


# ── plane 2: the stall detector, off the event loop ─────────────────────────

def _stall_watch() -> None:
    """Watch the loop heartbeat from a plain thread and dump stacks when it
    goes stale.

    Runs OUTSIDE asyncio on purpose: a task cannot observe the stall that is
    preventing it from being scheduled. If the loop is inside a C call holding
    the GIL this thread will not be scheduled either, which is what
    faulthandler.dump_traceback_later covers — it is a C watchdog and does not
    need the GIL.
    """
    warned_at = 0.0
    deep_at = 0.0
    while True:
        time.sleep(DIAG_POLL_S)
        hb = _heartbeat[0]
        if hb <= 0:
            continue
        stale = time.monotonic() - hb
        if stale >= DIAG_STALL_DEEP_S and deep_at != hb:
            deep_at = hb
            _dump_stacks(f"stall-deep-{stale:.0f}s")
        elif stale >= DIAG_STALL_WARN_S and warned_at != hb:
            warned_at = hb
            _dump_stacks(f"stall-warn-{stale:.0f}s")


def _dump_stacks(reason: str) -> None:
    """All thread stacks, appended with a timestamp and reason."""
    _stack_dumps[0] += 1
    try:
        os.makedirs(DIAG_DIR, exist_ok=True)
        with open(_path("stall-stacks.txt"), "a") as fh:
            fh.write(f"\n===== {datetime.now(timezone.utc).isoformat()} "
                     f"reason={reason} dump#{_stack_dumps[0]} =====\n")
            fh.flush()
            faulthandler.dump_traceback(file=fh, all_threads=True)
            fh.flush()
        # A LIGHT snapshot alongside the stack: what the heap looked like when
        # the loop was blocked is half the evidence, but a heavy tracemalloc
        # walk here would hold the GIL and prolong the very stall we are
        # measuring.
        snapshot(f"during-{reason}", heavy=False)
    except OSError as exc:
        print(f"diag: stack dump failed: {type(exc).__name__}", file=sys.stderr)


def stats() -> dict:
    """What the diagnostics themselves did — so a run can prove its evidence is
    complete rather than assuming it."""
    return {
        "enabled": DIAG_ENABLED,
        "started": _started,
        "snapshots_taken": _snapshots[0],
        "stack_dumps": _stack_dumps[0],
        "dir": DIAG_DIR if DIAG_ENABLED else "",
    }


def start() -> None:
    """Arm diagnostics. A no-op unless CORR_DIAG_MEMORY is set."""
    global _started
    if not DIAG_ENABLED or _started:
        return
    import tracemalloc
    try:
        os.makedirs(DIAG_DIR, exist_ok=True)
    except OSError as exc:
        print(f"diag: cannot create {DIAG_DIR}: {type(exc).__name__} — "
              f"diagnostics NOT started", file=sys.stderr)
        return
    tracemalloc.start(DIAG_TM_FRAMES)
    faulthandler.enable()
    _heartbeat[0] = time.monotonic()
    threading.Thread(target=_stall_watch, name="diag-stall-watch",
                     daemon=True).start()
    _started = True
    print(f"diag: memory diagnostics ENABLED (dir={DIAG_DIR}, "
          f"frames={DIAG_TM_FRAMES}, stall warn/deep = "
          f"{DIAG_STALL_WARN_S}/{DIAG_STALL_DEEP_S}s) — this run is diagnostic, "
          f"not qualification evidence", file=sys.stderr)
    snapshot("cold-start", heavy=True)
    set_baseline()
