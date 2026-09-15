#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Host profile — how fast this host really is, so installer budgets can scale.

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md §4.3 (row 3, §3.12 H1).
On 10.70.245.123 every synchronous write cost ≈60 ms and tasks were fully
stalled on IO 22 % of the time; every fixed installer budget was too short and
nothing had measured the disk. This module measures it, boundedly:

  * an O_DSYNC write-latency sample (64 × 8 KiB, hard 5 s cap) in a temporary
    file inside the data directory's filesystem and inside Docker's data root
    (the same filesystem is measured once); the file is always removed;
  * CPU count, MemTotal, and /proc/pressure/{io,cpu} avg60/avg300 when readable.

It writes data/.host-profile.json atomically (0644, no secrets).

CONTRACT (install.py budgets read it — do not deviate):
    {"class": "fast" | "normal" | "slow" | "very-slow",
     "budget_factor": 1 | 1 | 2 | 3, ...other fields informational}
When nothing can be measured no file is written: a consumer then keeps its
standard budgets (never a fifth class).

Owner decision (FMEA §7 Q1): very-slow WARNS in plain language and never
refuses. An "unusable" floor that would refuse is a later calibration on the
rig; UNUSABLE_FLOOR below is deliberately None until then.

CLI:
    python3 scripts/host_profile.py probe --data-dir DIR
        [--docker-root DIR | --no-docker] [--write FILE] [--json]
        [--writes N] [--cap-s S]
  line output: "<class>\\t<budget_factor>\\t<verdict>" then "note: ..." lines.
  exit 0 classified (and saved when --write) · 2 could not measure (first
  field "unknown", nothing written) · 3 classified but the file could not be saved.

Standard library only (CLAUDE.md §6). Timer, filesystem ops, /proc readers and
the docker runner are injectable (tests/test_host_profile.py).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CLASSES: tuple[str, ...] = ("fast", "normal", "slow", "very-slow")
BUDGET_FACTOR: dict[str, int] = {"fast": 1, "normal": 1, "slow": 2, "very-slow": 3}
_RANK = {c: i for i, c in enumerate(CLASSES)}

# p99 synchronous 8 KiB write latency, upper bound (inclusive) per class.
LATENCY_MS = {"fast": 2.0, "normal": 10.0, "slow": 50.0}
# IO PSI "full" (all non-idle tasks stalled on IO), max(avg60, avg300), percent:
# below 5 no effect, from 5 normal, from 10 slow, from 20 very-slow.
IO_FULL_PCT = {"normal": 5.0, "slow": 10.0, "very-slow": 20.0}
CPU_SOME_SLOW_PCT = 60.0   # CPU PSI some avg60 at or above this -> at least slow
LOW_CPU_SLOW = 2           # this many vCPU or fewer -> at least slow
HEALTHY_SSD_MS = 2.0

# Refusal floor (FMEA §7 Q1): NOT implemented. To be calibrated on the rig;
# until then the profile warns and never refuses.
UNUSABLE_FLOOR = None

DEFAULT_WRITES = 64
MAX_WRITES = 256
BLOCK_BYTES = 8192
HARD_CAP_S = 5.0
MIN_CAP_S = 0.5
DEFAULT_GRACE_S = 2.0
DOCKER_TIMEOUT_S = 15
MAX_PROC_BYTES = 64 << 10
MAX_PROFILE_BYTES = 256 << 10
PROBE_PREFIX = ".correlix-host-probe-"


class ProbeError(Exception):
    """A measurement could not be taken; the message says why, in plain words."""


# ── injectable seams ─────────────────────────────────────────────────────────

class OsProbeFS:
    """The real probe filesystem ops."""

    def open_dsync(self, path: str) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_DSYNC | getattr(os, "O_CLOEXEC", 0)
        return os.open(path, flags, 0o600)

    def write(self, fd: int, data: bytes) -> int:
        return os.write(fd, data)

    def close(self, fd: int) -> None:
        os.close(fd)

    def unlink(self, path: str) -> None:
        os.unlink(path)


def _bounded_read_text(path: str, limit: int = MAX_PROC_BYTES) -> str:
    with open(path, "rb") as f:
        return f.read(limit).decode("utf-8", errors="replace")


@dataclass
class HostReaders:
    """Reads /proc files (by canonical /proc/... path) and the CPU count."""
    read_text: Callable[[str], str]
    cpu_count: Callable[[], int]


def default_readers(proc_root: str | None = None) -> HostReaders:
    root = proc_root or os.environ.get("CORRELIX_HOST_PROFILE_PROC", "/proc")

    def read_text(path: str) -> str:
        real = root + path[len("/proc"):] if path.startswith("/proc/") else path
        return _bounded_read_text(real)

    def cpu_count() -> int:
        if hasattr(os, "sched_getaffinity"):
            return len(os.sched_getaffinity(0))
        return os.cpu_count() or 0

    return HostReaders(read_text=read_text, cpu_count=cpu_count)


Runner = Callable[[list[str], int], tuple[int, str, str]]


def subprocess_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Run argv bounded by `timeout` seconds; failures to run become ProbeError."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as e:
        raise ProbeError(f"`{' '.join(argv)}` did not answer within {timeout}s") from e
    except OSError as e:
        raise ProbeError(f"could not run `{argv[0]}`: {e.strerror or e}") from e
    return r.returncode, r.stdout, r.stderr


def docker_root_dir(runner: Runner = subprocess_runner) -> Path:
    rc, out, err = runner(["docker", "info", "--format", "{{.DockerRootDir}}"], DOCKER_TIMEOUT_S)
    if rc != 0:
        last = (err.strip().splitlines() or ["no output"])[-1][:300]
        raise ProbeError(f"could not ask the Docker daemon for its data root (exit {rc}): {last}")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) != 1 or not lines[0].startswith("/"):
        raise ProbeError("docker info returned an unexpected data root")
    return Path(lines[0])


def nearest_existing_dir(path: Path) -> Path:
    p = Path(path)
    while not p.is_dir():
        if p.parent == p:
            break
        p = p.parent
    return p


def _device_of(path: Path) -> int:
    try:
        return os.stat(path).st_dev
    except OSError as e:
        raise ProbeError(f"cannot stat {path}: {e.strerror or e}") from e


# ── write-latency probe ──────────────────────────────────────────────────────

@dataclass
class WriteSample:
    role: str
    path: str
    probed_dir: str
    writes: int = 0
    block_bytes: int = BLOCK_BYTES
    p50_ms: float | None = None
    p99_ms: float | None = None
    max_ms: float | None = None
    capped: bool = False
    stalled: bool = False
    error: str = ""
    same_as: str = ""
    samples_ms: list[float] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("samples_ms")
        return d


def _percentile(sorted_ms: list[float], q: float) -> float:
    idx = min(len(sorted_ms) - 1, max(0, math.ceil(q * len(sorted_ms)) - 1))
    return sorted_ms[idx]


def _cleanup(fs: OsProbeFS, fd: int, path: str) -> None:
    try:
        fs.close(fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            fs.unlink(path)


def _timed_writes(fs: OsProbeFS, path: str, sample: WriteSample, writes: int,
                  cap_s: float, clock: Callable[[], float]) -> None:
    fd = fs.open_dsync(path)
    try:
        buf = secrets.token_bytes(BLOCK_BYTES)
        start = clock()
        for _ in range(writes):
            if clock() - start >= cap_s:
                sample.capped = True
                break
            t = clock()
            fs.write(fd, buf)
            sample.samples_ms.append((clock() - t) * 1000.0)
            sample.writes += 1
    finally:
        _cleanup(fs, fd, path)


def _probe(fs: OsProbeFS, path: str, sample: WriteSample, writes: int, cap_s: float,
           clock: Callable[[], float]) -> None:
    try:
        _timed_writes(fs, path, sample, writes, cap_s, clock)
    except OSError as e:
        what = "create a probe file in" if sample.writes == 0 and not sample.samples_ms else "write to"
        raise ProbeError(f"could not {what} {sample.probed_dir}: {e.strerror or e}") from e


def measure_filesystem(target: Path, role: str, *, fs: OsProbeFS | None = None,
                       clock: Callable[[], float] = time.monotonic,
                       writes: int = DEFAULT_WRITES, cap_s: float = HARD_CAP_S,
                       grace_s: float = DEFAULT_GRACE_S) -> WriteSample:
    """Sample synchronous write latency on the filesystem holding `target`.

    Bounded twice: the loop stops once `cap_s` (clamped to 0.5..5 s) has
    elapsed, and the whole probe runs in a worker thread joined for
    cap_s + grace_s, so a single write that never returns is reported as
    `stalled` instead of hanging the caller. The probe file is removed in every
    outcome (a stalled write removes it when the write finally returns)."""
    fs = fs if fs is not None else OsProbeFS()
    cap_s = min(HARD_CAP_S, max(MIN_CAP_S, cap_s))
    writes = min(MAX_WRITES, max(1, writes))
    probed = nearest_existing_dir(target)
    path = str(probed / f"{PROBE_PREFIX}{secrets.token_hex(8)}")
    sample = WriteSample(role=role, path=str(target), probed_dir=str(probed))
    errors: list[str] = []

    def work() -> None:
        try:
            _probe(fs, path, sample, writes, cap_s, clock)
        except ProbeError as e:
            errors.append(str(e))

    worker = threading.Thread(target=work, name=f"host-probe-{role}", daemon=True)
    worker.start()
    worker.join(cap_s + grace_s)
    if worker.is_alive():
        sample.stalled = True
        sample.error = (f"a single {BLOCK_BYTES // 1024} KiB synchronous write in {probed} "
                        f"did not return within {cap_s + grace_s:.1f}s")
        return sample
    if errors:
        sample.error = errors[0]
    if sample.samples_ms:
        ordered = sorted(sample.samples_ms)
        sample.p50_ms = round(_percentile(ordered, 0.50), 3)
        sample.p99_ms = round(_percentile(ordered, 0.99), 3)
        sample.max_ms = round(ordered[-1], 3)
    return sample


# ── /proc parsing ────────────────────────────────────────────────────────────

def parse_psi(text: str) -> dict:
    out: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        vals: dict[str, float] = {}
        for kv in parts[1:]:
            k, _, v = kv.partition("=")
            if k in ("avg10", "avg60", "avg300"):
                try:
                    vals[k] = float(v)
                except ValueError as e:
                    raise ProbeError(f"unreadable pressure value {kv!r}") from e
        out[parts[0]] = vals
    if "some" not in out:
        raise ProbeError("pressure file has no 'some' line")
    return out


def parse_meminfo_kib(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                return int(fields[1])
    raise ProbeError("MemTotal not found in /proc/meminfo")


def _read_proc(readers: HostReaders, path: str) -> str:
    try:
        return readers.read_text(path)
    except OSError as e:
        raise ProbeError(f"{path} is not readable ({e.strerror or e})") from e


# ── classification ───────────────────────────────────────────────────────────

def latency_class(p99_ms: float) -> str:
    for klass in ("fast", "normal", "slow"):
        if p99_ms <= LATENCY_MS[klass]:
            return klass
    return "very-slow"


def sample_class(s: WriteSample) -> str | None:
    if s.stalled:
        return "very-slow"
    if s.p99_ms is None:
        return None
    return latency_class(s.p99_ms)


def io_pressure_class(full_pct: float) -> str:
    for klass in ("very-slow", "slow", "normal"):
        if full_pct >= IO_FULL_PCT[klass]:
            return klass
    return "fast"


def _worst(classes: list[str]) -> str:
    return max(classes, key=lambda c: _RANK[c])


def _verdict(klass: str | None, reasons: list[str], first_error: str) -> str:
    detail = "; ".join(reasons[:3])
    if klass is None:
        why = first_error or "no measurement was possible"
        return (f"Could not measure this host's speed ({why}). Standard time budgets apply "
                "and no profile was saved.")
    if klass == "fast":
        return f"This host is fast ({detail}). Standard time budgets apply."
    if klass == "normal":
        return f"This host's speed is normal ({detail}). Standard time budgets apply."
    if klass == "slow":
        return (f"This host is slow ({detail}). The install will take longer; the installer "
                "allows twice the usual time for services to start.")
    return (f"WARNING: this host is much slower than recommended ({detail}). The install will "
            "take much longer and first boots are at risk; the installer allows three times "
            "the usual time. For production use SSD storage or a less busy host.")


def build_profile(data_dir: Path, docker_root: Path | None, *, fs: OsProbeFS | None = None,
                  clock: Callable[[], float] = time.monotonic,
                  readers: HostReaders | None = None,
                  device_of: Callable[[Path], int] = _device_of,
                  writes: int = DEFAULT_WRITES, cap_s: float = HARD_CAP_S,
                  grace_s: float = DEFAULT_GRACE_S,
                  docker_note: str = "") -> dict:
    readers = readers if readers is not None else default_readers()
    notes: list[str] = [docker_note] if docker_note else []
    reasons: list[str] = []
    votes: list[str] = []
    measured = False

    samples: list[WriteSample] = []
    targets = [("data", Path(data_dir))] + ([("docker-root", Path(docker_root))] if docker_root else [])
    devices: dict[int, str] = {}
    for role, target in targets:
        dev: int | None
        try:
            dev = device_of(nearest_existing_dir(target))
        except ProbeError as e:
            notes.append(str(e))
            dev = None
        if dev is not None and dev in devices:
            first = next(s for s in samples if s.role == devices[dev])
            twin = WriteSample(role=role, path=str(target), probed_dir=first.probed_dir,
                               same_as=first.role)
            samples.append(twin)
            continue
        s = measure_filesystem(target, role, fs=fs, clock=clock, writes=writes, cap_s=cap_s,
                               grace_s=grace_s)
        samples.append(s)
        if dev is not None:
            devices[dev] = role
        klass = sample_class(s)
        if s.error:
            notes.append(f"{role}: {s.error}")
        if klass is not None:
            measured = True
            votes.append(klass)
            if s.stalled:
                reasons.append(f"a synchronous write on the {role} filesystem stalled")
            else:
                assert s.p99_ms is not None
                ratio = s.p99_ms / HEALTHY_SSD_MS
                scale = f", about {ratio:.0f}x a healthy SSD" if ratio >= 2 else ""
                reasons.append(f"{role} filesystem p99 synchronous write {s.p99_ms:.1f} ms{scale}")

    psi: dict[str, dict | None] = {"io": None, "cpu": None}
    for res in ("io", "cpu"):
        try:
            psi[res] = parse_psi(_read_proc(readers, f"/proc/pressure/{res}"))
        except ProbeError as e:
            notes.append(f"{res} pressure (PSI) not available: {e}")
    io = psi["io"]
    if io is not None and "full" in io:
        full = max(io["full"].get("avg60", 0.0), io["full"].get("avg300", 0.0))
        measured = True
        votes.append(io_pressure_class(full))
        if full >= IO_FULL_PCT["normal"]:
            reasons.append(f"tasks fully stalled on disk IO {full:.1f} % of the time")
    cpu_psi = psi["cpu"]
    if cpu_psi is not None and cpu_psi["some"].get("avg60", 0.0) >= CPU_SOME_SLOW_PCT:
        votes.append("slow")
        reasons.append(f"CPU pressure {cpu_psi['some']['avg60']:.1f} %")

    cpus = 0
    try:
        cpus = int(readers.cpu_count())
    except (ValueError, TypeError) as e:
        notes.append(f"CPU count not readable: {e}")
    if 0 < cpus <= LOW_CPU_SLOW:
        votes.append("slow")
        reasons.append(f"only {cpus} vCPU")
    mem_kib = None
    try:
        mem_kib = parse_meminfo_kib(_read_proc(readers, "/proc/meminfo"))
    except ProbeError as e:
        notes.append(f"memory size not readable: {e}")

    klass = _worst(votes) if measured and votes else None
    first_error = next((s.error for s in samples if s.error), "")
    return {
        "version": 1,
        "measured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "class": klass,
        "budget_factor": BUDGET_FACTOR[klass] if klass else None,
        "verdict": _verdict(klass, reasons, first_error),
        "reasons": reasons,
        "notes": notes,
        "cpus": cpus,
        "mem_total_kib": mem_kib,
        "psi": psi,
        "filesystems": [s.to_dict() for s in samples],
        "thresholds": {"latency_p99_ms": LATENCY_MS, "io_full_pct": IO_FULL_PCT,
                       "cpu_some_slow_pct": CPU_SOME_SLOW_PCT, "low_cpu_slow": LOW_CPU_SLOW},
        "refusal": ("never: a very slow host is warned about, not refused; an 'unusable' "
                    "floor will be calibrated on the rig (FMEA 2026-09-15 §7 Q1)"),
    }


# ── the file ─────────────────────────────────────────────────────────────────

def _check_contract(doc: dict) -> None:
    klass = doc.get("class")
    if klass not in BUDGET_FACTOR:
        raise ValueError(f"profile class {klass!r} is not one of {CLASSES}")
    if doc.get("budget_factor") != BUDGET_FACTOR[klass]:
        raise ValueError(f"budget_factor for {klass} must be {BUDGET_FACTOR[klass]}")


def write_profile(path: Path, doc: dict) -> None:
    """Atomically write the profile (0644). Raises ValueError for a document
    outside the contract, ProbeError when it cannot be written."""
    _check_contract(doc)
    path = Path(path)
    parent = path.parent
    if not parent.is_dir():
        if not parent.parent.is_dir():
            raise ProbeError(f"{parent.parent} does not exist, so {parent} is not created")
        try:
            parent.mkdir(mode=0o755, exist_ok=True)
        except OSError as e:
            raise ProbeError(f"cannot create {parent}: {e.strerror or e}") from e
    tmp = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o644)
        try:
            os.fchmod(fd, 0o644)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError as e:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise ProbeError(f"cannot write {path}: {e.strerror or e}") from e


def load_profile(path: Path) -> dict:
    """Read and validate a saved profile (bounded)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PROFILE_BYTES + 1)
    except OSError as e:
        raise ProbeError(f"cannot read {path}: {e.strerror or e}") from e
    if len(raw) > MAX_PROFILE_BYTES:
        raise ProbeError(f"{path} is larger than {MAX_PROFILE_BYTES} bytes")
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ProbeError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ProbeError(f"{path} is not a JSON object")
    try:
        _check_contract(doc)
    except ValueError as e:
        raise ProbeError(f"{path}: {e}") from e
    return doc


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="host_profile", description="Measure this host's speed.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--data-dir", required=True, type=Path)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--docker-root", type=Path)
    g.add_argument("--no-docker", action="store_true")
    p.add_argument("--write", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--writes", type=int, default=DEFAULT_WRITES)
    p.add_argument("--cap-s", type=float, default=HARD_CAP_S)
    args = ap.parse_args(argv)

    docker_root: Path | None = None
    docker_note = ""
    if args.docker_root:
        docker_root = args.docker_root
    elif not args.no_docker:
        try:
            docker_root = docker_root_dir()
        except ProbeError as e:
            docker_note = f"Docker's data root was not measured: {e}"

    doc = build_profile(args.data_dir, docker_root, writes=args.writes, cap_s=args.cap_s,
                        docker_note=docker_note)
    rc = 0 if doc["class"] else 2
    save_note = ""
    if args.write and doc["class"]:
        try:
            write_profile(args.write, doc)
            save_note = f"saved: {args.write}"
        except ProbeError as e:
            rc = 3
            save_note = f"not saved: {e}"
    elif args.write:
        save_note = "not saved: nothing could be measured"

    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
        if save_note:
            print(save_note, file=sys.stderr)
        return rc
    print(f"{doc['class'] or 'unknown'}\t{doc['budget_factor'] or '-'}\t{doc['verdict']}")
    for n in doc["notes"]:
        print(f"note: {n}")
    if save_note:
        print(save_note)
    return rc


if __name__ == "__main__":
    sys.exit(main())
