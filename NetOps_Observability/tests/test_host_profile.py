# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Host profile -> budgets (FMEA 2026-09-15 §4.3, row 3, §3.12 H1, §7 Q1).

scripts/host_profile.py measures how fast this host really is — a bounded
O_DSYNC write-latency sample on the data directory's filesystem and on
Docker's data root, CPU count, MemTotal and IO/CPU pressure — and writes
data/.host-profile.json, which install.py's budgets scale from.

CONTRACT (fixed with the install.py budget consumer, do not deviate):
    data/.host-profile.json is a JSON object with at least
      "class"          one of "fast" | "normal" | "slow" | "very-slow"
      "budget_factor"  1 for fast and normal, 2 for slow, 3 for very-slow
When nothing can be measured, NO file is written (never a fifth class).

Calibration pinned here: the .123 box (≈60 ms per synchronous write, IO PSI
full avg300 ≈22 %) classifies very-slow on EITHER signal alone; a healthy SSD
(<2 ms p99) is fast. Owner Q1: very-slow WARNS in plain language, it never
refuses — an "unusable" floor is a later rig calibration.

Every test injects the timer, the filesystem ops, /proc readers and the
docker runner, except the two that run the real probe inside tmp_path.

Run:  python3 -m pytest tests/test_host_profile.py -v
"""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import host_profile as hp
import install_signatures

PSI_QUIET = ("some avg10=0.00 avg60=0.10 avg300=0.05 total=1234\n"
             "full avg10=0.00 avg60=0.00 avg300=0.00 total=99\n")
PSI_123_IO = ("some avg10=30.10 avg60=35.00 avg300=36.50 total=987654321\n"
              "full avg10=20.00 avg60=21.00 avg300=22.50 total=123456789\n")
MEMINFO = "MemTotal:       16336988 kB\nMemFree:         1234 kB\n"


# ── fakes ────────────────────────────────────────────────────────────────────

class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeFS:
    """Probe filesystem ops; each write costs `write_ms` on the fake clock."""

    def __init__(self, clock: FakeClock, write_ms: float = 0.5, *, fail_open: int = 0,
                 fail_write_at: int = -1, block: threading.Event | None = None) -> None:
        self.clock = clock
        self.write_ms = write_ms
        self.fail_open = fail_open
        self.fail_write_at = fail_write_at
        self.block = block
        self.live: set[str] = set()
        self.created: list[str] = []
        self.writes = 0
        self.closed = 0

    def open_dsync(self, path: str) -> int:
        if self.fail_open:
            raise OSError(self.fail_open, os.strerror(self.fail_open), path)
        self.live.add(path)
        self.created.append(path)
        return 42

    def write(self, fd: int, data: bytes) -> int:
        if self.block is not None:
            self.block.wait(10)
        if self.writes == self.fail_write_at:
            raise OSError(errno.ENOSPC, "No space left on device")
        self.writes += 1
        self.clock.advance(self.write_ms / 1000.0)
        return len(data)

    def close(self, fd: int) -> None:
        self.closed += 1

    def unlink(self, path: str) -> None:
        self.live.discard(path)


def readers(*, io: str | None = PSI_QUIET, cpu: str | None = PSI_QUIET, cpus: int = 8,
            meminfo: str | None = MEMINFO) -> hp.HostReaders:
    files = {"/proc/pressure/io": io, "/proc/pressure/cpu": cpu, "/proc/meminfo": meminfo}

    def read_text(path: str) -> str:
        v = files.get(path)
        if v is None:
            raise FileNotFoundError(errno.ENOENT, "No such file", path)
        return v

    return hp.HostReaders(read_text=read_text, cpu_count=lambda: cpus)


def profile(tmp_path: Path, write_ms: float, **kw) -> dict:
    clock = FakeClock()
    data = tmp_path / "root" / "data"
    data.parent.mkdir(parents=True, exist_ok=True)
    return hp.build_profile(data, None, fs=FakeFS(clock, write_ms), clock=clock,
                            readers=kw.pop("readers", readers()), **kw)


# ── the fixed contract ──────────────────────────────────────────────────────

def test_contract_classes_and_budget_factor_mapping():
    assert hp.CLASSES == ("fast", "normal", "slow", "very-slow")
    assert hp.BUDGET_FACTOR == {"fast": 1, "normal": 1, "slow": 2, "very-slow": 3}


@pytest.mark.parametrize("write_ms,klass,factor", [
    (0.4, "fast", 1), (5.0, "normal", 1), (20.0, "slow", 2), (60.0, "very-slow", 3),
])
def test_written_file_carries_class_and_budget_factor(tmp_path, write_ms, klass, factor):
    doc = profile(tmp_path, write_ms)
    out = tmp_path / "root" / "data" / ".host-profile.json"
    hp.write_profile(out, doc)
    got = json.loads(out.read_text())
    assert isinstance(got, dict)
    assert got["class"] == klass
    assert got["budget_factor"] == factor
    assert isinstance(got["budget_factor"], (int, float)) and not isinstance(got["budget_factor"], bool)
    assert got["budget_factor"] == hp.BUDGET_FACTOR[got["class"]]


def test_write_refuses_anything_outside_the_contract(tmp_path):
    out = tmp_path / "p.json"
    with pytest.raises(ValueError):
        hp.write_profile(out, {"class": None, "budget_factor": 2})
    with pytest.raises(ValueError):
        hp.write_profile(out, {"class": "unknown", "budget_factor": 2})
    with pytest.raises(ValueError):
        hp.write_profile(out, {"class": "slow", "budget_factor": 1})
    assert not out.exists()


# ── calibration ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("p99_ms,klass", [
    (0.2, "fast"), (1.9, "fast"), (2.0, "fast"), (2.1, "normal"), (9.9, "normal"),
    (10.5, "slow"), (49.0, "slow"), (50.5, "very-slow"), (60.0, "very-slow"), (400.0, "very-slow"),
])
def test_latency_thresholds(p99_ms, klass):
    assert hp.latency_class(p99_ms) == klass


def test_123_write_latency_alone_is_very_slow(tmp_path):
    doc = profile(tmp_path, 60.0)
    assert doc["class"] == "very-slow"
    assert doc["budget_factor"] == 3


def test_123_io_pressure_alone_is_very_slow_even_on_a_fast_disk(tmp_path):
    doc = profile(tmp_path, 0.5, readers=readers(io=PSI_123_IO))
    assert doc["class"] == "very-slow"
    assert any("22.5" in r for r in doc["reasons"])


def test_io_pressure_avg60_alone_counts_too(tmp_path):
    io = ("some avg10=0 avg60=0 avg300=0 total=1\n"
          "full avg10=0.00 avg60=20.50 avg300=3.00 total=1\n")
    assert profile(tmp_path, 0.5, readers=readers(io=io))["class"] == "very-slow"


def test_healthy_ssd_is_fast(tmp_path):
    doc = profile(tmp_path, 0.3)
    assert doc["class"] == "fast"
    assert doc["filesystems"][0]["p99_ms"] < 2


def test_very_slow_warns_in_plain_language_and_never_refuses(tmp_path):
    doc = profile(tmp_path, 60.0, readers=readers(io=PSI_123_IO))
    v = doc["verdict"].lower()
    assert v.startswith("warning")
    assert "slower than recommended" in v
    for word in ("refus", "abort", "cannot install", "blocked"):
        assert word not in v
    assert "never" in doc["refusal"].lower()


def test_cpu_floors(tmp_path):
    assert profile(tmp_path, 0.3, readers=readers(cpus=2))["class"] == "slow"
    busy = "some avg10=70 avg60=65.00 avg300=60 total=1\n"
    assert profile(tmp_path, 0.3, readers=readers(cpu=busy))["class"] == "slow"
    assert profile(tmp_path, 0.3, readers=readers(cpus=4))["class"] == "fast"


def test_worst_filesystem_decides(tmp_path):
    clock = FakeClock()
    data = tmp_path / "data"
    dock = tmp_path / "docker"
    dock.mkdir()
    fs = FakeFS(clock, 0.3)
    devices = {str(tmp_path): 1, str(dock): 2}

    def device_of(p: Path) -> int:
        return devices[str(p)]

    speeds = iter([0.3, 30.0])

    class SwitchFS(FakeFS):
        def open_dsync(self, path: str) -> int:
            self.write_ms = next(speeds)
            return super().open_dsync(path)

    fs = SwitchFS(clock)
    doc = hp.build_profile(data, dock, fs=fs, clock=clock, readers=readers(), device_of=device_of)
    assert [f["role"] for f in doc["filesystems"]] == ["data", "docker-root"]
    assert doc["class"] == "slow"


def test_same_filesystem_is_measured_once(tmp_path):
    clock = FakeClock()
    dock = tmp_path / "docker"
    dock.mkdir()
    fs = FakeFS(clock, 1.0)
    doc = hp.build_profile(tmp_path / "data", dock, fs=fs, clock=clock, readers=readers(),
                           device_of=lambda p: 7)
    assert len(fs.created) == 1
    assert doc["filesystems"][1]["same_as"] == "data"


def test_nothing_measurable_gives_no_class_and_no_file(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, fail_open=errno.EACCES)
    doc = hp.build_profile(tmp_path / "data", None, fs=fs, clock=clock,
                           readers=readers(io=None, cpu=None))
    assert doc["class"] is None
    assert doc["budget_factor"] is None
    assert "could not" in doc["verdict"].lower()
    assert any("permission" in (f["error"] or "").lower() for f in doc["filesystems"])


def test_unmeasurable_disk_but_readable_pressure_still_classifies(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, fail_open=errno.EACCES)
    doc = hp.build_profile(tmp_path / "data", None, fs=fs, clock=clock,
                           readers=readers(io=PSI_123_IO))
    assert doc["class"] == "very-slow"


# ── the probe itself ────────────────────────────────────────────────────────

def test_probe_writes_64_by_8kib_and_always_removes_its_file(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, 1.5)
    s = hp.measure_filesystem(tmp_path, "data", fs=fs, clock=clock)
    assert s.writes == 64 and fs.writes == 64
    assert s.block_bytes == 8192
    assert s.error == "" and not s.capped and not s.stalled
    assert fs.live == set(), "the probe file must be removed"
    assert fs.closed == 1
    assert s.p99_ms == pytest.approx(1.5)
    assert Path(fs.created[0]).parent == tmp_path
    assert Path(fs.created[0]).name.startswith(".correlix-host-probe-")


def test_probe_stops_at_the_hard_cap(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, 500.0)
    s = hp.measure_filesystem(tmp_path, "data", fs=fs, clock=clock, cap_s=5.0)
    assert s.capped
    assert s.writes == 10
    assert fs.live == set()


def test_cap_is_clamped_to_five_seconds(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, 1000.0)
    s = hp.measure_filesystem(tmp_path, "data", fs=fs, clock=clock, cap_s=60.0)
    assert s.writes == 5


def test_write_error_is_reported_and_file_removed(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, 1.0, fail_write_at=3)
    s = hp.measure_filesystem(tmp_path, "data", fs=fs, clock=clock)
    assert "no space" in s.error.lower()
    assert fs.live == set()
    assert fs.closed == 1


def test_open_error_is_reported(tmp_path):
    clock = FakeClock()
    s = hp.measure_filesystem(tmp_path, "data", fs=FakeFS(clock, fail_open=errno.EROFS), clock=clock)
    assert "read-only" in s.error.lower()
    assert s.writes == 0


def test_a_write_that_never_returns_is_stalled_not_a_hang(tmp_path):
    clock = FakeClock()
    gate = threading.Event()
    fs = FakeFS(clock, 1.0, block=gate)
    try:
        s = hp.measure_filesystem(tmp_path, "data", fs=fs, clock=clock, cap_s=0.5, grace_s=0.2)
        assert s.stalled
        assert hp.sample_class(s) == "very-slow"
    finally:
        gate.set()


def test_probe_targets_nearest_existing_directory(tmp_path):
    clock = FakeClock()
    fs = FakeFS(clock, 1.0)
    missing = tmp_path / "root" / "data"
    (tmp_path / "root").mkdir()
    s = hp.measure_filesystem(missing, "data", fs=fs, clock=clock)
    assert Path(fs.created[0]).parent == tmp_path / "root"
    assert s.probed_dir == str(tmp_path / "root")


def test_default_filesystem_opens_with_o_dsync(monkeypatch, tmp_path):
    seen: list[int] = []
    real_open = os.open

    def spy(path, flags, mode=0o777):
        seen.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(hp.os, "open", spy)
    fd = hp.OsProbeFS().open_dsync(str(tmp_path / "x"))
    os.close(fd)
    assert seen and seen[0] & os.O_DSYNC and seen[0] & os.O_EXCL


def test_real_probe_in_tmp_path_leaves_nothing_behind(tmp_path):
    s = hp.measure_filesystem(tmp_path, "data", writes=4, cap_s=2.0)
    assert s.error == ""
    assert s.writes == 4
    assert list(tmp_path.iterdir()) == []


# ── /proc and docker readers ────────────────────────────────────────────────

def test_parse_psi_and_meminfo():
    psi = hp.parse_psi(PSI_123_IO)
    assert psi["full"]["avg300"] == 22.5
    assert psi["some"]["avg60"] == 35.0
    assert hp.parse_meminfo_kib(MEMINFO) == 16336988
    with pytest.raises(hp.ProbeError):
        hp.parse_psi("garbage")
    with pytest.raises(hp.ProbeError):
        hp.parse_meminfo_kib("nothing here")


def test_missing_psi_is_reported_not_fatal(tmp_path):
    doc = profile(tmp_path, 1.0, readers=readers(io=None, cpu=None))
    assert doc["psi"]["io"] is None
    assert any("pressure" in n.lower() for n in doc["notes"])
    assert doc["class"] == "fast"


def test_docker_root_dir_via_injected_runner():
    calls: list[list[str]] = []

    def ok(argv, timeout):
        calls.append(argv)
        return 0, "/var/lib/docker\n", ""

    assert hp.docker_root_dir(ok) == Path("/var/lib/docker")
    assert calls[0] == ["docker", "info", "--format", "{{.DockerRootDir}}"]
    with pytest.raises(hp.ProbeError, match="daemon"):
        hp.docker_root_dir(lambda a, timeout: (1, "", "Cannot connect to the Docker daemon"))
    with pytest.raises(hp.ProbeError):
        hp.docker_root_dir(lambda a, timeout: (0, "relative/path\n", ""))
    with pytest.raises(hp.ProbeError):
        hp.docker_root_dir(lambda a, timeout: (0, "/a\n/b\n", ""))


def test_default_runner_bounds_and_escalates(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=15)

    monkeypatch.setattr(hp.subprocess, "run", boom)
    with pytest.raises(hp.ProbeError, match="15"):
        hp.subprocess_runner(["docker", "info"], 15)


# ── the file on disk ────────────────────────────────────────────────────────

def test_write_is_atomic_0644_under_a_strict_umask_and_clean(tmp_path):
    # (named without "secret": pytest puts the test name in tmp_path, which the
    # profile records, and the redaction regex would then match the path)
    doc = profile(tmp_path, 3.0)
    out = tmp_path / "root" / "data" / ".host-profile.json"
    old = os.umask(0o077)
    try:
        hp.write_profile(out, doc)
    finally:
        os.umask(old)
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    assert sorted(p.name for p in out.parent.iterdir()) == [".host-profile.json"]
    text = out.read_text()
    assert not install_signatures.SECRETISH.search(text)
    got = json.loads(text)
    assert got["version"] == 1 and got["measured_utc"].endswith("Z")
    assert got["cpus"] == 8 and got["mem_total_kib"] == 16336988


def test_write_creates_data_dir_only_under_an_existing_root(tmp_path):
    doc = profile(tmp_path, 3.0)
    hp.write_profile(tmp_path / "root" / "data" / ".host-profile.json", doc)
    with pytest.raises(hp.ProbeError):
        hp.write_profile(tmp_path / "nope" / "deeper" / ".host-profile.json", doc)


def test_load_profile_validates(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"class": "slow", "budget_factor": 2, "verdict": "x"}))
    assert hp.load_profile(p)["class"] == "slow"
    p.write_text(json.dumps({"class": "turbo", "budget_factor": 2}))
    with pytest.raises(hp.ProbeError):
        hp.load_profile(p)
    p.write_text("x" * (hp.MAX_PROFILE_BYTES + 1))
    with pytest.raises(hp.ProbeError):
        hp.load_profile(p)


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPTS / "host_profile.py"), *args],
                          capture_output=True, text=True, timeout=60, check=False)


def test_cli_probe_writes_the_contract_file_and_prints_a_verdict_line(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    out = root / "data" / ".host-profile.json"
    r = _cli(["probe", "--data-dir", str(root / "data"), "--no-docker", "--write", str(out),
              "--writes", "4", "--cap-s", "2"])
    assert r.returncode == 0, r.stderr
    klass, factor, verdict = r.stdout.splitlines()[0].split("\t", 2)
    assert klass in hp.CLASSES
    assert int(factor) == hp.BUDGET_FACTOR[klass]
    assert verdict
    got = json.loads(out.read_text())
    assert got["class"] == klass and got["budget_factor"] == hp.BUDGET_FACTOR[klass]
    assert [p.name for p in (root / "data").iterdir()] == [".host-profile.json"]


def test_cli_json(tmp_path):
    r = _cli(["probe", "--data-dir", str(tmp_path), "--no-docker", "--json", "--writes", "2"])
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["class"] in hp.CLASSES


def test_cli_unmeasurable_exits_2_and_writes_nothing(tmp_path, monkeypatch):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        if os.access(ro, os.W_OK):
            pytest.skip("running as root: a 0555 directory is still writable")
        env = dict(os.environ, CORRELIX_HOST_PROFILE_PROC="/nonexistent-proc")
        r = subprocess.run([sys.executable, str(SCRIPTS / "host_profile.py"), "probe",
                            "--data-dir", str(ro / "data"), "--no-docker",
                            "--write", str(tmp_path / "out" / ".host-profile.json")],
                           capture_output=True, text=True, timeout=60, env=env, check=False)
        assert r.returncode == 2, r.stdout + r.stderr
        assert r.stdout.splitlines()[0].startswith("unknown\t")
        assert not (tmp_path / "out").exists()
    finally:
        ro.chmod(0o755)


def test_cli_usage_errors():
    assert _cli([]).returncode == 2
    assert _cli(["probe"]).returncode == 2


def test_stdlib_only():
    import ast
    tree = ast.parse((SCRIPTS / "host_profile.py").read_text())
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree)
             if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
    assert mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names)
