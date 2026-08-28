"""An interrupted mini-ladder run must leave the stack CLEAN — or say exactly
what it left behind.

THE DEFECT THIS FILE KILLS (2026-08-28, run dir /var/tmp/scale-runs/
p1-on-08281911, runid 08281911zaz6). The run was signalled after the drain
phase. Its console ends:

    miniladder: [PASS] drain — KAFKA TRANSPORT lag drained ...
    miniladder: WARNING: interrupted — running cleanup before exit
    miniladder: [FAIL] interrupted — run interrupted by signal

...and nothing else. No cleanup verdict, no report.json in the run dir — and
all 2,500 `mlx-08281911zaz6-*` devices still standing in the device store,
which is what the NEXT run's onboard collides with.

Three code facts produced it, and each has a test below:

  1. A second signal during cleanup killed the purge. SIGINT raises
     KeyboardInterrupt; the old SIGTERM handler raised it too, from ANY point
     including mid-cleanup. The `except Exception` guarding the cleanup call
     cannot catch a BaseException, so it unwound out of execute(), skipping the
     rest of the purge AND report(). SIGHUP was never handled at all.
  2. Cleanup ran silently through up to ~15 minutes of bounded waits before the
     first DELETE — indistinguishable from a hang, which is why it got
     signalled a second time.
  3. The purge deleted only the ids the process held in memory and verified
     ONCE. /api/devices caps a page (2,500 observed), and a partial pass left
     residue nobody re-attempted. Deletion durability is a past defect (F-69):
     a 204 is not evidence, a successful re-LIST is.

Every test drives the harness against a fake API; nothing here touches a stack,
docker, or a real device.

Run:  python3 -m pytest tests/test_miniladder_interrupt_cleanup.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import sys
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_cleanup", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_cleanup"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, (
        "importing the harness must not mutate PATH — pin it in main() instead")
    return mod


ml = _load_harness()


# ── fakes ───────────────────────────────────────────────────────────────────
#
# FakeStack answers the same surface Stack does, with the REAL page cap: the
# device list refuses to return more than `page_cap` rows however large a limit
# the caller asks for. That is the shape that made a single-page verify lie.


class FakeStack:
    def __init__(self, device_ids, page_cap=2500, base_url="http://stack.test"):
        self.devices: list[str] = list(device_ids)
        self.page_cap = page_cap
        self.base_url = base_url
        self.token = "fake"
        self.tls = False
        self.deleted: list[str] = []
        self.delete_status: dict[str, int] = {}
        self.list_failures = 0            # leading GETs that answer 503
        self.list_offsets: list[int] = []
        self.on_delete = None             # callable(id) -> may raise
        self.lag_values: list[int] = []
        self.lag = 0
        self.ch_queries: list[str] = []
        self.ch_mutations: list[str] = []
        self.os_paths: list[str] = []
        self.logins = 0
        self.ch_signals_left = 0
        # OpenSearch purge model: the delete is ASYNC, so `os_count` answers a
        # scripted drain sequence (`os_counts`) and falls back to
        # `os_docs_left` once that runs out.
        self.os_docs_left = 0
        self.os_counts: list[int] = []
        self.os_task = "abc123:456"
        self.os_submit_ok = True
        self.os_refresh_ok = True
        self.os_refreshes = 0

    # -- API ----------------------------------------------------------------
    def login(self):
        self.logins += 1

    def api(self, method, path, body=None):
        if method == "GET" and path.startswith("/api/devices"):
            if self.list_failures > 0:
                self.list_failures -= 1
                return 503, "upstream unavailable"
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            limit = min(int(q.get("limit", ["5000"])[0]), self.page_cap)
            offset = int(q.get("offset", ["0"])[0])
            self.list_offsets.append(offset)
            rows = self.devices[offset:offset + limit]
            total = len(self.devices)
            return 200, {
                "devices": [{"id": d} for d in rows],
                "total": total, "returned": len(rows),
                "limit": limit, "offset": offset,
                "complete": offset + len(rows) >= total,
            }
        if method == "DELETE" and path.startswith("/api/devices/"):
            did = path.rsplit("/", 1)[1]
            if self.on_delete is not None:
                self.on_delete(did)
            st = self.delete_status.get(did, 204)
            if st in (200, 202, 204) and did in self.devices:
                self.devices.remove(did)
            if st in (200, 202, 204):
                self.deleted.append(did)
            return st, {}
        raise AssertionError(f"unexpected API call {method} {path}")

    # -- bus / stores -------------------------------------------------------
    def group_lag(self, group):
        if self.lag_values:
            self.lag = self.lag_values.pop(0)
        return {"_total": self.lag, "_members": 1, "_rows": 1}

    def ch(self, query, timeout=60):
        self.ch_queries.append(query)
        return True, str(self.ch_signals_left)

    def ch_mutation(self, query):
        self.ch_mutations.append(query)
        return True, ""

    def os_req(self, role_env, user, url_path, body=None, timeout=25):
        self.os_paths.append(url_path)
        if "_delete_by_query" in url_path:
            if not self.os_submit_ok:
                return False, ("curl exit 28 (TIMED OUT after 60s (curl "
                               "max-time)) on " + url_path + " [no output from curl]")
            return True, {"task": self.os_task}
        if url_path.endswith("_refresh"):
            self.os_refreshes += 1
            if not self.os_refresh_ok:
                return False, "curl exit 7 (failed to connect) on " + url_path
            return True, {"_shards": {"failed": 0}}
        return True, {}

    def os_count(self, index, field, prefix):
        self.os_paths.append(f"{index}/_count")
        if self.os_counts:
            return self.os_counts.pop(0)
        return self.os_docs_left

    def mem_sample(self):
        return {}


class FakeClock:
    """Deterministic monotonic clock: sleeping is the only thing that moves
    time, so a bounded wait's budget is testable without waiting."""

    def __init__(self, start=1000.0):
        self.t = start
        self.slept = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds
        self.slept += seconds


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(ml.time, "monotonic", c.monotonic)
    monkeypatch.setattr(ml.time, "sleep", c.sleep)
    return c


@pytest.fixture
def nosleep(monkeypatch):
    monkeypatch.setattr(ml.time, "sleep", lambda _s: None)


def _args(tmp_path, **over):
    argv = ["--devices", str(over.pop("devices", 10)),
            "--run-dir", str(tmp_path / "run"),
            "--env-file", str(tmp_path / "missing.env"),
            "--base-url", "http://stack.test"]
    for k, v in over.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    return ml.parse_args(argv)


def _harness(tmp_path, stack, **over):
    h = ml.Harness(_args(tmp_path, **over))
    h.stack = stack
    return h


def _ids(prefix, n, start=0):
    return [f"{prefix}{i:05d}" for i in range(start, start + n)]


# ── 1. the page-loop + re-verify (F-69) ─────────────────────────────────────

def test_pager_follows_the_endpoint_cap_not_the_requested_limit(nosleep):
    """6,000 devices behind a 2,500-row page cap: one page is a LIE."""
    ids = _ids("mlx-run-", 6000)
    stack = FakeStack(ids, page_cap=2500)
    found, err = ml.devices_with_prefix(stack, "mlx-run-")
    assert err == ""
    assert found == ids, "the pager must return every page, not the first"
    assert stack.list_offsets[:3] == [0, 2500, 5000], (
        "paging must advance by the rows RETURNED (the cap), never by the "
        f"limit asked for — offsets were {stack.list_offsets}")


def test_pager_selects_only_the_run_prefix():
    """Blast radius: other tenants' devices share the list endpoint."""
    mine = _ids("mlx-run-", 30)
    theirs = ["core-rtr-01", "mlx2-other-00001", "wlc-hq"]
    stack = FakeStack(mine + theirs, page_cap=10)
    found, err = ml.devices_with_prefix(stack, "mlx-run-")
    assert err == ""
    assert found == mine


def test_purge_deletes_every_page_and_verifies_zero(nosleep):
    ids = _ids("mlx-run-", 6000)
    stack = FakeStack(ids, page_cap=2500)
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=600)
    assert ev["verified_zero"] is True
    assert ev["remaining"] == 0
    assert ev["deleted"] == 6000
    assert stack.devices == []


def test_purge_re_lists_after_deleting_the_seed_ids(nosleep):
    """The run's in-memory id list is a SEED, not the truth: an interrupt mid
    onboard leaves devices the process never recorded."""
    known = _ids("mlx-run-", 5)
    unrecorded = _ids("mlx-run-", 3, start=900)
    stack = FakeStack(known + unrecorded, page_cap=2500)
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=600, seed_ids=known)
    assert ev["verified_zero"] is True
    assert sorted(stack.deleted) == sorted(known + unrecorded)


def test_purge_never_claims_zero_when_the_list_call_failed(nosleep):
    """A 204 is not evidence and neither is an unreadable list (F-69)."""
    stack = FakeStack(_ids("mlx-run-", 4), page_cap=2500)
    stack.list_failures = 99            # every verify list fails
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=30, seed_ids=_ids("mlx-run-", 4))
    assert ev["verified_zero"] is False
    assert ev["remaining"] == -1, "unverified must read UNKNOWN, never 0"
    assert "device list failed" in ev["list_error"]


def test_purge_reports_delete_failures_loudly(nosleep, capsys):
    ids = _ids("mlx-run-", 4)
    stack = FakeStack(ids, page_cap=2500)
    stack.delete_status[ids[2]] = 500
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=30, max_passes=2)
    err = capsys.readouterr().err
    assert ev["delete_failed"] >= 1
    assert ev["verified_zero"] is False
    assert ev["remaining"] == 1
    assert "device deletes FAILED" in err
    assert ids[2] in ev["first_delete_error"]


def test_purge_gives_up_fast_when_the_stack_never_answers(nosleep, capsys):
    """The preflight-refusal case: nothing was created and the API is down —
    teardown must not spend its whole budget retrying a dead stack, and must
    NOT report a clean stack it could not see."""
    stack = FakeStack([], page_cap=2500)
    stack.list_failures = 999
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=600)
    assert ev["passes"] <= 3, "a dead stack must be given up on quickly"
    assert ev["verified_zero"] is False
    assert ev["remaining"] == -1
    assert "UNKNOWN, not zero" in capsys.readouterr().err


def test_purge_stops_at_its_budget_and_says_so(clock, capsys):
    ids = _ids("mlx-run-", 50)
    stack = FakeStack(ids, page_cap=2500)

    def slow_delete(_did):
        clock.sleep(30)                 # each delete burns 30s of the budget

    stack.on_delete = slow_delete
    ev = ml.purge_devices(stack, "mlx-run-", budget_s=100)
    err = capsys.readouterr().err
    assert ev["out_of_budget"] is True
    assert ev["verified_zero"] is False
    assert "ran out of its" in err


# ── 2. interrupt → FULL cleanup ─────────────────────────────────────────────

def test_interrupt_runs_the_full_cleanup_and_leaves_no_residue(tmp_path, nosleep, capsys):
    ids = _ids("mlx-run-", 2500)
    stack = FakeStack(ids, page_cap=2500)
    h = _harness(tmp_path, stack, devices=2500)
    h.prefix = "mlx-run-"
    h.created_ids = list(ids)

    h.preflight = lambda: True

    def onboard():
        raise KeyboardInterrupt("SIGINT")

    h.onboard = onboard
    rc = h.execute()
    out = capsys.readouterr()

    assert stack.devices == [], "every device must be deleted on an interrupt"
    assert h.residue_devices == 0
    assert stack.ch_mutations and stack.os_paths, "CH/OS purge must still run"
    report = json.loads((Path(h.run_dir) / "report.json").read_text())
    phases = {p["phase"]: p["status"] for p in report["phases"]}
    assert phases["interrupted"] == "FAIL"
    assert phases["cleanup"] == "PASS", (
        "the interrupt path must run the FULL cleanup, not skip it")
    assert "residue: 0 devices (verified)" in out.out
    assert rc == 1                       # interrupted run is not a pass


def test_interrupt_before_cleanup_announces_the_teardown(tmp_path, nosleep, capsys):
    stack = FakeStack(_ids("mlx-run-", 3), page_cap=2500)
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.preflight = lambda: True

    def onboard():
        raise KeyboardInterrupt("SIGTERM")

    h.onboard = onboard
    h.execute()
    err = capsys.readouterr().err
    assert "running the FULL cleanup before exit" in err


def test_cleanup_purges_devices_the_run_never_recorded(tmp_path, nosleep):
    """Interrupted mid-onboard: 40 devices exist, 10 are in created_ids."""
    ids = _ids("mlx-run-", 40)
    stack = FakeStack(ids, page_cap=2500)
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.created_ids = ids[:10]
    h.preflight = lambda: True
    h.onboard = lambda: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))
    h.execute()
    assert stack.devices == []
    assert h.residue_devices == 0


# ── 3. a SECOND signal during cleanup ───────────────────────────────────────

@pytest.fixture
def restore_signals():
    saved = {}
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            saved[sig] = signal.getsignal(sig)
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


def test_guard_installs_sigint_sigterm_and_sighup(restore_signals):
    """SIGHUP was unhandled: a closing terminal killed the run outright."""
    guard = ml.InterruptGuard()
    guard.install()
    assert set(guard.installed) >= {"SIGINT", "SIGTERM", "SIGHUP"}
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        assert signal.getsignal(getattr(signal, name)) == guard.handle


def test_signal_before_cleanup_unwinds_into_cleanup():
    guard = ml.InterruptGuard()
    with pytest.raises(KeyboardInterrupt):
        guard.handle(signal.SIGINT, None)


def test_signal_during_cleanup_is_ignored_with_a_message(capsys):
    guard = ml.InterruptGuard(abort_after=3)
    guard.enter_cleanup()
    guard.handle(signal.SIGINT, None)          # must NOT raise
    guard.handle(signal.SIGTERM, None)         # must NOT raise
    err = capsys.readouterr().err
    assert err.count("IGNORED") == 2
    assert "LEAVE RESIDUE" in err
    assert "1 more time" in err, "the operator must be told how to force out"


def test_repeated_signals_during_cleanup_abort_deliberately():
    guard = ml.InterruptGuard(abort_after=2)
    guard.enter_cleanup()
    guard.handle(signal.SIGINT, None)
    with pytest.raises(ml.CleanupAborted):
        guard.handle(signal.SIGINT, None)


def test_guard_rearms_between_run_and_cleanup():
    guard = ml.InterruptGuard(abort_after=2)
    guard.enter_cleanup()
    guard.handle(signal.SIGINT, None)
    guard.leave_cleanup()
    with pytest.raises(KeyboardInterrupt):
        guard.handle(signal.SIGINT, None)      # outside cleanup: unwind again


def test_cleanup_abort_names_the_residue_and_the_fix(tmp_path, nosleep, capsys):
    """The Nth signal aborts — but the run must still report, and must print
    RESIDUE LEFT with the purge command."""
    ids = _ids("mlx-run-", 20)
    stack = FakeStack(ids, page_cap=2500)
    seen = {"n": 0}

    def abort_on_third(_did):
        seen["n"] += 1
        if seen["n"] == 3:
            raise ml.CleanupAborted("SIGINT")

    stack.on_delete = abort_on_third
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.created_ids = list(ids)
    h.preflight = lambda: True
    h.onboard = lambda: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))
    rc = h.execute()
    out = capsys.readouterr()

    assert "RESIDUE LEFT" in out.err
    assert "--cleanup-only mlx-run-" in out.err
    report = json.loads((Path(h.run_dir) / "report.json").read_text())
    phases = {p["phase"]: p["status"] for p in report["phases"]}
    assert phases["cleanup"] == "FAIL", "an aborted cleanup is never a PASS"
    assert rc == 1


def test_keyboardinterrupt_inside_cleanup_never_escapes_execute(tmp_path, nosleep, capsys):
    """THE 2026-08-28 SHAPE: KeyboardInterrupt is a BaseException, so the old
    `except Exception` let it unwind out of execute() — no purge, no report."""
    ids = _ids("mlx-run-", 20)
    stack = FakeStack(ids, page_cap=2500)
    stack.on_delete = lambda _d: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.created_ids = list(ids)
    h.preflight = lambda: True
    h.onboard = lambda: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))

    rc = h.execute()                     # must NOT raise
    out = capsys.readouterr()
    assert rc == 1
    assert (Path(h.run_dir) / "report.json").is_file(), (
        "report() must still run after an interrupted cleanup")
    assert "RESIDUE LEFT" in out.err
    assert "residue: UNKNOWN" in out.out, (
        "an unverified purge must never print as zero residue")


def test_cleanup_problems_are_printed_not_only_filed(tmp_path, clock, capsys):
    """16.1: a degraded teardown is loud, with counts."""
    ids = _ids("mlx-run-", 6)
    stack = FakeStack(ids, page_cap=2500)
    stack.delete_status[ids[0]] = 500
    stack.ch_signals_left = 12
    stack.os_docs_left = 3
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.created_ids = list(ids)
    h.preflight = lambda: True
    h.onboard = lambda: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))
    h.execute()
    out = capsys.readouterr()
    assert "device purge NOT verified to zero" in out.err
    assert "12 run rows left in corr_signals" in out.err
    assert "3 docs left in netops-syslog-*" in out.err
    assert "residue: 1 devices matching mlx-run-" in out.out


def test_guard_stays_armed_until_the_report_is_written(tmp_path, nosleep):
    """A signal landing between the purge and report() must not cost the run
    its evidence — the guard disarms only after execute() has reported."""
    stack = FakeStack(_ids("mlx-run-", 3), page_cap=2500)
    h = _harness(tmp_path, stack)
    h.prefix = "mlx-run-"
    h.preflight = lambda: True
    h.onboard = lambda: (_ for _ in ()).throw(KeyboardInterrupt("SIGINT"))
    armed: list[bool] = []
    real_report = h.report
    h.report = lambda: (armed.append(h.interrupts.in_cleanup), real_report())[1]

    h.execute()
    assert armed == [True], "signals must still be ignored while reporting"
    assert h.interrupts.in_cleanup is False, "the guard must disarm at the end"


# ── 4. --cleanup-only ───────────────────────────────────────────────────────

def test_cleanup_only_defaults_to_the_harness_namespace():
    args = ml.parse_args(["--cleanup-only"])
    assert args.cleanup_only == ml.DEVICE_PREFIX_ROOT == "mlx-"


def test_cleanup_only_refuses_a_prefix_outside_the_namespace(capsys):
    for bad in ("", "core-", "mlx", "prod-rtr-"):
        with pytest.raises(SystemExit):
            ml.parse_args(["--cleanup-only", bad])


def _patch_ingress(monkeypatch, ok=True):
    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(*_a, **_k):
        if not ok:
            raise urllib.error.URLError("connection refused")
        return _Resp()

    monkeypatch.setattr(ml.urllib.request, "urlopen", urlopen)


def test_cleanup_only_refuses_an_unreachable_stack(tmp_path, monkeypatch, capsys):
    stack = FakeStack(_ids("mlx-", 5))
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    _patch_ingress(monkeypatch, ok=False)
    args = _args(tmp_path)
    args.cleanup_only = "mlx-"
    with pytest.raises(SystemExit) as exc:
        ml.cleanup_only(args)
    assert exc.value.code == 2
    assert stack.deleted == [], "nothing may be deleted against a blind stack"
    assert "stack unreachable" in capsys.readouterr().err


def test_cleanup_only_purges_and_verifies_zero(tmp_path, monkeypatch, nosleep, capsys):
    residue = _ids("mlx-08281911zaz6-", 2500)
    others = ["core-rtr-01", "edge-fw-02"]
    stack = FakeStack(residue + others, page_cap=2500)
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    _patch_ingress(monkeypatch)
    args = _args(tmp_path, devices=2500)
    args.cleanup_only = "mlx-08281911zaz6-"

    rc = ml.cleanup_only(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert stack.devices == others, "only the mlx- prefix may be deleted"
    assert stack.ch_mutations and stack.os_paths
    assert "residue: 0 devices" in out


def test_cleanup_only_is_idempotent_on_a_clean_stack(tmp_path, monkeypatch, nosleep):
    stack = FakeStack(["core-rtr-01"], page_cap=2500)
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    _patch_ingress(monkeypatch)
    args = _args(tmp_path)
    args.cleanup_only = "mlx-"
    assert ml.cleanup_only(args) == 0
    assert ml.cleanup_only(args) == 0
    assert stack.deleted == []


def test_cleanup_only_exits_nonzero_when_residue_survives(tmp_path, monkeypatch,
                                                          nosleep, capsys):
    ids = _ids("mlx-", 3)
    stack = FakeStack(ids, page_cap=2500)
    stack.delete_status[ids[1]] = 500
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    _patch_ingress(monkeypatch)
    args = _args(tmp_path)
    args.cleanup_only = "mlx-"
    assert ml.cleanup_only(args) == 1
    assert "cleanup-only FAILED" in capsys.readouterr().err


def test_cleanup_only_dry_run_touches_nothing(tmp_path, monkeypatch, capsys):
    stack = FakeStack(_ids("mlx-", 4))
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    monkeypatch.setattr(ml.os.path, "isfile", lambda _p: True)
    # main() pins the cron PATH process-wide (CRON_PATH). Record it through
    # monkeypatch so pytest restores this process's PATH afterwards — without
    # this, every later test that shells out to a tool in ~/.local/bin
    # (shellcheck) fails with FileNotFoundError.
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    rc = ml.main(["--cleanup-only", "mlx-", "--dry-run",
                  "--base-url", "http://stack.test",
                  "--env-file", str(tmp_path / "x.env"), "--project", "netops"])
    assert rc == 0
    assert stack.deleted == []
    assert os.environ["PATH"] == ml.CRON_PATH, (
        "main() must still pin the cron-proof PATH (16.2)")
    assert "DRY RUN (--cleanup-only)" in capsys.readouterr().out


# ── 5. curl failures name their exit code ───────────────────────────────────
#
# LIVE DEFECT (2026-08-28, first real `--cleanup-only mlx-`): the synchronous
# `_delete_by_query?refresh=true` over 10,311,858 syslog docs blew through
# curl's `max-time = 300`. curl exits 28 with NOTHING on stdout or stderr, and
# `os_req` returned `(err or out).strip()` — so the operator was told:
#
#     WARNING: cleanup-only: OpenSearch syslog purge failed:
#
# An empty reason for a 10.3 M-document residue. The exit code WAS the
# diagnosis and it was thrown away (§16.1).


def _stack_with_curl_rc(monkeypatch, rc, out="", err=""):
    stack = ml.Stack("/nonexistent.env", "http://stack.test", "netops")
    monkeypatch.setattr(stack, "cid", lambda _svc: "oscid")
    monkeypatch.setattr(ml, "run", lambda *_a, **_k: (rc, out, err))
    return stack


def test_os_req_timeout_names_the_curl_exit_code(monkeypatch):
    """rc=28 with empty stdout AND stderr — the exact live shape."""
    stack = _stack_with_curl_rc(monkeypatch, 28)
    ok, msg = stack.os_req("OS_BOOTSTRAP_PASSWORD", "svc_bootstrap",
                           "/netops-syslog-*/_delete_by_query", {"q": 1},
                           timeout=300)
    assert ok is False
    assert "28" in msg
    assert "timed out" in msg.lower(), msg
    assert "300s" in msg, "the bound that was hit must be in the message"
    assert "_delete_by_query" in msg
    assert msg.strip() != "", "an empty failure message is never acceptable"


@pytest.mark.parametrize(("rc", "needle"), [
    (7, "failed to connect"),
    (6, "could not resolve host"),
    (52, "empty reply"),
    (60, "certificate"),
    (124, "subprocess bound"),
    (127, "binary not found"),
    (999, "unknown curl exit code"),
])
def test_os_req_every_failure_carries_a_meaning(monkeypatch, rc, needle):
    stack = _stack_with_curl_rc(monkeypatch, rc)
    ok, msg = stack.os_req("OS_BOOTSTRAP_PASSWORD", "svc_bootstrap", "/x", None)
    assert ok is False
    assert str(rc) in msg and needle in msg


def test_os_req_keeps_curl_stderr_when_there_is_some(monkeypatch):
    stack = _stack_with_curl_rc(monkeypatch, 7, err="curl: (7) Connection refused")
    ok, msg = stack.os_req("OS_BOOTSTRAP_PASSWORD", "svc_bootstrap", "/x", None)
    assert ok is False
    assert "Connection refused" in msg and "curl exit 7" in msg


# ── 6. the async OpenSearch purge ───────────────────────────────────────────

def test_os_purge_submits_async_and_verifies_zero_by_recount(clock, capsys):
    stack = FakeStack([], page_cap=2500)
    stack.os_counts = [10_000_000,          # pre-count
                       6_000_000, 2_000_000, 0,   # drain
                       0]                   # post-refresh confirmation
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-")
    out = capsys.readouterr().out

    assert problems == []
    assert ev["os_docs_left"] == 0
    assert ev["os_task"] == "abc123:456"
    assert ev["os_deleted"] == 10_000_000
    submit = next(p for p in stack.os_paths if "_delete_by_query" in p)
    assert "wait_for_completion=false" in submit, (
        "a synchronous delete cannot survive 10 M docs — that was the defect")
    assert "conflicts=proceed" in submit and "slices=auto" in submit
    assert "_tasks" not in " ".join(stack.os_paths), (
        "svc_bootstrap holds no cluster:monitor/tasks/lists — never poll _tasks")
    assert stack.os_refreshes == 1, "the final count must be refreshed first"
    assert "docs/s" in out and "docs left" in out, "progress must be printed"


def test_os_purge_budget_scales_with_the_starting_count(clock):
    stack = FakeStack([], page_cap=2500)
    stack.os_counts = [10_000_000] + [10_000_000] * 400
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-")
    assert ev["os_purge_budget_s"] == pytest.approx(
        ml.OS_PURGE_BUDGET_BASE_S + 10_000_000 * ml.OS_PURGE_SECONDS_PER_DOC)
    assert problems, "a purge that never drained must fail"


def test_os_purge_stall_fails_loudly_with_the_task_id(clock, capsys):
    stack = FakeStack([], page_cap=2500)
    stack.os_docs_left = 4_000                    # never drains
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=90, poll_s=30)
    assert ev["os_docs_left"] == 4_000
    assert len(problems) == 1
    assert "4000 docs left in netops-syslog-*" in problems[0]
    assert "abc123:456" in problems[0], "name the task still running server-side"
    assert "--cleanup-only mlx-run-" in problems[0]


def test_os_purge_never_reads_an_unreadable_count_as_clean(clock, capsys):
    """A count endpoint that fails is NOT evidence of an empty index."""
    stack = FakeStack([], page_cap=2500)
    stack.os_docs_left = -1                       # every count fails
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=60, poll_s=30)
    assert ev["os_docs_left"] == -1
    assert ev["os_deleted"] == -1
    assert any("UNKNOWN docs left" in p for p in problems), problems
    assert "progress UNKNOWN" in capsys.readouterr().err


def test_os_purge_reports_a_failed_submit_instead_of_polling_forever(clock, capsys):
    stack = FakeStack([], page_cap=2500)
    stack.os_counts = [5_000]
    stack.os_docs_left = 5_000
    stack.os_submit_ok = False
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=60, poll_s=30)
    assert ev["os_task"] == ""
    assert any("submit FAILED" in p for p in problems), problems
    assert any("curl exit 28" in p for p in problems), (
        "the curl exit code must survive into the purge's own message")
    assert any("5000 run docs left" in p for p in problems), problems


def test_os_purge_skips_the_delete_when_nothing_matches(clock):
    stack = FakeStack([], page_cap=2500)
    stack.os_docs_left = 0
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-")
    assert problems == []
    assert ev["os_docs_left"] == 0 and ev["os_task"] == ""
    assert not any("_delete_by_query" in p for p in stack.os_paths), (
        "idempotent: an already-clean index is not re-deleted")


def test_os_purge_survives_a_failed_refresh_but_says_so(clock, capsys):
    stack = FakeStack([], page_cap=2500)
    stack.os_counts = [1_000, 0, 0]
    stack.os_refresh_ok = False
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=120, poll_s=30)
    assert ev["os_docs_left"] == 0
    assert problems == []
    assert "_refresh before the final count failed" in capsys.readouterr().err


def test_os_purge_blind_pre_count_still_purges_and_reports(clock, capsys):
    stack = FakeStack([], page_cap=2500)
    stack.os_counts = [-1, 500, 0, 0]
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=120, poll_s=30)
    assert ev["os_task"] == "abc123:456", "a blind count must not skip the purge"
    assert any("pre-count" in p for p in problems), problems
    assert ev["os_docs_left"] == 0


def test_cleanup_only_reports_an_os_residue_as_a_failure(tmp_path, monkeypatch,
                                                         clock, capsys):
    """End to end: devices verified zero, OpenSearch NOT — exit 1, loudly.
    This is exactly the live run that produced the empty-message defect."""
    stack = FakeStack(_ids("mlx-", 10), page_cap=2500)
    stack.os_docs_left = 10_311_858
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: stack)
    monkeypatch.setattr(ml, "OS_PURGE_BUDGET_MAX_S", 90.0)
    _patch_ingress(monkeypatch)
    args = _args(tmp_path)
    args.cleanup_only = "mlx-"

    rc = ml.cleanup_only(args)
    err = capsys.readouterr().err
    assert rc == 1
    assert stack.devices == [], "devices still get purged and verified"
    assert "10311858 docs left in netops-syslog-*" in err
    assert "abc123:456" in err


# ── 7. preflight drain ETA ──────────────────────────────────────────────────

def test_preflight_lag_eta_reports_rate_and_eta(tmp_path, clock):
    stack = FakeStack([], page_cap=2500)
    stack.lag_values = [17000, 14000]
    h = _harness(tmp_path, stack)
    ev = h.lag_drain_eta("netops-correlation", 5000, first=20000)
    assert ev["rate_per_s"] == 200.0, ev
    assert ev["eta_seconds"] == 45.0, ev
    assert "ETA" in ev["summary"] and "min to reach 5000" in ev["summary"]


def test_preflight_lag_eta_says_so_when_the_backlog_is_not_draining(tmp_path, clock):
    stack = FakeStack([], page_cap=2500)
    stack.lag_values = [21000, 23000]
    h = _harness(tmp_path, stack)
    ev = h.lag_drain_eta("netops-correlation", 5000, first=20000)
    assert ev["eta_seconds"] is None
    assert "NOT draining" in ev["summary"], ev["summary"]


def test_preflight_lag_eta_never_blocks_longer_than_its_budget(tmp_path, clock,
                                                               monkeypatch):
    monkeypatch.setattr(ml, "LAG_ETA_INTERVAL_S", 45.0)
    monkeypatch.setattr(ml, "LAG_ETA_SAMPLES", 10)
    stack = FakeStack([], page_cap=2500)
    stack.lag_values = [9000] * 10
    h = _harness(tmp_path, stack)
    ev = h.lag_drain_eta("netops-correlation", 5000, first=10000)
    assert clock.slept <= ml.LAG_ETA_BUDGET_S, (
        f"preflight waited {clock.slept}s — the refusal must stay fast")
    assert ev["observed_s"] <= ml.LAG_ETA_BUDGET_S


def test_preflight_refusal_carries_the_eta(tmp_path, clock, capsys):
    """The refusal text itself must give the operator the number."""
    stack = FakeStack([], page_cap=2500)
    stack.lag_values = [17000, 14000]
    h = _harness(tmp_path, stack)
    ev = h.lag_drain_eta("netops-correlation", 5000, first=20000)
    assert ev["summary"] in capsys.readouterr().out
