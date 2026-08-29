"""Two mini-ladder runs on one stack must never inherit each other's devices.

THE DEFECT THIS FILE KILLS (2026-08-29). A cron ladder (`mlx-08290317j7hy`,
1,000 devices) and a manual 2,500-device run (`mlx-08290322msp1`) overlapped on
the SAME 198.18/15 addresses:

  * onboard reported "1000 of 2500 requested devices were ABSORBED by dedupe
    into an existing device" — and the run CARRIED ON into burst, injecting its
    full 900k events against devices whose identity belongs to the other run;
  * the manual run's cleanup reported "1500 devices deleted+verified (0
    remain)" and the cron run's reported "1000 devices deleted+verified (0
    remain)" — both TRUE per prefix;
  * and afterwards the store still held exactly 1,000 `mlx-08290322msp1-*`
    devices, because an absorbed create is still PERSISTED under the id the
    caller asked for (`discovery.Upsert` stores by id; only the READ projection
    `Devices()` -> `dedupeWithOwners` collapses the pair). Those shadow rows
    were invisible to a prefix LIST until the absorber was deleted — at which
    point no process was left that knew about them;
  * the next run's preflight then PASSED with those 1,000 devices standing and
    failed onboard on exactly the same collision.

Four guards, one section of tests each:

  1. preflight REFUSES on any `mlx-` device of ANY run id (override
     MLX_ALLOW_FOREIGN_RESIDUE=1, logged loudly).
  2. an onboard FAIL SKIPS burst/drain/completion/accounting and goes straight
     to cleanup.
  3. cleanup deletes the absorbed SHADOW ids and the devices that absorbed
     them, then verifies the WHOLE `mlx-` namespace — never "0 remain" while
     any mlx- device stands.
  4. a RUN LOCK (pid + run id) makes the overlap impossible in the first place.

`FakeApi` below reproduces the real API's identity semantics (persist by id,
absorb on a shared address, hide the shadow) so these are behaviour tests, not
mock-shaped assertions. Nothing here touches a stack, docker or a device.

Run:  python3 -m pytest tests/test_miniladder_cross_run_collision.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_collision", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_miniladder_collision"] = mod
    spec.loader.exec_module(mod)
    return mod


ml = _load_harness()


# ── the API's real identity semantics ───────────────────────────────────────


class FakeApi:
    """A device store with the API's ACTUAL identity semantics.

    * POST persists the REQUESTED id, always (`discovery.Upsert` keys by id).
    * When another record already holds the same management address, the create
      is ABSORBED: the response is 200 carrying the CANONICAL (surviving) id —
      the lexicographically smallest of the group, as `dedupeWithOwners` folds
      in sorted-id order — and the caller's own row becomes a SHADOW: persisted,
      but absent from GET /api/devices until the absorber is deleted.
    * DELETE removes exactly the id it names, shadow or not.
    """

    def __init__(self, rows: dict[str, str] | None = None, page_cap: int = 2500,
                 base_url: str = "http://stack.test"):
        self.rows: dict[str, str] = dict(rows or {})   # id -> address
        self.page_cap = page_cap
        self.base_url = base_url
        self.token = "fake"
        self.tls = False
        self.deleted: list[str] = []
        self.posted: list[str] = []
        self.post_status: dict[str, int] = {}   # id -> HTTP status to answer
        self.list_failures = 0
        self.logins = 0
        self.lag = 0
        self.ch_queries: list[str] = []
        self.ch_mutations: list[str] = []
        self.os_paths: list[str] = []
        self.ch_signals_left = 0
        self.os_docs_left = 0

    # -- identity model -----------------------------------------------------
    def visible(self) -> list[str]:
        groups: dict[tuple[str, str], list[str]] = {}
        for did, addr in self.rows.items():
            key = ("ip", addr) if addr else ("id", did)
            groups.setdefault(key, []).append(did)
        return sorted(min(ids) for ids in groups.values())

    def canonical_of(self, did: str) -> str:
        addr = self.rows.get(did, "")
        if not addr:
            return did
        return min(o for o, a in self.rows.items() if a == addr)

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
            shown = self.visible()
            rows = shown[offset:offset + limit]
            return 200, {"devices": [{"id": d} for d in rows],
                         "total": len(shown), "returned": len(rows),
                         "limit": limit, "offset": offset,
                         "complete": offset + len(rows) >= len(shown)}
        if method == "POST" and path == "/api/devices":
            did = str(body["id"])
            self.posted.append(did)
            if did in self.post_status:
                return self.post_status[did], {"error": "device was not saved"}
            self.rows[did] = str(body.get("address", ""))
            canonical = self.canonical_of(did)
            if canonical != did:
                return 200, {"id": canonical, "name": canonical}
            return 201, {"id": did, "name": did}
        if method == "DELETE" and path.startswith("/api/devices/"):
            did = path.rsplit("/", 1)[1]
            if did in self.rows:
                del self.rows[did]
                self.deleted.append(did)
                return 204, {}
            return 404, {}
        raise AssertionError(f"unexpected API call {method} {path}")

    # -- everything preflight/cleanup touches -------------------------------
    def service_states(self):
        return [{"service": s, "status": "running", "health": "healthy",
                 "exit_code": "0"} for s in ml.REQUIRED_SERVICES]

    def group_lag(self, _group):
        return {"_total": self.lag, "_members": 1, "_rows": 1}

    def mem_sample(self):
        return {}

    def anon_sample(self, _services):
        """cgroup-anon sampling (2026-08-29): memflat's instrument for every
        service that holds page cache. Nothing here judges memory."""
        return {}

    def ch_now(self):
        return "2026-08-29 07:00:00"

    def end_offset(self, _topic):
        return 0

    def ch(self, query, timeout=60):
        self.ch_queries.append(query)
        return True, str(self.ch_signals_left)

    def ch_mutation(self, query):
        self.ch_mutations.append(query)
        return True, ""

    def vm_query(self, _expr):
        return 0.0

    def corr_healthz(self):
        return {"durability": {"quarantine_write_failures": 0},
                "tenant_verification": {"registry_identities": 0}}

    def corr_metric(self, _name):
        return 0.0

    def corr_completion_state(self):
        return {"replicas": 1, "readable": 1}

    def os_count(self, index, _field, _prefix):
        self.os_paths.append(f"{index}/_count")
        return self.os_docs_left

    def os_req(self, _role, _user, url_path, body=None, timeout=25):
        self.os_paths.append(url_path)
        if "_delete_by_query" in url_path:
            return True, {"task": "t:1"}
        if url_path.endswith("_refresh"):
            return True, {"_shards": {"failed": 0}}
        return True, {}


@pytest.fixture(autouse=True)
def isolated_run_lock(tmp_path_factory, monkeypatch):
    """The run lock is a REAL file on the lab host (/var/tmp/scale-runs/.lock)
    and a live one gates a live run. No test may create, steal or delete it."""
    monkeypatch.setattr(ml, "RUN_LOCK_PATH",
                        str(tmp_path_factory.mktemp("runlock") / ".lock"))


@pytest.fixture(autouse=True)
def no_foreign_residue_override(monkeypatch):
    """The override is opt-in; a developer's shell must not decide a test."""
    monkeypatch.delenv(ml.ALLOW_FOREIGN_RESIDUE_ENV, raising=False)


@pytest.fixture
def nosleep(monkeypatch):
    monkeypatch.setattr(ml.time, "sleep", lambda _s: None)


def _args(tmp_path, **over):
    argv = ["--devices", str(over.pop("devices", 10)),
            "--run-dir", str(tmp_path / "run"),
            "--env-file", str(tmp_path / "stack.env"),
            "--base-url", "http://stack.test"]
    for k, v in over.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    return ml.parse_args(argv)


def _harness(tmp_path, stack, prefix="mlx-08290322msp1-", **over):
    h = ml.Harness(_args(tmp_path, **over))
    h.stack = stack
    h.prefix = prefix
    h.runid = prefix[len("mlx-"):-1]
    return h


def _fleet(prefix, n, first_addr_index=0):
    """A previous run's devices on the harness's OWN 198.18/15 addresses."""
    return {f"{prefix}{i:05d}": f"198.18.{i // 250}.{i % 250 + 1}"
            for i in range(first_addr_index, first_addr_index + n)}


# ═══ 0. the mechanism (what the harness is defending against) ═══════════════


def test_an_absorbed_create_persists_a_shadow_row_no_list_can_see():
    """src/backend/main.go handleDevices + internal/discovery/discovery.go:
    Upsert stores by id BEFORE ResolveIdentity reports the absorption, and only
    the read projection collapses the pair. This is why per-prefix teardown
    verified zero truthfully while 1,000 devices survived."""
    api = FakeApi(_fleet("mlx-00000000cron-", 3))
    st, resp = api.api("POST", "/api/devices",
                       {"id": "mlx-08290322msp1-00000", "address": "198.18.0.1"})
    assert st == 200, "an absorbed create answers 200, not 201 (tracker 161)"
    assert resp["id"] == "mlx-00000000cron-00000"
    # persisted...
    assert "mlx-08290322msp1-00000" in api.rows
    # ...but invisible, so a prefix-scoped verify sees nothing to delete
    assert "mlx-08290322msp1-00000" not in api.visible()
    ids, err = ml.devices_with_prefix(api, "mlx-08290322msp1-")
    assert (ids, err) == ([], "")
    # and it SURFACES the moment the absorber is deleted — with nobody left
    # who knows about it. That is the residue that broke three runs.
    api.api("DELETE", "/api/devices/mlx-00000000cron-00000")
    assert "mlx-08290322msp1-00000" in api.visible()


def test_run_id_is_recoverable_from_a_device_id():
    assert ml.run_id_of("mlx-08290317j7hy-00042") == "08290317j7hy"
    assert ml.run_id_of("core-rtr-01") == ""
    assert ml.residue_by_run(["mlx-a-1", "mlx-a-2", "mlx-b-1"]) == [("a", 2), ("b", 1)]
    assert "2 device(s) from 1 run id(s): a=2" in ml.residue_summary(["mlx-a-1", "mlx-a-2"])


# ═══ 1. preflight REFUSES on foreign residue ════════════════════════════════


def _preflight(tmp_path, api, monkeypatch, **over):
    h = _harness(tmp_path, api, **over)
    monkeypatch.setattr(h, "lag_drain_eta", lambda *a, **k: {"summary": ""})
    _patch_ingress(monkeypatch)
    os.makedirs(h.run_dir, exist_ok=True)
    return h, h.preflight()


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


def test_preflight_refuses_when_another_runs_devices_are_still_standing(
        tmp_path, monkeypatch, capsys):
    """THE OBSERVED RUN: preflight PASSED with 1,000 mlx- devices present."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 1000))
    h, ok = _preflight(tmp_path, api, monkeypatch)
    notes = h.phases[-1]["notes"]
    ev = h.phases[-1]["evidence"]

    assert ok is False, "a leftover mlx- fleet must REFUSE the run, not warn"
    assert h.phases[-1]["status"] == "FAIL"
    assert "1000 mlx- device(s) from a previous run" in notes
    assert "08290317j7hy=1000" in notes, "the refusal must name the run id(s)"
    assert "--cleanup-only mlx-" in notes, "and the exact command that fixes it"
    assert ev["namespace_residue_devices"] == 1000
    assert ev["namespace_residue_by_run"] == [("08290317j7hy", 1000)]
    assert api.posted == [], "a refused preflight must create nothing"


def test_preflight_names_every_offending_run_id(tmp_path, monkeypatch):
    api = FakeApi({**_fleet("mlx-08290317j7hy-", 3),
                   **_fleet("mlx-08281911zaz6-", 1, first_addr_index=500)})
    h, ok = _preflight(tmp_path, api, monkeypatch)
    assert ok is False
    assert h.phases[-1]["evidence"]["namespace_residue_by_run"] == [
        ("08290317j7hy", 3), ("08281911zaz6", 1)]


def test_preflight_passes_on_a_clean_namespace(tmp_path, monkeypatch):
    """Non-harness devices are somebody's real fleet and are none of our
    business — only the mlx- namespace is a refusal."""
    api = FakeApi({"core-rtr-01": "10.0.0.1", "edge-fw-02": "10.0.0.2"})
    h, ok = _preflight(tmp_path, api, monkeypatch)
    assert ok is True, h.phases[-1]["notes"]
    assert h.preflight_ok is True
    assert h.phases[-1]["evidence"]["namespace_residue_devices"] == 0


def test_preflight_refuses_when_the_namespace_cannot_be_listed(
        tmp_path, monkeypatch):
    """UNKNOWN is not clean (F-69). A blind check must never pass."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 5))
    api.list_failures = 99
    h, ok = _preflight(tmp_path, api, monkeypatch)
    assert ok is False
    assert "could not be listed" in h.phases[-1]["notes"]
    assert "UNKNOWN" in h.phases[-1]["notes"]


def test_preflight_override_proceeds_but_says_so_loudly(
        tmp_path, monkeypatch, capsys):
    api = FakeApi(_fleet("mlx-08290317j7hy-", 4))
    monkeypatch.setenv(ml.ALLOW_FOREIGN_RESIDUE_ENV, "1")
    h, ok = _preflight(tmp_path, api, monkeypatch)
    err = capsys.readouterr().err
    assert ok is True, h.phases[-1]["notes"]
    assert h.foreign_residue_allowed is True
    assert "MLX_ALLOW_FOREIGN_RESIDUE=1 — PROCEEDING" in err
    assert "4 device(s) from 1 run id(s)" in err
    assert "not qualification evidence" in err


def test_preflight_override_must_be_explicit(tmp_path, monkeypatch):
    """A typo'd value is NOT an override — default-closed."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 2))
    monkeypatch.setenv(ml.ALLOW_FOREIGN_RESIDUE_ENV, "maybe")
    _h, ok = _preflight(tmp_path, api, monkeypatch)
    assert ok is False


def test_MUTANT_a_prefix_scoped_preflight_check_passes_the_observed_run(
        tmp_path, monkeypatch):
    """The gate that was there: "does OpenSearch hold docs for MY prefix?".
    Both the old check and an own-prefix device count are blind to the 1,000
    devices of another run id that actually broke the run."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 1000))
    own, _err = ml.devices_with_prefix(api, "mlx-08290322msp1-")
    assert own == [], "a prefix-scoped check sees NOTHING — this is the mutant"
    everyone, _e2 = ml.devices_with_prefix(api, ml.DEVICE_PREFIX_ROOT)
    assert len(everyone) == 1000
    _h, ok = _preflight(tmp_path, api, monkeypatch)
    assert ok is False, "the namespace-wide gate must refuse where the old one passed"


# ═══ 2. an onboard FAIL never reaches the workload ══════════════════════════


def _phase(h, name):
    """The recorded phase entry called `name` (KeyError-loud if it never ran)."""
    return next(p for p in h.phases if p["phase"] == name)


def _instrument(h):
    """Record which phases execute() actually runs."""
    ran: list[str] = []

    def spy(name, result=True):
        def fn(*_a, **_k):
            ran.append(name)
            return result
        return fn

    h.burst = spy("burst")
    h.drain = spy("drain")
    h.correlation_completion = spy("correlation_completion")
    h.accounting = spy("accounting")
    h.memflat = spy("memflat")
    h.stability = spy("stability")
    return ran


def test_onboard_absorption_stops_the_run_before_the_burst(
        tmp_path, monkeypatch, nosleep, capsys):
    """THE OBSERVED RUN: onboard FAILED on 1,000 absorbed devices and the
    harness injected 900k events anyway."""
    api = FakeApi(_fleet("mlx-00000000cron-", 10))     # sorts before our runid
    h = _harness(tmp_path, api, devices=10)
    h.preflight = lambda: True
    h.preflight_ok = True
    ran = _instrument(h)
    rc = h.execute()
    out = capsys.readouterr()

    phases = {p["phase"]: p["status"] for p in h.phases}
    assert phases["onboard"] == "FAIL"
    assert ran == [], f"nothing may run after an onboard FAIL, ran {ran}"
    assert phases["workload"] == "SKIPPED"
    assert phases["cleanup"] == "PASS", "cleanup must still run"
    assert rc == 1, "the overall verdict is FAIL"
    assert "onboard stop=absorbed — skipping burst" in out.err
    onboard_ev = _phase(h, "onboard")["evidence"]
    assert onboard_ev["onboard_stop_reason"] == "absorbed"
    workload = _phase(h, "workload")
    assert workload["evidence"]["onboard_stop_reason"] == "absorbed"
    assert "stop=absorbed" in workload["notes"]
    report = json.loads((Path(h.run_dir) / "report.json").read_text())
    assert report["overall"] == "FAIL"


def test_onboard_records_the_canonical_ids_it_was_absorbed_into(
        tmp_path, nosleep):
    api = FakeApi(_fleet("mlx-00000000cron-", 10))
    h = _harness(tmp_path, api, devices=10)
    os.makedirs(h.run_dir, exist_ok=True)
    assert h.onboard() is False
    ev = h.phases[-1]["evidence"]
    assert ev["devices_absorbed_by_dedupe"] == 10
    assert ev["absorbed_canonical_count"] == 10
    assert ev["absorbed_canonical_ids"][0] == "mlx-00000000cron-00000"
    assert ev["absorbed_canonical_by_run"] == [("00000000cron", 10)]
    assert ev["onboard_stop_reason"] == "absorbed"
    assert h.absorbed["mlx-08290322msp1-00000"] == "mlx-00000000cron-00000"
    assert h.created_ids == [], "an absorbed device is not this run's device"
    assert "burst is SKIPPED" in h.phases[-1]["notes"]
    assert "--cleanup-only mlx-" in h.phases[-1]["notes"]


def test_MUTANT_ignoring_the_onboard_verdict_would_burst_on_absorbed_devices(
        tmp_path, monkeypatch, nosleep):
    """Half the fleet absorbed: `created_ids` is non-empty, which is exactly
    what the old `if self.created_ids and self.burst()` gate tested — and it
    injected the full burst against a fleet the run could not attribute."""
    api = FakeApi(_fleet("mlx-00000000cron-", 5))      # first 5 addresses taken
    h = _harness(tmp_path, api, devices=10)
    h.preflight = lambda: True
    h.preflight_ok = True
    ran = _instrument(h)
    h.execute()
    assert len(h.created_ids) == 5, "the mutant's gate would have been TRUE"
    assert len(h.absorbed) == 5
    assert h.onboard_stop_reason == "absorbed"
    assert ran == [], "a partially-absorbed fleet must not be burst against"


def test_a_clean_onboard_still_runs_the_whole_workload(
        tmp_path, monkeypatch, nosleep):
    """The skip must be conditional on the verdict, not a blanket disable."""
    api = FakeApi({"core-rtr-01": "10.0.0.1"})
    h = _harness(tmp_path, api, devices=10)
    h.preflight = lambda: True
    h.preflight_ok = True
    h.owns_run_lock = True
    ran = _instrument(h)
    h.execute()
    assert [p["status"] for p in h.phases if p["phase"] == "onboard"] == ["PASS"]
    assert h.onboard_stop_reason == "none"
    assert ran == ["burst", "drain", "correlation_completion", "accounting",
                   "memflat", "stability"]


def test_create_failures_stop_the_run_as_a_shortfall(tmp_path, nosleep, capsys):
    """A fleet smaller than the one planned is the second stop reason: the
    burst would be judged against devices that were never built."""
    api = FakeApi()
    api.post_status = {f"mlx-08290322msp1-{i:05d}": 500 for i in range(3)}
    h = _harness(tmp_path, api, devices=10)
    h.preflight = lambda: True
    h.preflight_ok = True
    h.owns_run_lock = True
    ran = _instrument(h)
    rc = h.execute()
    err = capsys.readouterr().err

    onboard = _phase(h, "onboard")
    assert onboard["status"] == "FAIL"
    assert onboard["evidence"]["onboard_stop_reason"] == "shortfall"
    assert onboard["evidence"]["devices_absorbed_by_dedupe"] == 0
    assert "stop=shortfall" in onboard["notes"]
    assert ran == [], "a short fleet must not be burst against"
    assert "onboard stop=shortfall — skipping burst" in err
    assert "only 7 of 10 requested devices exist" in err
    assert rc == 1


def test_a_linearity_only_fail_still_runs_the_whole_workload(
        tmp_path, nosleep, capsys):
    """OWNER DECISION 2026-08-29. The fleet is WHOLE and attributable; the
    O(N^2) verdict is about creation SPEED, and the burst it carries is still
    valid correlation evidence (the P1 verdict leg was exactly this case)."""
    api = FakeApi()
    h = _harness(tmp_path, api, devices=10, linearity_floor=999.0)
    h.preflight = lambda: True
    h.preflight_ok = True
    h.owns_run_lock = True
    ran = _instrument(h)
    h.execute()

    onboard = _phase(h, "onboard")
    assert onboard["status"] == "FAIL", "the linearity verdict still FAILS"
    assert onboard["evidence"]["onboard_stop_reason"] == "none"
    assert onboard["evidence"]["devices_created"] == 10
    assert onboard["evidence"]["devices_absorbed_by_dedupe"] == 0
    assert "[stop=none]" in onboard["notes"]
    assert "SUPER-LINEAR SLOWDOWN" in onboard["notes"]
    assert ran == ["burst", "drain", "correlation_completion", "accounting",
                   "memflat", "stability"], (
        "a speed verdict must not cost the run its correlation evidence")
    assert "workload" not in {p["phase"] for p in h.phases}
    assert "skipping burst" not in capsys.readouterr().err


def test_MUTANT_collapsing_the_stop_reasons_discards_valid_evidence(
        tmp_path, nosleep):
    """The mutant is the verdict-based gate (`if not onboard_ok`) this file
    shipped first: it cannot tell "the fleet is wrong" from "creation was
    slow", so it throws away a whole valid burst. Both branches are exercised
    here against ONE harness, so collapsing them fails exactly one of them."""
    slow = FakeApi()
    h_slow = _harness(tmp_path / "slow", slow, devices=10, linearity_floor=999.0)
    h_slow.preflight = lambda: True
    h_slow.preflight_ok = True
    h_slow.owns_run_lock = True
    ran_slow = _instrument(h_slow)
    h_slow.execute()

    # PARTIAL absorption on purpose: `created_ids` is non-empty, so the old
    # `elif self.created_ids` guard is TRUE and only the stop reason stands
    # between this run and a burst on an unattributable fleet.
    absorbed = FakeApi(_fleet("mlx-00000000cron-", 5))
    h_abs = _harness(tmp_path / "absorbed", absorbed, devices=10)
    h_abs.preflight = lambda: True
    h_abs.preflight_ok = True
    h_abs.owns_run_lock = True
    ran_abs = _instrument(h_abs)
    h_abs.execute()

    slow_onboard = _phase(h_slow, "onboard")
    abs_onboard = _phase(h_abs, "onboard")
    assert slow_onboard["status"] == abs_onboard["status"] == "FAIL", (
        "both are onboard FAILs — the VERDICT cannot distinguish them, which "
        "is precisely why the reason is recorded separately")
    assert h_slow.onboard_stop_reason == "none"
    assert h_abs.onboard_stop_reason == "absorbed"
    assert h_abs.created_ids, "the fleet-size guard alone would not have stopped it"
    assert ran_slow and not ran_abs, (
        "collapsing the two reasons either bursts on an unattributable fleet "
        "or discards a valid one")


# ═══ 3. cleanup: shadow rows, absorbers, and the whole namespace ════════════


def _cleanup(tmp_path, api, absorbed=None, created=(), **kw):
    h = _harness(tmp_path, api, **{k: v for k, v in kw.items()
                                   if k in ("devices", "prefix")})
    h.created_ids = list(created)
    h.absorbed = dict(absorbed or {})
    h.owns_run_lock = kw.get("owns_run_lock", True)
    h.preflight_ok = kw.get("preflight_ok", True)
    h.foreign_residue_allowed = kw.get("foreign_residue_allowed", False)
    os.makedirs(h.run_dir, exist_ok=True)
    return h, h.cleanup()


def test_cleanup_deletes_the_shadow_rows_a_list_cannot_see(
        tmp_path, nosleep):
    """The 1,000 devices that survived both teardowns."""
    api = FakeApi(_fleet("mlx-00000000cron-", 3))
    shadows = {}
    for i in range(3):
        did = f"mlx-08290322msp1-{i:05d}"
        st, resp = api.api("POST", "/api/devices",
                           {"id": did, "address": f"198.18.0.{i + 1}"})
        assert st == 200
        shadows[did] = resp["id"]
    assert ml.devices_with_prefix(api, "mlx-08290322msp1-")[0] == [], (
        "the shadow rows are invisible — that is the whole defect")

    h, ok = _cleanup(tmp_path, api, absorbed=shadows)
    assert ok is True, h.phases[-1]["notes"]
    assert api.rows == {}, f"every mlx- row must be gone, left {api.rows}"
    assert h.residue_devices == 0
    ev = h.phases[-1]["evidence"]
    assert ev["absorbed_shadow_ids_seeded"] == 3
    assert ev["absorbed_canonical_deleted"] == 3
    assert set(api.deleted) >= set(shadows) | set(shadows.values())


def test_cleanup_never_deletes_an_absorber_outside_the_harness_namespace(
        tmp_path, nosleep, capsys):
    """Blast radius (16.3): a real device that absorbed our create is not
    ours to delete — but the operator is TOLD, loudly."""
    api = FakeApi({"core-rtr-01": "198.18.0.1"})
    st, resp = api.api("POST", "/api/devices",
                       {"id": "mlx-08290322msp1-00000", "address": "198.18.0.1"})
    assert (st, resp["id"]) == (200, "core-rtr-01")
    h, _ok = _cleanup(tmp_path, api,
                      absorbed={"mlx-08290322msp1-00000": "core-rtr-01"})
    err = capsys.readouterr().err
    assert "core-rtr-01" in api.rows, "a real device must never be deleted"
    assert "OUTSIDE the mlx- namespace" in err
    assert h.phases[-1]["evidence"]["absorbed_canonical_outside_namespace"] == [
        "core-rtr-01"]
    # ...and OUR shadow row behind it is still deleted, by id. Nothing can see
    # it (the absorber survives, so the list never shows it) and no sweep can
    # find it: only the SEED — `self.absorbed`'s keys — reaches it.
    assert "mlx-08290322msp1-00000" in api.deleted
    assert "mlx-08290322msp1-00000" not in api.rows
    assert h.residue_devices == 0


def test_cleanup_sweeps_the_foreign_residue_that_surfaces_behind_our_own(
        tmp_path, nosleep, capsys):
    """The mirror image of the observed run: OUR ids won the merge, so the
    other run's rows were the hidden ones and surfaced as our devices were
    deleted. A prefix-scoped teardown would have walked away from them."""
    api = FakeApi()
    for i in range(4):                       # foreign fleet, hidden behind ours
        api.rows[f"mlx-99999999late-{i:05d}"] = f"198.18.0.{i + 1}"
    created = []
    for i in range(4):
        did = f"mlx-08290322msp1-{i:05d}"
        st, _r = api.api("POST", "/api/devices",
                         {"id": did, "address": f"198.18.0.{i + 1}"})
        assert st == 201, "our id sorts first, so WE are the survivor"
        created.append(did)
    assert ml.devices_with_prefix(api, "mlx-99999999late-")[0] == []

    h, ok = _cleanup(tmp_path, api, created=created)
    out = capsys.readouterr()
    assert api.rows == {}, f"the namespace must be empty, left {api.rows}"
    assert h.residue_devices == 0
    assert ok is True, h.phases[-1]["notes"]
    assert "FOREIGN RESIDUE" in out.err
    assert "99999999late=4" in out.err
    assert h.phases[-1]["evidence"]["namespace"]["swept"] is True


def test_cleanup_never_reports_zero_while_a_foreign_device_stands(
        tmp_path, nosleep, capsys):
    """Without the run lock we cannot prove the rows are orphaned, so they are
    NOT deleted — but the run is charged for them and exits non-zero. "0
    remain" while any mlx- device exists is the sentence this kills."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 6))
    h, ok = _cleanup(tmp_path, api, owns_run_lock=False)
    out = capsys.readouterr()
    assert ok is False, "a namespace with residue is not a PASS"
    assert h.residue_devices == 6
    assert "0 remain" not in h.phases[-1]["notes"]
    assert "were NOT swept" in h.phases[-1]["notes"]
    assert "--cleanup-only mlx-" in h.phases[-1]["notes"]
    assert "does not hold the run lock" in h.phases[-1]["notes"]
    assert len(api.rows) == 6, "another process's devices must not be deleted"
    assert "FOREIGN RESIDUE" in out.err


def test_cleanup_leaves_a_refused_runs_residue_for_the_operator(
        tmp_path, nosleep):
    """A run REFUSED at preflight was sent to --cleanup-only; deleting the
    evidence under the operator would be the second surprise of the day."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 5))
    h, ok = _cleanup(tmp_path, api, owns_run_lock=True, preflight_ok=False)
    assert ok is False
    assert len(api.rows) == 5
    assert "REFUSED at preflight" in h.phases[-1]["notes"]
    assert h.residue_devices == 5


def test_cleanup_honours_a_deliberate_foreign_residue(tmp_path, nosleep, capsys):
    """MLX_ALLOW_FOREIGN_RESIDUE: the rows are the operator's, so they are
    neither swept nor charged to this run — and the note never claims the
    namespace is empty."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 3))
    h, ok = _cleanup(tmp_path, api, foreign_residue_allowed=True)
    err = capsys.readouterr().err
    assert ok is True
    assert len(api.rows) == 3, "a deliberate residue must survive cleanup"
    assert h.residue_devices == 0
    assert "3 foreign mlx- device(s) left standing on purpose" in h.phases[-1]["notes"]
    assert "the NEXT run will refuse on them" in err


def test_cleanup_reports_an_unreadable_namespace_as_unknown(tmp_path, nosleep):
    api = FakeApi()
    h = _harness(tmp_path, api)
    h.owns_run_lock = True
    h.preflight_ok = True
    os.makedirs(h.run_dir, exist_ok=True)
    real = ml.devices_with_prefix

    def flaky(stack, prefix, **kw):
        if prefix == ml.DEVICE_PREFIX_ROOT:
            return [], "device list failed at offset 0: HTTP 503"
        return real(stack, prefix, **kw)

    ml.devices_with_prefix = flaky
    try:
        ok = h.cleanup()
    finally:
        ml.devices_with_prefix = real
    assert ok is False
    assert h.residue_devices == -1, "unverified must read UNKNOWN, never 0"
    assert "UNKNOWN, not zero" in h.phases[-1]["notes"]


def test_MUTANT_a_prefix_only_teardown_reports_zero_with_1000_devices_left(
        tmp_path, nosleep):
    """Exactly what both 2026-08-29 runs printed: "0 remain" per prefix, with
    the other run's fleet standing. The namespace verdict must differ."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 1000))
    prefix_only = ml.purge_devices(api, "mlx-08290322msp1-", budget_s=60)
    assert prefix_only["verified_zero"] is True and prefix_only["remaining"] == 0, (
        "the per-prefix purge is TRUTHFUL — that is why it was believed")
    assert len(api.rows) == 1000
    h, ok = _cleanup(tmp_path, api, owns_run_lock=False)
    assert ok is False and h.residue_devices == 1000


# ═══ 4. the run lock ════════════════════════════════════════════════════════


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _write_lock(path, pid, runid="08290317j7hy"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(
        {"pid": pid, "runid": runid, "started": "2026-08-29T03:17:01Z"}))


def test_lock_refuses_while_a_live_process_holds_it(tmp_path, capsys):
    path = str(tmp_path / "run.lock")
    _write_lock(path, os.getpid())
    held, msg = ml.RunLock(path=path, runid="new").acquire()
    assert held is False
    assert f"pid {os.getpid()}" in msg
    assert "08290317j7hy" in msg, "the refusal must name the holder's run"
    assert "cron collision" in msg
    assert Path(path).exists(), "a refusal must not disturb the live lock"


def test_lock_reclaims_a_stale_lock_and_says_so(tmp_path, capsys):
    path = str(tmp_path / "run.lock")
    _write_lock(path, _dead_pid())
    held, msg = ml.RunLock(path=path, runid="mine").acquire()
    err = capsys.readouterr().err
    assert held is True, msg
    assert "STALE lock" in err and "reclaiming" in err
    assert json.loads(Path(path).read_text())["pid"] == os.getpid()


def test_lock_reclaims_a_corrupt_lock_loudly(tmp_path, capsys):
    path = str(tmp_path / "run.lock")
    Path(path).write_text("{not json")
    held, _msg = ml.RunLock(path=path, runid="mine").acquire()
    err = capsys.readouterr().err
    assert held is True
    assert "unreadable" in err, "a corrupt lock is reported, never silent"


def test_lock_is_exclusive_between_two_harness_processes(tmp_path):
    path = str(tmp_path / "run.lock")
    first = ml.RunLock(path=path, runid="a")
    assert first.acquire()[0] is True
    second = ml.RunLock(path=path, runid="b")
    held, msg = second.acquire()
    assert held is False and "another scale-miniladder process" in msg
    first.release()
    assert ml.RunLock(path=path, runid="b").acquire()[0] is True


def test_lock_release_leaves_a_lock_that_is_no_longer_ours(tmp_path, capsys):
    path = str(tmp_path / "run.lock")
    lock = ml.RunLock(path=path, runid="a")
    assert lock.acquire()[0] is True
    _write_lock(path, os.getpid() + 1_000_000, runid="someone-else")
    lock.release()
    assert Path(path).exists(), "we may only remove OUR OWN lock"
    assert "leaving it alone" in capsys.readouterr().err


def test_dead_pid_is_not_alive_and_our_own_is(tmp_path):
    assert ml.RunLock.pid_alive(os.getpid()) is True
    assert ml.RunLock.pid_alive(_dead_pid()) is False
    assert ml.RunLock.pid_alive(0) is False


def _main_args(tmp_path, api, monkeypatch):
    (tmp_path / "stack.env").write_text("BASE_PORT=8000\nCOMPOSE_PROJECT_NAME=netops\n")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))   # restored by monkeypatch
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: api)
    return ["--devices", "10", "--run-dir", str(tmp_path / "run"),
            "--env-file", str(tmp_path / "stack.env"),
            "--base-url", "http://stack.test"]


def test_main_refuses_to_start_while_the_lock_is_held(tmp_path, monkeypatch, capsys):
    """The guard that would have prevented the whole 2026-08-29 collision: the
    cron run was already running."""
    api = FakeApi()
    argv = _main_args(tmp_path, api, monkeypatch)
    _write_lock(ml.RUN_LOCK_PATH, os.getpid(), runid="08290317j7hy")
    monkeypatch.setattr(ml.Harness, "execute",
                        lambda self: pytest.fail("the run must not start"))
    with pytest.raises(SystemExit) as exc:
        ml.main(argv)
    assert exc.value.code == 2, "refused before touching the stack"
    assert "another scale-miniladder process holds" in capsys.readouterr().err
    assert api.posted == []


def test_main_takes_and_releases_the_lock(tmp_path, monkeypatch):
    api = FakeApi()
    argv = _main_args(tmp_path, api, monkeypatch)
    seen: dict = {}

    def fake_execute(self):
        seen["locked"] = Path(ml.RUN_LOCK_PATH).exists()
        seen["owns"] = self.owns_run_lock
        seen["holder"] = json.loads(Path(ml.RUN_LOCK_PATH).read_text())
        return 0

    monkeypatch.setattr(ml.Harness, "execute", fake_execute)
    assert ml.main(argv) == 0
    assert seen["locked"] is True
    assert seen["owns"] is True, "only a lock holder may sweep the namespace"
    assert seen["holder"]["pid"] == os.getpid()
    assert not Path(ml.RUN_LOCK_PATH).exists(), "the lock must be released"


def test_main_releases_the_lock_on_an_interrupt(tmp_path, monkeypatch):
    """^C during a run must not leave a lock that blocks the next one."""
    api = FakeApi()
    argv = _main_args(tmp_path, api, monkeypatch)

    def boom(self):
        raise KeyboardInterrupt("SIGINT")

    monkeypatch.setattr(ml.Harness, "execute", boom)
    with pytest.raises(KeyboardInterrupt):
        ml.main(argv)
    assert not Path(ml.RUN_LOCK_PATH).exists()


def test_cleanup_only_takes_the_lock_and_releases_it_on_refusal(
        tmp_path, monkeypatch, capsys):
    """--cleanup-only DELETES devices: it must not run against a live run's
    stack, and it must not leak the lock when it refuses."""
    api = FakeApi(_fleet("mlx-08290317j7hy-", 3))
    argv = _main_args(tmp_path, api, monkeypatch)
    _patch_ingress(monkeypatch, ok=False)
    with pytest.raises(SystemExit) as exc:
        ml.main([*argv, "--cleanup-only", "mlx-"])
    assert exc.value.code == 2
    assert "stack unreachable" in capsys.readouterr().err
    assert api.deleted == []
    assert not Path(ml.RUN_LOCK_PATH).exists(), (
        "a refusal must release the lock, or the next purge is blocked")


def test_cleanup_only_refuses_while_a_run_holds_the_lock(
        tmp_path, monkeypatch, capsys):
    api = FakeApi(_fleet("mlx-08290317j7hy-", 3))
    argv = _main_args(tmp_path, api, monkeypatch)
    _write_lock(ml.RUN_LOCK_PATH, os.getpid(), runid="08290322msp1")
    with pytest.raises(SystemExit) as exc:
        ml.main([*argv, "--cleanup-only", "mlx-"])
    assert exc.value.code == 2
    assert api.deleted == [], "a live run's fleet must never be purged under it"
    assert "another scale-miniladder process holds" in capsys.readouterr().err


def test_MUTANT_an_existence_only_lock_would_wedge_the_lab(tmp_path):
    """Liveness, not existence, decides ownership: a killed run leaves a lock
    behind, and a lock nobody can reclaim is worse than no lock at all."""
    path = str(tmp_path / "run.lock")
    _write_lock(path, _dead_pid())
    assert Path(path).exists(), "the mutant's test (file exists) would refuse"
    assert ml.RunLock(path=path, runid="mine").acquire()[0] is True
