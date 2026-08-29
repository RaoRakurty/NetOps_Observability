"""A transient socket timeout must never cost the mini-ladder its teardown.

THE DEFECT THIS FILE KILLS (live 2026-08-29, /var/tmp/scale-runs/
p2-s012d-08290411/launcher.log, and once earlier during a concurrent
`--cleanup-only`). The box was under load — the correlation engine draining a
21k backlog, ClickHouse busy — and the platform API's HTTP client hit a socket
read timeout. `Stack.api()` had a fixed 15s timeout and NO retry, so a raw

    TimeoutError('timed out')

unwound out of `cleanup()`, past every remaining teardown step, and the run
ended:

    miniladder: WARNING: RESIDUE LEFT: UNKNOWN (never verified) devices ...

...with the fleet still standing. One timed-out socket, a whole teardown lost
and a residue count nobody could trust.

Three fixes, one section of tests each:

  1. ONE bounded retry policy (`http_retry`) on every urllib call site:
     5 attempts, exponential backoff with FULL jitter, an 8s per-sleep cap and
     a 30s total sleeping budget. Transient TRANSPORT failures only — a 4xx
     other than 429 is the server's considered answer and is never repeated.
     Every retry is logged (§16.1); after the budget the ORIGINAL exception is
     re-raised with the attempt count folded into its message.
  2. `Stack.api` reports an exhausted transport failure as `(0, "transport:
     ...")` instead of raising it: every caller already treats a non-2xx as
     "not evidence" (a list error means residue UNKNOWN, never zero — F-69).
  3. Cleanup runs its steps under `cleanup_step`: a step that fails after its
     retries is a recorded, warned PROBLEM and the next step still runs
     (devices -> ClickHouse -> OpenSearch), and the residue is RE-VERIFIED at
     the end — that re-verified count, not a step's optimism, is what the run
     reports and what `RESIDUE LEFT` names alongside the exact `--cleanup-only`
     command.

Section 4 covers the second half of the same live incident: the OpenSearch
purge budget assumed 2,000 docs/s and abandoned a delete that was working
(198s budget, 81,001 of 276,001 docs left, task still running server-side).
The budget now re-estimates itself from the MEASURED rate.

Nothing here touches a stack, docker or a device: urllib is mocked, the clock
is fake, and the only "API" is a dict keyed the way the real one is.

Run:  python3 -m pytest tests/test_miniladder_http_retry.py -v
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_retry", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_miniladder_retry"] = mod
    spec.loader.exec_module(mod)
    return mod


ml = _load_harness()


# ── fakes ───────────────────────────────────────────────────────────────────


class FakeResponse(io.BytesIO):
    """What `urllib.request.urlopen` returns: a context manager with a status."""

    def __init__(self, status: int = 200, body: object = None):
        super().__init__(json.dumps(body if body is not None else {}).encode())
        self.status = status

    def __enter__(self):     # -> Self, but this host is 3.10
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def http_error(code: int, body: str = "no") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://stack.test/api/x", code, body, {}, io.BytesIO(body.encode()))


def wrapped_timeout() -> urllib.error.URLError:
    """The exact shape urllib hands up on a socket read timeout: a URLError
    whose `.reason` is the TimeoutError. The classifier must see through it."""
    return urllib.error.URLError(TimeoutError("timed out"))


class Recorder:
    """A scripted `urlopen`: each entry is either an exception to raise or a
    (status, body) to answer with. Records every request it was given."""

    def __init__(self, script: list[object]):
        self.script = list(script)
        self.calls: list[tuple[str, str, object]] = []

    def __call__(self, req, timeout=None):            # unused: urlopen's shape
        body = req.data and json.loads(req.data.decode())
        self.calls.append((req.get_method(), req.full_url, body))
        step = self.script.pop(0) if self.script else (200, {})
        if isinstance(step, BaseException):
            raise step
        status, payload = step
        return FakeResponse(status, payload)


class Delays:
    """Records every backoff sleep; jitter is pinned to its ceiling so the
    SCHEDULE is assertable (full jitter itself is asserted separately)."""

    def __init__(self, monkeypatch, jitter: str = "max"):
        self.slept: list[float] = []
        monkeypatch.setattr(ml.time, "sleep", self.slept.append)
        if jitter == "max":
            monkeypatch.setattr(ml.random, "uniform", lambda _lo, hi: hi)
        elif jitter == "min":
            monkeypatch.setattr(ml.random, "uniform", lambda lo, _hi: lo)


@pytest.fixture
def delays(monkeypatch):
    return Delays(monkeypatch)


def _stack(monkeypatch, script: list[object]) -> tuple[object, Recorder]:
    rec = Recorder(script)
    monkeypatch.setattr(ml.urllib.request, "urlopen", rec)
    stack = ml.Stack("/nonexistent.env", "http://stack.test", "netops")
    stack.token = "tok"
    return stack, rec


# ═══ 1. the retry policy itself ═════════════════════════════════════════════


def test_a_socket_timeout_is_retried_once_and_then_succeeds(delays, capsys):
    """The live failure: one `TimeoutError('timed out')`, then the box answers."""
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("timed out")
        return "ok"

    assert ml.http_retry("GET /api/devices", flaky) == "ok"
    assert calls["n"] == 2, "exactly one retry — not zero, not a storm of them"
    assert delays.slept == [pytest.approx(ml.HTTP_RETRY_BASE_S)], (
        "the first retry waits one base interval (jitter pinned to its ceiling)")
    err = capsys.readouterr().err
    assert "socket timeout" in err and "attempt 1/5" in err, err
    assert "retrying in" in err, "§16.1: a silent retry is indistinguishable from a hang"


def test_a_url_error_wrapping_a_timeout_is_still_a_timeout(delays):
    """urllib buries the socket error in `.reason` — that is the live shape."""
    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise wrapped_timeout()
        return "ok"

    assert ml.http_retry("GET /", flaky) == "ok"
    assert calls["n"] == 3


def test_exhausting_the_budget_reraises_the_original_type_with_the_count(delays):
    """The operator must still see a TimeoutError — and how much was spent."""

    def always() -> None:
        raise TimeoutError("timed out")

    with pytest.raises(TimeoutError) as excinfo:
        ml.http_retry("GET /api/devices", always)
    msg = str(excinfo.value)
    assert "timed out" in msg, "the original message survives"
    assert "5 attempt(s)" in msg, f"the attempt count must ride in the message: {msg}"
    assert "GET /api/devices" in msg, "and WHICH call it was"
    assert len(delays.slept) == ml.HTTP_RETRY_ATTEMPTS - 1


def test_the_backoff_is_exponential_capped_and_jittered(monkeypatch):
    d = Delays(monkeypatch)

    def always() -> None:
        raise ConnectionResetError("reset by peer")

    with pytest.raises(ConnectionResetError):
        ml.http_retry("GET /", always, attempts=8, total_s=1000)
    assert d.slept == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0], (
        f"ceilings double to the {ml.HTTP_RETRY_CAP_S}s cap, then hold: {d.slept}")

    lo = Delays(monkeypatch, jitter="min")
    with pytest.raises(ConnectionResetError):
        ml.http_retry("GET /", always, attempts=3)
    assert lo.slept == [0.0, 0.0], (
        "FULL jitter: the delay is uniform over [0, ceiling], not the ceiling "
        "itself — that is what de-synchronises a fleet of retriers")


def test_the_total_sleeping_budget_is_bounded(monkeypatch):
    d = Delays(monkeypatch)

    def always() -> None:
        raise TimeoutError("timed out")

    with pytest.raises(TimeoutError):
        ml.http_retry("GET /", always, attempts=20, total_s=3.0)
    assert sum(d.slept) <= 3.0 + 1e-9, f"budget blown: {d.slept}"
    assert sum(d.slept) == pytest.approx(3.0), "and the budget is actually used"


def test_a_503_is_retried_and_a_429_too(delays):
    for code in (429, 502, 503, 504):
        calls = {"n": 0}

        def flaky(code=code, calls=calls) -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise http_error(code, "busy")
            return "ok"

        assert ml.http_retry(f"GET /{code}", flaky) == "ok"
        assert calls["n"] == 2, f"HTTP {code} means 'not now' — retry it"


def test_MUTANT_retrying_a_4xx_would_multiply_a_deliberate_answer(delays):
    """A 4xx (other than 429) is the server's considered answer about the
    REQUEST: repeating it cannot change it, and repeating the device purge's
    404s would quintuple every 'this device is already gone'."""
    for code in (400, 401, 403, 404, 409, 422):
        calls = {"n": 0}

        def once(code=code, calls=calls) -> None:
            calls["n"] += 1
            raise http_error(code, "nope")

        with pytest.raises(urllib.error.HTTPError):
            ml.http_retry(f"GET /{code}", once)
        assert calls["n"] == 1, f"HTTP {code} must be answered once, not retried"
    assert delays.slept == [], "and no backoff burned on a settled answer"


def test_a_non_transport_error_is_not_retried(delays):
    """A bug in the harness must surface on attempt 1, not five slow times."""
    calls = {"n": 0}

    def broken() -> None:
        calls["n"] += 1
        raise ValueError("bad json")

    with pytest.raises(ValueError):
        ml.http_retry("GET /", broken)
    assert calls["n"] == 1 and delays.slept == []


def test_connection_refused_and_reset_are_transient(delays):
    for exc in (ConnectionRefusedError("refused"),
                ConnectionResetError("reset"),
                OSError(ml.errno.EHOSTUNREACH, "no route to host")):
        calls = {"n": 0}

        def flaky(exc=exc, calls=calls) -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise exc
            return "ok"

        assert ml.http_retry("GET /", flaky) == "ok"
        assert calls["n"] == 2, f"{exc!r} is a busy box, not a bad request"


# ═══ 2. the call sites: Stack.api, login, the create loop ═══════════════════


def test_api_retries_a_timeout_and_returns_the_answer(monkeypatch, delays):
    stack, rec = _stack(monkeypatch, [wrapped_timeout(), (200, {"devices": []})])
    st, body = stack.api("GET", "/api/devices")
    assert (st, body) == (200, {"devices": []})
    assert len(rec.calls) == 2


def test_api_reports_an_exhausted_transport_failure_instead_of_raising(
        monkeypatch, delays, capsys):
    """THE 2026-08-29 CRASH. `TimeoutError` must not escape into cleanup."""
    stack, rec = _stack(monkeypatch, [TimeoutError("timed out")] * 5)
    st, body = stack.api("GET", "/api/devices")
    assert st == 0, "an unreachable API is HTTP 0, never an exception"
    assert "transport" in str(body) and "TimeoutError" in str(body), body
    assert stack.http_transport_failures == 1, "counted, not hidden"
    assert len(rec.calls) == 5
    assert "transport FAILED after retries" in capsys.readouterr().err


def test_an_unreadable_device_list_reads_as_UNKNOWN_not_as_zero(
        monkeypatch, delays):
    """F-69 end to end: the retried-then-failed list must never look clean."""
    stack, _ = _stack(monkeypatch, [TimeoutError("timed out")] * 5)
    found, err = ml.devices_with_prefix(stack, "mlx-")
    assert found == []
    assert err and "HTTP 0" in err, (
        f"the list error must carry the transport failure, not silence: {err}")


def test_api_still_relogins_once_on_401(monkeypatch, delays):
    monkeypatch.setenv("MLX_ADMIN_USER", "admin")
    monkeypatch.setenv("MLX_ADMIN_PASSWORD", "pw")
    stack, _rec = _stack(monkeypatch, [
        http_error(401, "expired"),
        (200, {"token": "fresh"}),          # the re-login
        (200, {"ok": True}),                # the retried call
    ])
    st, body = stack.api("GET", "/api/devices")
    assert (st, body) == (200, {"ok": True})
    assert stack.token == "fresh"
    assert delays.slept == [], "a 401 is a re-login, not a backoff"


def test_login_retries_a_transient_failure_then_raises_on_a_real_one(
        monkeypatch, delays):
    stack, login_rec = _stack(monkeypatch, [
        wrapped_timeout(), (200, {"token": "abc"})])
    monkeypatch.setattr(ml, "env_get", lambda *_a: "user-or-pw")
    stack.login()
    assert stack.token == "abc" and len(login_rec.calls) == 2

    monkeypatch.setenv("MLX_ADMIN_USER", "admin")
    monkeypatch.setenv("MLX_ADMIN_PASSWORD", "pw")
    stack2, _ = _stack(monkeypatch, [TimeoutError("timed out")] * 5)
    with pytest.raises(TimeoutError) as excinfo:
        stack2.login()
    assert "5 attempt(s)" in str(excinfo.value), (
        "login stays RAISING — 'cannot log in' is a refusal, not data")


def test_the_ingress_probe_is_retried(monkeypatch, delays):
    rec = Recorder([wrapped_timeout(), (200, {})])
    monkeypatch.setattr(ml.urllib.request, "urlopen", rec)
    assert ml.http_ingress_status("http://stack.test") == 200
    assert len(rec.calls) == 2


def test_a_retried_device_create_cannot_make_a_second_device(
        monkeypatch, delays):
    """THE IDEMPOTENCE FINDING, executed.

    POST /api/devices is safe to repeat because the handler keys the write by
    the caller's id: `handleDevices` calls `s.discovery.Upsert(d)`
    (src/backend/main.go:2368) and `Upsert` stores by `d.ID`
    (src/backend/internal/discovery/discovery.go:569-590 — `store.Put(d)` then
    `a.cache[d.ID] = d`). So the dangerous case — the request LANDED and only
    the response was lost — overwrites the same row instead of creating a
    twin. This fake reproduces exactly that.
    """
    store: dict[str, dict] = {}
    state = {"first": True}

    def urlopen(req, timeout=None):          # urlopen's shape
        body = json.loads(req.data.decode())
        store[body["id"]] = body              # the write ALWAYS lands (upsert)
        if state["first"]:
            state["first"] = False
            raise wrapped_timeout()           # ...and the answer is lost
        return FakeResponse(201, {"id": body["id"]})

    monkeypatch.setattr(ml.urllib.request, "urlopen", urlopen)
    stack = ml.Stack("/nonexistent.env", "http://stack.test", "netops")
    stack.token = "tok"
    st, resp = stack.api("POST", "/api/devices",
                         {"id": "mlx-run-00001", "name": "mlx-run-00001"})
    assert (st, resp) == (201, {"id": "mlx-run-00001"})
    assert list(store) == ["mlx-run-00001"], (
        "an upsert-by-id create is idempotent: the retry overwrote the row it "
        "had already written, it did not manufacture a second device")


# ═══ 3. cleanup: a failed step is loud, not fatal ═══════════════════════════


class FakeStack:
    """The teardown surface, with a device store keyed by id like the real one."""

    def __init__(self, device_ids=(), base_url="http://stack.test"):
        self.devices: list[str] = list(device_ids)
        self.base_url = base_url
        self.token = "fake"
        self.tls = False
        self.http_transport_failures = 0
        self.ch_mutations: list[str] = []
        self.os_paths: list[str] = []
        self.ch_raises: BaseException | None = None
        # The async OpenSearch purge measures progress by RE-COUNTING, so a
        # drain is a scripted sequence; `os_docs_left` is the steady state.
        self.os_counts: list[int] = []
        self.os_docs_left = 0
        self.deleted: list[str] = []

    def login(self) -> None:
        return None

    def api(self, method, path, body=None):
        if method == "GET" and path.startswith("/api/devices"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            offset = int(q.get("offset", ["0"])[0])
            limit = int(q.get("limit", ["5000"])[0])
            rows = self.devices[offset:offset + limit]
            return 200, {"devices": [{"id": d} for d in rows],
                         "total": len(self.devices), "returned": len(rows),
                         "limit": limit, "offset": offset,
                         "complete": offset + len(rows) >= len(self.devices)}
        if method == "DELETE" and path.startswith("/api/devices/"):
            did = path.rsplit("/", 1)[1]
            if did in self.devices:
                self.devices.remove(did)
            self.deleted.append(did)
            return 204, {}
        raise AssertionError(f"unexpected API call {method} {path}")

    def group_lag(self, _group):
        return {"_total": 0, "_members": 1, "_rows": 1}

    def ch(self, query, timeout=60):          # unused: Stack's shape
        if self.ch_raises is not None:
            raise self.ch_raises
        return True, "0"

    def ch_mutation(self, query):
        if self.ch_raises is not None:
            raise self.ch_raises
        self.ch_mutations.append(query)
        return True, ""

    def os_req(self, role_env, user, url_path, body=None, timeout=25):  # unused: Stack's shape
        self.os_paths.append(url_path)
        if "_delete_by_query" in url_path:
            return True, {"task": "task-9:1"}
        return True, {"_shards": {"failed": 0}}

    def os_count(self, index, field, prefix):  # unused: Stack's shape
        if self.os_counts:
            return self.os_counts.pop(0)
        return self.os_docs_left

    def mem_sample(self):
        return {}


@pytest.fixture(autouse=True)
def isolated_run_lock(tmp_path_factory, monkeypatch):
    """The run lock is a REAL file on the lab host and a live one gates a live
    run. No test may create, steal or delete it."""
    monkeypatch.setattr(
        ml, "RUN_LOCK_PATH",
        str(tmp_path_factory.mktemp("runlock") / ".lock"))


@pytest.fixture
def nosleep(monkeypatch):
    monkeypatch.setattr(ml.time, "sleep", lambda _s: None)


def _harness(tmp_path, stack, devices=10):
    args = ml.parse_args(["--devices", str(devices),
                          "--run-dir", str(tmp_path / "run"),
                          "--env-file", str(tmp_path / "missing.env"),
                          "--base-url", "http://stack.test"])
    h = ml.Harness(args)
    h.stack = stack
    h.owns_run_lock = True
    h.preflight_ok = True
    os.makedirs(h.run_dir, exist_ok=True)
    return h


def test_cleanup_step_records_a_final_failure_and_returns_the_default():
    problems: list[str] = []

    def boom():
        raise TimeoutError("timed out [gave up after 5 attempt(s)]")

    out = ml.cleanup_step("device purge", problems, boom, default="fallback")
    assert out == "fallback"
    assert len(problems) == 1
    assert "device purge" in problems[0] and "TimeoutError" in problems[0]


def test_cleanup_step_never_eats_an_operator_interrupt():
    for exc in (ml.CleanupAborted("SIGINT"), KeyboardInterrupt()):
        def boom(exc=exc):
            raise exc

        with pytest.raises(type(exc)):
            ml.cleanup_step("device purge", [], boom)


def test_cleanup_continues_past_a_failed_step_and_reverifies_the_residue(
        tmp_path, nosleep, capsys):
    """THE LIVE DEFECT, end to end. The device purge dies on a timeout after
    its retries; ClickHouse and OpenSearch must still be purged, the residue
    must be RE-VERIFIED against the stack, and the run must print the exact
    command that finishes the job."""
    stack = FakeStack([f"mlx-run-{i:05d}" for i in range(5)])
    stack.os_counts = [1_000, 0, 0]          # pre-count, drained, confirmed
    h = _harness(tmp_path, stack)

    def exhausted(*_a, **_kw):
        raise TimeoutError("timed out [GET /api/devices: gave up after 5 attempt(s)]")

    ml_purge = ml.purge_devices
    ml.purge_devices = exhausted
    try:
        ok = h.cleanup()
    finally:
        ml.purge_devices = ml_purge

    out = capsys.readouterr()
    assert ok is False, "a teardown that could not purge is a FAIL"
    assert any("_delete_by_query" in p for p in stack.os_paths), (
        "the OpenSearch step must still run after the device step died — that "
        "is the whole point (devices -> CH -> OS)")
    assert stack.ch_mutations, "and the ClickHouse step too"
    assert h.residue_devices == 5, (
        "the residue is what the stack SAYS at the end, re-verified — not the "
        "dead step's silence")
    assert "RESIDUE LEFT: 5 devices" in out.err
    assert "--cleanup-only mlx-" in out.err, (
        "the residue line must always carry the exact purge command")
    notes = h.phases[-1]["notes"]
    assert "device purge" in notes and "FAILED after its retries" in notes


def test_cleanup_reports_a_clickhouse_step_failure_but_still_purges_opensearch(
        tmp_path, nosleep):
    stack = FakeStack([f"mlx-run-{i:05d}" for i in range(3)])
    stack.os_counts = [1_000, 0, 0]
    stack.ch_raises = TimeoutError("timed out")
    h = _harness(tmp_path, stack)
    ok = h.cleanup()
    assert ok is False
    assert any("_delete_by_query" in p for p in stack.os_paths)
    assert h.residue_devices == 0, "the devices DID go — that must still be true"
    assert any("clickhouse" in p for p in h.phases[-1]["notes"].split(";"))


def test_cleanup_reverified_count_overrides_an_optimistic_step(
        tmp_path, nosleep, capsys):
    """A purge that reports success while devices remain must not be believed:
    the last word is a fresh list."""
    stack = FakeStack([f"mlx-run-{i:05d}" for i in range(4)])
    h = _harness(tmp_path, stack)
    ml_purge = ml.purge_devices
    ml.purge_devices = lambda *_a, **_kw: dict(
        ml.empty_purge_ev("mlx-run-", 1.0), verified_zero=True, remaining=0)
    try:
        ok = h.cleanup()
    finally:
        ml.purge_devices = ml_purge
    assert ok is False, "devices left standing is a FAILED teardown, whatever the step said"
    assert h.residue_devices == 4, "re-verification is what the run stands behind"
    assert "RESIDUE LEFT: 4 devices" in capsys.readouterr().err


def test_cleanup_reports_an_unreverifiable_residue_as_UNKNOWN(
        tmp_path, nosleep, capsys):
    stack = FakeStack([])
    h = _harness(tmp_path, stack)
    real = ml.devices_with_prefix
    calls = {"n": 0}

    def flaky(stack_, prefix, **kw):
        calls["n"] += 1
        if calls["n"] > 2:                       # the FINAL re-verify fails
            return [], "device list failed at offset 0: HTTP 0 transport: TimeoutError()"
        return real(stack_, prefix, **kw)

    ml.devices_with_prefix = flaky
    try:
        ok = h.cleanup()
    finally:
        ml.devices_with_prefix = real
    assert ok is False
    assert h.residue_devices == -1, "unverifiable must read UNKNOWN, never 0"
    assert "UNKNOWN, not zero" in "; ".join(h.phases[-1]["notes"].split(";"))


def test_cleanup_only_reverifies_and_names_the_command(tmp_path, monkeypatch,
                                                       nosleep, capsys):
    """`--cleanup-only` is the command the residue line tells the operator to
    run; it must survive a dead step the same way."""
    stack = FakeStack([f"mlx-run-{i:05d}" for i in range(2)])
    stack.os_counts = [1_000, 0, 0]
    monkeypatch.setattr(ml, "Stack", lambda *_a, **_kw: stack)
    monkeypatch.setattr(ml, "http_ingress_status", lambda _u: 200)
    monkeypatch.setattr(ml, "RUN_LOCK_PATH", str(tmp_path / ".lock"))

    def exhausted(*_a, **_kw):
        raise TimeoutError("timed out [gave up after 5 attempt(s)]")

    monkeypatch.setattr(ml, "purge_devices", exhausted)
    args = ml.parse_args(["--cleanup-only", "mlx-run-",
                          "--env-file", str(tmp_path / "missing.env"),
                          "--base-url", "http://stack.test"])
    rc = ml.cleanup_only(args)
    err = capsys.readouterr().err
    assert rc == 1
    assert "RESIDUE LEFT: 2 devices matching mlx-run-" in err
    assert "--cleanup-only mlx-run-" in err
    assert any("_delete_by_query" in p for p in stack.os_paths), (
        "the telemetry purge still ran after the device step died")


# ═══ 4. the OpenSearch purge budget re-estimates itself ═════════════════════


class DrainStack(FakeStack):
    """An index that drains at a fixed docs/s against the fake clock."""

    def __init__(self, docs: int, rate_per_s: float, clock):
        super().__init__([])
        self.docs = docs
        self.rate = rate_per_s
        self.clock = clock
        self.counts = 0

    def os_count(self, index, field, prefix):   # unused: Stack's shape
        self.counts += 1
        left = self.docs - self.rate * (self.clock.t - self.clock.start)
        return max(0, int(left))


class FakeClock:
    def __init__(self, start=1000.0):
        self.start = start
        self.t = start

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(ml.time, "monotonic", c.monotonic)
    monkeypatch.setattr(ml.time, "sleep", c.sleep)
    return c


def test_a_fast_drain_finishes_inside_the_original_budget(clock, capsys):
    """4,000 docs/s — twice the assumed rate. Nothing is extended."""
    stack = DrainStack(200_000, 4_000, clock)
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-")
    assert problems == []
    assert ev["os_docs_left"] == 0
    assert ev["os_purge_budget_extended"] is False
    assert ev["os_purge_seconds"] <= ev["os_purge_budget_initial_s"]


def test_MUTANT_a_fixed_budget_abandons_a_delete_that_is_working(clock, capsys):
    """THE LIVE NUMBERS (cleanup-only-08290543.log): 276,001 docs draining at
    ~1,000 docs/s against a budget of 60s + count/2000 = 198s. The old fixed
    budget expired with 81,001 docs left while the server-side task was still
    deleting. Measuring the rate is what makes this pass."""
    docs, rate = 276_001, 1_000.0
    fixed = ml.OS_PURGE_BUDGET_BASE_S + docs * ml.OS_PURGE_SECONDS_PER_DOC
    assert fixed == pytest.approx(198.0005), "the budget that failed live"
    assert docs / rate > fixed, (
        "the premise: at the OBSERVED rate the delete cannot finish inside the "
        "estimate — a fixed budget must abandon it")

    stack = DrainStack(docs, rate, clock)
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-")
    assert problems == [], f"a working delete must not be abandoned: {problems}"
    assert ev["os_docs_left"] == 0
    assert ev["os_purge_budget_extended"] is True
    assert ev["os_purge_budget_s"] > ev["os_purge_budget_initial_s"]
    assert ev["os_purge_seconds"] >= docs / rate
    out = capsys.readouterr().out
    assert "extending the budget" in out, "an invisible extension is a hang"
    assert "docs/s measured" in out, "and it must print the measured rate + ETA"


def test_the_extension_respects_the_hard_cap(clock, monkeypatch):
    """A glacial drain is still bounded — MLX_OS_PURGE_BUDGET_MAX_S is the wall."""
    monkeypatch.setattr(ml, "OS_PURGE_BUDGET_MAX_S", 600.0)
    stack = DrainStack(10_000_000, 100.0, clock)
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=60, poll_s=30)
    assert ev["os_purge_budget_s"] <= 600.0
    assert ev["os_purge_seconds"] <= 600.0 + 30, "one poll of overshoot at most"
    assert problems and "docs left" in problems[0]
    assert "hard cap" in problems[0], "say WHY it stopped"


def test_a_stall_fails_loudly_and_names_the_task(clock, capsys):
    """A count that stops decreasing is a stuck delete — call it out now
    instead of burning the rest of a three-hour budget on it."""
    stack = FakeStack([])
    stack.os_docs_left = 40_000
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=100_000,
                                      poll_s=30)
    assert ev["os_purge_stalled"] is True
    assert ev["os_purge_seconds"] < 200, (
        "the stall must end the wait in ~3 polls, not at the budget")
    assert len(problems) == 1
    assert "STALLED" in problems[0] and "task-9:1" in problems[0], problems
    assert "--cleanup-only mlx-run-" in problems[0]
    assert "STALLED" in capsys.readouterr().err


def test_a_recovering_drain_is_not_a_stall(clock):
    """Two flat polls then progress: delete_by_query's counts only move after a
    refresh interval, so one flat poll must never end the wait."""
    stack = FakeStack([])
    seq = [50_000, 50_000, 50_000, 20_000, 0, 0]
    stack.os_count = lambda *_a, **_kw: seq.pop(0) if seq else 0
    ev, problems = ml.os_purge_syslog(stack, "mlx-run-", budget_s=100_000,
                                      poll_s=30)
    assert ev["os_purge_stalled"] is False
    assert ev["os_docs_left"] == 0 and problems == []
