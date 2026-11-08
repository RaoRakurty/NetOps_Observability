# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""overlap_rotation.py — zero-downtime rotation of the vmauth service
credentials (`install.py --rotate-secret`, tracker 367 layer 3).

WHY
---
`--rotate-app-secrets` swaps a vmauth credential in one step: vmauth and the
clients each pick the new value up on their own schedule (vmauth within 10 s,
the api/prober/vmalert within 1 s, grafana/gnmic/vector only on a restart),
and every request that lands in between is a 401. For the write-only lanes
(gnmic, vector, prober) a 401 is lost telemetry — evidence the correlation
engine never sees. This module removes that window.

HOW (vmauth holds BOTH passwords while the clients move)
--------------------------------------------------------
vmauth v1.101.0 accepts one username with several passwords as separate user
entries, told apart by `name` and `metric_labels` (verified on the pinned
image). So, per identity:

  1 preflight   vmauth running, its config loaded, .env complete, the current
                credential authenticates. A <KEY>_PREVIOUS already in .env
                means a rotation was interrupted: RESUME it.
  2 mint        new value; .env (atomic) gets <KEY>=new, <KEY>_PREVIOUS=old.
                .env is the durable state: written BEFORE any effect, so a
                crash anywhere after this is resumed, never guessed at.
  3 overlap     auth.yml re-rendered with TWO blocks (svc-x cred=current,
                svc-x-previous cred=previous), SIGHUP, reload PROVEN on
                vmauth's own metrics (both series present, last reload ok),
                then the NEW credential is proven to work and the OLD one to
                still work. Any failure here, on a fresh rotation, rolls back
                to the single old block — no client has been touched yet.
  4 swap        client password files re-rendered (atomic rename; the api,
                prober and vmalert re-read within 1 s); grafana, gnmic and
                vector — which read theirs only at start — are restarted.
  5 drain       vmauth_user_requests_total{cred="previous"} must stay flat for
                3x the slowest client interval. Still moving after 10 min ->
                stop non-zero (exit 4) with BOTH credentials valid: the safe
                state, resumable, and CredentialRotationIncomplete fires after
                an hour of it.
  6 finalize    single block rendered, SIGHUP, reload proven (previous series
                gone), the OLD credential proven to get 401 and the new one to
                work; only then is <KEY>_PREVIOUS removed from .env.
  7 audit       a summary of names, phases, timings and request counts —
                never a value.

Every external call goes through an injected runner's run(argv, stdin,
timeout) (CLAUDE.md §2/§11) and is bounded (§9). No secret is ever in argv:
curl reads its whole request — URL, credential, options — as a config file on
stdin (`curl -K -`), so nothing reaches the host's process table or a log
(§8). Stdlib only (§6). No side effects on import.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import NamedTuple

import secret_rotation as sr

# ---- outcomes ----------------------------------------------------------------

OK = 0
FAILED = 1            # broke (rolled back when nothing had moved yet)
REFUSED = 2           # nothing was changed
INCOMPLETE_SAFE = 4   # stopped with BOTH credentials valid; re-run to resume

PREVIOUS_SUFFIX = "_PREVIOUS"   # must equal install.PREVIOUS_SUFFIX

# ---- the identities ----------------------------------------------------------


class Identity(NamedTuple):
    alias: str                 # CLI name: vmauth-<alias>
    env_key: str               # .env key holding the current password
    username: str              # vmauth username (and `name` of its block)
    services: tuple[str, ...]  # compose services that present it
    rereads: bool              # client re-reads its file on use (no restart)
    probe: str                 # "read" (a query) | "write" (an empty import)
    interval_s: int            # slowest request interval of the client


IDENTITIES: tuple[Identity, ...] = (
    Identity("api", "VMAUTH_API_PASSWORD", "svc-api", ("api",), True, "read", 60),
    Identity("prober", "VMAUTH_PROBER_PASSWORD", "svc-prober", ("prober",), True, "write", 60),
    # interval from VMALERT_EVAL_INTERVAL at run time (default 30 s)
    Identity("vmalert", "VMAUTH_VMALERT_PASSWORD", "svc-vmalert", ("vmalert",), True, "read", 30),
    Identity("grafana", "VMAUTH_GRAFANA_PASSWORD", "svc-grafana", ("grafana",), False, "read", 60),
    Identity("gnmic", "VMAUTH_GNMIC_PASSWORD", "svc-gnmic", ("gnmic",), False, "write", 15),
    Identity("vector", "VMAUTH_VECTOR_PASSWORD", "svc-vector", ("vector-aggregator",), False, "write", 60),
)
BY_ALIAS = {i.alias: i for i in IDENTITIES}
BY_KEY = {i.env_key: i for i in IDENTITIES}

DRAIN_FACTOR = 3            # window = 3x the slowest client interval
DRAIN_FLOOR_S = 30
DRAIN_TIMEOUT_S = 600       # 10 min, then stop leaving both valid
RELOAD_TIMEOUT_S = 60
RELOAD_POLL_S = 2.0
DRAIN_POLL_S = 10.0

VMAUTH_SERVICE = "vmauth"
VMAUTH_HOST = "vmauth:8427"
# Same image the stack's opensearch-init runs (docker-compose.yml pins it by
# digest). Referenced by TAG with --pull=never: a docker-load'ed offline image
# carries no registry digest, and a rotation must never reach the network.
CURL_IMAGE = "curlimages/curl:8.10.1"
CA_REL = Path("data") / "tls" / "ca.pem"

READ_PATH = "/api/v1/query?query=1"
WRITE_PATH = "/api/v1/import/prometheus"   # empty body: authenticates, writes nothing


def parse_names(spec: str) -> tuple[list[Identity], list[str]]:
    """`vmauth-api,vmauth-grafana` | `vmauth-all` | env keys -> identities.
    Returns (identities, unknown_names)."""
    picked: list[Identity] = []
    unknown: list[str] = []
    for raw in (p.strip() for p in (spec or "").split(",")):
        if not raw:
            continue
        if raw == "vmauth-all":
            found: Iterable[Identity] = IDENTITIES
        elif raw.startswith("vmauth-") and raw[len("vmauth-"):] in BY_ALIAS:
            found = (BY_ALIAS[raw[len("vmauth-"):]],)
        elif raw in BY_KEY:
            found = (BY_KEY[raw],)
        else:
            unknown.append(raw)
            continue
        for i in found:
            if i not in picked:
                picked.append(i)
    return picked, unknown


def duration_s(text: str, default: int) -> int:
    """`30s`, `1m`, `1m30s`, `2h` -> seconds (default when unparseable)."""
    parts = re.findall(r"(\d+)(ms|s|m|h)", (text or "").strip())
    if not parts or "".join(n + u for n, u in parts) != (text or "").strip():
        return default
    mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}
    return max(1, int(sum(int(n) * mult[u] for n, u in parts)))


# ---- .env surgery -------------------------------------------------------------

_ENV_LINE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)=")


def edit_env(text: str, updates: Mapping[str, str], remove: Iterable[str] = ()) -> str:
    """Replace/insert/remove `KEY=` lines, leaving every other byte alone.

    A new <KEY>_PREVIOUS is inserted directly after its <KEY> line (so the
    pair reads together); any other new key is appended."""
    rm = set(remove)
    todo = dict(updates)
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body):] or "\n"
        m = _ENV_LINE.match(body)
        key = m.group(2) if m else None
        if key in rm:
            continue
        if key in todo:
            out.append(f"{m.group(1)}{key}={todo.pop(key)}{eol}")
        else:
            out.append(line if line.endswith("\n") else line + "\n")
        prev = f"{key}{PREVIOUS_SUFFIX}" if key else None
        if prev and prev in todo:
            out.append(f"{prev}={todo.pop(prev)}{eol}")
    out.extend(f"{k}={v}\n" for k, v in todo.items())
    return "".join(out)


def parse_env_text(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


# ---- Prometheus text exposition ---------------------------------------------

_SAMPLE = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(\{[^}]*\})?\s+(\S+)")
_LABEL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')


class Metrics(NamedTuple):
    samples: list[tuple[str, dict[str, str], float]]

    def value(self, name: str, **labels: str) -> float | None:
        for n, lb, v in self.samples:
            if n == name and all(lb.get(k) == val for k, val in labels.items()):
                return v
        return None

    def users(self) -> dict[str, str]:
        """username label -> cred label, from the per-user request counter
        (vmauth registers it for every configured user at load)."""
        return {lb.get("username", ""): lb.get("cred", "")
                for n, lb, _ in self.samples if n == "vmauth_user_requests_total"}


def parse_metrics(text: str) -> Metrics:
    out: list[tuple[str, dict[str, str], float]] = []
    for line in (text or "").splitlines():
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if not m:
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue    # a malformed sample is skipped, never guessed at
        out.append((m.group(1), dict(_LABEL.findall(m.group(2) or "")), v))
    return Metrics(out)


# ---- the stack adapter (argv construction lives here, nowhere else) ----------

class Stack:
    """Talks to the running stack through runner.run(argv, stdin, timeout).

    The ONLY place this module builds a command line, so the no-secret-in-
    argv rule is enforced in one spot: credentials travel exclusively inside
    the curl config written to stdin."""

    def __init__(self, runner, ca_path: Path) -> None:
        self.runner = runner
        self.ca_path = ca_path

    def _compose(self, args: list[str], timeout: int) -> sr.ExecResult:
        return self.runner.run(["docker", "compose", *args], "", timeout)

    def container_id(self, service: str) -> str:
        r = self._compose(["ps", "-q", "--status", "running", service], 30)
        if r.returncode != 0:
            return ""
        ids = [ln.strip() for ln in r.stdout.splitlines() if re.fullmatch(r"[0-9a-f]{12,64}", ln.strip())]
        return ids[0] if ids else ""

    def running(self, service: str) -> bool:
        return bool(self.container_id(service))

    def hup_vmauth(self) -> sr.ExecResult:
        return self._compose(["kill", "-s", "HUP", VMAUTH_SERVICE], 30)

    def restart(self, service: str) -> sr.ExecResult:
        return self._compose(["restart", "-t", "30", service], 180)

    def http(self, path: str, *, user: str = "", password: str = "",
             post: bool = False) -> tuple[int, str]:
        """One HTTPS request to vmauth, from a throwaway curl container sharing
        vmauth's network namespace (so no compose network name is assumed).
        Returns (status, body); status 0 = curl/docker failed."""
        cid = self.container_id(VMAUTH_SERVICE)
        if not cid:
            return 0, "vmauth is not running"
        cfg = [
            "silent",
            "show-error",
            "connect-timeout = 5",
            "max-time = 15",
            'cacert = "/run/ca.pem"',
            f'resolve = "{VMAUTH_HOST}:127.0.0.1"',
            f'url = "{_curl_quote("https://" + VMAUTH_HOST + path)}"',
            'write-out = "\\n%{http_code}"',
        ]
        if user:
            cfg.append(f'user = "{_curl_quote(user + ":" + password)}"')
        if post:
            cfg += ['request = "POST"', 'header = "Content-Type: text/plain"',
                    'data-binary = ""']
        argv = ["docker", "run", "--rm", "-i", "--pull=never",
                "--network", f"container:{cid}",
                "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--memory", "64m",
                "-v", f"{self.ca_path}:/run/ca.pem:ro",
                CURL_IMAGE, "-K", "-"]
        r = self.runner.run(argv, "\n".join(cfg) + "\n", 60)
        body, _, code = (r.stdout or "").rpartition("\n")
        if r.returncode != 0 or not code.strip().isdigit():
            return 0, sr.redact(r.stderr or r.stdout, [password])
        return int(code.strip()), body

    def metrics(self) -> Metrics | None:
        status, body = self.http("/metrics")
        return parse_metrics(body) if status == 200 else None

    def probe(self, ident: Identity, password: str) -> int:
        if ident.probe == "write":
            return self.http(WRITE_PATH, user=ident.username, password=password, post=True)[0]
        return self.http(READ_PATH, user=ident.username, password=password)[0]


def _curl_quote(value: str) -> str:
    """curl config double-quoted string: escape backslash and quote."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _ok(status: int) -> bool:
    return 200 <= status < 300


# ---- the injected I/O --------------------------------------------------------

class Io(NamedTuple):
    read_env: Callable[[], str]
    write_env: Callable[[str, str], None]            # (text, what)
    render: Callable[[Mapping[str, str], bool], None]  # (env, vmauth_only)
    log: Callable[[str, str], None]                  # (level, message)
    mint: Callable[[], str]


class Outcome(NamedTuple):
    code: int
    message: str


class Run:
    """One --rotate-secret invocation. Holds the selection, the state read
    from .env, and the audit trail (names and numbers only)."""

    def __init__(self, idents: list[Identity], stack: Stack, io: Io, *,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.idents = idents
        self.stack = stack
        self.io = io
        self.clock = clock
        self.sleep = sleep
        self.audit: list[str] = []
        self.fresh: list[Identity] = []     # minted by THIS run
        self.resumed: list[Identity] = []   # had <KEY>_PREVIOUS already

    # -- small helpers -------------------------------------------------------
    def say(self, level: str, msg: str) -> None:
        self.io.log(level, msg)

    def note(self, msg: str) -> None:
        self.audit.append(msg)

    def env(self) -> dict[str, str]:
        return parse_env_text(self.io.read_env())

    def names(self, idents: Iterable[Identity] | None = None) -> str:
        return ", ".join(f"vmauth-{i.alias}" for i in (self.idents if idents is None else idents))

    def interval(self, ident: Identity, env: Mapping[str, str]) -> int:
        if ident.alias == "vmalert":
            return duration_s(env.get("VMALERT_EVAL_INTERVAL", ""), ident.interval_s)
        return ident.interval_s

    # -- phase 1 -------------------------------------------------------------
    def preflight(self, *, dry_run: bool) -> Outcome | None:
        env = self.env()
        missing = [i.env_key for i in self.idents if not env.get(i.env_key)]
        if missing:
            return Outcome(REFUSED, ".env lacks " + ", ".join(missing)
                           + " — run python3 scripts/install.py first (nothing was changed)")
        stray = sorted(k[:-len(PREVIOUS_SUFFIX)] for k in env
                       if k.endswith(PREVIOUS_SUFFIX) and k[:-len(PREVIOUS_SUFFIX)] in BY_KEY
                       and k[:-len(PREVIOUS_SUFFIX)] not in {i.env_key for i in self.idents})
        if stray:
            return Outcome(REFUSED, "a rotation of "
                           + ", ".join(f"vmauth-{BY_KEY[k].alias}" for k in stray)
                           + " is still in progress — resume it first (include it in "
                           "--rotate-secret, or use vmauth-all). Nothing was changed.")
        for i in self.idents:
            prev = env.get(i.env_key + PREVIOUS_SUFFIX)
            if prev is None:
                continue
            if not prev or prev == env[i.env_key]:
                return Outcome(REFUSED, f"{i.env_key}{PREVIOUS_SUFFIX} in .env is empty or equals "
                               f"{i.env_key} — the interrupted rotation cannot be resumed "
                               "safely; restore .env from its .env.snapshot copy. "
                               "Nothing was changed.")
            self.resumed.append(i)
        if not self.stack.running(VMAUTH_SERVICE):
            return Outcome(REFUSED, "vmauth is not running — a zero-downtime rotation needs "
                           "the live stack (cd deployment/docker && docker compose up -d "
                           "vmauth). Nothing was changed.")
        m = self.stack.metrics()
        if m is None:
            return Outcome(REFUSED, "cannot read vmauth's /metrics — the reload and drain "
                           "proofs would be blind. Nothing was changed.")
        if m.value("vmauth_config_last_reload_successful") != 1:
            return Outcome(REFUSED, "vmauth reports its LAST config reload failed — it is "
                           "serving an older auth.yml than data/secrets holds. Fix that "
                           "first (docker compose logs vmauth). Nothing was changed.")
        for i in self.idents:
            if i in self.resumed:
                continue
            if not _ok(self.stack.probe(i, env[i.env_key])):
                return Outcome(REFUSED, f"vmauth does not accept the CURRENT {i.env_key} — "
                               ".env and the running vmauth already disagree; rotating on "
                               "top of that would hide the cause. Nothing was changed.")
        fresh = [i for i in self.idents if i not in self.resumed]
        plan = []
        if fresh:
            plan.append("rotate " + self.names(fresh))
        if self.resumed:
            plan.append("resume " + self.names(self.resumed))
        restarts = sorted({s for i in self.idents if not i.rereads for s in i.services
                           if self.stack.running(s)})
        plan.append("restart " + (", ".join(restarts) or "(none)"))
        plan.append(f"drain window {self.drain_window(env)} s (cap {DRAIN_TIMEOUT_S} s)")
        self.say("info", "plan: " + "; ".join(plan))
        if dry_run:
            return Outcome(OK, "dry run — nothing was changed")
        return None

    def drain_window(self, env: Mapping[str, str]) -> int:
        return max(DRAIN_FLOOR_S, DRAIN_FACTOR * max(self.interval(i, env) for i in self.idents))

    # -- phase 2 -------------------------------------------------------------
    def mint(self) -> None:
        env = self.env()
        updates: dict[str, str] = {}
        for i in self.idents:
            if i in self.resumed:
                continue
            new = self.io.mint()
            for _ in range(3):
                if new != env[i.env_key]:
                    break
                new = self.io.mint()
            updates[i.env_key] = new
            updates[i.env_key + PREVIOUS_SUFFIX] = env[i.env_key]
            self.fresh.append(i)
        if updates:
            self.io.write_env(edit_env(self.io.read_env(), updates),
                              "record the rotation (new + previous credential)")
            self.say("ok", f"minted new credentials for {self.names(self.fresh)} "
                     "(.env holds both until the rotation completes)")
            self.note(f"minted: {self.names(self.fresh)}")
        if self.resumed:
            self.note(f"resumed: {self.names(self.resumed)}")

    # -- reload proof ---------------------------------------------------------
    def reload_and_prove(self, expect_previous: bool) -> str:
        """SIGHUP vmauth and wait until its metrics show the expected user set.
        Returns "" on success, else the reason."""
        r = self.stack.hup_vmauth()
        if r.returncode != 0:
            return "could not signal vmauth: " + sr.redact(r.stderr or r.stdout, [])
        deadline = self.clock() + RELOAD_TIMEOUT_S
        why = "no metrics read"
        while True:
            m = self.stack.metrics()
            if m is not None:
                users = m.users()
                ok_flag = m.value("vmauth_config_last_reload_successful") == 1
                bad = [i.username for i in self.idents
                       if users.get(i.username) != "current"
                       or ((i.username + "-previous") in users) != expect_previous
                       or (expect_previous and users.get(i.username + "-previous") != "previous")]
                if ok_flag and not bad:
                    return ""
                why = ("vmauth rejected the new config (last reload failed)" if not ok_flag
                       else "vmauth has not loaded the expected users for " + ", ".join(bad))
            if self.clock() >= deadline:
                return f"{why} after {RELOAD_TIMEOUT_S} s"
            self.sleep(RELOAD_POLL_S)

    # -- phase 3 -------------------------------------------------------------
    def overlap(self) -> Outcome | None:
        env = self.env()
        self.io.render(env, True)
        why = self.reload_and_prove(expect_previous=True)
        if not why:
            for i in self.idents:
                s_new = self.stack.probe(i, env[i.env_key])
                if not _ok(s_new):
                    why = f"the NEW credential of vmauth-{i.alias} is refused (HTTP {s_new})"
                    break
                s_old = self.stack.probe(i, env[i.env_key + PREVIOUS_SUFFIX])
                if not _ok(s_old):
                    why = f"the OLD credential of vmauth-{i.alias} stopped working during the overlap (HTTP {s_old})"
                    break
        if not why:
            self.say("ok", f"vmauth reloaded with both credentials for {self.names()}; "
                     "new and old both proven to authenticate")
            self.note("overlap: reload proven, new + old authenticate")
            return None
        if not self.fresh or self.resumed:
            # A resumed rotation may already have moved clients onto the new
            # credential: rolling back could cut them off. Stop, keep state.
            return Outcome(FAILED, f"overlap failed: {why}. .env still records the rotation "
                           "and no client file was changed by this run; fix vmauth and re-run "
                           "--rotate-secret to resume.")
        return self.rollback(why)

    def rollback(self, why: str) -> Outcome:
        updates = {i.env_key: self.env()[i.env_key + PREVIOUS_SUFFIX] for i in self.fresh}
        remove = [i.env_key + PREVIOUS_SUFFIX for i in self.fresh]
        self.io.write_env(edit_env(self.io.read_env(), updates, remove),
                          "roll back the rotation")
        self.io.render(self.env(), True)
        back = self.reload_and_prove(expect_previous=False)
        self.note(f"rolled back: {self.names(self.fresh)}")
        if back:
            return Outcome(FAILED, f"overlap failed: {why}. .env and auth.yml were rolled back "
                           f"to the old credential, but proving vmauth reloaded failed too "
                           f"({back}) — check `docker compose logs vmauth`. No client file was "
                           "changed, so clients still present the old (valid) credential.")
        return Outcome(FAILED, f"overlap failed: {why}. Rolled back: .env and auth.yml hold the "
                       "old credential again and vmauth reloaded it; no client was touched.")

    # -- phase 4 -------------------------------------------------------------
    def swap(self) -> Outcome | None:
        self.io.render(self.env(), False)
        self.say("ok", "client credential files now hold the new values "
                 "(api, prober and vmalert re-read them within 1 s)")
        restarted: list[str] = []
        for i in self.idents:
            if i.rereads:
                continue
            for svc in i.services:
                if not self.stack.running(svc):
                    self.say("info", f"{svc} is not running — nothing to restart (it reads "
                             "the new file when it next starts)")
                    continue
                r = self.stack.restart(svc)
                if r.returncode != 0 or not self.stack.running(svc):
                    return Outcome(INCOMPLETE_SAFE, f"restarting {svc} failed ("
                                   + sr.redact(r.stderr or r.stdout, []) + "). BOTH credentials "
                                   "are still valid; fix it and re-run --rotate-secret to resume.")
                restarted.append(svc)
        if restarted:
            self.say("ok", "restarted (they read their credential only at start): "
                     + ", ".join(restarted))
        self.note("restarted: " + (", ".join(restarted) or "(none)"))
        return None

    # -- phase 5 -------------------------------------------------------------
    def drain(self) -> Outcome | None:
        env = self.env()
        window = self.drain_window(env)
        start = self.clock()
        deadline = start + DRAIN_TIMEOUT_S

        def sample() -> dict[str, tuple[float | None, float | None]] | None:
            m = self.stack.metrics()
            if m is None:
                return None
            return {i.username: (
                m.value("vmauth_user_requests_total", username=i.username + "-previous", cred="previous"),
                m.value("vmauth_user_requests_total", username=i.username, cred="current"))
                for i in self.idents}

        last = sample()
        quiet_since = self.clock()
        cur_moved = {i.username: 0.0 for i in self.idents}
        prev_moved = {i.username: 0.0 for i in self.idents}
        self.say("info", f"drain: waiting for previous-credential traffic to stay flat for "
                 f"{window} s (cap {DRAIN_TIMEOUT_S} s)")
        while True:
            now = self.clock()
            if last is not None and now - quiet_since >= window:
                break
            if now >= deadline:
                busy = [u for u in prev_moved if prev_moved[u] > 0] or [i.username for i in self.idents]
                self.note(f"drain: TIMED OUT after {int(now - start)} s; still on previous: {', '.join(busy)}")
                return Outcome(INCOMPLETE_SAFE,
                               f"previous-credential traffic did not stop within {DRAIN_TIMEOUT_S} s "
                               f"(still presented by: {', '.join(busy)}). BOTH credentials remain "
                               "valid — nothing is broken. Find the client still holding the old "
                               "value, fix or restart it, then re-run --rotate-secret to resume. "
                               "CredentialRotationIncomplete fires if this stands for an hour.")
            self.sleep(min(DRAIN_POLL_S, max(1.0, window / 3)))
            cur = sample()
            if cur is None or last is None:
                last, quiet_since = cur, self.clock()     # blind: restart the window
                continue
            for u, (p, c) in cur.items():
                lp, lc = last[u]
                if p is None or lp is None or p < lp:      # series gone or counter reset
                    quiet_since = self.clock()
                elif p > lp:
                    prev_moved[u] += p - lp
                    quiet_since = self.clock()
                if c is not None and lc is not None and c >= lc:
                    cur_moved[u] += c - lc
            last = cur
        for i in self.idents:
            if cur_moved[i.username] == 0:
                self.say("warn", f"vmauth-{i.alias}: no request with the NEW credential during "
                         "the drain — the client may be idle or down; the old credential is "
                         "revoked regardless (it presented none either)")
        took = int(self.clock() - start)
        self.say("ok", f"drain proven: no previous-credential request for {window} s ({took} s total)")
        self.note(f"drain: {took} s; requests on new credential: "
                  + ", ".join(f"{u}+{int(v)}" for u, v in cur_moved.items()))
        return None

    # -- phase 6 -------------------------------------------------------------
    def finalize(self) -> Outcome | None:
        env = self.env()
        olds = {i.alias: env[i.env_key + PREVIOUS_SUFFIX] for i in self.idents}
        view = {k: v for k, v in env.items()
                if k not in {i.env_key + PREVIOUS_SUFFIX for i in self.idents}}
        self.io.render(view, True)
        why = self.reload_and_prove(expect_previous=False)
        if not why:
            for i in self.idents:
                s_old = self.stack.probe(i, olds[i.alias])
                if s_old != 401:
                    why = f"the OLD credential of vmauth-{i.alias} still gets HTTP {s_old}, not 401"
                    break
                s_new = self.stack.probe(i, env[i.env_key])
                if not _ok(s_new):
                    why = f"the NEW credential of vmauth-{i.alias} is refused after finalize (HTTP {s_new})"
                    break
        if why:
            # Put auth.yml back in line with .env (both credentials valid).
            self.io.render(env, True)
            back = self.reload_and_prove(expect_previous=True)
            extra = "" if not back else f" (re-establishing the overlap also failed: {back})"
            return Outcome(INCOMPLETE_SAFE if not back else FAILED,
                           f"finalize failed: {why}{extra}. .env still records the rotation; "
                           "re-run --rotate-secret to resume.")
        self.io.write_env(edit_env(self.io.read_env(), {},
                                   [i.env_key + PREVIOUS_SUFFIX for i in self.idents]),
                          "complete the rotation (drop the previous credential)")
        self.say("ok", f"old credentials revoked for {self.names()}: vmauth answers 401 to them")
        self.note("finalize: reload proven, old -> 401, new authenticates, .env committed")
        return None

    # -- driver --------------------------------------------------------------
    def execute(self, *, dry_run: bool) -> Outcome:
        out = self.preflight(dry_run=dry_run)
        if out is not None:
            return out
        self.mint()
        for phase in (self.overlap, self.swap, self.drain, self.finalize):
            out = phase()
            if out is not None:
                return out
        return Outcome(OK, f"zero-downtime rotation complete: {self.names()}")


def rotate(spec: str, *, runner, io: Io, ca_path: Path, dry_run: bool = False,
           clock: Callable[[], float] = time.monotonic,
           sleep: Callable[[float], None] = time.sleep) -> tuple[Outcome, list[str]]:
    """Entry point for install.py --rotate-secret. Returns (outcome, audit)."""
    idents, unknown = parse_names(spec)
    if unknown or not idents:
        others = [n for n in unknown if n in sr.POLICY]
        hint = (f" {', '.join(others)} cannot be overlapped — use "
                "python3 scripts/install.py --rotate-app-secrets for it." if others else "")
        return Outcome(REFUSED, "--rotate-secret takes "
                       + ", ".join(f"vmauth-{i.alias}" for i in IDENTITIES)
                       + " or vmauth-all (comma-separated); unknown: "
                       + (", ".join(unknown) or "(empty)") + "." + hint), []
    run = Run(idents, Stack(runner, ca_path), io, clock=clock, sleep=sleep)
    out = run.execute(dry_run=dry_run)
    return out, run.audit


__all__ = [
    "FAILED",
    "IDENTITIES",
    "INCOMPLETE_SAFE",
    "OK",
    "REFUSED",
    "Identity",
    "Io",
    "Metrics",
    "Outcome",
    "Stack",
    "duration_s",
    "edit_env",
    "parse_metrics",
    "parse_names",
    "rotate",
]
