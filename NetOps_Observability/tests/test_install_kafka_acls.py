"""Installer-owned Kafka ACL application (SEC-007 P0, 2026-08-16).

The TLS variant boots the broker with StandardAuthorizer and
allow.everyone.if.no.acl.found=false, and the KRaft ACL store lives in
data/kafka — so a fresh install (or a data/kafka wipe) started ENFORCING WITH
ZERO ACLs: vector-router + correlation were authorization-dead for ~80 min
while every container reported "healthy" (found live by the G2 mini-ladder
preflight). kafka-init only creates topics; nothing applied
deployment/docker/kafka/apply-acls.sh.

These tests pin the fix — install.py owns authorization convergence:

  (a) TLS + embedded-bus: after phase B the installer execs the mounted
      /acls/apply-acls.sh inside the broker, then proves a real consumer
      group holds membership through the enforcing broker (§16.1: no blind
      success);
  (b) persistent apply/verify failure ⇒ the install FAILS loudly (exit 1) —
      never "success" over a dead bus;
  (c) transient failure right after the phase-B recreate is retried within a
      bounded window;
  (d) the plaintext baseline NEVER runs it (base compose configures no
      authorizer — kafka-acls would die with SecurityDisabledException and
      nothing would enforce the result);
  (e) external-broker installs (embedded-bus profile off) skip with an
      operator pointer (owner-managed broker);
  (f) re-running is idempotent at the installer layer (the script itself
      converges: kafka-acls --add of an existing ACL is a no-op);
  (g) the compose/script contract holds: compose.tls.yml mounts the script
      where install.py execs it, and the script carries its own read-back
      verification + TLS admin-plane auto-detection.

Everything runs with subprocess/time monkeypatched — no docker, no broker.

Run:  python3 -m pytest tests/test_install_kafka_acls.py -v
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install

ACL_SCRIPT_PATH = ROOT / "deployment" / "docker" / "kafka" / "apply-acls.sh"
COMPOSE_TLS = ROOT / "deployment" / "docker" / "compose.tls.yml"

APPLY_OK_STDERR = (
    "acls: matrix applied and verified — 58 ACL entries live\n"
    "acls: (enforce posture: allow.everyone.if.no.acl.found=false since SEC-007.2)\n"
)

# kafka-consumer-groups.sh --describe: a LIVE member has a real CONSUMER-ID …
MEMBERS_OUT = (
    "GROUP               TOPIC          PARTITION CURRENT-OFFSET LOG-END-OFFSET "
    "LAG CONSUMER-ID    HOST      CLIENT-ID\n"
    "netops-correlation  netops.syslog  0         12             12             "
    "0   aiokafka-1-abc /10.0.0.5 aiokafka-1\n"
)
# … while a DEAD consumer keeps committed offsets but shows `-` (the wiped-ACL
# incident signature: offsets frozen, zero members, all healthchecks green).
DEAD_GROUP_OUT = (
    "GROUP               TOPIC          PARTITION CURRENT-OFFSET LOG-END-OFFSET "
    "LAG CONSUMER-ID HOST CLIENT-ID\n"
    "netops-correlation  netops.syslog  0         12             99             "
    "87  -           -    -\n"
)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def compose_dir(tmp_path: Path) -> Path:
    d = tmp_path / "deployment" / "docker"
    d.mkdir(parents=True)
    return d


def write_env(compose_dir: Path, profiles: str) -> Path:
    env_path = compose_dir / ".env"
    env_path.write_text(f"COMPOSE_PROFILES={profiles}\n")
    return env_path


class FakeClock:
    """Deterministic time for the bounded-retry windows (no real sleeps)."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s


@pytest.fixture()
def clock(monkeypatch) -> FakeClock:
    c = FakeClock()
    monkeypatch.setattr(install.time, "time", c.time)
    monkeypatch.setattr(install.time, "sleep", c.sleep)
    return c


class BusRecorder:
    """Stands in for subprocess.run; scripts responses per invoked tool."""

    def __init__(self, apply_results=None, describe_results=None):
        # Lists of (returncode, stdout, stderr); the last entry repeats.
        self.apply_results = list(apply_results or [(0, "", APPLY_OK_STDERR)])
        self.describe_results = list(describe_results or [(0, MEMBERS_OUT, "")])
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []

    @staticmethod
    def _next(results):
        return results.pop(0) if len(results) > 1 else results[0]

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        self.kwargs.append(kwargs)
        if "/acls/apply-acls.sh" in cmd:
            rc, out, err = self._next(self.apply_results)
        elif any("kafka-consumer-groups.sh" in c for c in cmd):
            rc, out, err = self._next(self.describe_results)
        else:  # pragma: no cover — an unexpected tool is a test failure
            raise AssertionError(f"unexpected subprocess call: {cmd}")
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr=err)

    @property
    def apply_calls(self) -> list[list[str]]:
        return [c for c in self.calls if "/acls/apply-acls.sh" in c]

    @property
    def describe_calls(self) -> list[list[str]]:
        return [c for c in self.calls
                if any("kafka-consumer-groups.sh" in x for x in c)]


# ── (a) TLS + embedded-bus: apply at the right phase, right arguments ────────

def test_tls_embedded_bus_applies_matrix_then_verifies_membership(
        compose_dir, clock, monkeypatch):
    env_path = write_env(compose_dir, "embedded-bus,prober")
    bus = BusRecorder()
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    # One idempotent in-container exec of the mounted matrix script — argv is
    # a list (no shell), -T (no TTY: runs unattended), cwd is the compose dir.
    assert bus.apply_calls == [
        ["docker", "compose", "exec", "-T", "kafka", "/acls/apply-acls.sh"]]
    apply_idx = bus.calls.index(bus.apply_calls[0])
    assert bus.kwargs[apply_idx]["cwd"] == str(compose_dir)
    assert bus.kwargs[apply_idx].get("timeout")  # bounded (§16.2/§9)

    # Then the liveness read-back through the enforcing broker: super-user
    # admin plane on the mTLS listener, correlation's group.
    assert len(bus.describe_calls) == 1
    d = bus.describe_calls[0]
    assert "--bootstrap-server" in d and "kafka:9094" in d
    assert "--command-config" in d and "/tmp/kafka-tls/admin.properties" in d
    assert "--describe" in d and "netops-correlation" in d


def test_verification_never_skipped_on_apply_success(compose_dir, clock,
                                                     monkeypatch):
    """A zero-exit apply without the liveness read-back would be blind
    success — the exact defect shape (§16.1)."""
    env_path = write_env(compose_dir, "embedded-bus")
    bus = BusRecorder()
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    assert len(bus.describe_calls) >= 1


# ── (b) failure ⇒ loud install failure, never success over a dead bus ────────

def test_persistent_apply_failure_fails_the_install(compose_dir, clock,
                                                    monkeypatch, capsys):
    env_path = write_env(compose_dir, "embedded-bus")
    bus = BusRecorder(apply_results=[
        (1, "", "acls: FATAL: could not list ACLs back after applying")])
    monkeypatch.setattr(install.subprocess, "run", bus)

    with pytest.raises(SystemExit) as e:
        install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "auth" in err.lower() and "SEC-007" in err
    # The bus liveness probe never ran — the apply itself already failed.
    assert bus.describe_calls == []


def test_dead_consumer_group_fails_the_install(compose_dir, clock,
                                               monkeypatch, capsys):
    """Matrix applied but no consumer ever joins (offsets-without-members —
    the 2026-08-16 incident signature) ⇒ the install must refuse success."""
    env_path = write_env(compose_dir, "embedded-bus")
    bus = BusRecorder(describe_results=[(0, DEAD_GROUP_OUT, "")])
    monkeypatch.setattr(install.subprocess, "run", bus)

    with pytest.raises(SystemExit) as e:
        install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    assert e.value.code == 1
    assert "netops-correlation" in capsys.readouterr().err
    assert len(bus.describe_calls) >= 2       # bounded polling, not one shot


def test_apply_timeout_is_bounded_and_fails(compose_dir, clock, monkeypatch):
    """A wedged broker exec must not hang the installer forever (§9/§16.2)."""
    env_path = write_env(compose_dir, "embedded-bus")

    def wedged(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 600))

    monkeypatch.setattr(install.subprocess, "run", wedged)

    with pytest.raises(SystemExit) as e:
        install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)
    assert e.value.code == 1


# ── (c) transient failure right after the phase-B recreate is retried ────────

def test_transient_apply_failure_retries_then_succeeds(compose_dir, clock,
                                                       monkeypatch):
    env_path = write_env(compose_dir, "embedded-bus")
    bus = BusRecorder(apply_results=[
        (1, "", "Connection to node -1 (kafka/…:9094) could not be established"),
        (0, "", APPLY_OK_STDERR),
    ])
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    assert len(bus.apply_calls) == 2
    assert clock.slept, "retry must back off, not spin"


# ── (d) plaintext baseline: no authorizer ⇒ never invoked ────────────────────

def test_plaintext_install_never_touches_kafka_acls(compose_dir, clock,
                                                    monkeypatch):
    env_path = write_env(compose_dir, "embedded-bus,prober")
    bus = BusRecorder()
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=False)

    assert bus.calls == []


def test_base_compose_has_no_authorizer_so_skip_is_correct():
    """The (d) skip is only valid while the base broker really has no
    authorizer — if one ever appears there, the plaintext variant needs the
    matrix too and this pin must be revisited."""
    base = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    assert "KAFKA_AUTHORIZER_CLASS_NAME" not in base
    assert "KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND" not in base
    tls = COMPOSE_TLS.read_text()
    assert 'KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND: "false"' in tls


# ── (e) external broker: owner-managed, skip with pointer ────────────────────

def test_external_broker_skips_with_operator_pointer(compose_dir, clock,
                                                     monkeypatch, capsys):
    env_path = write_env(compose_dir, "prober")     # no embedded-bus
    bus = BusRecorder()
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    assert bus.calls == []
    assert "broker owner" in capsys.readouterr().out


# ── (f) idempotent re-run ────────────────────────────────────────────────────

def test_rerun_is_idempotent_same_invocation(compose_dir, clock, monkeypatch):
    env_path = write_env(compose_dir, "embedded-bus")
    bus = BusRecorder()
    monkeypatch.setattr(install.subprocess, "run", bus)

    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)
    install.apply_bus_authorization(compose_dir, env_path, tls_enabled=True)

    # Same converging exec both times; the script itself is the idempotency
    # mechanism (kafka-acls --add of an existing ACL is a no-op).
    assert len(bus.apply_calls) == 2
    assert bus.apply_calls[0] == bus.apply_calls[1]


# ── member-parse unit ────────────────────────────────────────────────────────

def test_group_member_parse_live_vs_dead():
    assert install._kafka_group_members(MEMBERS_OUT, "netops-correlation") == 1
    assert install._kafka_group_members(DEAD_GROUP_OUT, "netops-correlation") == 0
    assert install._kafka_group_members("", "netops-correlation") == 0
    # Another group's members must not count.
    assert install._kafka_group_members(MEMBERS_OUT, "netops-router-syslog") == 0


# ── (g) compose/script contract pins ─────────────────────────────────────────

def test_compose_tls_mounts_the_script_where_install_execs_it():
    tls = COMPOSE_TLS.read_text()
    assert "./kafka/apply-acls.sh:/acls/apply-acls.sh:ro" in tls, (
        "compose.tls.yml must mount apply-acls.sh at /acls/apply-acls.sh — "
        "install.py execs that path inside the broker")


def test_acl_script_carries_tls_admin_plane_and_readback_verification():
    src = ACL_SCRIPT_PATH.read_text()
    # TLS admin-plane auto-detection (9092 died at SEC-006.3): first-class
    # command-config support, no argument-injection through KAFKA_BOOTSTRAP.
    assert "KAFKA_COMMAND_CONFIG" in src
    assert "/tmp/kafka-tls/admin.properties" in src
    assert "kafka:9094" in src
    # §16.1 read-back: the script fails itself if the matrix did not take.
    assert "--list --topic netops.deadletter" in src
    assert "FATAL" in src
    # The old swallowed count (`--list 2>/dev/null | grep -c ... || true` as
    # the only signal) must not return.
    assert "--list 2>/dev/null" not in src


def test_nightly_workflow_interim_step_is_gone():
    wf = ROOT.parent / ".github" / "workflows" / "scale-miniladder-nightly.yml"
    if not wf.exists():                      # tests may run from a subtree copy
        pytest.skip("workflows not present in this checkout")
    text = wf.read_text()
    assert "install-path gap" not in text and "docker cp" not in text, (
        "the interim CI ACL step must stay deleted — CI has to prove the "
        "installer applies the matrix itself")
