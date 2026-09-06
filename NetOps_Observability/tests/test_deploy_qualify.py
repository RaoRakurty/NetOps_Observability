# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Static guards for scripts/deploy-qualify.sh — the post-deploy gate.

WHY THIS EXISTS. On 2026-09-03 the gate appeared to HANG a real deploy at
"running B2 (kafka-init topics)"; it was killed after ~15 minutes. Three
separate defects combined, and each one is pinned below because each is the
kind that comes back:

  1. **The bound did not bind.** `timeout N cmd` sends SIGTERM only. The
     `docker compose` CLI traps SIGTERM to run its own graceful shutdown, so a
     600s "timeout" never fired. `timeout -k` escalates to SIGKILL.
  2. **`docker compose run` leaks.** It creates a SECOND, differently-named
     container (`<project>-<service>-run-<hash>`) which KEEPS RUNNING when the
     CLI is killed. One was found alive on the box afterwards.
  3. **The check was the run.** kafka-init starts a JVM twice per topic over 20
     topics (~5s each on this stack = 200s+ minimum) to discover that every
     topic already existed. The gate now READS the topic list first and re-runs
     the one-shot only when something is missing.

Plus the anti-drift guard that makes (3) safe: the script keeps its own copy of
the canonical topic list, and a topic added to compose but missed here would
make B2 report a green "all topics present" while a lane is unbootstrapped.

These are STATIC checks over the committed files — no docker, no running stack
— in the spirit of tests/test_watchdog_transitions.py.

Run:  python3 -m pytest tests/test_deploy_qualify.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deploy-qualify.sh"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
COMPOSE_TLS = ROOT / "deployment" / "docker" / "compose.tls.yml"

TOPIC_RE = re.compile(r"\bnetops\.[A-Za-z0-9_.]+")


def _compose_yaml(text: str) -> dict:
    """Compose merge tags (!override, !reset) are not plain YAML."""

    class _Loader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _Loader.add_constructor("!override", _passthrough)
    _Loader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_Loader)


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _script_topics() -> set[str]:
    m = re.search(r"^CANONICAL_TOPICS=\(\n(.*?)^\)$", _script(), re.S | re.M)
    assert m, "CANONICAL_TOPICS array not found in deploy-qualify.sh"
    return set(TOPIC_RE.findall(m.group(1)))


def _entrypoint_topics(path: Path) -> set[str]:
    svc = _compose_yaml(path.read_text(encoding="utf-8"))["services"]["kafka-init"]
    ep = svc.get("entrypoint")
    assert ep, f"{path.name}: kafka-init has no entrypoint"
    body = " ".join(str(x) for x in ep) if isinstance(ep, list) else str(ep)
    # The `for t in <topics>; do` list is the authority.
    m = re.search(r"for\s+t\s+in\s+(.*?);\s*do", body, re.S)
    assert m, f"{path.name}: could not find kafka-init's topic loop"
    return set(TOPIC_RE.findall(m.group(1)))


def test_script_topic_list_matches_compose() -> None:
    """The gate's copy of the canonical topics must equal kafka-init's.

    A topic in compose but missing here => B2 reports "all topics present"
    while that lane was never created, and producers to it fail loud at
    runtime instead (broker auto-create is OFF by design).
    """
    script = _script_topics()
    base = _entrypoint_topics(COMPOSE)
    assert script == base, (
        "deploy-qualify.sh CANONICAL_TOPICS has drifted from kafka-init's "
        f"entrypoint list.\n  only in script: {sorted(script - base)}\n"
        f"  only in compose: {sorted(base - script)}")


def test_tls_override_restates_the_same_topics() -> None:
    """compose.tls.yml REPLACES the entrypoint, so it restates the list."""
    base, tls = _entrypoint_topics(COMPOSE), _entrypoint_topics(COMPOSE_TLS)
    assert base == tls, (
        "the TLS kafka-init entrypoint creates a different topic set than the "
        f"base one.\n  only in base: {sorted(base - tls)}\n"
        f"  only in tls: {sorted(tls - base)}")


def test_timeout_escalates_to_sigkill() -> None:
    """Defect 1: a bound that only SIGTERMs is advisory, not binding."""
    m = re.search(r"^\s*bound\(\)\s*\{\s*timeout([^;}]*)", _script(), re.M)
    assert m, "bound() no longer wraps `timeout` — re-check how calls are bounded"
    assert "-k" in m.group(1), (
        "bound() calls `timeout` without -k. The docker compose CLI traps "
        "SIGTERM, so the bound will not fire — this is exactly the 2026-09-03 "
        f"hang. Got: timeout{m.group(1)!r}")


def test_oneshots_do_not_use_compose_run() -> None:
    """Defect 2: `compose run` orphans a container when the CLI is killed."""
    code = re.sub(r"^\s*#.*$", "", _script(), flags=re.M)   # strip comments
    # Only real INVOCATIONS count. Diagnostic strings legitimately mention the
    # banned construct (the orphan sweep names what it is cleaning up), so skip
    # lines that merely print text.
    offenders = []
    for ln in code.splitlines():
        stripped = ln.strip()
        if re.match(r"(warn|say|record|printf|echo)\b", stripped):
            continue
        if re.search(r"\brun\s+--rm\b", stripped) or re.search(
                r"(^|[|&;(]|\$\()\s*(docker\s+compose|dc)\b[^\"']*\brun\b", stripped):
            offenders.append(stripped)
    assert not offenders, (
        "a one-shot is invoked with `docker compose run`, which creates a "
        "second container that survives the CLI being killed (orphan found on "
        f"the box 2026-09-03). Use `up -d --no-deps --force-recreate` + "
        f"`docker wait`. Offending line(s): {offenders}")


def test_b2_verifies_the_topic_list_not_just_the_exit_code() -> None:
    """Defect 3's safety net: the verdict must come from observed state."""
    code = _script()
    assert "kafka_missing_topics" in code, (
        "B2 no longer reads the topic list — 'the bootstrap exited 0' is the "
        "same unfounded confidence as 'docker compose up exited 0', which is "
        "the premise this whole gate exists to reject.")
    assert "--list" in code, "no kafka-topics --list call remains in the script"


def test_a_global_deadline_exists_and_is_enforced() -> None:
    """The whole script must be bounded, not merely each call inside it."""
    code = _script()
    for token in ("GLOBAL_DEADLINE", "remaining()", "clamp()", "have_time()"):
        assert token in code, f"global-deadline machinery missing: {token}"
    assert "deadline_skip" in code, (
        "running out of time must record a REQUIRED skip (exit 2), never fall "
        "through as a pass")


def test_orphan_sweep_is_loud() -> None:
    """A silent cleanup would erase the evidence that a run was killed."""
    m = re.search(r"kafka_sweep_orphans\(\)\s*\{(.*?)\n\}", _script(), re.S)
    assert m, "kafka_sweep_orphans() not found"
    assert "warn " in m.group(1), (
        "the orphan sweep removes containers without saying so — §16.1: a "
        "degraded/abnormal condition must be reported, not tidied away")


def test_b1_is_check_first_like_b2() -> None:
    """B1 must not re-apply an idempotent matrix just to discover it is applied.

    Lowering the phase bound to 240s exposed this: apply-acls.sh issues 13
    `kafka-acls.sh --add` calls plus two read-backs, each a JVM start against
    the mTLS listener (~5-6s measured), so an unconditional re-apply blew the
    bound and reported FAIL on a stack whose matrix was already correct and
    verified. Same lesson as B2: read the state, and treat applying as the
    REMEDY rather than as the check.
    """
    code = _script()
    assert "kafka_acl_applied" in code, (
        "B1 no longer reads the ACL store before re-applying the matrix")
    # It must judge by the applier's own criteria, not a weaker proxy.
    m = re.search(r"kafka_acl_applied\(\)\s*\{(.*?)\n\}", code, re.S)
    assert m, "kafka_acl_applied() body not found"
    body = m.group(1)
    assert "KAFKA_ACL_FLOOR" in body and "vector-router" in body, (
        "the 'already applied?' read must assert BOTH the entry-count floor and "
        "the load-bearing vector-router grant — a high count with no router "
        "grant is a PARTIAL matrix, which is an auth-dead bus (2026-08-16).")


def test_each_bootstrap_bound_is_clamped_to_the_global_budget() -> None:
    """A phase may be given less time than it asks for; never more."""
    code = _script()
    for want in ('clamp "$ACL_TIMEOUT"', 'clamp "$BOOTSTRAP_TIMEOUT"',
                 'clamp "$DOCKER_TIMEOUT"'):
        assert want in code, (
            f"a bound is used unclamped ({want} missing) — the sum of the "
            "phases could then outrun the global deadline")
