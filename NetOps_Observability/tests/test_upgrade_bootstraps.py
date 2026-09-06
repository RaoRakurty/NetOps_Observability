# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Upgrade-path bootstraps — the two defects found on the lab, 2026-09-03.

An UPGRADE that adds an ingest lane touches four files that are applied by four
DIFFERENT mechanisms, and nothing checked that all four had actually landed:

  1. vector-router gets a sink            (container config, applied on `up`)
  2. index-templates.json gets a template (scripts/bootstrap-opensearch.sh)
  3. apply-ism.sh gets a retention pattern(the opensearch-init one-shot)
  4. **roles.yml gets an index pattern**  (the opensearch-security-init one-shot)

DEFECT 1 — the security findings lane shipped with (1)(2)(3) and NOT (4).
`netops-secfindings-*` was absent from `netops_writer`, so every bulk write from
svc_router was rejected with `no permissions for [indices:admin/create]`, Vector
classified the 403 as NON-RETRIABLE and DROPPED the batch. No index, no consumer
lag, no red healthcheck — the CTEM funnel was simply empty. This is the same
shape as the 2026-08-16 "auth-dead lane" Kafka-ACL incident, one tier down.
The guards below therefore assert the PROPERTY, not the one instance: every
index pattern vector-router sinks to must be writable by svc_router, and every
pattern the api reads must be readable by svc_api — so the NEXT lane cannot ship
unwritable either.

DEFECT 2 — scripts/bootstrap-opensearch.sh was blind on TLS installs. It curled
`http://localhost:9200` from inside the opensearch container; with the security
plugin on, 9200 speaks https and every template PUT came back "was NOT applied"
(all nine, observed). The script now detects the variant from COMPOSE_FILE in
deployment/docker/.env exactly as scripts/stack-watchdog.sh does, speaks
https://opensearch:9200 (the ONLY name in the issued SAN set — never localhost,
never -k) with the svc_bootstrap credential install.py already used, and fails
loud. The transport tests below EXECUTE the script against a fake `docker` on
PATH and inspect the argv it would have used — no network, no cluster.

Run:  python3 -m pytest tests/test_upgrade_bootstraps.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "deployment" / "docker"
ROUTER = COMPOSE_DIR / "vector-router" / "vector.yaml"
AGGREGATOR = COMPOSE_DIR / "vector" / "vector.yaml"
ROLES = COMPOSE_DIR / "opensearch" / "security" / "roles.yml"
ROLES_MAPPING = COMPOSE_DIR / "opensearch" / "security" / "roles_mapping.yml"
TEMPLATES = COMPOSE_DIR / "opensearch" / "index-templates.json"
SCRIPT = ROOT / "scripts" / "bootstrap-opensearch.sh"
DEPLOY_QUALIFY = ROOT / "scripts" / "deploy-qualify.sh"
OSLOG = ROOT / "src" / "backend" / "internal" / "oslog" / "oslog.go"
QUARANTINE = ROOT / "src" / "backend" / "internal" / "quarantine" / "quarantine.go"


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _roles() -> dict:
    return _yaml(ROLES)


def _role_index_patterns(role: str, required_action: str) -> set[str]:
    """Every index pattern `role` holds `required_action` on.

    `crud`/`indices_all`/`write` are OpenSearch action GROUPS; the members that
    matter here are spelled out so a role that grants `crud` (which contains
    write) is not reported as missing write.
    """
    contains = {
        "write": {"write", "crud", "indices_all", "indices:data/write/index",
                  "indices:data/write/bulk"},
        "create_index": {"create_index", "indices_all",
                         "indices:admin/create"},
        "read": {"read", "search", "crud", "indices_all",
                 "indices:data/read/search"},
    }[required_action]
    out: set[str] = set()
    for block in _roles()[role].get("index_permissions", []):
        if contains & set(block.get("allowed_actions", [])):
            out.update(block.get("index_patterns", []))
    return out


def _covers(patterns: set[str], wanted: str) -> bool:
    """Does any granted pattern match the concrete lane pattern `wanted`?

    Only the trailing `*` wildcard OpenSearch actually uses here is honoured —
    a role saying `netops-*` covers `netops-secfindings-*`.
    """
    for p in patterns:
        if p == wanted:
            return True
        if p.endswith("*") and wanted.startswith(p[:-1]):
            return True
    return False


# ── the lanes vector-router actually writes ────────────────────────────────


def _log_index_bases() -> set[str]:
    """`log_index_base` is a per-message value chosen by the AGGREGATOR; the
    router only defaults it. Read both files so a new base cannot be added in
    one and missed here."""
    bases = set(re.findall(r'\.log_index_base\s*=\s*"([a-z0-9_]+)"',
                           AGGREGATOR.read_text() + ROUTER.read_text()))
    assert bases, "no .log_index_base assignment found — the derivation below is stale"
    return bases


def router_sink_patterns() -> set[str]:
    """Every OpenSearch index pattern the router sinks to, normalised to the
    `netops-<lane>-*` form a role grants on."""
    cfg = _yaml(ROUTER)
    bases = _log_index_bases()
    patterns: set[str] = set()
    for name, sink in cfg["sinks"].items():
        if sink.get("type") != "elasticsearch":
            continue
        index = sink["bulk"]["index"]
        assert index.startswith("netops-"), \
            f"sink {name} writes to {index!r}, which is outside the netops-* namespace"
        seg = index.split("-")[1]
        var = re.fullmatch(r"\{\{\s*([a-z_]+)\s*\}\}", seg)
        if var is None:
            patterns.add(f"netops-{seg}-*")
        elif var.group(1) == "log_index_base":
            patterns.update(f"netops-{b}-*" for b in bases)
        else:
            pytest.fail(f"sink {name}: unhandled index variable {var.group(1)!r} in {index!r}")
    assert patterns, "no elasticsearch sinks found in the router config"
    return patterns


def test_every_router_sink_lane_is_writable_by_svc_router():
    """THE regression guard for defect 1. A lane the router sinks to that
    netops_writer does not name is write-dead the moment the security plugin is
    on: the bulk 403s on indices:admin/create and Vector drops the batch."""
    writable = _role_index_patterns("netops_writer", "write")
    creatable = _role_index_patterns("netops_writer", "create_index")
    for lane in sorted(router_sink_patterns()):
        assert _covers(writable, lane), \
            f"{lane} is written by vector-router but netops_writer holds no write on it"
        assert _covers(creatable, lane), \
            (f"{lane} is written by vector-router but netops_writer cannot CREATE it — "
             "the daily index PUT 403s on indices:admin/create and the batch is dropped")


def test_the_findings_lane_specifically_is_writable():
    """The instance that bit us, pinned by name so the diff that removes it is
    unmistakable."""
    assert "netops-secfindings-*" in router_sink_patterns()
    assert _covers(_role_index_patterns("netops_writer", "create_index"),
                   "netops-secfindings-*")


def test_router_sink_lanes_carry_a_mapping_template():
    """A writable lane with no declared template is 100% dynamically mapped —
    the F-06/F-15/F-53 defect that left snmptrap permanently yellow."""
    declared: set[str] = set()
    for tpl in json.loads(TEMPLATES.read_text())["templates"].values():
        declared.update(tpl["index_patterns"])
    for lane in sorted(router_sink_patterns()):
        assert lane in declared, \
            f"{lane} has no index template in index-templates.json (it would be dynamically mapped)"


def test_the_writer_role_is_the_router_identity():
    """The coverage assertions above are only meaningful if svc_router is still
    the user mapped to netops_writer."""
    assert _yaml(ROLES_MAPPING)["netops_writer"]["users"] == ["svc_router"]


# ── the lanes the api actually reads ───────────────────────────────────────


def api_read_patterns() -> set[str]:
    """Every index pattern the api can resolve a read to.

    Derived from the ONE chokepoint that builds them (internal/oslog.IndexBase —
    every read path funnels through TenantIndexPattern) plus the quarantine
    prefix the pipeline-processor surface reads directly.
    """
    bases = set(re.findall(r'return "(netops-[a-z]+)"', OSLOG.read_text()))
    bases.discard("netops")  # IndexBase's default for an unknown signal
    assert bases, "no index bases found in oslog.go — the derivation is stale"
    prefix = re.search(r'quarantineIndexPrefix\s*=\s*"(netops-[a-z]+-)"',
                       QUARANTINE.read_text())
    assert prefix, "quarantineIndexPrefix not found — the derivation is stale"
    return {b + "-*" for b in bases} | {prefix.group(1) + "*"}


def test_every_pattern_the_api_reads_is_readable_by_svc_api():
    """The read half of defect 1: the api serves the findings surface, so a
    role that stops covering netops-secfindings-* turns the CTEM UI into an
    empty-but-green screen."""
    readable = _role_index_patterns("netops_api", "read")
    for lane in sorted(api_read_patterns()):
        assert _covers(readable, lane), \
            f"the api reads {lane} but netops_api holds no read on it"


def test_the_api_reads_the_findings_lane():
    assert "netops-secfindings-*" in api_read_patterns()


def test_the_api_role_is_the_api_identity():
    assert _yaml(ROLES_MAPPING)["netops_api"]["users"] == ["svc_api"]


# ── defect 2: the bootstrap script's transport ─────────────────────────────


def test_script_parses_and_is_shellcheck_clean():
    assert subprocess.run(["bash", "-n", str(SCRIPT)],
                          capture_output=True, text=True).returncode == 0
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck not installed")
    r = subprocess.run(["shellcheck", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_tls_is_detected_from_compose_file_like_the_watchdog():
    """One detection rule across the repo: the COMPOSE_FILE line install.py
    writes into deployment/docker/.env. Two different rules is how a stack ends
    up half-configured."""
    script = SCRIPT.read_text()
    watchdog = (ROOT / "scripts" / "stack-watchdog.sh").read_text()
    probe = r"'\^COMPOSE_FILE=\.\*compose\\\.tls\\\.yml'"
    assert re.search(probe, script), "bootstrap-opensearch.sh no longer detects TLS from COMPOSE_FILE"
    assert re.search(probe, watchdog), "the watchdog's detection changed — keep the two in step"


def test_the_tls_host_is_never_localhost_and_never_insecure():
    """The issued SAN set is DNS:opensearch + a SPIFFE URI. `localhost` fails
    hostname verification, and `-k` would turn a real MITM into a silent pass."""
    script = SCRIPT.read_text()
    assert "https://opensearch:9200" in script
    assert not re.search(r"https://localhost", script)
    body = "\n".join(l for l in script.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"(?<![\w-])(-k|--insecure)(?![\w-])", body), \
        "bootstrap-opensearch.sh must never disable certificate verification"


# ---- executed: the argv the script would really use -----------------------

_FAKE_DOCKER = """#!/usr/bin/env bash
# Records argv, then answers whatever the script asked for.
{
  printf '%s\\n' "----"
  for a in "$@"; do printf '%s\\n' "$a"; done
} >> "$ARGV_LOG"
for a in "$@"; do
  case "$a" in
    */_cluster/health) exit 0 ;;
    */_index_template/*) printf '{"acknowledged":true}\\n'; exit 0 ;;
  esac
done
exit 0
"""


def _fake_repo(tmp_path: Path, env_lines: str) -> tuple[Path, Path]:
    """A minimal repo layout the script can run against, plus a fake `docker`."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, repo / "scripts" / SCRIPT.name)
    osdir = repo / "deployment" / "docker" / "opensearch"
    osdir.mkdir(parents=True)
    (repo / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    (repo / "deployment" / "docker" / ".env").write_text(env_lines)
    (osdir / "index-templates.json").write_text(json.dumps(
        {"templates": {"netops-secfindings": {
            "_comment": "stripped before the PUT",
            "index_patterns": ["netops-secfindings-*"],
            "template": {"settings": {"number_of_replicas": "${OPENSEARCH_REPLICAS}"}},
        }}}))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    fake.write_text(_FAKE_DOCKER)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    return repo, bindir


def _run(repo: Path, bindir: Path, tmp_path: Path, args: list[str] | None = None):
    argv_log = tmp_path / "argv.log"
    env = {**os.environ,
           "PATH": f"{bindir}:{os.environ['PATH']}",
           "ARGV_LOG": str(argv_log),
           # Keep the readiness wait out of the suite's wall clock; the
           # production default (30 x 2s) is asserted separately below.
           "OS_READY_ATTEMPTS": "2", "OS_READY_SLEEP": "0"}
    env.pop("OPENSEARCH_URL", None)
    r = subprocess.run(["bash", str(repo / "scripts" / SCRIPT.name)] + (args or []),
                       capture_output=True, text=True, env=env, timeout=120)
    return r, (argv_log.read_text() if argv_log.exists() else "")


TLS_ENV = ("COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n"
           "OS_BOOTSTRAP_PASSWORD=s3cr3t-not-a-real-password\n")
PLAIN_ENV = "COMPOSE_FILE=docker-compose.yml\n"


def test_tls_install_puts_over_https_with_the_cacert_and_svc_bootstrap(tmp_path):
    repo, bindir = _fake_repo(tmp_path, TLS_ENV)
    r, argv = _run(repo, bindir, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "https://opensearch:9200/_index_template/netops-secfindings" in argv
    assert "http://localhost:9200" not in argv
    # Credential forwarded by NAME through the container's environment...
    assert "--env\nOS_BOOTSTRAP_PASSWORD\n" in argv
    # ...and expanded inside the container, never on the host's argv (§8).
    assert "s3cr3t-not-a-real-password" not in argv
    assert "s3cr3t-not-a-real-password" not in (r.stdout + r.stderr)
    assert 'svc_bootstrap:$OS_BOOTSTRAP_PASSWORD' in argv
    assert "/usr/share/opensearch/config/tls/ca.pem" in argv
    assert "APPLIED  (1): netops-secfindings" in r.stdout


def test_plaintext_install_keeps_the_localhost_path(tmp_path):
    repo, bindir = _fake_repo(tmp_path, PLAIN_ENV)
    r, argv = _run(repo, bindir, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "http://localhost:9200/_index_template/netops-secfindings" in argv
    assert "https://" not in argv
    assert "--cacert" not in argv


def test_tls_install_without_the_credential_fails_loud_and_applies_nothing(tmp_path):
    """§16.1: the alternative is a 401 on every template and a run that looks
    like it tried."""
    repo, bindir = _fake_repo(tmp_path, "COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n")
    r, argv = _run(repo, bindir, tmp_path)
    assert r.returncode != 0
    assert "OS_BOOTSTRAP_PASSWORD" in r.stderr
    assert "_index_template" not in argv, "a template was PUT despite the fatal precondition"


def test_a_plaintext_opensearch_url_is_refused_on_a_tls_install(tmp_path):
    """update.sh used to force OPENSEARCH_URL=http://localhost:9200, which is
    exactly how the blind run happened."""
    repo, bindir = _fake_repo(tmp_path, TLS_ENV)
    argv_log = tmp_path / "argv.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "ARGV_LOG": str(argv_log), "OPENSEARCH_URL": "http://localhost:9200",
           "OS_READY_ATTEMPTS": "2", "OS_READY_SLEEP": "0"}
    r = subprocess.run(["bash", str(repo / "scripts" / SCRIPT.name)],
                       capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "plaintext but this stack runs the TLS variant" in r.stderr
    assert "https://opensearch:9200/_index_template/netops-secfindings" in argv_log.read_text()


def test_the_readiness_wait_is_bounded_by_construction():
    """§9: attempts x sleep, defaulted in the script so an operator gets the
    full production wait and the test harness does not."""
    script = SCRIPT.read_text()
    assert 'READY_ATTEMPTS="${OS_READY_ATTEMPTS:-30}"' in script
    assert 'READY_SLEEP="${OS_READY_SLEEP:-2}"' in script


def test_an_unreachable_cluster_is_fatal_not_a_silent_zero_template_run(tmp_path):
    repo, bindir = _fake_repo(tmp_path, PLAIN_ENV)
    (bindir / "docker").write_text("#!/usr/bin/env bash\nexit 7\n")
    (bindir / "docker").chmod(0o755)
    r, _ = _run(repo, bindir, tmp_path)
    assert r.returncode != 0
    assert "NO templates were applied" in r.stderr


def test_verify_mode_writes_nothing(tmp_path):
    repo, bindir = _fake_repo(tmp_path, PLAIN_ENV)
    # --verify reads the REAL router/roles files, so point the copy at them.
    for rel in ("vector-router/vector.yaml", "vector/vector.yaml",
                "opensearch/security/roles.yml"):
        dst = repo / "deployment" / "docker" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(COMPOSE_DIR / rel, dst)
    r, argv = _run(repo, bindir, tmp_path, ["--verify"])
    assert "-X\nPUT\n" not in argv, "--verify must not write to the cluster"
    assert "UNCOVERED" not in r.stdout, r.stdout


# ── one owner: nobody else PUTs an index template ──────────────────────────


def test_install_and_update_delegate_template_application_to_the_script():
    """The copies drifted once (install.py learned the TLS path, the script did
    not) and that drift IS defect 2. Keep one owner."""
    install = (ROOT / "scripts" / "install.py").read_text()
    update = (ROOT / "scripts" / "update.sh").read_text()
    assert "bootstrap-opensearch.sh" in install and "bootstrap-opensearch.sh" in update
    assert "_index_template/" not in install, \
        "install.py PUTs index templates again — bootstrap-opensearch.sh is the one owner"
    assert "_index_template/" not in update, \
        "update.sh PUTs index templates again — bootstrap-opensearch.sh is the one owner"
    # apply-ism.sh keeps exactly ONE template of its own, documented as such:
    # the settings-only security-auditlog one, deliberately not a log lane.
    ism = (COMPOSE_DIR / "opensearch" / "apply-ism.sh").read_text()
    assert re.findall(r"_index_template/([A-Za-z0-9._-]+)", ism) == ["security-auditlog"]


def test_deploy_qualify_b4_audits_lane_writability_read_only():
    """The gate that would have caught defect 1 on the deploy that shipped it."""
    gate = DEPLOY_QUALIFY.read_text()
    assert "B4 router lanes writable" in gate
    assert "bootstrap-opensearch.sh" in gate and "--verify" in gate
    # Bounded like B1/B2 — an unbounded check in a deploy gate is the hang it
    # is supposed to catch.
    assert re.search(r'b4_out="\$\(bound "\$b4_bound"', gate), \
        "B4 is not wall-clock bounded"
    assert 'record FAIL REQUIRED "B4 router lanes writable" "TIMED OUT' in gate
