#!/usr/bin/env python3
"""NetOps Observability — installer.

What this script does (and what it does NOT do):

* Verifies Docker and the `docker compose` (v2) plugin are present.
* Validates the project scaffold (src/, deployment/docker/) is intact.
* Generates a `.env` next to docker-compose.yml with cryptographically
  random secrets — DB password, JWT secret, encryption key, Grafana admin
  password — using Python's `secrets` module. No shell substitution.
* Creates the persistent data/ directories the compose stack expects.
* Builds images and starts the stack with `docker compose up -d --build`.
* Prints the URL the user should open.

It does NOT regenerate source code. The scaffold under src/ is the source
of truth — edit it in place rather than re-running this installer.

SECRET ROTATION (audit FUNC-HIGH-1). `--reset-env` is not a blanket "write new
random values" — that bricked running installs, because most of these secrets
are validated by a store that only read them once, on the first boot of an
empty volume. Every generated secret is classified in scripts/secret_rotation.py
and `--reset-env` either genuinely rotates it (reconciling the live store and
verifying the new credential) or REFUSES before writing anything. See
docs/runbooks/secret-rotation.md.

Usage:
    python3 install.py [--port 8000] [--no-start] [--reset-env]
    python3 install.py --rotate-app-secrets       # rotate what is safe to rotate
    python3 install.py --reset-env --rotate-kafka-cluster-id   # destructive
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Compose profiles a default install activates (written to .env as
# COMPOSE_PROFILES — the single source of truth; see compose_up). --core
# bundles install with --profiles "embedded-bus,prober" (no OSD image in the
# bundle); external-broker installs drop embedded-bus.
# "sso" (Keycloak) is DEFAULT-ON (owner decision 2026-08-04: enterprise SSO is
# a first-class capability, configured entirely from the admin GUI) — it can
# still be dropped from COMPOSE_PROFILES for footprint-constrained installs.
DEFAULT_PROFILES = "embedded-bus,prober,osd,self-monitoring,sso"

# ---- styling ----------------------------------------------------------------

def info(msg: str) -> None:    print(f"[info ] {msg}")
def ok(msg: str) -> None:      print(f"[ ok  ] {msg}")
def warn(msg: str) -> None:    print(f"[warn ] {msg}", file=sys.stderr)
def fail(msg: str) -> "None":  print(f"[fail ] {msg}", file=sys.stderr); sys.exit(1)
def step(msg: str) -> None:    print(); print(f"=== {msg} ===")

# ---- secret generation ------------------------------------------------------

# Use only URL-safe / shell-safe characters so values can sit unquoted in
# .env without parser surprises. `secrets.token_urlsafe` is the right tool
# for the high-entropy values; the admin password uses a smaller alphabet
# to keep it pasteable.

_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#%^&*-_=+"

def generate_password(length: int = 24) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))

# Credentials that ride URL userinfo (https://user:pw@host — the SEC-010
# vmauth family today) must NOT contain @ # % ^ & + =: Go's url.Parse rejects
# a stray %, # truncates as a fragment, and @ shifts the authority split.
# 2026-08-07: found as a latent fresh-install landmine — generate_password's
# alphabet gives each minted credential a ~2% chance of breaking its client
# at startup. URL-embedded credentials use this alphabet instead.
_URLSAFE_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "-_"

def generate_urlsafe_password(length: int = 24) -> str:
    return "".join(secrets.choice(_URLSAFE_PASSWORD_ALPHABET) for _ in range(length))

def _git_sha(root: Path) -> str:
    """HEAD of the checkout, or "unknown".

    "unknown" is the honest answer for a source bundle with no .git, and the
    drift check treats it as a FAILURE rather than a pass — an unidentifiable
    artifact is exactly the condition build provenance exists to end.
    """
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root),
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def generate_token(bytes_: int = 32) -> str:
    return secrets.token_urlsafe(bytes_)

# ---- prerequisite checks ----------------------------------------------------

def check_docker() -> None:
    if shutil.which("docker") is None:
        _maybe_bootstrap_ubuntu("docker is not installed.")
        # If the bootstrap ran, we still exit afterwards — the user must
        # re-login for the docker group to take effect. _maybe_bootstrap
        # never returns normally on a missing Docker.
        fail("docker is not installed. See https://docs.docker.com/get-docker/")

    res = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        _maybe_bootstrap_ubuntu("Docker Compose v2 plugin is not available.")
        fail(
            "Docker Compose v2 plugin is not available. The legacy "
            "`docker-compose` binary is not supported by this installer. "
            "Install the Compose plugin: "
            "https://docs.docker.com/compose/install/"
        )
    ok(f"docker compose: {res.stdout.strip()}")


# ---- host bootstrap (Ubuntu / Debian) ---------------------------------------

def _is_debian_family() -> bool:
    """True if the host is Ubuntu, Debian, or a derivative."""
    osr = Path("/etc/os-release")
    if not osr.exists():
        return False
    try:
        text = osr.read_text()
    except OSError:
        return False
    return (
        "ID=ubuntu" in text
        or "ID=debian" in text
        or "ID_LIKE=debian" in text
        or 'ID_LIKE="debian"' in text
    )


def _maybe_bootstrap_ubuntu(reason: str) -> None:
    """Offer to run scripts/bootstrap-ubuntu.sh when Docker is missing on
    a Debian-family host. Exits the installer afterwards either way —
    the user has to log out + back in for the docker group to take
    effect before re-running install.py."""
    if not _is_debian_family():
        return  # caller will fall through to the generic fail() message
    here = Path(__file__).resolve().parent
    script = here / "bootstrap-ubuntu.sh"
    if not script.exists():
        return

    print()
    warn(reason)
    print(f"\n  This is an Ubuntu/Debian host, and {script.name} can install everything")
    print( "  the stack needs (Docker Engine, Compose v2, OpenSearch sysctl, docker group).")
    print( "  You'll be prompted for your sudo password.")
    print()
    try:
        ans = input("  Install Docker now? [y/N] ").strip().lower()
    except EOFError:
        ans = "n"
    if ans not in ("y", "yes"):
        fail("aborted. Install Docker manually, then re-run install.py.")

    info(f"running: sudo bash {script} --yes")
    res = subprocess.run(["sudo", "bash", str(script), "--yes"])
    if res.returncode != 0:
        fail(f"bootstrap-ubuntu.sh failed (exit {res.returncode}).")

    print()
    print("==============================================================")
    print("  Docker is installed. Two more things to do:")
    print("    1. Log out and back in   (so docker group membership applies)")
    print("       — or run:  newgrp docker")
    print("    2. Re-run: python3 scripts/install.py")
    print("==============================================================")
    sys.exit(0)

# ---- scaffold validation ----------------------------------------------------

REQUIRED_PATHS = [
    # Go backend
    "src/backend/main.go",
    "src/backend/logs.go",
    "src/backend/flows.go",
    "src/backend/copilot.go",
    "src/backend/graphql.go",
    "src/backend/auth.go",
    # The auth tier moved into packages (P2 decomposition); anchor the moved
    # files, plus the /cmd entrypoint the image builds from (P2 W5).
    "src/backend/internal/token/jwt.go",
    "src/backend/internal/token/password.go",
    "src/backend/internal/users/store.go",
    "src/backend/cmd/api/main.go",
    "src/backend/events.go",
    "src/backend/dashboard.go",
    # Ops scripts
    "scripts/update.sh",
    "scripts/reset-admin.sh",
    "src/backend/go.mod",
    # Scripts
    "scripts/bootstrap-ubuntu.sh",
    # Frontend
    "src/frontend/package.json",
    "src/frontend/src/App.tsx",
    "src/frontend/src/pages/Login.tsx",
    "src/frontend/src/hooks/useAuth.ts",
    "src/frontend/src/tabs/Logs.tsx",
    "src/frontend/src/tabs/Flows.tsx",
    # Topology.tsx/Copilot.tsx no longer exist (renamed to the canvas pages /
    # Opsis in old refactors); their stale entries broke the FIRST real bundle
    # install (2026-07-04) because only install.py runs this validator. It now
    # also runs in CI via preflight-install.py so the list can't rot again.
    "src/frontend/src/features/topology/renderers/react-flow/TopologyCanvas.tsx",
    "src/frontend/src/tabs/Opsis.tsx",
    "src/frontend/src/tabs/Findings.tsx",
    # Correlation/AI service
    "src/correlation/main.py",
    "src/correlation/requirements.txt",
    # Config templates
    "src/config/config.yaml",
    "src/config/rules.yaml",
    "src/config/devices.yaml",
    "src/config/vmscrape.yml",
    # Deployment
    "deployment/docker/docker-compose.yml",
    "deployment/docker/Dockerfile.backend",
    "deployment/docker/Dockerfile.frontend",
    "deployment/docker/Dockerfile.correlation",
    "deployment/docker/nginx/default.conf",
    "deployment/docker/vector/vector.yaml",
    "deployment/docker/vector-router/vector.yaml",
    "deployment/docker/goflow2/goflow2.yaml",
    "deployment/docker/syslog-ng/syslog-ng.conf",
    "deployment/docker/telegraf/telegraf.conf",
    "deployment/docker/clickhouse/init.sql",
    "deployment/docker/opensearch/index-templates.json",
    "deployment/docker/grafana/provisioning/datasources/datasources.yaml",
]

def validate_scaffold(root: Path) -> None:
    missing = [p for p in REQUIRED_PATHS if not (root / p).exists()]
    if missing:
        for m in missing:
            warn(f"missing: {m}")
        fail("scaffold is incomplete — refusing to install. See warnings above.")
    ok(f"scaffold ok ({len(REQUIRED_PATHS)} required paths present)")

# ---- resource plan (#102) ---------------------------------------------------

def run_resource_plan(env_path: Path, profile: str, sizing_file: "Path | None") -> None:
    """Compute + splice the managed resource block. Sole sizing entry point."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import resource_planner as rp

    doc = {}
    if sizing_file:
        doc = rp.parse_sizing_file(sizing_file.read_text())
    if profile == "auto":
        profile = doc.get("profile") or None
    host = rp.detect_host(data_path=str(env_path.parent))
    if profile is None:
        gib = host["memory_bytes"] / (1 << 30)
        profile = ("demo" if gib < 24 else "small" if gib < 48 else
                   "medium" if gib < 96 else "large")
        info(f"auto-selected profile '{profile}' for {gib:.0f} GiB host")
    env_text = env_path.read_text() if env_path.exists() else ""
    legacy = rp.read_env_overrides(env_text)
    workload = rp.normalize_workload(doc) if doc else {}
    try:
        plan = rp.compute_plan(host, profile, workload, doc.get("overrides", {}), legacy)
    except rp.SizingError as e:
        fail(f"resource plan refused:\n{e}")
        return
    # Canonical backup map (shared with --rollback-plan) — covers .env AND the
    # generated plan artifacts, so rollback restores everything managed.
    for src, bak in rp.plan_backup_paths(env_path).items():
        if os.path.exists(src):
            Path(bak).write_text(Path(src).read_text())
            os.chmod(bak, 0o600)
    env_path.write_text(rp.splice_env(env_text, rp.env_block(plan)))
    env_path.chmod(0o600)
    for name, text in (("resource-plan.json",
                        json.dumps(plan, indent=2, sort_keys=True) + "\n"),
                       ("resource-plan.txt", rp.plan_txt(plan))):
        (env_path.parent / name).write_text(text)
    for w in plan["warnings"]:
        warn(w)
    ok(f"resource plan written (profile {plan['profile']}) — "
       f"{env_path.parent / 'resource-plan.txt'}")


# ---- .env generation --------------------------------------------------------

def generate_secrets() -> dict[str, str]:
    """Every secret a fresh install mints.

    Each key MUST also carry a rotation classification in
    scripts/secret_rotation.py:POLICY — tests/test_secret_rotation.py fails the
    build otherwise. An unclassified store credential is precisely how
    `--reset-env` came to hand out passwords no store had ever been told about
    (audit FUNC-HIGH-1).
    """
    return {
        # URL-safe: the documented DATABASE_URL shape embeds it in userinfo
        # (postgres://netops:pw@postgres:5432/...) — see _URLSAFE alphabet note.
        "DB_PASSWORD":              generate_urlsafe_password(28),
        "JWT_SECRET":               generate_token(48),
        "ENCRYPTION_KEY":           generate_token(32),
        "GRAFANA_ADMIN_PASSWORD":   generate_password(20),
        "CLICKHOUSE_PASSWORD":      generate_password(24),
        "GRAFANA_CH_PASSWORD":      generate_password(24),
        "ADMIN_INITIAL_PASSWORD":   generate_password(16),
        "KEYCLOAK_ADMIN_PASSWORD":  generate_password(20),
        # Bundled (internal) NetBox source-of-truth.
        "NETBOX_SECRET_KEY":         generate_token(40),    # >=50 url-safe chars
        "NETBOX_DB_PASSWORD":        generate_urlsafe_password(24),  # rides a DB URL like DB_PASSWORD
        "NETBOX_SUPERUSER_PASSWORD": generate_password(20),
        "NETBOX_TOKEN":              secrets.token_hex(20),  # 40-hex NetBox API token
        # F-08 ingest credential shared by every in-stack telemetry producer.
        "INGEST_TOKEN":              generate_token(32),
        # SEC-010: per-service credentials for the vmauth metrics front
        # (profile `vmauth`; src/config/vmauth.yml expands them via %{ENV}).
        # URL-safe: every consumer embeds them in URL userinfo
        # (VICTORIA_URL=https://svc-*:pw@vmauth:8427).
        "VMAUTH_API_PASSWORD":       generate_urlsafe_password(24),
        "VMAUTH_GNMIC_PASSWORD":     generate_urlsafe_password(24),
        "VMAUTH_VECTOR_PASSWORD":    generate_urlsafe_password(24),
        "VMAUTH_VMALERT_PASSWORD":   generate_urlsafe_password(24),
        "VMAUTH_GRAFANA_PASSWORD":   generate_urlsafe_password(24),
        "VMAUTH_PROBER_PASSWORD":    generate_urlsafe_password(24),
        # SEC-012: Valkey (RCA evidence store) authentication.
        "REDIS_PASSWORD":            generate_password(24),
        # SEC-008: per-identity OpenSearch credentials (security plugin).
        # URL-safe: several ride OPENSEARCH_URL userinfo in the TLS variant
        # (https://svc_x:pw@opensearch:9200); the whole family is minted
        # URL-safe so no future consumer trips the userinfo landmine.
        "OS_API_PASSWORD":           generate_urlsafe_password(24),
        "OS_ROUTER_PASSWORD":        generate_urlsafe_password(24),
        "OS_CORRELATION_PASSWORD":   generate_urlsafe_password(24),
        "OS_BOOTSTRAP_PASSWORD":     generate_urlsafe_password(24),
        "OS_DASHBOARDS_PASSWORD":    generate_urlsafe_password(24),
        "OS_AGGREGATOR_PASSWORD":    generate_urlsafe_password(24),
        # SEC-013.1 (narrowed): per-lane ingest tokens — the ONLY credentials
        # the four Vector lanes accept; the shared INGEST_TOKEN opens no lane.
        # The .env migration below seeds them into pre-epic installs.
        "INGEST_TOKEN_TRAPS":        generate_password(32),
        "INGEST_TOKEN_PROBES":       generate_password(32),
        "INGEST_TOKEN_METRICS":      generate_password(32),
        "INGEST_TOKEN_BUS":          generate_password(32),
        # KRaft storage id for the embedded Kafka broker (22-char base64url
        # uuid, same format kafka-storage random-uuid emits). Generated ONCE
        # per install: the data dir is formatted with it, and a changed id
        # would make the broker refuse its own volume on recreation.
        "KAFKA_CLUSTER_ID":          base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="),
    }


def write_env(env_path: Path, port: int, *, force: bool,
              profiles: str = DEFAULT_PROFILES,
              broker_urls: str | None = None,
              retention_profile: str = "production",
              preserve: dict[str, str] | None = None) -> dict[str, str]:
    if env_path.exists() and not force:
        info(f".env already exists at {env_path} — keeping existing secrets")
        env = _parse_env(env_path)
        # Migration (Redpanda→Kafka, #97): a pre-Kafka .env lacks the bus vars
        # the compose file now requires. Append them idempotently so rerunning
        # the installer upgrades an existing install instead of failing on
        # ${KAFKA_CLUSTER_ID:?}.
        additions: list[str] = []
        if "BROKER_URLS" not in env:
            additions.append("BROKER_URLS=kafka:9092")
        if "KAFKA_CLUSTER_ID" not in env:
            additions.append("KAFKA_CLUSTER_ID="
                             + base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="))
        if "COMPOSE_PROFILES" not in env:
            additions.append(f"COMPOSE_PROFILES={profiles}")
        if "CORRELIX_UID" not in env:
            additions.append(f"CORRELIX_UID={os.getuid()}")
            additions.append(f"CORRELIX_GID={os.getgid()}")
        # Migration (#101): pre-retention .env gets the correlation retention
        # profile so upgraded installs get bounded correlation history too.
        if "CORR_RETENTION_PROFILE" not in env:
            additions.append(f"CORR_RETENTION_PROFILE={retention_profile}")
        if "CORR_CHAOS_FIXTURES" not in env:
            additions.append("CORR_CHAOS_FIXTURES=")
        # Migration (F-08): a pre-auth .env has no ingest credential, and
        # vector-aggregator now refuses to start without one (${INGEST_TOKEN:?}).
        # Seed it here so an upgrade converges instead of taking the whole
        # ingest tier down — this is the ONLY supported way to get the value,
        # so it must never be generated per-boot or the producers and the
        # collector would disagree.
        if "INGEST_TOKEN" not in env:
            additions.append("INGEST_USER=netops-ingest")
            additions.append(f"INGEST_TOKEN={generate_token(32)}")
        # Migration (F-07/F-59): search-tier durability posture.
        if "OPENSEARCH_REPLICAS" not in env:
            additions.append("OPENSEARCH_REPLICAS=0")
        if "OPENSEARCH_SNAPSHOT_KEEP" not in env:
            additions.append("OPENSEARCH_SNAPSHOT_KEEP=14")
        # Migration (SEC-010/012/013/008): credentials the security epics
        # introduced. generate_secrets() has minted them since those epics
        # landed, but a pre-epic .env lacks them and the fresh-install template
        # only covers NEW installs. Values converge on the next compose up —
        # every consumer reads the same .env.
        if "REDIS_PASSWORD" not in env:
            additions.append(f"REDIS_PASSWORD={generate_password(24)}")
        for lane in ("TRAPS", "PROBES", "METRICS", "BUS"):
            if f"INGEST_TOKEN_{lane}" not in env:
                additions.append(f"INGEST_TOKEN_{lane}={generate_token(32)}")
        for svc in ("API", "GNMIC", "VECTOR", "VMALERT", "GRAFANA", "PROBER"):
            if f"VMAUTH_{svc}_PASSWORD" not in env:
                additions.append(f"VMAUTH_{svc}_PASSWORD={generate_urlsafe_password(24)}")
        for svc in ("API", "ROUTER", "CORRELATION", "BOOTSTRAP", "DASHBOARDS", "AGGREGATOR"):
            if f"OS_{svc}_PASSWORD" not in env:
                additions.append(f"OS_{svc}_PASSWORD={generate_urlsafe_password(24)}")
        if additions:
            with env_path.open("a") as f:
                f.write("\n# ---- Event bus (Apache Kafka) — appended by install.py migration ----\n")
                f.write("\n".join(additions) + "\n")
            ok(f"migrated .env: added {', '.join(a.split('=')[0] for a in additions)}")
            env = _parse_env(env_path)
        return env

    # NOTE (FUNC-HIGH-1): this path used to delete data/api/users.json on
    # --reset-env so the api would re-seed the admin from the new
    # ADMIN_INITIAL_PASSWORD. That destroys EVERY local account, not just the
    # admin's password, and it contradicted the template's own "--reset-env does
    # NOT rotate it" note. The user store is now a rotation store like any
    # other: once it exists, ADMIN_INITIAL_PASSWORD is inert and the rotation
    # gate refuses instead (scripts/reset-admin.sh remains the deliberate,
    # explicitly destructive way to force a re-seed).

    secrets_map = generate_secrets()
    # Values the rotation gate ruled un-rotatable keep their current value; a
    # regenerated one would be a lie the stores never agreed to.
    for key, value in (preserve or {}).items():
        if key in secrets_map:
            secrets_map[key] = value

    body = f"""# NetOps Observability — environment.
# Generated by scripts/install.py at {datetime.now(timezone.utc).isoformat()}.
#
# Treat this file as a secret. Do not commit it.
#
# Rotating: `install.py --reset-env` regenerates this file, but ONLY while it
# can honour every value it writes. Once the stack has started, most secrets
# below are validated by a store that read them once and kept them, so
# --reset-env reconciles those stores (and refuses, changing nothing, for the
# ones it cannot). `install.py --rotate-app-secrets` rotates just the safe set
# in place, keeping every operator edit in this file. Full matrix:
# docs/runbooks/secret-rotation.md.

BASE_PORT={port}

# Containers that write bind-mounted data/ dirs (api, grafana add-on) run as
# THIS user, so no sudo/chown is ever needed. Written once at install.
CORRELIX_UID={os.getuid()}
CORRELIX_GID={os.getgid()}

# Initial admin user. The API creates this on first start (only if the
# user store is empty), then never again — so once data/api/users.json
# exists this value is INERT and no longer the admin's password. Change
# the password from the Settings tab in the dashboard. `--reset-env`
# refuses to pretend it rotates this; scripts/reset-admin.sh wipes the
# user store deliberately (destroying every local account) to re-seed it.
ADMIN_USERNAME=admin
ADMIN_INITIAL_PASSWORD={secrets_map["ADMIN_INITIAL_PASSWORD"]}

# Database (Postgres — app state)
DB_HOST=postgres
DB_PORT=5432
DB_USER=netops
DB_PASSWORD={secrets_map["DB_PASSWORD"]}
DB_NAME=netops

# ClickHouse (OLAP — flow analytics, findings)
CLICKHOUSE_USER=netops
CLICKHOUSE_PASSWORD={secrets_map["CLICKHOUSE_PASSWORD"]}

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# Time-series DB
VICTORIA_URL=http://victoria:8428
VICTORIA_RETENTION=30d

# Grafana admin login (force a password change on first browse anyway).
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD={secrets_map["GRAFANA_ADMIN_PASSWORD"]}
# Set only while the self-monitoring add-on is enabled — gates the Grafana
# stack-health probe (empty = probe skipped, no false red).
GRAFANA_URL={"http://grafana:3000" if "self-monitoring" in profiles else ""}
# Read-only ClickHouse user Grafana's provisioned ClickHouse datasource binds to.
# Its CH profile pins tenant_scope='' (readonly CONST) so it sees only untagged
# platform/infra rows — never another tenant's data. Created by bootstrap_grafana.
GRAFANA_CH_PASSWORD={secrets_map["GRAFANA_CH_PASSWORD"]}

# Application secrets
JWT_SECRET={secrets_map["JWT_SECRET"]}
ENCRYPTION_KEY={secrets_map["ENCRYPTION_KEY"]}

# Ingest identity (F-08). The four Vector http_server ingest sources
# (traps :8688, probes :8689, metrics :8690, bus bridge :8692) accepted
# UNAUTHENTICATED writes to any netops.* topic, including a forged tenant_id —
# a cross-tenant injection path guarded only by the assumption that nothing
# hostile can reach the compose network. Lane credentials are the PER-LANE
# INGEST_TOKEN_<LANE> values below (SEC-013 narrowing: the shared token opens
# no lane); INGEST_TOKEN itself remains only the stack-internal edge-keys
# gate (vector-router -> api, internalStackCaller).
INGEST_USER=netops-ingest
INGEST_TOKEN={secrets_map["INGEST_TOKEN"]}

# Search-tier durability posture.
#   OPENSEARCH_REPLICAS      F-07 — 0 is correct for the single-node appliance
#                            (a replica can never be assigned on one node and
#                            pins the cluster YELLOW forever). Raise it to >= 1
#                            on a real multi-node cluster.
#   OPENSEARCH_SNAPSHOT_KEEP F-59 — daily snapshots retained in the netops-fs
#                            repository (data/opensearch-snapshots). 0 disables
#                            snapshots entirely, leaving the search tier with
#                            no backup of any kind.
OPENSEARCH_REPLICAS=0
OPENSEARCH_SNAPSHOT_KEEP=14

# Feature toggles
# Discovery is OPT-IN: an appliance must never scan a network unasked.
# Enable + scope it in the UI (Administration -> Discovery) or here.
ENABLE_SNMP_DISCOVERY=false
SNMP_CIDR_RANGES=
ENABLE_SNMP_COLLECTION=true
ENABLE_GNMI_COLLECTION=false
ENABLE_NETCONF_COLLECTION=false

FEATURE_SLACK_NOTIFICATIONS=false
SLACK_WEBHOOK_URL=

FEATURE_PAGERDUTY_NOTIFICATIONS=false
PAGERDUTY_KEY=

FEATURE_EMAIL_NOTIFICATIONS=false
SMTP_HOST=                     # e.g. smtp.example.com:587
SMTP_FROM=                     # e.g. monitoring@example.com
SMTP_USER=
SMTP_PASS=
SMTP_TO=                       # comma-separated list of recipient addresses

# SMS via Twilio (requires a Twilio account)
FEATURE_TWILIO_NOTIFICATIONS=false
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=            # E.164 format, e.g. +15551234567
TWILIO_TO_NUMBERS=             # comma-separated E.164 numbers

# SMS via AWS SNS (cheaper than Twilio; SMS only, no voice)
FEATURE_SNS_NOTIFICATIONS=false
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=                    # e.g. us-east-1
SNS_PHONE_NUMBERS=             # comma-separated E.164 numbers, OR set SNS_TOPIC_ARN
SNS_TOPIC_ARN=

# ITSM — ServiceNow auto-ticketing. Opens a deduped incident when an alert at
# or above SERVICENOW_MIN_SEVERITY fires and auto-resolves it when the alert
# clears. See docs/ITSM_INTEGRATION.md.
FEATURE_SERVICENOW_NOTIFICATIONS=false
SERVICENOW_INSTANCE_URL=       # e.g. https://dev12345.service-now.com
SERVICENOW_USER=
SERVICENOW_PASSWORD=
SERVICENOW_MIN_SEVERITY=critical   # critical|error|warning|notice|info
SERVICENOW_ASSIGNMENT_GROUP=

# ITSM — Jira auto-ticketing. Same bi-directional shape as ServiceNow: opens a
# deduped issue at/above JIRA_MIN_SEVERITY and transitions it to Done when the
# alert clears. Auth is an Atlassian email + API token. See docs/ITSM_INTEGRATION.md.
FEATURE_JIRA_NOTIFICATIONS=false
JIRA_BASE_URL=                 # e.g. https://yourorg.atlassian.net
JIRA_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=              # e.g. NETOPS
JIRA_ISSUE_TYPE=Task
JIRA_MIN_SEVERITY=critical     # critical|error|warning|notice|info
JIRA_RESOLVE_TRANSITION=       # transition name/id to close; blank = auto-detect

# SSO — OIDC/SAML/LDAP brokered by Keycloak (DEFAULT-ON: "sso" is in the
# default COMPOSE_PROFILES; drop it there for footprint-constrained installs).
# The Go API only verifies the resulting tokens (stdlib RS256/JWKS), so the
# backend stays dependency-free. install.py creates the keycloak database
# (Keycloak cannot create its own and crash-loops without it) and starts the
# service. Realm, OIDC client, identity providers and role mappings are all
# configured from Administration → Authentication → SSO — no Keycloak console
# work (the api drives Keycloak's admin API with the credentials below).
# NOTE: the OIDC_* values below are a first-boot SEED / fallback only — a config
# saved from Administration → Authentication is persisted in the kv store and
# WINS over this file (see docs/runbooks/okta-sso-setup.md §2b). Editing them
# here does nothing once a real config has been saved.
OIDC_ENABLED=false
OIDC_ISSUER=                   # e.g. http://localhost:{port}/auth/realms/netops
OIDC_CLIENT_ID=netops
OIDC_CLIENT_SECRET=
OIDC_REDIRECT_URL=             # e.g. http://localhost:{port}/api/auth/sso/callback
OIDC_POST_LOGIN_URL=/
OIDC_PROVIDERS=                # extra IdP buttons: id:Label:kind,comma-separated
OIDC_ADMIN_ROLES=super-admin,admin,netops-admin
OIDC_OPERATOR_ROLES=operator,netops-operator
OIDC_DEFAULT_ROLE=read-only
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD={secrets_map["KEYCLOAK_ADMIN_PASSWORD"]}
KEYCLOAK_DB_NAME=keycloak

# Transport security (#18 / tracker #151). All DORMANT when empty — a fresh
# install runs the documented plaintext baseline (docs/security/
# transport-inventory.yaml is the per-hop truth). The enable sequence is
# docs/runbooks/tls-mtls.md; the full variable set lives on the api service in
# docker-compose.yml (TLS_INTERNAL_CA, TLS_CERT_FILE, ...). Declared here so
# the surface is discoverable from .env, not only from compose internals.
TLS_INTERNAL_CA=
# Multi-region SPIFFE federation (domain=/path/root.pem, comma-separated).
# Malformed values or missing files refuse the boot — fail-closed by design.
TLS_FEDERATED_BUNDLES=
# Workload identity registry (SEC-003.3): a directory where the internal CA
# mints one SVID per service (additive; consumed per-epic). e.g. /data/tls/services
TLS_SERVICE_CERT_ROOT=

# Bundled NetBox (Automation → Source of Truth). The platform runs NetBox
# internally; the API auto-wires to it (NETBOX_INTERNAL_URL) with the seeded
# token, so the UI needs no URL/token. Start it with:  docker compose --profile
# netbox up -d   (omit the profile to run without the bundled NetBox). To use an
# EXTERNAL NetBox instead, leave NETBOX_INTERNAL_URL blank and set NETBOX_URL.
NETBOX_INTERNAL_URL=http://netbox:8080/netbox
# Origins NetBox trusts for POST/edit (creating inventory) via the proxied UI at
# /netbox/. Set to the URL you browse from, e.g. http://<host>:8000.
NETBOX_CSRF_ORIGINS=http://localhost:8000
NETBOX_SECRET_KEY={secrets_map["NETBOX_SECRET_KEY"]}
NETBOX_DB_PASSWORD={secrets_map["NETBOX_DB_PASSWORD"]}
NETBOX_SUPERUSER=admin
NETBOX_SUPERUSER_PASSWORD={secrets_map["NETBOX_SUPERUSER_PASSWORD"]}
NETBOX_TOKEN={secrets_map["NETBOX_TOKEN"]}
NETBOX_URL=

# Identity/saved-object persistence backend. "file" (default) keeps the JSON
# stores on the data volume; "postgres" moves them into a single key/value table
# with NO API change. Postgres needs a driver compiled in — see pgkv.go /
# docs/IDENTITY_ACCESS.md — so the default build stays stdlib-only.
STORE_BACKEND=file
# DATABASE_URL=postgres://netops:netops@postgres:5432/netops?sslmode=disable
# On a --tls install postgres REQUIRES TLS (pg_hba `hostssl`, F-4): use
# ?sslmode=verify-full&sslrootcert=/data/tls/ca.pem instead of sslmode=disable.
# DATABASE_DRIVER=postgres

# Token lifetimes
ACCESS_TOKEN_TTL=1h
REFRESH_TOKEN_TTL=168h

# Default per-API-key rate limit (requests/minute, fixed window). Per-key
# overrides are set when minting a key in Administration → API Access. 0 = no
# app-level limit. Over-cap calls return 429 + Retry-After.
APIKEY_RATE_LIMIT_PER_MIN=600

# Correlix AI assistant. ON by default in key-free GROUNDED mode (deterministic,
# in-process, no external calls). Set FEATURE_COPILOT=false to disable. Add a
# provider key in the assistant settings UI (or COPILOT_API_KEY here) to enable
# LLM answers + investigations. Provider: 'gemini' (default, free tier),
# 'anthropic' or 'openai'.
FEATURE_COPILOT=true
COPILOT_PROVIDER=gemini
COPILOT_API_KEY=
COPILOT_MODEL=

# Correlation/AI Python service log level: info|debug|warning
CORRELATION_LOG_LEVEL=info

# ---- Correlation data retention (#101) ----------------------------------
# Hot-ClickHouse retention profile for correlation history, applied by the
# API on every start: lab (90/45/60 days) | demo (30/14/30) |
# production (180/90/90) | extended (730/365/365) — history/archive/closed.
# Per-knob overrides: CORR_RETENTION_HISTORY_DAYS / _ARCHIVE_DAYS /
# _CLOSED_DAYS (0 = keep forever). Cold Parquet export must lead the TTL
# horizon: cron scripts/ch-cold-export.sh monthly (see
# docs/runbooks/correlation-retention-cold-archive.md).
CORR_RETENTION_PROFILE={retention_profile}

# Named intentional chaos/storm sources ("name=match,..."), e.g. a lab
# target kept unreachable on purpose. Tagged objects are badged in Command
# Center and skipped by auto-ticketing. Leave empty in production unless a
# drill is officially scheduled.
CORR_CHAOS_FIXTURES=

# ---- Critical alert push (#101 first-customer gate) ----------------------
# Critical alerts MUST leave the app before go-live — in-app visibility alone
# fails acceptance (docs/runbooks/first-customer-acceptance.md §4). Set a
# DEDICATED ntfy topic here (or configure any channel in Admin →
# Notifications). NEVER reuse the external watchdog's topic — set
# WATCHDOG_NTFY_TOPIC so the platform can refuse it. Verify with
# scripts/verify-critical-alert-channel.sh --send.
FEATURE_NTFY_NOTIFICATIONS=false
NTFY_ALERT_TOPIC=
NTFY_ALERT_SERVER=
NTFY_ALERT_TOKEN=
WATCHDOG_NTFY_TOPIC=

# Device-side ingestion ports (host-side, mapped into the syslog-ng /
# goflow2 containers). Use standard ports (514, 2055, 4739, 6343) on
# Linux with rootful Docker; on rootless or Docker Desktop use non-
# privileged alternatives like 5514. Devices must be configured to send
# to the host's IP on these ports.
SYSLOG_PORT=5514
NETFLOW_PORT=2055
IPFIX_PORT=4739
SFLOW_PORT=6343

# ---- Event bus (Apache Kafka) ------------------------------------------
# Kafka bootstrap list every service resolves the bus through. The default
# is the embedded single-node broker (service `kafka`, internal network
# only — no host port). External-broker mode points this at your own
# Kafka-compatible cluster and removes `embedded-bus` from
# COMPOSE_PROFILES below (install-correlix.sh --external-kafka does both).
BROKER_URLS={broker_urls or "kafka:9092"}
# KRaft storage id for the embedded broker. Do NOT change it after first
# start — the broker's data dir is formatted with this id and would refuse
# its own volume, taking the whole bus/ingest path down. install.py enforces
# this: --reset-env leaves it alone and refuses; rotating it really does
# require discarding the broker's data, which only
# `install.py --reset-env --rotate-kafka-cluster-id` will do (it moves
# data/kafka aside first).
KAFKA_CLUSTER_ID={secrets_map["KAFKA_CLUSTER_ID"]}

# Valkey (compose name: redis) AUTH. Read by the api/prober AND the server
# command line — a fresh value converges on the next compose up.
REDIS_PASSWORD={secrets_map["REDIS_PASSWORD"]}

# Per-lane ingest tokens (SEC-013.2). Identity is mTLS's job; the lane token
# is lane AUTHORIZATION. Producers and the collector both read these — the
# shared INGEST_TOKEN above remains the fallback until the enforce wave drops it.
INGEST_TOKEN_TRAPS={secrets_map["INGEST_TOKEN_TRAPS"]}
INGEST_TOKEN_PROBES={secrets_map["INGEST_TOKEN_PROBES"]}
INGEST_TOKEN_METRICS={secrets_map["INGEST_TOKEN_METRICS"]}
INGEST_TOKEN_BUS={secrets_map["INGEST_TOKEN_BUS"]}

# vmauth per-service credentials (SEC-010). Consumed only when the vmauth
# profile is active; harmless otherwise. One user per client, scoped routes.
VMAUTH_API_PASSWORD={secrets_map["VMAUTH_API_PASSWORD"]}
VMAUTH_GNMIC_PASSWORD={secrets_map["VMAUTH_GNMIC_PASSWORD"]}
VMAUTH_VECTOR_PASSWORD={secrets_map["VMAUTH_VECTOR_PASSWORD"]}
VMAUTH_VMALERT_PASSWORD={secrets_map["VMAUTH_VMALERT_PASSWORD"]}
VMAUTH_GRAFANA_PASSWORD={secrets_map["VMAUTH_GRAFANA_PASSWORD"]}
VMAUTH_PROBER_PASSWORD={secrets_map["VMAUTH_PROBER_PASSWORD"]}

# OpenSearch security-plugin identities (SEC-008). Consumed only when the
# security plugin is enabled (TLS variant / security profile); harmless otherwise.
OS_API_PASSWORD={secrets_map["OS_API_PASSWORD"]}
OS_ROUTER_PASSWORD={secrets_map["OS_ROUTER_PASSWORD"]}
OS_CORRELATION_PASSWORD={secrets_map["OS_CORRELATION_PASSWORD"]}
OS_BOOTSTRAP_PASSWORD={secrets_map["OS_BOOTSTRAP_PASSWORD"]}
OS_DASHBOARDS_PASSWORD={secrets_map["OS_DASHBOARDS_PASSWORD"]}
OS_AGGREGATOR_PASSWORD={secrets_map["OS_AGGREGATOR_PASSWORD"]}

# Active compose profiles (additive; non-profiled services always start).
#   embedded-bus  the bundled Apache Kafka broker + topic init
#   prober        raw-socket active-measurement sidecar
#   osd           OpenSearch Dashboards (omitted by --core bundles)
COMPOSE_PROFILES={profiles}
"""
    env_path.write_text(body)
    env_path.chmod(0o600)
    ok(f"wrote {env_path} (mode 0600)")
    return secrets_map


def _parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


# ---- secret rotation (FUNC-HIGH-1) ------------------------------------------

def refuse(msg: str) -> "None":
    """Refuse a rotation we cannot honour. Exit 2 (distinct from fail()'s 1)
    so callers/CI can tell "refused, nothing changed" from "broke halfway"."""
    print(f"[fail ] {msg}", file=sys.stderr)
    sys.exit(2)


def _rotation_module():
    """Import scripts/secret_rotation.py the same way resource_planner is."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import secret_rotation as sr
    return sr


class ComposeRunner:
    """Runs commands inside stack containers. The ONLY place rotation touches
    docker — reconcilers take it as a parameter (CLAUDE.md §2: dependencies are
    explicit and injectable), so the policy is testable without a stack.

    Every call is bounded by a timeout (§9): a wedged store must fail the
    rotation, never hang the installer forever."""

    def __init__(self, compose_dir: Path) -> None:
        self.compose_dir = compose_dir

    def _run(self, argv: list[str], stdin: str, timeout: int):
        sr = _rotation_module()
        try:
            r = subprocess.run(argv, cwd=str(self.compose_dir), input=stdin,
                               capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return sr.ExecResult(124, "", f"timed out after {timeout}s: {argv[:4]}")
        except (OSError, subprocess.SubprocessError) as e:
            return sr.ExecResult(126, "", f"{type(e).__name__}: {e}")
        return sr.ExecResult(r.returncode, r.stdout, r.stderr)

    def exec(self, service: str, argv: list[str], stdin: str = "",
             timeout: int = 60):
        return self._run(["docker", "compose", "exec", "-T", service, *argv],
                         stdin, timeout)

    def recreate(self, service: str, timeout: int = 300):
        return self._run(
            ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps",
             service], "", timeout)


def confirm(prompt: str, assume_yes: bool) -> bool:
    """Interactive yes/no. Non-interactive (cron, CI, piped stdin) is always
    NO — a destructive default must never be reachable by accident (§16.2)."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        warn("not a terminal — refusing to assume consent (pass --assume-yes)")
        return False
    try:
        return input(f"  {prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def rotate_secrets(root: Path, compose_dir: Path, env_path: Path, *,
                   strict: bool, allow_kafka_wipe: bool, assume_yes: bool,
                   runner=None, sleep=time.sleep) -> tuple[dict[str, str], int]:
    """Rotate every secret that can be rotated for real, in place.

    Returns (rotated_values, failures). Guarantees, in this order:
      1. Nothing is written until the whole plan is known to be completable —
         a blocked secret in `strict` mode refuses with exit 2 and an untouched
         .env.
      2. Store-catalog credentials (ALTER class) are changed on the LIVE store
         and verified BEFORE .env is rewritten, so .env never advertises a
         credential the store has not accepted.
      3. Anything that fails afterwards is rolled back to its previous value in
         .env, so the file always describes the running stores.
    """
    sr = _rotation_module()
    if not env_path.exists():
        refuse(f"no .env at {env_path} — nothing to rotate. Run a full install first.")
    env = _parse_env(env_path)
    profiles = env.get("COMPOSE_PROFILES", "")
    runner = runner if runner is not None else ComposeRunner(compose_dir)

    verdicts = sr.classify(root, profiles, allow_kafka_wipe=allow_kafka_wipe,
                           names=generate_secrets().keys())
    stuck = sr.blocked(verdicts)
    if stuck and strict:
        refuse(sr.refusal_text(stuck, len(verdicts)))
    fresh = generate_secrets()
    plan = [v for v in verdicts if v.rotatable]
    new_values = {v.name: fresh[v.name] for v in plan}

    # -- preflight: every live store this plan depends on must answer NOW -----
    unreachable: list[str] = []
    for v in plan:
        if not v.reconcile or v.cls == sr.IMMUTABLE:
            continue
        okay, why = sr.preflight(runner, v.name, env, new_values.get(v.name, ""))
        if not okay:
            unreachable.append(
                f"  {v.name}\n      {why}\n      -> {sr.POLICY[v.name].remedy}")
    if unreachable:
        refuse("rotation needs these stores and cannot reach them; nothing was "
               "written:\n" + "\n".join(unreachable))

    rotated: dict[str, str] = {}
    failures: list[str] = []

    # -- the one destructive opt-in, taken FIRST ------------------------------
    # Consent and the volume move both happen before anything else is mutated:
    # aborting here must leave the install exactly as it was found, and it
    # cannot do that once a live store's password has already been ALTERed.
    if allow_kafka_wipe and "KAFKA_CLUSTER_ID" in new_values and \
            sr.store_initialized(root, "kafka", profiles):
        kdir = root / "data" / "kafka"
        dest = kdir.with_name(f"kafka.pre-rotate-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}")
        print()
        warn("--rotate-kafka-cluster-id is DESTRUCTIVE to the embedded bus.")
        info(f"  will move {kdir}  ->  {dest}")
        info("  every topic, consumer offset and in-flight message on the "
             "embedded broker is discarded (durable copies in OpenSearch / "
             "VictoriaMetrics / ClickHouse are untouched).")
        if not confirm(f"move {kdir} aside and rotate the cluster id?", assume_yes):
            refuse("aborted at the Kafka confirmation — nothing was written.")
        try:
            kdir.rename(dest)
        except OSError as e:
            refuse(f"could not move {kdir} aside ({e}); KAFKA_CLUSTER_ID was NOT "
                   "rotated and nothing was written. Fix the permissions "
                   f"(sudo mv {kdir} {dest}) and re-run.")
        ok(f"moved {kdir} -> {dest} (delete it once the new broker is healthy)")

    # -- phase A: live-catalog credentials, BEFORE .env moves ----------------
    for name, service, user, db in (
            ("DB_PASSWORD", "postgres", env.get("DB_USER", "netops"),
             env.get("DB_NAME", "netops")),
            ("NETBOX_DB_PASSWORD", "netbox-postgres", "netbox", "netbox")):
        v = next((x for x in plan if x.name == name), None)
        if v is None or not v.reconcile:
            continue
        done, msg = sr.reconcile_postgres(runner, service=service, user=user,
                                          db=db, new_password=new_values[name])
        if done:
            ok(f"{name}: {msg}")
        else:
            warn(f"{name} NOT rotated — {msg}")
            failures.append(name)
            new_values.pop(name, None)

    # -- write .env (line surgery: operator edits survive) -------------------
    text = env_path.read_text()
    backup = env_path.with_suffix(env_path.suffix + ".rotate.bak")
    backup.write_text(text)
    backup.chmod(0o600)
    new_text, missing = sr.substitute_env(text, new_values)
    if missing:
        new_text += ("\n# ---- added by install.py secret rotation ----\n"
                     + "".join(f"{k}={new_values[k]}\n" for k in missing))
    env_path.write_text(new_text)
    env_path.chmod(0o600)
    rotated.update(new_values)
    ok(f"{env_path} updated ({len(new_values)} secrets; previous copy at "
       f"{backup.name}, mode 0600)")

    # -- phase B: credentials the RUNNING container re-reads from .env -------
    def _revert(name: str, why: str) -> None:
        warn(f"{name} NOT rotated — {why}")
        failures.append(name)
        rotated.pop(name, None)
        if name not in env:
            warn(f"{name} had no previous value in .env — left as generated; "
                 "verify the store before relying on it")
            return
        reverted, _ = sr.substitute_env(env_path.read_text(), {name: env[name]})
        env_path.write_text(reverted)
        env_path.chmod(0o600)
        info(f"{name} rolled back in .env so it still matches the running store")

    ch_admin_pw = env.get("CLICKHOUSE_PASSWORD", "")
    v = next((x for x in plan if x.name == "CLICKHOUSE_PASSWORD" and x.reconcile), None)
    if v is not None:
        done, msg = sr.reconcile_clickhouse_admin(
            runner, user=env.get("CLICKHOUSE_USER", "netops"),
            old_password=ch_admin_pw, new_password=new_values["CLICKHOUSE_PASSWORD"],
            sleep=sleep)
        if done:
            ch_admin_pw = new_values["CLICKHOUSE_PASSWORD"]
            ok(f"CLICKHOUSE_PASSWORD: {msg}")
        else:
            _revert("CLICKHOUSE_PASSWORD", msg)
            # Put the container back on the value .env still holds. Never
            # swallowed: if this fails the operator must know the container and
            # the file may now disagree (§16.1).
            back = runner.recreate("clickhouse")
            if back.returncode != 0:
                warn("could not recreate clickhouse after the rollback: "
                     + sr.redact(back.stderr or back.stdout,
                                 [new_values.get("CLICKHOUSE_PASSWORD", ""),
                                  env.get("CLICKHOUSE_PASSWORD", "")]))
                warn("clickhouse may still be running with the ROLLED-BACK "
                     "password; run: docker compose up -d --force-recreate clickhouse")

    v = next((x for x in plan if x.name == "GRAFANA_CH_PASSWORD" and x.reconcile), None)
    if v is not None:
        done, msg = sr.reconcile_grafana_ch_user(
            runner, admin_user=env.get("CLICKHOUSE_USER", "netops"),
            admin_password=ch_admin_pw,
            grafana_password=new_values["GRAFANA_CH_PASSWORD"])
        if done:
            ok(f"GRAFANA_CH_PASSWORD: {msg}")
        else:
            _revert("GRAFANA_CH_PASSWORD", msg)

    # -- report (names only, never values) -----------------------------------
    print()
    ok("rotated: " + (", ".join(sorted(rotated)) or "(nothing)"))
    if stuck:
        info("kept (cannot be rotated on a started install — see "
             "docs/runbooks/secret-rotation.md): "
             + ", ".join(v.name for v in stuck))
    if failures:
        warn("FAILED to rotate: " + ", ".join(sorted(failures))
             + " — these keep their previous value in .env")
    return rotated, len(failures)


# ---- data dirs --------------------------------------------------------------

def ensure_data_dirs(root: Path) -> None:
    """Create per-service subdirectories under data/ and (where we know
    the container runs as a non-root user) chown them to that UID/GID.

    Container UIDs are derived from each upstream image:
        grafana       472 (grafana)
        opensearch   1000 (opensearch)
        clickhouse    101 (clickhouse)
        victoria     1000
        kafka        1000 (appuser)
    The other services (postgres, redis, api correlation store) either
    chown their own data dirs on first boot or write as root."""
    owners: dict[str, tuple[int, int] | None] = {
        "postgres":   None,             # initdb chowns its own
        "redis":      None,             # writes as redis user via its own init
        "victoria":   (1000, 1000),
        "grafana":    None,             # user-mapped to the installing user (CORRELIX_UID)
        "kafka":      (1000, 1000),
        "opensearch": (1000, 1000),
        # F-59: snapshot repository destination (path.repo). Must be writable
        # by the opensearch UID or the repository registers and then every
        # snapshot fails — which is the worst of the three states, because the
        # stack then reports that it HAS backups.
        "opensearch-snapshots": (1000, 1000),
        "clickhouse": (101, 101),
        "api":        None,             # Go API runs as nonroot but writes JSON only
        "secrets-seal": None,           # #17 sealing-sidecar socket dir (root-owned; opt-in 'seal' profile)
        "swtpm":      None,             # #17 software-TPM state (sealed KEK objects); root-owned
        "netbox-postgres": None,        # bundled-NetBox DB (opt-in 'netbox' profile); initdb self-chowns
        "netbox-media":    None,        # bundled-NetBox media (opt-in 'netbox' profile)
        # F-38/durability: the correlation dead-letter volume. The Python service
        # runs as root inside its container and writes NDJSON, so no chown — but
        # the directory must exist and be writable before first boot, or the very
        # first rejected RCA-critical evidence has nowhere durable to land.
        "correlation/deadletter": None,
        # tracker #151: the internal CA's mint target (SVIDs, trust bundle).
        # Docker would auto-create a bind-mount source as ROOT, and the api
        # (uid 65532) could then never mint into it — pre-create owned by the
        # api's uid. Dormant/empty on plaintext installs.
        "tls": (65532, 65532),
    }
    for name, uid_gid in owners.items():
        d = root / "data" / name
        d.mkdir(parents=True, exist_ok=True)
        if uid_gid is not None:
            try:
                os.chown(d, uid_gid[0], uid_gid[1])
                # Be permissive on existing contents too, in case this is a
                # re-run after a previous failed install left files behind.
                for child in d.rglob("*"):
                    try: os.chown(child, uid_gid[0], uid_gid[1])
                    except OSError: pass
            except PermissionError:
                # Not root — note it but continue. The relevant containers
                # will fail to start until the user fixes ownership.
                warn(
                    f"can't chown data/{name} to {uid_gid[0]}:{uid_gid[1]} "
                    f"(not root). The {name} container may fail to start."
                )
                info(
                    f"  Fix: sudo chown -R {uid_gid[0]}:{uid_gid[1]} {d}"
                )

    # #20: device→tenant enrichment dir. The api (nonroot 65532) exports the CSV
    # here; the Vector aggregator + correlation mount it read-only. Seed a
    # header-only CSV so the aggregator's enrichment-table load never fails on a
    # cold start (before the api has written its first map). Owned by the api uid.
    enrich = root / "data" / "api" / "enrichment"
    enrich.mkdir(parents=True, exist_ok=True)
    seed = enrich / "device_tenant.csv"
    if not seed.exists():
        seed.write_text("identity,tenant_id\n")
    try:
        os.chown(enrich, 65532, 65532)
        os.chown(seed, 65532, 65532)
    except (PermissionError, OSError):
        pass  # not root; api will adopt it on first write where it can

    # Item 121: per-tenant processor rules → generated Vector-router config.
    # The api (nonroot 65532) writes processors/router/processors.yaml; the
    # router loads it as a second --config, so it MUST exist before the router
    # boots. Seed the checked-in no-op default (all five hooks, zero rules);
    # the api rewrites it on first start and on every rule change.
    proc_dir = root / "data" / "api" / "processors" / "router"
    proc_dir.mkdir(parents=True, exist_ok=True)
    proc_seed = proc_dir / "processors.yaml"
    if not proc_seed.exists():
        default = root / "deployment" / "docker" / "vector-router" / "processors-default.yaml"
        proc_seed.write_text(default.read_text())
    try:
        os.chown(proc_dir.parent, 65532, 65532)
        os.chown(proc_dir, 65532, 65532)
        os.chown(proc_seed, 65532, 65532)
    except (PermissionError, OSError):
        pass  # not root; api will adopt it on first write where it can

    # #81 P1: Application Identification IP→app catalog feeds dir. The api (nonroot
    # 65532) reads vendor IP-range snapshots dropped here by scripts/fetch-appid-feeds.sh
    # (APPID_FEEDS_DIR=/data/appid-feeds). Pre-create it (empty is fine — the resolver
    # returns "unknown" until feeds land) so the opt-in feature works without a restart.
    appid_feeds = root / "data" / "api" / "appid-feeds"
    appid_feeds.mkdir(parents=True, exist_ok=True)
    # #81 P3A: Cloud App Observability inventory fixtures dir (CLOUD_FIXTURES_DIR=
    # /data/cloud-fixtures). Empty by default — populate with provider inventory JSON
    # (or wire real connectors) to light up the App Observability cloud views.
    cloud_fixtures = root / "data" / "api" / "cloud-fixtures"
    cloud_fixtures.mkdir(parents=True, exist_ok=True)
    # Runtime layer of the cloud inventory (static-fixture/runtime split): the
    # live cloud-ingest poller writes its snapshots HERE (gitignored data/),
    # and the api/correlation read it first with fixture fallback
    # (CLOUD_RUNTIME_DIR / CLOUD_TOPOLOGY_RUNTIME_DIR). Empty is fine.
    # NOT chowned to the api uid: the WRITER is the poller (the operator's
    # uid, 1000 in the lab); the api only reads it.
    cloud_runtime = root / "data" / "api" / "cloud-runtime"
    cloud_runtime.mkdir(parents=True, exist_ok=True)
    for d in (appid_feeds, cloud_fixtures):
        try:
            os.chown(d, 65532, 65532)
        except (PermissionError, OSError):
            pass  # not root; api adopts it where it can

    # #13: vulnerability-feed dir. OPERATOR-owned (unlike the service dirs) —
    # the operator writes it with scripts/vuln-feed-prepare.py and the api only
    # reads it (mounted read-only). Under sudo, chown to the invoking user so
    # the prepare script works without root afterwards.
    vuln = root / "data" / "vuln"
    vuln.mkdir(parents=True, exist_ok=True)
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if sudo_uid:
        try:
            os.chown(vuln, int(sudo_uid), int(sudo_gid or sudo_uid))
        except (PermissionError, OSError, ValueError):
            pass

    ok("data/ directories ready")


# ---- compose ----------------------------------------------------------------

def write_offline_override(compose_dir: Path, env_path: Path) -> None:
    """Air-gapped installs (#97): compose pins third-party images as
    tag@sha256:digest, but a registry digest is PULL-time metadata — a
    docker-load'ed image carries only its tag. On a virgin host compose
    therefore treats every digest-pinned image as missing and tries to pull,
    which an offline install must never do (first virgin-host test,
    2026-07-04). Generate an override that references the same images by tag
    only — integrity is already covered end-to-end by the bundle's
    SHA256SUMS — and activate it via COMPOSE_FILE in .env so every later
    `docker compose` in this directory agrees. Digest pinning stays in the
    committed compose for online installs (supply-chain guard at pull time)."""
    src = (compose_dir / "docker-compose.yml").read_text()
    overrides: dict[str, str] = {}
    svc, in_services = None, False
    for line in src.splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services:
            if re.match(r"^\S", line):          # left the services: block
                break
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                svc = m.group(1)
                continue
            mi = re.match(r"^\s+image:\s*([^\s@]+)@sha256:[0-9a-f]{64}\s*$", line)
            if mi and svc:
                overrides[svc] = mi.group(1)
    if not overrides:
        return
    body = [
        "# Generated by install.py for OFFLINE installs — do not edit.",
        "# docker-load restores image TAGS, not registry digests; this pins the",
        "# same images by tag (bundle SHA256SUMS covers integrity end-to-end).",
        "services:",
    ]
    for s in sorted(overrides):
        body += [f"  {s}:", f"    image: {overrides[s]}"]
    (compose_dir / "compose.offline-images.yml").write_text("\n".join(body) + "\n")
    env_text = env_path.read_text() if env_path.exists() else ""
    if "COMPOSE_FILE=" not in env_text:
        with env_path.open("a") as f:
            f.write("\n# Offline install: tag-pinned image override (see file header).\n")
            f.write("COMPOSE_FILE=docker-compose.yml:compose.offline-images.yml\n")
    ok(f"offline image override written ({len(overrides)} digest-pinned images → tag-pinned)")


# ---- TLS/mTLS transport security (tracker #151 delivery shape) --------------
# One question on a fresh install; --tls=yes|no for unattended runs. "yes" is
# the COMPLETE mesh in two phases: phase A boots the plaintext baseline with
# the mint variables set so the api's internal CA writes every SVID to
# data/tls; phase B activates deployment/docker/compose.tls.yml (fail-closed
# store wrappers, mTLS listeners) via the COMPOSE_FILE chain and recreates.
# The two-phase shape exists because the CA's own state lives in the platform
# store: a fail-closed postgres cannot start without certs that only a running
# api can mint (the SEC-011 bootstrap-deadlock lesson).

# These values MUST stay in lockstep with the api service block in
# deployment/docker/compose.tls.yml — phase A mints from .env through the base
# compose ${VAR:-} passthroughs; phase B serves from the variant's literals.
TLS_ENV_VALUES: dict[str, str] = {
    "TLS_INTERNAL_CA":       "true",
    "TLS_TRUST_DOMAIN":      "netops",
    "TLS_SVID_TTL":          "168h",
    "TLS_CLIENT_CA_FILE":    "/data/tls/ca.pem",
    "TLS_CERT_FILE":         "/data/tls/api.crt",
    "TLS_KEY_FILE":          "/data/tls/api.key",
    "TLS_NGINX_CERT_DIR":    "/data/tls/nginx",
    "TLS_NGINX_KEY_MODE":    "0644",
    "TLS_VICTORIA_CERT_DIR": "/data/tls/victoria",
    "TLS_SERVICE_CERT_ROOT": "/data/tls/services",
    "TLS_OS_ADMIN_CERT_DIR": "/data/tls/admin",
    "TLS_SERVICE_KEY_MODE":  "0644",
    "SEAL_PROVIDER":         "swtpm",
}

# Profiles the mesh requires beyond the defaults: the seal sidecar (the CA
# seal-gate refuses a plaintext CA key), the OpenSearch security bootstrap,
# and the authenticating VictoriaMetrics front.
TLS_EXTRA_PROFILES = ("seal", "security", "vmauth")

# Files whose existence proves the phase-A mint completed. One per issuance
# surface — a partial mint must FAIL the install, not half-enable the mesh.
TLS_MINT_SENTINELS = (
    # Verified against a live minted tree 2026-08-06 — note the victoria dir
    # does NOT hold a victoria.crt (it stages the scrape-client material), so
    # it is deliberately not a sentinel.
    "data/tls/ca.pem",
    "data/tls/api.crt",
    "data/tls/nginx/nginx.crt",
    "data/tls/admin/admin.crt",
    "data/tls/services/kafka/kafka.crt",
    "data/tls/services/postgres/postgres.crt",
    "data/tls/services/opensearch/opensearch.crt",
)


def resolve_tls_choice(args) -> bool:
    """The one install question. Flag wins; interactive default is YES
    (the owner's [Y/n] shape); unattended without the flag keeps the
    declared-plaintext baseline — an install script must never surprise an
    unattended run with a mesh it did not ask for."""
    if args.tls is not None:
        return args.tls == "yes"
    if not sys.stdin.isatty():
        info("no --tls given and stdin is not a TTY — keeping the declared-plaintext "
             "baseline (rerun with --tls=yes for the full mTLS mesh)")
        return False
    answer = input("  Enable TLS/mTLS transport security? [Y/n] ").strip().lower()
    return answer in ("", "y", "yes")


def enable_tls_env(env_path: Path) -> None:
    """Line-surgery the TLS values into .env (idempotent): substitute existing
    keys in place, append the missing ones under one header. Never rewrites
    the file wholesale — operator edits survive, same doctrine as rotation."""
    text = env_path.read_text()
    lines = text.splitlines()
    present: dict[str, int] = {}
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in TLS_ENV_VALUES:
            present[key] = i
    changed = False
    for key, idx in present.items():
        want = f"{key}={TLS_ENV_VALUES[key]}"
        if lines[idx] != want:
            lines[idx] = want
            changed = True
    missing = [k for k in TLS_ENV_VALUES if k not in present]
    if missing:
        lines.append("")
        lines.append("# ---- TLS/mTLS mesh (tracker #151) — written by install.py --tls=yes ----")
        lines.append("# Values pair with deployment/docker/compose.tls.yml; keep in lockstep.")
        for k in missing:
            lines.append(f"{k}={TLS_ENV_VALUES[k]}")
        changed = True
    if changed:
        env_path.write_text("\n".join(lines) + "\n")
        ok(f"TLS variables set in .env ({len(present)} updated, {len(missing)} added)")
    else:
        info("TLS variables already present in .env")


def augment_profiles_for_tls(env_path: Path) -> None:
    """Ensure COMPOSE_PROFILES carries the mesh profiles. Line surgery."""
    lines = env_path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("COMPOSE_PROFILES="):
            current = [p for p in line.split("=", 1)[1].split(",") if p]
            added = [p for p in TLS_EXTRA_PROFILES if p not in current]
            if added:
                lines[i] = "COMPOSE_PROFILES=" + ",".join(current + added)
                env_path.write_text("\n".join(lines) + "\n")
                ok(f"compose profiles gained {', '.join(added)}")
            return
    # No COMPOSE_PROFILES line at all would already have failed compose; be loud.
    fail(".env has no COMPOSE_PROFILES line — cannot enable the TLS profiles")
    raise SystemExit(2)


def activate_tls_compose_file(compose_dir: Path, env_path: Path) -> None:
    """Append compose.tls.yml to the COMPOSE_FILE chain (idempotent). The TLS
    variant goes LAST so its merges win; an offline-images chain stays ahead
    of it."""
    variant = compose_dir / "compose.tls.yml"
    if not variant.exists():
        fail(f"{variant} missing — the repo checkout is incomplete")
        raise SystemExit(2)
    lines = env_path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("COMPOSE_FILE="):
            chain = line.split("=", 1)[1]
            if "compose.tls.yml" in chain.split(":"):
                info("compose.tls.yml already active in COMPOSE_FILE")
                return
            lines[i] = f"COMPOSE_FILE={chain}:compose.tls.yml"
            env_path.write_text("\n".join(lines) + "\n")
            ok("compose.tls.yml appended to the COMPOSE_FILE chain")
            return
    with env_path.open("a") as f:
        f.write("\n# TLS/mTLS variant (tracker #151): activated by install.py --tls=yes.\n")
        f.write("COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n")
    ok("compose.tls.yml activated via COMPOSE_FILE")


def wait_for_minted_certs(root: Path, timeout_s: int = 300) -> None:
    """Phase-A gate: block until the api has minted every issuance surface.
    A timeout is a loud install FAILURE — activating fail-closed wrappers on
    a half-minted tree would take the whole stack down."""
    step(f"waiting for the internal CA to mint service identities (≤{timeout_s}s)")
    deadline = time.time() + timeout_s
    remaining = list(TLS_MINT_SENTINELS)
    while time.time() < deadline:
        remaining = [p for p in remaining if not (root / p).exists()]
        if not remaining:
            ok("all service identities minted")
            return
        time.sleep(5)
    fail("the api did not mint the full identity set in time; still missing:")
    for p in remaining:
        print(f"    - {p}")
    fail("check `docker compose logs api` (seal sidecar up? SEAL_PROVIDER=swtpm? "
         "data/tls writable by the api uid?) and rerun the installer — it is idempotent.")
    raise SystemExit(2)


def ensure_ingress_cert(root: Path) -> None:
    """The nginx TLS ingress needs a cert before its first TLS start. Dev/lab:
    self-signed via gen-dev-cert.sh; production replaces the files in place
    (documented in the script header)."""
    certs = root / "deployment" / "docker" / "nginx" / "certs"
    if certs.exists() and any(certs.glob("*.crt")):
        info("nginx ingress certs already present")
        return
    step("generating a self-signed ingress certificate (replace for production)")
    res = subprocess.run(["bash", str(root / "scripts" / "gen-dev-cert.sh")],
                         capture_output=True, text=True)
    if res.returncode != 0:
        fail(f"gen-dev-cert.sh failed: {res.stderr.strip() or res.stdout.strip()}")
        raise SystemExit(2)
    ok("self-signed ingress certificate generated")


def compose_up(compose_dir: Path, offline: bool = False,
               root: Path | None = None) -> None:
    # Profiles come from COMPOSE_PROFILES in the generated .env — NOT from a
    # --profile flag here: the CLI flag would OVERRIDE (not merge with) the env
    # var, silently dropping profiles like embedded-bus/prober. The .env is the
    # single source of truth so every later `docker compose ...` an operator
    # runs in this directory sees the same service set. The "sso" profile
    # (Keycloak) stays opt-in.
    #
    # Offline installs (client bundles built by scripts/make-installer.sh) start
    # from pre-loaded images: --no-build means a missing image is a hard, honest
    # error instead of a silent multi-GB build/pull attempt on a host that may
    # have no registry access at all.
    if offline:
        info("starting services from pre-loaded images (offline install)…")
        build_flag = "--no-build"
    else:
        info("building and starting services (this can take a few minutes the first time)…")
        build_flag = "--build"
    # First-boot resilience (virgin-host finding, 2026-07-04): on a fresh host the
    # data tier (OpenSearch/ClickHouse JVM cold start + first-time index/schema
    # init) can take longer to report HEALTHY than a single `compose up` waits for
    # a depends_on: service_healthy gate — compose then aborts the dependency wait
    # and leaves api/correlation/nginx in "Created". `up -d` is idempotent, so a
    # second/third pass starts exactly those stragglers once their deps have since
    # gone healthy. Retry before giving up.
    # Build provenance (2026-07-22): stamp the git SHA into every image built
    # here, so the running binary can report which commit it is at
    # /admin/version and stack-watchdog can alarm on drift.
    #
    # F-08 is why. Its code and config were both correct and both committed, but
    # the api image was never rebuilt — so the feature sat built-but-undeployed
    # for weeks while looking complete, and nothing in the system could tell.
    # `docker compose up -d` recreates from whatever image already exists; it
    # does not rebuild. Supplying these through the environment means the normal
    # install path CANNOT produce an unidentifiable image.
    # `root` was a free variable here (NameError on every non-offline start) —
    # it is the project root, not a global. Passed in explicitly now.
    build_env = dict(os.environ)
    build_env.setdefault("GIT_SHA", _git_sha(root or compose_dir.parent.parent))
    build_env.setdefault("BUILD_TIME",
                         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    last = 1
    for attempt in range(1, 4):
        r = subprocess.run(["docker", "compose", "up", "-d", build_flag],
                           cwd=str(compose_dir), env=build_env)
        if r.returncode == 0:
            ok("services started")
            return
        last = r.returncode
        if attempt < 3:
            warn(f"start pass {attempt} incomplete (slow first-boot health) — "
                 "waiting 30s and retrying…")
            time.sleep(30)
    fail(f"docker compose up did not converge after 3 attempts (last exit {last}). "
         "Check: docker compose ps")


def load_bundle(bundle: Path) -> None:
    """docker-load the installer's image archive (.tar, .tar.gz, or .tar.zst).

    docker load handles gzip natively; zstd archives are streamed through the
    host's zstd binary (a documented prerequisite of the offline bundle).
    """
    if not bundle.is_file():
        fail(f"image bundle not found: {bundle}")
    info(f"loading images from {bundle.name} (this can take a few minutes)…")
    if bundle.suffix == ".zst":
        if shutil.which("zstd") is None:
            fail("zstd is required to unpack the image bundle: apt-get install zstd")
        zstd = subprocess.Popen(["zstd", "-dc", str(bundle)], stdout=subprocess.PIPE)
        res = subprocess.run(["docker", "load"], stdin=zstd.stdout)
        zstd.stdout.close()
        if zstd.wait() != 0 or res.returncode != 0:
            fail("docker load from bundle failed")
    else:
        subprocess.run(["docker", "load", "-i", str(bundle)], check=True)
    ok("images loaded")


def compose_status(compose_dir: Path) -> None:
    subprocess.run(["docker", "compose", "ps"], cwd=str(compose_dir), check=False)


def bootstrap_opensearch(root: Path, tls: bool = False) -> None:
    """Apply index templates after the stack is up. Non-fatal on error —
    OpenSearch may still be starting; the user can re-run the script.

    TLS installs (SEC-008): the security plugin is on, so the probe and every
    template PUT ride https with the svc_bootstrap credential. The credential
    is read from the CONTAINER's own environment inside `sh -c` (never argv —
    argv is world-readable in /proc). Readiness must wait for the SEEDED
    security config (the opensearch-security-init one-shot), not just the TLS
    listener: an authenticated 200 proves both."""
    script = root / "scripts" / "bootstrap-opensearch.sh"
    if not script.exists():
        warn("bootstrap-opensearch.sh missing; skipping")
        return
    # Hit the cluster from inside via docker exec since :9200 isn't exposed.
    compose_dir = root / "deployment" / "docker"
    if tls:
        # opensearch-security-init needs OS healthy + securityadmin runtime
        # (~40s); 90 attempts x 2s bounds the wait at 3 minutes.
        ready_sh = (
            "for i in $(seq 1 90); do "
            'curl -sf --cacert /usr/share/opensearch/config/tls/ca.pem '
            '-u "svc_bootstrap:$OS_BOOTSTRAP_PASSWORD" '
            "https://opensearch:9200/_cluster/health >/dev/null && exit 0; "
            "sleep 2; done; exit 1"
        )
        cmd = ["docker", "compose", "exec", "-T",
               "--env", "OS_BOOTSTRAP_PASSWORD",
               "opensearch", "bash", "-c", ready_sh]
    else:
        cmd = [
            "docker", "compose", "exec", "-T", "opensearch",
            "bash", "-lc",
            "for i in $(seq 1 30); do "
            "curl -sf http://localhost:9200/_cluster/health >/dev/null && break; "
            "sleep 2; done; echo opensearch ready",
        ]
    env = {**os.environ}
    if tls:
        env["OS_BOOTSTRAP_PASSWORD"] = _parse_env(
            compose_dir / ".env").get("OS_BOOTSTRAP_PASSWORD", "")
        if not env["OS_BOOTSTRAP_PASSWORD"]:
            warn("OS_BOOTSTRAP_PASSWORD missing from .env — cannot bootstrap "
                 "templates on a secured cluster; re-run the installer")
            return
    res = subprocess.run(cmd, cwd=str(compose_dir), env=env,
                         capture_output=True, text=True)
    if res.returncode != 0:
        warn(f"opensearch not ready (skipping templates): {res.stderr.strip()}")
        info("re-run after a minute: scripts/bootstrap-opensearch.sh")
        return
    if tls:
        _bootstrap_opensearch_via_exec(root, tls=True)
        return
    # Run the bootstrap from the host (it shells curl + python3 inline).
    res = subprocess.run(
        ["bash", str(script)],
        env={**os.environ, "OPENSEARCH_URL": "http://localhost:9200"},
        # OpenSearch isn't reachable on the host by default — we need
        # docker compose port forwarding OR we copy templates from inside.
        # For now, do it from inside the container.
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        # Fallback: apply each template via docker exec curl.
        warn("host-side bootstrap failed; falling back to docker exec")
        _bootstrap_opensearch_via_exec(root)
        return
    ok("index templates applied")


def _bootstrap_opensearch_via_exec(root: Path, tls: bool = False) -> None:
    """Apply index templates from inside the opensearch container.

    TLS (SEC-008): https + svc_bootstrap basic auth, CA-validated. The
    credential is expanded from the exec's OWN environment inside `sh -c`
    (never on argv), and the template body arrives on stdin (`-d @-`)."""
    import json as _json
    compose_dir = root / "deployment" / "docker"
    tpl_path = root / "deployment" / "docker" / "opensearch" / "index-templates.json"
    if not tpl_path.exists():
        warn("index-templates.json missing")
        return
    env = {**os.environ}
    if tls:
        env["OS_BOOTSTRAP_PASSWORD"] = _parse_env(
            compose_dir / ".env").get("OS_BOOTSTRAP_PASSWORD", "")
    data = _json.loads(tpl_path.read_text())
    for name, body in (data.get("templates") or {}).items():
        # §3: the name is interpolated into a shell line below — refuse
        # anything that isn't a plain index-template identifier.
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            warn(f"template name {name!r} is not a valid identifier; skipping")
            continue
        body_json = _json.dumps(body)
        if tls:
            put_sh = (
                'curl -sf --cacert /usr/share/opensearch/config/tls/ca.pem '
                '-u "svc_bootstrap:$OS_BOOTSTRAP_PASSWORD" -X PUT '
                f'"https://opensearch:9200/_index_template/{name}" '
                '-H "Content-Type: application/json" -d @-'
            )
            cmd = ["docker", "compose", "exec", "-T",
                   "--env", "OS_BOOTSTRAP_PASSWORD",
                   "opensearch", "sh", "-c", put_sh]
            res = subprocess.run(cmd, cwd=str(compose_dir), env=env,
                                 input=body_json, capture_output=True, text=True)
        else:
            cmd = [
                "docker", "compose", "exec", "-T", "opensearch",
                "curl", "-sf", "-X", "PUT",
                f"http://localhost:9200/_index_template/{name}",
                "-H", "Content-Type: application/json",
                "-d", body_json,
            ]
            res = subprocess.run(cmd, cwd=str(compose_dir),
                                 capture_output=True, text=True)
        if res.returncode == 0:
            ok(f"template applied: {name}")
        else:
            warn(f"template {name}: {res.stderr.strip()}")


# Postgres identifiers this installer will interpolate into SQL/shell. Both
# values come from the operator's .env — validate at the boundary (§3) instead
# of trusting them into a quoted string.
_PG_IDENT = re.compile(r"^[A-Za-z0-9_]+$")


def bootstrap_keycloak_db(compose_dir: Path, env: dict) -> None:
    """Create Keycloak's database when the `sso` profile is active.

    Keycloak does not create its own DB: without this it crash-loops on first
    boot with `FATAL: database "keycloak" does not exist` (hit on the first
    real SSO bring-up, 2026-08-03 — docs/runbooks/okta-sso-setup.md §1).
    install.py owns first-boot provisioning, so it owns this too. Idempotent
    (SELECT-then-CREATE); non-fatal like the other bootstrap steps — the rest
    of the stack is healthy without Keycloak — but loud, with the manual
    command, because Keycloak stays in a crash-loop until the DB exists."""
    user = env.get("DB_USER", "netops")
    db = env.get("KEYCLOAK_DB_NAME", "keycloak")
    manual = f"docker compose exec postgres createdb -U {user} {db}"
    if not _PG_IDENT.match(user) or not _PG_IDENT.match(db):
        # Deliberately NOT echoed into a suggested command — a copy-pasted shell
        # line containing the unvalidated value is exactly the injection this
        # guard exists to prevent.
        warn("DB_USER/KEYCLOAK_DB_NAME contain characters this step will not "
             "interpolate into SQL ([A-Za-z0-9_] only) — fix them in .env and "
             "re-run, or create the database manually")
        return
    # Bounded readiness wait (the postgres container may still be starting on a
    # first boot), then the existence probe. -tAc → bare "1" when the row exists.
    probe = [
        "docker", "compose", "exec", "-T", "postgres", "bash", "-lc",
        f"for i in $(seq 1 30); do pg_isready -q -U {user} && break; sleep 2; done; "
        f"psql -U {user} -d postgres -tAc "
        f"\"SELECT 1 FROM pg_database WHERE datname='{db}'\"",
    ]
    res = subprocess.run(probe, cwd=str(compose_dir), capture_output=True,
                         text=True, timeout=120)
    if res.returncode != 0:
        warn(f"could not check for the {db} database (Keycloak will crash-loop "
             f"until it exists): {res.stderr.strip()}")
        info(f"re-run install.py once postgres is healthy, or run: {manual}")
        return
    if res.stdout.strip() == "1":
        ok(f"keycloak database '{db}' already exists")
        return
    create = [
        "docker", "compose", "exec", "-T", "postgres",
        "psql", "-U", user, "-d", "postgres",
        "-c", f'CREATE DATABASE "{db}" OWNER "{user}"',
    ]
    res = subprocess.run(create, cwd=str(compose_dir), capture_output=True,
                         text=True, timeout=60)
    if res.returncode != 0:
        warn(f"creating the {db} database failed (Keycloak will crash-loop "
             f"until it exists): {res.stderr.strip()}")
        info(f"create it manually: {manual}")
        return
    ok(f"keycloak database '{db}' created (owner {user})")


def bootstrap_grafana(root: Path, secrets_map: dict) -> None:
    """Enable Grafana's ClickHouse datasource: (1) create a read-only,
    tenant-scoped ClickHouse user the datasource binds to, and (2) install the
    grafana-clickhouse-datasource plugin into the bind-mounted plugins dir,
    falling back to an insecure fetch on TLS-intercepted networks. Non-fatal —
    the Prometheus/VictoriaMetrics dashboards work without any of this."""
    compose_dir = root / "deployment" / "docker"
    env_path = compose_dir / ".env"
    env = _parse_env(env_path) if env_path.exists() else {}

    # 1. Ensure GRAFANA_CH_PASSWORD exists (installs predating this step won't
    #    have it in their .env). Append so the grafana container picks it up.
    ch_pw = (secrets_map.get("GRAFANA_CH_PASSWORD") or env.get("GRAFANA_CH_PASSWORD") or "").strip()
    if not ch_pw:
        ch_pw = generate_password(24)
        with env_path.open("a") as f:
            f.write("\n# Read-only ClickHouse user for Grafana (added on upgrade).\n"
                    f"GRAFANA_CH_PASSWORD={ch_pw}\n")
        info("added GRAFANA_CH_PASSWORD to .env")

    # 2. Create / update the read-only ClickHouse user. tenant_scope='' is pinned
    #    CONST so the row policies on netops.* return only untagged platform/infra
    #    rows — the user cannot widen its own scope even if a query tries. Runs
    #    through the shared reconciler: idempotent, verified with the new
    #    credential, and it keeps both passwords off the host command line (they
    #    used to ride in the docker CLI argv, visible to any `ps` on the host).
    sr = _rotation_module()
    admin_pw = (secrets_map.get("CLICKHOUSE_PASSWORD") or env.get("CLICKHOUSE_PASSWORD") or "").strip()
    admin_user = env.get("CLICKHOUSE_USER", "netops")
    done, msg = sr.reconcile_grafana_ch_user(
        ComposeRunner(compose_dir), admin_user=admin_user,
        admin_password=admin_pw, grafana_password=ch_pw)
    if not done:
        warn(f"grafana ClickHouse user not created (skipping): {msg}")
        info("re-run install.py once ClickHouse is healthy to finish Grafana wiring")
        return
    ok("read-only Grafana ClickHouse user ready (tenant_scope='' pinned)")

    # 3. Install the datasource plugin into the bind-mounted plugins dir. Try the
    #    normal (verified) path first; fall back to --insecure for networks that
    #    MITM grafana.com. The plugin ships signed, so Grafana loads it either way.
    plug = "grafana-clickhouse-datasource"
    base = ["docker", "compose", "exec", "-T", "grafana", "grafana", "cli",
            "--pluginsDir", "/var/lib/grafana/plugins", "plugins", "install", plug]
    r = subprocess.run(base, cwd=str(compose_dir), capture_output=True, text=True)
    if r.returncode != 0:
        info("plugin download failed verified; retrying with --insecure (TLS-intercepted network)")
        r = subprocess.run(
            ["docker", "compose", "exec", "-T", "grafana", "grafana", "cli", "--insecure",
             "--pluginsDir", "/var/lib/grafana/plugins", "plugins", "install", plug],
            cwd=str(compose_dir), capture_output=True, text=True)
    if r.returncode != 0:
        warn(f"ClickHouse plugin not installed: {r.stderr.strip() or r.stdout.strip()}")
        info("flow/findings dashboards will be unavailable until the plugin installs")
        return
    ok("grafana-clickhouse-datasource installed")

    # 4. Recreate Grafana so it loads the plugin, the ClickHouse datasource, and
    #    the (possibly newly added) GRAFANA_CH_PASSWORD env.
    subprocess.run(["docker", "compose", "up", "-d", "grafana"],
                   cwd=str(compose_dir), check=False)
    ok("grafana reloaded with ClickHouse datasource + flow/findings dashboards")


# ---- main -------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Install the NetOps Observability stack.")
    ap.add_argument("--port", type=int, default=int(os.environ.get("BASE_PORT", "8000")),
                    help="Host port the dashboard listens on (default 8000).")
    ap.add_argument("--no-start", action="store_true",
                    help="Generate config but don't run docker compose up.")
    ap.add_argument("--reset-env", action="store_true",
                    help="Rotate secrets. On an install that has never started this "
                         "regenerates .env wholesale; on a started install it rotates "
                         "in place (reconciling the live stores) and REFUSES, changing "
                         "nothing, for any secret it cannot rotate for real.")
    ap.add_argument("--rotate-app-secrets", action="store_true",
                    help="Rotate only the secrets that can be rotated safely right now "
                         "(application secrets + live store credentials this tool can "
                         "reconcile and verify); keep the rest. Then exit.")
    ap.add_argument("--rotate-kafka-cluster-id", action="store_true",
                    help="DESTRUCTIVE opt-in: also rotate KAFKA_CLUSTER_ID, moving "
                         "data/kafka aside (discards every topic/offset on the "
                         "embedded bus). Only meaningful with --reset-env or "
                         "--rotate-app-secrets.")
    ap.add_argument("--assume-yes", action="store_true",
                    help="Answer yes to the destructive-rotation confirmation "
                         "(non-interactive runs otherwise refuse).")
    ap.add_argument("--offline", action="store_true",
                    help="Air-gapped install: start from pre-loaded images, never build or pull.")
    ap.add_argument("--bundle", type=Path, default=None, metavar="IMAGES.tar.zst",
                    help="Image archive from make-installer.sh to docker-load first (implies --offline).")
    ap.add_argument("--profiles", default=DEFAULT_PROFILES, metavar="CSV",
                    help=f"Compose profiles to activate (default: {DEFAULT_PROFILES}). "
                         "Customer bundle installs use 'embedded-bus,prober' (add-ons enable more).")
    ap.add_argument("--retention-profile", default="production",
                    choices=["lab", "demo", "production", "extended"],
                    help="correlation history retention profile written to .env "
                         "(#101: hot TTLs + cold Parquet export; default: production)")
    # #102/#119: DEFAULT-ON, matching the customer bundle (install-correlix.sh
    # passes --plan-resources unless CORRELIX_NO_SIZING=1). A dev install and a
    # customer install now size the same way by default, so the sizing path is
    # exercised continuously instead of only on customer hosts. Opt out with
    # --no-plan-resources or CORRELIX_NO_SIZING=1.
    ap.add_argument("--plan-resources", nargs="?", const="auto",
                    default=("auto" if os.environ.get("CORRELIX_NO_SIZING", "0") != "1" else None),
                    metavar="PROFILE",
                    help="Generate host/workload-derived resource limits into a "
                         "managed .env block via scripts/resource_planner.py (#102). "
                         "PROFILE = demo|small|medium|large|custom; 'auto' (bare "
                         "flag, and the default) picks by detected host RAM.")
    ap.add_argument("--no-plan-resources", action="store_const", const=None,
                    dest="plan_resources",
                    help="Skip resource planning; keep the static compose defaults "
                         "(equivalent to CORRELIX_NO_SIZING=1).")
    ap.add_argument("--tls", choices=["yes", "no"], default=None,
                    help="Enable the full TLS/mTLS transport mesh (tracker #151): "
                         "ingress TLS, nginx→api mTLS, all stores, Kafka mTLS+ACL "
                         "listeners, Vector lanes, sealed CA custody. Interactive "
                         "installs are asked ([Y/n]); unattended runs without this "
                         "flag keep the declared-plaintext baseline.")
    ap.add_argument("--sizing-file", type=Path, default=None, metavar="YAML",
                    help="correlix-sizing.yaml workload inputs for --plan-resources.")
    ap.add_argument("--replan", action="store_true",
                    help="Only regenerate the resource-plan block in the existing "
                         ".env, then exit (run 'docker compose up -d' to apply).")
    ap.add_argument("--rollback-plan", action="store_true",
                    help="Restore .env from the pre-replan backup, then exit.")
    ap.add_argument("--broker-urls", default=None, metavar="HOST:PORT[,HOST:PORT...]",
                    help="ADVANCED: use an external Kafka-compatible broker instead of the "
                         "embedded one. Disables the embedded-bus profile and points every "
                         "service at this bootstrap list.")
    args = ap.parse_args()
    if args.bundle:
        args.offline = True

    # External-broker mode: the embedded Kafka must not start, and the
    # bootstrap list must actually be usable. Reachability is best-effort
    # advisory (the broker may be firewalled from the installer shell but
    # reachable from containers) — an empty value is the hard error.
    if args.broker_urls is not None:
        args.broker_urls = args.broker_urls.strip()
        if not args.broker_urls:
            fail("--broker-urls needs a value, e.g. --broker-urls broker1:9092,broker2:9092")
        args.profiles = ",".join(
            p for p in args.profiles.split(",") if p.strip() and p.strip() != "embedded-bus")
        first = args.broker_urls.split(",")[0].strip()
        host, _, port = first.partition(":")
        try:
            with socket.create_connection((host, int(port or "9092")), timeout=5):
                ok(f"external broker reachable: {first}")
        except (OSError, ValueError) as e:
            warn(f"could not reach external broker {first} from this shell ({e}) — "
                 "continuing; services will retry from inside the network")

    # Project root = parent of `scripts/` containing this file.
    root = Path(__file__).resolve().parent.parent
    compose_dir = root / "deployment" / "docker"
    env_path = compose_dir / ".env"

    # Standalone resource-plan operations (#102) — no install steps.
    if args.rollback_plan:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import resource_planner as rp
        paths = rp.plan_backup_paths(env_path)
        env_bak = paths[str(env_path.resolve())]
        if not os.path.exists(env_bak):
            fail(f"no plan backup found at {env_bak}")
        restored = []
        for src, bak in paths.items():
            if os.path.exists(bak):
                Path(src).write_text(Path(bak).read_text())
                os.chmod(src, 0o600)
                restored.append(os.path.basename(src))
        ok(f"restored {', '.join(restored)} from .plan.bak backups — "
           "run 'docker compose up -d' to apply")
        return
    if args.replan:
        if not env_path.exists():
            fail(".env not found — run a full install first")
        run_resource_plan(env_path, args.plan_resources or "auto", args.sizing_file)
        info("replan complete — apply with: cd deployment/docker && docker compose up -d")
        return

    # Standalone rotation (#FUNC-HIGH-1): rotate what is safely rotatable and
    # leave everything else — including every operator edit in .env — alone.
    if args.rotate_app_secrets:
        step("rotating secrets in place")
        sr = _rotation_module()
        # Reconciling a live store needs the compose CLI. Only demand it when
        # something has actually started — a pre-start rotation is file-only.
        if env_path.exists() and sr.install_started(
                root, _parse_env(env_path).get("COMPOSE_PROFILES", "")):
            check_docker()
        _rotated, failures = rotate_secrets(
            root, compose_dir, env_path, strict=False,
            allow_kafka_wipe=args.rotate_kafka_cluster_id,
            assume_yes=args.assume_yes)
        print()
        info("apply the new values (recreates the services that consume them):")
        info("    cd deployment/docker && docker compose up -d --force-recreate")
        if failures:
            fail(f"{failures} secret(s) could not be rotated (details above)")
        return

    step("checking prerequisites")
    check_docker()

    step("validating scaffold")
    validate_scaffold(root)

    step("generating environment")
    # --reset-env on a STARTED install is a rotation, not a regeneration: the
    # stores already hold most of these credentials, and rewriting the template
    # would also revert every operator setting in .env.
    sr = _rotation_module()
    if args.reset_env and env_path.exists() and sr.install_started(
            root, _parse_env(env_path).get("COMPOSE_PROFILES", "")):
        info("this install has already started — rotating in place "
             "(see docs/runbooks/secret-rotation.md)")
        secrets_map, failures = rotate_secrets(
            root, compose_dir, env_path, strict=True,
            allow_kafka_wipe=args.rotate_kafka_cluster_id,
            assume_yes=args.assume_yes)
        if failures:
            fail(f"{failures} secret(s) could not be rotated (details above)")
    else:
        if args.reset_env and args.rotate_kafka_cluster_id:
            info("nothing has started yet — KAFKA_CLUSTER_ID rotates with the "
                 "rest; no data to discard")
        secrets_map = write_env(env_path, args.port, force=args.reset_env,
                                profiles=args.profiles, broker_urls=args.broker_urls,
                                retention_profile=args.retention_profile)

    if args.plan_resources:
        step("planning resources (#102)")
        run_resource_plan(env_path, args.plan_resources, args.sizing_file)

    # The one transport-security question (tracker #151 delivery shape).
    # Resolved AFTER .env exists so both fresh and existing installs converge
    # through the same line-surgery path; the actual activation is two-phase
    # around compose_up below.
    tls_enabled = resolve_tls_choice(args)
    if tls_enabled:
        step("enabling TLS/mTLS transport security")
        enable_tls_env(env_path)
        augment_profiles_for_tls(env_path)
        ensure_ingress_cert(root)

    step("preparing data directories")
    ensure_data_dirs(root)

    if args.no_start:
        if tls_enabled:
            ok(".env and data/ ready with TLS variables set. compose.tls.yml is "
               "NOT yet activated (the two-phase mint needs a running stack) — "
               "rerun without --no-start to complete enablement.")
        else:
            ok(".env and data/ ready. Skipping docker compose up (per --no-start).")
        return

    if args.bundle:
        step("loading image bundle")
        load_bundle(args.bundle)

    if args.offline:
        write_offline_override(compose_dir, env_path)

    # Phase A (TLS): the baseline stack boots with the mint variables set; the
    # api's internal CA writes every SVID to data/tls while the stores are
    # still plaintext. On a rerun with certs already minted this converges in
    # one pass (the sentinels exist, the variant is already in the chain).
    step("starting stack" + (" (TLS phase A: mint identities)" if tls_enabled else ""))
    compose_up(compose_dir, offline=args.offline, root=root)

    if tls_enabled:
        wait_for_minted_certs(root)
        activate_tls_compose_file(compose_dir, env_path)
        step("starting stack (TLS phase B: fail-closed mesh)")
        compose_up(compose_dir, offline=args.offline, root=root)

    step("status")
    compose_status(compose_dir)

    step("bootstrap OpenSearch index templates")
    bootstrap_opensearch(root, tls=tls_enabled)

    # Gate on the EFFECTIVE profiles from .env — the source of truth compose_up
    # starts from — not args.profiles, which an existing install's .env ignores.
    active = {p.strip() for p in
              _parse_env(env_path).get("COMPOSE_PROFILES", "").split(",")}
    if "sso" in active:
        step("bootstrap Keycloak database (profile sso)")
        bootstrap_keycloak_db(compose_dir, _parse_env(env_path))

    if "self-monitoring" in args.profiles:
        step("wiring grafana clickhouse datasource")
        bootstrap_grafana(root, secrets_map)

    print()
    print("==============================================================")
    if tls_enabled:
        # compose.tls.yml publishes the TLS ingress on 443; the plaintext
        # port stays alongside during the migration window (see the nginx
        # NOTE in compose.tls.yml — it is removed together with this
        # messaging becoming the only path).
        print("  Dashboard: https://localhost/   (TLS ingress, port 443)")
        print("  API:       https://localhost/api/")
        print("  Health:    https://localhost/admin/health")
        print(f"             (plaintext http://localhost:{args.port} remains "
              "during the migration window)")
        print()
        print("  The ingress certificate is SELF-SIGNED (gen-dev-cert.sh) —")
        print("  your browser will warn once; replace the files under")
        print("  deployment/docker/nginx/certs/ with a real certificate for")
        print("  production (same filenames, then: docker compose restart nginx).")
    else:
        print(f"  Dashboard: http://localhost:{args.port}")
        print(f"  API:       http://localhost:{args.port}/api/")
        print(f"  Health:    http://localhost:{args.port}/admin/health")
    print()
    if "ADMIN_INITIAL_PASSWORD" in secrets_map:
        print("  First-time sign-in to the dashboard:")
        print(f"    user: admin")
        print(f"    pass: (see ADMIN_INITIAL_PASSWORD in {env_path})")
        print(f"    -> Change it on Settings > Change password.")
    if "GRAFANA_ADMIN_PASSWORD" in secrets_map:
        print()
        print("  First-time Grafana login (separate from app auth):")
        print(f"    user: admin")
        print(f"    pass: (see GRAFANA_ADMIN_PASSWORD in {env_path})")
    print()
    print("  Stop:      cd deployment/docker && docker compose down")
    print("  Logs:      cd deployment/docker && docker compose logs -f")
    print("==============================================================")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        fail(f"command failed (exit {e.returncode}): {' '.join(e.cmd)}")
    except KeyboardInterrupt:
        print()
        fail("interrupted")
