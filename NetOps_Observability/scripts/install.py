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

Usage:
    python3 install.py [--port 8000] [--no-start] [--reset-env]
"""

from __future__ import annotations

import argparse
import base64
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
DEFAULT_PROFILES = "embedded-bus,prober,osd,self-monitoring"

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
    "src/backend/jwt.go",
    "src/backend/password.go",
    "src/backend/users.go",
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

# ---- .env generation --------------------------------------------------------

def write_env(env_path: Path, port: int, *, force: bool,
              profiles: str = DEFAULT_PROFILES,
              broker_urls: str | None = None) -> dict[str, str]:
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
        if additions:
            with env_path.open("a") as f:
                f.write("\n# ---- Event bus (Apache Kafka) — appended by install.py migration ----\n")
                f.write("\n".join(additions) + "\n")
            ok(f"migrated .env: added {', '.join(a.split('=')[0] for a in additions)}")
            env = _parse_env(env_path)
        return env

    # When forcing a fresh .env, also wipe the user store. Otherwise the
    # bootstrap admin keeps the password from the FIRST .env it was
    # seeded with, and the new ADMIN_INITIAL_PASSWORD in .env won't
    # unlock the dashboard. Removing users.json causes the api container
    # to re-seed on its next start with the current .env value.
    if force:
        users_file = env_path.parent.parent.parent / "data" / "api" / "users.json"
        if users_file.exists():
            try:
                users_file.unlink()
                info(f"removed {users_file} so admin re-seeds with new password")
            except OSError as e:
                warn(f"couldn't remove {users_file}: {e} (run scripts/reset-admin.sh later)")

    secrets_map = {
        "DB_PASSWORD":              generate_password(28),
        "JWT_SECRET":               generate_token(48),
        "ENCRYPTION_KEY":           generate_token(32),
        "GRAFANA_ADMIN_PASSWORD":   generate_password(20),
        "CLICKHOUSE_PASSWORD":      generate_password(24),
        "GRAFANA_CH_PASSWORD":      generate_password(24),
        "ADMIN_INITIAL_PASSWORD":   generate_password(16),
        "KEYCLOAK_ADMIN_PASSWORD":  generate_password(20),
        # Bundled (internal) NetBox source-of-truth.
        "NETBOX_SECRET_KEY":         generate_token(40),    # >=50 url-safe chars
        "NETBOX_DB_PASSWORD":        generate_password(24),
        "NETBOX_SUPERUSER_PASSWORD": generate_password(20),
        "NETBOX_TOKEN":              secrets.token_hex(20),  # 40-hex NetBox API token
        # KRaft storage id for the embedded Kafka broker (22-char base64url
        # uuid, same format kafka-storage random-uuid emits). Generated ONCE
        # per install: the data dir is formatted with it, and a changed id
        # would make the broker refuse its own volume on recreation.
        "KAFKA_CLUSTER_ID":          base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="),
    }

    body = f"""# NetOps Observability — environment.
# Generated by scripts/install.py at {datetime.now(timezone.utc).isoformat()}.
#
# Treat this file as a secret. Do not commit it. Re-run install.py with
# --reset-env to roll a new copy.

BASE_PORT={port}

# Containers that write bind-mounted data/ dirs (api, grafana add-on) run as
# THIS user, so no sudo/chown is ever needed. Written once at install.
CORRELIX_UID={os.getuid()}
CORRELIX_GID={os.getgid()}

# Initial admin user. The API creates this on first start (only if the
# user store is empty), then never again. Change the password from the
# Settings tab in the dashboard; `--reset-env` does NOT rotate it.
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

# SSO — OIDC/SAML/LDAP brokered by Keycloak (opt-in). The Go API only verifies
# the resulting tokens (stdlib RS256/JWKS), so the backend stays dependency-free.
# To enable: create the keycloak DB once
#   docker compose exec postgres createdb -U $DB_USER keycloak
# then `docker compose --profile sso up -d keycloak`, configure a realm + OIDC
# client, and set OIDC_ENABLED=true with the values below. See docs/IDENTITY_ACCESS.md.
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
# start — the broker's data dir is formatted with this id.
KAFKA_CLUSTER_ID={secrets_map["KAFKA_CLUSTER_ID"]}

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
        "clickhouse": (101, 101),
        "api":        None,             # Go API runs as nonroot but writes JSON only
        "secrets-seal": None,           # #17 sealing-sidecar socket dir (root-owned; opt-in 'seal' profile)
        "swtpm":      None,             # #17 software-TPM state (sealed KEK objects); root-owned
        "netbox-postgres": None,        # bundled-NetBox DB (opt-in 'netbox' profile); initdb self-chowns
        "netbox-media":    None,        # bundled-NetBox media (opt-in 'netbox' profile)
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


def compose_up(compose_dir: Path, offline: bool = False) -> None:
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
    last = 1
    for attempt in range(1, 4):
        r = subprocess.run(["docker", "compose", "up", "-d", build_flag],
                           cwd=str(compose_dir))
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


def bootstrap_opensearch(root: Path) -> None:
    """Apply index templates after the stack is up. Non-fatal on error —
    OpenSearch may still be starting; the user can re-run the script."""
    script = root / "scripts" / "bootstrap-opensearch.sh"
    if not script.exists():
        warn("bootstrap-opensearch.sh missing; skipping")
        return
    # Hit the cluster from inside via docker exec since :9200 isn't exposed.
    compose_dir = root / "deployment" / "docker"
    cmd = [
        "docker", "compose", "exec", "-T", "opensearch",
        "bash", "-lc",
        "for i in $(seq 1 30); do "
        "curl -sf http://localhost:9200/_cluster/health >/dev/null && break; "
        "sleep 2; done; echo opensearch ready",
    ]
    res = subprocess.run(cmd, cwd=str(compose_dir), capture_output=True, text=True)
    if res.returncode != 0:
        warn(f"opensearch not ready (skipping templates): {res.stderr.strip()}")
        info("re-run after a minute: scripts/bootstrap-opensearch.sh")
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


def _bootstrap_opensearch_via_exec(root: Path) -> None:
    """Apply index templates from inside the opensearch container."""
    import json as _json
    compose_dir = root / "deployment" / "docker"
    tpl_path = root / "deployment" / "docker" / "opensearch" / "index-templates.json"
    if not tpl_path.exists():
        warn("index-templates.json missing")
        return
    data = _json.loads(tpl_path.read_text())
    for name, body in (data.get("templates") or {}).items():
        body_json = _json.dumps(body)
        cmd = [
            "docker", "compose", "exec", "-T", "opensearch",
            "curl", "-sf", "-X", "PUT",
            f"http://localhost:9200/_index_template/{name}",
            "-H", "Content-Type: application/json",
            "-d", body_json,
        ]
        res = subprocess.run(cmd, cwd=str(compose_dir), capture_output=True, text=True)
        if res.returncode == 0:
            ok(f"template applied: {name}")
        else:
            warn(f"template {name}: {res.stderr.strip()}")


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
    #    rows — the user cannot widen its own scope even if a query tries. Run as
    #    the admin (netops) user; password embedded is safe (generator alphabet
    #    has no quote/backslash) but we double single-quotes defensively.
    admin_pw = (secrets_map.get("CLICKHOUSE_PASSWORD") or env.get("CLICKHOUSE_PASSWORD") or "").strip()
    admin_user = env.get("CLICKHOUSE_USER", "netops")
    esc = ch_pw.replace("'", "''")
    sql = (
        f"CREATE USER IF NOT EXISTS grafana IDENTIFIED BY '{esc}';\n"
        f"ALTER USER grafana IDENTIFIED BY '{esc}' "
        f"SETTINGS tenant_scope = '' CONST, readonly = 2;\n"
        "GRANT SELECT ON netops.flows TO grafana;\n"
        "GRANT SELECT ON netops.findings TO grafana;\n"
        "GRANT SELECT ON netops.tunnels TO grafana;\n"
    )
    res = subprocess.run(
        ["docker", "compose", "exec", "-T", "clickhouse",
         "clickhouse-client", "--user", admin_user, "--password", admin_pw,
         "--multiquery"],
        cwd=str(compose_dir), input=sql, capture_output=True, text=True,
    )
    if res.returncode != 0:
        warn(f"grafana ClickHouse user not created (skipping): {res.stderr.strip()}")
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
                    help="Regenerate .env (rotates secrets).")
    ap.add_argument("--offline", action="store_true",
                    help="Air-gapped install: start from pre-loaded images, never build or pull.")
    ap.add_argument("--bundle", type=Path, default=None, metavar="IMAGES.tar.zst",
                    help="Image archive from make-installer.sh to docker-load first (implies --offline).")
    ap.add_argument("--profiles", default=DEFAULT_PROFILES, metavar="CSV",
                    help=f"Compose profiles to activate (default: {DEFAULT_PROFILES}). "
                         "Customer bundle installs use 'embedded-bus,prober' (add-ons enable more).")
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

    step("checking prerequisites")
    check_docker()

    step("validating scaffold")
    validate_scaffold(root)

    step("generating environment")
    secrets_map = write_env(env_path, args.port, force=args.reset_env,
                            profiles=args.profiles, broker_urls=args.broker_urls)

    step("preparing data directories")
    ensure_data_dirs(root)

    if args.no_start:
        ok(".env and data/ ready. Skipping docker compose up (per --no-start).")
        return

    if args.bundle:
        step("loading image bundle")
        load_bundle(args.bundle)

    if args.offline:
        write_offline_override(compose_dir, env_path)

    step("starting stack")
    compose_up(compose_dir, offline=args.offline)

    step("status")
    compose_status(compose_dir)

    step("bootstrap OpenSearch index templates")
    bootstrap_opensearch(root)

    if "self-monitoring" in args.profiles:
        step("wiring grafana clickhouse datasource")
        bootstrap_grafana(root, secrets_map)

    print()
    print("==============================================================")
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
