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
import os
import secrets
import shutil
import string
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

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
    "src/frontend/src/tabs/Topology.tsx",
    "src/frontend/src/tabs/Copilot.tsx",
    "src/frontend/src/tabs/Findings.tsx",
    # Correlation/AI service
    "src/correlation/main.py",
    "src/correlation/requirements.txt",
    # Config templates
    "src/config/config.yaml",
    "src/config/rules.yaml",
    "src/config/devices.yaml",
    "src/config/prometheus.yml",
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

def write_env(env_path: Path, port: int, *, force: bool) -> dict[str, str]:
    if env_path.exists() and not force:
        info(f".env already exists at {env_path} — keeping existing secrets")
        return _parse_env(env_path)

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
    }

    body = f"""# NetOps Observability — environment.
# Generated by scripts/install.py at {datetime.now(timezone.utc).isoformat()}.
#
# Treat this file as a secret. Do not commit it. Re-run install.py with
# --reset-env to roll a new copy.

BASE_PORT={port}

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
# Read-only ClickHouse user Grafana's provisioned ClickHouse datasource binds to.
# Its CH profile pins tenant_scope='' (readonly CONST) so it sees only untagged
# platform/infra rows — never another tenant's data. Created by bootstrap_grafana.
GRAFANA_CH_PASSWORD={secrets_map["GRAFANA_CH_PASSWORD"]}

# Application secrets
JWT_SECRET={secrets_map["JWT_SECRET"]}
ENCRYPTION_KEY={secrets_map["ENCRYPTION_KEY"]}

# Feature toggles
ENABLE_SNMP_DISCOVERY=true
SNMP_CIDR_RANGES=10.0.0.0/8
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

# AI Copilot (chat pane in the dashboard). Leave FEATURE_COPILOT=false
# to disable. Provider: 'gemini' (default — free tier), 'anthropic' or 'openai';
# the key is usually pasted in the assistant settings UI instead of here.
FEATURE_COPILOT=false
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

# Redpanda client ports (host side). Devices and external producers
# can publish directly to REDPANDA_KAFKA_PORT if you ever skip Vector.
REDPANDA_KAFKA_PORT=19092
REDPANDA_PROXY_PORT=18082
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
        prometheus  65534 (nobody)
        grafana       472 (grafana)
        opensearch   1000 (opensearch)
        clickhouse    101 (clickhouse)
        victoria     1000
        redpanda      101
    The other services (postgres, redis, api correlation store) either
    chown their own data dirs on first boot or write as root."""
    owners: dict[str, tuple[int, int] | None] = {
        "postgres":   None,             # initdb chowns its own
        "redis":      None,             # writes as redis user via its own init
        "victoria":   (1000, 1000),
        "grafana":    (472, 472),
        "prometheus": (65534, 65534),
        "redpanda":   (101, 101),
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

def compose_up(compose_dir: Path) -> None:
    info("building and starting services (this can take a few minutes the first time)…")
    # --profile osd brings up OpenSearch Dashboards alongside the base stack so the
    # platform-admin /search route is served rather than 502-ing (nginx still
    # graceful-degrades if it's later stopped). The "sso" profile (Keycloak) stays
    # opt-in. Profiles are additive: non-profiled services always start.
    subprocess.run(
        ["docker", "compose", "--profile", "osd", "up", "-d", "--build"],
        cwd=str(compose_dir),
        check=True,
    )
    ok("services started")


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
    args = ap.parse_args()

    # Project root = parent of `scripts/` containing this file.
    root = Path(__file__).resolve().parent.parent
    compose_dir = root / "deployment" / "docker"
    env_path = compose_dir / ".env"

    step("checking prerequisites")
    check_docker()

    step("validating scaffold")
    validate_scaffold(root)

    step("generating environment")
    secrets_map = write_env(env_path, args.port, force=args.reset_env)

    step("preparing data directories")
    ensure_data_dirs(root)

    if args.no_start:
        ok(".env and data/ ready. Skipping docker compose up (per --no-start).")
        return

    step("starting stack")
    compose_up(compose_dir)

    step("status")
    compose_status(compose_dir)

    step("bootstrap OpenSearch index templates")
    bootstrap_opensearch(root)

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
