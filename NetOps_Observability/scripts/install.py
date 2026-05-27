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

    secrets_map = {
        "DB_PASSWORD":              generate_password(28),
        "JWT_SECRET":               generate_token(48),
        "ENCRYPTION_KEY":           generate_token(32),
        "GRAFANA_ADMIN_PASSWORD":   generate_password(20),
        "CLICKHOUSE_PASSWORD":      generate_password(24),
        "ADMIN_INITIAL_PASSWORD":   generate_password(16),
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

# Application secrets
JWT_SECRET={secrets_map["JWT_SECRET"]}
ENCRYPTION_KEY={secrets_map["ENCRYPTION_KEY"]}

# Netbox integration (optional — leave blank to disable)
NETBOX_URL=
NETBOX_TOKEN=

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

# AI Copilot (chat pane in the dashboard). Leave FEATURE_COPILOT=false
# to disable. Provider can be 'anthropic' or 'openai'.
FEATURE_COPILOT=false
COPILOT_PROVIDER=anthropic
COPILOT_API_KEY=
COPILOT_MODEL=claude-sonnet-4-5

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
    for name in (
        "postgres", "redis", "victoria", "grafana", "prometheus",
        "redpanda", "opensearch", "clickhouse", "api",
    ):
        (root / "data" / name).mkdir(parents=True, exist_ok=True)
    ok("data/ directories ready")


# ---- compose ----------------------------------------------------------------

def compose_up(compose_dir: Path) -> None:
    info("building and starting services (this can take a few minutes the first time)…")
    subprocess.run(
        ["docker", "compose", "up", "-d", "--build"],
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
