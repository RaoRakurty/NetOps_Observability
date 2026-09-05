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
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
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


def fail(msg: str) -> None:
    _stage_fail(msg)
    _timing_finish("fail")
    print(f"[fail ] {msg}", file=sys.stderr)
    sys.exit(1)


def step(msg: str, stage: str | None = None) -> None:
    if stage is not None:
        _stage_start(stage, msg)
    print()
    print(f"=== {msg} ===")


# ---- GUI progress markers (design gui-installer-2026-08.md §6, phase P0) ----
# One ADDITIONAL stdout line per stage transition: `@CX@ {json}` — the human
# output is unchanged, parsers ignore non-marker lines. Activated by
# --progress-json or CORRELIX_PROGRESS_JSON=1 (set by the GUI when spawning).
# The terminal `result` marker carries url + admin_user ONLY — NEVER a
# password (the GUI reads credentials via its own trusted channel).

# Stage ids in contract order. `step(..., stage=)` call sites must use exactly
# these ids; tests/test_installer_gui_contract.py pins the set.
PROGRESS_STAGES = (
    "prereq", "scaffold", "env", "sizing", "tls-env", "data-dirs",
    "bundle", "up-a", "mint", "up-b", "kafka-acls", "status",
    "bootstrap-os", "bootstrap-kc", "bootstrap-grafana",
)

# Module state, not a hidden singleton: activation + the one currently-open
# stage, so the NEXT stage start (or the run end) closes it with "ok".
_PROGRESS: dict = {
    "on": os.environ.get("CORRELIX_PROGRESS_JSON", "") == "1",
    "stage": None,  # (id, title) of the open stage, or None
}

# ---- deployment-friction instrument (Project 2 G6) --------------------------
# Time-to-first-value is a product metric, not a feeling: every stage carries
# its own wall clock, each closing marker reports `elapsed_s`, and a run writes
# data/install-timing.json (total + per stage) so a pilot install can be
# MEASURED instead of remembered. `--time-report` prints the same table.
#
# Timing is collected whether or not --progress-json is on (the JSON file is
# the instrument; markers are the GUI's view of it). `record` gates the two
# terminal side effects — the summary marker and the file — to a real install
# run, so importing this module or calling fail() in a unit test writes
# nothing.
_TIMING: dict = {
    "t0": time.monotonic(),
    "open_t": None,           # monotonic start of the currently-open stage
    "stages": [],             # [{"id","title","status","elapsed_s"}]
    "record": False,          # set by main(): a real run may write the file
    "report": False,          # --time-report: print the table at the end
    "path": None,             # data/install-timing.json (resolved in main())
}


def _progress(obj: dict) -> None:
    """Emit one marker line, unbuffered (the GUI streams stdout live)."""
    if not _PROGRESS["on"]:
        return
    print("@CX@ " + json.dumps(obj, separators=(",", ":")), flush=True)


def _stage_elapsed() -> float:
    """Wall-clock seconds since the open stage started (0.0 if none is open)."""
    if _TIMING["open_t"] is None:
        return 0.0
    return round(time.monotonic() - _TIMING["open_t"], 3)


def _stage_record(sid: str, title: str, status: str, elapsed: float) -> None:
    _TIMING["stages"].append({"id": sid, "title": title, "status": status,
                              "elapsed_s": elapsed})
    _TIMING["open_t"] = None


def _stage_close_ok() -> None:
    if _PROGRESS["stage"] is not None:
        sid, title = _PROGRESS["stage"]
        _PROGRESS["stage"] = None
        elapsed = _stage_elapsed()
        _stage_record(sid, title, "ok", elapsed)
        _progress({"kind": "stage", "id": sid, "title": title, "status": "ok",
                   "elapsed_s": elapsed})


def _stage_start(sid: str, title: str) -> None:
    _stage_close_ok()
    _PROGRESS["stage"] = (sid, title)
    _TIMING["open_t"] = time.monotonic()
    _progress({"kind": "stage", "id": sid, "title": title, "status": "start"})


def _stage_fail(message: str) -> None:
    """fail() path: close the open stage as failed, then the terminal result."""
    if _PROGRESS["stage"] is not None:
        sid, title = _PROGRESS["stage"]
        _PROGRESS["stage"] = None
        elapsed = _stage_elapsed()
        _stage_record(sid, title, "fail", elapsed)
        _progress({"kind": "stage", "id": sid, "title": title,
                   "status": "fail", "message": message, "elapsed_s": elapsed})
    _progress({"kind": "result", "status": "fail"})


def _result_ok(url: str, admin_user: str) -> None:
    _stage_close_ok()
    _progress({"kind": "result", "status": "ok", "url": url,
               "admin_user": admin_user})


def _timing_doc(status: str) -> dict:
    return {
        "version": 1,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "total_s": round(time.monotonic() - _TIMING["t0"], 3),
        "stages": list(_TIMING["stages"]),
    }


def _print_time_report(doc: dict) -> None:
    print()
    print("=== install timing ===")
    print(f"  {'stage':<18} {'status':<7} {'elapsed_s':>10}")
    for st in doc["stages"]:
        print(f"  {st['id']:<18} {st['status']:<7} {st['elapsed_s']:>10.1f}")
    print(f"  {'TOTAL':<18} {doc['status']:<7} {doc['total_s']:>10.1f}")


def _timing_finish(status: str) -> None:
    """Terminal timing side effects: the summary marker, the JSON file and —
    with --time-report — the table. Never fatal: a run that installed the stack
    must not be reported as failed because a timing file could not be written,
    but the failure IS named (§16.1 — reported, never swallowed)."""
    if not _TIMING["record"]:
        return
    doc = _timing_doc(status)
    _progress({"kind": "timing", "status": doc["status"],
               "total_s": doc["total_s"],
               "stages": [{"id": s["id"], "status": s["status"],
                           "elapsed_s": s["elapsed_s"]} for s in doc["stages"]]})
    path = _TIMING["path"]
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(doc, indent=2) + "\n")
            os.replace(tmp, path)
        except OSError as e:
            warn(f"could not write the install timing file {path}: {e} "
                 "(the install itself is unaffected)")
    if _TIMING["report"]:
        _print_time_report(doc)

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
                           capture_output=True, text=True, timeout=10, check=False)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def generate_token(bytes_: int = 32) -> str:
    return secrets.token_urlsafe(bytes_)

# ---- prerequisite checks ----------------------------------------------------

def check_docker(bootstrap_docker: str | None = None) -> None:
    if shutil.which("docker") is None:
        _maybe_bootstrap_ubuntu("docker is not installed.", bootstrap_docker)
        # If the bootstrap ran, we still exit afterwards — the user must
        # re-login for the docker group to take effect. _maybe_bootstrap
        # never returns normally on a missing Docker.
        fail("docker is not installed. See https://docs.docker.com/get-docker/")

    res = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, text=True, check=False,
    )
    if res.returncode != 0:
        _maybe_bootstrap_ubuntu("Docker Compose v2 plugin is not available.",
                                bootstrap_docker)
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


def _maybe_bootstrap_ubuntu(reason: str, choice: str | None = None) -> None:
    """Offer to run scripts/bootstrap-ubuntu.sh when Docker is missing on
    a Debian-family host. Exits the installer afterwards either way —
    the user has to log out + back in for the docker group to take
    effect before re-running install.py.

    `choice` is the --bootstrap-docker flag ("yes"/"no"): like --tls in
    resolve_tls_choice, the flag WINS over the prompt so a non-TTY run is
    never blocked here. Without the flag, behavior is unchanged (interactive
    prompt; EOF means no)."""
    if not _is_debian_family():
        return  # caller will fall through to the generic fail() message
    here = Path(__file__).resolve().parent
    script = here / "bootstrap-ubuntu.sh"
    if not script.exists():
        return

    print()
    warn(reason)
    if choice is not None:
        info(f"--bootstrap-docker {choice} given — skipping the prompt")
        ans = "y" if choice == "yes" else "n"
    else:
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
    res = subprocess.run(["sudo", "bash", str(script), "--yes"], check=False)
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

# Web assets the `frontend` image COPYs in. They are BUILD ARTIFACTS, gitignored
# by design (deployment/docker/Dockerfile.frontend explains why: npm install
# inside the docker build hangs on container DNS/registry timeouts), so a clean
# clone has neither. Without this check `docker compose build frontend` fails
# deep inside BuildKit with
#     failed to compute cache key: "/src/frontend/dist": not found
# — which tells an evaluator nothing about what to do. Each entry is
# (path, what it is, how to build it).
#
# Checked ONLY when this run will actually build images: --offline / --bundle
# start from pre-loaded images (`--no-build`) and --no-start never reaches
# compose at all, so requiring the assets there would break the CI provisioning
# path (release-bundle.yml runs `install.py --no-start` on a runner with no npm).
PREBUILT_WEB_ASSETS = [
    ("src/frontend/dist",
     "the compiled React SPA",
     "cd src/frontend && npm ci --no-audit --no-fund && npm run build"),
    ("docs-portal/build",
     "the in-app documentation portal served at /docs/",
     "cd docs-portal && npm ci --no-audit --no-fund && npm run build"),
]


def validate_scaffold(root: Path, *, will_build: bool = True) -> None:
    missing = [p for p in REQUIRED_PATHS if not (root / p).exists()]
    if missing:
        for m in missing:
            warn(f"missing: {m}")
        fail("scaffold is incomplete — refusing to install. See warnings above.")
    ok(f"scaffold ok ({len(REQUIRED_PATHS)} required paths present)")
    if will_build:
        validate_prebuilt_web_assets(root)


def _is_populated_dir(path: Path) -> bool:
    """A directory that exists but is EMPTY fails the docker build identically.

    `npm run build` writing into a half-created tree, or a `rm -rf dist/*`, both
    leave the directory behind — so existence alone is not the contract.
    """
    if not path.is_dir():
        return False
    try:
        return any(path.iterdir())
    except OSError as exc:
        # §16.1: an UNREADABLE directory is not "missing". Reporting it as
        # missing would print an `npm run build` recipe that cannot fix a
        # permission problem, and the docker build would fail on the same
        # directory a second time. Refuse and name the real error.
        fail(f"cannot read {path}: {exc}\n"
             "The frontend image build reads this directory; fix its "
             "ownership/permissions and re-run this installer.")
        return False  # unreachable — fail() exits


def validate_prebuilt_web_assets(root: Path) -> None:
    missing = [(rel, what, how) for rel, what, how in PREBUILT_WEB_ASSETS
               if not _is_populated_dir(root / rel)]
    if not missing:
        ok(f"web assets present ({len(PREBUILT_WEB_ASSETS)} pre-built directories)")
        return
    for rel, what, _ in missing:
        warn(f"missing (or empty): {rel} — {what}")
    lines = [
        "pre-built web assets are missing — refusing to build.",
        "",
        "The frontend image COPYs these directories in; they are build",
        "artifacts and are deliberately NOT in git, so a fresh clone has to",
        "produce them once (needs Node 20+ and npm on this host):",
        "",
    ]
    for rel, _, how in missing:
        lines.append(f"    # {rel}")
        lines.append(f"    {how}")
    lines += [
        "",
        f"Run those from {root}, then re-run this installer (it is idempotent).",
        "",
        "Alternatives that need no Node:",
        "  * install from a customer bundle — `install.py --bundle IMAGES.tar.zst`",
        "    starts from pre-loaded images and never builds;",
        "  * `install.py --no-start` to generate .env and data/ only.",
    ]
    fail("\n".join(lines))

# ---- resource plan (#102) ---------------------------------------------------

def run_resource_plan(env_path: Path, profile: str, sizing_file: Path | None) -> None:
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
        # Shared thresholds: resource_planner.suggest_profile is the single
        # source of the auto-profile mapping (also served to the GUI via
        # `resource_planner.py --detect-json`).
        gib = host["memory_bytes"] / (1 << 30)
        profile = rp.suggest_profile(host["memory_bytes"])
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
            _write_private(Path(bak), Path(src).read_text())
    _write_private(env_path, rp.splice_env(env_text, rp.env_block(plan)))
    for name, text in (("resource-plan.json",
                        json.dumps(plan, indent=2, sort_keys=True) + "\n"),
                       ("resource-plan.txt", rp.plan_txt(plan))):
        (env_path.parent / name).write_text(text)
    for w in plan["warnings"]:
        warn(w)
    ok(f"resource plan written (profile {plan['profile']}) — "
       f"{env_path.parent / 'resource-plan.txt'}")


# ---- .env generation --------------------------------------------------------

def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path` owner-only FROM THE FIRST BYTE (M26).

    Path.write_text() + chmod(0o600) leaves a umask-wide window (0644 on a
    stock host) between creation and chmod during which any local user can
    open the file — and every caller here writes stack secrets (.env, its
    .rotate.bak / .plan.bak siblings). O_EXCL on a fresh temp name in the same
    directory, mode 0600 at open, then an atomic rename over the destination;
    a crashed run leaves at worst a 0600 temp file, never a half-written or
    world-readable secret."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass  # the normal case: replace() already moved it into place


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
        # vmalert -> api alert-delivery shared secret (internal/alertwebhook).
        # URL-safe by construction (generate_token = secrets.token_urlsafe), and
        # that matters: docker-compose.yml's default notifier flag embeds it in
        # URL userinfo (http://vmalert:<token>@api:8080/...), where a stray
        # @ # % would break the url vmalert parses.
        #
        # PLAINTEXT in .env, deliberately NOT vault-sealed: the vmalert
        # container must be able to SEND this value, so compose has to be able
        # to interpolate it in cleartext — exactly like INGEST_TOKEN. Sealing it
        # would leave vmalert with nothing to present and silently restore the
        # "13 alerts firing, none delivered" state this credential exists to end.
        "VMALERT_WEBHOOK_TOKEN":     generate_token(32),
        # Pipeline debugger (correlix-debug) — the shared secret the api
        # presents to the correlation container's debug sidecar for the bounded
        # bus PEEK and the correlation log-level switch
        # (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §4). BOTH services read
        # the same value from this file; unset means the routes answer 503 and
        # a trace honestly reports the bus stage as "not observable", which is
        # a debugger that goes blind on exactly the install that needs it.
        # PLAINTEXT in .env, not vault-sealed: compose has to interpolate it
        # into two containers (same reasoning as INGEST_TOKEN). URL-safe by
        # construction, so it is safe in a bearer header and in any future
        # userinfo use.
        "CORR_DEBUG_TOKEN":          generate_token(32),
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
        # Migration (vmalert delivery): a pre-webhook .env has no shared secret,
        # and without one the api refuses to register the receiver (fail-closed)
        # — i.e. the upgrade would keep delivering nothing. Seed it so an
        # upgraded install converges on the same behaviour as a fresh one. Same
        # generator as INGEST_TOKEN: URL-safe, because it rides URL userinfo.
        if "VMALERT_WEBHOOK_TOKEN" not in env:
            additions.append(f"VMALERT_WEBHOOK_TOKEN={generate_token(32)}")
        if "VMALERT_WEBHOOK_COOLDOWN" not in env:
            # Byte-identical to the docker-compose default and to
            # alertwebhook.DefaultCooldown.
            additions.append("VMALERT_WEBHOOK_COOLDOWN=30m")
        # Migration (pipeline debugger): a pre-debugger .env has no sidecar
        # secret, so the bus peek and the correlation log-level switch stay
        # default-closed forever on an upgraded install — `correlix-debug
        # trace` would report the bus stage "not observable" on the very host
        # where someone is trying to find a lost record. Seeded, never
        # overwritten: an operator-set value is authoritative, and rewriting it
        # here would desynchronise the api from the correlation sidecar.
        if "CORR_DEBUG_TOKEN" not in env:
            additions.append(f"CORR_DEBUG_TOKEN={generate_token(32)}")
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

# vmalert alert DELIVERY (src/backend/internal/alertwebhook).
#   VMALERT_WEBHOOK_TOKEN    the shared secret vmalert's notifier presents to
#                            POST /api/internal/vmalert/api/v2/alerts. EMPTY
#                            disables the receiver entirely (fail-closed: the
#                            api does not register the route and logs a loud
#                            warning) — which means vmalert rules fire and
#                            NOTHING is delivered to any channel. That was the
#                            shipped state until this landed: 13 alerts firing,
#                            zero delivered, and a 3h correlation outage on
#                            2026-09-02 that nobody saw.
#                            PLAINTEXT on purpose, not vault-sealed: the
#                            vmalert container has to send it, so compose must
#                            be able to interpolate it (same as INGEST_TOKEN).
#   VMALERT_WEBHOOK_COOLDOWN suppression window for a repeat of an identical
#                            alert. Must match the compose default (30m).
VMALERT_WEBHOOK_TOKEN={secrets_map["VMALERT_WEBHOOK_TOKEN"]}
VMALERT_WEBHOOK_COOLDOWN=30m

# Pipeline debugger (correlix-debug — docs/runbooks/pipeline-debug.md).
#   CORR_DEBUG_TOKEN   the shared secret the api presents to the correlation
#                      container's debug sidecar. It gates exactly two
#                      default-closed routes on that sidecar: a BOUNDED,
#                      group-less bus PEEK (it cannot move the engine's
#                      offsets) and a self-reverting log-level switch. The
#                      SAME value must be set for both services — compose
#                      passes this one variable to each. EMPTY means both
#                      routes answer 503 and a trace reports the bus stage as
#                      "not observable" WITH that reason (never as a lost
#                      record). PLAINTEXT on purpose, like INGEST_TOKEN: two
#                      containers have to receive it via compose
#                      interpolation, so it cannot be vault-sealed.
CORR_DEBUG_TOKEN={secrets_map["CORR_DEBUG_TOKEN"]}

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

# ---- Platform self-health alerts -> HOST MONITORING ---------------------
# The stack's OWN alerts (vmalert: engines not consuming, storage refusing
# writes, ingest silent, the alerting heartbeat) are pushed to the
# host-monitoring phone channel, NOT to the product notification channels:
# that route has to work on an install where nobody configured a channel
# yet, because it is how the stack reports on itself.
# Leave EMPTY to use WATCHDOG_NTFY_TOPIC above (the recommended setup — the
# same phone channel that already carries the watchdog's dead-man's-switch).
# Server/token fall back to NTFY_ALERT_SERVER / NTFY_ALERT_TOKEN, then to
# https://ntfy.sh. Set these only to split the platform alerts onto their own
# topic. NOTE: the product ntfy channel still REFUSES the watchdog topic —
# that refusal is about tenant-facing alerting and is unchanged.
#PLATFORM_ALERTS_NTFY_TOPIC=
#PLATFORM_ALERTS_NTFY_SERVER=
#PLATFORM_ALERTS_NTFY_TOKEN=
# Alert NOISE + RATE-LIMIT control. ntfy.sh's free public server rate-limits
# per topic/IP; on 2026-09-03 it answered 429 to this route because chronic
# WARNINGS (vector component errors, dead letters, disk headroom) were each
# spending a push, and a real page can be refused behind them. So: the warning
# tier is never pushed on its own, it is summarized into ONE digest per
# interval (a warning that resolves inside the window is folded in as
# resolved), and an hourly token budget reserves capacity only a PAGE may
# spend. Pages are never digested and retry with backoff on 429/5xx.
# The values below are the code defaults; uncomment only to change them.
# PUSH_BUDGET=-1 disables the budget guard (self-hosted ntfy with no limits).
#PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL=30m
#PLATFORM_ALERTS_PUSH_BUDGET=30
#PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE=10

# ---- Optional modules (default OFF — uncomment to enable) ---------------
# Each block below is DORMANT unless its flag is uncommented: nothing is
# constructed, scheduled or routed, no route is registered and no metric
# series exists. Compose already carries the same defaults, so a commented
# line and a missing line mean exactly the same thing.
#
# Security evidence lane — per-tenant hardening + vendor-advisory + threat
# detections onto the netops.security topic, persisted as CTEM findings.
# Bounded: one jittered pass per interval, at most N findings per tenant per
# run (the excess is counted, never silently dropped).
#FEATURE_SECURITY_LANE=true
#SECURITY_SCAN_INTERVAL=15m
#SECURITY_MAX_FINDINGS_PER_TENANT=5000
#
# Config Backup & Drift — scheduled READ-ONLY SSH capture of each device's
# running-config, sealed at rest, content-addressed, with a drift verdict per
# device. NEEDS: (1) a sealing provider — add 'seal' to COMPOSE_PROFILES and
# set SEAL_PROVIDER=swtpm, or the module refuses to start rather than write
# configurations in cleartext; (2) a least-privilege read-only capture
# account; (3) disk for the sealed blobs under data/config-backups (0700,
# api-owned) — roughly config size x KEEP_VERSIONS x devices.
#FEATURE_CONFIG_BACKUP=true
#CONFIG_BACKUP_INTERVAL=24h
#CONFIG_BACKUP_KEEP_VERSIONS=30
#CONFIG_BACKUP_SSH_USER=
#CONFIG_BACKUP_SSH_PASSWORD=
#CONFIG_BACKUP_SSH_KEY=
#CONFIG_BACKUP_SSH_PORT=22
#
# On-demand packet capture — a bounded, operator-triggered tcpdump over the
# same read-only SSH gateway, sealed at rest. Duration/size ceilings are HARD
# CAPS in code, not knobs; only retention and the capture identity are
# tunable. NEEDS the same sealing provider as config backup, plus disk under
# data/pcap (0700, api-owned): PCAP_KEEP x up to 25 MiB per capture.
#FEATURE_PACKET_CAPTURE=true
#PCAP_KEEP=20
#PCAP_SSH_USER=
#PCAP_SSH_PASSWORD=
#PCAP_SSH_KEY=
#PCAP_SSH_PORT=22
#
# Protocol diagnostics — LIVE collect. The Troubleshooting page's BGP/OSPF/IS-IS
# collect→analyze runs a curated bundle of READ-ONLY `show` commands against the
# device you pick, over the SAME read-only SSH gateway and pinned host-key
# custody as config backup. With the flag off the collect button returns an
# honest 503; the catalog and the paste-your-own-output analysis still work
# (neither touches a device). NEEDS a least-privilege read-only account —
# leaving PROTOCOL_DIAG_SSH_* empty reuses the CONFIG_BACKUP_SSH_* one.
#FEATURE_PROTOCOL_DIAG_COLLECT=true
#PROTOCOL_DIAG_SSH_USER=
#PROTOCOL_DIAG_SSH_PASSWORD=
#PROTOCOL_DIAG_SSH_KEY=
#PROTOCOL_DIAG_SSH_PORT=22
#
# BMP receiver — the LIVE BGP feed. Your own routers push a copy of their
# Adj-RIB-In to this platform over TCP (RFC 7854); nothing external is needed
# and NOTHING is configured on any device by us — pointing a router here is a
# human act on the router (config snippets for IOS-XR/IOS-XE/Junos/SR OS are in
# docs/INGESTION.md). Binds host TCP 11019 (BMP_PORT) → :11019 in the container.
# A session is accepted ONLY from a source address that resolves to a device in
# inventory, and the tenant is stamped from that device row — an unknown source
# is disconnected, never stored untenanted. Message size, connection count and
# per-session update depth are hard caps in code, not knobs.
#FEATURE_BMP=true
#BMP_LISTEN=:11019
#BMP_PORT=11019
#
# BGP operations depth + alerting. All three default OFF and each is
# independent; none of them configures anything on any device.
#   FEATURE_BGP_LIVE_FEED  — a bounded RIPEstat poller keeps a per-tenant ring
#       of recent updates for the prefixes on your watchlist. Outbound HTTPS to
#       stat.ripe.net only, rate-limited and cached; nothing is pushed out.
#   FEATURE_BGP_ALERTS     — the watchlist evaluator: per watched prefix it
#       classifies visibility loss / origin change / RPKI-invalid / route leak /
#       bogon and raises a transition alert through the normal notifier, plus
#       evidence on the netops.bgp topic. The watchlist itself is durable with
#       or without Postgres (file backend: BGP_WATCHLIST_FILE, default
#       /data/bgp_watchlist.json), so this works on a single-box install.
#   FEATURE_BGP_BOGON_FEED — layers the optional Team Cymru full-bogons list
#       over the embedded IANA/RFC set. Off = the embedded set, no network.
#FEATURE_BGP_LIVE_FEED=true
#FEATURE_BGP_ALERTS=true
#FEATURE_BGP_BOGON_FEED=true
#
# BGP_FEED_LOOKBACK is the window the FIRST poll of each resource asks for. It
# matters because the near-live feed polls a public ARCHIVE, not a stream, and
# that archive has been measured hours behind real time (3 h 15 m on
# 2026-09-03): a window shorter than the lag returns only records the cursor
# already rejects, so the feed buffers nothing forever with no error anywhere.
# The default (6h) covers the measured lag with room to spare; raise it if the
# feed page reports an upstream lag larger than the window. Clamped to 1m..24h.
#BGP_FEED_LOOKBACK=6h
#
# Parser-coverage mining bound (one run's OpenSearch scan) and the explicit
# correlation replica list the per-process parser counters are summed over
# (empty = the single-replica default, which falls back to CORRELATION_URL).
#PARSERCOV_MAX_LINES=200000
#CORRELATION_REPLICA_URLS=
#
# Correlation lane switches. CORR_SYSLOG_TOPIC swaps the raw syslog lane for
# a pre-screened topic; CORR_FIDELITY_WEIGHTING weighs evidence by parser
# fidelity tier (default off). CORR_EVIDENCE_TOPICS is deliberately NOT
# listed as an empty key: unset means "every registered evidence class",
# while an EMPTY value means "subscribe to none" — set it only when you mean
# that, e.g. while the broker still lacks a Read ACL on a class topic.
#CORR_SYSLOG_TOPIC=netops.syslog
#CORR_FIDELITY_WEIGHTING=0

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
    _write_private(env_path, body)
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

def refuse(msg: str) -> None:
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
                               capture_output=True, text=True, timeout=timeout, check=False)
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
    _write_private(backup, text)
    new_text, missing = sr.substitute_env(text, new_values)
    if missing:
        new_text += ("\n# ---- added by install.py secret rotation ----\n"
                     + "".join(f"{k}={new_values[k]}\n" for k in missing))
    _write_private(env_path, new_text)
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
        _write_private(env_path, reverted)
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

def api_runtime_uid(root: Path) -> tuple[int, int]:
    """The uid:gid the api container actually RUNS as.

    Compose maps the api to `user: ${CORRELIX_UID:-65532}` — write_env stamps
    CORRELIX_UID with the installer's uid, so everything the api writes
    (data/api, data/tls) must be owned by THAT uid, never a hardcoded one.
    Hardcoding 65532 broke root installs (CI tls-boot leg, 2026-08-13): under
    sudo the api runs as uid 0 with cap_drop:ALL — no CAP_DAC_OVERRIDE — so a
    65532-owned data/api is unwritable and the api crash-loops before minting.
    Reads the freshly-written .env; falls back to the compose default (65532)
    if the variable is absent, because that is what compose would resolve."""
    env_path = root / "deployment" / "docker" / ".env"
    uid, gid = 65532, 65532
    try:
        for line in env_path.read_text().splitlines():
            if line.startswith("CORRELIX_UID="):
                uid = int(line.split("=", 1)[1].strip())
            elif line.startswith("CORRELIX_GID="):
                gid = int(line.split("=", 1)[1].strip())
    except (OSError, ValueError):
        pass  # no .env yet (e.g. --no-start dry paths) → compose default
    return uid, gid


# Helper image for the not-root chown fallback below. This is the SAME pinned
# ref compose pulls for the postgres service (and restore-drill.sh reuses for
# its scratch container) — on any install that reaches "up" this image is on
# the host anyway, so the fallback introduces no new image and no unpinned pull.
CHOWN_HELPER_IMAGE = ("postgres:16-alpine@sha256:"
                      "16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229")


def _docker_chown(d: Path, uid: int, gid: int) -> tuple[bool, str]:
    """Chown a data dir recursively via a throwaway helper container.

    The installer already REQUIRES a working Docker daemon (which is
    root-equivalent on the host), so a non-root install can still repair
    bind-mount ownership this way. Returns (ok, error-detail). Bounded (§16.3):
    a wedged daemon cannot hang the install forever.
    """
    cmd = ["docker", "run", "--rm", "--network", "none",
           "--entrypoint", "/bin/chown",
           "-v", f"{d}:/target",
           CHOWN_HELPER_IMAGE,
           "-R", "-h", f"{uid}:{gid}", "/target"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip() or f"exit {res.returncode}"
        return False, detail
    return True, ""


def chown_tree(d: Path, uid: int, gid: int, name: str) -> None:
    """Make `d` and EVERYTHING under it owned uid:gid, or fail the install.

    Direct chown first (works under sudo/root); when that cannot finish — the
    normal case for a non-root installer targeting a service uid, and for
    stale root-owned subtrees left by Docker on a previous run — fall back to
    a root helper container (_docker_chown). The old behavior (print a
    "Fix: sudo chown ..." hint and CONTINUE) is the §16.1 swallow that shipped
    two broken deployments in one week: an unwritable correlation DLQ that
    silently dropped 238k dead-letter payloads, and a root-owned
    data/tls/services that crash-looped the api before it could mint SVIDs.
    Fails (exit 1, actionable remedy) only when BOTH paths fail.
    """
    direct_err: str | None = None
    try:
        os.chown(d, uid, gid)
        # Existing contents too: a re-install must repair stale ownership from
        # previous runs (e.g. Docker auto-created subdirs as root). Collect
        # failures instead of swallowing them — a child we can SEE but not
        # chown means the tree is not ours; a child we cannot even see lives
        # under a dir that itself just failed, so it is covered as well.
        failed: list[tuple[Path, OSError]] = []
        for child in d.rglob("*"):
            try:
                os.chown(child, uid, gid, follow_symlinks=False)
            except OSError as exc:
                failed.append((child, exc))
        if not failed:
            return
        direct_err = (f"{len(failed)} path(s) not chownable "
                      f"(first: {failed[0][0]}: {failed[0][1]})")
    except OSError as exc:  # PermissionError: non-root installer, service uid
        direct_err = str(exc)
    docker_ok, docker_err = _docker_chown(d, uid, gid)
    if docker_ok:
        info(f"{name}: ownership repaired to {uid}:{gid} via helper "
             f"container (direct chown unavailable: {direct_err})")
        return
    fail(
        f"cannot set ownership of {d} to {uid}:{gid}.\n"
        f"  direct chown failed: {direct_err}\n"
        f"  docker helper fallback failed: {docker_err}\n"
        f"  The stack cannot run with a mis-owned {name} — continuing would "
        f"ship a broken deployment (an unwritable correlation DLQ silently "
        f"dropped 238k payloads exactly this way).\n"
        f"  Fix and re-run the installer (it is idempotent):\n"
        f"    sudo chown -R {uid}:{gid} {d}"
    )


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
    api_uid, api_gid = api_runtime_uid(root)
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
        # The api OWNS this tree (file-kv store, vault wrapped-keys, enrichment,
        # processors) — and it runs user-mapped as CORRELIX_UID with
        # cap_drop:ALL, so the owner MUST be that runtime uid. A fixed 65532
        # here broke sudo installs (api ran as 0 without CAP_DAC_OVERRIDE →
        # EACCES crash-loop before minting; CI tls-boot leg, 2026-08-13).
        "api":        (api_uid, api_gid),
        "secrets-seal": None,           # #17 sealing-sidecar socket dir (root-owned; opt-in 'seal' profile)
        "swtpm":      None,             # #17 software-TPM state (sealed KEK objects); root-owned
        "netbox-postgres": None,        # bundled-NetBox DB (opt-in 'netbox' profile); initdb self-chowns
        "netbox-media":    None,        # bundled-NetBox media (opt-in 'netbox' profile)
        # F-38/durability: the correlation dead-letter volume. The service runs
        # as uid 10001 (Dockerfile.correlation appuser) and MUST own its durable
        # DLQ — root-created on 2026-07-27 and invisible until the RCA canary
        # paged; a wrong-owned dir then silently dropped 238k payloads in the
        # 2026-08 scale test (the service now also refuses to boot on it).
        "correlation/deadletter": (10001, 999),
        # tracker #151: the internal CA's mint target (SVIDs, trust bundle).
        # Docker would auto-create a bind-mount source as ROOT, and a
        # non-matching api uid could then never mint into it — pre-create
        # owned by the api's RUNTIME uid. Dormant/empty on plaintext installs.
        # RECURSIVE repair matters here: it is populated across installs, and a
        # stale root-owned data/tls/services deadlocked the TLS phase-A
        # bootstrap (api: "mkdir /data/tls/services/api: permission denied").
        "tls": (api_uid, api_gid),
        # Sealed device-configuration blobs (FEATURE_CONFIG_BACKUP,
        # internal/configstore). Same class as data/tls: a bind-mount source
        # Docker would otherwise auto-create as ROOT, into which the api
        # (user-mapped, cap_drop:ALL) could then never write — the module
        # fails its FIRST capture and every one after it. Pre-create it owned
        # by the api's RUNTIME uid, and 0700 below: the blobs are sealed but
        # the directory listing itself (device ids, capture times) is not for
        # every local user to read.
        "config-backups": (api_uid, api_gid),
        # Sealed packet-capture blobs (FEATURE_PACKET_CAPTURE, internal/pcap).
        # Same class and same 0700 reasoning as config-backups — a capture can
        # contain payload bytes, so the directory is owner-only.
        "pcap": (api_uid, api_gid),
    }
    # Directories whose MODE is part of the contract, not just their owner.
    private_modes: dict[str, int] = {"config-backups": 0o700, "pcap": 0o700}
    for name, uid_gid in owners.items():
        d = root / "data" / name
        try:
            d.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # The dir (or an ancestor) already exists owned by a SERVICE uid
            # (e.g. a re-install over a uid-70 mode-0700 data/postgres, or a
            # data/ tree left container-owned by a prior run) so the installer
            # user can neither create the subdir nor traverse in. Fail with an
            # actionable remedy instead of a raw traceback (customer reset/
            # reinstall experience, 2026-08-16).
            fail(
                f"cannot create data/{name}: it (or a parent) is owned by another "
                f"user and not writable by {os.getenv('USER', 'the installer')}. "
                f"This usually means a previous run left data/ owned by container "
                f"UIDs. Fix ownership and retry, e.g.:\n"
                f"    sudo chown -R $(id -u):$(id -g) {root / 'data'}\n"
                f"or, to start from a clean slate, stop the stack and remove data/ "
                f"(this DELETES all stored telemetry/state):\n"
                f"    cd {root / 'deployment' / 'docker'} && docker compose down\n"
                f"    docker run --rm -v {root / 'data'}:/d alpine sh -c 'rm -rf /d/*'"
            )
        mode = private_modes.get(name)
        if mode is not None:
            # Idempotent: a re-install over a dir the SERVICE uid already owns
            # cannot chmod it, and must not need to — check the mode first and
            # only act when it is actually wrong. When it IS wrong and we
            # cannot fix it, FAIL (§16.1): a sealed-blob dir left group/world
            # readable is a real posture regression, and the operator can only
            # fix what they are told about.
            try:
                current = stat.S_IMODE(d.stat().st_mode)
            except OSError as exc:
                fail(f"cannot stat data/{name}: {exc}")
            if current != mode:
                try:
                    d.chmod(mode)
                except OSError as exc:
                    fail(f"cannot set mode {mode:04o} on data/{name} "
                         f"(currently {current:04o}): {exc}\n"
                         f"    sudo chmod {mode:04o} {d}")
        if uid_gid is not None:
            chown_tree(d, uid_gid[0], uid_gid[1], f"data/{name}")

    # ------------------------------------------------------------------
    # A SIGN ON THE DOOR for data/opensearch-snapshots (2026-09-03).
    #
    # The seven-day unrestorable-backup incident had no code root cause: a
    # human ran `rm -rf data/opensearch-snapshots/indices` from a shell during
    # a disk crunch while the repository was still registered. OpenSearch
    # re-created the empty tree at the next scheduled snapshot and every shard
    # from then on failed with NoSuchFileException, while `_cat/snapshots`
    # kept listing SUCCESS rows. No guard inside the process can stop that
    # command; a README next to the directory can at least make the operator
    # who is about to run it stop and read.
    #
    # WHY HERE AND NOT IN opensearch/apply-ism.sh (where the repository is
    # registered, and where this was first proposed): the opensearch-init
    # container mounts ONLY `./opensearch:/opensearch-init:ro`. It has no
    # mount of the snapshot repository at all, so it physically cannot write
    # this file anywhere the operator would ever see it — and it must not be
    # given one, because handing the bootstrap a writable mount of the blob
    # tree is a new way to damage the blob tree. The installer already owns
    # the data/ layout, runs on the host, and is the only component that can
    # place a SIBLING of the repository directory (deliberately a sibling: a
    # stray file INSIDE a repository is something `_cleanup` may remove and
    # something a future reader may mistake for a blob).
    #
    # The text is versioned in the repo — data/ is gitignored, so the copy
    # next to the repository is an artefact, never the source.
    snap_readme = root / "data" / "opensearch-snapshots.DO-NOT-DELETE-README.txt"
    if not snap_readme.exists():
        snap_src = (root / "deployment" / "docker" / "opensearch" /
                    "SNAPSHOTS-DO-NOT-DELETE-README.txt")
        try:
            snap_readme.write_text(snap_src.read_text(encoding="utf-8"),
                                   encoding="utf-8")
        except OSError as e:
            # §16.1: named, never swallowed. NOT fatal — a stack that installed
            # correctly must not be reported as a failed install because a
            # warning notice could not be written, and escalating here would
            # replace a real install error with this one. The operator is told
            # exactly which protection they do not have.
            warn(f"could not write {snap_readme}: {e} — the snapshot repository "
                 f"will have NO 'do not delete' notice beside it. The stack is "
                 f"unaffected; see docs/runbooks/storage-and-volume-operations.md"
                 f"#managing-snapshots for why deleting inside a registered "
                 f"repository silently destroys every restore point.")

    # #20: device→tenant enrichment dir. The api exports the CSV here; the
    # Vector aggregator + correlation mount it read-only. Seed a header-only
    # CSV so the aggregator's enrichment-table load never fails on a cold
    # start (before the api has written its first map). The api WRITES this
    # dir at runtime (CSV re-export, path_graph.json), so it must OWN it —
    # same escalation contract as the service dirs above (chown_tree), never
    # the old swallowed chown: a wrong-owned enrichment dir means the api
    # cannot refresh the device→tenant map and telemetry silently keeps the
    # stale (header-only) tenant stamping.
    enrich = root / "data" / "api" / "enrichment"
    enrich.mkdir(parents=True, exist_ok=True)
    seed = enrich / "device_tenant.csv"
    if not seed.exists():
        seed.write_text("identity,tenant_id\n")
    chown_tree(enrich, api_uid, api_gid, "data/api/enrichment")

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
    # The api rewrites processors.yaml on first start and on EVERY rule
    # change, so it must own the tree — a wrong owner means per-tenant rule
    # changes silently stop reaching the router. Recursive chown_tree on the
    # parent covers processors/ + router/ + the seed in one contract.
    chown_tree(proc_dir.parent, api_uid, api_gid, "data/api/processors")

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
    # The api only READS these two (appid.NewCatalogHolder /
    # cloud.LoadTopologiesLayered — no non-test writes in either package), but
    # the WRITER is the operator (scripts/fetch-appid-feeds.sh, fixture JSON
    # drops) whose uid is CORRELIX_UID by construction — and a sudo install /
    # legacy-.env re-install can leave them owned by the wrong uid, breaking
    # that operator workflow with EACCES. Same contract as above: repair or
    # refuse, never swallow.
    for d in (appid_feeds, cloud_fixtures):
        chown_tree(d, api_uid, api_gid, f"data/api/{d.name}")

    # #13: vulnerability-feed dir. OPERATOR-owned (unlike the service dirs) —
    # the operator writes it with scripts/vuln-feed-prepare.py and the api only
    # reads it (mounted read-only). Under sudo, chown to the invoking user so
    # the prepare script works without root afterwards.
    vuln = root / "data" / "vuln"
    vuln.mkdir(parents=True, exist_ok=True)
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if sudo_uid:
        # sudo sets numeric SUDO_UID/SUDO_GID itself; a malformed value means a
        # mangled environment — report it and leave the dir root-owned rather
        # than guessing an owner (the prepare script will then need sudo, and
        # the operator was told why). A chown FAILURE, by contrast, escalates
        # through chown_tree like every other ownership handoff.
        try:
            vuln_uid, vuln_gid = int(sudo_uid), int(sudo_gid or sudo_uid)
        except ValueError:
            warn(f"SUDO_UID/SUDO_GID malformed ({sudo_uid!r}/{sudo_gid!r}) — "
                 f"leaving {vuln} owner unchanged; scripts/vuln-feed-prepare.py "
                 f"will need sudo (or chown {vuln} to your user) until fixed")
        else:
            chown_tree(vuln, vuln_uid, vuln_gid, "data/vuln (operator-owned)")

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


def splice_env_values(env_path: Path, values: dict[str, str],
                      header: list[str], label: str) -> None:
    """Line-surgery `values` into .env (idempotent): substitute existing keys
    in place, append the missing ones under one header. Never rewrites the
    file wholesale — operator edits survive, same doctrine as rotation."""
    text = env_path.read_text()
    lines = text.splitlines()
    present: dict[str, int] = {}
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in values:
            present[key] = i
    changed = False
    for key, idx in present.items():
        want = f"{key}={values[key]}"
        if lines[idx] != want:
            lines[idx] = want
            changed = True
    missing = [k for k in values if k not in present]
    if missing:
        lines.append("")
        lines.extend(header)
        for k in missing:
            lines.append(f"{k}={values[k]}")
        changed = True
    if changed:
        env_path.write_text("\n".join(lines) + "\n")
        ok(f"{label} set in .env ({len(present)} updated, {len(missing)} added)")
    else:
        info(f"{label} already present in .env")


def normalize_database_url_for_bootstrap(env_path: Path) -> None:
    """Force .env's DATABASE_URL to the PLAINTEXT bootstrap form (sslmode=disable,
    no sslrootcert) so TLS phase A can always mint the mesh CA.

    In the working model .env keeps a plaintext DATABASE_URL and the verify-full
    DSN comes ONLY from compose.tls.yml (activated in phase B). If an older install
    or a manual edit baked `sslmode=verify-full&sslrootcert=/data/tls/ca.pem` into
    .env, phase A's api dies at config-parse ("unable to read CA file …/ca.pem")
    because the CA does not exist yet — the api is the thing that mints it. That is
    a silent crash-loop on re-install / backup-restore (customer experience,
    2026-08-16). Normalizing here is a no-op on a standard plaintext .env and
    self-heals the baked-in-verify-full case; the phase-B compose override still
    provides verify-full for the final running state."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    lines = env_path.read_text().splitlines()
    changed = False
    for i, line in enumerate(lines):
        if not line.startswith("DATABASE_URL="):
            continue
        val = line.split("=", 1)[1]
        parts = urlsplit(val)
        q = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True)
             if k not in ("sslmode", "sslrootcert", "sslcert", "sslkey")]
        q.append(("sslmode", "disable"))
        newval = urlunsplit((parts.scheme, parts.netloc, parts.path,
                             urlencode(q), parts.fragment))
        if newval != val:
            lines[i] = f"DATABASE_URL={newval}"
            changed = True
        break
    if changed:
        env_path.write_text("\n".join(lines) + "\n")
        info("normalized DATABASE_URL to the plaintext bootstrap form for TLS "
             "phase-A minting (verify-full is supplied by compose.tls.yml in phase B)")


def enable_tls_env(env_path: Path) -> None:
    """Line-surgery the TLS values into .env (idempotent)."""
    splice_env_values(
        env_path, TLS_ENV_VALUES,
        ["# ---- TLS/mTLS mesh (tracker #151) — written by install.py --tls=yes ----",
         "# Values pair with deployment/docker/compose.tls.yml; keep in lockstep."],
        "TLS variables")
    # Guarantee phase A can mint even if .env carried a baked-in verify-full DSN.
    normalize_database_url_for_bootstrap(env_path)


def enable_snmp_discovery_env(env_path: Path, cidrs: str) -> None:
    """--snmp-discovery: opt the install in to SNMP discovery over the given
    (already validated) CIDR ranges. Line surgery, same doctrine as
    enable_tls_env — idempotent, operator edits elsewhere in .env survive.
    Discovery stays OPT-IN: without the flag the template defaults
    (disabled, empty scope) are untouched."""
    splice_env_values(
        env_path,
        {"ENABLE_SNMP_DISCOVERY": "true", "SNMP_CIDR_RANGES": cidrs},
        ["# ---- SNMP discovery scope — written by install.py --snmp-discovery ----"],
        "SNMP discovery variables")


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
    step(f"waiting for the internal CA to mint service identities (≤{timeout_s}s)",
         stage="mint")
    deadline = time.time() + timeout_s
    remaining = list(TLS_MINT_SENTINELS)
    while time.time() < deadline:
        remaining = [p for p in remaining if not (root / p).exists()]
        if not remaining:
            ok("all service identities minted")
            return
        time.sleep(5)
    # Print the evidence BEFORE failing — fail() exits immediately, so the
    # original order made the missing-list and the hint unreachable dead code
    # (found by the CI tls-boot leg's first mint timeout, 2026-08-12).
    print("[fail ] the api did not mint the full identity set in time; still missing:",
          file=sys.stderr)
    for p in remaining:
        print(f"    - {p}", file=sys.stderr)
    fail("check `docker compose logs api` (seal sidecar up? SEAL_PROVIDER=swtpm? "
         "data/tls writable by the api uid?) and rerun the installer — it is idempotent.")


def ensure_ingress_key_owner(key: Path, statfn=os.stat) -> None:
    """The 0600 ingress private key MUST be owned by uid 101: the hardened
    nginx image runs as USER 101 with cap_drop:ALL (no DAC_OVERRIDE), so a
    key owned by anyone else crash-loops the ingress on "cannot load
    certificate key ... Permission denied" (CI tls-boot leg, 2026-08-13).
    Already-correct ownership is left alone (no helper container spawned on
    every re-run); otherwise the same direct-chown → docker-helper → fail
    contract as the data dirs (chown_tree) — the old warn-and-continue here
    was one more instance of the §16.1 swallow that shipped broken installs.
    """
    if not key.exists():
        fail(f"ingress private key missing: {key} — certificate generation "
             "claimed success but produced no key; refusing to continue to a "
             "TLS ingress that cannot start")
    st = statfn(key)
    if (st.st_uid, st.st_gid) == (101, 101):
        return
    chown_tree(key, 101, 101, "nginx ingress TLS key (privkey.pem)")


def ensure_ingress_cert(root: Path) -> None:
    """The nginx TLS ingress needs a cert before its first TLS start. Dev/lab:
    self-signed via gen-dev-cert.sh; production replaces the files in place
    (documented in the script header)."""
    certs = root / "deployment" / "docker" / "nginx" / "certs"
    if certs.exists() and (any(certs.glob("*.crt")) or (certs / "fullchain.pem").exists()):
        info("nginx ingress certs already present")
        # Re-run path: a previous run may have left the key owned by the wrong
        # uid (e.g. root-installed then re-run, or vice versa). Idempotent
        # fix-up; non-root repairs through the docker helper. Guarded on
        # exists(): a production cert replaced in place may use its own layout.
        key = certs / "privkey.pem"
        if key.exists():
            ensure_ingress_key_owner(key)
        return
    step("generating a self-signed ingress certificate (replace for production)")
    res = subprocess.run(["bash", str(root / "scripts" / "gen-dev-cert.sh")],
                         capture_output=True, text=True, check=False)
    if res.returncode != 0:
        fail(f"gen-dev-cert.sh failed: {res.stderr.strip() or res.stdout.strip()}")
        raise SystemExit(2)
    # gen-dev-cert.sh documents the uid-101 handoff as a manual step; an
    # unattended install completes it itself — see ensure_ingress_key_owner
    # (direct chown, docker-helper fallback for non-root, hard fail if both
    # fail; never the old warn-and-continue into a crash-looping ingress).
    ensure_ingress_key_owner(certs / "privkey.pem")
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
                           cwd=str(compose_dir), env=build_env, check=False)
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
        res = subprocess.run(["docker", "load"], stdin=zstd.stdout, check=False)
        zstd.stdout.close()
        if zstd.wait() != 0 or res.returncode != 0:
            fail("docker load from bundle failed")
    else:
        subprocess.run(["docker", "load", "-i", str(bundle)], check=True)
    ok("images loaded")


def compose_status(compose_dir: Path) -> None:
    subprocess.run(["docker", "compose", "ps"], cwd=str(compose_dir), check=False)


# ---- Kafka authorization (SEC-007) ------------------------------------------
# The TLS variant boots the broker with StandardAuthorizer and
# allow.everyone.if.no.acl.found=false (SEC-007.2), and the KRaft ACL store
# lives in data/kafka — so a fresh install (or a data/kafka wipe, e.g.
# --rotate-kafka-cluster-id) starts ENFORCING WITH ZERO ACLs: every producer
# and consumer except the broker's own super-user SVID is denied while every
# container still reports "healthy". Exactly that shipped live 2026-08-16
# (~80 min auth-dead ingest tier, router lag frozen, all healthchecks green).
# kafka-init only creates topics; the installer owns authorization state too,
# so a completed install is never a silently dead bus.

_ACL_SCRIPT = "/acls/apply-acls.sh"          # mounted by compose.tls.yml
_KAFKA_ADMIN_PROPS = "/tmp/kafka-tls/admin.properties"  # tls-entrypoint.sh


def _kafka_group_members(describe_out: str, group: str) -> int:
    """Count ACTIVE members in `kafka-consumer-groups.sh --describe` output.

    Data rows are `GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG
    CONSUMER-ID HOST CLIENT-ID`; a live member shows a real CONSUMER-ID while
    a dead consumer keeps its committed offsets but shows `-` — exactly the
    wiped-ACL failure shape. Same parse the scale mini-ladder preflight uses
    (scripts/scale-miniladder.py group_lag)."""
    members = 0
    for line in describe_out.splitlines():
        f = line.split()
        if len(f) >= 7 and f[0] == group and f[6] != "-":
            members += 1
    return members


def apply_kafka_acls(compose_dir: Path, timeout_s: int = 900) -> None:
    """Run the SEC-007 ACL matrix inside the broker, bounded + loud (§16.1).

    deployment/docker/kafka/apply-acls.sh executes in the kafka container
    against the mTLS listener with the broker's super-user SVID (it
    auto-detects /tmp/kafka-tls/admin.properties). It is idempotent
    (kafka-acls --add of an existing ACL is a no-op) and verifies the matrix
    back before exiting 0, so a zero exit here is a proven-applied matrix.
    Retries over a bounded window because right after the phase-B recreate
    the broker may still be in log recovery; persistent failure FAILS the
    install — completing with a dead bus is the defect this step removes."""
    cmd = ["docker", "compose", "exec", "-T", "kafka", _ACL_SCRIPT]
    deadline = time.time() + timeout_s
    attempt = 0
    last = "no output"
    while True:
        attempt += 1
        try:
            res = subprocess.run(cmd, cwd=str(compose_dir), capture_output=True,
                                 text=True, timeout=600, check=False)
            rc, out, err = res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = 1, "", "apply-acls.sh timed out after 600s inside the broker"
        if rc == 0:
            applied = [ln for ln in err.splitlines() if "matrix applied" in ln]
            ok(applied[-1].removeprefix("acls: ") if applied
               else "Kafka ACL matrix applied and verified (SEC-007)")
            return
        last = (err.strip() or out.strip() or "no output")[-500:]
        if time.time() >= deadline:
            break
        warn(f"ACL apply attempt {attempt} failed (broker may still be "
             f"recovering after the phase-B recreate) — retrying in 15s: "
             f"{last.splitlines()[-1]}")
        time.sleep(15)
    fail("could not apply the SEC-007 Kafka ACL matrix — with "
         "allow.everyone.if.no.acl.found=false an empty ACL store leaves the "
         "ENTIRE ingest tier authorization-dead while every container reports "
         "healthy (live incident 2026-08-16). Refusing to report install "
         "success over a dead bus. Inspect `docker compose logs kafka`, then "
         "re-run the installer (idempotent) or the runbook step: "
         f"docker compose exec kafka {_ACL_SCRIPT}. Last error: {last}")


def verify_bus_consumers(compose_dir: Path, group: str = "netops-correlation",
                         timeout_s: int = 420) -> None:
    """Post-apply liveness gate (§16.1: no blind success).

    The matrix being WRITTEN is necessary but not sufficient — prove a real
    workload consumer holds group membership through the enforcing broker
    before calling the bus alive (the 2026-08-16 incident's signature was
    committed offsets with zero members). Bounded wait: right after phase B
    the correlation engine may still be (re)connecting and kafka-init may
    still be creating topics."""
    describe = ["docker", "compose", "exec", "-T", "kafka",
                "/opt/kafka/bin/kafka-consumer-groups.sh",
                "--bootstrap-server", "kafka:9094",
                "--command-config", _KAFKA_ADMIN_PROPS,
                "--describe", "--group", group]
    deadline = time.time() + timeout_s
    last = "no output"
    while time.time() < deadline:
        try:
            res = subprocess.run(describe, cwd=str(compose_dir),
                                 capture_output=True, text=True, timeout=90,
                                 check=False)
            if res.returncode == 0 and _kafka_group_members(res.stdout, group) > 0:
                ok(f"bus alive: consumer group {group} holds active membership "
                   "through the enforcing broker")
                return
            last = (res.stderr.strip() or res.stdout.strip() or "no output")[-400:]
        except subprocess.TimeoutExpired:
            last = "kafka-consumer-groups.sh timed out after 90s"
        time.sleep(10)
    fail(f"consumer group {group} shows NO active member {timeout_s}s after "
         "the ACL matrix was applied — the bus is still authorization-dead "
         "(or the consumer never came up). Refusing to report install "
         "success. Inspect `docker compose logs correlation` and the broker "
         "authorizer log (`docker compose logs kafka | grep -i denied`), fix, "
         f"and re-run the installer. Last probe output: {last}")


def apply_bus_authorization(compose_dir: Path, env_path: Path,
                            tls_enabled: bool) -> None:
    """Install-owned Kafka authorization convergence (SEC-007, P0 2026-08-16).

    Only the TLS variant runs it: the plaintext baseline configures NO
    authorizer at all (base docker-compose.yml has no
    KAFKA_AUTHORIZER_CLASS_NAME), so kafka-acls there fails with
    SecurityDisabledException and nothing would enforce the result — skipping
    is correct, not a gap. External-broker installs (embedded-bus profile
    off) skip too: ACL management on a broker we do not run belongs to its
    owner (docs/runbooks/tls-enforce-wave.md)."""
    if not tls_enabled:
        return
    active = {p.strip() for p in
              _parse_env(env_path).get("COMPOSE_PROFILES", "").split(",")
              if p.strip()}
    step("applying Kafka ACL matrix (SEC-007)", stage="kafka-acls")
    if "embedded-bus" not in active:
        info("external broker (embedded-bus profile off) — ACL management "
             "belongs to the broker owner; apply the SEC-007 matrix there "
             "per docs/runbooks/tls-enforce-wave.md")
        return
    apply_kafka_acls(compose_dir)
    verify_bus_consumers(compose_dir)


def bootstrap_opensearch(root: Path, tls: bool = False) -> None:
    """Apply index templates after the stack is up, by CALLING the one owner:
    scripts/bootstrap-opensearch.sh. Non-fatal on error — OpenSearch may still
    be starting; the operator can re-run the script.

    2026-09-03: this function used to carry its OWN copy of the template-PUT
    loop (`_bootstrap_opensearch_via_exec`) alongside the script's. The copies
    drifted — install.py learned the SEC-008 https/svc_bootstrap path and the
    script did not, so `bootstrap-opensearch.sh` (which update.sh and every
    upgrade runbook call) was BLIND on TLS installs and reported all nine
    templates "NOT applied". One owner now: the script detects the variant from
    COMPOSE_FILE, authenticates the same way this code did, and fails loud.
    """
    script = root / "scripts" / "bootstrap-opensearch.sh"
    if not script.exists():
        warn("bootstrap-opensearch.sh missing; skipping")
        return
    compose_dir = root / "deployment" / "docker"
    env = {**os.environ}
    # The script re-detects TLS from .env itself; drop any inherited
    # OPENSEARCH_URL so a stale plaintext value cannot steer it.
    env.pop("OPENSEARCH_URL", None)
    env["OPENSEARCH_REPLICAS"] = _parse_env(compose_dir / ".env").get(
        "OPENSEARCH_REPLICAS", "0")
    # §9: bounded. The script's own readiness wait is 60s and nine PUTs are
    # fast, so 10 minutes is generous; a wedged docker must not hang install.
    try:
        res = subprocess.run(["bash", str(script)], cwd=str(root), env=env,
                             capture_output=True, text=True, check=False,
                             timeout=600)
    except subprocess.TimeoutExpired:
        warn("bootstrap-opensearch.sh did not finish within 600s — index "
             "templates were NOT applied")
        info("re-run after a minute: scripts/bootstrap-opensearch.sh")
        return
    # The script names the transport it chose and every template it applied;
    # surface that verdict rather than a bare ok/warn (§16.1 — a bare "Done."
    # has hidden a fully-failed run before). `tls` is not passed down: the
    # script re-detects the variant from COMPOSE_FILE, which is the single
    # on-disk statement of it, so the two can never disagree.
    for line in (res.stdout or "").splitlines():
        if line.startswith(("APPLIED", "FAILED", "Transport:", "!!")):
            info(line)
    if res.returncode != 0:
        detail = (res.stderr or "").strip() or (res.stdout or "").strip()
        last = detail.splitlines()[-1] if detail else "see the output above"
        warn(f"index templates NOT fully applied (tls={tls}): {last}")
        info("re-run after a minute: scripts/bootstrap-opensearch.sh")
        return
    ok("index templates applied")


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
        (f"for i in $(seq 1 30); do pg_isready -q -U {user} && break; sleep 2; done; "
         f"psql -U {user} -d postgres -tAc "
         f"\"SELECT 1 FROM pg_database WHERE datname='{db}'\""),
    ]
    res = subprocess.run(probe, cwd=str(compose_dir), capture_output=True,
                         text=True, timeout=120, check=False)
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
                         text=True, timeout=60, check=False)
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
    r = subprocess.run(base, cwd=str(compose_dir), capture_output=True, text=True, check=False)
    if r.returncode != 0:
        info("plugin download failed verified; retrying with --insecure (TLS-intercepted network)")
        r = subprocess.run(
            ["docker", "compose", "exec", "-T", "grafana", "grafana", "cli", "--insecure",
             "--pluginsDir", "/var/lib/grafana/plugins", "plugins", "install", plug],
            cwd=str(compose_dir), capture_output=True, text=True, check=False)
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
    ap.add_argument("--progress-json", action="store_true",
                    help="Emit machine-readable '@CX@ {json}' progress markers on "
                         "stdout alongside the human output (GUI installer contract; "
                         "also activated by CORRELIX_PROGRESS_JSON=1).")
    ap.add_argument("--time-report", action="store_true",
                    help="Print a per-stage wall-clock table when the run ends. "
                         "The same numbers are always written to "
                         "data/install-timing.json (deployment-friction "
                         "instrument; see docs/DEPLOY_LINUX.md).")
    ap.add_argument("--bootstrap-docker", choices=["yes", "no"], default=None,
                    help="Answer the Ubuntu/Debian Docker-bootstrap prompt "
                         "non-interactively — the flag wins over the prompt, "
                         "exactly like --tls. Without it, non-TTY behavior is "
                         "unchanged.")
    ap.add_argument("--snmp-discovery", default=None, metavar="CIDR[,CIDR]",
                    help="Enable SNMP discovery scoped to these CIDR ranges: sets "
                         "ENABLE_SNMP_DISCOVERY=true + SNMP_CIDR_RANGES in .env "
                         "(line surgery on an existing .env). Absent flag keeps "
                         "discovery off (the opt-in default).")
    args = ap.parse_args()
    if args.progress_json:
        _PROGRESS["on"] = True
    if args.bundle:
        args.offline = True

    # --snmp-discovery: validate every CIDR at the boundary (§3) BEFORE any
    # install step runs — an invalid range must fail fast, not after compose up.
    if args.snmp_discovery is not None:
        cidrs = [c.strip() for c in args.snmp_discovery.split(",") if c.strip()]
        if not cidrs:
            fail("--snmp-discovery needs at least one CIDR, "
                 "e.g. --snmp-discovery 10.70.0.0/16")
        for c in cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                fail(f"--snmp-discovery: {c!r} is not a valid CIDR "
                     "(e.g. 10.70.0.0/16)")
        args.snmp_discovery = ",".join(cidrs)

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
                _write_private(Path(src), Path(bak).read_text())
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
            check_docker(args.bootstrap_docker)
        _rotated, failures = rotate_secrets(
            root, compose_dir, env_path, strict=False,
            allow_kafka_wipe=args.rotate_kafka_cluster_id,
            assume_yes=args.assume_yes)
        print()
        info("apply the new values (recreates the services that consume them):")
        info("    cd deployment/docker && docker compose up -d --force-recreate")
        if args.rotate_kafka_cluster_id:
            # SEC-007: the wiped data/kafka is also the KRaft ACL store — on a
            # TLS install the recreated broker enforces default-deny over ZERO
            # ACLs (silently auth-dead bus, live incident 2026-08-16).
            info("data/kafka was moved aside: on a TLS install the recreated "
                 "broker boots an EMPTY ACL store (default-deny = auth-dead "
                 "bus). After the recreate, re-run `python3 scripts/install.py` "
                 "(idempotent; applies + verifies the SEC-007 matrix) or run "
                 "the runbook step: docker compose exec kafka /acls/apply-acls.sh")
        if failures:
            fail(f"{failures} secret(s) could not be rotated (details above)")
        return

    # The install proper starts here — arm the timing instrument (the standalone
    # replan/rotate/rollback paths above run no stages and write no timing).
    _TIMING["record"] = True
    _TIMING["report"] = args.time_report
    _TIMING["path"] = root / "data" / "install-timing.json"

    step("checking prerequisites", stage="prereq")
    check_docker(args.bootstrap_docker)

    step("validating scaffold", stage="scaffold")
    # A build only happens on the online, starting path: --offline/--bundle pass
    # --no-build to compose, and --no-start returns before compose runs at all.
    validate_scaffold(root, will_build=not (args.no_start or args.offline))

    step("generating environment", stage="env")
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

    # --snmp-discovery: same line-surgery doctrine as --tls, so a fresh
    # template and an existing operator-edited .env converge identically.
    if args.snmp_discovery:
        enable_snmp_discovery_env(env_path, args.snmp_discovery)

    if args.plan_resources:
        step("planning resources (#102)", stage="sizing")
        run_resource_plan(env_path, args.plan_resources, args.sizing_file)

    # The one transport-security question (tracker #151 delivery shape).
    # Resolved AFTER .env exists so both fresh and existing installs converge
    # through the same line-surgery path; the actual activation is two-phase
    # around compose_up below.
    tls_enabled = resolve_tls_choice(args)
    dash_url = "https://localhost/" if tls_enabled else f"http://localhost:{args.port}"
    if tls_enabled:
        step("enabling TLS/mTLS transport security", stage="tls-env")
        enable_tls_env(env_path)
        augment_profiles_for_tls(env_path)
        ensure_ingress_cert(root)

    step("preparing data directories", stage="data-dirs")
    ensure_data_dirs(root)

    if args.no_start:
        if tls_enabled:
            ok(".env and data/ ready with TLS variables set. compose.tls.yml is "
               "NOT yet activated (the two-phase mint needs a running stack) — "
               "rerun without --no-start to complete enablement.")
        else:
            ok(".env and data/ ready. Skipping docker compose up (per --no-start).")
        _result_ok(dash_url, _parse_env(env_path).get("ADMIN_USERNAME", "admin"))
        _timing_finish("ok")
        return

    if args.bundle:
        step("loading image bundle", stage="bundle")
        load_bundle(args.bundle)

    if args.offline:
        write_offline_override(compose_dir, env_path)

    # Phase A (TLS): the baseline stack boots with the mint variables set; the
    # api's internal CA writes every SVID to data/tls while the stores are
    # still plaintext. On a rerun with certs already minted this converges in
    # one pass (the sentinels exist, the variant is already in the chain).
    step("starting stack" + (" (TLS phase A: mint identities)" if tls_enabled else ""),
         stage="up-a")
    compose_up(compose_dir, offline=args.offline, root=root)

    if tls_enabled:
        wait_for_minted_certs(root)
        activate_tls_compose_file(compose_dir, env_path)
        step("starting stack (TLS phase B: fail-closed mesh)", stage="up-b")
        compose_up(compose_dir, offline=args.offline, root=root)

    # SEC-007 P0 (2026-08-16): with default-deny enforced, an empty KRaft ACL
    # store (fresh install, data/kafka wipe) is a silently auth-dead ingest
    # tier — apply + verify the matrix before claiming success. No-op on the
    # plaintext baseline (no authorizer) and external brokers (owner-managed).
    apply_bus_authorization(compose_dir, env_path, tls_enabled)

    step("status", stage="status")
    compose_status(compose_dir)

    step("bootstrap OpenSearch index templates", stage="bootstrap-os")
    bootstrap_opensearch(root, tls=tls_enabled)

    # Gate on the EFFECTIVE profiles from .env — the source of truth compose_up
    # starts from — not args.profiles, which an existing install's .env ignores.
    active = {p.strip() for p in
              _parse_env(env_path).get("COMPOSE_PROFILES", "").split(",")}
    if "sso" in active:
        step("bootstrap Keycloak database (profile sso)", stage="bootstrap-kc")
        bootstrap_keycloak_db(compose_dir, _parse_env(env_path))

    if "self-monitoring" in args.profiles:
        step("wiring grafana clickhouse datasource", stage="bootstrap-grafana")
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
        print("    user: admin")
        print(f"    pass: (see ADMIN_INITIAL_PASSWORD in {env_path})")
        print("    -> Change it on Settings > Change password.")
    if "GRAFANA_ADMIN_PASSWORD" in secrets_map:
        print()
        print("  First-time Grafana login (separate from app auth):")
        print("    user: admin")
        print(f"    pass: (see GRAFANA_ADMIN_PASSWORD in {env_path})")
    print()
    print("  Stop:      cd deployment/docker && docker compose down")
    print("  Logs:      cd deployment/docker && docker compose logs -f")
    print("==============================================================")
    # Terminal machine-readable marker (GUI contract): url + admin_user ONLY —
    # the password never rides a progress event.
    _result_ok(dash_url, _parse_env(env_path).get("ADMIN_USERNAME", "admin"))
    _timing_finish("ok")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        fail(f"command failed (exit {e.returncode}): {' '.join(e.cmd)}")
    except KeyboardInterrupt:
        print()
        fail("interrupted")
