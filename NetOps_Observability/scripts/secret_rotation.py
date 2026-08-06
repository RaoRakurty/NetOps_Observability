#!/usr/bin/env python3
"""secret_rotation.py — the policy behind `install.py --reset-env`.

WHY THIS MODULE EXISTS (audit FUNC-HIGH-1)
------------------------------------------
`--reset-env` used to regenerate EVERY value in the generated `.env` and do
nothing else. On an install that had already started, that was not a rotation —
it was an outage:

  * `KAFKA_CLUSTER_ID` was regenerated even though the .env's own comment says
    it must never change after first start. The embedded broker's data dir is
    formatted with that id, nothing wiped it, so the broker refused its own
    volume and the whole bus/ingest path died.
  * `DB_PASSWORD` / `CLICKHOUSE_PASSWORD` / `NETBOX_DB_PASSWORD` were rewritten
    in .env but never applied to the stores, which only provision credentials on
    the FIRST boot of an empty volume. The API then could not authenticate.

Both are the same defect: writing a new value where nothing consumes it and
calling that "rotated". A secret is only rotated when the thing that VALIDATES
it has been changed too. So every secret is classified by what rotating it
actually requires, and anything this tool cannot complete is REFUSED loudly
before a single byte of .env is written.

THE FIVE CLASSES
----------------
free       The consuming process re-reads it from the environment at every
           start. Rewrite .env + `docker compose up -d` and it is genuinely
           rotated.
alter      The value provisioned a credential inside a store's own catalog on
           first boot. Rotation = ALTER on the LIVE store, verified with the new
           credential, before .env is written.
recreate   The store re-derives the credential from its environment at every
           container start, but the RUNNING container still holds the old one.
           Rotation = write .env, force-recreate that one service, verify.
seeded     Written into a store's user table on first boot ONLY, with no safe
           reconcile from here (Grafana/Keycloak/NetBox admin users, the local
           API admin seed). Refused once the store is initialized; the operator
           is told the product's own reset path.
immutable  Identity of an on-disk format (KAFKA_CLUSTER_ID). Never rotated in
           place. Requires an explicit destructive opt-in that moves the
           broker's data dir aside.

On an install that has never started, EVERY class is freely rotatable — the
store takes the value on its first boot. That state is detected from the data/
volumes (see `store_initialized`), never assumed.

Stdlib only (install.py's ethos + CLAUDE.md §6). No side effects on import.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Callable, Iterable, NamedTuple

# ---- classes ----------------------------------------------------------------

FREE = "free"
ALTER = "alter"
RECREATE = "recreate"
SEEDED = "seeded"
IMMUTABLE = "immutable"

#: Classes whose rotation touches a live store and therefore needs a preflight.
NEEDS_STORE = (ALTER, RECREATE)


class Policy(NamedTuple):
    cls: str
    store: str      # key into STORE_DIRS/STORE_MARKERS; "" for class free
    why: str        # why a plain .env rewrite is not a rotation
    remedy: str     # what the operator must do when this one is blocked


# Every secret install.py generates MUST appear here. tests/test_secret_rotation
# fails the build if a new generated secret is added without a classification —
# an unclassified store credential is exactly how FUNC-HIGH-1 happened.
POLICY: dict[str, Policy] = {
    # ---- free: read from the environment at every process start -------------
    "JWT_SECRET": Policy(
        FREE, "", "", ""),
    "ENCRYPTION_KEY": Policy(
        FREE, "", "", ""),
    "INGEST_TOKEN": Policy(
        FREE, "", "", ""),
    # SEC-013.2 per-lane tokens: same read-at-start contract as INGEST_TOKEN —
    # vector expands them from env, producers read theirs at process start.
    "INGEST_TOKEN_TRAPS": Policy(
        FREE, "", "", ""),
    "INGEST_TOKEN_PROBES": Policy(
        FREE, "", "", ""),
    "INGEST_TOKEN_METRICS": Policy(
        FREE, "", "", ""),
    "INGEST_TOKEN_BUS": Policy(
        FREE, "", "", ""),
    "NETBOX_SECRET_KEY": Policy(
        FREE, "", "", ""),
    # SEC-010 vmauth per-service credentials: vmauth expands them from env at
    # start; each CLIENT reads its URL env at start too — rotation = reset-env
    # then recreate vmauth + the owning client.
    "VMAUTH_API_PASSWORD": Policy(
        FREE, "", "", ""),
    "VMAUTH_GNMIC_PASSWORD": Policy(
        FREE, "", "", ""),
    "VMAUTH_VECTOR_PASSWORD": Policy(
        FREE, "", "", ""),
    "VMAUTH_VMALERT_PASSWORD": Policy(
        FREE, "", "", ""),
    "VMAUTH_GRAFANA_PASSWORD": Policy(
        FREE, "", "", ""),
    # SEC-012: valkey reads --requirepass from env at start; clients read it at
    # their start — rotation = reset-env then recreate redis + api + prober.
    "REDIS_PASSWORD": Policy(
        FREE, "", "", ""),
    # SEC-008: applied to the security index by the opensearch-init bootstrap,
    # which re-runs on every stack start — a changed env var converges without
    # operator action (hence FREE, not ALTER).
    "OS_API_PASSWORD": Policy(
        FREE, "", "", ""),
    "OS_ROUTER_PASSWORD": Policy(
        FREE, "", "", ""),
    "OS_CORRELATION_PASSWORD": Policy(
        FREE, "", "", ""),
    "OS_BOOTSTRAP_PASSWORD": Policy(
        FREE, "", "", ""),
    "OS_DASHBOARDS_PASSWORD": Policy(
        FREE, "", "", ""),
    # F-17 stats identity (svc_aggregator) — same bootstrap-applied contract.
    "OS_AGGREGATOR_PASSWORD": Policy(
        FREE, "", "", ""),

    # ---- alter: a credential inside a store's own catalog -------------------
    "DB_PASSWORD": Policy(
        ALTER, "postgres",
        "Postgres provisions POSTGRES_PASSWORD only on the first boot of an "
        "empty data dir; the running server still validates the old one.",
        "start the database and re-run:  cd deployment/docker && "
        "docker compose up -d postgres"),
    "NETBOX_DB_PASSWORD": Policy(
        ALTER, "netbox-postgres",
        "The bundled NetBox database provisions its password only on the first "
        "boot of an empty data dir.",
        "start it and re-run:  cd deployment/docker && "
        "docker compose --profile netbox up -d netbox-postgres"),
    "GRAFANA_CH_PASSWORD": Policy(
        ALTER, "clickhouse",
        "The read-only `grafana` ClickHouse user is created by install.py with "
        "this password; ClickHouse keeps the credential, not the .env.",
        "start ClickHouse and re-run:  cd deployment/docker && "
        "docker compose up -d clickhouse"),

    # ---- recreate: re-read from the container environment at start ----------
    "CLICKHOUSE_PASSWORD": Policy(
        RECREATE, "clickhouse",
        "The running ClickHouse container still validates the password it was "
        "created with; the new one only takes effect on a container recreate.",
        "start ClickHouse and re-run:  cd deployment/docker && "
        "docker compose up -d clickhouse"),

    # ---- seeded: first-boot-only user seeding, no safe reconcile from here ---
    "ADMIN_INITIAL_PASSWORD": Policy(
        SEEDED, "api-users",
        "This value only seeds the FIRST admin when the user store is empty. "
        "The store already exists, so it is inert — and deleting it to force a "
        "re-seed would destroy every account created since.",
        "change the password in the dashboard (Settings -> Change password), "
        "or, if you are locked out, wipe the user store deliberately with "
        "scripts/reset-admin.sh"),
    "GRAFANA_ADMIN_PASSWORD": Policy(
        SEEDED, "grafana",
        "Grafana stores the admin password in its own database and only takes "
        "GF_SECURITY_ADMIN_PASSWORD when that database is created.",
        "rotate it in Grafana:  cd deployment/docker && docker compose exec -T "
        "grafana grafana cli admin reset-admin-password --password-from-stdin "
        "  (then set the same value as GRAFANA_ADMIN_PASSWORD in .env)"),
    "KEYCLOAK_ADMIN_PASSWORD": Policy(
        SEEDED, "keycloak",
        "KC_BOOTSTRAP_ADMIN_PASSWORD only creates the bootstrap admin on an "
        "empty Keycloak database.",
        "rotate it in the Keycloak console (Users -> admin -> Credentials), "
        "then set the same value as KEYCLOAK_ADMIN_PASSWORD in .env"),
    "NETBOX_SUPERUSER_PASSWORD": Policy(
        SEEDED, "netbox-postgres",
        "NetBox creates its superuser on first boot and never updates an "
        "existing one from SUPERUSER_PASSWORD.",
        "rotate it in NetBox (/netbox/ -> admin -> change password), then set "
        "the same value as NETBOX_SUPERUSER_PASSWORD in .env"),
    "NETBOX_TOKEN": Policy(
        SEEDED, "netbox-postgres",
        "SUPERUSER_API_TOKEN is only minted when the token does not exist; a "
        "new value in .env would make the API present a token NetBox rejects.",
        "mint a replacement in NetBox (Admin -> API Tokens), revoke the old "
        "one, then set the new value as NETBOX_TOKEN in .env"),

    # ---- immutable: identity of an on-disk format ---------------------------
    "KAFKA_CLUSTER_ID": Policy(
        IMMUTABLE, "kafka",
        "The embedded broker formatted data/kafka with this id. A new id makes "
        "the broker refuse its own volume on the next start and takes the "
        "entire bus/ingest path down with it.",
        "keep it (recommended), or re-run with --rotate-kafka-cluster-id to "
        "rotate the id AND move data/kafka aside — DESTRUCTIVE: every topic, "
        "offset and in-flight message on the embedded bus is discarded"),
}


# ---- store state -------------------------------------------------------------

#: Bind-mount roots (relative to the project root) backing each store.
STORE_DIRS: dict[str, str] = {
    "postgres": "data/postgres",
    "clickhouse": "data/clickhouse",
    "kafka": "data/kafka",
    "netbox-postgres": "data/netbox-postgres",
    "grafana": "data/grafana",
    "api-users": "data/api",
}

#: Unambiguous "this volume has been initialized" markers. A marker hit is
#: proof; its absence is not — see store_initialized.
STORE_MARKERS: dict[str, tuple[str, ...]] = {
    "postgres": ("data/postgres/PG_VERSION",),
    "clickhouse": ("data/clickhouse/status", "data/clickhouse/metadata",
                   "data/clickhouse/store"),
    "kafka": ("data/kafka/meta.properties",),
    "netbox-postgres": ("data/netbox-postgres/PG_VERSION",),
    "grafana": ("data/grafana/grafana.db",),
    "api-users": ("data/api/users.json",),
}

def store_initialized(root: Path, store: str, profiles: str = "") -> bool:
    """Has this store's volume ever been written by its service?

    Fail-SAFE: anything we cannot prove is fresh is reported as initialized.
    A false "fresh" is the FUNC-HIGH-1 outage; a false "initialized" only costs
    the operator a refusal they can override with an explicit flag.
    """
    if store == "keycloak":
        # Keycloak has no volume of its own — it lives in a database inside the
        # main Postgres, created by hand, and only runs under the `sso` profile.
        return ("sso" in _csv(profiles)) and store_initialized(root, "postgres")
    for marker in STORE_MARKERS.get(store, ()):
        if (root / marker).exists():
            return True
    rel = STORE_DIRS.get(store)
    if rel is None:
        return True                     # unknown store: assume the worst
    d = root / rel
    if not d.exists():
        return False
    try:
        return any(d.iterdir())
    except OSError:
        # Unreadable because the service (running as its own uid) owns it —
        # which is itself evidence that the service has been there.
        return True


def install_started(root: Path, profiles: str = "") -> bool:
    """True if ANY persistent store has been initialized."""
    return any(store_initialized(root, s, profiles) for s in STORE_DIRS)


def _csv(v: str) -> list[str]:
    return [p.strip() for p in (v or "").split(",") if p.strip()]


# ---- classification ----------------------------------------------------------

class Verdict(NamedTuple):
    name: str
    cls: str
    rotatable: bool
    reconcile: bool     # rotating it requires touching a live store
    store: str
    why: str            # why it is blocked / why it needs reconciliation
    remedy: str


def classify(root: Path, profiles: str = "", *,
             allow_kafka_wipe: bool = False,
             names: Iterable[str] | None = None) -> list[Verdict]:
    """Classify each secret against the CURRENT on-disk state of the install."""
    out: list[Verdict] = []
    for name in sorted(names if names is not None else POLICY):
        pol = POLICY.get(name)
        if pol is None:
            # Unclassified = unknown blast radius. Refuse rather than guess.
            out.append(Verdict(name, "unknown", False, False, "",
                               "this secret has no rotation classification",
                               "classify it in scripts/secret_rotation.py:POLICY"))
            continue
        if pol.cls == FREE:
            out.append(Verdict(name, pol.cls, True, False, "", "", ""))
            continue
        if not store_initialized(root, pol.store, profiles):
            # Fresh volume: the store adopts whatever .env says on first boot.
            out.append(Verdict(name, pol.cls, True, False, pol.store, "", ""))
            continue
        if pol.cls in NEEDS_STORE:
            out.append(Verdict(name, pol.cls, True, True, pol.store,
                               pol.why, pol.remedy))
        elif pol.cls == IMMUTABLE and allow_kafka_wipe and name == "KAFKA_CLUSTER_ID":
            out.append(Verdict(name, pol.cls, True, True, pol.store, pol.why,
                               pol.remedy))
        else:
            out.append(Verdict(name, pol.cls, False, False, pol.store,
                               pol.why, pol.remedy))
    return out


def blocked(verdicts: Iterable[Verdict]) -> list[Verdict]:
    return [v for v in verdicts if not v.rotatable]


CLASS_LABEL = {
    SEEDED: "seeded into its store on first boot only",
    IMMUTABLE: "immutable after first start",
    ALTER: "lives in the store's own catalog",
    RECREATE: "held by the running container",
    "unknown": "UNCLASSIFIED",
}


def refusal_text(blocked_verdicts: list[Verdict], total: int,
                 *, command: str = "--reset-env") -> str:
    """The exact operator-facing refusal. Names only — never values."""
    width = max((len(v.name) for v in blocked_verdicts), default=0)
    lines = [
        f"{command} cannot rotate {len(blocked_verdicts)} of the {total} generated "
        "secrets on this install.",
        "Nothing was written: a .env that no longer matches the running stores is",
        "worse than no rotation at all.",
        "",
    ]
    for v in blocked_verdicts:
        pad = f"  {' ' * width}    "
        lines.append(f"  {v.name.ljust(width)}  {CLASS_LABEL.get(v.cls, v.cls)}")
        for chunk in _wrap(v.why, 68):
            lines.append(f"{pad}   {chunk}")
        for i, chunk in enumerate(_wrap(v.remedy, 68)):
            lines.append(f"{pad}{'-> ' if i == 0 else '   '}{chunk}")
        lines.append("")
    lines += [
        "  Rotate everything that CAN be rotated safely right now (application",
        "  secrets plus every live store credential this tool can reconcile and",
        "  verify), leaving the entries above untouched:",
        "",
        "      python3 scripts/install.py --rotate-app-secrets",
        "",
        "  See docs/runbooks/secret-rotation.md for the full matrix.",
    ]
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, line, out = (text or "").split(), "", []
    for w in words:
        if line and len(line) + 1 + len(w) > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


# ---- .env line surgery -------------------------------------------------------

def substitute_env(text: str, updates: dict[str, str]) -> tuple[str, list[str]]:
    """Replace `KEY=...` lines in place, leaving every other byte alone.

    A running install's .env carries operator state the template does not know
    about (feature flags, SMTP, OIDC, the managed resource-plan block, an
    offline COMPOSE_FILE). Regenerating the whole file to rotate a password
    silently reverts all of it, so rotation is a line substitution.

    Returns (new_text, keys_not_found).
    """
    remaining = dict(updates)
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        m = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)=", body)
        if m and m.group(2) in remaining:
            key = m.group(2)
            eol = line[len(body):]
            out.append(f"{m.group(1)}{key}={remaining.pop(key)}{eol or os.linesep}")
        else:
            out.append(line)
    return "".join(out), sorted(remaining)


# ---- live-store reconciliation ----------------------------------------------

class ExecResult(NamedTuple):
    returncode: int
    stdout: str = ""
    stderr: str = ""


# A runner is anything with .exec(service, argv, stdin=..., timeout=...) and
# .recreate(service). install.py supplies the docker-compose one; tests supply a
# fake, so nothing here needs a live stack to be exercised (CLAUDE.md §2/§11:
# every external dependency is injected, never reached for directly).
Sleep = Callable[[float], None]


def _sq(value: str) -> str:
    """Single-quote a value for both SQL literals and /bin/sh."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def _sql_lit(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ident(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def redact(message: str, secretvalues: Iterable[str]) -> str:
    """Never let a store's error text carry a credential into a log (§8)."""
    out = (message or "").strip()
    for s in secretvalues:
        if s and len(s) >= 8:
            out = out.replace(s, "***")
    return out[:400]


# -- Postgres (main app DB and the bundled NetBox DB) --------------------------

def _pg_probe(runner, service: str, user: str, db: str) -> ExecResult:
    """Reach the server over its local socket (trust auth inside the container).
    Carries no credential in argv, so it is also the preflight."""
    return runner.exec(service, ["psql", "-v", "ON_ERROR_STOP=1", "-U", user,
                                 "-d", db, "-tAc", "SELECT 1"], stdin="", timeout=30)


def _pg_verify(runner, service: str, user: str, db: str, password: str) -> bool:
    """Prove the credential works over TCP, exactly as the app authenticates.
    The password is piped in as a shell script on stdin — never in argv, so it
    cannot appear in the host's process table."""
    script = (
        "set -eu\n"
        f"PGPASSWORD={_sq(password)} psql -h 127.0.0.1 -p 5432 "
        f"-U {_sq(user)} -d {_sq(db)} -tAc 'SELECT 1' >/dev/null\n"
    )
    return runner.exec(service, ["sh", "-s"], stdin=script, timeout=30).returncode == 0


def reconcile_postgres(runner, *, service: str, user: str, db: str,
                       new_password: str) -> tuple[bool, str]:
    """ALTER the live role, then prove the new credential authenticates.

    Idempotent: if the store already validates the new password (a re-run after
    a partial rotation) it returns without touching anything.
    """
    if _pg_verify(runner, service, user, db, new_password):
        return True, "already applied (store already accepts the new credential)"
    sql = f"ALTER USER {_ident(user)} WITH PASSWORD {_sql_lit(new_password)};\n"
    r = runner.exec(service, ["psql", "-v", "ON_ERROR_STOP=1", "-U", user,
                              "-d", "postgres"], stdin=sql, timeout=60)
    if r.returncode != 0:
        return False, f"ALTER USER failed: {redact(r.stderr or r.stdout, [new_password])}"
    if not _pg_verify(runner, service, user, db, new_password):
        return False, "ALTER USER reported success but the new credential does not authenticate"
    return True, "ALTER USER applied and verified"


# -- ClickHouse ----------------------------------------------------------------

def _ch_client(runner, user: str, password: str, sql: str,
               timeout: int = 60) -> ExecResult:
    """Run SQL as `user`. The whole invocation is delivered on stdin so the
    credential never reaches the host's argv (the pre-existing bootstrap path
    passed --password on the docker CLI command line; this does not)."""
    script = (
        "set -eu\n"
        f"PW={_sq(password)}\n"
        f"clickhouse-client --user {_sq(user)} --password \"$PW\" --multiquery <<'__SQL__'\n"
        f"{sql}\n"
        "__SQL__\n"
    )
    return runner.exec("clickhouse", ["sh", "-s"], stdin=script, timeout=timeout)


def _ch_verify(runner, user: str, password: str) -> bool:
    return _ch_client(runner, user, password, "SELECT 1;", timeout=30).returncode == 0


def reconcile_clickhouse_admin(runner, *, user: str, old_password: str,
                               new_password: str, allow_recreate: bool = True,
                               sleep: Sleep = time.sleep,
                               attempts: int = 30) -> tuple[bool, str]:
    """Move the ClickHouse admin user onto the new password.

    Two strategies, in order, because which one applies depends on how the
    image provisioned the user and that is not knowable from here:
      1. ALTER USER — works when the user lives in ClickHouse's SQL access
         storage.
      2. force-recreate the container — the official image regenerates
         users.d/default-user.xml from CLICKHOUSE_PASSWORD at every start, and
         a config-file user cannot be ALTERed ("readonly storage").
    Either way the function only reports success after authenticating with the
    NEW credential. Requires .env to already hold the new value for (2).
    """
    if _ch_verify(runner, user, new_password):
        return True, "already applied (store already accepts the new credential)"
    r = _ch_client(runner, user, old_password,
                   f"ALTER USER {_ident(user)} IDENTIFIED BY {_sql_lit(new_password)};")
    if r.returncode == 0 and _ch_verify(runner, user, new_password):
        return True, "ALTER USER applied and verified"
    if not allow_recreate:
        return False, ("ALTER USER did not take: "
                       + redact(r.stderr or r.stdout, [old_password, new_password]))
    rr = runner.recreate("clickhouse")
    if rr.returncode != 0:
        return False, ("container recreate failed: "
                       + redact(rr.stderr or rr.stdout, [old_password, new_password]))
    for _ in range(max(1, attempts)):
        if _ch_verify(runner, user, new_password):
            return True, "container recreated with the new password and verified"
        sleep(2)
    return False, "ClickHouse did not accept the new password after a container recreate"


def reconcile_grafana_ch_user(runner, *, admin_user: str, admin_password: str,
                              grafana_password: str) -> tuple[bool, str]:
    """Create-or-update the read-only `grafana` ClickHouse user (idempotent).

    tenant_scope='' stays pinned CONST + readonly=2 so the datasource can only
    ever see untagged platform/infra rows (CLAUDE.md §3a)."""
    lit = _sql_lit(grafana_password)
    sql = (
        f"CREATE USER IF NOT EXISTS grafana IDENTIFIED BY {lit};\n"
        f"ALTER USER grafana IDENTIFIED BY {lit} "
        "SETTINGS tenant_scope = '' CONST, readonly = 2;\n"
        "GRANT SELECT ON netops.flows TO grafana;\n"
        "GRANT SELECT ON netops.findings TO grafana;\n"
        "GRANT SELECT ON netops.tunnels TO grafana;\n"
    )
    r = _ch_client(runner, admin_user, admin_password, sql)
    if r.returncode != 0:
        return False, ("could not update the grafana ClickHouse user: "
                       + redact(r.stderr or r.stdout,
                                [admin_password, grafana_password]))
    if not _ch_verify(runner, "grafana", grafana_password):
        return False, "the grafana ClickHouse user does not accept its new password"
    return True, "grafana ClickHouse user updated and verified"


# ---- preflight ---------------------------------------------------------------

def preflight(runner, name: str, env: dict[str, str],
              new_password: str = "") -> tuple[bool, str]:
    """Can this secret's store be reconciled RIGHT NOW? Runs before any write.

    Deliberately tolerant of a .env that has already drifted from its store
    (e.g. a half-finished rotation from the old --reset-env): reachability is
    the gate, because re-applying is exactly the repair.
    """
    if name == "DB_PASSWORD":
        r = _pg_probe(runner, "postgres", env.get("DB_USER", "netops"),
                      env.get("DB_NAME", "netops"))
        if r.returncode != 0:
            return False, "postgres is initialized but not reachable"
        return True, ""
    if name == "NETBOX_DB_PASSWORD":
        r = _pg_probe(runner, "netbox-postgres", "netbox", "netbox")
        if r.returncode != 0:
            return False, "the bundled NetBox database is initialized but not reachable"
        return True, ""
    if name in ("CLICKHOUSE_PASSWORD", "GRAFANA_CH_PASSWORD"):
        user = env.get("CLICKHOUSE_USER", "netops")
        cur = env.get("CLICKHOUSE_PASSWORD", "")
        if _ch_verify(runner, user, cur):
            return True, ""
        if new_password and _ch_verify(runner, user, new_password):
            return True, ""
        return False, ("ClickHouse is initialized but did not accept the admin "
                       "credential in .env")
    return True, ""


__all__ = [
    "FREE", "ALTER", "RECREATE", "SEEDED", "IMMUTABLE", "POLICY", "Policy",
    "Verdict", "ExecResult", "STORE_DIRS", "STORE_MARKERS",
    "classify", "blocked", "refusal_text", "store_initialized",
    "install_started", "substitute_env", "preflight", "reconcile_postgres",
    "reconcile_clickhouse_admin", "reconcile_grafana_ch_user", "redact",
]
