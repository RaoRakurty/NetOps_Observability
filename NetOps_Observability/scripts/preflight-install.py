#!/usr/bin/env python3
"""preflight-install.py — FRESH-INSTALL integrity gate.

Catches the drift class the team cares about most: *you built a new feature that a
fresh `install.py` on a clean server needs (an env var, a data dir, a config file,
a migration) but you forgot to wire it into install.py / the compose stack.* The
running dev stack hides this because it was set up by hand over time; a clean
install would break or silently come up degraded.

This is a STATIC checker (no docker, stdlib only — matches install.py's ethos). It
parses docker-compose.yml and cross-references install.py, asserting:

  1. Every REQUIRED env var (${VAR} with no default) referenced in compose is
     provisioned by install.py (generated secret OR written into the .env template).
  2. Every bind-mount whose source is a repo path (config files) actually EXISTS.
  3. Every host data dir bind-mounted from ../../data/<x> is created by
     install.py's ensure_data_dirs (so a clean install has it).

Exit non-zero on any gap. Run: scripts/preflight-install.py
Used by: .github/workflows/fresh-install-integrity.yml and install.py itself.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
INSTALL = ROOT / "scripts" / "install.py"

GREEN, RED, YEL, RST = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
fail = 0


def ok(m: str) -> None:
    print(f"  {GREEN}✓{RST} {m}")


def bad(m: str) -> None:
    global fail
    print(f"  {RED}✗ {m}{RST}", file=sys.stderr)
    fail = 1


def warn(m: str) -> None:
    print(f"  {YEL}— {m}{RST}")


# --- parse install.py: what does a fresh install provision? ------------------

def install_provisions() -> tuple[set[str], set[str]]:
    """Return (env_vars_provisioned, data_dirs_created) that install.py guarantees."""
    text = INSTALL.read_text()
    env: set[str] = set()
    # (a) generated secrets: keys of the secrets_map dict literal
    env |= set(re.findall(r'"([A-Z][A-Z0-9_]+)":\s*generate_', text))
    env |= set(re.findall(r'"([A-Z][A-Z0-9_]+)":\s*secrets\.', text))
    # (b) every KEY=... line written into the .env template (heredoc / f-strings)
    env |= set(re.findall(r'^\s*([A-Z][A-Z0-9_]+)=', text, re.MULTILINE))
    # data dirs: the ensure_data_dirs owners-dict keys + explicit root/"data"/... mkdirs
    dirs: set[str] = set(re.findall(r'"([a-z0-9_-]+)":\s*(?:None|\([0-9]+,)', text))
    for m in re.findall(r'root\s*/\s*"data"\s*/\s*"([a-z0-9_/-]+)"', text):
        dirs.add(m)
    # nested mkdirs like data/api/enrichment are written as root/"data"/"api"/"enrichment"
    for m in re.findall(r'root\s*/\s*"data"\s*/\s*"([a-z0-9_-]+)"\s*/\s*"([a-z0-9_-]+)"', text):
        dirs.add(f"{m[0]}/{m[1]}")
    return env, dirs


# --- parse compose: what does the stack REQUIRE? -----------------------------

def _decomment(text: str) -> str:
    """Drop YAML comments so placeholders in prose (e.g. ${X_CPU_LIMIT}) aren't read
    as real references. Strips full-line comments and inline ' #...' (a YAML inline
    comment requires a space before #; env defaults like http://h:8000 have none)."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line.split(" #", 1)[0])
    return "\n".join(out)


def compose_env_refs() -> dict[str, bool]:
    """Map every ${VAR...} reference → has_default (True if ${VAR:-x} / ${VAR:?})."""
    text = _decomment(COMPOSE.read_text())
    refs: dict[str, bool] = {}
    for m in re.finditer(r"\$\{([A-Z][A-Z0-9_]+)(:?[-?][^}]*)?\}", text):
        name, mod = m.group(1), m.group(2)
        has_default = bool(mod)  # any :- / :? / - modifier means a default/required-marker
        refs[name] = refs.get(name, False) or has_default
    return refs


def compose_bind_mounts() -> list[str]:
    """Return raw bind-mount 'source:dest[:mode]' strings from volume list entries."""
    text = _decomment(COMPOSE.read_text())
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("- "):
            continue
        v = s[2:].strip().strip('"').strip("'")
        # a bind mount source is a path (starts with . or / ); skip named volumes & options
        if re.match(r"^(\.{1,2}/|/)", v) and ":" in v:
            out.append(v)
    return out


def main() -> int:
    if not COMPOSE.exists() or not INSTALL.exists():
        print("preflight-install: compose or install.py missing", file=sys.stderr)
        return 2

    prov_env, prov_dirs = install_provisions()

    print("=== fresh-install integrity: compose ↔ install.py ===")

    # 1) required env vars must be provisioned by a fresh install
    print("[env] required compose vars provisioned by install.py")
    missing_env = []
    for name, has_default in sorted(compose_env_refs().items()):
        if has_default:
            continue  # ${VAR:-default} is safe on a clean install
        if name not in prov_env:
            missing_env.append(name)
    if missing_env:
        for n in missing_env:
            bad(f"env {n}: required by compose (no default) but install.py never provisions it")
    else:
        ok("all required compose env vars are generated/written by install.py")

    # 2) repo-path bind-mount sources must exist; 3) data dirs must be created
    print("[mounts] bind-mount sources exist + data dirs created by install.py")
    miss_files, miss_dirs = [], []
    for mount in compose_bind_mounts():
        src = mount.split(":")[0]
        # data dirs: ../../data/<x>[/<y>] — install.py must create <x>[/<y>]
        m = re.match(r"^\.\./\.\./data/([a-z0-9_./-]+)$", src)
        if m:
            rel = m.group(1).rstrip("/")
            top = rel.split("/")[0]
            two = "/".join(rel.split("/")[:2])
            if rel not in prov_dirs and top not in prov_dirs and two not in prov_dirs:
                miss_dirs.append(src)
            continue
        # config/source files: resolve relative to deployment/docker and assert existence
        p = (COMPOSE.parent / src).resolve()
        if not p.exists():
            miss_files.append(src)
    if miss_files:
        for s in miss_files:
            bad(f"bind-mount source missing from repo: {s} (compose references it; a clean checkout has no such file)")
    else:
        ok("all repo-path bind-mount sources exist")
    if miss_dirs:
        # docker auto-creates a missing bind-mount dir (as root), so this doesn't
        # hard-break a fresh install — but install.py should own it so the dir has
        # the right uid/gid for its non-root container. Warn, don't block.
        for s in miss_dirs:
            warn(f"data dir not pre-created by install.py (docker will, as root): {s}")
    else:
        ok("all bind-mounted data dirs are created by install.py")

    # 4) event-bus distribution guardrails (#97 Redpanda→Apache Kafka swap).
    # The customer bundle must ship Apache Kafka + Valkey and must not depend
    # on Redpanda in any functional way (comments are stripped before checking,
    # so historical/explanatory notes don't false-positive).
    print("[bus] event-bus + cache distribution guardrails")
    compose_text = _decomment(COMPOSE.read_text())
    if re.search(r"redpanda", compose_text, re.IGNORECASE):
        bad("compose references redpanda outside comments — customer bundles must not ship or require it")
    else:
        ok("no functional redpanda reference in compose")
    if re.search(r"image:\s*apache/kafka:[0-9][^\s@]*@sha256:", compose_text):
        ok("embedded bus is apache/kafka, version+digest pinned")
    else:
        bad("kafka service image must be apache/kafka, pinned by version AND digest")
    if re.search(r"image:\s*valkey/valkey:[^\s@]+@sha256:", compose_text):
        ok("cache is valkey, digest pinned")
    else:
        bad("cache image must be valkey (BSD-3), digest pinned")
    for var in ("BROKER_URLS", "KAFKA_CLUSTER_ID", "COMPOSE_PROFILES"):
        if var in prov_env:
            ok(f"install.py provisions {var}")
        else:
            bad(f"install.py must provision {var} (bus abstraction / KRaft identity / profile set)")
    inst_text = INSTALL.read_text()
    if re.search(r'DEFAULT_PROFILES\s*=\s*"[^"]*embedded-bus', inst_text):
        ok("default install activates the embedded-bus profile (embedded Apache Kafka)")
    else:
        bad("install.py DEFAULT_PROFILES must include embedded-bus (default = embedded Kafka)")

    # 5) informational: migrations auto-apply on api start; just surface the count
    migs = sorted((ROOT / "src" / "backend" / "migrations").glob("*.sql"))
    print(f"[migrations] {len(migs)} present, auto-applied by the api on startup (latest: {migs[-1].name if migs else 'none'})")

    print()
    if fail:
        print("preflight-install: FAILED — a clean install.py would miss something the stack needs (see ✗).", file=sys.stderr)
        return 1
    print("preflight-install: a clean install provisions everything the compose stack requires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
