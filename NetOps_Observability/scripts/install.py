#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
import errno
import fcntl
import functools
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import stat
import string
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

# Compose profiles a default install activates (written to .env as
# COMPOSE_PROFILES — the single source of truth; see compose_up). --core
# bundles install with --profiles "embedded-bus,prober" (no OSD image in the
# bundle); external-broker installs drop embedded-bus.
# "sso" (Keycloak) is DEFAULT-ON (owner decision 2026-08-04: enterprise SSO is
# a first-class capability, configured entirely from the admin GUI) — it can
# still be dropped from COMPOSE_PROFILES for footprint-constrained installs.
DEFAULT_PROFILES = "embedded-bus,prober,osd,self-monitoring,sso"

# ---- optional add-on packs --------------------------------------------------
# Optional capability does NOT ship inside the base image archive. Each pack is
# its own `correlix-addon-<name>-<version>.tar.zst` next to the installer, and
# the compose profile that needs it is the key: activate the profile on an
# offline install and the pack has to be loaded first, or `docker compose up`
# reaches for a registry that an air-gapped appliance does not have.
#
# Keycloak joined this table on 2026-09-06. It used to be a base image ("sso"
# default-on, owner decision 2026-08-04) and cost 235 MB in EVERY bundle for a
# capability that docs/design/SSO_SAML_* records as DEFERRED. Keep this table
# in sync with make-installer.sh's ADDONS and install-correlix.sh's addon_spec.
#
#   compose profile -> (pack name, what the customer asked for)
ADDON_PACKS = {
    "osd":             ("log-search-ui",   "the log-search UI (OpenSearch Dashboards)"),
    "self-monitoring": ("self-monitoring", "Grafana + container/host metrics"),
    "sso":             ("sso",             "single sign-on (Keycloak)"),
}

# ---- styling ----------------------------------------------------------------

def info(msg: str) -> None:    print(f"[info ] {msg}")
def ok(msg: str) -> None:      print(f"[ ok  ] {msg}")
def warn(msg: str) -> None:    print(f"[warn ] {msg}", file=sys.stderr)


def fail(msg: str, *, interrupted: bool = False) -> None:
    _stage_fail(msg, journal_status="interrupted" if interrupted else "failed")
    _timing_finish("fail")
    print(f"[fail ] {msg}", file=sys.stderr)
    sys.exit(1)


def step(msg: str, stage: str | None = None, *, key: str | None = None,
         inputs: dict | None = None) -> None:
    """Start a stage. `key` names its install-journal entry when one stage id
    runs more than once (addon-pack:<name>); `inputs` are its fingerprints."""
    if stage is not None:
        _stage_start(stage, msg, key=key, inputs=inputs)
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
    # bootstrap-appstate runs BEFORE the stack: on the postgres state backend
    # the api cannot start until its non-superuser role exists (tracker 245).
    "bundle", "addon-pack", "bootstrap-appstate", "up-a", "mint", "up-b",
    "kafka-acls",
    "status", "bootstrap-os", "bootstrap-kc", "bootstrap-grafana",
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
    # Install journal (FMEA §4.1): stage key -> {status, started_utc,
    # ended_utc, pid, inputs}. Carried over from the previous run's file, so a
    # re-run knows what already finished. Replaced (never mutated in place) on
    # every change, so a caller holding the old dict keeps a stable snapshot.
    "journal": {},
    "open_key": None,         # journal key of the currently-open stage
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


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal_open(key: str, inputs: dict) -> None:
    entry = {"status": "running", "started_utc": _utc_stamp(), "ended_utc": None,
             "pid": os.getpid(), "inputs": dict(inputs)}
    _TIMING["journal"] = {**_TIMING.get("journal", {}), key: entry}
    _TIMING["open_key"] = key


def _journal_close(status: str) -> None:
    key = _TIMING.get("open_key")
    if key is None:
        return
    entry = dict(_TIMING.get("journal", {}).get(key) or {})
    entry.update(status=status, ended_utc=_utc_stamp())
    _TIMING["journal"] = {**_TIMING.get("journal", {}), key: entry}
    _TIMING["open_key"] = None


def _stage_close_ok() -> None:
    if _PROGRESS["stage"] is not None:
        sid, title = _PROGRESS["stage"]
        _PROGRESS["stage"] = None
        elapsed = _stage_elapsed()
        _stage_record(sid, title, "ok", elapsed)
        _journal_close("done")
        _progress({"kind": "stage", "id": sid, "title": title, "status": "ok",
                   "elapsed_s": elapsed})


def _stage_start(sid: str, title: str, *, key: str | None = None,
                 inputs: dict | None = None) -> None:
    _stage_close_ok()
    _PROGRESS["stage"] = (sid, title)
    _TIMING["open_t"] = time.monotonic()
    _journal_open(key or sid, inputs or {})
    _progress({"kind": "stage", "id": sid, "title": title, "status": "start"})
    # Journal on disk at every stage start: a run killed mid-stage (SIGKILL,
    # reboot, a wizard restart) leaves the stage `running`, which the next run
    # reads as interrupted and runs again.
    _timing_finish("running", final=False)


def _stage_fail(message: str, journal_status: str = "failed") -> None:
    """fail() path: close the open stage as failed, then the terminal result."""
    if _PROGRESS["stage"] is not None:
        sid, title = _PROGRESS["stage"]
        _PROGRESS["stage"] = None
        elapsed = _stage_elapsed()
        _stage_record(sid, title, "fail", elapsed)
        _journal_close(journal_status)
        _progress({"kind": "stage", "id": sid, "title": title,
                   "status": "fail", "message": message, "elapsed_s": elapsed})
    _progress({"kind": "result", "status": "fail"})


def _route_source_address() -> str | None:
    """The source IPv4 the kernel would use for off-box traffic, or None.

    A UDP connect() to a documentation address (RFC 5737) sends no packet and
    resolves no name — the kernel just fills in the source address of the
    default route. On a host with no default route it raises, which is the
    None case."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect(("192.0.2.1", 9))
            addr = sock.getsockname()[0]
    except OSError:
        return None
    return addr if addr and not addr.startswith("127.") else None


def _first_host_address() -> str | None:
    """The host's first non-loopback IPv4 per `hostname -I`, or None.

    The fallback for a genuinely air-gapped segment with no default route,
    and the same source install-correlix.sh's print_success reads."""
    try:
        res = subprocess.run(["hostname", "-I"], capture_output=True, text=True,
                             timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    for addr in (res.stdout or "").split():
        if ":" not in addr and not addr.startswith("127."):
            return addr
    return None


def _reachable_host() -> str:
    """The address an operator most likely reached this host on, or "localhost".

    The installer runs ON the appliance, so it cannot know which name the
    operator typed. Printing a bare "localhost" is actively wrong for the
    common case (a remote install over SSH): the fresh-install acceptance
    (2026-09-06, DEFECT-7) watched the product hand an operator a URL that only
    resolves on the server itself, and under TLS the plaintext port they would
    otherwise fall back to is now loopback-only. Never raises: any failure
    degrades to "localhost", which is exactly what the caller printed before
    this existed."""
    return _route_source_address() or _first_host_address() or "localhost"


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
        # Additive (v1 readers ignore it): the resumable-stage journal, FMEA
        # §4.1. Stage keys, statuses, UTC stamps, pids and sha256 input
        # fingerprints only — never a secret value.
        "journal": {"schema": JOURNAL_SCHEMA, "pid": os.getpid(),
                    "stages": dict(_TIMING.get("journal", {}))},
    }


def _print_time_report(doc: dict) -> None:
    print()
    print("=== install timing ===")
    print(f"  {'stage':<18} {'status':<7} {'elapsed_s':>10}")
    for st in doc["stages"]:
        print(f"  {st['id']:<18} {st['status']:<7} {st['elapsed_s']:>10.1f}")
    print(f"  {'TOTAL':<18} {doc['status']:<7} {doc['total_s']:>10.1f}")


def _timing_finish(status: str, final: bool = True) -> None:
    """Terminal timing side effects: the summary marker, the JSON file and —
    with --time-report — the table. Never fatal: a run that installed the stack
    must not be reported as failed because a timing file could not be written,
    but the failure IS named (§16.1 — reported, never swallowed).

    final=False is the mid-run journal write at each stage start: the file
    only, no marker, no table."""
    if not _TIMING["record"]:
        return
    doc = _timing_doc(status)
    if final:
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
    if final and _TIMING["report"]:
        _print_time_report(doc)

# ---- install journal: resume without redoing finished work (FMEA §4.1, B1) ---
# data/install-timing.json doubles as the journal (one file, not a third): per
# stage key a status (running|done|failed|interrupted), UTC stamps, the pid and
# sha256 input fingerprints. Rules:
#   1. Advisory. A missing, unreadable or corrupt journal means "run every
#      stage" — never a refusal.
#   2. Only the image loads may be skipped (SKIPPABLE_STAGES), and only when the
#      journal says done from the SAME bundle fingerprint AND every image the
#      MANIFEST lists for that archive still inspects present on this host.
#   3. Every state-changing stage (up-a, mint, up-b, the bootstraps) always runs
#      and verifies its own post-condition; the journal only describes it.
#   4. A stage left `running` belongs to a run that died (the install lock
#      guarantees no other run is live); it is marked `interrupted` and re-run.

JOURNAL_SCHEMA = 1
JOURNAL_STATUSES = ("running", "done", "failed", "interrupted")
SKIPPABLE_STAGES = frozenset({"bundle", "addon-pack"})
_JOURNAL_MAX_BYTES = 1 << 20
_MANIFEST_MAX_BYTES = 1 << 20
# A MANIFEST image ref goes to `docker image inspect` as one argv element. No
# shell is involved, but a ref starting with "-" would be read as an option.
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")


def _pid_alive(pid: int) -> bool:
    """Linux-only (the installer is): a live pid has a /proc entry."""
    return pid > 0 and Path(f"/proc/{pid}").exists()


def journal_may_skip(stage_id: str) -> bool:
    """Only the pure image loads are ever skipped on the journal's word."""
    return stage_id in SKIPPABLE_STAGES


def load_install_journal(path: Path, *, pid_alive=_pid_alive) -> tuple[dict, list[str]]:
    """Read the previous run's journal. Returns (stages, notes-to-print).

    Never raises for a bad journal and never refuses: anything unusable yields
    an empty journal, which means every stage runs."""
    everything = "every stage runs"
    if not path.is_file():
        return {}, [f"no install journal yet ({path.name}) — {everything}"]
    if not os.access(path, os.R_OK):
        return {}, [f"install journal {path} is not readable by this user — {everything}"]
    if path.stat().st_size > _JOURNAL_MAX_BYTES:
        return {}, [f"install journal {path} is implausibly large — ignoring it; {everything}"]
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except ValueError as e:
        return {}, [(f"install journal {path} is corrupt ({type(e).__name__}) — "
                     f"ignoring it; {everything}")]
    journal = doc.get("journal") if isinstance(doc, dict) else None
    stages = journal.get("stages") if isinstance(journal, dict) else None
    if not isinstance(stages, dict) or journal.get("schema") != JOURNAL_SCHEMA:
        return {}, [f"{path.name} carries no usable install journal — {everything}"]
    out: dict[str, dict] = {}
    notes: list[str] = []
    for key, entry in stages.items():
        if not (isinstance(key, str) and isinstance(entry, dict)
                and entry.get("status") in JOURNAL_STATUSES):
            continue                     # malformed entry: forget it, the stage runs
        entry = dict(entry)
        if entry["status"] == "running":
            pid = entry.get("pid") if isinstance(entry.get("pid"), int) else 0
            state = ("is still alive but does not hold the install lock (a reused pid)"
                     if pid and pid != os.getpid() and pid_alive(pid)
                     else "is no longer running")
            entry["status"] = "interrupted"
            notes.append(f"the previous run was interrupted during stage {key!r} "
                         f"(pid {pid or '?'} {state}) — that stage runs again")
        out[key] = entry
    return out, notes


def _sha256sums_entry(sums: Path, name: str) -> str | None:
    """The digest SHA256SUMS records for `name`, or None."""
    if not (sums.is_file() and os.access(sums, os.R_OK)
            and sums.stat().st_size <= _MANIFEST_MAX_BYTES):
        return None
    for line in sums.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(?:\./)?(\S+)", line.strip())
        if m and m.group(2) == name:
            return m.group(1)
    return None


def archive_fingerprint(archive: Path) -> str | None:
    """sha256 identity of an image archive, or None when it cannot be pinned.

    Hashing a multi-GB archive on every re-run would cost the time the skip is
    meant to save, so this binds: the MANIFEST's bytes, the archive's name and
    size, and the digest SHA256SUMS records for it (install-correlix.sh has
    already verified the archive against that digest). Without a SHA256SUMS
    entry the mtime stands in. No MANIFEST → None → the load is never skipped."""
    manifest = archive.parent / "MANIFEST"
    if not (archive.is_file() and manifest.is_file() and os.access(manifest, os.R_OK)):
        return None
    if manifest.stat().st_size > _MANIFEST_MAX_BYTES:
        return None
    st = archive.stat()
    h = hashlib.sha256(b"correlix-archive-fingerprint/1\0")
    h.update(hashlib.sha256(manifest.read_bytes()).digest())
    h.update(f"{archive.name}\0{st.st_size}\0".encode())
    digest = _sha256sums_entry(archive.parent / "SHA256SUMS", archive.name)
    h.update((f"sha256:{digest}" if digest else f"mtime:{st.st_mtime_ns}").encode())
    return h.hexdigest()


def manifest_image_refs(text: str) -> dict[str, list[str]]:
    """Image refs per MANIFEST section, digests stripped (docker load restores
    tags, not registry digests). Keys: "base" (the `images:` list) and
    "addon:<name>" (each `addon <name> (profile <p>):` list — make-installer.sh
    writes both). A ref that is not a plausible image reference is dropped, so
    the section then counts as unverifiable and its load is not skipped."""
    out: dict[str, list[str]] = {}
    section: str | None = None
    bad: set[str] = set()
    for line in text.splitlines():
        if line.rstrip() == "images:":
            section = "base"
            out.setdefault(section, [])
            continue
        m = re.fullmatch(r"addon ([A-Za-z0-9._-]+) \(profile [^)]*\):\s*", line)
        if m:
            section = f"addon:{m.group(1)}"
            out.setdefault(section, [])
            continue
        item = re.fullmatch(r"  - (\S+)\s*", line)
        if item and section:
            ref = re.sub(r"@sha256:[0-9a-f]{64}$", "", item.group(1))
            if _IMAGE_REF.match(ref):
                out[section].append(ref)
            else:
                bad.add(section)
            continue
        if line and not line.startswith(" "):
            section = None
    for s in bad:
        out[s] = []
    return out


def image_load_decision(journal: dict, key: str, archive: Path, section: str,
                        image_present) -> tuple[bool, str, str | None]:
    """(skip, why, fingerprint) for one image-archive load. Pure apart from the
    injected `image_present(ref) -> bool` and reading the bundle's MANIFEST."""
    stage_id = key.split(":", 1)[0]
    fp = archive_fingerprint(archive)
    entry = journal.get(key)
    if not journal_may_skip(stage_id):
        return False, f"stage {stage_id!r} is never skipped", fp
    if not isinstance(entry, dict) or entry.get("status") != "done":
        state = entry.get("status") if isinstance(entry, dict) else "never run"
        return False, f"the journal has no completed load of it ({state})", fp
    if fp is None:
        return False, "the bundle has no readable MANIFEST to verify against", fp
    if (entry.get("inputs") or {}).get("bundle") != fp:
        return False, "the archive or its MANIFEST differs from the one recorded as loaded", fp
    refs = manifest_image_refs(
        (archive.parent / "MANIFEST").read_text(encoding="utf-8", errors="replace")
    ).get(section, [])
    if not refs:
        return False, f"the MANIFEST lists no verifiable images for {section}", fp
    missing = [r for r in refs if not image_present(r)]
    if missing:
        return False, (f"{len(missing)} of its {len(refs)} images are no longer on "
                       f"this host (first: {missing[0]})"), fp
    return True, (f"already loaded from this same archive (journal fingerprint "
                  f"{fp[:12]}) and all {len(refs)} images it lists are present"), fp


def stage_inputs(env_path: Path) -> dict:
    """Fingerprints of what a compose stage starts from: .env key NAMES (never
    values), the COMPOSE_FILE chain and the profile set."""
    env = _parse_env_text(env_path.read_text()) if env_path.is_file() else {}

    def h(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()
    return {"env_keys": h("\n".join(sorted(env))),
            "compose_file": h(env.get("COMPOSE_FILE", "")),
            "profiles": h(env.get("COMPOSE_PROFILES", ""))}


# ---- secret generation ------------------------------------------------------

# Use only URL-safe / shell-safe characters so values can sit unquoted in
# .env without parser surprises. `secrets.token_urlsafe` is the right tool
# for the high-entropy values; the admin password uses a smaller alphabet
# to keep it pasteable.

_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#%^&*-_=+"

def generate_password(length: int = 24) -> str:
    return _no_leading_dash(_PASSWORD_ALPHABET, length)

# Credentials that ride URL userinfo (https://user:pw@host — the SEC-010
# vmauth family today) must NOT contain @ # % ^ & + =: Go's url.Parse rejects
# a stray %, # truncates as a fragment, and @ shifts the authority split.
# 2026-08-07: found as a latent fresh-install landmine — generate_password's
# alphabet gives each minted credential a ~2% chance of breaking its client
# at startup. URL-embedded credentials use this alphabet instead.
_URLSAFE_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "-_"

# A generated secret must never START with "-". Several consumers hand the
# value to a command-line parser as the argument AFTER an option — the
# OpenSearch Dashboards image turns OPENSEARCH_PASSWORD into
# `--opensearch.password <value>`, and a value beginning with "-" is read as
# another option ("must have a value"), so the service crash-loops. With "-"
# in a 64-character alphabet that was a ~1-in-64 chance per fresh install
# (CI two-phase boot run 34911914843, 2026-09-15; reproduced locally). The
# first character is drawn from letters and digits only — about 0.1 bits of
# entropy for a 24-character secret.
_LEADING_SAFE_ALPHABET = string.ascii_letters + string.digits


def _no_leading_dash(alphabet: str, length: int) -> str:
    if length <= 0:
        return ""
    return secrets.choice(_LEADING_SAFE_ALPHABET) + "".join(
        secrets.choice(alphabet) for _ in range(length - 1))


def generate_urlsafe_password(length: int = 24) -> str:
    return _no_leading_dash(_URLSAFE_PASSWORD_ALPHABET, length)

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
    write_env_text(env_path, rp.splice_env(env_text, rp.env_block(plan)),
                   what="write the resource plan")
    for name, text in (("resource-plan.json",
                        json.dumps(plan, indent=2, sort_keys=True) + "\n"),
                       ("resource-plan.txt", rp.plan_txt(plan))):
        (env_path.parent / name).write_text(text)
    for w in plan["warnings"]:
        warn(w)
    ok(f"resource plan written (profile {plan['profile']}) — "
       f"{env_path.parent / 'resource-plan.txt'}")


# ---- .env generation --------------------------------------------------------

def _raw_write(fd: int, data: memoryview) -> int:
    """os.write under a name of its own, so a test can inject a failure part
    way through a write (ENOSPC) and prove the destination survives."""
    return os.write(fd, data)


def _preserve_owner(fd: int, path: Path) -> None:
    """Keep the destination's owner across the replace. A root re-run must not
    hand an operator's .env to root; a non-root run cannot take root's file
    (fchown raises, and the write fails loudly instead of changing owner)."""
    if not path.exists():
        return
    st = path.stat()
    if (st.st_uid, st.st_gid) != (os.geteuid(), os.getegid()):
        os.fchown(fd, st.st_uid, st.st_gid)


def _write_private(path: Path, text: str) -> None:
    """Write `text` to `path` owner-only FROM THE FIRST BYTE (M26), atomically.

    Path.write_text() + chmod(0o600) leaves a umask-wide window (0644 on a
    stock host) between creation and chmod during which any local user can
    open the file — and every caller here writes stack secrets (.env, its
    .rotate.bak / .plan.bak / .snapshot siblings). O_EXCL on a fresh temp name
    in the same directory, mode 0600 at open, every byte written, fsync, the
    destination's owner kept, then an atomic rename over the destination. A
    kill or ENOSPC at any point leaves the destination byte-identical and at
    worst a 0600 temp file (removed on the error path) — never a half-written
    or world-readable secret (FMEA row 13 / E1)."""
    data = memoryview(text.encode("utf-8"))
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        try:
            while data:
                n = _raw_write(fd, data)
                if n <= 0:
                    raise OSError(errno.EIO, f"short write to {tmp.name}")
                data = data[n:]
            os.fsync(fd)
            _preserve_owner(fd, path)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass  # the normal case: replace() already moved it into place


# ---- .env integrity: one writer, a snapshot, a completeness gate (row 13/E1) --

ENV_SNAPSHOT_SUFFIX = ".snapshot"
ENV_DAMAGED_SUFFIX = ".damaged"
ENV_REQUIRED_COMPOSE_FILES = ("docker-compose.yml", "compose.tls.yml")
# `${VAR:?msg}` / `${VAR?msg}` — compose refuses to start without VAR. `$${`
# is compose's escape for a literal `${` and is not a requirement.
_COMPOSE_REQUIRED_VAR = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*):?\?")


def env_snapshot_path(env_path: Path) -> Path:
    return env_path.with_name(env_path.name + ENV_SNAPSHOT_SUFFIX)


def compose_required_env_keys(compose_dir: Path) -> set[str]:
    """Every variable compose itself refuses to start without."""
    keys: set[str] = set()
    for name in ENV_REQUIRED_COMPOSE_FILES:
        f = compose_dir / name
        if f.is_file():
            keys.update(_COMPOSE_REQUIRED_VAR.findall(f.read_text(encoding="utf-8")))
    return keys


def required_env_keys(compose_dir: Path) -> set[str]:
    """Keys a complete .env carries: compose's `${VAR:?}` set plus every secret
    install.py mints (names only; the values generated here are discarded)."""
    return compose_required_env_keys(compose_dir) | set(generate_secrets())


def migrated_env_keys() -> set[str]:
    """Keys write_env's re-run migration can seed into an older .env —
    derived from the migration code itself, so the two cannot drift."""
    return {line.split("=", 1)[0] for line in _env_migration_lines({})}


def env_missing_keys(env: dict, keys) -> list[str]:
    """Names of `keys` that are absent or empty in `env`, sorted."""
    return sorted(k for k in keys if not (env.get(k) or "").strip())


def _snapshot_env(env_path: Path, current: str) -> None:
    """Keep the last COMPLETE .env beside it before a change. A damaged file
    never replaces a good snapshot, and an unchanged one is not rewritten."""
    if env_missing_keys(_parse_env_text(current), required_env_keys(env_path.parent)):
        return
    snap = env_snapshot_path(env_path)
    if snap.is_file() and snap.read_text(encoding="utf-8", errors="replace") == current:
        return
    _write_private(snap, current)


def write_env_text(env_path: Path, text: str, *, what: str) -> None:
    """The ONE way install.py changes .env (FMEA row 13 / E1): snapshot the
    current file when it is complete, then replace it atomically. Any failure
    (ENOSPC, EACCES, EIO) is named and fatal, and the .env on disk is the
    previous one, byte for byte."""
    try:
        if env_path.is_file():
            _snapshot_env(env_path, env_path.read_text(encoding="utf-8", errors="replace"))
        _write_private(env_path, text)
    except OSError as e:
        fail(f"could not {what} in {env_path}: {e.strerror or e}. The .env on disk "
             "is unchanged (every write is atomic). Free disk space or fix the "
             "permission, then re-run the installer — re-running is safe.")


def validate_env_complete(env_path: Path, *, before_migration: bool = False) -> None:
    """Refuse to continue from a .env that lost keys (FMEA row 13 / E1).

    Default (after generation or migration): every key compose requires and
    every key generate_secrets() mints must be present and non-empty.

    before_migration=True (a re-run, before write_env's migration mints
    anything): the keys no migration can recreate must be present, AND no
    required key the last complete snapshot holds may be missing. A truncated
    file loses its tail, and letting the migration re-mint REDIS_PASSWORD, the
    OS_* credentials or KAFKA_CLUSTER_ID into it would silently split the
    stores from their own credentials.

    Incomplete → restore the snapshot when the snapshot is complete (the
    damaged file is kept as .env.damaged), otherwise refuse. Messages carry KEY
    NAMES only, never a value."""
    full = required_env_keys(env_path.parent)
    need = full - migrated_env_keys() if before_migration else full
    env = _parse_env_text(env_path.read_text(encoding="utf-8", errors="replace"))
    snap = env_snapshot_path(env_path)
    snap_text = snap.read_text(encoding="utf-8", errors="replace") if snap.is_file() else ""
    snap_env = _parse_env_text(snap_text)
    missing = set(env_missing_keys(env, need))
    if before_migration:
        missing.update(k for k in full
                       if (snap_env.get(k) or "").strip() and not (env.get(k) or "").strip())
    if not missing:
        return
    names = ", ".join(sorted(missing))
    if snap_env and not env_missing_keys(snap_env, need):
        damaged = env_path.with_name(env_path.name + ENV_DAMAGED_SUFFIX)
        try:
            _write_private(damaged, env_path.read_text(encoding="utf-8", errors="replace"))
            _write_private(env_path, snap_text)
        except OSError as e:
            fail(f".env is incomplete (missing or empty: {names}) and restoring it "
                 f"from {snap.name} failed: {e.strerror or e}. Nothing else was changed.")
        warn(f".env was incomplete — missing or empty: {names}. Restored it from "
             f"{snap.name}, the last complete copy install.py kept; the damaged file "
             f"is kept as {damaged.name}. Re-apply any edit made after that copy.")
        return
    root = env_path.parent.parent.parent
    profiles = env.get("COMPOSE_PROFILES") or snap_env.get("COMPOSE_PROFILES") or ""
    if _rotation_module().install_started(root, profiles):
        remedy = ("Restore .env from a backup. Do NOT regenerate it: the stores "
                  "already hold the current secrets, and new ones would lock the "
                  "stack out of its own data.")
    else:
        remedy = ("Nothing has started yet, so `python3 scripts/install.py "
                  "--reset-env` can safely regenerate it.")
    why = (f"Its snapshot {snap.name} is incomplete too." if snap_env
           else "There is no snapshot to restore it from.")
    fail(f".env is incomplete — these keys are missing or empty: {names}. {why} {remedy}")


def _kafka_volume_initialized(env_path: Path) -> bool:
    """True when this .env sits in a real install tree whose embedded broker
    has already formatted data/kafka with some cluster id."""
    compose_dir = env_path.parent
    if compose_dir.name != "docker" or compose_dir.parent.name != "deployment":
        return False
    return _rotation_module().store_initialized(compose_dir.parent.parent, "kafka")


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


def _env_migration_lines(env: dict, profiles: str = DEFAULT_PROFILES,
                         retention_profile: str = "production") -> list[str]:
    """`KEY=value` lines a re-run appends to an older .env that lacks them.

    Also the single source of migrated_env_keys(): calling it with an empty
    env names every key a migration can seed."""
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
    # Migration (tracker 245): a .env written before the app-state backend
    # became explicit has no STORE_BACKEND line, and the compose fallback
    # (`${STORE_BACKEND:-file}`) is the only thing keeping such an install on
    # the backend its data actually lives on. Stamp the historical value
    # EXPLICITLY so the choice survives any future default change — an
    # upgrade must never silently repoint a registry at an empty database.
    # A fresh install gets `postgres` from the template above; this path
    # only ever writes what the install is already running on.
    if "STORE_BACKEND" not in env:
        additions.append("STORE_BACKEND=file")
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
    # Migration (row 13 / E1): the read-only Grafana ClickHouse credential.
    # bootstrap_grafana used to append it at the very END of a run, so an
    # older .env was "incomplete" for the whole install; seeding it here
    # is the same value-generation, just early enough for the completeness
    # gate. bootstrap_grafana reconciles the ClickHouse user to it.
    if "GRAFANA_CH_PASSWORD" not in env:
        additions.append(f"GRAFANA_CH_PASSWORD={generate_password(24)}")
    return additions


def write_env(env_path: Path, port: int, *, force: bool,
              profiles: str = DEFAULT_PROFILES,
              broker_urls: str | None = None,
              retention_profile: str = "production",
              preserve: dict[str, str] | None = None) -> dict[str, str]:
    if env_path.exists() and not force:
        info(f".env already exists at {env_path} — keeping existing secrets")
        env = _parse_env(env_path)
        # A KAFKA_CLUSTER_ID the migration would mint for a broker that has
        # already formatted data/kafka is not an upgrade, it is a broker that
        # refuses its own volume. Only a damaged .env gets here.
        if "KAFKA_CLUSTER_ID" not in env and _kafka_volume_initialized(env_path):
            fail("KAFKA_CLUSTER_ID is missing from .env, but the embedded broker "
                 "has already formatted data/kafka with an id: minting a new one "
                 "would make the broker refuse its own data. Restore the key from "
                 f"{env_snapshot_path(env_path).name} or a backup (see "
                 "docs/runbooks/secret-rotation.md for a deliberate rotation).")
        additions = _env_migration_lines(env, profiles, retention_profile)
        if additions:
            write_env_text(
                env_path,
                env_path.read_text()
                + "\n# ---- Event bus (Apache Kafka) — appended by install.py migration ----\n"
                + "\n".join(additions) + "\n",
                what="migrate .env")
            ok(f"migrated .env: added {', '.join(a.split('=')[0] for a in additions)}")
            env = _parse_env(env_path)
        # Heal (2026-09-15): an install minted before the leading-character fix
        # can hold an OS_DASHBOARDS_PASSWORD that starts with "-", which the
        # Dashboards image passes as `--opensearch.password <value>` and its
        # parser reads as an option — the service crash-loops on every start.
        # The password is bootstrap-applied (apply-security.sh re-hashes it
        # from .env on each run; secret_rotation classes it FREE), so
        # re-minting it here is safe and converges on the next compose up.
        if (env.get("OS_DASHBOARDS_PASSWORD") or "").startswith("-"):
            text = env_path.read_text()
            healed, not_found = _rotation_module().substitute_env(
                text, {"OS_DASHBOARDS_PASSWORD": generate_urlsafe_password(24)})
            if "OS_DASHBOARDS_PASSWORD" in not_found:
                fail("OS_DASHBOARDS_PASSWORD starts with '-' (OpenSearch "
                     "Dashboards cannot start with it) and could not be "
                     "re-minted in .env — set a new value by hand")
            write_env_text(env_path, healed, what="re-mint OS_DASHBOARDS_PASSWORD")
            ok("re-minted OS_DASHBOARDS_PASSWORD: the old value began with "
               "'-', which OpenSearch Dashboards reads as a command-line option")
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
    # The Postgres app-state role's password. Deliberately NOT part of
    # generate_secrets(): it lives inside DATABASE_URL (the api reads a DSN, not
    # a password), and install.py reconciles the live role against whatever that
    # DSN says on every run — so rotating it is "edit DATABASE_URL, re-run
    # install.py", not a --reset-env class. URL-safe: it rides URL userinfo.
    app_db_password = generate_urlsafe_password(28)
    # Two values the GUI installer collects and this template writes verbatim.
    # They arrive through the environment rather than as flags because they are
    # not decisions install.py makes — they are strings it records once, on a
    # FRESH install only (this whole function only ever writes a new .env).
    # Both are re-validated here: install-correlix.sh already checked them, and
    # a value that reaches .env unchecked is a value nobody checked.
    admin_username = os.environ.get("CORRELIX_ADMIN_USERNAME", "admin").strip() or "admin"
    if not re.fullmatch(r"[a-z][a-z0-9._-]{2,31}", admin_username):
        fail(f"CORRELIX_ADMIN_USERNAME={admin_username!r} is not a valid administrator name "
             f"(3-32 characters, lowercase letter first, then letters, digits, dot, dash "
             f"or underscore).")
    # PostgreSQL is the default state backend for every fresh install
    # (tracker 245). "file" is the explicit compatibility choice; there is no
    # implicit fallback and "memory" is never a shipped install.
    store_backend = os.environ.get("CORRELIX_STORE_BACKEND", "postgres").strip() or "postgres"
    if store_backend not in ("postgres", "file"):
        fail(f"CORRELIX_STORE_BACKEND={store_backend!r} must be 'postgres' (default) or 'file'.")
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
ADMIN_USERNAME={admin_username}
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

# Registry / app-state persistence backend (tracker 245).
#
#   postgres  DEFAULT for a new installation. Normalized per-row tables with
#             PostgreSQL Row-Level Security; the authoritative durable store for
#             users, tenants, API keys, saved objects, the service catalog and
#             the APPLICATION REGISTRY (which exists ONLY here — see below).
#   file      Explicit compatibility / PostgreSQL-less mode: JSON on the data
#             volume. Durable, but registries with no file implementation are
#             UNAVAILABLE on it and say so rather than pretending.
#   memory    Development and test ONLY. Ephemeral — nothing survives a restart.
#             Never a default and never entered by accident.
#
# UPGRADING an install that already runs `file`? It STAYS on file: install.py
# never rewrites this line on an existing .env, because switching backends does
# not move your data (docs/DEPLOY_POSTGRES_APPSTATE.md documents the one-time
# IMPORT_FILE_STATE_DIR importer and exactly which collections it covers).
#
# DATABASE_URL must authenticate as a NON-superuser role: superusers bypass
# Row-Level Security, so the api refuses to start as one. install.py provisions
# `netops_app` with the password below and keeps them in step on every re-run.
STORE_BACKEND={store_backend}
DATABASE_URL=postgres://netops_app:{app_db_password}@postgres:5432/netops?sslmode=disable
# On a --tls install postgres REQUIRES TLS (pg_hba `hostssl`, F-4): install.py
# rewrites the DSN to ?sslmode=verify-full&sslrootcert=/data/tls/ca.pem in TLS
# phase B. Set it by hand only if you point at an external database.
#
# One-time file -> Postgres cutover: point this at the old JSON directory and
# the api imports the durable collections ONCE (idempotent, marker-recorded, it
# never clobbers live rows). Leave empty on a fresh install.
IMPORT_FILE_STATE_DIR=

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
    write_env_text(env_path, body, what="write .env")
    ok(f"wrote {env_path} (mode 0600)")
    return secrets_map


def _parse_env(path: Path) -> dict[str, str]:
    return _parse_env_text(path.read_text())


def _parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
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
    write_env_text(env_path, new_text, what="write the rotated secrets")
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
        write_env_text(env_path, reverted, what=f"roll back {name}")
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
# ...but ONLY on an ONLINE install. `docker load` restores an image by TAG;
# a registry digest is pull-time metadata the archive does not carry (the same
# lesson write_offline_override() encodes for compose, and cmd_uninstall for
# `docker rmi`). So on an air-gapped bundle install the digest ref above is
# "not found locally" and docker reaches for the registry — which is both a
# broken air-gap promise and a hard install failure on a host with no egress
# (fresh-install acceptance, 2026-09-06: every non-root TLS install died here).
# Resolve against what is actually on the host, preferring the digest.
CHOWN_HELPER_IMAGE_TAG = "postgres:16-alpine"


def _image_present(ref: str) -> bool:
    """True when `ref` already resolves on this host (never pulls)."""
    try:
        res = subprocess.run(["docker", "image", "inspect", ref],
                             capture_output=True, text=True, timeout=30,
                             check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


def _chown_helper_ref() -> str:
    """Pick the helper ref: the digest-pinned one when it is local (online
    install / already pulled), the tag when only the docker-load'ed tag is
    (offline bundle), else the digest so an online host pulls a pinned image
    rather than a floating tag."""
    for ref in (CHOWN_HELPER_IMAGE, CHOWN_HELPER_IMAGE_TAG):
        if _image_present(ref):
            return ref
    return CHOWN_HELPER_IMAGE


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
           _chown_helper_ref(),
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


def tls_service_mount_dirs(compose_dir: Path) -> list[str]:
    """Every `data/tls/services/<name>` a compose file bind-mounts.

    Docker creates a missing bind-mount SOURCE as **root** the moment the
    service starts. The api is user-mapped with cap_drop:ALL, so once Docker
    has created data/tls/services (and a sibling inside it) as root, the api's
    internal CA can no longer mint: "mkdir /data/tls/services/api: permission
    denied", and TLS phase A deadlocks. That is not hypothetical — it is how a
    fresh install failed once vmauth (which mounts one of these) joined the
    default profile set (acceptance, 2026-09-06).

    Derived from the compose files rather than listed here, so a new
    TLS-fronted service needs no edit in two places. Returns paths relative to
    data/, e.g. "tls/services/vmauth".
    """
    out: set[str] = set()
    for name in ("docker-compose.yml", "compose.tls.yml"):
        f = compose_dir / name
        if not f.exists():
            continue
        for m in re.finditer(r"\.\./\.\./data/(tls/services/[A-Za-z0-9_.-]+)",
                             f.read_text()):
            out.add(m.group(1).rstrip("/"))
    return sorted(out)


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
        # ...and the SVID root itself. data/tls is chowned recursively, but on a
        # FRESH install it is empty at that moment, so there is nothing under it
        # to repair; Docker then creates data/tls/services (and a per-service dir
        # inside it) as ROOT when the first TLS-fronted service starts, and the
        # api can never mint. Pre-creating the root — and each mounted child, see
        # tls_service_mount_dirs below — is what keeps it the api's tree.
        "tls/services": (api_uid, api_gid),
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
    for rel in tls_service_mount_dirs(root / "deployment" / "docker"):
        owners.setdefault(rel, (api_uid, api_gid))

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
        write_env_text(
            env_path,
            env_text
            + "\n# Offline install: tag-pinned image override (see file header).\n"
            + "COMPOSE_FILE=docker-compose.yml:compose.offline-images.yml\n",
            what="activate the offline image override")
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
        write_env_text(env_path, "\n".join(lines) + "\n", what=f"set the {label}")
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
        write_env_text(env_path, "\n".join(lines) + "\n",
                       what="normalize DATABASE_URL")
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
                write_env_text(env_path, "\n".join(lines) + "\n",
                               what="add the TLS compose profiles")
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
            write_env_text(env_path, "\n".join(lines) + "\n",
                           what="append compose.tls.yml to COMPOSE_FILE")
            ok("compose.tls.yml appended to the COMPOSE_FILE chain")
            return
    write_env_text(
        env_path,
        env_path.read_text()
        + "\n# TLS/mTLS variant (tracker #151): activated by install.py --tls=yes.\n"
        + "COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n",
        what="activate compose.tls.yml")
    ok("compose.tls.yml activated via COMPOSE_FILE")


# ── host profile → wait budgets (FMEA 2026-09-15 §4.3, row 3) ───────────────
#
# Every fixed wait was too short on a slow disk: on .123 the install quit about
# 25 s before postgres would have answered. install-correlix.sh's preflight
# measures the host (scripts/host_profile.py) and writes data/.host-profile.json
# with a speed class and a budget_factor; every installer wait is base × factor.
# The profile is advisory: without a usable one the waits are the bases below,
# which are exactly what the installer used before it existed. An explicit
# setting always wins over the profile.

HOST_PROFILE_PATH = Path("data") / ".host-profile.json"
HOST_CLASSES = ("fast", "normal", "slow", "very-slow")
BUDGET_FACTOR_MIN = 1.0
BUDGET_FACTOR_MAX = 4.0
_JSON_READ_LIMIT = 64 * 1024

MINT_WAIT_BASE_S = 300
ACL_APPLY_BASE_S = 900
BUS_CONSUMERS_BASE_S = 420
# Compose reads these two windows from .env (docker-compose.yml); its defaults
# equal the bases here (pinned by tests/test_install_budgets.py).
STORE_STOP_GRACE_ENV = "STORE_STOP_GRACE"
STORE_STOP_GRACE_BASE_S = 120
PG_START_PERIOD_ENV = "PG_START_PERIOD"
PG_START_PERIOD_BASE_S = 300


# NamedTuple, not @dataclass: several tests load install.py by file path without
# registering it in sys.modules, and dataclasses resolves string annotations
# through sys.modules[cls.__module__] (AttributeError at import there).
class HostProfile(NamedTuple):
    """What the preflight measured, reduced to what the waits need."""
    host_class: str      # one of HOST_CLASSES, or "unknown"
    factor: float        # within [BUDGET_FACTOR_MIN, BUDGET_FACTOR_MAX]


class InstallBudgets(NamedTuple):
    """Every installer wait for this run, in seconds, after the profile and
    any explicit setting. `yours` names the budgets a setting decided."""
    host_class: str
    factor: float
    converge_s: int
    pg_ready_s: float
    mint_s: int
    acl_apply_s: int
    bus_consumers_s: int
    store_stop_grace_s: int
    pg_start_period_s: int
    yours: frozenset[str] = frozenset()


def _short_repr(value: object) -> str:
    text = repr(value)
    return text if len(text) <= 40 else text[:37] + "..."


def _read_json_object(path: Path) -> tuple[dict | None, str]:
    """(object, "") or (None, reason) — reason is "missing" when there is no
    file. Bounded read. Every caller treats the file as advisory and says why
    it was not used, so an unreadable file is a reason, not a crash."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_JSON_READ_LIMIT + 1)
    except FileNotFoundError:
        return None, "missing"
    except OSError as e:
        return None, f"unreadable ({e.strerror or e})"
    if len(raw) > _JSON_READ_LIMIT:
        return None, f"larger than {_JSON_READ_LIMIT // 1024} KiB"
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError as e:     # includes UnicodeDecodeError
        return None, f"not valid JSON ({e})"
    if not isinstance(doc, dict):
        return None, "not a JSON object"
    return doc, ""


def load_host_profile(path: Path) -> HostProfile:
    """The host profile, or factor 1 with a line saying why the waits are not
    scaled. Never fatal: every wait it scales worked before it existed."""
    doc, why = _read_json_object(path)
    if doc is None:
        if why == "missing":
            info(f"no host speed profile at {path} — waits are not scaled")
        else:
            warn(f"the host speed profile {path} is {why} — waits are not scaled")
        return HostProfile("unknown", 1.0)
    cls = doc.get("class")
    factor = doc.get("budget_factor")
    if not isinstance(cls, str) or cls not in HOST_CLASSES:
        warn(f"the host speed profile {path} has no known class ({_short_repr(cls)}) "
             "— waits are not scaled")
        return HostProfile("unknown", 1.0)
    if (isinstance(factor, bool) or not isinstance(factor, (int, float))
            or not math.isfinite(factor)):
        warn(f"the host speed profile {path} has a budget_factor that is not a number "
             f"({_short_repr(factor)}) — waits are not scaled")
        return HostProfile("unknown", 1.0)
    clamped = min(BUDGET_FACTOR_MAX, max(BUDGET_FACTOR_MIN, float(factor)))
    if clamped != factor:
        info(f"the host speed profile's budget_factor {factor:g} is outside "
             f"{BUDGET_FACTOR_MIN:g}–{BUDGET_FACTOR_MAX:g}; using {clamped:g}")
    return HostProfile(cls, clamped)


_COMPOSE_DURATION = re.compile(r"(?:(\d{1,6})h)?(?:(\d{1,6})m)?(?:(\d{1,7})s)?")


def parse_compose_seconds(value: str) -> int | None:
    """Seconds in a compose duration like `120s`, `5m` or `1m30s`; None for
    anything compose would not read the same way (a bare number has no unit,
    `ms` is not whole seconds)."""
    m = _COMPOSE_DURATION.fullmatch(value)
    if not value or m is None:
        return None
    h, mins, s = (int(g) if g else 0 for g in m.groups())
    return h * 3600 + mins * 60 + s


def _window_setting(name: str, scaled: int, environ: Mapping[str, str],
                    dotenv: Mapping[str, str]) -> tuple[int, bool]:
    """A compose window (stop grace, start period): (seconds, explicit?).

    Set in this shell → it wins (compose reads the shell before .env), and one
    compose cannot parse stops the install now rather than at `compose up`. Set
    in .env → kept when longer than the scaled value, never shortened; one
    compose cannot parse is replaced by write_budget_env."""
    raw = (environ.get(name) or "").strip()
    if raw:
        secs = parse_compose_seconds(raw)
        if secs is None or secs <= 0:
            fail(f"{name}={raw!r} (set in this shell) is not a duration docker compose "
                 "accepts, such as 120s or 5m. Fix or unset it, then re-run the installer.")
            raise SystemExit(2)
        return secs, True
    raw = (dotenv.get(name) or "").strip()
    if raw:
        secs = parse_compose_seconds(raw)
        if secs is None or secs <= 0:
            warn(f"{name}={raw!r} in .env is not a duration docker compose accepts "
                 f"— replacing it with {scaled}s")
            return scaled, False
        return max(scaled, secs), False
    return scaled, False


def resolve_budgets(profile: HostProfile, environ: Mapping[str, str] | None = None,
                    dotenv: Mapping[str, str] | None = None) -> InstallBudgets:
    """Scale every installer wait by the host profile; explicit settings win
    (CORRELIX_CONVERGE_BUDGET_S, CORRELIX_PG_READY_TIMEOUT, STORE_STOP_GRACE,
    PG_START_PERIOD). `dotenv` is the current .env, for the two compose windows."""
    environ = os.environ if environ is None else environ
    dotenv = {} if dotenv is None else dotenv
    f = profile.factor

    def scaled(base: float) -> int:
        return math.ceil(base * f)

    yours: set[str] = set()
    converge, mine = _converge_setting(min(3600, scaled(_CONVERGE_BUDGET_DEFAULT_S)), environ)
    if mine:
        yours.add("converge")
    pg_ready, mine = _pg_ready_setting(float(scaled(PG_READY_BUDGET_S)), environ)
    if mine:
        yours.add("pg_ready")
    grace, mine = _window_setting(STORE_STOP_GRACE_ENV, scaled(STORE_STOP_GRACE_BASE_S),
                                  environ, dotenv)
    if mine:
        yours.add("store_stop_grace")
    start, mine = _window_setting(PG_START_PERIOD_ENV, scaled(PG_START_PERIOD_BASE_S),
                                  environ, dotenv)
    if mine:
        yours.add("pg_start_period")
    return InstallBudgets(
        host_class=profile.host_class, factor=f, converge_s=converge, pg_ready_s=pg_ready,
        mint_s=scaled(MINT_WAIT_BASE_S), acl_apply_s=scaled(ACL_APPLY_BASE_S),
        bus_consumers_s=scaled(BUS_CONSUMERS_BASE_S), store_stop_grace_s=grace,
        pg_start_period_s=start, yours=frozenset(yours))


_SPEED_WORDS = {
    "fast": "this host's disk is fast",
    "normal": "this host's disk speed is normal",
    "slow": "this host's disk is slow",
    "very-slow": "this host's disk is very slow",
}
_SPEED_UNKNOWN = "this host's disk speed was not measured"


def _duration_words(seconds: float) -> str:
    return f"{round(seconds / 60, 1):g} min" if seconds >= 120 else f"{seconds:.0f}s"


def describe_budgets(b: InstallBudgets) -> str:
    """One plain-words line: how slow the host is and how long each wait is."""
    speed = _SPEED_WORDS.get(b.host_class, _SPEED_UNKNOWN)
    head = (f"{speed} — waits are {b.factor:g}× longer" if b.factor > 1
            else f"{speed} — standard waits")
    parts = [f"{_duration_words(secs)} for {what}"
             + (" (your setting)" if key in b.yours else "")
             for key, what, secs in (
                 ("converge", "services to start", b.converge_s),
                 ("pg_ready", "the database to answer", b.pg_ready_s),
                 ("mint", "service identities to be issued", b.mint_s),
                 ("acl", "bus permissions to apply", b.acl_apply_s),
                 ("store_stop_grace", "each data store to shut down cleanly",
                  b.store_stop_grace_s))]
    return f"{head}: up to {', '.join(parts)}"


def write_budget_env(env_path: Path, budgets: InstallBudgets,
                     environ: Mapping[str, str] | None = None) -> None:
    """Put the stores' shutdown window and postgres' start period into .env
    (through the atomic writer) when this host needs longer ones, or when the
    value there is one compose cannot parse. A window set in this shell is left
    to the shell; a longer one already in .env is kept (resolve_budgets)."""
    environ = os.environ if environ is None else environ
    current = _parse_env(env_path)
    wanted: dict[str, str] = {}
    for name, secs in ((STORE_STOP_GRACE_ENV, budgets.store_stop_grace_s),
                       (PG_START_PERIOD_ENV, budgets.pg_start_period_s)):
        if (environ.get(name) or "").strip():
            continue
        raw = (current.get(name) or "").strip()
        have = parse_compose_seconds(raw) if raw else None
        if (raw and not have) or (budgets.factor > 1 and have != secs):
            wanted[name] = f"{secs}s"
    if not wanted:
        return
    splice_env_values(
        env_path, wanted,
        header=["# Host speed (data/.host-profile.json, FMEA §4.3): longer store",
                "# shutdown and database start windows for a slow disk. install.py",
                "# manages these and never shortens a longer value set here."],
        label="slow-host start and stop windows")


def wait_for_minted_certs(root: Path, timeout_s: int = MINT_WAIT_BASE_S) -> None:
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
               root: Path | None = None, *, ops=None,
               sleep=time.sleep, clock=time.monotonic,
               budget_s: int | None = None,
               services: list[str] | None = None,
               tiered: bool = False) -> None:
    # `services`: start only these, and wait until they have settled (healthy,
    # or running with no healthcheck) — an empty list starts nothing, never
    # everything. `tiered`: start the stack group by group (FMEA §4.5, see
    # plan_tiers), then everything together. Neither: one `up -d` of it all.
    if services is not None and not services:
        info("no services to start in this group")
        return
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

    # Convergence (2026-09-15, .123 fresh install): the old loop was three blind
    # passes 30 s apart. Postgres, SIGKILLed mid-shutdown when phase B recreated
    # it, spent 145 s in crash recovery; its health gate said "unhealthy" at
    # 50 s and the install failed while the database was healing itself. Now a
    # failed pass is DIAGNOSED: a dependency compose gave up on is watched until
    # it is healthy (with the reason shown), a crash loop or an exit fails at once
    # with that service's own log lines, and failures no wait can fix (port in
    # use, missing image, full disk) fail on the first pass with the remedy.
    budget = budget_s if budget_s is not None else _converge_budget()
    ops = ops if ops is not None else ComposeOps(compose_dir, build_env)
    if services is not None:
        _converge(ops, build_flag, budget, sleep, clock, list(services))
    elif tiered:
        _tiered_up(ops, build_flag, budget, sleep, clock)
    else:
        _converge(ops, build_flag, budget, sleep, clock)


def _converge(ops, build_flag: str, budget: int, sleep, clock,
              services: list[str] | None = None, *, required: bool = True,
              label: str = "") -> None:
    """Drive one `up -d` (of everything, or of `services`) to convergence
    within `budget` seconds. With `services`, a passed `up` is followed by a
    wait until they have settled; `required=False` reports a group that cannot
    settle instead of failing on it (see _settle)."""
    started = clock()
    deadline = started + budget
    last = 1
    passes = 0
    for passes in range(1, _UP_MAX_PASSES + 1):
        rc, out = ops.up(build_flag) if services is None else ops.up(build_flag, services)
        if rc == 0:
            ok(f"{label or 'services'} started"
               + (f" (converged on pass {passes})" if passes > 1 else ""))
            if services:
                _settle(ops, services, started, deadline, budget, sleep, clock,
                        required=required, label=label or ", ".join(services))
            return
        last = rc
        for sig, remedy in _UP_FATAL_SIGNATURES:
            if sig.search(out):
                fail(f"docker compose up failed (exit {rc}): {remedy}")
        if clock() >= deadline:
            break
        blockers = sorted({m.group(1) for m in _UP_BLOCKER.finditer(out)})
        if blockers:
            warn(f"start pass {passes}: compose stopped waiting for "
                 f"{', '.join(blockers)} before it reported healthy — watching it")
            kind, msg = _wait_blockers_healthy(ops, blockers, started, deadline,
                                               budget, sleep, clock)
            if kind == "timeout":
                fail(msg)
            if kind != "healthy":
                fail(msg + "\n  Re-running the installer is safe once the cause is fixed.")
            continue
        pause = max(0.0, min(30.0, deadline - clock()))
        warn(f"start pass {passes} incomplete (exit {rc}, no single service to "
             f"wait on) — retrying in {int(pause)}s")
        sleep(pause)
    fail(f"docker compose up did not converge within {budget}s ({passes} passes, "
         f"last exit {last}). Check: docker compose ps -a")


def _settle(ops, services: list[str], started: float, deadline: float, budget: int,
            sleep, clock, *, required: bool, label: str) -> None:
    """Wait until a started group has settled, before the next group starts.

    A required group (the data stores) that cannot settle fails the install:
    every later service depends on it, so a single start would fail on it too.
    Any other group is reported and the final full pass decides — the verdict
    must not depend on whether this host was slow enough to start in groups.
    One-shot bootstraps that exited 0 have settled."""
    names, why = ops.containers(services)
    if names is None:
        warn(f"could not list the containers of the {label} ({why}) — not waiting "
             "for them; compose's own dependency checks still apply")
        return
    if not names:
        return
    kind, msg = _wait_blockers_healthy(ops, names, started, deadline, budget, sleep,
                                       clock, exit_ok=not required)
    if kind == "healthy":
        return
    if required:
        fail(msg if kind == "timeout"
             else msg + "\n  Re-running the installer is safe once the cause is fixed.")
    warn(msg + f"\n  continuing: nothing else waits on the {label} here; the final "
               "start pass checks the whole stack, as a single start would")


def _tiered_up(ops, build_flag: str, budget: int, sleep, clock) -> None:
    """Start the stack group by group (plan_tiers), each group settling before
    the next, then one full `up -d` so nothing is left out. The groups come from
    the effective compose config, never from an assumption about it."""
    available, why = ops.services()
    if available is None:
        warn(f"could not read which services this install runs ({why}) — starting "
             "them all together instead")
        _converge(ops, build_flag, budget, sleep, clock)
        return
    tiers, rest = plan_tiers(available)
    for n, (label, names, required) in enumerate(tiers, start=1):
        if not names:
            info(f"group {n} of {len(tiers)} ({label}): nothing to start on this install")
            continue
        info(f"group {n} of {len(tiers)} ({label}): {', '.join(names)}")
        _converge(ops, build_flag, budget, sleep, clock, names, required=required,
                  label=label)
    info("final pass: starting everything together so nothing is left out"
         + (f" (not in any group: {', '.join(rest)})" if rest else ""))
    _converge(ops, build_flag, budget, sleep, clock)


# ── compose convergence policy ───────────────────────────────────────────────

_UP_MAX_PASSES = 8
_CRASHLOOP_RESTARTS = 3
_CONVERGE_BUDGET_DEFAULT_S = 900

# `docker compose up` output that no amount of waiting fixes.
_UP_FATAL_SIGNATURES = (
    (re.compile(r"port is already allocated|address already in use", re.IGNORECASE),
     ("a host port Correlix needs is already in use by another process. Find it "
      "with `ss -ltnp`, stop it, and re-run the installer")),
    (re.compile(r"No such image|pull access denied|manifest unknown|"
                r"image with reference .* was found but does not match", re.IGNORECASE),
     ("an image is missing on this host, so the bundle load did not complete. "
      "Re-run the installer; it reloads the image bundle")),
    (re.compile(r"no space left on device", re.IGNORECASE),
     ("the disk is full. Free space under the install directory and Docker's "
      "data root (`docker system df`), then re-run the installer")),
)
# The dependency compose gave up on, e.g.
#   dependency failed to start: container netops-postgres-1 is unhealthy
_UP_BLOCKER = re.compile(
    r"dependency failed to start: container (\S+) (?:is unhealthy|exited)")

# Log lines that say a slow service is healing, not broken. Only the WORDING
# of the wait note comes from here — whether to keep waiting is decided by the
# container's state, restart count and the budget. Each store's pattern is
# pinned by a log line recorded from a real container
# (tests/test_install_selfheal_signatures.py).
_PROGRESS_SIGNATURES = (
    (re.compile(r"syncing data directory|automatic recovery in progress|"
                r"redo starts|database system was interrupted|end-of-recovery"),
     ("recovering from an unclean stop (normal after an interrupted shutdown; "
      "slow disks take minutes)")),
    (re.compile(r"database system is starting up|not yet accepting connections"),
     "still starting up"),
    # Kafka (apache/kafka 4.x LogLoader / LogManager): segments past the
    # recovery point are re-validated after a stop that did not flush them.
    (re.compile(r"Recovering unflushed segment|no clean shutdown file was found"),
     ("Kafka is recovering log segments it had not flushed (normal after an "
      "unclean stop; slow disks take minutes)")),
    # ClickHouse 24.x: metadata then asynchronous table/part loading. Every
    # start does this; after an unclean stop the part checks make it slow.
    # "Loading data parts" is the debug-level wording of the same phase.
    (re.compile(r"Loading data parts|Loading metadata from /var/lib/clickhouse|"
                r"Start asynchronous loading of databases|AsyncLoader: Processed: \d"),
     ("ClickHouse is loading its tables and data parts (slower after an "
      "unclean stop)")),
    # OpenSearch 2.x: the gateway recovers index metadata, then local shard
    # recovery (translog replay after an unclean stop) turns health from RED.
    (re.compile(r"recovered \[\d+\] indices into cluster_state|"
                r"Cluster health status changed from \[RED\]|"
                r"\btranslog\b.*\brecover|\brecover\w*\b.*\btranslog\b"),
     ("OpenSearch is recovering its shards (translog replay after an unclean "
      "stop takes minutes)")),
)
_SECRETISH = re.compile(r"passw|secret|token|apikey|api_key|credential|bearer",
                        re.IGNORECASE)
# A compose service or container name (never starts with "-", no spaces).
_COMPOSE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _converge_setting(default: int, environ: Mapping[str, str] | None = None
                      ) -> tuple[int, bool]:
    """(budget, explicit?) — CORRELIX_CONVERGE_BUDGET_S wins, clamped to
    120..3600; otherwise `default` (the host-profile-scaled value)."""
    environ = os.environ if environ is None else environ
    raw = (environ.get("CORRELIX_CONVERGE_BUDGET_S") or "").strip()
    if not raw:
        return default, False
    try:
        v = int(raw)
    except ValueError:
        warn(f"CORRELIX_CONVERGE_BUDGET_S={raw!r} is not a number of seconds; "
             f"using {default}")
        return default, False
    return max(120, min(3600, v)), True


def _converge_budget(default: int = _CONVERGE_BUDGET_DEFAULT_S) -> int:
    return _converge_setting(default)[0]


# ── tiered bring-up (FMEA 2026-09-15 §4.5, row 11) ──────────────────────────
#
# On .123 each phase created and started ~25 containers at once on 4 cores and
# a slow disk, so every first-boot timer competed for the same IO. A slow host
# starts the stack in these groups instead. Only services the effective compose
# config runs are started; anything in no group (opensearch-init — its ISM
# script can wait a long time, FMEA row 9 — or a TLS init container) is left to
# the final full pass. (label, members, settling required?)
BRING_UP_TIERS: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("data stores", ("postgres", "clickhouse", "kafka", "opensearch", "redis",
                     "victoria", "secrets-seal"), True),
    # The app-state role and Keycloak's database are created before any start.
    ("store bootstraps", ("kafka-init", "opensearch-security-init"), False),
    ("engines", ("api", "correlation", "vector-aggregator", "vector-router", "syslog-ng",
                 "goflow2", "gnmic", "prober", "vmalert", "vmauth"), False),
    ("dashboard and ingress", ("frontend", "nginx"), False),
    ("add-ons", ("opensearch-dashboards", "grafana", "cadvisor", "node-exporter",
                 "kafka-exporter", "keycloak"), False),
)
_SLOW_HOST_CLASSES = ("slow", "very-slow")


def plan_tiers(available: Iterable[str]
               ) -> tuple[list[tuple[str, list[str], bool]], list[str]]:
    """(groups with only the available services, in group order; the
    available services in no group, sorted)."""
    avail = set(available)
    tiers: list[tuple[str, list[str], bool]] = []
    placed: set[str] = set()
    for label, members, required in BRING_UP_TIERS:
        names = [s for s in members if s in avail]
        placed.update(names)
        tiers.append((label, names, required))
    return tiers, sorted(avail - placed)


BRING_UP_MODES = ("auto", "tiered", "single")


def choose_bring_up_mode(host_class: str, overcommit: str, override: str = "") -> tuple[bool, str]:
    """(start in groups?, the reason in plain words). Groups on a slow or very
    slow host, or when the resource plan over-commits memory (`overcommit` is
    the planner's finding in words, "" when it fits).

    `override` is CORRELIX_BRINGUP_MODE, the support lever: the host-speed
    thresholds are uncalibrated, so `tiered` and `single` settle the question
    for a host they read wrong, with no patched installer. A value nobody
    defined stops the install instead of falling back to auto — an ignored
    lever is a support call told the variable was set and an install that never
    saw it."""
    mode = (override or "auto").strip().lower()
    if mode not in BRING_UP_MODES:
        fail(f"CORRELIX_BRINGUP_MODE={override!r} must be "
             + ", ".join(f"'{m}'" for m in BRING_UP_MODES)
             + " ('auto', the default, chooses from this host's speed and the resource plan).")
    if mode == "tiered":
        return True, ("starting the stack in groups: CORRELIX_BRINGUP_MODE=tiered was set, so "
                      "the data stores start first and each group waits for the one before it "
                      "— this overrides what this host's speed and the resource plan would "
                      "have chosen")
    if mode == "single":
        return False, ("starting every service together: CORRELIX_BRINGUP_MODE=single was set "
                       "— this overrides what this host's speed and the resource plan would "
                       "have chosen")
    if host_class in _SLOW_HOST_CLASSES:
        return True, ("starting the stack in groups: this host's disk is "
                      f"{host_class.replace('-', ' ')}, so the data stores start first and "
                      "each group waits for the one before it, instead of every service "
                      "competing for the disk at once")
    if overcommit:
        return True, (f"starting the stack in groups: {overcommit}, so the data stores "
                      "start first and each group waits for the one before it")
    speed = _SPEED_WORDS.get(host_class, _SPEED_UNKNOWN)
    return False, (f"starting every service together: {speed} and the resource plan "
                   "reports no over-commitment")


def planner_overcommit(plan_path: Path) -> str:
    """The resource plan's memory over-commitment in plain words, from the
    resource-plan.json run_resource_plan records; "" when it fits or there is
    no plan (sizing was skipped)."""
    doc, why = _read_json_object(plan_path)
    if doc is None:
        if why != "missing":
            warn(f"could not read the resource plan {plan_path} ({why}) — treating it "
                 "as fitting this host")
        return ""
    try:
        reserved = sum(int(v) for v in doc["reservations_bytes"].values())
        allocatable = int(doc["reserves"]["allocatable_bytes"])
        limits = int(doc["totals"]["limits_bytes"])
        budget = int(doc["totals"]["budget_bytes"])
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        warn(f"the resource plan {plan_path} is missing a total ({type(e).__name__}: {e}) "
             "— treating it as fitting this host")
        return ""
    if reserved > allocatable:
        return "the resource plan reserves more memory than this host can guarantee"
    if limits > budget:
        return "the resource plan's memory limits exceed what this host can over-commit"
    return ""


class ComposeOps:
    """Everything compose_up asks Docker. Injectable, so the convergence policy
    is tested without a stack (CLAUDE.md §2). Every call is bounded (§9)."""

    UP_TIMEOUT_S = 1800

    def __init__(self, compose_dir: Path, env: dict) -> None:
        self.compose_dir = compose_dir
        self.env = env

    QUERY_TIMEOUT_S = 120

    def _query(self, argv: list[str]) -> tuple[str | None, str]:
        """stdout of a read-only compose query, or (None, redacted reason)."""
        what = " ".join(argv[:3])
        try:
            r = subprocess.run(argv, cwd=str(self.compose_dir), env=self.env,
                               capture_output=True, text=True,
                               timeout=self.QUERY_TIMEOUT_S, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            return None, f"could not run {what}: {e}"
        if r.returncode != 0:
            detail = " | ".join(_redacted_tail((r.stderr or "") + "\n" + (r.stdout or ""), 3))
            return None, f"{what} exited {r.returncode}: {detail or 'no output'}"
        return r.stdout or "", ""

    @staticmethod
    def _names(text: str, what: str) -> tuple[list[str] | None, str]:
        names = [ln.strip() for ln in text.splitlines() if ln.strip()]
        # A name becomes an argv element of the next compose call: never let
        # unexpected output (a flag, a warning line) through (§3).
        if len(names) > 500 or any(not _COMPOSE_NAME.fullmatch(n) for n in names):
            return None, f"unexpected output from {what}"
        return names, ""

    def services(self) -> tuple[list[str] | None, str]:
        """The services the effective compose config runs — the compose files
        and active profiles from .env — or (None, reason)."""
        out, why = self._query(["docker", "compose", "config", "--services"])
        if out is None:
            return None, why
        names, why = self._names(out, "docker compose config")
        if names is not None and not names:
            return None, "docker compose config listed no services"
        return names, why

    def containers(self, services: list[str]) -> tuple[list[str] | None, str]:
        """Container names of these services, or (None, reason)."""
        out, why = self._query(["docker", "compose", "ps", "-a", "--format", "{{.Name}}",
                                *services])
        if out is None:
            return None, why
        return self._names(out, "docker compose ps")

    def up(self, build_flag: str, services: list[str] | None = None) -> tuple[int, str]:
        """Run `up -d` (of everything, or of `services`), streaming its output
        live (the GUI parses it) while keeping the tail for diagnosis."""
        try:
            p = subprocess.Popen(["docker", "compose", "up", "-d", build_flag,
                                  *(services or [])],
                                 cwd=str(self.compose_dir), env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True)
        except OSError as e:
            # No docker binary / no permission to run it: no pass can succeed,
            # so there is nothing to converge on (§16.1: stop, and say why).
            fail(f"could not run docker compose: {e}")
            raise
        killer = threading.Timer(self.UP_TIMEOUT_S, p.kill)
        killer.start()
        tail: list[str] = []
        try:
            assert p.stdout is not None
            for line in p.stdout:
                print(line, end="", flush=True)
                tail.append(line)
                if len(tail) > 400:
                    del tail[:100]
            rc = p.wait()
        finally:
            killer.cancel()
        return rc, "".join(tail)

    def inspect(self, name: str) -> dict | None:
        try:
            r = subprocess.run(["docker", "inspect", "--format",
                                '{"state":{{json .State}},"restarts":{{.RestartCount}}}',
                                name], capture_output=True, text=True, timeout=30,
                               check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        try:
            return json.loads(r.stdout)
        except ValueError:
            return None

    def logs(self, name: str, n: int = 40) -> str:
        try:
            r = subprocess.run(["docker", "logs", "--tail", str(n), name],
                               capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            return f"(could not read logs: {e})"
        return (r.stdout or "") + (r.stderr or "")


def _redacted_tail(text: str, n: int = 15) -> list[str]:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    return [("[line withheld: may contain a credential]" if _SECRETISH.search(ln) else ln)
            for ln in lines[-n:]]


def _progress_reason(logs: str) -> str:
    recent = "\n".join(logs.splitlines()[-30:])
    for sig, why in _PROGRESS_SIGNATURES:
        if sig.search(recent):
            return why
    return ""


def _diagnosis(ops, name: str, headline: str) -> str:
    body = "\n".join("    " + ln for ln in _redacted_tail(ops.logs(name, 40)))
    return f"{headline}\n  last log lines of {name}:\n{body or '    (no output)'}"


def _wait_blockers_healthy(ops, names: list[str], started: float, deadline: float,
                           budget: int, sleep, clock, *,
                           exit_ok: bool = False) -> tuple[str, str]:
    """Watch the containers compose gave up on until every one is healthy.

    Returns ("healthy", "") or a failure kind with an operator-facing message:
    "exited" / "crashloop" (waiting cannot fix it) or "timeout" (the budget ran
    out while it was still progressing). `exit_ok`: a container that exited 0
    has finished (a one-shot bootstrap in a start group)."""
    base: dict[str, int] = {}
    last_note = float("-inf")
    while True:
        pending: list[tuple[str, str]] = []
        for n in names:
            st = ops.inspect(n)
            if st is None:
                return "exited", (f"{n} no longer exists (it was removed while the "
                                  "installer waited). Check: docker compose ps -a")
            state = st.get("state") or {}
            restarts = int(st.get("restarts") or 0)
            base.setdefault(n, restarts)
            status = state.get("Status", "")
            health = (state.get("Health") or {}).get("Status", "")
            if restarts - base[n] >= _CRASHLOOP_RESTARTS:
                return "crashloop", _diagnosis(
                    ops, n, f"{n} keeps restarting ({restarts - base[n]} restarts "
                            "while the installer waited), so waiting will not fix it.")
            if status in ("exited", "dead"):
                if exit_ok and status == "exited" and state.get("ExitCode") == 0:
                    continue
                return "exited", _diagnosis(
                    ops, n, f"{n} stopped with exit code {state.get('ExitCode')}.")
            if status == "running" and health in ("healthy", ""):
                continue
            pending.append((n, health or status or "unknown"))
        if not pending:
            ok(f"{', '.join(names)} healthy after {int(clock() - started)}s — "
               "starting the rest")
            return "healthy", ""
        now = clock()
        if now >= deadline:
            n, h = pending[0]
            return "timeout", _diagnosis(
                ops, n, f"{n} is still {h} after the {budget}s start budget. "
                        "A slower host can raise it with CORRELIX_CONVERGE_BUDGET_S "
                        "(max 3600) and re-run the installer, which is safe.")
        if now - last_note >= 30:
            for n, h in pending:
                why = _progress_reason(ops.logs(n, 30))
                info(f"waiting for {n}: {h}" + (f" — {why}" if why else "")
                     + f" ({int(now - started)}s of a {budget}s budget)")
            last_note = now
        sleep(max(0.0, min(5.0, deadline - now)))


# Stores the TLS phase-B restart recreates. Stopping them first, with a real
# shutdown window, is what keeps that restart from being a crash.
_STATEFUL_STORES = ("postgres", "clickhouse", "kafka", "opensearch")
_SIGKILL_EXIT = 137


# The last line a postgres postmaster writes after a clean (smart/fast)
# shutdown. Recorded from netops-postgres-1: `[1] LOG:  database system is shut
# down`. Exit code 0 alone does not prove it: a wrapper can exit 0 around a
# postmaster that never finished.
_PG_SHUTDOWN_DONE = "database system is shut down"


def _postgres_shutdown_unconfirmed(compose_dir: Path, since: str, run) -> str:
    """"" when postgres logged a completed shutdown since `since`, else why not."""
    try:
        r = run(["docker", "compose", "logs", "--since", since, "--no-color", "postgres"],
                cwd=str(compose_dir), capture_output=True, text=True, timeout=60,
                check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return f"its log could not be read to confirm a clean shutdown ({e})"
    if r.returncode != 0:
        return ("its log could not be read to confirm a clean shutdown ("
                f"{(r.stderr or r.stdout).strip()[:200]})")
    if _PG_SHUTDOWN_DONE not in (r.stdout or "") + (r.stderr or ""):
        return f"it did not log '{_PG_SHUTDOWN_DONE}'"
    return ""


def stop_stores_cleanly(compose_dir: Path, services=_STATEFUL_STORES, *,
                        run=subprocess.run, grace_s: int = STORE_STOP_GRACE_BASE_S,
                        now=lambda: datetime.now(timezone.utc)) -> None:
    """Stop the running stateful stores with a shutdown window before phase B
    recreates them, and say so when one was killed anyway (its next start runs
    crash recovery, which compose_up now waits through). Never fatal: the
    recreate would stop them regardless; this only makes the stop clean.

    postgres counts as clean only when it logged `database system is shut
    down` after the stop began — not merely because it exited 0."""
    try:
        ps = run(["docker", "compose", "ps", "--status", "running", "--services"],
                 cwd=str(compose_dir), capture_output=True, text=True, timeout=60,
                 check=False)
    except (OSError, subprocess.SubprocessError) as e:
        warn(f"could not list running services before the TLS restart: {e}")
        return
    if ps.returncode != 0:
        warn("could not list running services before the TLS restart: "
             f"{(ps.stderr or ps.stdout).strip()}")
        return
    running = set(ps.stdout.split())
    targets = [s for s in services if s in running]
    if not targets:
        return
    info(f"stopping {', '.join(targets)} cleanly before the TLS restart "
         f"(up to {grace_s}s)…")
    since = now().strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        r = run(["docker", "compose", "stop", "--timeout", str(grace_s), *targets],
                cwd=str(compose_dir), capture_output=True, text=True,
                timeout=grace_s + 120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        warn(f"stopping the stores before the TLS restart failed: {e}")
        return
    if r.returncode != 0:
        warn(f"stopping the stores before the TLS restart failed: "
             f"{(r.stderr or r.stdout).strip()}")
    killed = []
    for svc in targets:
        try:
            q = run(["docker", "compose", "ps", "-a", "--format", "{{.ExitCode}}", svc],
                    cwd=str(compose_dir), capture_output=True, text=True, timeout=60,
                    check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if q.returncode == 0 and q.stdout.strip().splitlines()[:1] == [str(_SIGKILL_EXIT)]:
            killed.append(svc)
    unconfirmed: list[str] = []
    if "postgres" in targets and "postgres" not in killed:
        why = _postgres_shutdown_unconfirmed(compose_dir, since, run)
        if why:
            unconfirmed.append("postgres")
            warn(f"postgres stopped, but {why}; its next start may run crash "
                 "recovery, which can take minutes on a slow disk (the installer "
                 "waits for it)")
    if killed:
        warn(f"{', '.join(killed)} did not finish shutting down within {grace_s}s "
             "and was killed; its next start runs crash recovery, which can take "
             "minutes on a slow disk (the installer waits for it)")
    clean = [s for s in targets if s not in killed and s not in unconfirmed]
    if clean:
        ok(f"{', '.join(clean)} stopped cleanly")

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


def load_addon_packs(bundle: Path, profiles: str, *, image_present=None) -> None:
    """docker-load the add-on pack for every activated profile that has one.

    WHY THIS REFUSES INSTEAD OF CONTINUING. On an offline install the images
    are whatever the archives put in the daemon; compose is started with
    --no-build and a pull it cannot perform. If the customer asks for `sso` on
    a bundle that carries no sso pack, the honest outcome is a named refusal
    HERE — naming the pack, the file, and the two ways forward — rather than
    twenty minutes later as `keycloak: Error response from daemon: pull access
    denied`, from a host with no route to a registry (scripts/CLAUDE.md 16.1:
    a step that cannot do its job says so, by name).

    Packs live next to the base archive, which is what --bundle points at.
    """
    active = {p.strip() for p in profiles.split(",") if p.strip()}
    image_present = image_present if image_present is not None else _image_present
    for prof in sorted(active & set(ADDON_PACKS)):
        name, what = ADDON_PACKS[prof]
        packs = sorted(bundle.parent.glob(f"correlix-addon-{name}-*.tar.zst"))
        if not packs:
            fail(f"the '{prof}' profile needs the {name!r} add-on pack, and this "
                 f"bundle does not contain it.\n"
                 f"       Looked for: {bundle.parent}/correlix-addon-{name}-*.tar.zst\n"
                 f"       {what} ships as a SEPARATE download so the base "
                 f"appliance stays small.\n"
                 f"       Either copy correlix-addon-{name}-<version>.tar.zst next "
                 f"to the installer and re-run, or install without it "
                 f"(drop '{prof}' from --profiles).")
        # Journal-driven skip (B1): a re-run does not reload a pack that the
        # journal records as loaded from this same archive when every image
        # its MANIFEST section lists is still present.
        key = f"addon-pack:{name}"
        skip, why, fp = image_load_decision(_TIMING["journal"], key, packs[-1],
                                            f"addon:{name}", image_present)
        step(f"loading add-on pack {name}", stage="addon-pack", key=key,
             inputs={"bundle": fp or ""})
        if skip:
            info(f"skipping add-on pack {name}: {why}")
            continue
        info(f"loading add-on pack {name} (not skipped: {why})")
        load_bundle(packs[-1])


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

# The matrix is the script THIS bundle ships, piped into the broker on stdin —
# never the copy compose.tls.yml bind-mounts into the container. A single-file
# bind mount pins the inode it was created with, so after an upgrade that does
# not recreate kafka the mounted copy is the OLD matrix (FMEA row 7 / T7; the
# 2026-09-02 lab incident: an ungranted topic, consumer auth-dead for 3 h, all
# green). deploy-qualify.sh B1 applies it the same way.
_ACL_SCRIPT_REL = Path("kafka") / "apply-acls.sh"   # under deployment/docker
_ACL_EXEC = ["docker", "compose", "exec", "-T", "kafka", "sh", "-s"]
_ACL_SCRIPT_MAX_BYTES = 1024 * 1024
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


def _acl_runbook_step(compose_dir: Path) -> str:
    return f"cd {compose_dir} && docker compose exec -T kafka sh -s < {_ACL_SCRIPT_REL}"


def apply_kafka_acls(compose_dir: Path, timeout_s: int = ACL_APPLY_BASE_S, *,
                     run=None) -> None:
    """Run the SEC-007 ACL matrix inside the broker, bounded + loud (§16.1).

    The bundle's deployment/docker/kafka/apply-acls.sh is piped into
    `sh -s` in the kafka container (never the bind-mounted copy, which can be
    stale — see _ACL_SCRIPT_REL) and runs against the mTLS listener with the
    broker's super-user SVID (it auto-detects /tmp/kafka-tls/admin.properties).
    It is idempotent (kafka-acls --add of an existing ACL is a no-op) and
    verifies the matrix back before exiting 0, so a zero exit here is a
    proven-applied matrix. Retries over a bounded window because right after
    the phase-B recreate the broker may still be in log recovery; persistent
    failure FAILS the install — completing with a dead bus is the defect this
    step removes. `run` is the injected subprocess runner."""
    run = run if run is not None else subprocess.run
    script_path = compose_dir / _ACL_SCRIPT_REL
    try:
        size = script_path.stat().st_size
        if size > _ACL_SCRIPT_MAX_BYTES:
            raise OSError(errno.EFBIG, f"{size} bytes is larger than expected")
        script = script_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        fail(f"cannot read the Kafka ACL matrix script {script_path} "
             f"({getattr(e, 'strerror', None) or e}) — the installer applies the copy "
             "this bundle ships and refuses to report success over an "
             "authorization-dead bus. Re-extract the bundle, then re-run the installer.")
        raise SystemExit(1) from e
    deadline = time.time() + timeout_s
    attempt = 0
    last = "no output"
    while True:
        attempt += 1
        try:
            res = run(_ACL_EXEC, cwd=str(compose_dir), input=script,
                      capture_output=True, text=True, timeout=600, check=False)
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
         f"{_acl_runbook_step(compose_dir)}. Last error: {last}")


def verify_bus_consumers(compose_dir: Path, group: str = "netops-correlation",
                         timeout_s: int = BUS_CONSUMERS_BASE_S) -> None:
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


# Where the ACL matrix's application time is recorded, relative to the repo
# root. scripts/deploy-qualify.sh reads it to floor Q6's log window: the
# installer necessarily starts the stack BEFORE this matrix can exist, so a
# fresh install always writes bootstrap-class authorization errors into its own
# logs, and a fixed wall-clock window makes the gate fail by construction on a
# stack that is working (fresh-install acceptance, 2026-09-06, DEFECT-10).
#
# It lives under data/ on purpose: the KRaft ACL store IS data/kafka, so any
# wipe that destroys the matrix (uninstall --purge, reset-demo) destroys this
# claim about it in the same stroke. A stale marker is therefore impossible.
KAFKA_ACL_MARKER = ".kafka-acls-applied"


def record_bus_authorization_time(root: Path, when: float | None = None) -> Path | None:
    """Stamp data/.kafka-acls-applied. Advisory: never fails an install.

    A marker we could not write costs deploy-qualify.sh its bootstrap floor and
    nothing else (Q6 falls back to its fixed window), so a warning is the
    correct severity — but it IS warned, never swallowed (§16.1)."""
    path = root / "data" / KAFKA_ACL_MARKER
    stamp = time.time() if when is None else when
    utc = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "# The SEC-007 Kafka ACL matrix was applied and verified at this\n"
            "# moment by scripts/install.py. Read by scripts/deploy-qualify.sh\n"
            "# (Q6) to floor its log window; safe to delete.\n"
            f"applied_epoch={int(stamp)}\n"
            f"applied_utc={utc}\n")
    except OSError as exc:
        warn(f"could not record the ACL-application time in {path}: {exc}. "
             "deploy-qualify.sh's Q6 will fall back to its fixed log window "
             "and may report the install's own pre-ACL bootstrap noise.")
        return None
    return path


def apply_bus_authorization(compose_dir: Path, env_path: Path,
                            tls_enabled: bool, *,
                            acl_timeout_s: int = ACL_APPLY_BASE_S,
                            consumers_timeout_s: int = BUS_CONSUMERS_BASE_S) -> None:
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
    apply_kafka_acls(compose_dir, timeout_s=acl_timeout_s)
    verify_bus_consumers(compose_dir, timeout_s=consumers_timeout_s)
    # Both proved: the matrix is written AND a real consumer holds membership
    # through the enforcing broker. That instant is the honest floor for Q6.
    record_bus_authorization_time(compose_dir.parents[1])


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


def bootstrap_keycloak_db(compose_dir: Path, env: dict, *,
                          start_postgres: bool = False,
                          pg_budget_s: float | None = None) -> bool:
    """Create Keycloak's database when the `sso` profile is active. Returns True
    when the database exists afterwards.

    Keycloak does not create its own DB: without this it crash-loops on first
    boot with `FATAL: database "keycloak" does not exist` (hit on the first
    real SSO bring-up, 2026-08-03 — docs/runbooks/okta-sso-setup.md §1).
    install.py owns first-boot provisioning, so it owns this too. Idempotent
    (SELECT-then-CREATE). A single attempt is non-fatal and loud, with the
    manual command: the early pre-start call may simply be too early. The
    post-start confirmation (confirm_keycloak_db) retries it and makes a
    database that still does not exist FATAL under `sso` — reporting success
    over a crash-looping Keycloak is FMEA §2 #5 (T2 residual)."""
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
        return False
    # Bounded readiness wait (the postgres container may still be starting on a
    # first boot), then the existence probe. The wait is the SHARED helper — a
    # real query against the real server, never pg_isready, which also answers
    # for the entrypoint's temporary init server (2026-09-14 lab install).
    # Before the stack starts (the normal install path) nothing has started
    # postgres yet unless the app-state backend did; start ONLY postgres.
    if start_postgres:
        try:
            up = subprocess.run(["docker", "compose", "up", "-d", "postgres"],
                                cwd=str(compose_dir), capture_output=True, text=True,
                                timeout=300, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            warn(f"could not start postgres to create the {db} database: {e}")
            info(f"re-run install.py, or once postgres is up run: {manual}")
            return False
        if up.returncode != 0:
            warn(f"could not start postgres to create the {db} database: "
                 f"{(up.stderr or up.stdout).strip()}")
            info(f"re-run install.py, or once postgres is up run: {manual}")
            return False
    runner = ComposeRunner(compose_dir)
    rok, rmsg = wait_for_postgres(runner, user=user, db="postgres",
                                  label="postgres (keycloak db check)",
                                  budget_s=pg_budget_s)
    if not rok:
        warn(f"could not reach postgres to check for the {db} database "
             f"(Keycloak will crash-loop until it exists): {rmsg}")
        info(f"re-run install.py once postgres is healthy, or run: {manual}")
        return False
    # -tAc → bare "1" when the row exists.
    res = runner.exec("postgres", ["psql", "-v", "ON_ERROR_STOP=1", "-U", user,
                                   "-d", "postgres", "-tAc",
                                   f"SELECT 1 FROM pg_database WHERE datname='{db}'"],
                      stdin="", timeout=60)
    if res.returncode != 0:
        warn(f"could not check for the {db} database (Keycloak will crash-loop "
             f"until it exists): {(res.stderr or res.stdout).strip()}")
        info(f"re-run install.py once postgres is healthy, or run: {manual}")
        return False
    if res.stdout.strip() == "1":
        ok(f"keycloak database '{db}' already exists")
        return True
    res = runner.exec("postgres", ["psql", "-v", "ON_ERROR_STOP=1", "-U", user,
                                   "-d", "postgres", "-c",
                                   f'CREATE DATABASE "{db}" OWNER "{user}"'],
                      stdin="", timeout=60)
    if res.returncode != 0:
        warn(f"creating the {db} database failed (Keycloak will crash-loop "
             f"until it exists): {(res.stderr or res.stdout).strip()}")
        info(f"create it manually: {manual}")
        return False
    ok(f"keycloak database '{db}' created (owner {user})")
    return True


KEYCLOAK_DB_CONFIRM_ATTEMPTS = 3
KEYCLOAK_DB_RETRY_BASE_S = 10.0


def confirm_keycloak_db(compose_dir: Path, env: dict, *, bootstrap=None,
                        attempts: int = KEYCLOAK_DB_CONFIRM_ATTEMPTS,
                        base_delay_s: float = KEYCLOAK_DB_RETRY_BASE_S,
                        sleep=time.sleep,
                        pg_budget_s: float | None = None) -> None:
    """Post-start confirmation under the `sso` profile: the database must
    exist. Bounded retry (each attempt carries its own postgres readiness
    budget, `pg_budget_s` from the host profile) with exponential backoff and
    jitter (§9), then FATAL with the manual command — never "installed" over a
    crash-looping Keycloak."""
    bootstrap = (bootstrap if bootstrap is not None
                 else functools.partial(bootstrap_keycloak_db, pg_budget_s=pg_budget_s))
    for attempt in range(1, attempts + 1):
        if bootstrap(compose_dir, env):
            return
        if attempt < attempts:
            delay = _jittered(base_delay_s * (2 ** (attempt - 1)))
            warn(f"Keycloak's database is not confirmed yet (attempt {attempt} of "
                 f"{attempts}); trying again in {delay:.0f}s")
            sleep(delay)
    user = env.get("DB_USER", "netops")
    db = env.get("KEYCLOAK_DB_NAME", "keycloak")
    if _PG_IDENT.match(user) and _PG_IDENT.match(db):
        manual = (f"cd {compose_dir} && docker compose exec postgres "
                  f"createdb -U {user} {db}")
        name = f"'{db}'"
    else:
        manual = ("fix DB_USER / KEYCLOAK_DB_NAME in .env ([A-Za-z0-9_] only), "
                  "then create that database by hand")
        name = "(KEYCLOAK_DB_NAME)"
    fail(f"Keycloak's database {name} still does not exist after {attempts} "
         "attempts, and the sso profile is active: Keycloak crash-loops without "
         "it, so this install is not reported as a success.\n"
         f"  Create it:  {manual}\n"
         "  then re-run the installer (safe), or remove 'sso' from "
         "COMPOSE_PROFILES in .env if single sign-on is not wanted.")


# The non-superuser role the Postgres app-state backend authenticates as. It is
# NOT the cluster superuser (DB_USER): a superuser — or any BYPASSRLS role —
# ignores FORCE ROW LEVEL SECURITY, which would silently disable tenant
# isolation, and the api refuses to start as one.
APP_STATE_ROLE = "netops_app"


def app_state_backend(env: dict) -> str:
    """The configured registry/app-state backend, normalized."""
    v = (env.get("STORE_BACKEND") or "").strip().lower()
    return "postgres" if v in ("postgres", "postgresql", "pg") else (v or "file")


def _split_app_dsn(dsn: str) -> tuple[str, str, str, str]:
    """(user, password, host, dbname) from a DSN. Never logged, never echoed."""
    from urllib.parse import unquote, urlsplit
    parts = urlsplit(dsn)
    return (unquote(parts.username or ""), unquote(parts.password or ""),
            parts.hostname or "", (parts.path or "/").lstrip("/"))


# Postgres first-boot states that are NOT a failure, only "not yet". The
# official entrypoint runs initdb, brings up a TEMPORARY server on the unix
# socket to run its init scripts, SHUTS THAT DOWN, and only then starts the
# real one, so for the first ~10-30s of a fresh install every connection to
# the container either finds no socket at all, is refused, or is dropped
# mid-handshake.
#
# 2026-09-14, fresh install on the .123 lab box: this classifier MISSED the
# most common form of that window and the install died on the first attempt —
#
#   psql: error: connection to server on socket
#   "/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory
#
# because the old pattern spelled it `No such file or directory.*PGSQL`, and
# psql (>= 14) prints the socket path BEFORE the errno text. Nothing matched,
# the error was classified as fatal, and zero retries were spent on a
# condition that cleared seconds later. Order-independent alternatives below,
# each one a CONNECTION-class failure only: an authentication failure, a
# missing database or a SQL error must still surface immediately (never mask a
# real error as transient).
_PG_TRANSIENT = re.compile(
    r"the database system is (shutting down|starting up|not yet accepting"
    r" connections|in recovery mode)"
    r"|could not connect to server"
    r"|connection to server (on socket|at) [^\n]*failed:\s*"
    r"(no such file or directory|connection refused|network is unreachable"
    r"|connection timed out|timeout expired|server closed)"
    r"|connection refused"
    r"|server closed the connection unexpectedly"
    r"|terminating connection due to (administrator command"
    r"|unexpected postmaster exit)"
    r"|is not running|is restarting"
    r"|timed out after \d+s",
    re.IGNORECASE)

# …and the veto. psql reports an authentication or SQL failure in the SAME
# "connection to server at … failed:" envelope as a refused connection, so the
# pattern above alone would happily retry a wrong password for three minutes
# and then report the socket window instead of the credential. Anything here
# is a real error: it is returned to the operator on the first attempt.
_PG_FATAL = re.compile(
    r"password authentication failed|authentication failed for user"
    r"|no pg_hba\.conf entry|role \".*\" does not exist"
    r"|database \".*\" does not exist|permission denied"
    r"|syntax error|does not exist|already exists",
    re.IGNORECASE)


def _pg_db_not_created_yet(message: str, db: str) -> bool:
    """True when psql says the TARGET database does not exist — the state the
    postgres entrypoint's init server is in before it creates POSTGRES_DB.
    Readiness-only: provisioning keeps classifying this as a real error."""
    if not db:
        return False
    return re.search(r'database "' + re.escape(db) + r'" does not exist',
                     message or "", re.IGNORECASE) is not None


def _pg_transient(message: str) -> bool:
    """True only for a CONNECTION-class psql failure — one that can clear by
    waiting. A real SQL/auth error is never masked as "not ready yet" (§16.1).
    """
    text = message or ""
    if _PG_FATAL.search(text):
        return False
    return bool(_PG_TRANSIENT.search(text))


# How long to wait for postgres to finish its first boot before giving up, and
# how long it must keep answering before we believe it is the REAL server and
# not the entrypoint's temporary init server. Env-tunable (§9: bounded, but a
# slow disk must be survivable without editing the installer).
PG_READY_BUDGET_S = 180.0
PG_READY_STABLE_S = 2.0
PG_READY_BUDGET_ENV = "CORRELIX_PG_READY_TIMEOUT"


def _pg_ready_setting(default: float, environ: Mapping[str, str] | None = None
                      ) -> tuple[float, bool]:
    """(budget, explicit?) — CORRELIX_PG_READY_TIMEOUT wins when it is a
    positive number; otherwise `default` (the host-profile-scaled value)."""
    environ = os.environ if environ is None else environ
    raw = (environ.get(PG_READY_BUDGET_ENV) or "").strip()
    if not raw:
        return default, False
    try:
        value = float(raw)
    except ValueError:
        warn(f"{PG_READY_BUDGET_ENV}={raw!r} is not a number — using the "
             f"{default:.0f}s default")
        return default, False
    if not math.isfinite(value) or value <= 0:
        warn(f"{PG_READY_BUDGET_ENV}={raw!r} must be > 0 — using the "
             f"{default:.0f}s default")
        return default, False
    return value, True


def _pg_ready_budget_s(default: float = PG_READY_BUDGET_S) -> float:
    """The readiness budget in seconds, from CORRELIX_PG_READY_TIMEOUT."""
    return _pg_ready_setting(default)[0]


def _jittered(delay: float) -> float:
    """delay ±25% (§9: backoff WITH jitter). `secrets` not because this is a
    security decision but because it is the RNG already imported here."""
    return delay * (0.75 + (secrets.randbelow(501) / 1000.0))


def wait_for_postgres(runner, *, user: str, db: str, service: str = "postgres",
                      budget_s: float | None = None,
                      stable_s: float = PG_READY_STABLE_S,
                      sleep=time.sleep, now=time.monotonic,
                      label: str = "postgres") -> tuple[bool, str]:
    """Block until `service` answers a REAL query on the REAL server.

    `pg_isready` is NOT the signal: it answers "yes" against the temporary
    server the postgres entrypoint runs during initdb, and it answers about a
    moment that has already passed by the time the next command runs. So this
    runs the query the caller is about to depend on — `SELECT 1`, over the
    container's local socket, as the superuser (trust auth inside the
    container, no credential in argv) — and requires TWO successes at least
    `stable_s` apart. The init server is torn down between them, so a pair of
    spaced successes cannot come from it.

    Bounded (§9/§16.3): the loop always ends, at the latest when the budget is
    spent. Loud (§16.1): every wait is logged with the elapsed time, and the
    failure carries the elapsed time, the probe count and the last error.

    Returns (ready, message). A probe that fails for a reason that is NOT a
    connection-class error (authentication, a missing database, a broken
    server) returns False IMMEDIATELY: waiting three minutes cannot fix it,
    and calling it "not ready yet" would hide the error the operator needs.
    """
    budget = _pg_ready_budget_s() if budget_s is None else budget_s
    started = now()
    probes, delay, first_ok = 0, 1.0, None
    last = "no probe ran"
    while True:
        probes += 1
        r = runner.exec(service, ["psql", "-v", "ON_ERROR_STOP=1", "-U", user,
                                  "-d", db, "-Atc", "select 1"],
                        stdin="", timeout=30)
        if r.returncode == 0 and "1" in (r.stdout or "").split():
            t = now()
            if first_ok is None:
                first_ok = t
                info(f"{label}: answered a query after {t - started:.0f}s — "
                     f"confirming it is the real server (the first-boot init "
                     f"server answers too, then goes away)")
            elif t - first_ok >= stable_s:
                return True, (f"ready after {t - started:.0f}s "
                              f"({probes} probes, answering for "
                              f"{t - first_ok:.0f}s)")
            wait = max(stable_s - (now() - first_ok), 0.5)
            reason = "confirming the server stays up"
        else:
            detail = ((r.stderr or "") + " " + (r.stdout or "")).strip()
            last = (detail.splitlines() or ["(no output)"])[0].strip()[:300]
            # FIRST BOOT: the entrypoint's temporary server is up before it has
            # run CREATE DATABASE for POSTGRES_DB, so a probe of the target
            # database can be told it "does not exist" for a few seconds. That
            # is a first-boot state, not a misconfiguration: wait it out inside
            # the same bounded budget. Only the TARGET database is excused, and
            # only here — once readiness is proven, the provisioning classifier
            # still treats a missing database as a real error (§16.1). Found by
            # the CI two-phase boot test (run 34909387288, 2026-09-14): second
            # probe, `FATAL:  database "netops" does not exist`.
            if _pg_db_not_created_yet(detail, db):
                if first_ok is not None:
                    warn(f"{label} stopped answering after it had answered — "
                         f"that is the first-boot handover; the stability "
                         f"wait restarts")
                    first_ok = None
                wait = _jittered(delay)
                delay = min(delay * 2, 10.0)
                reason = (f"database {db!r} not created yet (the first-boot "
                          f"init server is still running)")
                elapsed = now() - started
                if elapsed >= budget:
                    return False, (f"{label} did not create database {db!r} "
                                   f"within {budget:.0f}s ({probes} probes, "
                                   f"{elapsed:.0f}s elapsed); last error: "
                                   f"{last}")
                info(f"waiting for {label}: {reason} ({elapsed:.0f}s of a "
                     f"{budget:.0f}s budget; next probe in {wait:.1f}s)")
                sleep(wait)
                continue
            if not _pg_transient(detail):
                return False, (f"{label} refused a probe with an error that is "
                               f"not a connection failure — this will not clear "
                               f"by waiting: {last}")
            if first_ok is not None:
                # It answered and then stopped: that IS the init→real handover.
                warn(f"{label} stopped answering after it had answered — that "
                     f"is the first-boot handover; the stability wait restarts")
                first_ok = None
            wait = _jittered(delay)
            delay = min(delay * 2, 10.0)
            reason = last
        elapsed = now() - started
        if elapsed >= budget:
            return False, (f"{label} did not become ready within {budget:.0f}s "
                           f"({probes} probes, {elapsed:.0f}s elapsed); last "
                           f"error: {last}")
        info(f"waiting for {label}: {reason} ({elapsed:.0f}s of a "
             f"{budget:.0f}s budget; next probe in {wait:.1f}s)")
        sleep(wait)


def _provision_app_state_role_with_retry(sr, compose_dir: Path, *, db_user: str,
                                         db_name: str, app_user: str,
                                         app_password: str,
                                         deadline_s: float = 180.0,
                                         sleep=time.sleep, now=time.monotonic,
                                         runner=None, ready=None
                                         ) -> tuple[bool, str]:
    """provision_app_state_role, retried across the first-boot restart.

    Returns the LAST (ok, message) pair. A non-transient failure (bad
    credentials, a syntax error, a genuinely broken database) is returned
    immediately — retrying those would only delay a real error by three
    minutes. Bounded (§16.3): the loop always ends.

    Before every RETRY the server is re-proved ready (`ready`, by default
    `wait_for_postgres` with whatever is left of the budget), so an attempt is
    never thrown at a socket that is still gone: the retry waits for the real
    server rather than burning the budget on `psql` invocations.
    """
    runner = ComposeRunner(compose_dir) if runner is None else runner
    if ready is None:
        def ready(budget_s: float) -> tuple[bool, str]:
            return wait_for_postgres(runner, user=db_user, db=db_name,
                                     budget_s=budget_s, sleep=sleep, now=now)
    started = now()
    attempt, backoff, last = 0, 1.0, (False, "not attempted")
    while True:
        attempt += 1
        last = sr.provision_app_state_role(
            runner, db_user=db_user, db_name=db_name,
            app_user=app_user, app_password=app_password)
        if last[0]:
            if attempt > 1:
                info(f"app-state role provisioned on attempt {attempt} after "
                     f"{now() - started:.0f}s (postgres was still completing "
                     f"its first boot)")
            return last
        if not _pg_transient(last[1] or ""):
            return last                      # a real error: surface it now
        elapsed = now() - started
        if elapsed >= deadline_s:
            return (False, (f"{last[1]} (still transient after {elapsed:.0f}s "
                            f"and {attempt} attempts)"))
        info(f"postgres is still completing its first boot ({last[1]}) — "
             f"retrying the app-state role provisioning "
             f"({elapsed:.0f}s of a {deadline_s:.0f}s budget)")
        sleep(_jittered(backoff))
        backoff = min(backoff * 2, 10.0)
        remaining = deadline_s - (now() - started)
        if remaining <= 0:
            waited = now() - started
            return (False, (f"{last[1]} (still transient after {waited:.0f}s "
                            f"and {attempt} attempts)"))
        rok, rmsg = ready(remaining)
        if not rok:
            # Not "not ready yet" — the readiness helper is itself bounded and
            # has already spent what was left, so this is the final word (§16.1).
            return (False, rmsg)


def bootstrap_app_state_role(compose_dir: Path, env: dict, *,
                             pg_budget_s: float | None = None) -> None:
    """Provision the Postgres role the api's registry storage connects as
    (tracker 245).

    Runs BEFORE the stack starts: with `postgres` as the default state backend,
    an api whose DSN does not authenticate has no registry storage at all and
    fails its boot by design (it must never fall back to files or RAM). So the
    role has to exist first, and every re-run re-aligns it with whatever
    DATABASE_URL now says — that is also the supported way to rotate it.

    No-op for the file/memory backends and for an EXTERNAL database (a DSN that
    does not point at this stack's own `postgres` service): there is no
    container here to provision, and guessing would be worse than saying so.
    """
    if app_state_backend(env) != "postgres":
        return
    dsn = (env.get("DATABASE_URL") or "").strip()
    if not dsn:
        fail("STORE_BACKEND=postgres but DATABASE_URL is empty — the api cannot "
             "start without it. Set DATABASE_URL in deployment/docker/.env "
             "(docs/DEPLOY_POSTGRES_APPSTATE.md) and re-run.")
        return
    app_user, app_pw, host, dbname = _split_app_dsn(dsn)
    if host not in ("postgres", "localhost", "127.0.0.1"):
        info(f"DATABASE_URL points at an external database ({host}) — provision "
             f"its non-superuser app role yourself (deployment/docker/postgres/"
             f"netops-app-role.sql); nothing here to do")
        return
    db_user = env.get("DB_USER", "netops")
    dbname = dbname or env.get("DB_NAME", "netops")
    if not app_user or not app_pw:
        fail("DATABASE_URL carries no user/password for the app-state role; "
             "expected postgres://<role>:<password>@postgres:5432/<db>")
        return
    # Everything below is interpolated into SQL/shell inside the container —
    # validate at the boundary instead of trusting an operator-edited .env (§3).
    for name, value in (("DB_USER", db_user), ("the DATABASE_URL role", app_user),
                        ("DB_NAME", dbname)):
        if not _PG_IDENT.match(value):
            fail(f"{name} must match [A-Za-z0-9_]+ to be provisioned safely; "
                 f"fix it in .env and re-run")
            return

    # Start ONLY the database first. The api must not race a store that does not
    # yet accept it, and a crash-looping api during a fresh install is exactly
    # the experience this step exists to prevent.
    step("provisioning the Postgres app-state role", stage="bootstrap-appstate")
    up = subprocess.run(["docker", "compose", "up", "-d", "postgres"],
                        cwd=str(compose_dir), capture_output=True, text=True,
                        timeout=300, check=False)
    if up.returncode != 0:
        detail = (up.stderr or up.stdout or "").strip().splitlines()
        fail("could not start the postgres service, so the app-state role cannot "
             "be provisioned: " + (detail[-1] if detail else "see the output above"))
        return
    # Readiness is a REAL query on the REAL server, twice, seconds apart — not
    # pg_isready, which answers for the entrypoint's temporary init server and
    # for a moment that has already passed (see wait_for_postgres).
    runner = ComposeRunner(compose_dir)
    budget = _pg_ready_budget_s() if pg_budget_s is None else pg_budget_s
    rok, rmsg = wait_for_postgres(runner, user=db_user, db=dbname,
                                  budget_s=budget)
    if not rok:
        fail(f"postgres is not usable, so the app-state role was NOT "
             f"provisioned and the api would fail to start: {rmsg}. Check "
             f"`docker compose logs postgres` and re-run install.py "
             f"(a slow disk can need a longer wait: "
             f"{PG_READY_BUDGET_ENV}=600 python3 scripts/install.py).")
        return
    info(f"postgres {rmsg}")

    sr = _rotation_module()
    done, msg = _provision_app_state_role_with_retry(
        sr, compose_dir, db_user=db_user, db_name=dbname,
        app_user=app_user, app_password=app_pw, runner=runner,
        deadline_s=budget)
    if not done:
        fail(f"the app-state role could not be provisioned: {msg}. The api needs "
             f"it to store registries (STORE_BACKEND=postgres) and will not "
             f"start without it. Fix the database and re-run install.py, or set "
             f"STORE_BACKEND=file to run without one.")
        return
    ok(f"app-state role '{app_user}' ready ({msg})")


def enable_tls_database_url(env_path: Path) -> None:
    """TLS phase B: point DATABASE_URL at the now-TLS-only postgres.

    Phase A deliberately runs the DSN plaintext (the api is the thing that mints
    the mesh CA, so the CA file does not exist yet). Once compose.tls.yml is
    active, postgres' pg_hba is `hostssl` and refuses a non-TLS connection — a
    plaintext DSN there is a crash-loop with the registry storage down. Idempotent
    line surgery; a no-op unless the app-state backend is postgres.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    lines = env_path.read_text().splitlines()
    env = _parse_env(env_path)
    if app_state_backend(env) != "postgres":
        return
    changed = False
    for i, line in enumerate(lines):
        if not line.startswith("DATABASE_URL="):
            continue
        val = line.split("=", 1)[1]
        parts = urlsplit(val)
        q = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True)
             if k not in ("sslmode", "sslrootcert")]
        q.append(("sslmode", "verify-full"))
        q.append(("sslrootcert", "/data/tls/ca.pem"))
        newval = urlunsplit((parts.scheme, parts.netloc, parts.path,
                             urlencode(q), parts.fragment))
        if newval != val:
            lines[i] = f"DATABASE_URL={newval}"
            changed = True
        break
    if changed:
        write_env_text(env_path, "\n".join(lines) + "\n",
                       what="switch DATABASE_URL to verify-full")
        ok("DATABASE_URL switched to sslmode=verify-full for the TLS mesh")
    else:
        info("DATABASE_URL already carries the TLS verify-full form")


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
        write_env_text(
            env_path,
            (env_path.read_text() if env_path.exists() else "")
            + "\n# Read-only ClickHouse user for Grafana (added on upgrade).\n"
            + f"GRAFANA_CH_PASSWORD={ch_pw}\n",
            what="add GRAFANA_CH_PASSWORD")
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


# ---- single-writer install lock (FMEA §2 #12, §4.2) --------------------------
# GUI + CLI, two wizard processes, or a cron update.sh must never run install
# steps at once: they race on .env surgery and on compose. flock releases on
# process death, so a held lock always means a live holder; the file contents
# (pid, command, start) exist only to NAME that holder in the refusal.
#
# Contract with install-correlix.sh (implemented there, not here): the shell
# holds `flock -n 9` on this same file and exports CORRELIX_INSTALL_LOCK_FD=9.
# install.py then re-flocks THAT descriptor (the same open file description,
# so it succeeds) instead of opening the file, and leaves its contents to the
# shell. A direct `python3 scripts/install.py` opens and locks the file itself.

INSTALL_LOCK_NAME = ".install.lock"
INSTALL_LOCK_FD_ENV = "CORRELIX_INSTALL_LOCK_FD"
INSTALL_LOCK_BUSY_EXIT = 3
_LOCK_INFO_MAX = 4096
_LOCK_FIELDS = ("pid", "cmd", "started_utc")

# Module state, not a hidden singleton: the lock this run holds, released by
# the __main__ block on every exit path.
_LOCK: dict = {"held": None}


class InstallLock:
    """A held install lock. `owned` = this process opened (and records itself
    in) the file; otherwise the descriptor was inherited from the shell."""

    def __init__(self, path: Path, fd: int, owned: bool) -> None:
        self.path = path
        self.fd = fd
        self.owned = owned

    def release(self) -> None:
        if self.fd < 0:
            return
        fd, self.fd = self.fd, -1
        if self.owned:
            # Empty the holder record so the next run does not report a stale
            # lock after a clean exit; closing releases the flock.
            os.ftruncate(fd, 0)
            os.close(fd)
        # Inherited: never LOCK_UN or close the shell's lock — it still holds it.


def _read_lock_holder(fd: int) -> dict[str, str]:
    """The holder record, bounded and reduced to printable text (the file is
    writable by whoever can write deployment/docker — never trust it)."""
    raw = os.pread(fd, _LOCK_INFO_MAX, 0).decode("utf-8", errors="replace")
    out: dict[str, str] = {}
    for line in raw.splitlines():
        k, sep, v = line.partition("=")
        if sep and k in _LOCK_FIELDS:
            out[k] = "".join(ch for ch in v if ch.isprintable())[:200]
    return out


def _lock_holder_text(holder: dict[str, str]) -> str:
    parts = []
    if holder.get("pid"):
        parts.append(f"pid {holder['pid']}")
    if holder.get("cmd"):
        parts.append(f"command {holder['cmd']!r}")
    if holder.get("started_utc"):
        parts.append(f"started {holder['started_utc']}")
    return ", ".join(parts)


def _refuse_lock_busy(path: Path, holder: dict[str, str]) -> None:
    who = _lock_holder_text(holder) or "a process that has not recorded itself yet"
    print(f"[fail ] another Correlix install is already running on this "
          f"installation ({who}).", file=sys.stderr)
    print("        Two installs at once race on .env and on docker compose, so this "
          "one stops here and changed nothing.", file=sys.stderr)
    print(f"        Wait for it to finish (the lock {path} is released the moment "
          "it exits), then re-run.", file=sys.stderr)
    _progress({"kind": "result", "status": "fail"})
    sys.exit(INSTALL_LOCK_BUSY_EXIT)


def _inherited_lock_fd(path: Path, environ, proc_fd_dir: Path = Path("/proc/self/fd")) -> int | None:
    """The descriptor install-correlix.sh passed in CORRELIX_INSTALL_LOCK_FD,
    when it really is an open descriptor on THIS lock file; else None (with a
    warning when the variable was set but unusable)."""
    raw = (environ.get(INSTALL_LOCK_FD_ENV) or "").strip()
    if not raw:
        return None
    if not re.fullmatch(r"[0-9]{1,5}", raw) or int(raw) < 3:
        warn(f"ignoring {INSTALL_LOCK_FD_ENV}: {raw[:16]!r} is not a usable file "
             "descriptor number; taking the install lock directly")
        return None
    fd = int(raw)
    if not (proc_fd_dir / str(fd)).exists():
        warn(f"ignoring {INSTALL_LOCK_FD_ENV}={fd}: that descriptor is not open in "
             "this process; taking the install lock directly")
        return None
    if not path.exists() or not os.path.samestat(os.fstat(fd), os.stat(path)):
        warn(f"ignoring {INSTALL_LOCK_FD_ENV}={fd}: that descriptor is not {path}; "
             "taking the install lock directly")
        return None
    return fd


def acquire_install_lock(compose_dir: Path, argv: list[str], *, environ=None,
                         pid_alive=_pid_alive) -> InstallLock:
    """Take the single-writer lock or refuse (exit 3) naming the holder."""
    environ = os.environ if environ is None else environ
    path = compose_dir / INSTALL_LOCK_NAME
    fd = _inherited_lock_fd(path, environ)
    if fd is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _refuse_lock_busy(path, _read_lock_holder(fd))
        except OSError as e:
            fail(f"could not take the install lock {path} through the inherited "
                 f"descriptor {fd}: {e.strerror or e}")
        return InstallLock(path, fd, owned=False)
    if not compose_dir.is_dir():
        fail(f"{compose_dir} does not exist — the checkout or bundle is incomplete, "
             "so there is no installation to lock")
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError as e:
        fail(f"could not open the install lock {path}: {e.strerror or e}")
        raise
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        holder = _read_lock_holder(fd)
        os.close(fd)
        _refuse_lock_busy(path, holder)
    except OSError as e:
        os.close(fd)
        fail(f"could not take the install lock {path}: {e.strerror or e}")
    previous = _read_lock_holder(fd)
    prev_pid = previous.get("pid", "")
    if prev_pid.isdigit() and int(prev_pid) != os.getpid():
        who = _lock_holder_text(previous)
        if pid_alive(int(prev_pid)):
            warn(f"took over the install lock: its record named {who}, which is "
                 "running but no longer holds the lock (a reused pid)")
        else:
            warn(f"took over a stale install lock: {who} is no longer running "
                 "(that run was killed or crashed; see data/install-timing.json "
                 "for the stage it reached)")
    cmd = " ".join([Path(argv[0]).name, *argv[1:2]]) if argv else "install.py"
    record = f"pid={os.getpid()}\ncmd={cmd}\nstarted_utc={_utc_stamp()}\n"
    try:
        os.ftruncate(fd, 0)
        os.pwrite(fd, record.encode("utf-8"), 0)
    except OSError as e:
        os.close(fd)
        fail(f"could not record this run in the install lock {path}: {e.strerror or e}")
    return InstallLock(path, fd, owned=True)


def _release_install_lock() -> None:
    held = _LOCK["held"]
    _LOCK["held"] = None
    if held is not None:
        held.release()


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
    ap.add_argument("--bootstrap-sso", action="store_true",
                    help="Create Keycloak's database against the running stack, "
                         "then exit. The `sso` add-on can be enabled long after "
                         "the install (./install-correlix.sh enable sso), and "
                         "Keycloak crash-loops on `FATAL: database \"keycloak\" "
                         "does not exist` until this has run. Idempotent.")
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

    # Every mode from here on changes this installation (.env, data/, the
    # stack), so every one holds the single-writer lock (FMEA §2 #12, §4.2).
    # The read-only paths — --help and argument errors — exited above without
    # touching anything. Released by the __main__ block on every exit path.
    _LOCK["held"] = acquire_install_lock(compose_dir, sys.argv)

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
                if Path(src).resolve() == env_path.resolve():
                    write_env_text(env_path, Path(bak).read_text(),
                                   what="restore .env from its plan backup")
                else:
                    _write_private(Path(src), Path(bak).read_text())
                restored.append(os.path.basename(src))
        ok(f"restored {', '.join(restored)} from .plan.bak backups — "
           "run 'docker compose up -d' to apply")
        return
    # Standalone Keycloak-database bootstrap. `install.py` owns first-boot
    # provisioning (bootstrap_keycloak_db), but the `sso` capability is now an
    # add-on that can be enabled at ANY time — and the enable path must not have
    # to re-run a whole install to get the one thing Keycloak cannot do for
    # itself. install-correlix.sh's `enable sso` calls this.
    if args.bootstrap_sso:
        if not env_path.exists():
            fail(".env not found — run a full install first")
        step("bootstrap Keycloak database (profile sso)", stage="bootstrap-kc")
        budgets = resolve_budgets(load_host_profile(root / HOST_PROFILE_PATH),
                                  os.environ, _parse_env(env_path))
        bootstrap_keycloak_db(compose_dir, _parse_env(env_path),
                              pg_budget_s=budgets.pg_ready_s)
        return

    if args.replan:
        if not env_path.exists():
            fail(".env not found — run a full install first")
        validate_env_complete(env_path, before_migration=True)
        run_resource_plan(env_path, args.plan_resources or "auto", args.sizing_file)
        info("replan complete — apply with: cd deployment/docker && docker compose up -d")
        return

    # Standalone rotation (#FUNC-HIGH-1): rotate what is safely rotatable and
    # leave everything else — including every operator edit in .env — alone.
    if args.rotate_app_secrets:
        step("rotating secrets in place")
        if env_path.exists():
            # Never rotate into a truncated .env (heals from the snapshot or
            # refuses naming the missing keys).
            validate_env_complete(env_path, before_migration=True)
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
                 f"the runbook step: {_acl_runbook_step(compose_dir)}")
        if failures:
            fail(f"{failures} secret(s) could not be rotated (details above)")
        return

    # The install proper starts here — arm the timing instrument (the standalone
    # replan/rotate/rollback paths above run no stages and write no timing).
    _TIMING["record"] = True
    _TIMING["report"] = args.time_report
    _TIMING["path"] = root / "data" / "install-timing.json"
    # The previous run's journal (FMEA §4.1): what finished, what was
    # interrupted. Advisory only — unusable means every stage runs.
    journal, journal_notes = load_install_journal(_TIMING["path"])
    _TIMING["journal"] = journal
    for note in journal_notes:
        info(note)

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
    started = env_path.exists() and sr.install_started(
        root, _parse_env(env_path).get("COMPOSE_PROFILES", ""))
    # A re-run starts from whatever .env the last run, an ENOSPC or an editor
    # left: heal a truncated file from its snapshot, or refuse naming the
    # missing keys, BEFORE a migration mints replacements for them (row 13 /
    # E1). --reset-env on an install that never started regenerates it anyway.
    if env_path.exists() and (started or not args.reset_env):
        validate_env_complete(env_path, before_migration=True)
    if args.reset_env and started:
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
    # After generation, migration or rotation: every key compose and the
    # stack need is present and non-empty, or heal/refuse (row 13 / E1).
    validate_env_complete(env_path)

    # --snmp-discovery: same line-surgery doctrine as --tls, so a fresh
    # template and an existing operator-edited .env converge identically.
    if args.snmp_discovery:
        enable_snmp_discovery_env(env_path, args.snmp_discovery)

    if args.plan_resources:
        step("planning resources (#102)", stage="sizing")
        run_resource_plan(env_path, args.plan_resources, args.sizing_file)

    # Every wait from here on is scaled to the host's measured speed (FMEA
    # §4.3). Resolved once, after the .env is generated and planned — the
    # stores' shutdown window and postgres' start period land in it — and
    # before anything starts or waits.
    budgets = resolve_budgets(load_host_profile(root / HOST_PROFILE_PATH),
                              os.environ, _parse_env(env_path))
    info(describe_budgets(budgets))
    write_budget_env(env_path, budgets)

    # Load the image archive BEFORE the first step that may need the chown
    # helper container. Both ensure_ingress_cert() (uid 101 ingress key) and
    # ensure_data_dirs() (per-service uids) fall back to a root helper
    # container when the installer is not root — the documented, recommended
    # way to install — and on a virgin air-gapped host NO image exists until
    # this runs, so the fallback had nothing to run and the install died at
    # the TLS stage 100% of the time (fresh-install acceptance, 2026-09-06).
    # load_bundle() depends on nothing above it but the extracted tree.
    if args.bundle:
        # Journal-driven skip (B1): the core archive was 382 s of the .123 run.
        # Skipped only when the journal records it loaded from this SAME
        # archive + MANIFEST and every image the MANIFEST lists still inspects.
        skip, why, bundle_fp = image_load_decision(
            _TIMING["journal"], "bundle", args.bundle, "base", _image_present)
        step("loading image bundle", stage="bundle", inputs={"bundle": bundle_fp or ""})
        if skip:
            info(f"skipping the image load: {why}")
        else:
            info(f"loading the image archive (not skipped: {why})")
            load_bundle(args.bundle)

    # The one transport-security question (tracker #151 delivery shape).
    # Resolved AFTER .env exists so both fresh and existing installs converge
    # through the same line-surgery path; the actual activation is two-phase
    # around compose_up below.
    tls_enabled = resolve_tls_choice(args)
    # Under TLS the ingress is 443 and the plaintext port is loopback-only
    # (compose.tls.yml), so "localhost" is not merely unhelpful to a remote
    # operator, it is the ONLY thing that would not answer them. Resolve the
    # host we can actually be reached on (tracker 265 / DEFECT-7).
    dash_host = _reachable_host()
    dash_url = (f"https://{dash_host}/" if tls_enabled
                else f"http://localhost:{args.port}")
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
        # Add-on packs ride next to the base archive and are loaded only for
        # the profiles this install actually activates. Gate on the EFFECTIVE
        # profiles from .env (what compose_up will start), not args.profiles —
        # an existing install's .env wins, exactly as the Keycloak-database
        # bootstrap below does.
        load_addon_packs(args.bundle,
                         _parse_env(env_path).get("COMPOSE_PROFILES", args.profiles))

    if args.offline:
        write_offline_override(compose_dir, env_path)

    # The api's registry storage must exist before the api does (tracker 245):
    # on the default postgres backend a missing role is a failed boot, not a
    # quiet downgrade to another store.
    bootstrap_app_state_role(compose_dir, _parse_env(env_path), pg_budget_s=budgets.pg_ready_s)

    # Keycloak cannot create its own database, and a Keycloak started without
    # it crash-loops. This used to run only AFTER the stack converged, so any
    # failed start left sign-on crash-looping on a missing database as well
    # (2026-09-15, .123). Create it before anything starts; the check after
    # the stack is up stays as an idempotent confirmation.
    if "sso" in {p.strip() for p in
                 _parse_env(env_path).get("COMPOSE_PROFILES", "").split(",")}:
        step("bootstrap Keycloak database (profile sso)", stage="bootstrap-kc")
        bootstrap_keycloak_db(compose_dir, _parse_env(env_path), start_postgres=True, pg_budget_s=budgets.pg_ready_s)

    # Phase A (TLS): the baseline stack boots with the mint variables set; the
    # api's internal CA writes every SVID to data/tls while the stores are
    # still plaintext. On a rerun with certs already minted this converges in
    # one pass (the sentinels exist, the variant is already in the chain).
    # Last gate before anything reads .env to start containers: the surgery
    # above (TLS, offline override) must not have left it incomplete.
    validate_env_complete(env_path)
    step("starting stack" + (" (TLS phase A: mint identities)" if tls_enabled else ""),
         stage="up-a", inputs=stage_inputs(env_path))
    # Start in groups on a slow host or an over-committed plan (FMEA §4.5);
    # phase B reuses the same choice.
    tiered, why = choose_bring_up_mode(budgets.host_class,
                                       planner_overcommit(compose_dir / "resource-plan.json"),
                                       os.environ.get("CORRELIX_BRINGUP_MODE", ""))
    info(why)
    compose_up(compose_dir, offline=args.offline, root=root, budget_s=budgets.converge_s, tiered=tiered)

    if tls_enabled:
        wait_for_minted_certs(root, timeout_s=budgets.mint_s)
        activate_tls_compose_file(compose_dir, env_path)
        enable_tls_database_url(env_path)
        # Never skipped on the journal's word (§4.1 rule 3): the recreate runs
        # and compose_up verifies convergence every time.
        step("starting stack (TLS phase B: fail-closed mesh)", stage="up-b",
             inputs=stage_inputs(env_path))
        stop_stores_cleanly(compose_dir, grace_s=budgets.store_stop_grace_s)
        compose_up(compose_dir, offline=args.offline, root=root, budget_s=budgets.converge_s, tiered=tiered)

    # SEC-007 P0 (2026-08-16): with default-deny enforced, an empty KRaft ACL
    # store (fresh install, data/kafka wipe) is a silently auth-dead ingest
    # tier — apply + verify the matrix before claiming success. No-op on the
    # plaintext baseline (no authorizer) and external brokers (owner-managed).
    apply_bus_authorization(compose_dir, env_path, tls_enabled,
                            acl_timeout_s=budgets.acl_apply_s,
                            consumers_timeout_s=budgets.bus_consumers_s)

    step("status", stage="status")
    compose_status(compose_dir)

    step("bootstrap OpenSearch index templates", stage="bootstrap-os")
    bootstrap_opensearch(root, tls=tls_enabled)

    # Gate on the EFFECTIVE profiles from .env — the source of truth compose_up
    # starts from — not args.profiles, which an existing install's .env ignores.
    active = {p.strip() for p in
              _parse_env(env_path).get("COMPOSE_PROFILES", "").split(",")}
    if "sso" in active:
        # Confirmation pass: normally "already exists" (created before the first
        # start); creates it when that early attempt could not reach postgres.
        # FATAL after a bounded retry (T2 residual): with sso active, a missing
        # database is a crash-looping Keycloak, not a successful install.
        step("bootstrap Keycloak database (profile sso)", stage="bootstrap-kc")
        confirm_keycloak_db(compose_dir, _parse_env(env_path), pg_budget_s=budgets.pg_ready_s)

    if "self-monitoring" in args.profiles:
        step("wiring grafana clickhouse datasource", stage="bootstrap-grafana")
        bootstrap_grafana(root, secrets_map)

    print()
    print("==============================================================")
    if tls_enabled:
        # compose.tls.yml publishes the TLS ingress on 443 and binds the
        # plaintext port to 127.0.0.1, so :8000 is reachable only from the
        # appliance itself (the host-local qualifier/watchdog probes). Say both
        # halves plainly: the URL that works from elsewhere, and the fact that
        # the http one deliberately does not (tracker 265 / DEFECT-7).
        print(f"  Dashboard: https://{dash_host}/   (TLS ingress, port 443)")
        print(f"  API:       https://{dash_host}/api/")
        print(f"  Health:    https://{dash_host}/admin/health")
        print(f"             (http://localhost:{args.port} answers on this host "
              "only — it is bound to loopback so nothing off-box can reach the "
              "dashboard or the login API unencrypted)")
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
        fail("interrupted", interrupted=True)
    finally:
        _release_install_lock()
