#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Installer log-signature classifier — one table, many callers.

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md §4.4. Every installer
component that looks at a container's log and asks "what is wrong, and what
may be done about it" asks HERE, so compose_up, wait_healthy, `doctor`, the
wizard's failure panel and deploy-qualify.sh can never disagree.

This module only CLASSIFIES. A verdict carries:

  class   one of CLASSES (`unknown` when no signature matches — never a guess)
  action  a word from a closed vocabulary a caller MAY carry out:
            wait                 bounded wait; the service is healing itself
            bootstrap:<name>     run one named, idempotent bootstrap
            recreate:<service>   recreate one service (once per run)
            fail                 stop and show the remedy
          `none` is returned only with `unknown`. Nothing here executes.
  remedy  plain-language next step for the operator
  evidence the matching log line, REDACTED (install.py's _SECRETISH regex)

Precedence when several lines match: the most severe class wins (a full disk
explains a crash recovery, not the other way round); among equally severe
matches the most recent line wins.

CLI (stdin is the log text; only its last MAX_STDIN_BYTES are kept):

    python3 scripts/install_signatures.py classify <service> [--json] [--lines N]
    cd scripts && python3 -m install_signatures classify postgres < pg.log

Standard library only (CLAUDE.md §6).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

# ── vocabulary ───────────────────────────────────────────────────────────────

CLASSES: tuple[str, ...] = (
    "recovering", "starting", "fatal-config", "port-conflict", "disk-full",
    "image-missing", "auth-denied", "db-missing", "flood-stage", "oom-killed",
    "lsm-denied", "daemon-down", "unknown",
)

# Higher = more severe. `unknown` never competes: it is the no-match result.
_RANK: dict[str, int] = {
    "daemon-down": 100, "disk-full": 90, "oom-killed": 85, "flood-stage": 80,
    "port-conflict": 75, "image-missing": 70, "lsm-denied": 65,
    "fatal-config": 60, "db-missing": 55, "auth-denied": 50,
    "recovering": 20, "starting": 10,
}

# The bootstraps a verdict may name. Each maps to an existing idempotent
# installer step (keycloak DB creation, Kafka ACL apply, OpenSearch templates).
BOOTSTRAPS: frozenset[str] = frozenset({"keycloak-db", "kafka-acls", "opensearch-templates"})

_ACTION_RE = re.compile(
    r"(?:wait|fail|bootstrap:(?P<boot>[a-z][a-z0-9-]{0,40})|recreate:[a-z0-9][a-z0-9_-]{0,62})")

# Verbatim install.py `_SECRETISH` (pinned by tests/test_install_signatures.py).
SECRETISH = re.compile(r"passw|secret|token|apikey|api_key|credential|bearer",
                       re.IGNORECASE)
WITHHELD = "[line withheld: may contain a credential]"

MAX_LINE_CHARS = 4096          # a line is truncated to this before matching
MAX_STDIN_BYTES = 4 << 20      # CLI keeps only the tail of its input
DEFAULT_LINES = 200
MAX_LINES = 5000

_SERVICE_ARG = re.compile(r"[A-Za-z0-9/][A-Za-z0-9_./-]{0,127}")
_PG = re.compile(r"(?:netbox-)?postgres")
_ANY = re.compile(r".*")


@dataclass(frozen=True)
class Signature:
    sig_id: str
    service: re.Pattern      # fullmatch against the normalised service name
    log: re.Pattern          # searched in each (truncated) line
    klass: str
    remedy: str              # may contain {key}: filled from a named group `key`
    action: str


@dataclass(frozen=True)
class Verdict:
    service: str
    klass: str
    sig_id: str
    action: str
    remedy: str
    evidence: str

    def to_dict(self) -> dict:
        return {"service": self.service, "class": self.klass, "signature": self.sig_id,
                "action": self.action, "remedy": self.remedy, "evidence": self.evidence}


# ── the table ────────────────────────────────────────────────────────────────
# Order matters only when ONE line matches two rows: the first row wins for
# that line. Every row has a recorded real log-line fixture in the tests.

SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "daemon-down", _ANY,
        re.compile(r"Cannot connect to the Docker daemon|error during connect: .*docker",
                   re.IGNORECASE),
        "daemon-down",
        "The Docker daemon is not answering (it may be restarting, for example during a "
        "package upgrade). Wait until `docker info` answers; if it has not within two "
        "minutes, start it with: sudo systemctl start docker",
        "wait"),
    Signature(
        "no-space", _ANY,
        re.compile(r"no space left on device|\bENOSPC\b", re.IGNORECASE),
        "disk-full",
        "The disk is full. See what uses it with `df -h` and `docker system df`, free space "
        "under the install directory and Docker's data root, then re-run the installer. "
        "Do not delete data/ directories or shrink Kafka retention to make room.",
        "fail"),
    Signature(
        "jvm-oom", _ANY,
        re.compile(r"java\.lang\.OutOfMemoryError"),
        "oom-killed",
        "The service ran out of memory. Give the host more RAM, or lower the stack's size "
        "(re-run the installer, which sizes services to this host) and restart it.",
        "fail"),
    Signature(
        "runtime-oom", _ANY,
        re.compile(r"fatal error: runtime: out of memory|Out of memory: Killed process"),
        "oom-killed",
        "The kernel or the runtime killed a process for lack of memory. Give the host more "
        "RAM or reduce the stack's size, then restart the service.",
        "fail"),
    Signature(
        "opensearch-flood-stage", _ANY,
        re.compile(r"flood[- ]stage (?:disk )?watermark|read[-_ ]only[-_ ]allow[-_ ]delete|"
                   r"ClusterBlockException.*read[-_ ]only", re.IGNORECASE),
        "flood-stage",
        "OpenSearch made its indices read-only because the disk passed the 95 % flood-stage "
        "watermark. Free space on the filesystem holding data/ (never delete data/opensearch "
        "by hand); OpenSearch lifts the block itself once usage is back under 90 %.",
        "fail"),
    Signature(
        "port-allocated", _ANY,
        re.compile(r"port is already allocated|address already in use", re.IGNORECASE),
        "port-conflict",
        "A host port Correlix needs is already used by another program. Find it with "
        "`sudo ss -lntup`, stop it (or move the Correlix port), then re-run the installer.",
        "fail"),
    Signature(
        "image-missing", _ANY,
        re.compile(r"No such image|pull access denied|manifest unknown|"
                   r"Unable to find image .* locally|"
                   r"image with reference .* was found but does not match", re.IGNORECASE),
        "image-missing",
        "An image is missing on this host, so the image bundle did not finish loading. "
        "Re-run the installer; it loads the bundle again.",
        "fail"),
    Signature(
        "lsm-denial", _ANY,
        re.compile(r"apparmor=\"DENIED\"|avc:\s+denied|SELinux is preventing"),
        "lsm-denied",
        "The host's security module (AppArmor or SELinux) refused the container access to "
        "a file. Check `sudo aa-status` or `sudo ausearch -m avc` for the denied path; "
        "Correlix supports Ubuntu/Debian with the default docker-default profile.",
        "fail"),
    Signature(
        "compose-required-variable", _ANY,
        re.compile(r"required variable (?P<key>[A-Z][A-Z0-9_]{0,63}) is missing a value"),
        "fatal-config",
        "The setting {key} is missing or empty in deployment/docker/.env. Run "
        "`./install-correlix.sh doctor` to list every missing setting, then re-run the "
        "installer, which generates missing values.",
        "fail"),
    Signature(
        "osd-empty-setting", re.compile(r"opensearch-dashboards"),
        re.compile(r"--opensearch\.[A-Za-z.]+ must have a value"),
        "fatal-config",
        "OpenSearch Dashboards was started with an empty or malformed connection setting "
        "(a generated secret that begins with '-' is read as a flag). Re-run the installer "
        "to regenerate it; `./install-correlix.sh doctor` names empty settings.",
        "fail"),
    Signature(
        "keycloak-db-missing", re.compile(r"keycloak"),
        re.compile(r"database \"keycloak\" does not exist"),
        "db-missing",
        "Keycloak started before its database was created. The installer's Keycloak "
        "database step creates it; Keycloak then needs one restart.",
        "bootstrap:keycloak-db"),
    Signature(
        "kafka-authorization", _ANY,
        re.compile(r"TopicAuthorizationFailedError|TopicAuthorizationException|"
                   r"GroupAuthorizationFailedError|GroupAuthorizationException|"
                   r"Not authorized to access (?:topics|group)"),
        "auth-denied",
        "The event bus refused this service access to a topic or consumer group: its Kafka "
        "ACLs are missing. The installer's ACL step re-applies them; the service then "
        "reconnects.",
        "bootstrap:kafka-acls"),
    Signature(
        "kafka-authentication", _ANY,
        re.compile(r"SaslAuthentication(?:Exception|FailedError)|"
                   r"Authentication failed during authentication"),
        "auth-denied",
        "The event bus rejected this service's credentials. The password in .env and the "
        "one stored in Kafka disagree; re-run the installer (it re-applies credentials) and "
        "do not edit .env by hand.",
        "fail"),
    Signature(
        "pg-crash-recovery", _PG,
        re.compile(r"syncing data directory|automatic recovery in progress|redo starts at|"
                   r"database system was interrupted|end-of-recovery"),
        "recovering",
        "PostgreSQL is recovering from an unclean stop. This is normal after an interrupted "
        "shutdown and takes minutes on a slow disk. Wait; do not restart it.",
        "wait"),
    Signature(
        "pg-starting", _PG,
        re.compile(r"the database system is (?:starting up|not yet accepting connections)"),
        "starting",
        "PostgreSQL is still starting up. Wait.",
        "wait"),
    Signature(
        "osd-waiting-for-opensearch", re.compile(r"opensearch-dashboards"),
        re.compile(r"Unable to retrieve version information from OpenSearch nodes"),
        "starting",
        "OpenSearch Dashboards is waiting for OpenSearch to come up. Wait; if OpenSearch "
        "itself is not starting, look at its log first.",
        "wait"),
)

_UNKNOWN_REMEDY = ("This log is not recognised by the signature table, so no automatic "
                   "action is suggested. Read the service's own recent log lines.")


# ── validation ───────────────────────────────────────────────────────────────

def is_valid_action(action: str) -> bool:
    """True only for the closed action vocabulary (never `none`)."""
    m = _ACTION_RE.fullmatch(action)
    if m is None:
        return False
    boot = m.group("boot")
    return boot is None or boot in BOOTSTRAPS


def validate_table(table: tuple[Signature, ...]) -> None:
    """Refuse a table with an unknown class, an action outside the vocabulary,
    an empty remedy, or a duplicate id. Raises ValueError."""
    seen: set[str] = set()
    for s in table:
        if s.sig_id in seen:
            raise ValueError(f"duplicate signature id {s.sig_id!r}")
        seen.add(s.sig_id)
        if s.klass not in _RANK:
            raise ValueError(f"signature {s.sig_id!r}: class {s.klass!r} is not a known class")
        if not is_valid_action(s.action):
            raise ValueError(f"signature {s.sig_id!r}: action {s.action!r} is not whitelisted")
        if not s.remedy.strip():
            raise ValueError(f"signature {s.sig_id!r}: empty remedy")


validate_table(SIGNATURES)


# ── classification ───────────────────────────────────────────────────────────

def normalize_service(name: str) -> str:
    """`/netops-opensearch-dashboards-1` -> `opensearch-dashboards`."""
    n = name.strip().lstrip("/")
    n = re.sub(r"^netops-", "", n)
    return re.sub(r"-\d+$", "", n)


def redact_line(line: str) -> str:
    return WITHHELD if SECRETISH.search(line) else line


def redacted_tail(text: str, n: int = 15) -> list[str]:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    return [redact_line(ln) for ln in lines[-n:]] if n > 0 else []


def classify(service: str, text: str, max_lines: int = DEFAULT_LINES) -> Verdict:
    """Classify the last `max_lines` lines of one service's log."""
    svc = normalize_service(service)
    rows = [s for s in SIGNATURES if s.service.fullmatch(svc)]
    best: tuple[int, Signature, re.Match, str] | None = None
    for raw in text.splitlines()[-max_lines:] if max_lines > 0 else []:
        line = raw[:MAX_LINE_CHARS]
        for sig in rows:
            m = sig.log.search(line)
            if m is None:
                continue
            rank = _RANK[sig.klass]
            if best is None or rank >= best[0]:
                best = (rank, sig, m, line)
            break
    if best is None:
        return Verdict(svc, "unknown", "", "none", _UNKNOWN_REMEDY, "")
    _, sig, m, line = best
    remedy = sig.remedy
    if "key" in sig.log.groupindex:
        remedy = remedy.format(key=m.group("key"))
    return Verdict(svc, sig.klass, sig.sig_id, sig.action, remedy, redact_line(line.strip()))


# ── CLI ──────────────────────────────────────────────────────────────────────

def _read_stdin_tail(limit: int = MAX_STDIN_BYTES) -> str:
    buf = bytearray()
    stream = sys.stdin.buffer
    while True:
        chunk = stream.read(1 << 16)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 2 * limit:
            del buf[:-limit]
    return bytes(buf[-limit:]).decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="install_signatures",
                                 description="Classify a container log (read from stdin).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify", help="classify stdin as the log of SERVICE")
    c.add_argument("service")
    c.add_argument("--json", action="store_true")
    c.add_argument("--lines", type=int, default=DEFAULT_LINES)
    args = ap.parse_args(argv)
    if not _SERVICE_ARG.fullmatch(args.service):
        ap.error(f"invalid service name {args.service!r}")
    if not 1 <= args.lines <= MAX_LINES:
        ap.error(f"--lines must be 1..{MAX_LINES}")
    v = classify(args.service, _read_stdin_tail(), args.lines)
    if args.json:
        print(json.dumps(v.to_dict(), separators=(",", ":")))
    else:
        print(f"class: {v.klass}")
        print(f"action: {v.action}")
        print(f"signature: {v.sig_id or '-'}")
        print(f"remedy: {v.remedy}")
        print(f"evidence: {v.evidence or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
