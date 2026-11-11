#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""
mounted_config.py — which running services are still on an OLD mounted config.

Why this exists
---------------
`docker compose up -d` recreates a container only when its IMAGE or its compose
DEFINITION changed. A service whose only change is the CONTENT of a bind-mounted
config file or directory keeps running with what it read at start:
vector-aggregator stayed 7 h on the old VRL after a deploy, syslog-ng kept its old
conf, and vmalert only picks up changed alert rules after a manual restart. A
customer running update.sh would silently keep old parsing and alert rules — a
scripts/CLAUDE.md §16.1 silent failure. A FILE bind mount is worse than stale: a
release that replaces the file (new inode) leaves the running container pinned to
the OLD inode, so even `docker compose restart` does not fix it — only a recreate.

This module is the decision half; scripts/lib/mounted-config.sh is the shell half
that deploy.sh and update.sh source. It never talks to docker itself: the shell
feeds it `docker compose config --format json` and `docker compose ps --format
json`, so every docker call stays bounded and visible in one place.

Which mounts count as "config" (the selection rule)
---------------------------------------------------
A mount is fingerprinted only when ALL of these hold:

  1. it is a BIND mount marked read-only. A writable bind is state the service
     writes (data/postgres, data/kafka, …); read-only is what it consumes.
  2. its real source path (symlinks resolved) lives inside the install's
     `deployment/` or `src/config/` tree. Those are exactly the trees a release
     replaces (git pull / rsync / the bundle). Everything else is excluded on
     purpose: host paths (`/`, `/sys`, docker.sock — not ours), and all of `data/`,
     which is generated or written at runtime (enrichment tables and processors
     the api rewrites live and the consumers hot-reload, TLS material, rendered
     credential files) — restarting on those would bounce services on every run.
  3. no path component is a key-material directory (`certs`, `tls`, `secrets`,
     `secrets-seal`, `swtpm`). Key material rotates through its own reload path
     (SVID renewal, rotate-tls-services.sh), and a deploy script must never read
     private keys — they are deliberately not readable by everyone.

Directories are hashed recursively in a fixed order: every entry contributes its
path relative to the install root, its type, and its content (files) or link text
(symlinks are recorded, never followed). Paths are root-relative so the same tree
fingerprints identically wherever the install lives. A missing source is recorded
as missing rather than skipped, so its later appearance is a change.

Subcommands
-----------
  fingerprint --root R          stdin: compose config JSON -> stdout {service: sha256}
  snapshot                      stdin: compose ps JSON     -> stdout {service: "id,id"}
  plan --state S --fingerprints F --before B --after A [--named a,b]
                                prints one line per decision (see plan_lines())
  save --state S --fingerprints F --before B --after A
                                records fingerprints atomically (0600)

Exit codes: 0 ok; 2 bad input or an unreadable config source (stderr says which).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Protocol

STATE_VERSION = 1
CONFIG_TREES = ("deployment", "src/config")
KEY_MATERIAL_DIRS = frozenset({"certs", "tls", "secrets", "secrets-seal", "swtpm"})
_CHUNK = 1 << 16


class _Hasher(Protocol):
    """What the hashing helpers need from a hashlib object."""

    def update(self, data: bytes, /) -> None: ...


class InputError(Exception):
    """A malformed input or an unreadable config source. Always fatal (exit 2)."""


# ── selection ────────────────────────────────────────────────────────────────


def config_mount_base(mount: dict, root: Path) -> tuple[Path, str] | None:
    """Apply the selection rule in the module docstring to one compose mount.

    Returns (real tree base, tree name) for a config mount, else None. Paths are
    later labelled relative to that base, so a `deployment/` that is itself a
    symlink elsewhere still fingerprints the same."""
    if mount.get("type") != "bind" or mount.get("read_only") is not True:
        return None
    source = mount.get("source")
    if not isinstance(source, str) or not source:
        return None
    real = Path(os.path.realpath(source))
    for tree in CONFIG_TREES:
        base = Path(os.path.realpath(root / tree))
        if real == base or base in real.parents:
            rel = real.relative_to(base)
            if any(part in KEY_MATERIAL_DIRS for part in rel.parts):
                return None
            return base, tree
    return None


# ── hashing ──────────────────────────────────────────────────────────────────


def _hash_file(path: Path, h: _Hasher) -> None:
    try:
        with path.open("rb") as fh:
            while True:
                block = fh.read(_CHUNK)
                if not block:
                    return
                h.update(block)
    except OSError as exc:
        raise InputError(f"cannot read mounted config file {path}: {exc.strerror or exc}") from exc


def _entry(h: _Hasher, kind: str, rel: str) -> None:
    h.update(f"\0{kind}\0{rel}\0".encode())


def hash_source(source: Path, base: Path, tree: str, h: _Hasher) -> None:
    """Feed one mount source (file, dir or missing) into `h`, deterministically.
    Every path is labelled `<tree>/<path relative to the tree>`."""
    real = Path(os.path.realpath(source))

    def label(p: Path) -> str:
        rel = p.relative_to(base).as_posix()
        return tree if rel == "." else f"{tree}/{rel}"

    rel = label(real)
    try:
        st = os.stat(real)
    except FileNotFoundError:
        _entry(h, "missing", rel)
        return
    except OSError as exc:
        raise InputError(f"cannot stat mounted config source {real}: {exc.strerror or exc}") from exc
    if stat.S_ISREG(st.st_mode):
        _entry(h, "file", rel)
        _hash_file(real, h)
        return
    if not stat.S_ISDIR(st.st_mode):
        _entry(h, "special", rel)
        return
    _entry(h, "dir", rel)

    def walk_error(exc: OSError) -> None:
        raise InputError(f"cannot list mounted config directory {exc.filename}: {exc.strerror or exc}")

    for dirpath, dirnames, filenames in os.walk(real, onerror=walk_error, followlinks=False):
        dirnames.sort()
        here = Path(dirpath)
        names = sorted(set(filenames) | {d for d in dirnames if (here / d).is_symlink()})
        for d in dirnames:
            if not (here / d).is_symlink():
                _entry(h, "dir", label(here / d))
        for name in names:
            p = here / name
            prel = label(p)
            try:
                lst = os.lstat(p)
            except OSError as exc:
                raise InputError(f"cannot stat {p}: {exc.strerror or exc}") from exc
            if stat.S_ISLNK(lst.st_mode):
                try:
                    target = os.readlink(p)
                except OSError as exc:
                    raise InputError(f"cannot read link {p}: {exc.strerror or exc}") from exc
                _entry(h, "link", prel)
                h.update(target.encode())
            elif stat.S_ISREG(lst.st_mode):
                _entry(h, "file", prel)
                _hash_file(p, h)
            else:  # socket / fifo / device: presence only, never opened
                _entry(h, "special", prel)


def fingerprints(config: dict, root: Path) -> dict[str, str]:
    """{service: sha256} over each service's config mounts. A service with no
    config mount is absent (there is nothing of it to track)."""
    services = config.get("services")
    if not isinstance(services, dict):
        raise InputError("compose config has no 'services' mapping")
    out: dict[str, str] = {}
    for name in sorted(services):
        spec = services[name] or {}
        if not isinstance(spec, dict):
            raise InputError(f"compose config: service {name!r} is not an object")
        mounts = []
        for m in spec.get("volumes") or []:
            sel = config_mount_base(m, root) if isinstance(m, dict) else None
            if sel is not None:
                mounts.append((str(m.get("target", "")), m["source"], sel))
        if not mounts:
            continue
        h = hashlib.sha256()
        for target, source, (base, tree) in sorted(mounts, key=lambda t: (t[0], t[1])):
            h.update(f"\0mount\0{target}\0".encode())
            hash_source(Path(source), base, tree, h)
        out[name] = h.hexdigest()
    return out


# ── container snapshots ──────────────────────────────────────────────────────


def parse_ps(text: str) -> dict[str, str]:
    """`docker compose ps --format json` -> {service: sorted container ids}.

    Compose emits a JSON array (older v2) or one object per line (v2.21+); both
    are accepted. Only RUNNING containers count: an exited one-shot or a stopped
    service reads its config afresh on its next start."""
    text = text.strip()
    if not text:
        return {}
    rows: list = []
    try:
        doc = json.loads(text)
        rows = doc if isinstance(doc, list) else [doc]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise InputError(f"unparseable `docker compose ps` line: {line[:120]!r}") from exc
    ids: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise InputError("`docker compose ps` row is not an object")
        svc, cid, state = row.get("Service"), row.get("ID"), str(row.get("State", "")).lower()
        if not svc or not cid:
            raise InputError(f"`docker compose ps` row lacks Service/ID: {sorted(row)}")
        if state == "running":
            ids.setdefault(svc, []).append(cid)
    return {s: ",".join(sorted(v)) for s, v in ids.items()}


def recreated(before: dict[str, str], after: dict[str, str]) -> set[str]:
    """Services whose running container is new since `before` (created or replaced)."""
    return {s for s, cid in after.items() if before.get(s) != cid}


# ── state ────────────────────────────────────────────────────────────────────


def load_state(path: Path) -> tuple[dict[str, str] | None, str]:
    """(fingerprints, problem). (None, "") = no state file yet (first run);
    (None, reason) = present but malformed. An unreadable file is fatal."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        # Unreadable is not "absent": the write at the end of this run would fail
        # the same way, so refuse now rather than after the stack was touched.
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON ({exc.msg})"
    svcs = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("version") != STATE_VERSION or not isinstance(svcs, dict) \
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in svcs.items()):
        return None, f"{path} does not have the expected version-{STATE_VERSION} shape"
    return dict(svcs), ""


def write_state(path: Path, services: dict[str, str]) -> None:
    """Atomic: temp file in the same dir, fsync, 0600, rename, fsync the dir."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    doc = {
        "version": STATE_VERSION,
        "updated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "services": dict(sorted(services.items())),
    }
    fd, tmp = tempfile.mkstemp(prefix=".config-fingerprints.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(doc, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass  # the rename already consumed it, or it was never created
        raise
    # Run as root (sudo update.sh), the record would become root-owned 0600 and
    # the next unprivileged deploy.sh could not read it — which is fatal there.
    # Hand it to whoever owns the data dir it lives in, as install.py does.
    if os.geteuid() == 0:
        owner = os.stat(path.parent.parent)
        for p in (path.parent, path):
            os.chown(p, owner.st_uid, owner.st_gid)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ── decisions ────────────────────────────────────────────────────────────────


def plan_lines(state: dict[str, str] | None, state_problem: str, fps: dict[str, str],
               before: dict[str, str], after: dict[str, str], named: list[str] | None) -> list[str]:
    """One line per decision, `<verb> <service>`; the shell acts on `restart`.

      first-run               no state file: nothing is restarted, a baseline is recorded
      state-unreadable <why>  state present but unusable: EVERY tracked running service
                              is treated as changed (fresh config is guaranteed; loud)
      restart <svc>           mounted config changed, running, not recreated this run,
                              in scope -> the shell force-recreates it
      stale <svc>             same, but OUT of scope (deploy.sh named-service mode
                              without --reload-changed-config) -> the shell warns
      recreated <svc>         mounted config changed and this run already recreated it
      not-running <svc>       mounted config changed but no running container
                              (its next start reads the new config)
      baseline <svc>          running, no fingerprint on record: recorded, not restarted
    """
    if state is None and not state_problem:
        return ["first-run"]
    lines: list[str] = []
    if state_problem:
        lines.append(f"state-unreadable {state_problem}")
    fresh = recreated(before, after)
    scope = None if named is None else set(named)
    for svc in sorted(fps):
        if state is not None and svc not in state:
            if svc in after:
                lines.append(f"baseline {svc}")
            continue
        if state is not None and state[svc] == fps[svc]:
            continue
        if svc not in after:
            lines.append(f"not-running {svc}")
        elif svc in fresh:
            lines.append(f"recreated {svc}")
        elif scope is None or svc in scope:
            lines.append(f"restart {svc}")
        else:
            lines.append(f"stale {svc}")
    return lines


def merged_state(state: dict[str, str] | None, fps: dict[str, str],
                 before: dict[str, str], after: dict[str, str]) -> dict[str, str]:
    """What to record after a SUCCESSFUL run. A fingerprint is advanced only for a
    running service whose container is known to hold it: recreated this run,
    unchanged, or seen for the first time. A changed service that was NOT restarted
    (out of scope) keeps its old fingerprint, so the next run still flags it.
    Entries for services not running now are kept untouched."""
    out = dict(state or {})
    fresh = recreated(before, after)
    for svc, fp in fps.items():
        if svc not in after:
            continue
        if svc in fresh or svc not in out or out[svc] == fp:
            out[svc] = fp
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────


def _read_json_file(path: str) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON ({exc.msg})") from exc
    if not isinstance(doc, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in doc.items()):
        raise InputError(f"{path} is not a {{service: string}} object")
    return doc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fingerprint")
    f.add_argument("--root", required=True)
    sub.add_parser("snapshot")
    for name in ("plan", "save"):
        p = sub.add_parser(name)
        for opt in ("--state", "--fingerprints", "--before", "--after"):
            p.add_argument(opt, required=True)
        if name == "plan":
            p.add_argument("--named", default=None,
                           help="comma-separated in-scope services; omit for all")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "fingerprint":
            try:
                config = json.loads(sys.stdin.read())
            except json.JSONDecodeError as exc:
                raise InputError(f"compose config is not valid JSON ({exc.msg})") from exc
            if not isinstance(config, dict):
                raise InputError("compose config is not a JSON object")
            json.dump(fingerprints(config, Path(args.root)), sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        if args.cmd == "snapshot":
            json.dump(parse_ps(sys.stdin.read()), sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        fps = _read_json_file(args.fingerprints)
        before = _read_json_file(args.before)
        after = _read_json_file(args.after)
        state, problem = load_state(Path(args.state))
        if args.cmd == "plan":
            named = None if args.named is None else [s for s in args.named.split(",") if s]
            for line in plan_lines(state, problem, fps, before, after, named):
                print(line)
            return 0
        new = merged_state(state, fps, before, after)
        try:
            write_state(Path(args.state), new)
        except OSError as exc:
            raise InputError(f"cannot write {args.state}: {exc.strerror or exc}") from exc
        print(f"recorded mounted-config fingerprints for {len(new)} service(s) in {args.state}")
        return 0
    except InputError as exc:
        print(f"mounted_config: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
