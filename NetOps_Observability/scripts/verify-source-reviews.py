#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""verify-source-reviews.py — mechanically verify scripts/source-review.json
before a signature lands on it (tracker 238(a)).

WHY THIS EXISTS
---------------
`scripts/source-review.json` holds one written licence determination per
(component, version, package type) that an image scan could not resolve on its
own. Every entry starts `owner_signoff: false`, and
`oci-compliance.py --release` refuses to pass while a review it relied on is
unsigned — so the signature IS the gate, and an automated first pass must never
be able to clear a customer release by asserting its own correctness.

The owner's 2026-09-13 decision approved the technical sign-off SUBJECT TO a
mechanical verification of seven conditions per entry. A signature is worth
exactly what the evidence under it is worth, and "a first pass wrote a
convincing paragraph" is not evidence. This is that verification.

It is a SCRIPT, not a one-off, because the table is rewritten on every
base-image bump (docs/compliance/OCI_SOURCE_COMPLIANCE.md §13): the next bump
must be able to re-run the same seven checks instead of re-arguing them.

THE SEVEN CONDITIONS (all must hold before `--sign` flips one boolean)
  1  THE EVIDENCE EXISTS. The file the IMAGE ITSELF carries, or the APKBUILD at
     the exact aports commit the image's apk database records, is actually
     fetched and read — and for an APKBUILD, the commit the entry cites must be
     the commit that database records.
  2  THE SHA256 IS PRESENT AND VALID. 64 hex characters, recomputed over the
     bytes that were just fetched.
  3  THE CONCLUSION IS EXPLICIT. `governing_licences` non-empty and
     `source_required` is true, false or "unclear".
  4  THE RATIONALE EXPLAINS THE SHIPPED ARTIFACT, not the upstream source tree
     in general. Satisfied either by naming what the package ships (its file
     list, the `Files: *` catch-all stanza, the image it is read out of), or —
     when the package's own licence record contains NO copyleft term at all —
     by stating that, because then nothing in the record can bind the binary
     more strictly than it binds the tree. Which path was taken is REPORTED.
  5  NO PLACEHOLDERS. No TODO / TBD / FIXME / UNKNOWN / placeholder / N/A
     anywhere in the entry.
  6  THE ENTRY DESCRIBES THE SHIPPED VERSION. The version string must match
     what the image's own package database records (apk `V:`, dpkg `Version:`,
     CPython's `patchlevel.h`), and must not contradict the committed OCI
     inventory.
  7  NO CONTRADICTION BETWEEN EVIDENCE AND CONCLUSION. The licences the
     package's own metadata records must support the licences the review claims
     govern the shipped binary; a copyleft term may be narrowed away only when
     the rationale NAMES that term and rests on the package's file list; and a
     copyleft conclusion may never come back as `source_required: false`.

WHAT IT WILL NEVER DO
  It never edits a conclusion, a rationale, a licence or an evidence record to
  make a condition pass. A failing entry stays unsigned and is REPORTED, one
  line per failure, with the condition number and the concrete reason. It never
  REMOVES a signature either: only the owner does that.

USAGE
  python3 scripts/verify-source-reviews.py --check      # report only
  python3 scripts/verify-source-reviews.py --sign       # verify, then sign passes
  python3 scripts/verify-source-reviews.py --check --cache-dir /var/tmp/correlix-ev
  python3 scripts/verify-source-reviews.py --selftest   # offline, no docker/network

EXIT CODES
  0  every eligible review passed (and, with --sign, is signed)
  1  at least one eligible review FAILED a condition
  2  CANNOT RUN — the table is unreadable, docker or the network is
     unavailable, or the file cannot be rewritten without reformatting it.
     Never reported as "no failures": an unverifiable review is not a passing
     one (CLAUDE.md §16.1).

EVIDENCE SOURCES
  aports   gitlab.alpinelinux.org raw (git.alpinelinux.org cgit as fallback),
           fetched over the SYSTEM CA bundle — this host's egress is
           TLS-intercepted, so a bundled certifi trust store fails where the
           system store succeeds. Bounded timeout, retries with backoff+jitter.
  images   read-only, `docker create` + `docker cp`. No container is STARTED,
           nothing is built, pulled, pruned or removed except the throw-away
           container this script created and removes itself.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
REVIEW_TABLE = os.path.join(ROOT, "scripts", "source-review.json")
OCI_TOOL = os.path.join(ROOT, "scripts", "oci-compliance.py")
INVENTORY = os.path.join(ROOT, "docs", "compliance", "oci-inventory.json")

# The system trust store. The lab's egress is re-signed by a TLS-intercepting
# proxy; a certifi failure here is the interception, not the site.
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

APORTS_URLS = (
    "https://gitlab.alpinelinux.org/alpine/aports/-/raw/{commit}/{repo}/{pkg}/APKBUILD",
    "https://git.alpinelinux.org/aports/plain/{repo}/{pkg}/APKBUILD?id={commit}",
)
# No custom User-Agent: gitlab.alpinelinux.org's bot filter answers HTTP 418 to
# one (and cgit answers 403), while urllib's own default identifier is accepted.
# An audit tool that cannot fetch its evidence is useless, and a UA that lies
# about being a browser would be worse than the default that names the language.

APKBUILD_PATH = re.compile(
    r"^aports\s+(?P<repo>[A-Za-z0-9_.-]+)/(?P<pkg>[A-Za-z0-9_.+-]+)/APKBUILD"
    r"\s*@\s*(?P<commit>[0-9a-f]{40})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# §5: anything that says "this entry is not finished". `unclear` is a VALID
# verdict value and is deliberately absent from this list.
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:\b(?:to-?do|tbd|tbc|fixme|unknown|placeholder|n/a|xxx+)\b|\?\?\?|<[a-z_]{3,}>)")

# §4: phrases that tie a rationale to the artifact the image DISTRIBUTES.
SHIPPED_MARKERS = (
    "shipped", "ships", "ship ", "installs", "installed", "install", "file list",
    "binary package", "the image", "this image", "image's", "image itself",
    "distribut", "carries", "zero files", "no files", "subpackage",
    "files: *", "files:*", "whole copyright file", "in-image",
)
# §4 fallback path: the rationale argues from the ABSENCE of copyleft.
NO_COPYLEFT_MARKERS = (
    "no copyleft", "not copyleft", "neither is copyleft", "notice only",
    "notice-only", "permissive", "public domain", "public-domain",
    "no source obligation", "no source requirement", "no reciprocal",
    "not a work at all",
)
# §7: a rationale that narrows a copyleft term away must rest on what the
# package SHIPS, not on an assertion.
FILE_LIST_MARKERS = (
    "file list", "installs r:", "ships only", "installs only", "zero files",
    "no files", "shipped binary", "this subpackage does not ship",
)
MIN_RATIONALE_CHARS = 60

# §7 for free-text evidence (a Debian copyright file, an in-image licence
# text): a licence claim is only verifiable against prose when we know what
# that licence's prose LOOKS like. An id with no pattern here FAILS CLOSED —
# add the pattern instead of assuming the claim.
FREE_TEXT_MARKERS: dict[str, tuple[str, ...]] = {
    "gpl-2.0-or-later": (r"GNU\s+General\s+Public\s+License", r"version\s+2",
                         r"later\s+version"),
    "gpl-2.0-only": (r"GNU\s+General\s+Public\s+License", r"version\s+2"),
    "gpl-3.0-or-later": (r"GNU\s+General\s+Public\s+License", r"version\s+3",
                         r"later\s+version"),
    "gpl-3.0-only": (r"GNU\s+General\s+Public\s+License", r"version\s+3"),
    "lgpl-2.1-or-later": (r"GNU\s+(?:Lesser|Library)\s+General\s+Public\s+License",
                          r"version\s+2\.1", r"later\s+version"),
    "psf-2.0": (r"PYTHON\s+SOFTWARE\s+FOUNDATION\s+LICENSE\s+VERSION\s+2",),
    "python-2.0": (r"PYTHON\s+SOFTWARE\s+FOUNDATION\s+LICENSE\s+VERSION\s+2",),
    "public-domain": (r"public[-\s]domain",),
    "mit": (r"Permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge",),
    "apache-2.0": (r"Apache\s+License",),
    "isc": (r"Permission\s+to\s+use,\s+copy,\s+modify",),
    "bsd-2-clause": (r"Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms",),
    "bsd-3-clause": (r"Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms",),
    "0bsd": (r"Permission\s+to\s+use,\s+copy,\s+modify",),
}

KIND_APKBUILD = "alpine-apkbuild"
KIND_APK_RECORD_QUOTED = "apk-installed-db-record"
KIND_APK_RECORD_FILE = "alpine-apk-db-record"
KIND_DPKG_COPYRIGHT = "dpkg-copyright"
KIND_IN_IMAGE_LICENCE = "in-image-licence-file"
KIND_NO_EVIDENCE = "no-licence-evidence-in-image"
KNOWN_KINDS = (KIND_APKBUILD, KIND_APK_RECORD_QUOTED, KIND_APK_RECORD_FILE,
               KIND_DPKG_COPYRIGHT, KIND_IN_IMAGE_LICENCE, KIND_NO_EVIDENCE)

APK_DB_PATH = "/lib/apk/db/installed"


# ── errors ───────────────────────────────────────────────────────────────────
class VerifyError(Exception):
    """CANNOT RUN (exit 2). Never a silent pass."""


class Unavailable(VerifyError):
    """The evidence could not be REACHED (no docker, no network, a wedged
    daemon). Distinct from MissingEvidence on purpose: "I could not look" must
    never be reported as "it is not there"."""


class MissingEvidence(Exception):
    """The artifact is genuinely absent (HTTP 404, no such path in the image).
    That is a condition-1 failure for one review, not a reason to stop."""


# ── the compliance tool's own tables, reused rather than restated ────────────
def load_oci(path: str | None = None) -> Any:
    """scripts/oci-compliance.py as a module: one source of truth for which
    licence ids carry a corresponding-source obligation."""
    p = path or OCI_TOOL
    spec = importlib.util.spec_from_file_location("_oci_compliance_for_verify", p)
    if spec is None or spec.loader is None:
        raise VerifyError(f"cannot load the compliance tool: {p}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        raise VerifyError(f"cannot load the compliance tool ({p}): {exc}") from exc
    return mod


# ── licence-token algebra ────────────────────────────────────────────────────
def canon(token: str, oci: Any) -> str:
    """One licence token → a comparable key. Never guesses into a permissive id
    (that is `normalize_license_id`'s contract); only spelling is normalised."""
    tok = (token or "").strip().strip("()").strip()
    if not tok:
        return ""
    tok = oci.normalize_license_id(tok) or tok
    return re.sub(r"[\s_]+", "-", tok.strip()).lower()


def split_expression(expr: str) -> list[str]:
    """An apk/SPDX licence field → its member tokens.

    Splits only on the AND/OR operators, so free text Alpine actually ships
    ("2-clause BSD-like license", "Public Domain") survives as ONE token
    instead of being shredded into words the way a scanner does.
    """
    text = (expr or "").strip()
    if not text:
        return []
    text = text.replace("(", " ").replace(")", " ")
    parts = re.split(r"\s+(?:AND|OR|and|or)\s+", text)
    return [p.strip() for p in parts if p.strip()]


def copyleft_keys(oci: Any) -> set[str]:
    return {canon(t, oci) for t in set(oci.SOURCE_REQUIRED) | set(oci.FAMILY_UNSPECIFIED)}


def known_keys(oci: Any) -> set[str]:
    return {canon(t, oci) for t in set(oci.SOURCE_REQUIRED) | set(oci.NO_SOURCE_OBLIGATION)}


# ── evidence parsers ─────────────────────────────────────────────────────────
def parse_apk_db(text: str) -> dict[str, dict[str, Any]]:
    """An apk `installed` database → {package: {"raw", "fields", "files"}}.

    `fields` keeps every occurrence of a key (apk repeats F:/R:), so a caller
    can read a package's own file list and not just its metadata.
    """
    out: dict[str, dict[str, Any]] = {}
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        fields: dict[str, list[str]] = {}
        for line in block.split("\n"):
            if len(line) < 2 or line[1] != ":":
                continue
            fields.setdefault(line[0], []).append(line[2:])
        names = fields.get("P") or []
        if not names:
            continue
        out[names[0]] = {
            "raw": block,
            "fields": fields,
            "files": list(fields.get("R") or []),
        }
    return out


def parse_apkbuild(text: str) -> dict[str, Any]:
    """An APKBUILD → the fields a licence review rests on.

    `licenses` collects EVERY `license=` assignment, because apk sets a
    subpackage's licence inside that subpackage's function (musl-utils is
    "MIT AND BSD-2-Clause AND GPL-2.0-or-later" while musl itself is "MIT").
    """
    def one(name: str) -> str:
        m = re.search(rf"^\s*{name}=\"?([^\"\n]*)\"?\s*$", text, re.MULTILINE)
        return m.group(1).strip() if m else ""

    licences = [m.group(1).strip()
                for m in re.finditer(r"^\s*license=\"?([^\"\n]*)\"?\s*$", text, re.MULTILINE)]
    return {
        "pkgname": one("pkgname"),
        "pkgver": one("pkgver"),
        "pkgrel": one("pkgrel"),
        "licenses": licences,
    }


def parse_dpkg_stanzas(text: str) -> list[dict[str, str]]:
    """A dpkg status / status.d stanza file → a list of field maps."""
    out: list[dict[str, str]] = []
    for block in re.split(r"\n\s*\n", text):
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        key = ""
        for line in block.split("\n"):
            if line[:1] in (" ", "\t") and key:
                fields[key] += "\n" + line.strip()
                continue
            m = re.match(r"^([A-Za-z0-9-]+):\s*(.*)$", line)
            if m:
                key = m.group(1)
                fields[key] = m.group(2).strip()
        if fields:
            out.append(fields)
    return out


def parse_dpkg_copyright(text: str) -> dict[str, Any]:
    """A Debian copyright file → what it says about the WHOLE package.

    `files_star` is the licence of the catch-all `Files: *` stanza, which is
    the only stanza that speaks for every shipped file. `licences` is every
    `License:` value in the file — the unordered list a scanner cannot resolve.
    """
    machine_readable = bool(re.search(r"^Format:\s*https?://", text, re.MULTILINE))
    files_star = ""
    stanzas = re.split(r"\n\s*\n", text)
    for block in stanzas:
        if re.search(r"^Files:\s*\*\s*$", block, re.MULTILINE):
            m = re.search(r"^License:\s*(.+)$", block, re.MULTILINE)
            if m:
                files_star = m.group(1).strip()
            break
    licences = [m.group(1).strip()
                for m in re.finditer(r"^License:\s*(\S.*)$", text, re.MULTILINE)]
    return {"machine_readable": machine_readable, "files_star": files_star,
            "licences": licences}


# ── where evidence bytes come from ───────────────────────────────────────────
class Fetcher:
    """The evidence transport, injected so the tests need neither docker nor a
    network (§3 zero trust: the verifier is testable without its environment)."""

    def aports_apkbuild(self, repo: str, pkg: str, commit: str) -> bytes:
        raise NotImplementedError

    def image_file(self, image: str, path: str) -> bytes:
        raise NotImplementedError

    def image_id(self, image: str) -> str:
        raise NotImplementedError

    def close(self) -> None:
        return None


class MappingFetcher(Fetcher):
    """A dict-backed fetcher: {(repo, pkg, commit): bytes} and
    {(image, path): bytes}. Anything absent raises MissingEvidence, which is
    exactly what a 404 or a missing path means."""

    def __init__(self, aports: dict[tuple[str, str, str], bytes] | None = None,
                 files: dict[tuple[str, str], bytes] | None = None,
                 image_ids: dict[str, str] | None = None) -> None:
        self.aports = dict(aports or {})
        self.files = dict(files or {})
        self.image_ids = dict(image_ids or {})
        self.calls: list[tuple[str, ...]] = []

    def aports_apkbuild(self, repo: str, pkg: str, commit: str) -> bytes:
        self.calls.append(("aports", repo, pkg, commit))
        try:
            return self.aports[(repo, pkg, commit)]
        except KeyError as exc:
            raise MissingEvidence(
                f"aports {repo}/{pkg}/APKBUILD @ {commit}: not in the fixture") from exc

    def image_file(self, image: str, path: str) -> bytes:
        self.calls.append(("image", image, path))
        try:
            return self.files[(image, path)]
        except KeyError as exc:
            raise MissingEvidence(f"{image}: no such path {path}") from exc

    def image_id(self, image: str) -> str:
        return self.image_ids.get(image, "")


class LiveFetcher(Fetcher):
    """The real thing: aports over HTTPS, image files through `docker cp`.

    Every call is bounded (§9) and retried with backoff+jitter. A container is
    CREATED and never started, then removed by close(); no image is built,
    pulled, pruned or removed.
    """

    def __init__(self, *, timeout: float = 45.0, attempts: int = 3,
                 cache_dir: str | None = None, image_tag: str = "latest",
                 docker: str = "docker", backoff: float = 1.5,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.timeout = timeout
        self.attempts = max(1, attempts)
        self.cache_dir = cache_dir
        self.image_tag = image_tag
        self.docker = docker
        self.backoff = backoff
        self._sleep = sleep
        self._containers: dict[str, str] = {}
        self._image_ids: dict[str, str] = {}
        self._jitter = random.Random(0xC0FFEE)  # reproducible spread, not a secret
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    # -- cache (content is sha-checked by the caller, so caching is safe) ----
    def _cache_path(self, key: str) -> str | None:
        if not self.cache_dir:
            return None
        return os.path.join(self.cache_dir,
                            hashlib.sha256(key.encode()).hexdigest() + ".bin")

    def _cache_get(self, key: str) -> bytes | None:
        p = self._cache_path(key)
        if not p or not os.path.isfile(p):
            return None
        with open(p, "rb") as fh:
            return fh.read()

    def _cache_put(self, key: str, data: bytes) -> None:
        p = self._cache_path(key)
        if not p:
            return
        tmp = p + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, p)

    # -- aports -------------------------------------------------------------
    def _http_get(self, url: str) -> bytes:
        ctx = ssl.create_default_context(
            cafile=CA_BUNDLE if os.path.isfile(CA_BUNDLE) else None)
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status != 200:
                    raise Unavailable(f"{url}: HTTP {resp.status}")
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                raise MissingEvidence(f"{url}: HTTP {exc.code}") from exc
            raise Unavailable(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            raise Unavailable(f"{url}: {exc}") from exc

    def aports_apkbuild(self, repo: str, pkg: str, commit: str) -> bytes:
        key = f"aports/{commit}/{repo}/{pkg}/APKBUILD"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        problems: list[str] = []
        for template in APORTS_URLS:
            url = template.format(repo=repo, pkg=pkg, commit=commit)
            for attempt in range(1, self.attempts + 1):
                try:
                    data = self._http_get(url)
                except MissingEvidence:
                    raise
                except Unavailable as exc:
                    problems.append(f"attempt {attempt}: {exc}")
                    if attempt < self.attempts:
                        delay = self.backoff * (2 ** (attempt - 1))
                        self._sleep(delay * (0.5 + self._jitter.random()))
                    continue
                self._cache_put(key, data)
                return data
        raise Unavailable(f"aports {repo}/{pkg}/APKBUILD @ {commit} unreachable: "
                          + "; ".join(problems))

    # -- images -------------------------------------------------------------
    def _ref(self, image: str) -> str:
        return image if (":" in image or "@" in image) else f"{image}:{self.image_tag}"

    def _docker(self, args: list[str], *, what: str) -> bytes:
        if not shutil.which(self.docker):
            raise Unavailable(f"{self.docker} is not on PATH; cannot read image "
                              f"evidence ({what})")
        try:
            proc = subprocess.run([self.docker, *args], capture_output=True,
                                  timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Unavailable(f"{self.docker} {args[0]} timed out after "
                              f"{self.timeout}s ({what})") from exc
        except OSError as exc:
            raise Unavailable(f"cannot run {self.docker} ({what}): {exc}") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            if re.search(r"(?i)could not find the file|no such file or directory",
                         err):
                raise MissingEvidence(f"{what}: {err}")
            raise Unavailable(f"{self.docker} {args[0]} failed ({what}): {err}")
        return proc.stdout

    def image_id(self, image: str) -> str:
        if image in self._image_ids:
            return self._image_ids[image]
        out = self._docker(["image", "inspect", "--format", "{{.Id}}", self._ref(image)],
                           what=f"image id of {self._ref(image)}")
        ident = out.decode("utf-8", "replace").strip()
        self._image_ids[image] = ident
        return ident

    def _container(self, image: str) -> str:
        if image in self._containers:
            return self._containers[image]
        ref = self._ref(image)
        try:
            out = self._docker(["create", ref], what=f"container for {ref}")
        except Unavailable as exc:
            if "no command specified" not in str(exc).lower():
                raise
            # An image with neither ENTRYPOINT nor CMD: the command is never
            # run (the container is never started), it only has to be named.
            out = self._docker(["create", "--entrypoint", "/bin/true", ref],
                               what=f"container for {ref}")
        cid = out.decode("utf-8", "replace").strip()
        if not cid:
            raise Unavailable(f"docker create {ref} produced no container id")
        self._containers[image] = cid
        return cid

    def image_file(self, image: str, path: str) -> bytes:
        key = f"image/{self.image_id(image)}/{path}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        cid = self._container(image)
        blob = self._docker(["cp", f"{cid}:{path}", "-"],
                            what=f"{self._ref(image)}:{path}")
        try:
            with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
                members = [m for m in tf.getmembers() if m.isreg()]
                if len(members) != 1:
                    raise Unavailable(
                        f"{self._ref(image)}:{path}: expected one regular file in the "
                        f"docker cp stream, got {len(members)}")
                handle = tf.extractfile(members[0])
                if handle is None:
                    raise Unavailable(f"{self._ref(image)}:{path}: unreadable member")
                data = handle.read()
        except tarfile.TarError as exc:
            raise Unavailable(f"{self._ref(image)}:{path}: "
                              f"docker cp stream is not a tar ({exc})") from exc
        self._cache_put(key, data)
        return data

    def close(self) -> None:
        problems: list[str] = []
        for image, cid in list(self._containers.items()):
            try:
                self._docker(["rm", "-f", cid], what=f"cleanup of {image} container")
            except (Unavailable, MissingEvidence) as exc:
                problems.append(str(exc))
            self._containers.pop(image, None)
        if problems:
            # Loud, never swallowed (§16.1): a leaked container is the operator's
            # to clean up and they have to be told which.
            print("verify-source-reviews: WARNING: could not remove a throw-away "
                  "container: " + "; ".join(problems), file=sys.stderr)


# ── results ──────────────────────────────────────────────────────────────────
PASS = "PASS"
FAIL = "FAIL"
NEEDS_HUMAN = "NEEDS-HUMAN"


class Finding:
    __slots__ = ("condition", "reason")

    def __init__(self, condition: int, reason: str) -> None:
        self.condition = condition
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Finding(C{self.condition}, {self.reason!r})"


class Result:
    def __init__(self, review: dict) -> None:
        self.component: str = str(review.get("component", "?"))
        self.version: str = str(review.get("version", "?"))
        self.package_type: str = str(review.get("package_type", "?"))
        self.signed: bool = bool(review.get("owner_signoff"))
        self.eligible: bool = not (bool(review.get("needs_human"))
                                   or review.get("source_required") == "unclear")
        self.findings: list[Finding] = []
        self.notes: list[str] = []

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.component, self.version, self.package_type)

    @property
    def passed(self) -> bool:
        return not self.findings

    @property
    def disposition(self) -> str:
        if not self.eligible:
            return NEEDS_HUMAN
        return PASS if self.passed else FAIL

    def fail(self, condition: int, reason: str) -> None:
        self.findings.append(Finding(condition, reason))

    def note(self, text: str) -> None:
        self.notes.append(text)

    def conditions_failed(self) -> list[int]:
        return sorted({f.condition for f in self.findings})


# ── the verifier ─────────────────────────────────────────────────────────────
class Verifier:
    def __init__(self, fetcher: Fetcher, oci: Any, *,
                 inventory: dict | None = None) -> None:
        self.fetcher = fetcher
        self.oci = oci
        self.inventory = inventory or {}
        self._copyleft = copyleft_keys(oci)
        self._known = known_keys(oci)
        self._apk_db: dict[str, dict[str, dict[str, Any]]] = {}
        self._inv_index: dict[tuple[str, str], set[str]] = {}
        for comp in (self.inventory.get("components") or []):
            key = (str(comp.get("name", "")), str(comp.get("package_type", "")))
            self._inv_index.setdefault(key, set()).add(str(comp.get("version", "")))

    # -- helpers ------------------------------------------------------------
    def apk_db(self, image: str) -> dict[str, dict[str, Any]]:
        """The image's own apk database, read once per image."""
        if image not in self._apk_db:
            raw = self.fetcher.image_file(image, APK_DB_PATH)
            self._apk_db[image] = parse_apk_db(raw.decode("utf-8", "replace"))
        return self._apk_db[image]

    def is_copyleft(self, token: str) -> bool:
        return canon(token, self.oci) in self._copyleft

    def is_resolved_id(self, token: str) -> bool:
        return canon(token, self.oci) in self._known

    # -- the seven conditions ----------------------------------------------
    def verify(self, review: dict) -> Result:
        res = Result(review)
        ev = review.get("evidence")
        if not isinstance(ev, dict):
            res.fail(1, "the entry carries no `evidence` object")
            ev = {}
        kind = str(ev.get("kind") or "")
        if kind and kind not in KNOWN_KINDS:
            res.fail(1, f"evidence kind {kind!r} is not one this verifier knows how "
                        f"to re-check (known: {', '.join(KNOWN_KINDS)})")

        self.check_conclusion_is_explicit(review, res)       # 3
        self.check_no_placeholders(review, res)              # 5

        evidence = self.acquire(review, ev, kind, res)       # 1 + 2
        self.check_rationale(review, evidence, res)          # 4
        # An artifact that is simply absent is one review's condition failure,
        # never a reason to abandon the run (a transport fault still is, and
        # LiveFetcher raises Unavailable for that).
        try:
            self.check_shipped_version(review, ev, kind, res)  # 6
        except MissingEvidence as exc:
            res.fail(6, f"the image's package database could not be read: {exc}")
        try:
            self.check_no_contradiction(review, evidence, res)  # 7
        except MissingEvidence as exc:
            res.fail(7, f"the evidence could not be re-read: {exc}")
        return res

    # condition 1 + 2 ------------------------------------------------------
    def acquire(self, review: dict, ev: dict, kind: str, res: Result) -> dict:
        """Fetch the evidence and re-hash it. Returns the facts the later
        conditions read out of it ({} when nothing could be fetched)."""
        path = str(ev.get("path") or "")
        sha = str(ev.get("sha256") or "")
        image = str(ev.get("image") or "")
        facts: dict[str, Any] = {"kind": kind, "image": image}
        if not path:
            res.fail(1, "no evidence path: a determination with no evidence is an "
                        "assertion, not a review")
            return facts

        if kind == KIND_NO_EVIDENCE:
            res.fail(1, f"evidence kind {KIND_NO_EVIDENCE!r}: the entry itself states "
                        f"the image carries no licence text at {path} — there are no "
                        f"bytes to re-check, so this determination cannot be verified "
                        f"mechanically")
            self.check_sha_present(sha, res)
            return facts

        data: bytes | None = None
        try:
            if kind == KIND_APKBUILD:
                data = self.acquire_apkbuild(review, ev, path, res, facts)
            elif kind == KIND_APK_RECORD_QUOTED:
                data = self.acquire_quoted_record(review, ev, path, res, facts)
            elif kind == KIND_APK_RECORD_FILE:
                data = self.acquire_apk_db_file(review, ev, path, res, facts)
            elif kind in (KIND_DPKG_COPYRIGHT, KIND_IN_IMAGE_LICENCE):
                data = self.acquire_image_file(image, path, res, facts)
            else:
                res.fail(1, f"no way to fetch evidence of kind {kind!r}")
        except MissingEvidence as exc:
            res.fail(1, f"evidence not found: {exc}")
            data = None

        if data is None:
            self.check_sha_present(sha, res)
            return facts

        facts["bytes"] = data
        facts["text"] = data.decode("utf-8", "replace")
        if self.check_sha_present(sha, res):
            got = hashlib.sha256(data).hexdigest()
            if got != sha:
                res.fail(2, f"sha256 does not match the evidence: recorded {sha}, "
                            f"recomputed {got} over {len(data)} bytes fetched from "
                            f"{path}")
        return facts

    def check_sha_present(self, sha: str, res: Result) -> bool:
        if not sha:
            res.fail(2, "no sha256 on the evidence: the determination cannot be "
                        "re-checked against the same bytes")
            return False
        if not SHA256_RE.match(sha):
            res.fail(2, f"sha256 {sha!r} is not 64 lowercase hex characters")
            return False
        return True

    def acquire_apkbuild(self, review: dict, ev: dict, path: str, res: Result,
                         facts: dict) -> bytes | None:
        m = APKBUILD_PATH.match(path)
        if not m:
            res.fail(1, f"evidence path {path!r} does not parse as "
                        f"'aports <repo>/<pkg>/APKBUILD @ <40-hex commit>'")
            return None
        repo, pkg, commit = m.group("repo"), m.group("pkg"), m.group("commit")
        facts.update({"repo": repo, "pkg": pkg, "commit": commit})
        # The condition is the APKBUILD at the commit THE IMAGE RECORDS, so the
        # image's own database decides whether this is the right evidence.
        record = self.apk_record(review, facts, res)
        if record is not None:
            recorded = (record["fields"].get("c") or [""])[0]
            if not recorded:
                res.note(f"the image's apk database records no aports commit for "
                         f"{review.get('component')} (an out-of-tree package); the "
                         f"cited commit cannot be corroborated from the image")
            elif recorded != commit:
                res.fail(1, f"evidence cites aports commit {commit}, but the image's "
                            f"apk database records commit {recorded} for this package")
        data = self.fetcher.aports_apkbuild(repo, pkg, commit)
        facts["apkbuild"] = parse_apkbuild(data.decode("utf-8", "replace"))
        return data

    def acquire_quoted_record(self, review: dict, ev: dict, path: str, res: Result,
                              facts: dict) -> bytes | None:
        record = str(ev.get("record") or "")
        if not record:
            res.fail(1, f"evidence kind {KIND_APK_RECORD_QUOTED!r} quotes no `record`, "
                        f"so its sha256 covers nothing")
            return None
        # A quoted record is only evidence if the image really carries it.
        db_record = self.apk_record(review, facts, res)
        if db_record is not None:
            missing = [line for line in record.split("\n")
                       if line and not re.search(rf"^{re.escape(line)}$",
                                                 db_record["raw"], re.MULTILINE)]
            if missing:
                res.fail(1, f"the quoted apk record does not appear in {path} of "
                            f"image {facts.get('image')}: "
                            f"{len(missing)} line(s) absent, first {missing[0]!r}")
        return record.encode("utf-8")

    def acquire_apk_db_file(self, review: dict, ev: dict, path: str, res: Result,
                            facts: dict) -> bytes | None:
        # "/lib/apk/db/installed (the P:<name> record)" — the sha covers the
        # database FILE; the parenthesis names the record inside it.
        real = path.split(" (")[0].strip()
        image = str(ev.get("image") or "")
        data = self.acquire_image_file(image, real, res, facts)
        if data is None:
            return None
        db = parse_apk_db(data.decode("utf-8", "replace"))
        name = str(review.get("component") or "")
        if name not in db:
            res.fail(1, f"{real} of image {image} carries no P:{name} record")
        else:
            facts["record"] = db[name]
        return data

    def acquire_image_file(self, image: str, path: str, res: Result,
                           facts: dict) -> bytes | None:
        if not image:
            res.fail(1, f"evidence at {path} names no image to read it from")
            return None
        data = self.fetcher.image_file(image, path)
        if not data:
            res.fail(1, f"{image}:{path} is empty")
            return None
        return data

    def apk_record(self, review: dict, facts: dict, res: Result) -> dict | None:
        """The image's own apk database record for this component."""
        if "record" in facts:
            return facts["record"]
        image = str(facts.get("image") or "")
        if not image:
            return None
        name = str(review.get("component") or "")
        db = self.apk_db(image)
        record = db.get(name)
        if record is None:
            res.fail(6, f"image {image} carries no apk database record for {name!r}, "
                        f"so the shipped version cannot be confirmed")
            return None
        facts["record"] = record
        return record

    # condition 3 ----------------------------------------------------------
    def check_conclusion_is_explicit(self, review: dict, res: Result) -> None:
        gov = review.get("governing_licences")
        if not isinstance(gov, list) or not gov or not all(
                isinstance(g, str) and g.strip() for g in gov):
            res.fail(3, "`governing_licences` is empty: the entry states no licence "
                        "for the shipped artifact")
        req = review.get("source_required")
        if req not in (True, False, "unclear"):
            res.fail(3, f"`source_required` is {req!r}; expected true, false or "
                        f"\"unclear\"")

    # condition 4 ----------------------------------------------------------
    def check_rationale(self, review: dict, facts: dict, res: Result) -> None:
        rationale = str(review.get("rationale") or "").strip()
        if not rationale:
            res.fail(4, "no rationale")
            return
        if len(rationale) < MIN_RATIONALE_CHARS:
            res.fail(4, f"the rationale is {len(rationale)} characters — too short to "
                        f"explain a determination (minimum {MIN_RATIONALE_CHARS})")
            return
        low = rationale.lower()
        if any(m in low for m in SHIPPED_MARKERS):
            return
        # Fallback: with no copyleft term anywhere in the package's own licence
        # record there is nothing the binary can carry that the record does not,
        # so a statement about the record IS a statement about the artifact.
        tokens = self.evidence_tokens(facts)
        if tokens and not any(self.is_copyleft(t) for t in tokens) and any(
                m in low for m in NO_COPYLEFT_MARKERS):
            res.note("C4 satisfied by exclusion: the rationale never names the "
                     "shipped artifact, but the package's own licence record "
                     f"({' AND '.join(tokens)}) contains no copyleft term and the "
                     "rationale says so")
            return
        res.fail(4, "the rationale argues about the source package's licence field "
                    "and never about the SHIPPED artifact (no reference to what the "
                    "package installs, to its file list, to the `Files: *` catch-all "
                    "stanza, or to the image it is read out of)")

    # condition 5 ----------------------------------------------------------
    def check_no_placeholders(self, review: dict, res: Result) -> None:
        blob = json.dumps(review, ensure_ascii=False, sort_keys=True)
        hits = sorted({m.group(0) for m in PLACEHOLDER_RE.finditer(blob)})
        if hits:
            res.fail(5, f"placeholder text in the entry: {', '.join(repr(h) for h in hits)}")

    # condition 6 ----------------------------------------------------------
    def check_shipped_version(self, review: dict, ev: dict, kind: str,
                              res: Result) -> None:
        version = str(review.get("version") or "")
        name = str(review.get("component") or "")
        ptype = str(review.get("package_type") or "")
        image = str(ev.get("image") or "")
        shipped = ""
        source = ""
        if kind in (KIND_APKBUILD, KIND_APK_RECORD_QUOTED, KIND_APK_RECORD_FILE):
            db = self.apk_db(image) if image else {}
            record = db.get(name)
            if record is not None:
                shipped = (record["fields"].get("V") or [""])[0]
                source = f"{image}:{APK_DB_PATH} V:"
        elif ptype == "deb":
            shipped, source = self.dpkg_version(image, name)
        elif kind == KIND_IN_IMAGE_LICENCE and name.lower() in ("python", "cpython"):
            shipped, source = self.cpython_version(image, str(ev.get("path") or ""))

        if shipped:
            if shipped != version:
                res.fail(6, f"the entry is written for {version}, but {source} records "
                            f"{shipped} as the shipped version")
        else:
            res.fail(6, f"could not read the shipped version of {name} out of image "
                        f"{image or '(unnamed)'}: nothing to compare {version!r} "
                        f"against, so the entry cannot be shown to describe the "
                        f"bytes we distribute")

        inv = self._inv_index.get((name, ptype))
        if inv is None:
            res.note(f"the committed OCI inventory records no {ptype} component "
                     f"named {name!r} (it cannot corroborate the version)")
        elif version not in inv:
            res.fail(6, f"the committed OCI inventory records {name} "
                        f"{', '.join(sorted(inv))} for package type {ptype}, not "
                        f"{version}")

    def dpkg_version(self, image: str, name: str) -> tuple[str, str]:
        """A Debian package's version out of the image's own dpkg database.

        distroless images carry /var/lib/dpkg/status.d/<pkg> instead of one
        status file, so both shapes are tried; neither found is "unknown", which
        the caller turns into a condition-6 failure.
        """
        if not image:
            return ("", "")
        for path in (f"/var/lib/dpkg/status.d/{name}", "/var/lib/dpkg/status"):
            try:
                raw = self.fetcher.image_file(image, path)
            except MissingEvidence:
                continue
            for stanza in parse_dpkg_stanzas(raw.decode("utf-8", "replace")):
                if stanza.get("Package") == name and stanza.get("Version"):
                    return (stanza["Version"], f"{image}:{path} Version:")
        return ("", "")

    def cpython_version(self, image: str, licence_path: str) -> tuple[str, str]:
        """CPython records its own version in patchlevel.h; the interpreter is
        not an apk/dpkg package in the python:*-alpine images, so the header
        beside the licence text is the image's own statement of the version."""
        m = re.match(r"^(?P<prefix>.*)/lib/(?P<pyver>python3\.\d+)/LICENSE\.txt$",
                     licence_path)
        if not m:
            return ("", "")
        path = f"{m.group('prefix')}/include/{m.group('pyver')}/patchlevel.h"
        try:
            raw = self.fetcher.image_file(image, path)
        except MissingEvidence:
            return ("", "")
        text = raw.decode("utf-8", "replace")
        got = re.search(r'^#define\s+PY_VERSION\s+"([^"]+)"', text, re.MULTILINE)
        return ((got.group(1), f"{image}:{path} PY_VERSION") if got else ("", ""))

    # condition 7 ----------------------------------------------------------
    def evidence_tokens(self, facts: dict) -> list[str]:
        """The licence tokens the PACKAGE'S OWN metadata records.

        The apk database's `L:` field is per-package (per subpackage, in fact),
        which is why it — not the origin APKBUILD's top-level `license=` — is
        the authority on what governs the shipped binary.
        """
        record = facts.get("record")
        if isinstance(record, dict):
            expr = (record["fields"].get("L") or [""])[0]
            if expr.strip():
                return split_expression(expr)
        apkbuild = facts.get("apkbuild")
        if isinstance(apkbuild, dict) and apkbuild.get("licenses"):
            return split_expression(apkbuild["licenses"][0])
        return []

    def check_no_contradiction(self, review: dict, facts: dict, res: Result) -> None:
        gov = [g for g in (review.get("governing_licences") or []) if isinstance(g, str)]
        req = review.get("source_required")
        rationale = str(review.get("rationale") or "")
        low = rationale.lower()

        # (a) a copyleft conclusion can never come back as "no obligation"
        gov_copyleft = [g for g in gov if self.is_copyleft(g)]
        if gov_copyleft and req is False:
            res.fail(7, f"the review names copyleft licence(s) "
                        f"{', '.join(gov_copyleft)} as governing the shipped binary "
                        f"and still concludes source_required=false")

        if "text" not in facts:
            return  # the evidence never arrived; condition 1/2 already said so

        tokens = self.evidence_tokens(facts)
        if tokens:
            self.compare_tokens(gov, tokens, req, rationale, low, facts, res)
        else:
            self.compare_free_text(gov, req, str(facts.get("text") or ""), res)

        # (b) an APKBUILD that does not carry the claimed licence at all
        apkbuild = facts.get("apkbuild")
        if isinstance(apkbuild, dict) and apkbuild.get("licenses"):
            everything = {canon(t, self.oci)
                          for expr in apkbuild["licenses"]
                          for t in split_expression(expr)}
            unknown = [g for g in gov if canon(g, self.oci) not in everything]
            if unknown and tokens:
                # The apk database is authoritative for the binary; a licence it
                # records but the APKBUILD does not is a note, not a failure.
                res.note(f"the APKBUILD at the cited commit does not spell "
                         f"{', '.join(unknown)}; the image's apk database does "
                         f"(a per-subpackage licence override)")

    def compare_tokens(self, gov: list[str], tokens: list[str], req: Any,
                       rationale: str, low: str, facts: dict, res: Result) -> None:
        gov_keys = {canon(g, self.oci) for g in gov}
        tok_keys = {canon(t, self.oci) for t in tokens}
        recorded = " AND ".join(tokens)

        # Licences the review claims but the record does not spell. Allowed ONLY
        # where the record's own token is unresolvable free text or a placeholder
        # ("custom", "2-clause BSD-like license") that the review is READING —
        # and then the review must quote the thing it read.
        extra = [g for g in gov if canon(g, self.oci) not in tok_keys]
        if extra:
            opaque = [t for t in tokens if not self.is_resolved_id(t)]
            unquoted = [t for t in opaque if t.lower() not in low]
            if not opaque:
                res.fail(7, f"the review names {', '.join(extra)} as governing, but "
                            f"the package's own licence record is {recorded!r} and "
                            f"every term in it is an SPDX id the scan can already "
                            f"resolve — there is nothing for the review to interpret")
            elif unquoted:
                res.fail(7, f"the review reads {', '.join(extra)} out of the record's "
                            f"unresolvable term(s) {', '.join(repr(t) for t in unquoted)} "
                            f"without quoting them in the rationale, so the reading "
                            f"cannot be checked")
            else:
                res.note(f"the review resolves the record's free-text term(s) "
                         f"{', '.join(repr(t) for t in opaque)} to "
                         f"{', '.join(extra)} (quoted in the rationale)")

        # Licences the record spells but the review drops. Copyleft may only be
        # dropped against the package's FILE LIST, with the term named.
        dropped_copyleft = [t for t in tokens
                            if self.is_copyleft(t) and canon(t, self.oci) not in gov_keys]
        if dropped_copyleft:
            unnamed = [t for t in dropped_copyleft if t.lower() not in low]
            if unnamed:
                res.fail(7, f"the package's own licence record is {recorded!r}; the "
                            f"review narrows it to {', '.join(gov) or '(nothing)'} "
                            f"without ever naming the copyleft term(s) "
                            f"{', '.join(unnamed)} it drops")
            elif not any(m in low for m in FILE_LIST_MARKERS):
                res.fail(7, f"the review drops the copyleft term(s) "
                            f"{', '.join(dropped_copyleft)} from {recorded!r} but "
                            f"rests on no statement of what the package actually "
                            f"ships (its file list)")
            else:
                shipped = facts.get("record")
                files = list(shipped.get("files") or []) if isinstance(shipped, dict) else []
                res.note(f"narrowing accepted: {recorded!r} -> {', '.join(gov)}; the "
                         f"rationale names the dropped copyleft term(s) and the "
                         f"package's file list in the image is "
                         f"{', '.join(files) if files else '(empty)'}")
            return

        if any(self.is_copyleft(t) for t in tokens) and req is False:
            res.fail(7, f"the package's own licence record {recorded!r} contains a "
                        f"copyleft term and the review concludes source_required=false")

    def compare_free_text(self, gov: list[str], req: Any, text: str,
                          res: Result) -> None:
        """Free-text evidence (a Debian copyright file, an in-image licence
        text). Every claimed licence must be FOUND in the prose; an id with no
        marker pattern fails closed rather than being taken on trust."""
        for g in gov:
            key = canon(g, self.oci)
            patterns = FREE_TEXT_MARKERS.get(key)
            if not patterns:
                res.fail(7, f"cannot verify the claim that {g} governs this artifact: "
                            f"the evidence is free text and this verifier has no "
                            f"marker pattern for {g} (add one to FREE_TEXT_MARKERS "
                            f"rather than assuming the claim)")
                continue
            absent = [p for p in patterns if not re.search(p, text, re.IGNORECASE)]
            if absent:
                res.fail(7, f"the evidence text does not read like {g}: pattern(s) "
                            f"{', '.join(absent)} are absent from it")
        parsed = parse_dpkg_copyright(text)
        star = parsed["files_star"]
        if star and self.is_copyleft(star) and req is False:
            res.fail(7, f"the copyright file's `Files: *` stanza is {star} (copyleft) "
                        f"and the review concludes source_required=false")
        if star:
            res.note(f"the copyright file's catch-all `Files: *` stanza is {star!r}")


# ── the table ────────────────────────────────────────────────────────────────
def read_table(path: str) -> tuple[dict, str]:
    """The review table plus its exact bytes, so --sign can prove its rewrite
    changes nothing but the booleans."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise VerifyError(f"cannot read the licence review table ({path}): {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("reviews"), list) \
            or not doc["reviews"]:
        raise VerifyError(f"{path}: review table declares no `reviews`")
    return doc, raw


def serialise(doc: dict) -> str:
    """The file's own formatting: 2-space indent, real UTF-8, trailing newline."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def read_inventory(path: str | None) -> dict:
    p = path or INVENTORY
    if not os.path.isfile(p):
        if path:
            raise VerifyError(f"OCI inventory not found: {p}")
        return {}
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifyError(f"cannot read the OCI inventory ({p}): {exc}") from exc


def verify_table(doc: dict, verifier: Verifier, *,
                 only: str | None = None) -> list[Result]:
    results: list[Result] = []
    for review in doc["reviews"]:
        if not isinstance(review, dict):
            raise VerifyError("a review entry is not a JSON object")
        if only and only.lower() not in str(review.get("component", "")).lower():
            continue
        results.append(verifier.verify(review))
    return results


def report(results: list[Result], *, table: str, signed_now: list[Result] | None = None,
           stream: Any = None) -> None:
    # Resolved at call time, not at def time: a caller (or a test harness) may
    # have replaced sys.stdout since import.
    stream = sys.stdout if stream is None else stream
    width = max([len(r.component) for r in results] + [9])
    vwidth = max([len(r.version) for r in results] + [7])
    print(f"verify-source-reviews: {len(results)} review(s) in {table}", file=stream)
    print(f"  {'component'.ljust(width)}  {'version'.ljust(vwidth)}  "
          f"{'type':8s}  result", file=stream)
    print(f"  {'-' * width}  {'-' * vwidth}  {'-' * 8}  {'-' * 34}", file=stream)
    for r in results:
        verdict = r.disposition
        if verdict == FAIL:
            verdict += "  " + " ".join(f"C{c}" for c in r.conditions_failed())
        elif verdict == NEEDS_HUMAN:
            verdict += "  (not signable)"
        elif r.signed:
            verdict += "  (signed)"
        print(f"  {r.component.ljust(width)}  {r.version.ljust(vwidth)}  "
              f"{r.package_type:8s}  {verdict}", file=stream)

    failures = [(r, f) for r in results if r.eligible for f in r.findings]
    if failures:
        print(f"\n  FAILED CONDITIONS ({len(failures)}) — these entries stay unsigned:",
              file=stream)
        for r, f in failures:
            print(f"    C{f.condition}  {r.component} {r.version} "
                  f"[{r.package_type}]: {f.reason}", file=stream)

    human = [r for r in results if not r.eligible]
    if human:
        print(f"\n  NOT ELIGIBLE FOR SIGN-OFF ({len(human)}) — `needs_human` / "
              f"`unclear`:", file=stream)
        for r in human:
            detail = ", ".join(f"C{f.condition}: {f.reason}" for f in r.findings)
            print(f"    ?  {r.component} {r.version} [{r.package_type}]"
                  + (f" — {detail}" if detail else ""), file=stream)

    noted = [r for r in results if r.notes]
    if noted:
        print(f"\n  NOTES ({sum(len(r.notes) for r in noted)}) — how a check was "
              f"satisfied, or what could not be corroborated:", file=stream)
        for r in noted:
            for n in r.notes:
                print(f"    -  {r.component} {r.version}: {n}", file=stream)

    passed = [r for r in results if r.disposition == PASS]
    failed = [r for r in results if r.disposition == FAIL]
    print(f"\n  summary: {len(passed)} pass, {len(failed)} fail, {len(human)} need a "
          f"human, of {len(results)} entr(ies)", file=stream)
    # Result.signed is captured BEFORE --sign writes, so the two counts are
    # disjoint and their sum is the number of signed passing entries.
    just_signed = len(signed_now or [])
    already = len([r for r in passed if r.signed])
    print(f"  signed:  {already} already signed, {just_signed} signed by this run, "
          f"{len(passed) - already - just_signed} passing but unsigned", file=stream)


def sign(doc: dict, raw: str, results: list[Result], path: str) -> list[Result]:
    """Set `owner_signoff: true` on the entries that passed all seven.

    Idempotent, and byte-conservative: the rewrite is refused outright unless
    re-serialising the UNTOUCHED document reproduces the file exactly, which is
    the proof that the only diff this can produce is the flipped booleans.
    """
    if serialise(doc) != raw:
        raise VerifyError(
            f"refusing to rewrite {path}: re-serialising it does not reproduce the "
            f"file byte for byte, so a --sign would reformat unrelated lines. Fix "
            f"the formatting (2-space indent, UTF-8, trailing newline) first.")
    by_key = {r.key: r for r in results}
    signed_now: list[Result] = []
    for review in doc["reviews"]:
        key = (str(review.get("component", "")), str(review.get("version", "")),
               str(review.get("package_type", "")))
        res = by_key.get(key)
        if res is None or res.disposition != PASS:
            continue
        if review.get("owner_signoff") is True:
            continue
        review["owner_signoff"] = True
        signed_now.append(res)
    if not signed_now:
        return signed_now
    out = serialise(doc)
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(path)),
            prefix=".source-review.", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(out)
        os.replace(tmp, path)
        tmp = ""
    except OSError as exc:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        raise VerifyError(f"cannot write {path}: {exc}") from exc
    return signed_now


def validate_with_compliance_tool(oci: Any, path: str) -> None:
    """The rewritten table must still load in the tool that consumes it."""
    try:
        oci.load_reviews(path, required=True)
    except Exception as exc:
        raise VerifyError(f"{path} no longer loads in oci-compliance.py after the "
                          f"rewrite: {exc}") from exc


# ── selftest (offline: no docker, no network) ────────────────────────────────
def selftest() -> int:
    fails: list[str] = []
    ran = 0

    def check(label: str, got: Any, want: Any) -> None:
        nonlocal ran
        ran += 1
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    check("expression split keeps free text",
          split_expression("2-clause BSD-like license"), ["2-clause BSD-like license"])
    check("expression split on AND",
          split_expression("GPL-2.0-or-later AND 0BSD"), ["GPL-2.0-or-later", "0BSD"])
    db = parse_apk_db("C:Q1x=\nP:xz-libs\nV:5.8.3-r0\nL:0BSD\nR:liblzma.so.5\n\n"
                      "C:Q1y=\nP:musl\nV:1.2.6-r2\nL:MIT\n")
    check("apk db names", sorted(db), ["musl", "xz-libs"])
    check("apk db version", db["xz-libs"]["fields"]["V"], ["5.8.3-r0"])
    check("apk db file list", db["xz-libs"]["files"], ["liblzma.so.5"])
    apk = parse_apkbuild('pkgname=musl\npkgver=1.2.6\npkgrel=2\nlicense="MIT"\n'
                         'utils() {\n\tlicense="MIT AND GPL-2.0-or-later"\n}\n')
    check("apkbuild pkgver", apk["pkgver"], "1.2.6")
    check("apkbuild subpackage licence",
          apk["licenses"], ["MIT", "MIT AND GPL-2.0-or-later"])
    check("dpkg stanza version",
          parse_dpkg_stanzas("Package: base-files\nVersion: 12.4\n")[0]["Version"],
          "12.4")
    cop = parse_dpkg_copyright("Format: https://x\n\nFiles: *\nLicense: GPL-2\n")
    check("copyright Files:* licence", cop["files_star"], "GPL-2")
    check("placeholder detected", bool(PLACEHOLDER_RE.search("licence: TBD")), True)
    check("verdict word is not a placeholder",
          bool(PLACEHOLDER_RE.search("source_required unclear")), False)

    oci = load_oci()
    good = {
        "component": "xz-libs", "version": "5.8.3-r0", "package_type": "apk",
        "images": ["netops-correlation"],
        "evidence": {"kind": KIND_APK_RECORD_FILE, "image": "netops-correlation",
                     "path": "/lib/apk/db/installed (the P:xz-libs record)",
                     "sha256": ""},
        "governing_licences": ["0BSD"], "source_required": False,
        "needs_human": False,
        "rationale": ("The package's own file list in the image says what it ships: "
                      "xz-libs installs R:liblzma.so.5 and nothing else, and liblzma "
                      "is 0BSD; the GPL-2.0-or-later term covers the command-line "
                      "tools this subpackage does not ship."),
        "reviewer": "selftest", "reviewed": "2026-09-13", "owner_signoff": False,
    }
    dbtext = ("C:Q1x=\nP:xz-libs\nV:5.8.3-r0\n"
              "L:GPL-2.0-or-later AND 0BSD\nR:liblzma.so.5\n")
    good["evidence"]["sha256"] = hashlib.sha256(dbtext.encode()).hexdigest()
    fetcher = MappingFetcher(files={("netops-correlation", APK_DB_PATH):
                                    dbtext.encode()})
    inv = {"components": [{"name": "xz-libs", "version": "5.8.3-r0",
                           "package_type": "apk"}]}
    res = Verifier(fetcher, oci, inventory=inv).verify(good)
    check("a complete review passes all seven",
          [f"C{f.condition}: {f.reason}" for f in res.findings], [])
    bad = json.loads(json.dumps(good))
    bad["source_required"] = False
    bad["rationale"] = good["rationale"].replace("GPL-2.0-or-later", "some")
    res_bad = Verifier(fetcher, oci, inventory=inv).verify(bad)
    check("an unnamed dropped copyleft term fails condition 7",
          res_bad.conditions_failed(), [7])

    if fails:
        for f in fails:
            print(f"selftest FAIL: {f}", file=sys.stderr)
        return 1
    print(f"verify-source-reviews: selftest OK ({ran} checks)")
    return 0


# ── cli ──────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="verify and report only (default); exit 1 if any "
                           "sign-off-eligible review fails a condition")
    mode.add_argument("--sign", action="store_true",
                      help="verify, then set `owner_signoff: true` on every entry "
                           "that passed all seven conditions (idempotent)")
    mode.add_argument("--selftest", action="store_true",
                      help="offline self-tests of the parsers and the conditions")
    ap.add_argument("--reviews-file", help=f"licence review table (default {REVIEW_TABLE})")
    ap.add_argument("--inventory", help=f"committed OCI inventory (default {INVENTORY})")
    ap.add_argument("--image-tag", default="latest",
                    help="tag to read image evidence from (default latest)")
    ap.add_argument("--cache-dir", help="cache fetched evidence here (content is "
                                       "sha-verified on every run, so a cache can "
                                       "never launder a wrong answer)")
    ap.add_argument("--timeout", type=float, default=45.0,
                    help="per-call timeout in seconds (default 45)")
    ap.add_argument("--attempts", type=int, default=3,
                    help="fetch attempts per URL, with backoff+jitter (default 3)")
    ap.add_argument("--only", help="verify only components whose name contains this")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="machine-readable result instead of the table")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    table = args.reviews_file or REVIEW_TABLE
    fetcher: Fetcher | None = None
    try:
        oci = load_oci()
        doc, raw = read_table(table)
        inventory = read_inventory(args.inventory)
        fetcher = LiveFetcher(timeout=args.timeout, attempts=args.attempts,
                              cache_dir=args.cache_dir, image_tag=args.image_tag)
        verifier = Verifier(fetcher, oci, inventory=inventory)
        results = verify_table(doc, verifier, only=args.only)
        signed_now: list[Result] | None = None
        if args.sign:
            signed_now = sign(doc, raw, results, table)
            validate_with_compliance_tool(oci, table)
    except VerifyError as exc:
        print(f"verify-source-reviews: CANNOT RUN: {exc}", file=sys.stderr)
        return 2
    finally:
        if fetcher is not None:
            fetcher.close()

    if not results:
        print("verify-source-reviews: CANNOT RUN: no review entries matched",
              file=sys.stderr)
        return 2

    if args.as_json:
        json.dump({
            "table": table,
            "results": [{
                "component": r.component, "version": r.version,
                "package_type": r.package_type, "disposition": r.disposition,
                "owner_signoff": r.signed or (signed_now is not None
                                              and r in signed_now),
                "failures": [{"condition": f.condition, "reason": f.reason}
                             for f in r.findings],
                "notes": r.notes,
            } for r in results],
            "signed_by_this_run": [r.component for r in (signed_now or [])],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        report(results, table=table, signed_now=signed_now)
        if signed_now:
            print(f"\n  wrote {table}: {len(signed_now)} entr(ies) now carry "
                  f"`owner_signoff: true`", file=sys.stdout)

    failed = [r for r in results if r.disposition == FAIL]
    if failed:
        print(f"\nverify-source-reviews: {len(failed)} review(s) FAILED mechanical "
              f"verification and must not be signed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
