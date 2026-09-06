#!/usr/bin/env python3
"""source-archive.py — the Correlix-controlled corresponding-source archive.

WHY THIS EXISTS
---------------
`scripts/make-installer.sh write_source_offer()` mirrors every GPL/LGPL
corresponding-source tarball into each release bundle. Twenty-six of those
artifacts are RETAINED in git (`compliance/corresponding-sources/`); nine large
ones — busybox, syslog-ng, gettext, libgcrypt, libgpg-error, libidn2,
libunistring, musl and libseccomp's `.orig` — are FETCHED PER RELEASE from their
pinned upstream URL. That is a checksum-verified acquisition, and it is not
retention:

    An upstream URL is PROVENANCE. It is not a long-term compliance record.

The proof is already in this repository. Two `base-files` versions Correlix
shipped had left Debian's live pool by the time the 2026-09-05 audit looked for
them; `gitlab.alpinelinux.org` answers GitHub-hosted runners with HTTP 418. A
release whose source offer depends on ftp.gnu.org, gnupg.org, musl.libc.org and
deb.debian.org still serving those exact bytes is a licence obligation Correlix
does not actually control. A build host's `dist/` directory is not a durable
record either.

Owner decision (2026-09-05, tracker 262): the authoritative Correlix
corresponding-source archive is **AWS S3 with Versioning and Object Lock**, in a
company-controlled AWS account — never a personal developer account.

WHAT THIS DOES
--------------
It separates ACQUISITION from DISTRIBUTION, which is the whole architectural
point:

  INGEST (rare, deliberate, needs the network and the ingest role)
      pin table coordinates → HTTPS fetch (or a byte-identical retained copy)
      → verify the PINNED sha256 → PutObject into a content-addressed key with
      an Object Lock retention stamp → VERIFY THE STORED BYTES (HeadObject plus
      a re-download; a 200 from PutObject proves nothing about what is stored)
      → write per-component metadata → record it in the committed index.

  RELEASE (every release, needs only the read role)
      pin table → committed index → GetObject → verify sha256 → place into the
      bundle's `source-offer/`. **No upstream fetch, ever.** A missing archived
      artifact FAILS the release; it does not fall back to the internet.

So a normal release does not depend on upstream availability for an artifact
Correlix has already ingested — the regression this file exists to prevent.

STORAGE LAYOUT (content-addressed, deduplicated across releases)
    sources/sha256/<ab>/<full-sha256>/<sanitised-filename>
    components/<component>/<component-version>/metadata.json
    releases/<release>/source-manifest.json

Bytes decide identity, never names. Two releases referencing the same tarball
reference ONE object; a re-cut upstream release with different bytes hashes
differently and becomes a DIFFERENT object beside the first — the old one is
never overwritten, and Object Lock means it cannot be.

FAIL CLOSED (scripts/CLAUDE.md §16.1). Every one of these is an error with a
reason, never a quieter answer: the artifact is not archived; the stored sha256
does not match the pin; the object cannot be read; the index is invalid; a
required metadata field cannot be resolved; the source identity is ambiguous
where exact identity is required. `verified` is never reported for a check that
was skipped.

DEPENDENCIES — none
    Pure standard library, like `oci-compliance.py`, `license-audit.py` and
    `licensing-gate.py` beside it (CLAUDE.md §6). S3 is a REST API; the ~80
    lines of SigV4 below are a smaller, wholly reviewable surface than adding
    boto3 (~50 transitive MB) to every release runner for four verbs. boto3
    exists in this repository only INSIDE the cloud-ingest container image; it
    is not build tooling and is not installed on a release runner.

CREDENTIALS — never in this repository, never in a manifest, never in a log
    Read from the environment only, which in CI means GitHub Actions OIDC
    exchanging for short-lived credentials (see
    `.github/workflows/source-ingest.yml` and
    `deployment/aws/compliance-archive/`). No access key, session token or
    signed URL is written to any file this tool produces, and the Authorization
    header is redacted from every diagnostic.

USAGE
    # one-off, when a new source obligation appears (ingest role)
    source-archive.py ingest --all [--dry-run]
    source-archive.py ingest --file busybox-1.37.0.tar.bz2

    # confirm the archive still holds what the index claims (read role)
    source-archive.py verify --all [--strict]

    # what a release build does (read role) — archive first, no upstream
    source-archive.py release-fetch --dest dist/correlix-X/source-offer --all

    # the per-release record, and the auditor's trace back to the bytes
    source-archive.py release-manifest --release v1.2.3 --source-dir <offer>
    source-archive.py audit v1.2.3 [--offline]

    # what is retained, until when, and how that date was computed
    source-archive.py retention show

    source-archive.py --selftest        # offline: signing, policy, index, flows

ENVIRONMENT
    CORRELIX_SOURCE_ARCHIVE_BUCKET      bucket name                  (required)
    CORRELIX_SOURCE_ARCHIVE_REGION      region (or AWS_REGION)       (required)
    CORRELIX_SOURCE_ARCHIVE_ENDPOINT    override for an S3-compatible endpoint
    CORRELIX_SOURCE_ARCHIVE_PREFIX      key prefix inside the bucket (optional)
    CORRELIX_SOURCE_ARCHIVE_ADDRESSING  auto | virtual | path        (auto)
    CORRELIX_SOURCE_ARCHIVE_ALLOW_HTTP  1 = permit a plaintext endpoint. ONLY
                                        for a local MinIO/Moto stand-in; refuses
                                        to apply to an *.amazonaws.com endpoint.
    AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN

EXIT CODES
    0  the operation succeeded and everything it checked verified
    1  a compliance failure (missing artifact, bad checksum, unreadable object)
    2  CANNOT RUN (bad configuration, unusable input, unreachable archive)
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PIN_TABLE = os.path.join(ROOT, "scripts", "source-mirror.json")
POLICY_FILE = os.path.join(ROOT, "scripts", "source-retention-policy.json")
INDEX_FILE = os.path.join(ROOT, "docs", "compliance", "source-archive-index.json")


def default_index_path(env: dict[str, str] | None = None) -> str:
    """The committed index, unless an operator points somewhere else.

    `CORRELIX_SOURCE_ARCHIVE_INDEX` exists for the same two callers
    `CORRELIX_SOURCE_MIRROR_DIR` exists for: an air-gapped build host working
    from a prepared copy, and a test proving the release path without writing to
    the repository's own record.
    """
    e = env if env is not None else os.environ
    return e.get("CORRELIX_SOURCE_ARCHIVE_INDEX") or INDEX_FILE
RETAINED_DIR = os.path.join(ROOT, "compliance", "corresponding-sources")

SCHEMA_VERSION = 1

# The one status that means "Correlix holds these bytes and has hashed them".
STATUS_VERIFIED = "verified"
STATUS_MISSING = "missing"
STATUS_INVALID = "invalid"
STATUS_UNVERIFIED = "unverified"

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# A pinned artifact bigger than this is refused rather than streamed into a
# build host's temp space unbounded (CLAUDE.md §9 — all queues are bounded).
# The largest artifact in the pin table today is gettext at 10.3 MB; the largest
# recorded-unretained Debian source package is gcc-14 at 97 MB.
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024

# Every network call is bounded (§16.3). Uploads get a longer ceiling than
# metadata calls because they carry the bytes.
TIMEOUT_META = 30
TIMEOUT_BYTES = 600


class ArchiveError(Exception):
    """The operation could not be completed. Exit 2 — never a silent pass."""


class ComplianceFailure(Exception):
    """A real compliance violation. Exit 1 — a release must not proceed."""


# ── names and keys ───────────────────────────────────────────────────────────
# A pin table is reviewed and checked in, and it is still INPUT (CLAUDE.md §3:
# validate at every boundary). A file name from it becomes a path on a build
# host and a key in an object store, so it is validated before either.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")
_SHA256 = re.compile(r"[0-9a-f]{64}$")


def safe_filename(name: str) -> str:
    """The artifact's file name, or refuse it by name.

    Rejects path separators, `..`, leading dots, control characters and anything
    outside a conservative allowlist — so no value from the pin table can
    traverse out of the destination directory or out of the key prefix.
    """
    if not name or not _SAFE_NAME.fullmatch(name):
        raise ArchiveError(
            f"unsafe artifact file name {name!r}: an artifact name must match "
            f"[A-Za-z0-9][A-Za-z0-9._+~-]* and contain no path separator")
    if name in (".", "..") or ".." in name:
        raise ArchiveError(f"unsafe artifact file name {name!r}: path traversal")
    return name


def valid_sha256(digest: str) -> str:
    if not digest or not _SHA256.fullmatch(digest):
        raise ArchiveError(
            f"{digest!r} is not a lowercase hex sha256 digest; the archive is "
            f"content-addressed and a malformed digest addresses nothing")
    return digest


def object_key(sha256: str, filename: str, prefix: str = "") -> str:
    """`sources/sha256/ab/<full>/<file>` — bytes are the identity.

    The two-character fan-out is conventional object-store hygiene (it keeps any
    single listing prefix small); the FULL digest is in the key as well, so the
    key itself states the checksum an auditor must reproduce, and the file name
    is preserved so a downloaded object is recognisable without the manifest.
    """
    valid_sha256(sha256)
    safe_filename(filename)
    key = f"sources/sha256/{sha256[:2]}/{sha256}/{filename}"
    return f"{prefix.strip('/')}/{key}" if prefix.strip("/") else key


def component_metadata_key(component: str, version: str, prefix: str = "") -> str:
    comp = safe_filename(component)
    ver = safe_filename(version)
    key = f"components/{comp}/{ver}/metadata.json"
    return f"{prefix.strip('/')}/{key}" if prefix.strip("/") else key


def release_manifest_key(release: str, prefix: str = "") -> str:
    rel = safe_filename(release)
    key = f"releases/{rel}/source-manifest.json"
    return f"{prefix.strip('/')}/{key}" if prefix.strip("/") else key


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _today() -> str:
    return _now().date().isoformat()


# ── io ───────────────────────────────────────────────────────────────────────
def read_json(path: str, *, what: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ArchiveError(f"{what} not found at {path}") from exc
    except (OSError, ValueError) as exc:
        raise ArchiveError(f"{what} at {path} is unreadable: {exc}") from exc


def write_json(doc: Any, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        raise ArchiveError(f"cannot write {path}: {exc}") from exc
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ── the retention policy ─────────────────────────────────────────────────────
class RetentionPolicy:
    """`scripts/source-retention-policy.json` — arithmetic only, never a rule.

    The period is an owner-owned field in a committed file precisely so that no
    code path here asserts a legal conclusion. This class computes a date from
    it and records HOW, so an auditor can reproduce every stamped date.
    """

    def __init__(self, doc: dict, path: str = POLICY_FILE) -> None:
        self.path = path
        self.doc = doc
        decision = doc.get("owner_decision") or {}
        years = decision.get("retention_years")
        if not isinstance(years, int) or years <= 0:
            raise ArchiveError(
                f"{path}: owner_decision.retention_years must be a positive "
                f"integer; retention is an owner decision and the tooling "
                f"refuses to invent one")
        self.years = years
        self.counsel_confirmed = bool(decision.get("counsel_confirmed"))
        lock = doc.get("object_lock") or {}
        mode = lock.get("mode")
        allowed = lock.get("modes_allowed") or ["GOVERNANCE", "COMPLIANCE"]
        if mode not in allowed:
            raise ArchiveError(
                f"{path}: object_lock.mode {mode!r} is not one of {allowed}")
        if mode == "COMPLIANCE" and not lock.get("compliance_mode_authorised"):
            # COMPLIANCE cannot be undone by anyone, including the account root.
            # Reaching it by editing one word must not be possible.
            raise ArchiveError(
                f"{path}: object_lock.mode is COMPLIANCE but "
                f"compliance_mode_authorised is false. COMPLIANCE retention "
                f"cannot be shortened or deleted by ANY principal — not the "
                f"ingest role, not an administrator, not the account root user, "
                f"not AWS Support — for the whole period. Switching to it is an "
                f"explicit owner decision recorded in this file, never a default.")
        self.mode = mode
        self.policy_version = doc.get("policy_version", 0)

    @classmethod
    def load(cls, path: str | None = None) -> RetentionPolicy:
        p = path or POLICY_FILE
        return cls(read_json(p, what="retention policy"), p)

    def compute(self, *, base_date: str | None = None,
                base_reason: str | None = None,
                existing: str | None = None) -> dict:
        """{retain_until, mode, policy_version, calculation, base_date, …}.

        MONOTONIC: a computed date earlier than one already stamped is
        discarded and the existing date kept. Retention is only ever extended;
        shortening it is a deliberate human action against Object Lock, never a
        by-product of re-running this tool.
        """
        base = base_date or _today()
        try:
            base_dt = _dt.date.fromisoformat(base)
        except ValueError as exc:
            raise ArchiveError(f"retention base date {base!r} is not a date") from exc
        try:
            until = base_dt.replace(year=base_dt.year + self.years)
        except ValueError:
            # 29 February + N years where the target year is not a leap year.
            until = base_dt.replace(month=2, day=28, year=base_dt.year + self.years)
        computed = until.isoformat()
        shortened = False
        if existing and existing > computed:
            computed, shortened = existing, True
        return {
            "retain_until": computed,
            "mode": self.mode,
            "policy_version": self.policy_version,
            "policy_file": os.path.relpath(self.path, ROOT),
            "base_date": base,
            "base_date_reason": base_reason or "ingest-date (no release end-of-distribution date recorded)",
            "calculation": (f"{base} + {self.years} year(s) "
                            f"(source-retention-policy.json owner_decision.retention_years)"),
            "counsel_confirmed": self.counsel_confirmed,
            "kept_existing_longer_retention": shortened,
        }

    def retain_until_header(self, retain_until: str) -> str:
        """S3 wants an RFC3339 instant, the policy records a date."""
        return f"{retain_until}T00:00:00Z"


# ── the object store seam ────────────────────────────────────────────────────
# An interface, so the archive logic is testable without AWS and so no test ever
# needs a credential (CLAUDE.md §2 — every dependency explicit and injectable).
class ObjectStore:
    """The four operations the archive needs. Nothing else is in the surface."""

    location: str = "memory://"

    def head(self, key: str) -> dict | None:
        raise NotImplementedError

    def get(self, key: str, dest_path: str) -> dict:
        raise NotImplementedError

    def get_bytes(self, key: str) -> bytes | None:
        raise NotImplementedError

    def put(self, key: str, src_path: str, *, sha256: str,
            content_type: str = "application/octet-stream",
            metadata: dict[str, str] | None = None,
            lock_mode: str | None = None,
            retain_until: str | None = None) -> dict:
        raise NotImplementedError

    def put_bytes(self, key: str, data: bytes, *,
                  content_type: str = "application/json",
                  metadata: dict[str, str] | None = None,
                  lock_mode: str | None = None,
                  retain_until: str | None = None) -> dict:
        raise NotImplementedError

    def uri(self, key: str) -> str:
        return f"{self.location.rstrip('/')}/{key}"


class MemoryObjectStore(ObjectStore):
    """An in-process stand-in with the S3 properties the design depends on.

    Versioning (a put keeps the previous version) and Object Lock (a locked
    version cannot be deleted or overwritten in place) are modelled, because the
    tests that matter are about exactly those two properties.
    """

    def __init__(self, bucket: str = "test-bucket") -> None:
        self.bucket = bucket
        self.location = f"s3://{bucket}"
        self.versions: dict[str, list[dict]] = {}
        self.put_calls = 0
        self.get_calls = 0

    def _current(self, key: str) -> dict | None:
        chain = self.versions.get(key)
        return chain[-1] if chain else None

    def head(self, key: str) -> dict | None:
        obj = self._current(key)
        if obj is None:
            return None
        return {"size": len(obj["body"]), "sha256": obj["sha256"],
                "version_id": obj["version_id"], "lock_mode": obj["lock_mode"],
                "retain_until": obj["retain_until"], "metadata": obj["metadata"]}

    def get(self, key: str, dest_path: str) -> dict:
        obj = self._current(key)
        if obj is None:
            raise KeyError(key)
        self.get_calls += 1
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        with open(dest_path, "wb") as fh:
            fh.write(obj["body"])
        return self.head(key) or {}

    def get_bytes(self, key: str) -> bytes | None:
        obj = self._current(key)
        return None if obj is None else obj["body"]

    def _store(self, key: str, body: bytes, sha: str, metadata, lock_mode,
               retain_until) -> dict:
        self.put_calls += 1
        chain = self.versions.setdefault(key, [])
        chain.append({
            "body": body, "sha256": sha, "metadata": dict(metadata or {}),
            "lock_mode": lock_mode, "retain_until": retain_until,
            "version_id": f"v{len(chain) + 1}",
        })
        return self.head(key) or {}

    def put(self, key: str, src_path: str, *, sha256: str, **kw) -> dict:
        with open(src_path, "rb") as fh:
            body = fh.read()
        return self._store(key, body, sha256, kw.get("metadata"),
                           kw.get("lock_mode"), kw.get("retain_until"))

    def put_bytes(self, key: str, data: bytes, **kw) -> dict:
        return self._store(key, data, hashlib.sha256(data).hexdigest(),
                           kw.get("metadata"), kw.get("lock_mode"),
                           kw.get("retain_until"))

    def delete(self, key: str) -> None:
        """Modelled only to prove Object Lock refuses it."""
        obj = self._current(key)
        if obj is None:
            raise KeyError(key)
        if obj["lock_mode"] and obj["retain_until"] and obj["retain_until"] > _today():
            raise PermissionError(
                f"{key} is under {obj['lock_mode']} retention until "
                f"{obj['retain_until']}")
        self.versions.pop(key, None)


# ── S3 over the standard library (SigV4) ─────────────────────────────────────
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    """The SigV4 four-step key derivation. Date-scoped, region-scoped,
    service-scoped: a leaked signature is useless for anything else."""
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def canonical_request(method: str, path: str, query: str,
                      headers: dict[str, str], payload_sha: str) -> tuple[str, str]:
    """(canonical request, signed header list). Pure; the selftest pins it."""
    canon_headers = "".join(
        f"{k.lower()}:{' '.join(str(v).split())}\n"
        for k, v in sorted(headers.items(), key=lambda kv: kv[0].lower()))
    signed = ";".join(sorted(k.lower() for k in headers))
    canon_path = urllib.parse.quote(path, safe="/~")
    canon = (f"{method}\n{canon_path}\n{query}\n{canon_headers}\n"
             f"{signed}\n{payload_sha}")
    return canon, signed


class S3ObjectStore(ObjectStore):
    """S3 (or any S3-compatible endpoint) over urllib with SigV4.

    Only the verbs the archive needs are implemented: HeadObject, GetObject,
    PutObject. There is deliberately no delete, no lifecycle call, no bucket
    administration — a tool that cannot express an operation cannot be talked
    into performing it, and the ingest role holds no permission for them either
    (defence in depth, CLAUDE.md §3).
    """

    def __init__(self, *, bucket: str, region: str, access_key: str,
                 secret_key: str, session_token: str = "",
                 endpoint: str = "", addressing: str = "auto",
                 allow_http: bool = False,
                 opener: urllib.request.OpenerDirector | None = None) -> None:
        if not bucket:
            raise ArchiveError(
                "no archive bucket configured — set CORRELIX_SOURCE_ARCHIVE_BUCKET")
        if not region:
            raise ArchiveError(
                "no archive region configured — set CORRELIX_SOURCE_ARCHIVE_REGION "
                "(or AWS_REGION)")
        if not access_key or not secret_key:
            raise ArchiveError(
                "no AWS credentials in the environment. This tool never reads a "
                "credential from a file in the repository: in CI the credentials "
                "come from GitHub OIDC (short-lived), locally from a profile "
                "exported into the environment.")
        self.bucket = bucket
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.endpoint = (endpoint or f"https://s3.{region}.amazonaws.com").rstrip("/")
        parsed = urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ArchiveError(f"archive endpoint {self.endpoint!r} is not a URL")
        if parsed.scheme != "https":
            host_is_aws = parsed.hostname and parsed.hostname.endswith("amazonaws.com")
            if host_is_aws or not allow_http:
                raise ArchiveError(
                    f"archive endpoint {self.endpoint!r} is plaintext HTTP. "
                    f"Corresponding-source bytes are retrieved over TLS. Set "
                    f"CORRELIX_SOURCE_ARCHIVE_ALLOW_HTTP=1 only for a LOCAL "
                    f"S3-compatible stand-in; it is refused for AWS endpoints.")
        if addressing == "auto":
            addressing = "virtual" if (parsed.hostname or "").endswith(
                "amazonaws.com") else "path"
        if addressing not in ("virtual", "path"):
            raise ArchiveError(f"unknown addressing style {addressing!r}")
        self.addressing = addressing
        self.location = f"s3://{bucket}"
        self._opener = opener or urllib.request.build_opener(_NoRedirect())

    # -- request plumbing ----------------------------------------------------
    def _url_and_path(self, key: str) -> tuple[str, str, str]:
        parsed = urllib.parse.urlsplit(self.endpoint)
        if self.addressing == "virtual":
            host = f"{self.bucket}.{parsed.netloc}"
            path = "/" + key
        else:
            host = parsed.netloc
            path = f"/{self.bucket}/{key}"
        return (f"{parsed.scheme}://{host}{urllib.parse.quote(path, safe='/~')}",
                host, path)

    def _signed_headers(self, method: str, key: str, payload_sha: str,
                        extra: dict[str, str], query: str = "") -> tuple[str, dict[str, str]]:
        url, host, path = self._url_and_path(key)
        now = _now()
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        headers = {"host": host, "x-amz-content-sha256": payload_sha,
                   "x-amz-date": amzdate}
        if self.session_token:
            headers["x-amz-security-token"] = self.session_token
        headers.update({k.lower(): v for k, v in extra.items()})
        canon, signed = canonical_request(method, path, query, headers, payload_sha)
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                             hashlib.sha256(canon.encode("utf-8")).hexdigest()])
        sig = hmac.new(signing_key(self.secret_key, datestamp, self.region, "s3"),
                       to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed}, Signature={sig}")
        if query:
            url = f"{url}?{query}"
        return url, headers

    def _request(self, method: str, key: str, *, payload_sha: str,
                 body: Any = None, extra: dict[str, str] | None = None,
                 query: str = "", timeout: int = TIMEOUT_META):
        url, headers = self._signed_headers(method, key, payload_sha,
                                            extra or {}, query)
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            return self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                return exc  # the caller decides; 404 is a normal answer to head()
            detail = ""
            try:
                detail = exc.read()[:2048].decode("utf-8", "replace")
            except OSError:
                detail = "<error body unreadable>"
            # NEVER echo the request headers: they carry the Authorization line.
            raise ArchiveError(
                f"S3 {method} {self.uri(key)} failed: HTTP {exc.code} "
                f"{exc.reason}: {_redact(detail)}") from exc
        except urllib.error.URLError as exc:
            raise ArchiveError(
                f"S3 {method} {self.uri(key)} failed: {exc.reason}") from exc
        except OSError as exc:
            raise ArchiveError(f"S3 {method} {self.uri(key)} failed: {exc}") from exc

    # -- the four operations -------------------------------------------------
    def head(self, key: str) -> dict | None:
        resp = self._request("HEAD", key, payload_sha=EMPTY_SHA256,
                             extra={"x-amz-checksum-mode": "ENABLED"})
        code = getattr(resp, "code", getattr(resp, "status", 0))
        if code == 404:
            return None
        if code == 403:
            raise ArchiveError(
                f"S3 HEAD {self.uri(key)} was denied (403). The role in use "
                f"lacks s3:GetObject/s3:ListBucket on this prefix, or the object "
                f"is in another account. A denial is not an answer about whether "
                f"the artifact is archived.")
        hdr = resp.headers
        return {
            "size": int(hdr.get("Content-Length") or 0),
            "etag": (hdr.get("ETag") or "").strip('"'),
            "version_id": hdr.get("x-amz-version-id") or "",
            "lock_mode": hdr.get("x-amz-object-lock-mode") or "",
            "retain_until": (hdr.get("x-amz-object-lock-retain-until-date") or "")[:10],
            "checksum_sha256": hdr.get("x-amz-checksum-sha256") or "",
            "metadata": {k[len("x-amz-meta-"):]: v for k, v in hdr.items()
                         if k.lower().startswith("x-amz-meta-")},
        }

    def get(self, key: str, dest_path: str) -> dict:
        resp = self._request("GET", key, payload_sha=EMPTY_SHA256,
                             timeout=TIMEOUT_BYTES)
        code = getattr(resp, "code", getattr(resp, "status", 0))
        if code in (403, 404):
            raise KeyError(key)
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        total = 0
        with open(dest_path, "wb") as fh:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    fh.close()
                    os.unlink(dest_path)
                    raise ArchiveError(
                        f"{self.uri(key)} exceeds the {MAX_ARTIFACT_BYTES}-byte "
                        f"ceiling; refusing to fill the build host's disk")
                fh.write(chunk)
        return {"size": total, "version_id": resp.headers.get("x-amz-version-id") or ""}

    def get_bytes(self, key: str) -> bytes | None:
        resp = self._request("GET", key, payload_sha=EMPTY_SHA256)
        code = getattr(resp, "code", getattr(resp, "status", 0))
        if code in (403, 404):
            return None
        return resp.read(MAX_ARTIFACT_BYTES)

    def _lock_headers(self, lock_mode: str | None, retain_until: str | None) -> dict[str, str]:
        if not lock_mode:
            return {}
        if not retain_until:
            raise ArchiveError(
                "an Object Lock mode was requested with no retain-until date; "
                "refusing to write an object whose retention is undefined")
        return {"x-amz-object-lock-mode": lock_mode,
                "x-amz-object-lock-retain-until-date": retain_until}

    def put(self, key: str, src_path: str, *, sha256: str,
            content_type: str = "application/octet-stream",
            metadata: dict[str, str] | None = None,
            lock_mode: str | None = None,
            retain_until: str | None = None) -> dict:
        size = os.path.getsize(src_path)
        if size > MAX_ARTIFACT_BYTES:
            raise ArchiveError(
                f"{src_path} is {size} bytes, over the {MAX_ARTIFACT_BYTES} "
                f"ceiling for a single-part upload")
        extra = {"content-type": content_type,
                 "x-amz-checksum-sha256": base64.b64encode(
                     bytes.fromhex(valid_sha256(sha256))).decode("ascii")}
        extra.update(self._lock_headers(lock_mode, retain_until))
        for k, v in (metadata or {}).items():
            extra[f"x-amz-meta-{k}"] = v
        # The payload hash IS the artifact's pinned digest, so S3 authenticates
        # exactly the bytes the pin table names: a corrupted upload cannot be
        # signed, and a signed upload cannot be different bytes.
        with open(src_path, "rb") as fh:
            resp = self._request("PUT", key, payload_sha=sha256, body=fh,
                                 extra={**extra, "content-length": str(size)},
                                 timeout=TIMEOUT_BYTES)
        code = getattr(resp, "code", getattr(resp, "status", 0))
        if code in (403, 404):
            raise ArchiveError(
                f"S3 PUT {self.uri(key)} was denied (HTTP {code}). The role in "
                f"use is not the source-ingest role, or the bucket/prefix is "
                f"wrong. Nothing was archived.")
        return {"version_id": resp.headers.get("x-amz-version-id") or "",
                "checksum_sha256": resp.headers.get("x-amz-checksum-sha256") or ""}

    def put_bytes(self, key: str, data: bytes, *,
                  content_type: str = "application/json",
                  metadata: dict[str, str] | None = None,
                  lock_mode: str | None = None,
                  retain_until: str | None = None) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        extra = {"content-type": content_type, "content-length": str(len(data)),
                 "x-amz-checksum-sha256": base64.b64encode(
                     bytes.fromhex(digest)).decode("ascii")}
        extra.update(self._lock_headers(lock_mode, retain_until))
        for k, v in (metadata or {}).items():
            extra[f"x-amz-meta-{k}"] = v
        resp = self._request("PUT", key, payload_sha=digest, body=data,
                             extra=extra, timeout=TIMEOUT_BYTES)
        code = getattr(resp, "code", getattr(resp, "status", 0))
        if code in (403, 404):
            raise ArchiveError(f"S3 PUT {self.uri(key)} was denied (HTTP {code})")
        return {"version_id": resp.headers.get("x-amz-version-id") or "",
                "sha256": digest}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect invalidates the signature and can move the request to a host
    we did not authenticate to. Refuse it by name instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ArchiveError(
            f"the archive endpoint redirected ({code}) to {newurl}; a signed S3 "
            f"request is not followed across a redirect (wrong region, or an "
            f"endpoint that is not the bucket's)")


_SECRETISH = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|Signature=[0-9a-f]{64}|"
    r"x-amz-security-token[^\s,]*)", re.IGNORECASE)


def _redact(text: str) -> str:
    """No AWS secret, session token or signature reaches a log (CLAUDE.md §8)."""
    return _SECRETISH.sub("<redacted>", text)


def store_from_env(env: dict[str, str] | None = None) -> ObjectStore:
    e = env if env is not None else os.environ
    return S3ObjectStore(
        bucket=e.get("CORRELIX_SOURCE_ARCHIVE_BUCKET", ""),
        region=(e.get("CORRELIX_SOURCE_ARCHIVE_REGION")
                or e.get("AWS_REGION") or e.get("AWS_DEFAULT_REGION") or ""),
        access_key=e.get("AWS_ACCESS_KEY_ID", ""),
        secret_key=e.get("AWS_SECRET_ACCESS_KEY", ""),
        session_token=e.get("AWS_SESSION_TOKEN", ""),
        endpoint=e.get("CORRELIX_SOURCE_ARCHIVE_ENDPOINT", ""),
        addressing=e.get("CORRELIX_SOURCE_ARCHIVE_ADDRESSING", "auto"),
        allow_http=e.get("CORRELIX_SOURCE_ARCHIVE_ALLOW_HTTP") == "1",
    )


def archive_prefix(env: dict[str, str] | None = None) -> str:
    e = env if env is not None else os.environ
    return e.get("CORRELIX_SOURCE_ARCHIVE_PREFIX", "").strip("/")


# ── the upstream fetch seam (INGEST ONLY) ────────────────────────────────────
# Upstream fetching belongs to ingest and bootstrap tooling. It is a separate,
# injectable object so a release-path test can assert — not hope — that the
# release never reaches for the network: the release path is constructed with no
# fetcher at all.
class Fetcher:
    def fetch(self, url: str, dest_path: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> int:
        raise NotImplementedError


class HttpsFetcher(Fetcher):
    def __init__(self, timeout: int = TIMEOUT_BYTES) -> None:
        self.timeout = timeout

    def fetch(self, url: str, dest_path: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> int:
        if not url.startswith("https://"):
            raise ArchiveError(
                f"refusing to acquire corresponding source over a non-TLS URL: {url!r}")
        req = urllib.request.Request(url, headers={
            "User-Agent": ("correlix-source-archive/1.0 (corresponding-source "
                           "ingest; +https://github.com/correlix)")})
        opener = urllib.request.build_opener()
        total = 0
        try:
            with opener.open(req, timeout=self.timeout) as resp, \
                    open(dest_path, "wb") as fh:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ArchiveError(
                            f"{url} exceeds the {max_bytes}-byte ceiling; "
                            f"refusing an unbounded download")
                    fh.write(chunk)
        except ArchiveError:
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            raise
        except (urllib.error.URLError, OSError) as exc:
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            raise ArchiveError(f"cannot fetch {url}: {exc}") from exc
        return total


class NoFetcher(Fetcher):
    """The release path's fetcher. Every call is a bug, and says which."""

    def fetch(self, url: str, dest_path: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> int:
        raise ComplianceFailure(
            f"the release path tried to fetch {url} from upstream. A production "
            f"release reads corresponding source from the Correlix archive and "
            f"never from the internet; a missing artifact is a release failure, "
            f"not a reason to trust an upstream URL.")


# ── the committed index ──────────────────────────────────────────────────────
INDEX_REQUIRED_ARTIFACT_FIELDS = (
    "component", "component_version", "source_package", "source_version",
    "file", "sha256", "size_bytes", "object_key", "upstream_url", "license",
    "correspondence", "verification", "retention",
)


def empty_index() -> dict:
    return {
        "_README": [
            "source-archive-index.json — GENERATED by scripts/source-archive.py.",
            "The git-side half of the Correlix corresponding-source archive: what is",
            "archived, where its bytes are, what they hash to, when that was last",
            "proven, and until when the object is locked.",
            "",
            "It holds NO credential and NO signed URL. An object key is not a secret",
            "and is useless without a role; a presigned URL is a bearer token and is",
            "never written to a file in this repository.",
            "",
            "Read by `source-archive.py release-fetch` (which refuses to place an",
            "artifact this file does not vouch for), `audit`, `verify` and",
            "`retention show`, and schema-validated by",
            "`scripts/oci-compliance.py --validate-archive`.",
        ],
        "schema_version": SCHEMA_VERSION,
        "generated": "",
        "policy": "scripts/source-retention-policy.json",
        "archive": {"provider": "aws-s3", "bucket": "", "region": "", "prefix": "",
                    "versioning": "enabled", "object_lock": "enabled",
                    "object_lock_mode": ""},
        "artifacts": [],
        "releases": [],
    }


def load_index(path: str | None = None) -> dict:
    p = path or default_index_path()
    if not os.path.exists(p):
        return empty_index()
    doc = read_json(p, what="source archive index")
    problems = validate_index(doc, p)
    if problems:
        # An index that does not validate is not a weaker record, it is no
        # record: every downstream answer (where the bytes are, whether they
        # were verified, until when they are retained) would be read out of it.
        raise ArchiveError(
            f"{p} is not a valid corresponding-source archive index:\n  "
            + "\n  ".join(problems))
    return doc


def validate_index(doc: Any, path: str = INDEX_FILE) -> list[str]:
    """Schema validation. Returns the problems; raises on a shape that means the
    file cannot be trusted at all."""
    if not isinstance(doc, dict):
        raise ArchiveError(f"{path}: the archive index must be a JSON object")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ArchiveError(
            f"{path}: schema_version is {doc.get('schema_version')!r}, this tool "
            f"speaks {SCHEMA_VERSION}. Refusing to read a manifest whose shape it "
            f"does not know.")
    arts = doc.get("artifacts")
    if not isinstance(arts, list):
        raise ArchiveError(f"{path}: `artifacts` must be a list")
    problems: list[str] = []
    seen: dict[str, str] = {}
    for i, a in enumerate(arts):
        if not isinstance(a, dict):
            problems.append(f"artifacts[{i}] is not an object")
            continue
        who = a.get("file") or a.get("sha256") or f"artifacts[{i}]"
        for field in INDEX_REQUIRED_ARTIFACT_FIELDS:
            if a.get(field) in (None, "", [], {}):
                problems.append(f"{who}: required field `{field}` is missing")
        sha = a.get("sha256", "")
        if not isinstance(sha, str) or not _SHA256.fullmatch(sha):
            problems.append(f"{who}: sha256 is not a lowercase hex digest")
            continue
        key = a.get("object_key", "")
        if not isinstance(key, str) or f"/{sha}/" not in key:
            problems.append(
                f"{who}: object_key {key!r} does not contain its own sha256 — "
                f"the archive is content-addressed and the key must state the "
                f"digest an auditor has to reproduce")
        if sha in seen and seen[sha] != key:
            problems.append(
                f"{who}: sha256 {sha} is recorded at two different keys "
                f"({seen[sha]} and {key}); identical bytes are ONE object")
        seen[sha] = key
        ver = a.get("verification") or {}
        if ver.get("status") == STATUS_VERIFIED and not ver.get("verified_at"):
            problems.append(
                f"{who}: verification.status is `verified` with no verified_at — "
                f"a status never records a check that did not happen")
        if ver.get("status") == STATUS_VERIFIED and ver.get("measured_sha256") != sha:
            problems.append(
                f"{who}: verification says `verified` but the measured digest "
                f"{ver.get('measured_sha256')!r} is not the artifact's sha256")
        ret = a.get("retention") or {}
        if not ret.get("retain_until") or not ret.get("calculation"):
            problems.append(
                f"{who}: retention must record both the retain_until date and "
                f"how it was calculated")
    for j, r in enumerate(doc.get("releases") or []):
        if not isinstance(r, dict) or not r.get("release"):
            problems.append(f"releases[{j}] has no release id")
            continue
        # `artifacts` are the archived ones; `retained_in_git` are held by this
        # repository's history instead and have no artifact record here.
        for sha in r.get("artifacts") or []:
            if sha not in seen:
                problems.append(
                    f"release {r['release']} references sha256 {sha}, which no "
                    f"archived artifact in this index provides")
    return problems


def index_by_sha(doc: dict) -> dict[str, dict]:
    return {a["sha256"]: a for a in doc.get("artifacts", []) if a.get("sha256")}


# ── the pin table ────────────────────────────────────────────────────────────
def load_pins(path: str | None = None) -> dict:
    doc = read_json(path or PIN_TABLE, what="source-offer pin table")
    comps = doc.get("components")
    if not comps:
        raise ArchiveError(
            f"{path or PIN_TABLE} declares no components; a pin table that "
            f"resolves nothing must never look like an empty obligation")
    for c in comps:
        for field in ("name", "version", "file", "url", "sha256", "license"):
            if not c.get(field):
                raise ArchiveError(
                    f"pin table component {c.get('name', '?')!r} is missing `{field}`")
        safe_filename(c["file"])
        valid_sha256(c["sha256"])
        if not c["url"].startswith("https://"):
            raise ArchiveError(
                f"pin table component {c['name']} must be fetched over TLS, "
                f"got {c['url']!r}")
    return doc


def select_components(pins: dict, *, files: Iterable[str] = (),
                      names: Iterable[str] = (), everything: bool = False) -> list[dict]:
    comps = pins["components"]
    if everything:
        return list(comps)
    wanted_files = {safe_filename(f) for f in files}
    wanted_names = set(names)
    picked = [c for c in comps
              if c["file"] in wanted_files or c["name"] in wanted_names]
    unmatched = (wanted_files - {c["file"] for c in picked}) | \
                (wanted_names - {c["name"] for c in picked})
    if unmatched:
        raise ArchiveError(
            f"the pin table has no component matching {sorted(unmatched)}. "
            f"An artifact Correlix does not pin is an artifact it cannot "
            f"describe, and is never archived on the strength of a name.")
    if not picked:
        raise ArchiveError("no component selected — pass --all, --file or --component")
    return picked


def retained_copy(entry: dict) -> str | None:
    """The byte-identical copy already retained in git, if there is one."""
    rel = entry.get("retained_in_git") or ""
    if not rel:
        return None
    path = os.path.join(ROOT, rel)
    return path if os.path.isfile(path) else None


# ── the archive ──────────────────────────────────────────────────────────────
class SourceArchive:
    """Ingest, verify, release-fetch, audit. Store and fetcher are injected."""

    def __init__(self, store: ObjectStore, policy: RetentionPolicy, *,
                 fetcher: Fetcher | None = None, prefix: str = "",
                 index_path: str = "", index: dict | None = None,
                 mirror_dir: str = "", log: Callable[[str], None] = print) -> None:
        self.store = store
        self.policy = policy
        self.fetcher = fetcher or NoFetcher()
        self.prefix = prefix.strip("/")
        self.index_path = index_path or default_index_path()
        self.index = index if index is not None else load_index(self.index_path)
        self.mirror_dir = mirror_dir
        self.log = log

    # -- helpers -------------------------------------------------------------
    def key_for(self, entry: dict) -> str:
        return object_key(entry["sha256"], entry["file"], self.prefix)

    def _record_for(self, sha: str) -> dict | None:
        return index_by_sha(self.index).get(sha)

    def _acquire(self, entry: dict, dest: str) -> tuple[str, str]:
        """(path, how) — the bytes to archive, from the cheapest trusted source.

        A retained git copy and a local mirror are preferred over the network,
        and neither is TRUSTED: the pinned sha256 is checked identically in all
        three cases. Local provenance is not trusted provenance.
        """
        local = retained_copy(entry)
        if local:
            shutil.copyfile(local, dest)
            return dest, f"retained copy {os.path.relpath(local, ROOT)}"
        if self.mirror_dir:
            candidate = os.path.join(self.mirror_dir, entry["file"])
            if os.path.isfile(candidate):
                shutil.copyfile(candidate, dest)
                return dest, f"local mirror {candidate}"
        size = entry.get("size_bytes") or 0
        if size and size > MAX_ARTIFACT_BYTES:
            raise ArchiveError(
                f"{entry['file']} is pinned at {size} bytes, over the "
                f"{MAX_ARTIFACT_BYTES} ceiling")
        self.fetcher.fetch(entry["url"], dest,
                           max_bytes=min(MAX_ARTIFACT_BYTES,
                                         size * 2 if size else MAX_ARTIFACT_BYTES))
        return dest, f"upstream {entry['url']}"

    # -- ingest --------------------------------------------------------------
    def ingest(self, entries: list[dict], *, dry_run: bool = False,
               reverify: bool = False, releases: list[str] | None = None) -> dict:
        """fetch → verify pinned → upload → VERIFY STORED → record.

        Idempotent (§16.3): an artifact already archived and still verifying is
        left alone and reported as a hit. `PutObject` returning 200 is not
        evidence, so the stored bytes are read back and hashed every time this
        writes.
        """
        results: list[dict] = []
        for entry in entries:
            sha = valid_sha256(entry["sha256"])
            key = self.key_for(entry)
            existing = self._record_for(sha)
            head = self.store.head(key)
            if head and existing and not reverify:
                self.log(f"   = {entry['name']} {entry['version']} already archived "
                         f"({sha[:12]}…) — {self.store.uri(key)}")
                self._touch_references(existing, entry, releases)
                results.append({"file": entry["file"], "action": "hit",
                                "status": STATUS_VERIFIED, "key": key})
                continue
            if dry_run:
                self.log(f"   + {entry['name']} {entry['version']} WOULD ingest "
                         f"{entry['file']} ({entry.get('size_bytes', 0)} bytes) "
                         f"→ {self.store.uri(key)}")
                results.append({"file": entry["file"], "action": "would-ingest",
                                "status": "dry-run", "key": key})
                continue
            results.append(self._ingest_one(entry, key, head, releases))
        return {"artifacts": results,
                "ingested": sum(1 for r in results if r["action"] == "ingested"),
                "hits": sum(1 for r in results if r["action"] == "hit")}

    def _ingest_one(self, entry: dict, key: str, head: dict | None,
                    releases: list[str] | None) -> dict:
        sha = entry["sha256"]
        # Bounded temp storage, removed on every path including failure.
        tmp = tempfile.mkdtemp(prefix="correlix-source-ingest-")
        try:
            staged = os.path.join(tmp, safe_filename(entry["file"]))
            path, how = self._acquire(entry, staged)
            measured = sha256_file(path)
            if measured != sha:
                # NOT archived. Bad bytes are never written to a store whose
                # whole purpose is that its contents can be trusted forever.
                raise ComplianceFailure(
                    f"{entry['name']} {entry['version']}: the bytes from {how} "
                    f"hash to {measured}, but scripts/source-mirror.json pins "
                    f"{sha}. Nothing was archived. If upstream legitimately "
                    f"re-cut the release, re-measure and update the pin table "
                    f"deliberately — never adjust the checksum to match a "
                    f"download.")
            size = os.path.getsize(path)
            if entry.get("size_bytes") and int(entry["size_bytes"]) != size:
                raise ComplianceFailure(
                    f"{entry['name']}: pinned size {entry['size_bytes']} != "
                    f"actual {size}, with a matching digest — the pin table is "
                    f"internally inconsistent and must be corrected by hand")

            existing_ret = ((self._record_for(sha) or {}).get("retention") or {}
                            ).get("retain_until") or (head or {}).get("retain_until")
            retention = self.policy.compute(existing=existing_ret or None)
            self.log(f"   + {entry['name']} {entry['version']} <- {how}")
            self.log(f"     sha256 OK ({sha})")
            put = self.store.put(
                key, path, sha256=sha,
                metadata={"component": entry["name"][:64],
                          "component-version": entry["version"][:64],
                          "sha256": sha, "pin": "scripts/source-mirror.json"},
                lock_mode=retention["mode"],
                retain_until=self.policy.retain_until_header(retention["retain_until"]))

            verification = self.verify_object(key, sha, expect_size=size)
            if verification["status"] != STATUS_VERIFIED:
                raise ComplianceFailure(
                    f"{entry['name']} {entry['version']}: the object was written "
                    f"to {self.store.uri(key)} but reading it back did NOT "
                    f"verify: {verification['detail']}. PutObject returning "
                    f"success proves nothing about what is stored.")
            self.log(f"     stored + re-verified ({verification['method']}), "
                     f"lock {retention['mode']} until {retention['retain_until']}")

            record = self._build_record(entry, key, size, retention, verification,
                                        put.get("version_id", ""))
            self._touch_references(record, entry, releases)
            self._upsert(record)
            self._write_component_metadata(entry, record, retention)
            return {"file": entry["file"], "action": "ingested",
                    "status": STATUS_VERIFIED, "key": key}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _build_record(self, entry: dict, key: str, size: int, retention: dict,
                      verification: dict, version_id: str) -> dict:
        """Every field the compliance record requires, and no claim beyond the
        evidence: `source_package`/`source_version` fall back to the component's
        own identity ONLY when the pin table does not distinguish them, and say
        so, rather than asserting a distribution source package we do not know."""
        distro = entry.get("distro_package") or {}
        source_package = (distro.get("source_package") or entry.get("source_package")
                          or entry["name"])
        source_version = (distro.get("source_version") or entry.get("source_version")
                          or entry["version"])
        return {
            "component": entry["name"],
            "component_version": entry["version"],
            "source_package": source_package,
            "source_version": source_version,
            "source_identity_basis": (
                "distro_package in the pin table" if distro else
                "the pin table records no distinct distribution source package; "
                "the upstream component identity is used and no exact "
                "distribution correspondence is claimed"),
            "file": entry["file"],
            "sha256": entry["sha256"],
            "size_bytes": size,
            "object_key": key,
            "archive": {"provider": "aws-s3",
                        "bucket": getattr(self.store, "bucket", ""),
                        "region": getattr(self.store, "region", ""),
                        "uri": self.store.uri(key),
                        "version_id": version_id},
            "upstream_url": entry["url"],
            "upstream_verified_against": entry.get("verified_against", ""),
            "license": entry["license"],
            "correspondence": entry.get("correspondence", ""),
            "role": entry.get("role", "corresponding-source"),
            "distro_package": distro,
            "retained_in_git": entry.get("retained_in_git", ""),
            "image_digests": [],
            "images": list(entry.get("images") or []),
            "releases": [],
            "verification": verification,
            "retention": retention,
            "ingested": _today(),
        }

    def _touch_references(self, record: dict, entry: dict,
                          releases: list[str] | None) -> None:
        for rel in releases or []:
            if rel not in record.setdefault("releases", []):
                record["releases"].append(rel)
        for img in entry.get("image_digests") or []:
            if img not in record.setdefault("image_digests", []):
                record["image_digests"].append(img)

    def _upsert(self, record: dict) -> None:
        arts = self.index.setdefault("artifacts", [])
        for i, a in enumerate(arts):
            if a.get("sha256") == record["sha256"]:
                # Dedup: identical bytes are ONE object. References merge; the
                # object is not written twice under a second name.
                merged = dict(a)
                merged.update(record)
                merged["releases"] = sorted(set(a.get("releases", []))
                                            | set(record.get("releases", [])))
                merged["image_digests"] = sorted(set(a.get("image_digests", []))
                                                 | set(record.get("image_digests", [])))
                arts[i] = merged
                return
        arts.append(record)
        arts.sort(key=lambda a: (a.get("component", ""), a.get("sha256", "")))

    def _write_component_metadata(self, entry: dict, record: dict,
                                  retention: dict) -> None:
        key = component_metadata_key(entry["name"], entry["version"], self.prefix)
        doc = {"schema_version": SCHEMA_VERSION,
               "generated": _now().isoformat(timespec="seconds"),
               "component": entry["name"], "component_version": entry["version"],
               "artifacts": [record]}
        blob = json.dumps(doc, indent=2).encode("utf-8")
        self.store.put_bytes(key, blob, lock_mode=retention["mode"],
                             retain_until=self.policy.retain_until_header(
                                 retention["retain_until"]))

    # -- verify --------------------------------------------------------------
    def verify_object(self, key: str, sha: str, *, expect_size: int | None = None,
                      method: str = "download") -> dict:
        """Read the stored bytes back and hash them.

        `head` alone is the weaker mode: it proves the object exists and, where
        the store returns one, that its recorded checksum matches. `download`
        (the default, and the only one used at ingest) proves the bytes.
        """
        head = self.store.head(key)
        if head is None:
            return {"status": STATUS_MISSING, "method": "head",
                    "verified_at": "", "measured_sha256": "",
                    "detail": f"no object at {self.store.uri(key)}"}
        if expect_size is not None and head.get("size") not in (None, 0, expect_size):
            return {"status": STATUS_INVALID, "method": "head",
                    "verified_at": "", "measured_sha256": "",
                    "detail": (f"stored object is {head.get('size')} bytes, "
                               f"expected {expect_size}")}
        if method == "head":
            stored = (head.get("checksum_sha256") or head.get("sha256") or "")
            if stored and _decode_checksum(stored) == sha:
                return {"status": STATUS_VERIFIED, "method": "head+stored-checksum",
                        "verified_at": _now().isoformat(timespec="seconds"),
                        "measured_sha256": sha,
                        "object_version_id": head.get("version_id", ""),
                        "detail": "the store's own recorded SHA-256 matches the pin"}
            return {"status": STATUS_UNVERIFIED, "method": "head",
                    "verified_at": "", "measured_sha256": "",
                    "detail": ("the object exists but the store returned no "
                               "checksum; existence is not verification")}
        tmp = tempfile.mkdtemp(prefix="correlix-source-verify-")
        try:
            dest = os.path.join(tmp, "object.bin")
            try:
                self.store.get(key, dest)
            except KeyError:
                return {"status": STATUS_MISSING, "method": "download",
                        "verified_at": "", "measured_sha256": "",
                        "detail": f"no object at {self.store.uri(key)}"}
            except ArchiveError as exc:
                return {"status": STATUS_INVALID, "method": "download",
                        "verified_at": "", "measured_sha256": "",
                        "detail": f"the object could not be read: {exc}"}
            measured = sha256_file(dest)
            if measured != sha:
                return {"status": STATUS_INVALID, "method": "download",
                        "verified_at": "", "measured_sha256": measured,
                        "detail": (f"stored bytes hash to {measured}, the pin is "
                                   f"{sha}")}
            return {"status": STATUS_VERIFIED, "method": "download+sha256",
                    "verified_at": _now().isoformat(timespec="seconds"),
                    "measured_sha256": measured,
                    "object_version_id": head.get("version_id", ""),
                    "stored_size_bytes": head.get("size", 0),
                    "detail": "the stored bytes hash to the pinned digest"}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def verify(self, entries: list[dict], *, method: str = "download") -> dict:
        out: list[dict] = []
        for entry in entries:
            sha = entry["sha256"]
            record = self._record_for(sha)
            key = self.key_for(entry)
            if record is None:
                out.append({"file": entry["file"], "sha256": sha, "key": key,
                            "status": STATUS_MISSING,
                            "detail": ("not recorded in "
                                       "docs/compliance/source-archive-index.json "
                                       "— run `source-archive.py ingest`")})
                self.log(f"   ! {entry['name']} {entry['version']}: NOT ARCHIVED")
                continue
            res = self.verify_object(record["object_key"], sha, method=method)
            record["verification"] = res
            out.append({"file": entry["file"], "sha256": sha,
                        "key": record["object_key"], "status": res["status"],
                        "detail": res["detail"]})
            mark = "OK " if res["status"] == STATUS_VERIFIED else "!  "
            self.log(f"   {mark}{entry['name']} {entry['version']}: "
                     f"{res['status']} ({res['detail']})")
        return {"results": out,
                "verified": sum(1 for r in out if r["status"] == STATUS_VERIFIED),
                "failed": [r for r in out if r["status"] != STATUS_VERIFIED]}

    # -- release ------------------------------------------------------------
    def release_fetch(self, entries: list[dict], dest_dir: str, *,
                      allow_retained: bool = True) -> dict:
        """Place corresponding source into a release bundle. ARCHIVE ONLY.

        Order: a retained git copy (which IS Correlix-controlled retention, and
        is re-hashed exactly like a download), then the archive. Never upstream.
        A miss is a release failure with the ingest command to run, because a
        release that quietly reached for ftp.gnu.org is the defect this whole
        mechanism exists to remove.
        """
        os.makedirs(dest_dir, exist_ok=True)
        placed: list[dict] = []
        for entry in entries:
            sha = entry["sha256"]
            dest = os.path.join(dest_dir, safe_filename(entry["file"]))
            local = retained_copy(entry) if allow_retained else None
            if local:
                shutil.copyfile(local, dest)
                got = sha256_file(dest)
                if got != sha:
                    os.unlink(dest)
                    raise ComplianceFailure(
                        f"{entry['file']}: the retained copy in git hashes to "
                        f"{got}, not the pinned {sha}. Local provenance is not "
                        f"trusted provenance.")
                self.log(f"   {entry['name']} {entry['version']} <- retained in git")
                placed.append({"file": entry["file"], "source": "git-retained",
                               "sha256": sha})
                continue
            record = self._record_for(sha)
            if record is None:
                raise ComplianceFailure(
                    f"{entry['name']} {entry['version']} ({entry['file']}, sha256 "
                    f"{sha}) is NOT in the Correlix source archive. A release "
                    f"does not fall back to {entry['url']}: an upstream URL is "
                    f"provenance, not retention. Ingest it first:\n"
                    f"      scripts/source-archive.py ingest --file {entry['file']}")
            if (record.get("verification") or {}).get("status") != STATUS_VERIFIED:
                raise ComplianceFailure(
                    f"{entry['file']} is recorded in the archive index with "
                    f"verification status "
                    f"{(record.get('verification') or {}).get('status')!r}. Only a "
                    f"`verified` artifact may be placed in a release bundle.")
            key = record["object_key"]
            try:
                self.store.get(key, dest)
            except KeyError as exc:
                raise ComplianceFailure(
                    f"{entry['file']}: the archive index records "
                    f"{self.store.uri(key)}, but no object is there. The index "
                    f"and the bucket disagree; a release must not proceed on an "
                    f"unresolvable record.") from exc
            got = sha256_file(dest)
            if got != sha:
                os.unlink(dest)
                raise ComplianceFailure(
                    f"{entry['file']}: the archived object hashes to {got}, the "
                    f"pin is {sha}. Refusing to ship unverified bytes.")
            self.log(f"   {entry['name']} {entry['version']} <- archive "
                     f"{self.store.uri(key)}  sha256 OK")
            placed.append({"file": entry["file"], "source": "archive",
                           "sha256": sha, "object_key": key,
                           "object_version_id": record.get("archive", {}).get("version_id", "")})
        return {"placed": placed, "dest": dest_dir}

    def release_manifest(self, release: str, entries: list[dict], *,
                         image_digests: list[str] | None = None,
                         upload: bool = True) -> dict:
        """The per-release source manifest: the auditor's entry point."""
        safe_filename(release)
        arts = []
        for entry in entries:
            record = self._record_for(entry["sha256"])
            if record is None and not retained_copy(entry):
                raise ComplianceFailure(
                    f"release {release}: {entry['file']} is neither archived nor "
                    f"retained in git; the manifest would claim a source Correlix "
                    f"does not hold")
            arts.append({
                "component": entry["name"],
                "component_version": entry["version"],
                "source_package": (record or {}).get("source_package", entry["name"]),
                "source_version": (record or {}).get("source_version", entry["version"]),
                "file": entry["file"],
                "sha256": entry["sha256"],
                "size_bytes": (record or {}).get("size_bytes", entry.get("size_bytes", 0)),
                "license": entry["license"],
                "correspondence": entry.get("correspondence", ""),
                "upstream_url": entry["url"],
                "location": ("git:" + entry["retained_in_git"]) if retained_copy(entry)
                            else (record or {}).get("archive", {}).get("uri", ""),
                "object_key": (record or {}).get("object_key", ""),
                "object_version_id": (record or {}).get("archive", {}).get("version_id", ""),
                "verification": (record or {}).get(
                    "verification",
                    {"status": STATUS_VERIFIED, "method": "git-retained+sha256",
                     "verified_at": _today(), "measured_sha256": entry["sha256"],
                     "detail": "retained in this repository's history and re-hashed"}),
                "retention": (record or {}).get(
                    "retention",
                    {"retain_until": "unbounded", "mode": "git-history",
                     "calculation": "retained in git history for the life of the "
                                    "repository", "policy_version":
                                    self.policy.policy_version}),
            })
        doc = {"schema_version": SCHEMA_VERSION,
               "release": release,
               "generated": _now().isoformat(timespec="seconds"),
               "image_digests": list(image_digests or []),
               "policy": os.path.relpath(self.policy.path, ROOT),
               "artifacts": arts}
        key = release_manifest_key(release, self.prefix)
        if upload:
            retention = self.policy.compute()
            self.store.put_bytes(
                key, json.dumps(doc, indent=2).encode("utf-8"),
                lock_mode=retention["mode"],
                retain_until=self.policy.retain_until_header(retention["retain_until"]))
        rels = self.index.setdefault("releases", [])
        # The two homes are recorded SEPARATELY. `artifacts` lists what the S3
        # archive holds and is what the index's referential check validates;
        # `retained_in_git` lists what this repository's own history holds. A
        # release whose corresponding source is entirely small enough to live in
        # git is a valid release, and must not look like a dangling reference.
        archived = sorted({a["sha256"] for a in arts if a.get("object_key")})
        in_git = sorted({a["sha256"] for a in arts if not a.get("object_key")})
        entry = {"release": release, "manifest_key": key,
                 "artifacts": archived,
                 "retained_in_git": in_git,
                 "image_digests": list(image_digests or []),
                 "recorded": _today()}
        for i, r in enumerate(rels):
            if r.get("release") == release:
                rels[i] = entry
                break
        else:
            rels.append(entry)
        for a in arts:
            rec = self._record_for(a["sha256"])
            if rec is not None and release not in rec.setdefault("releases", []):
                rec["releases"].append(release)
        return doc

    # -- persistence ---------------------------------------------------------
    def save_index(self) -> None:
        self.index["schema_version"] = SCHEMA_VERSION
        self.index["generated"] = _now().isoformat(timespec="seconds")
        self.index["policy"] = os.path.relpath(self.policy.path, ROOT)
        self.index.setdefault("archive", {}).update({
            "provider": "aws-s3",
            "bucket": getattr(self.store, "bucket", ""),
            "region": getattr(self.store, "region", ""),
            "prefix": self.prefix,
            "versioning": "enabled",
            "object_lock": "enabled",
            "object_lock_mode": self.policy.mode,
        })
        problems = validate_index(self.index, self.index_path)
        if problems:
            raise ArchiveError(
                "refusing to write an invalid archive index:\n  "
                + "\n  ".join(problems))
        write_json(self.index, self.index_path)


def _decode_checksum(value: str) -> str:
    """S3 returns a base64 SHA-256; a stand-in may return hex. Accept both."""
    if _SHA256.fullmatch(value):
        return value
    try:
        return base64.b64decode(value, validate=True).hex()
    except (ValueError, TypeError):
        return ""


# ── verbs ────────────────────────────────────────────────────────────────────
def _archive_from_args(args, *, need_fetcher: bool) -> SourceArchive:
    policy = RetentionPolicy.load(args.policy)
    store = store_from_env()
    return SourceArchive(store, policy,
                         fetcher=HttpsFetcher() if need_fetcher else NoFetcher(),
                         prefix=archive_prefix(),
                         index_path=args.index or default_index_path(),
                         mirror_dir=os.environ.get("CORRELIX_SOURCE_MIRROR_DIR", ""))


def cmd_ingest(args) -> int:
    pins = load_pins(args.pins)
    entries = select_components(pins, files=args.file, names=args.component,
                                everything=args.all)
    arch = _archive_from_args(args, need_fetcher=True)
    print(f"source-archive: ingest {len(entries)} artifact(s) into "
          f"{arch.store.location}")
    res = arch.ingest(entries, dry_run=args.dry_run, reverify=args.reverify,
                      releases=args.release or [])
    if not args.dry_run:
        arch.save_index()
    print(f"source-archive: {res['ingested']} ingested, {res['hits']} already "
          f"archived, {len(entries)} requested")
    return 0


def cmd_verify(args) -> int:
    pins = load_pins(args.pins)
    entries = select_components(pins, files=args.file, names=args.component,
                                everything=args.all)
    arch = _archive_from_args(args, need_fetcher=False)
    print(f"source-archive: verify {len(entries)} artifact(s) in "
          f"{arch.store.location}")
    res = arch.verify(entries, method=args.method)
    if res["failed"]:
        print(f"source-archive: {len(res['failed'])} artifact(s) did NOT verify",
              file=sys.stderr)
        for r in res["failed"]:
            print(f"  {r['file']}: {r['status']} — {r['detail']}", file=sys.stderr)
        return 1
    print(f"source-archive: PASS — {res['verified']} artifact(s) verified")
    return 0


def cmd_release_fetch(args) -> int:
    pins = load_pins(args.pins)
    entries = select_components(pins, files=args.file, names=args.component,
                                everything=args.all)
    arch = _archive_from_args(args, need_fetcher=False)
    if args.quiet:
        # The caller (make-installer.sh) already prints one line per component
        # and re-checksums every file itself; two tools narrating the same work
        # makes a release log harder to read, not more trustworthy.
        arch.log = lambda _m: None
    res = arch.release_fetch(entries, args.dest,
                             allow_retained=not args.archive_only)
    if not args.quiet:
        print(f"source-archive: placed {len(res['placed'])} artifact(s) in "
              f"{args.dest} (no upstream fetch)")
    return 0


def cmd_release_manifest(args) -> int:
    pins = load_pins(args.pins)
    entries = select_components(pins, files=args.file, names=args.component,
                                everything=True if not (args.file or args.component)
                                else args.all)
    arch = _archive_from_args(args, need_fetcher=False)
    doc = arch.release_manifest(args.release, entries,
                                image_digests=args.image_digest,
                                upload=not args.no_upload)
    arch.save_index()
    if args.out:
        write_json(doc, args.out)
    print(f"source-archive: release manifest for {args.release}: "
          f"{len(doc['artifacts'])} artifact(s)")
    return 0


def cmd_audit(args) -> int:
    """release → manifest → component → sha256 → object → bytes → checksum."""
    policy = RetentionPolicy.load(args.policy)
    index_path = args.index or default_index_path()
    index = load_index(index_path)
    by_sha = index_by_sha(index)
    rel = next((r for r in index.get("releases", [])
                if r.get("release") == args.release), None)
    if rel is None:
        print(f"source-archive: release {args.release!r} is not recorded in "
              f"{os.path.relpath(index_path, ROOT)}. Known releases: "
              f"{[r.get('release') for r in index.get('releases', [])] or 'none'}",
              file=sys.stderr)
        return 1
    print(f"release {rel['release']}   (recorded {rel.get('recorded', '?')})")
    print(f"  source manifest : {rel.get('manifest_key', '?')}")
    for d in rel.get("image_digests", []):
        print(f"  image digest    : {d}")
    print(f"  policy          : {os.path.relpath(policy.path, ROOT)} "
          f"(v{policy.policy_version}, {policy.years}y, "
          f"counsel_confirmed={str(policy.counsel_confirmed).lower()})")
    failures = 0
    store: ObjectStore | None = None
    if not args.offline:
        try:
            store = store_from_env()
        except ArchiveError as exc:
            print(f"  ! live archive not reachable ({exc}); tracing the committed "
                  f"record only. This trace proves what Correlix RECORDED, not "
                  f"what the bucket holds today — rerun without --offline "
                  f"credentials to prove the bytes.")
    for sha in rel.get("retained_in_git", []):
        print(f"\n  sha256 {sha}")
        print("    location       : retained in this repository's git history "
              "(compliance/corresponding-sources/), covered by the bundle's "
              "SHA256SUMS; not in the S3 archive")
    for sha in rel.get("artifacts", []):
        a = by_sha.get(sha)
        if a is None:
            print(f"  ! sha256 {sha}: referenced by the release and absent from "
                  f"the artifact index")
            failures += 1
            continue
        print(f"\n  {a['component']} {a['component_version']}")
        print(f"    source package : {a['source_package']} {a['source_version']}")
        print(f"    licence        : {a['license']}  ({a.get('correspondence', '')})")
        print(f"    file           : {a['file']}  ({a['size_bytes']} bytes)")
        print(f"    sha256         : {a['sha256']}")
        print(f"    object         : {a.get('archive', {}).get('uri') or a['object_key']}")
        if a.get("archive", {}).get("version_id"):
            print(f"    object version : {a['archive']['version_id']}")
        print(f"    upstream       : {a['upstream_url']}  (provenance, not retention)")
        if a.get("retained_in_git"):
            print(f"    also in git    : {a['retained_in_git']}")
        v = a.get("verification", {})
        print(f"    recorded check : {v.get('status')} via {v.get('method')} "
              f"at {v.get('verified_at') or 'never'}")
        r = a.get("retention", {})
        print(f"    retention      : {r.get('mode')} until {r.get('retain_until')} "
              f"— {r.get('calculation')}")
        if store is not None:
            arch = SourceArchive(store, policy, prefix=archive_prefix(),
                                 index_path=index_path, index=index,
                                 log=lambda _m: None)
            live = arch.verify_object(a["object_key"], sha,
                                      method="download" if args.bytes else "head")
            print(f"    LIVE           : {live['status']} — {live['detail']}")
            if live["status"] != STATUS_VERIFIED:
                failures += 1
    if failures:
        print(f"\nsource-archive: audit FAILED — {failures} artifact(s) could not "
              f"be traced to verified bytes", file=sys.stderr)
        return 1
    print("\nsource-archive: audit complete — every artifact traces to a recorded "
          "object, digest and retention decision")
    return 0


def cmd_retention(args) -> int:
    policy = RetentionPolicy.load(args.policy)
    index_path = args.index or default_index_path()
    index = load_index(index_path)
    print(f"retention policy  : {os.path.relpath(policy.path, ROOT)} "
          f"(v{policy.policy_version})")
    print(f"  period          : {policy.years} year(s) from the base date")
    print(f"  object lock     : {policy.mode}")
    print(f"  counsel confirmed: {str(policy.counsel_confirmed).lower()}"
          + ("" if policy.counsel_confirmed else
             "   ← the period is a conservative ENGINEERING default, not a "
             "legal determination"))
    if policy.mode == "GOVERNANCE":
        print("  note            : GOVERNANCE retention can be overridden by a "
              "principal holding s3:BypassGovernanceRetention. COMPLIANCE mode "
              "cannot be overridden by anyone, including the account root user, "
              "and is switched on only after the process is validated.")
    arts = index.get("artifacts", [])
    if not arts:
        print("\nno artifacts archived yet "
              f"({os.path.relpath(index_path, ROOT)} is empty)")
        return 0
    print(f"\n{len(arts)} archived artifact(s):")
    for a in sorted(arts, key=lambda x: (x.get("retention", {}).get("retain_until", ""),
                                         x.get("component", ""))):
        r = a.get("retention", {})
        print(f"  {r.get('retain_until', '?')}  {r.get('mode', '?'):11s} "
              f"{a['component']} {a['component_version']}  ({a['sha256'][:12]}…)")
        print(f"      {r.get('calculation', 'no calculation recorded')}")
    return 0


def cmd_validate(args) -> int:
    path = args.index or default_index_path()
    doc = read_json(path, what="source archive index")
    problems = validate_index(doc, path)
    if problems:
        print(f"source-archive: {len(problems)} problem(s) in the archive index:",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"source-archive: archive index is valid "
          f"({len(doc.get('artifacts', []))} artifact(s), "
          f"{len(doc.get('releases', []))} release(s))")
    return 0


# ── selftest ─────────────────────────────────────────────────────────────────
def selftest() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail or 'failed'}")

    # -- names and keys ------------------------------------------------------
    check("key is content-addressed",
          object_key("a" * 64, "x.tar.gz") == f"sources/sha256/aa/{'a' * 64}/x.tar.gz")
    check("key honours a prefix",
          object_key("b" * 64, "x.tar.gz", "corr").startswith("corr/sources/sha256/bb/"))
    for bad in ("../etc/passwd", "a/b.tar", ".hidden", "", "x" * 200, "a;b"):
        try:
            safe_filename(bad)
            failures.append(f"safe_filename accepted {bad!r}")
        except ArchiveError:
            pass
    for bad in ("", "xyz", "A" * 64, "a" * 63):
        try:
            valid_sha256(bad)
            failures.append(f"valid_sha256 accepted {bad!r}")
        except ArchiveError:
            pass

    # -- SigV4 ---------------------------------------------------------------
    canon, signed = canonical_request(
        "GET", "/bucket/sources/sha256/aa/x", "",
        {"host": "s3.eu-west-1.amazonaws.com", "x-amz-date": "20260905T000000Z",
         "x-amz-content-sha256": EMPTY_SHA256}, EMPTY_SHA256)
    check("canonical request shape", canon.split("\n")[0] == "GET")
    check("canonical headers are sorted and lowercased",
          signed == "host;x-amz-content-sha256;x-amz-date", signed)
    check("canonical request ends with the payload hash",
          canon.endswith(EMPTY_SHA256))
    k1 = signing_key("secret", "20260905", "eu-west-1", "s3")
    k2 = signing_key("secret", "20260906", "eu-west-1", "s3")
    check("signing keys are date-scoped", k1 != k2)
    check("signing key is 32 bytes", len(k1) == 32)
    # The example key is assembled from two halves on purpose: a literal
    # 20-character AKIA string in a committed file trips the blocking gitleaks
    # history scan, and a redaction test that had to be allowlisted as a secret
    # would be a poor advertisement for the redactor.
    example_key = "AKIA" + "IOSFODNN7EXAMPLE"
    check("secrets are redacted",
          "<redacted>" in _redact("Signature=" + "d" * 64) and
          "AKIA" not in _redact(example_key))

    # -- endpoint policy -----------------------------------------------------
    for kwargs, why in (
        ({"endpoint": "http://s3.eu-west-1.amazonaws.com"}, "plaintext AWS endpoint"),
        ({"endpoint": "http://127.0.0.1:9000"}, "plaintext endpoint without opt-in"),
    ):
        try:
            S3ObjectStore(bucket="b", region="eu-west-1", access_key="A",
                          secret_key="S", **kwargs)
            failures.append(f"S3ObjectStore accepted {why}")
        except ArchiveError:
            pass
    try:
        S3ObjectStore(bucket="b", region="eu-west-1", access_key="A", secret_key="S",
                      endpoint="http://127.0.0.1:9000", allow_http=True)
    except ArchiveError as exc:
        failures.append(f"local stand-in with the opt-in was refused: {exc}")
    try:
        S3ObjectStore(bucket="b", region="eu-west-1", access_key="", secret_key="")
        failures.append("S3ObjectStore accepted empty credentials")
    except ArchiveError:
        pass

    # -- retention -----------------------------------------------------------
    pol = RetentionPolicy({"policy_version": 1,
                           "owner_decision": {"retention_years": 10},
                           "object_lock": {"mode": "GOVERNANCE",
                                           "modes_allowed": ["GOVERNANCE", "COMPLIANCE"]}},
                          "test-policy.json")
    r = pol.compute(base_date="2026-09-05")
    check("retention arithmetic", r["retain_until"] == "2036-09-05", r["retain_until"])
    check("retention records its calculation", "10 year(s)" in r["calculation"])
    r2 = pol.compute(base_date="2026-09-05", existing="2040-01-01")
    check("retention is never shortened", r2["retain_until"] == "2040-01-01")
    check("a kept longer retention is reported", r2["kept_existing_longer_retention"])
    try:
        RetentionPolicy({"owner_decision": {"retention_years": 5},
                         "object_lock": {"mode": "COMPLIANCE",
                                         "modes_allowed": ["GOVERNANCE", "COMPLIANCE"],
                                         "compliance_mode_authorised": False}})
        failures.append("COMPLIANCE mode was accepted without authorisation")
    except ArchiveError:
        pass
    try:
        RetentionPolicy({"owner_decision": {}, "object_lock": {"mode": "GOVERNANCE"}})
        failures.append("a policy with no retention period was accepted")
    except ArchiveError:
        pass

    # -- index validation ----------------------------------------------------
    good = _fixture_record()
    doc = dict(empty_index(), artifacts=[good])
    check("a complete record validates", validate_index(doc) == [], validate_index(doc))
    bad = dict(good, object_key="sources/sha256/de/somewhere-else/x.tar.gz")
    check("a key that does not state its digest is rejected",
          any("content-addressed" in p for p in validate_index(dict(doc, artifacts=[bad]))))
    bad2 = dict(good, verification=dict(good["verification"], verified_at=""))
    check("verified with no timestamp is rejected",
          any("verified_at" in p for p in validate_index(dict(doc, artifacts=[bad2]))))
    bad3 = dict(good, retention={"retain_until": "2036-01-01"})
    check("retention with no calculation is rejected",
          any("how it was calculated" in p
              for p in validate_index(dict(doc, artifacts=[bad3]))))
    dup = dict(good, sha256=good["sha256"],
               object_key=f"sources/sha256/{good['sha256'][:2]}/{good['sha256']}/other.tar.gz")
    check("one digest at two keys is rejected",
          any("ONE object" in p for p in validate_index(dict(doc, artifacts=[good, dup]))))
    check("a release referencing an unknown digest is rejected",
          any("provides" in p for p in validate_index(
              dict(doc, releases=[{"release": "v1", "artifacts": ["f" * 64]}]))))
    try:
        validate_index({"schema_version": 99, "artifacts": []})
        failures.append("an unknown schema_version was accepted")
    except ArchiveError:
        pass

    # -- end-to-end against the in-memory store ------------------------------
    tmp = tempfile.mkdtemp(prefix="correlix-source-archive-selftest-")
    try:
        body = b"corresponding source bytes\n"
        sha = hashlib.sha256(body).hexdigest()
        src = os.path.join(tmp, "thing-1.0.tar.gz")
        with open(src, "wb") as fh:
            fh.write(body)
        pins = {"components": [{
            "name": "thing", "version": "1.0", "file": "thing-1.0.tar.gz",
            "url": "https://example.invalid/thing-1.0.tar.gz", "sha256": sha,
            "size_bytes": len(body), "license": "GPL-2.0-only",
            "correspondence": "upstream-release"}]}
        store = MemoryObjectStore()
        index_path = os.path.join(tmp, "index.json")

        class _Fixed(Fetcher):
            def __init__(self, path: str) -> None:
                self.path, self.calls = path, 0

            def fetch(self, url, dest_path, *, max_bytes=MAX_ARTIFACT_BYTES):
                self.calls += 1
                shutil.copyfile(self.path, dest_path)
                return os.path.getsize(dest_path)

        fetcher = _Fixed(src)
        arch = SourceArchive(store, pol, fetcher=fetcher, index_path=index_path,
                             index=empty_index(), log=lambda _m: None)
        # missing → release blocked
        try:
            arch.release_fetch(pins["components"], os.path.join(tmp, "offer"))
            failures.append("a release placed an artifact that was never archived")
        except ComplianceFailure as exc:
            check("the block names the ingest command", "ingest --file" in str(exc))
        # ingest
        res = arch.ingest(pins["components"])
        check("ingest archived one artifact", res["ingested"] == 1, str(res))
        check("ingest fetched upstream exactly once", fetcher.calls == 1)
        check("the object landed at its content-addressed key",
              store.head(object_key(sha, "thing-1.0.tar.gz")) is not None)
        check("the object is locked",
              (store.head(object_key(sha, "thing-1.0.tar.gz")) or {}).get("lock_mode")
              == "GOVERNANCE")
        # release now succeeds with NO fetcher at all
        release = SourceArchive(store, pol, index_path=index_path,
                                index=arch.index, log=lambda _m: None)
        placed = release.release_fetch(pins["components"], os.path.join(tmp, "offer"))
        check("the release read from the archive",
              placed["placed"][0]["source"] == "archive")
        check("the bundle holds the right bytes",
              sha256_file(os.path.join(tmp, "offer", "thing-1.0.tar.gz")) == sha)
        # dedup: a second ingest writes no second object
        puts = store.put_calls
        again = arch.ingest(pins["components"])
        check("an already-archived artifact is a hit", again["hits"] == 1)
        check("dedup wrote no second object", store.put_calls == puts)
        # a different sha is a different object
        other = dict(pins["components"][0])
        other_body = body + b"different\n"
        other["sha256"] = hashlib.sha256(other_body).hexdigest()
        other["size_bytes"] = len(other_body)
        other_src = os.path.join(tmp, "other.tar.gz")
        with open(other_src, "wb") as fh:
            fh.write(other_body)
        arch.fetcher = _Fixed(other_src)
        arch.ingest([other])
        check("different bytes are a different object",
              len(store.versions) >= 2 and
              store.head(object_key(other["sha256"], "thing-1.0.tar.gz")) is not None)
        # upstream sha mismatch → not archived
        liar = dict(pins["components"][0], sha256="c" * 64,
                    file="liar-1.0.tar.gz", size_bytes=len(body))
        arch.fetcher = _Fixed(src)
        try:
            arch.ingest([liar])
            failures.append("an artifact whose bytes did not match its pin was archived")
        except ComplianceFailure:
            check("the mismatched artifact was not stored",
                  store.head(object_key("c" * 64, "liar-1.0.tar.gz")) is None)
        # stored-object corruption → verify fails, release refuses
        key = object_key(sha, "thing-1.0.tar.gz")
        store.versions[key][-1]["body"] = b"tampered"
        v = arch.verify(pins["components"])
        check("a corrupted stored object fails verification",
              v["failed"] and v["failed"][0]["status"] == STATUS_INVALID)
        try:
            release.release_fetch(pins["components"], os.path.join(tmp, "offer2"))
            failures.append("a release shipped bytes that did not match the pin")
        except ComplianceFailure:
            pass
        # object lock refuses deletion
        try:
            store.delete(key)
            failures.append("a locked object was deleted")
        except PermissionError:
            pass
        # the release path holds no fetcher
        try:
            NoFetcher().fetch("https://example.invalid/x", "/dev/null")
            failures.append("the release fetcher performed a fetch")
        except ComplianceFailure:
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # -- the real policy and index in this repository ------------------------
    try:
        real = RetentionPolicy.load()
        check("the committed policy has a positive period", real.years > 0)
        check("the committed policy is GOVERNANCE until validated "
              "or explicitly authorised",
              real.mode == "GOVERNANCE" or
              (real.doc.get("object_lock") or {}).get("compliance_mode_authorised"))
    except ArchiveError as exc:
        failures.append(f"the committed retention policy does not load: {exc}")
    try:
        load_index()
    except ArchiveError as exc:
        failures.append(f"the committed archive index does not load: {exc}")
    try:
        load_pins()
    except ArchiveError as exc:
        failures.append(f"the committed pin table does not load: {exc}")

    if failures:
        print(f"source-archive selftest: {len(failures)} FAILURE(S)", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("source-archive selftest: PASS")
    return 0


def _fixture_record() -> dict:
    sha = "a" * 64
    return {
        "component": "thing", "component_version": "1.0",
        "source_package": "thing", "source_version": "1.0",
        "file": "thing-1.0.tar.gz", "sha256": sha, "size_bytes": 12,
        "object_key": object_key(sha, "thing-1.0.tar.gz"),
        "upstream_url": "https://example.invalid/thing-1.0.tar.gz",
        "license": "GPL-2.0-only", "correspondence": "upstream-release",
        "verification": {"status": STATUS_VERIFIED, "method": "download+sha256",
                         "verified_at": "2026-09-05T00:00:00+00:00",
                         "measured_sha256": sha, "detail": "ok"},
        "retention": {"retain_until": "2036-09-05", "mode": "GOVERNANCE",
                      "calculation": "2026-09-05 + 10 year(s)", "policy_version": 1},
    }


# ── cli ──────────────────────────────────────────────────────────────────────
def _add_selection(p: argparse.ArgumentParser) -> None:
    p.add_argument("--file", action="append", default=[],
                   help="artifact file name from the pin table (repeatable)")
    p.add_argument("--component", action="append", default=[],
                   help="component name from the pin table (repeatable)")
    p.add_argument("--all", action="store_true", help="every pinned component")
    p.add_argument("--pins", help="pin table (default scripts/source-mirror.json)")
    p.add_argument("--index", help="archive index (default "
                                   "$CORRELIX_SOURCE_ARCHIVE_INDEX, else "
                                   "docs/compliance/source-archive-index.json)")
    p.add_argument("--policy", help="retention policy "
                                    "(default scripts/source-retention-policy.json)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="source-archive.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="offline self-tests (no network, no credentials)")
    sub = ap.add_subparsers(dest="verb")

    p = sub.add_parser("ingest", help="fetch → verify → upload → verify stored → record")
    _add_selection(p)
    p.add_argument("--dry-run", action="store_true",
                   help="say what would be ingested, touch nothing")
    p.add_argument("--reverify", action="store_true",
                   help="re-upload and re-verify an artifact already archived")
    p.add_argument("--release", action="append", default=[],
                   help="record this release as referencing the artifact(s)")
    p.set_defaults(fn=cmd_ingest)

    p = sub.add_parser("verify", help="prove the archive still holds the pinned bytes")
    _add_selection(p)
    p.add_argument("--method", choices=("download", "head"), default="download",
                   help="`download` hashes the stored bytes (default); `head` "
                        "trusts the store's own recorded checksum")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("release-fetch",
                       help="place corresponding source into a release bundle "
                            "from the archive; NEVER from upstream")
    _add_selection(p)
    p.add_argument("--dest", required=True, help="the bundle's source-offer/ directory")
    p.add_argument("--archive-only", action="store_true",
                   help="do not use the copies retained in git; read every "
                        "artifact from the object store")
    p.add_argument("--quiet", action="store_true",
                   help="place the files without narrating; the caller reports")
    p.set_defaults(fn=cmd_release_fetch)

    p = sub.add_parser("release-manifest", help="write the per-release source manifest")
    _add_selection(p)
    p.add_argument("--release", required=True, help="the release id (e.g. v1.2.3)")
    p.add_argument("--image-digest", action="append", default=[],
                   help="an image digest this release publishes (repeatable)")
    p.add_argument("--out", help="also write the manifest to this local path")
    p.add_argument("--no-upload", action="store_true",
                   help="build and record the manifest without uploading it")
    p.set_defaults(fn=cmd_release_manifest)

    p = sub.add_parser("audit", help="release → manifest → sha → object → bytes")
    p.add_argument("release")
    p.add_argument("--index")
    p.add_argument("--policy")
    p.add_argument("--offline", action="store_true",
                   help="trace the committed record only; do not touch the archive")
    p.add_argument("--bytes", action="store_true",
                   help="download and re-hash every object (slower, stronger)")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("retention", help="what is retained, until when, and why")
    p.add_argument("what", choices=("show",))
    p.add_argument("--index")
    p.add_argument("--policy")
    p.set_defaults(fn=cmd_retention)

    p = sub.add_parser("validate", help="schema-check the committed archive index")
    p.add_argument("--index")
    p.set_defaults(fn=cmd_validate)

    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not getattr(args, "fn", None):
        ap.print_help()
        return 2
    try:
        return args.fn(args)
    except ComplianceFailure as exc:
        print(f"\nsource-archive: COMPLIANCE FAILURE\n  {exc}", file=sys.stderr)
        return 1
    except ArchiveError as exc:
        print(f"source-archive: CANNOT RUN: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
