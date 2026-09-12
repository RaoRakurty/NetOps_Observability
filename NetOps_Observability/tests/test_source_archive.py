# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The Correlix-controlled corresponding-source archive (tracker 262).

WHAT IS ACTUALLY BEING PROVEN
-----------------------------
`scripts/make-installer.sh` mirrors every GPL/LGPL corresponding-source tarball
into each release bundle, checksum-verified. Nine of them are still FETCHED PER
RELEASE from a pinned upstream URL, and that is an acquisition, not a retention:
two `base-files` versions Correlix shipped had already left Debian's live pool
by the time the 2026-09-05 audit went looking, and gitlab.alpinelinux.org
answers GitHub-hosted runners with HTTP 418.

So the property under test is not "the tool can talk to S3". It is:

    A RELEASE MUST SUCCEED WHEN EVERY UPSTREAM URL IS DEAD,
    AND MUST FAIL WHEN CORRELIX DOES NOT HOLD THE BYTES.

`test_release_succeeds_when_every_upstream_url_is_dead` is the regression that
matters; everything else exists so that one cannot pass by accident.

HOW THESE RUN WITHOUT AWS
-------------------------
There is no company AWS account yet (tracker 262 is blocked on the owner), and
no test in this repository has ever held an AWS credential. Two seams make that
irrelevant:

  * the OBJECT STORE is an interface. `MemoryObjectStore` models the two S3
    properties the design rests on — versioning and Object Lock — so the flows
    are proven in-process.
  * the UPSTREAM FETCHER is an interface. The release path is constructed with
    `NoFetcher`, whose every call raises. "The release did not touch the
    network" is therefore asserted by construction, not hoped for.

The IAM model is tested as DATA: `deployment/aws/compliance-archive/policies/*.json`
are parsed and asserted to deny what a read role must never hold. A live IAM
test is NOT RUN and cannot be until the account exists.

The full loop against a real S3 implementation (MinIO with Object Lock) lives at
the bottom, skipped unless CORRELIX_SOURCE_ARCHIVE_E2E=1 with an endpoint.

Run:  python3 -m pytest tests/test_source_archive.py -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
TOOL = os.path.join(ROOT, "scripts", "source-archive.py")
POLICY = os.path.join(ROOT, "scripts", "source-retention-policy.json")
INDEX = os.path.join(ROOT, "docs", "compliance", "source-archive-index.json")
PINS = os.path.join(ROOT, "scripts", "source-mirror.json")
INSTALLER = os.path.join(ROOT, "scripts", "make-installer.sh")
IAC = os.path.join(ROOT, "deployment", "aws", "compliance-archive")
POLICIES = os.path.join(IAC, "policies")


def _load_tool():
    spec = importlib.util.spec_from_file_location("correlix_source_archive", TOOL)
    assert spec and spec.loader, TOOL
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sa = _load_tool()


# ── fixtures ─────────────────────────────────────────────────────────────────
class RecordingFetcher(sa.Fetcher):
    """An upstream that works, and counts every time it was reached for."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def fetch(self, url, dest_path, *, max_bytes=sa.MAX_ARTIFACT_BYTES):
        self.calls.append(url)
        with open(dest_path, "wb") as fh:
            fh.write(self.payload)
        return len(self.payload)


class DeadUpstreamFetcher(sa.Fetcher):
    """Every upstream URL is gone — the state this whole mechanism assumes will
    eventually be true of every URL in the pin table."""

    def fetch(self, url, dest_path, *, max_bytes=sa.MAX_ARTIFACT_BYTES):
        raise sa.ArchiveError(f"cannot fetch {url}: [Errno -2] Name or service not known")


BODY = b"# corresponding source for a thing\nint main(void){return 0;}\n"
SHA = hashlib.sha256(BODY).hexdigest()


def pin_entry(**over) -> dict:
    entry = {
        "name": "thing", "version": "1.0", "file": "thing-1.0.tar.gz",
        "url": "https://upstream.invalid/thing-1.0.tar.gz", "sha256": SHA,
        "size_bytes": len(BODY), "license": "GPL-2.0-only",
        "correspondence": "upstream-release", "retained_in_git": "",
    }
    entry.update(over)
    return entry


@pytest.fixture
def policy():
    return sa.RetentionPolicy.load(POLICY)


@pytest.fixture
def store():
    return sa.MemoryObjectStore("correlix-archive-test")


def archive(store, policy, tmp_path, *, fetcher=None):
    return sa.SourceArchive(
        store, policy, fetcher=fetcher,
        index_path=str(tmp_path / "index.json"), index=sa.empty_index(),
        log=lambda _m: None)


# ── 1. nothing archived → ingest required, release blocked ───────────────────
def test_a_release_is_blocked_when_the_artifact_was_never_archived(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path)          # NoFetcher by construction
    with pytest.raises(sa.ComplianceFailure) as exc:
        arch.release_fetch([pin_entry()], str(tmp_path / "source-offer"))
    text = str(exc.value)
    assert "NOT in the Correlix source archive" in text
    assert "ingest --file thing-1.0.tar.gz" in text, (
        "a release failure must name the command that fixes it")
    assert "upstream.invalid" in text and "provenance, not retention" in text
    assert not (tmp_path / "source-offer" / "thing-1.0.tar.gz").exists(), (
        "a blocked release must leave no half-placed artifact behind")


def test_an_unverified_index_record_does_not_satisfy_a_release(
        store, policy, tmp_path):
    """A record whose verification never reached `verified` is not evidence."""
    fetcher = RecordingFetcher(BODY)
    arch = archive(store, policy, tmp_path, fetcher=fetcher)
    arch.ingest([pin_entry()])
    rec = arch.index["artifacts"][0]
    rec["verification"] = dict(rec["verification"], status=sa.STATUS_UNVERIFIED)
    with pytest.raises(sa.ComplianceFailure, match="Only a `verified` artifact"):
        arch.release_fetch([pin_entry()], str(tmp_path / "source-offer"))


# ── 2. the initial ingest ────────────────────────────────────────────────────
def test_initial_ingest_fetches_verifies_uploads_and_verifies_the_stored_bytes(
        store, policy, tmp_path):
    fetcher = RecordingFetcher(BODY)
    arch = archive(store, policy, tmp_path, fetcher=fetcher)

    res = arch.ingest([pin_entry()])

    assert res["ingested"] == 1
    assert fetcher.calls == ["https://upstream.invalid/thing-1.0.tar.gz"]
    key = sa.object_key(SHA, "thing-1.0.tar.gz")
    head = store.head(key)
    assert head is not None, "the artifact was not stored at its content-addressed key"
    assert head["sha256"] == SHA
    rec = arch.index["artifacts"][0]
    assert rec["verification"]["status"] == sa.STATUS_VERIFIED
    assert rec["verification"]["method"] == "download+sha256", (
        "the stored bytes must be READ BACK; PutObject returning success proves "
        "nothing about what is stored")
    assert rec["verification"]["measured_sha256"] == SHA
    assert rec["verification"]["verified_at"], (
        "`verified` may never be recorded for a check that did not happen")


def test_ingest_stamps_object_lock_retention_from_the_committed_policy(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    head = store.head(sa.object_key(SHA, "thing-1.0.tar.gz"))
    assert head["lock_mode"] == policy.mode
    assert head["retain_until"], "an archived artifact must carry a retention date"
    ret = arch.index["artifacts"][0]["retention"]
    assert ret["calculation"], "the date must be reproducible from what is recorded"
    assert str(policy.years) in ret["calculation"]
    assert ret["policy_file"].endswith("source-retention-policy.json")


def test_ingest_records_every_field_the_compliance_manifest_requires(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()], releases=["v9.9.9"])
    rec = arch.index["artifacts"][0]
    for field in sa.INDEX_REQUIRED_ARTIFACT_FIELDS:
        assert rec.get(field) not in (None, "", [], {}), f"missing {field}"
    assert rec["upstream_url"].startswith("https://")
    assert rec["releases"] == ["v9.9.9"]
    assert rec["source_identity_basis"], (
        "the record must say on what basis it claims a source-package identity, "
        "never assert an exact correspondence it cannot support")
    arch.save_index()   # writes only if the schema validates
    assert sa.validate_index(json.load(open(arch.index_path, encoding="utf-8")),
                             arch.index_path) == []


def test_the_component_metadata_object_is_written_beside_the_bytes(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    meta_key = sa.component_metadata_key("thing", "1.0")
    blob = store.get_bytes(meta_key)
    assert blob, "human-readable component metadata must exist alongside the blob"
    doc = json.loads(blob)
    assert doc["component"] == "thing"
    assert doc["artifacts"][0]["sha256"] == SHA


# ── 3. an existing artifact is a hit, and the release needs no upstream ──────
def test_an_already_archived_artifact_is_a_hit_with_no_upstream_request(
        store, policy, tmp_path):
    first = RecordingFetcher(BODY)
    arch = archive(store, policy, tmp_path, fetcher=first)
    arch.ingest([pin_entry()])
    assert len(first.calls) == 1

    second = RecordingFetcher(BODY)
    arch.fetcher = second
    res = arch.ingest([pin_entry()])

    assert res["hits"] == 1 and res["ingested"] == 0
    assert second.calls == [], (
        "an artifact already archived must not be fetched from upstream again")


def test_the_release_path_holds_no_fetcher_at_all(store, policy, tmp_path):
    """Constructed, not asserted after the fact: `NoFetcher` raises on any call."""
    arch = archive(store, policy, tmp_path)
    assert isinstance(arch.fetcher, sa.NoFetcher)
    with pytest.raises(sa.ComplianceFailure, match="never from the internet"):
        arch.fetcher.fetch("https://anything.invalid/x", str(tmp_path / "x"))


# ── 4. THE REGRESSION: dead upstream, live release ───────────────────────────
def test_release_succeeds_when_every_upstream_url_is_dead(store, policy, tmp_path):
    """The property the whole mechanism exists for.

    Ingest once while upstream still answers. Then upstream disappears — every
    URL in the pin table resolves to nothing, exactly as `base-files` did — and
    the release still ships the right bytes, from Correlix's own store.
    """
    ingest = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    ingest.ingest([pin_entry()])

    release = sa.SourceArchive(store, policy, fetcher=DeadUpstreamFetcher(),
                               index_path=str(tmp_path / "index.json"),
                               index=ingest.index, log=lambda _m: None)
    offer = tmp_path / "bundle" / "source-offer"
    res = release.release_fetch([pin_entry()], str(offer))

    placed = offer / "thing-1.0.tar.gz"
    assert placed.exists(), "the bundle has no corresponding source"
    assert hashlib.sha256(placed.read_bytes()).hexdigest() == SHA
    assert res["placed"][0]["source"] == "archive"
    assert res["placed"][0]["object_key"] == sa.object_key(SHA, "thing-1.0.tar.gz")


def test_a_copy_retained_in_git_is_used_and_still_rehashed(store, policy, tmp_path,
                                                           monkeypatch):
    """Small archives stay in git. That is retention too — and it is still not
    trusted provenance: the copy is re-hashed exactly like a download."""
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(BODY)
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    entry = pin_entry(retained_in_git="retained/thing-1.0.tar.gz")

    arch = archive(store, policy, tmp_path)      # no fetcher, nothing archived
    res = arch.release_fetch([entry], str(tmp_path / "offer"))
    assert res["placed"][0]["source"] == "git-retained"

    (retained / "thing-1.0.tar.gz").write_bytes(b"tampered in the working tree")
    with pytest.raises(sa.ComplianceFailure,
                       match="Local provenance is not trusted provenance"):
        arch.release_fetch([entry], str(tmp_path / "offer2"))


# ── 5/6. checksum failures, both ends ────────────────────────────────────────
def test_a_sha_mismatch_from_upstream_fails_and_archives_nothing(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path,
                   fetcher=RecordingFetcher(b"these are not the pinned bytes"))
    with pytest.raises(sa.ComplianceFailure) as exc:
        arch.ingest([pin_entry()])
    assert "Nothing was archived" in str(exc.value)
    assert "never adjust the checksum to match a download" in str(exc.value)
    assert store.put_calls == 0, "bad bytes must never reach the archive"
    assert store.head(sa.object_key(SHA, "thing-1.0.tar.gz")) is None
    assert arch.index["artifacts"] == []


def test_a_pinned_size_that_contradicts_the_pinned_digest_fails(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    with pytest.raises(sa.ComplianceFailure, match="internally inconsistent"):
        arch.ingest([pin_entry(size_bytes=len(BODY) + 1)])
    assert store.put_calls == 0


def test_a_corrupted_stored_object_fails_verification_and_blocks_the_release(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    key = sa.object_key(SHA, "thing-1.0.tar.gz")
    store.versions[key][-1]["body"] = b"silently different bytes"

    # The release refuses the BYTES first: even with an index that still says
    # `verified`, the sha256 of what came out of the store decides.
    with pytest.raises(sa.ComplianceFailure, match="Refusing to ship unverified"):
        arch.release_fetch([pin_entry()], str(tmp_path / "offer"))
    assert not (tmp_path / "offer" / "thing-1.0.tar.gz").exists(), (
        "bad bytes must not be left in the bundle for a later step to pick up")

    # And `verify` records the failure rather than leaving a stale `verified`.
    res = arch.verify([pin_entry()])
    assert res["failed"] and res["failed"][0]["status"] == sa.STATUS_INVALID
    assert "hash to" in res["failed"][0]["detail"]
    with pytest.raises(sa.ComplianceFailure, match="Only a `verified` artifact"):
        arch.release_fetch([pin_entry()], str(tmp_path / "offer3"))


def test_a_missing_object_behind_a_present_record_fails_the_release(
        store, policy, tmp_path):
    """The index and the bucket disagreeing is never resolved optimistically."""
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    store.versions.clear()
    with pytest.raises(sa.ComplianceFailure, match="index and the bucket disagree"):
        arch.release_fetch([pin_entry()], str(tmp_path / "offer"))


def test_ingest_fails_when_the_stored_bytes_do_not_read_back(
        store, policy, tmp_path, monkeypatch):
    """PutObject succeeding is not evidence. If the read-back disagrees, ingest
    fails rather than recording a `verified` it never established."""
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    real_put = store.put

    def lying_put(key, src_path, *, sha256, **kw):
        out = real_put(key, src_path, sha256=sha256, **kw)
        store.versions[key][-1]["body"] = b"what actually landed"
        return out

    monkeypatch.setattr(store, "put", lying_put)
    with pytest.raises(sa.ComplianceFailure) as exc:
        arch.ingest([pin_entry()])
    assert "PutObject returning" in str(exc.value)
    assert arch.index["artifacts"] == [], (
        "a failed read-back must not leave a record claiming the artifact is held")


# ── 7/8. content addressing: dedup, and never dedup on names ────────────────
def test_identical_bytes_across_releases_are_one_object_with_many_references(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()], releases=["v1.0.0"])
    puts_after_first = store.put_calls
    arch.ingest([pin_entry()], releases=["v1.1.0"])
    arch.ingest([pin_entry()], releases=["v2.0.0"])

    assert store.put_calls == puts_after_first, (
        "the same tarball must never be uploaded once per release")
    assert len(arch.index["artifacts"]) == 1
    assert arch.index["artifacts"][0]["releases"] == ["v1.0.0", "v1.1.0", "v2.0.0"]
    sources = [k for k in store.versions if k.startswith("sources/")]
    assert len(sources) == 1, sources


def test_different_bytes_under_the_same_name_are_different_objects(
        store, policy, tmp_path):
    """Never dedup on names. An upstream that re-cuts a release under the same
    file name is different corresponding source, and the first one is still the
    source of a binary Correlix shipped."""
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])

    recut = b"upstream re-cut this release\n"
    recut_sha = hashlib.sha256(recut).hexdigest()
    arch.fetcher = RecordingFetcher(recut)
    arch.ingest([pin_entry(sha256=recut_sha, size_bytes=len(recut))])

    sources = sorted(k for k in store.versions if k.startswith("sources/"))
    assert len(sources) == 2, sources
    assert sa.object_key(SHA, "thing-1.0.tar.gz") in sources
    assert sa.object_key(recut_sha, "thing-1.0.tar.gz") in sources
    assert store.get_bytes(sa.object_key(SHA, "thing-1.0.tar.gz")) == BODY, (
        "the original must be untouched: it is the source of a shipped binary")


def test_object_lock_refuses_to_delete_a_retained_object(store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    key = sa.object_key(SHA, "thing-1.0.tar.gz")
    with pytest.raises(PermissionError, match="retention"):
        store.delete(key)
    assert store.head(key) is not None


# ── retention semantics ──────────────────────────────────────────────────────
def test_retention_is_never_shortened_automatically(policy):
    computed = policy.compute(base_date="2026-09-05")
    kept = policy.compute(base_date="2026-09-05", existing="2099-01-01")
    assert kept["retain_until"] == "2099-01-01"
    assert kept["kept_existing_longer_retention"] is True
    assert computed["retain_until"] < kept["retain_until"]


def test_the_committed_policy_is_owner_owned_and_conservative(policy):
    doc = json.load(open(POLICY, encoding="utf-8"))
    assert doc["owner_decision"]["retention_years"] >= 3, (
        "GPL-2.0 §3(b) alone names three years")
    assert "counsel_confirmed" in doc["owner_decision"]
    if not doc["owner_decision"]["counsel_confirmed"]:
        assert not doc["owner_decision"]["counsel_confirmed_by"], (
            "an unconfirmed policy must not name a reviewer")
        assert "NOT a legal determination" in doc["owner_decision"]["note"]
    assert doc["object_lock"]["mode"] in ("GOVERNANCE", "COMPLIANCE")


def test_compliance_mode_cannot_be_reached_by_editing_one_word():
    with pytest.raises(sa.ArchiveError, match="cannot be shortened or deleted"):
        sa.RetentionPolicy({
            "owner_decision": {"retention_years": 10},
            "object_lock": {"mode": "COMPLIANCE",
                            "modes_allowed": ["GOVERNANCE", "COMPLIANCE"],
                            "compliance_mode_authorised": False}})


def test_the_policy_documents_that_compliance_mode_is_irreversible():
    text = json.dumps(json.load(open(POLICY, encoding="utf-8")))
    assert "COMPLIANCE MODE IS INTENTIONALLY IMPOSSIBLE TO OVERRIDE" in text
    for who in ("root user", "AWS Support", "administrator"):
        assert who in text, f"the irreversibility note must name {who}"


# ── input validation and secret hygiene ──────────────────────────────────────
@pytest.mark.parametrize("name", [
    "../../etc/passwd", "a/b.tar.gz", "/abs.tar.gz", ".ssh", "", "a" * 200,
    "x;rm -rf /", "file\nname",
])
def test_an_unsafe_artifact_name_never_becomes_a_path_or_a_key(name):
    with pytest.raises(sa.ArchiveError):
        sa.safe_filename(name)


def test_the_key_states_the_digest_an_auditor_must_reproduce():
    key = sa.object_key("f" * 64, "x.tar.gz")
    assert key == f"sources/sha256/ff/{'f' * 64}/x.tar.gz"
    assert "f" * 64 in key


def test_a_plaintext_endpoint_is_refused_and_never_for_aws():
    with pytest.raises(sa.ArchiveError, match="plaintext"):
        sa.S3ObjectStore(bucket="b", region="eu-west-1", access_key="A",
                         secret_key="S", endpoint="http://127.0.0.1:9000")
    with pytest.raises(sa.ArchiveError, match="refused for AWS endpoints"):
        sa.S3ObjectStore(bucket="b", region="eu-west-1", access_key="A",
                         secret_key="S",
                         endpoint="http://s3.eu-west-1.amazonaws.com",
                         allow_http=True)


def test_credentials_come_only_from_the_environment():
    with pytest.raises(sa.ArchiveError, match="never reads a credential from a file"):
        sa.S3ObjectStore(bucket="b", region="eu-west-1", access_key="",
                         secret_key="")


def test_secrets_are_redacted_from_every_diagnostic():
    # Assembled from halves so this file carries no 20-character AKIA/ASIA
    # literal for the blocking gitleaks history scan to flag. A redaction test
    # that itself had to be allowlisted as a secret would be self-defeating.
    keys = ["AKIA" + "IOSFODNN7EXAMPLE", "ASIA" + "IOSFODNN7EXAMPLE"]
    dirty = f"{keys[0]} {keys[1]} Signature={'a' * 64} x-amz-security-token=abc"
    clean = sa._redact(dirty)
    for secret in (*keys, "a" * 64):
        assert secret not in clean, clean


def test_no_committed_file_in_the_archive_mechanism_carries_a_credential():
    """A manifest, a policy file or an IaC file holding a key would be the one
    unrecoverable mistake here: git history is forever."""
    suspects = [INDEX, POLICY]
    for base, _dirs, files in os.walk(IAC):
        suspects += [os.path.join(base, f) for f in files]
    bad = re.compile(r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
                     r"aws_secret_access_key\s*=\s*\"[^\"]+\"|"
                     r"X-Amz-Signature=)")
    for path in suspects:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert not bad.search(text), f"{path} appears to contain a credential"
        assert "X-Amz-Signature" not in text, (
            f"{path} contains a presigned URL — a bearer token in git")


# ── the committed index and pin table agree ──────────────────────────────────
def test_the_committed_index_is_schema_valid():
    doc = json.load(open(INDEX, encoding="utf-8"))
    assert sa.validate_index(doc, INDEX) == []
    assert doc["schema_version"] == sa.SCHEMA_VERSION


def test_every_indexed_artifact_is_still_pinned():
    """An archived artifact whose pin disappeared is an orphan: nothing in the
    build would place it, and nothing would notice it had gone stale."""
    index = json.load(open(INDEX, encoding="utf-8"))
    pins = json.load(open(PINS, encoding="utf-8"))
    pinned = {c["sha256"] for c in pins["components"]}
    for a in index["artifacts"]:
        assert a["sha256"] in pinned, (
            f"{a['file']} is archived but no longer pinned in source-mirror.json")


def test_the_selftest_passes():
    proc = subprocess.run([sys.executable, TOOL, "--selftest"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ── 9. the IAM model, tested as data (a live IAM test is NOT RUN) ───────────
def _policy_doc(name: str) -> dict:
    """Parse a Terraform-templated IAM document.

    `${...}` placeholders are substituted with harmless literals so the document
    parses as JSON. The test is about the ACTIONS, which no substitution
    changes.
    """
    with open(os.path.join(POLICIES, name), encoding="utf-8") as fh:
        text = fh.read()
    # Only the UNQUOTED occurrence is a JSON value; the same token also appears
    # inside the document's `_comment` prose, where it must stay a string.
    text = text.replace(": ${admin_principals}",
                        ': ["arn:aws:iam::000000000000:role/admin-1",'
                        ' "arn:aws:iam::000000000000:role/admin-2"]')
    text = re.sub(r"\$\{[a-z_]+\}", "PLACEHOLDER", text)
    return json.loads(text)


FORBIDDEN_FOR_CI = [
    "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
    "s3:PutObjectRetention", "s3:PutObjectLegalHold",
    "s3:BypassGovernanceRetention", "s3:PutBucketVersioning",
    "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration",
    "s3:DeleteBucket", "s3:PutBucketPolicy",
]


def _allowed_actions(doc: dict) -> set[str]:
    out: set[str] = set()
    for st in doc["Statement"]:
        if st.get("Effect") != "Allow":
            continue
        act = st.get("Action")
        out.update([act] if isinstance(act, str) else act)
    return out


def _denied_actions(doc: dict) -> set[str]:
    out: set[str] = set()
    for st in doc["Statement"]:
        if st.get("Effect") != "Deny":
            continue
        act = st.get("Action")
        out.update([act] if isinstance(act, str) else act)
    return out


def test_the_ci_read_role_can_never_write_delete_or_alter_retention():
    doc = _policy_doc("ci-read.json")
    allowed = _allowed_actions(doc)
    denied = _denied_actions(doc)
    for action in FORBIDDEN_FOR_CI:
        assert action not in allowed, f"the read role must not ALLOW {action}"
        assert action in denied, (
            f"{action} must be explicitly DENIED, so no later policy edit can "
            f"silently promote the read role to a write role")
    assert "*" not in allowed and "s3:*" not in allowed
    assert allowed <= {
        "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
        "s3:GetObjectVersionAttributes", "s3:ListBucket", "s3:ListBucketVersions",
    }, allowed


def test_the_ci_read_role_lists_only_the_archive_prefixes():
    doc = _policy_doc("ci-read.json")
    listing = [st for st in doc["Statement"]
               if "s3:ListBucket" in (st.get("Action") or [])
               and st["Effect"] == "Allow"]
    assert listing, "the read role needs a scoped ListBucket"
    prefixes = listing[0]["Condition"]["StringLike"]["s3:prefix"]
    assert set(prefixes) == {"sources/*", "components/*", "releases/*"}


def test_the_ingest_role_can_write_but_never_delete_or_bypass():
    doc = _policy_doc("source-ingest.json")
    allowed = _allowed_actions(doc)
    denied = _denied_actions(doc)
    assert "s3:PutObject" in allowed
    assert "s3:GetObject" in allowed, (
        "ingest must read back what it wrote; PutObject success proves nothing")
    assert "s3:PutObjectRetention" in allowed, (
        "extending a retention is safe and is part of the ingest role")
    for action in ("s3:DeleteObject", "s3:DeleteObjectVersion",
                   "s3:BypassGovernanceRetention", "s3:PutBucketVersioning",
                   "s3:PutBucketObjectLockConfiguration", "s3:DeleteBucket",
                   "s3:PutLifecycleConfiguration"):
        assert action not in allowed, f"the ingest role must not ALLOW {action}"
        assert action in denied, f"{action} must be explicitly DENIED"
    assert not any(a.startswith("iam:") or a == "*" for a in allowed)


def test_the_ingest_role_cannot_write_an_artifact_without_object_lock():
    doc = _policy_doc("source-ingest.json")
    guard = [st for st in doc["Statement"]
             if st.get("Sid") == "RequireObjectLockOnEveryWrite"]
    assert guard, "an unprotected write must be refused by the bucket, not by luck"
    assert guard[0]["Effect"] == "Deny"
    assert guard[0]["Condition"]["Null"]["s3:object-lock-mode"] == "true"


def test_the_bucket_policy_denies_plaintext_and_scopes_the_bypass():
    doc = _policy_doc("bucket-policy.json")
    sids = {st.get("Sid") for st in doc["Statement"]}
    assert "DenyPlaintextTransport" in sids
    bypass = [st for st in doc["Statement"]
              if st.get("Sid") == "OnlyNamedAdministratorsMayBypassGovernanceRetention"]
    assert bypass and bypass[0]["Effect"] == "Deny"
    admins = bypass[0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]
    assert isinstance(admins, list) and len(admins) >= 2, (
        "at least two administrators: no single-employee dependency on "
        "compliance evidence")


def test_the_oidc_trust_is_scoped_to_one_repository_never_the_whole_org():
    for name in ("trust-ci-read.json", "trust-source-ingest.json"):
        doc = _policy_doc(name)
        st = doc["Statement"][0]
        assert st["Action"] == "sts:AssumeRoleWithWebIdentity"
        cond = st["Condition"]["StringEquals"]
        sub = cond["token.actions.githubusercontent.com:sub"]
        assert sub.startswith("repo:"), sub
        assert not sub.startswith("repo:PLACEHOLDER/*"), (
            f"{name} trusts every repository in the org")
        assert ":environment:" in sub, (
            f"{name} must be scoped to a GitHub Environment, which a fork PR "
            f"cannot reach")
        assert cond["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"


def test_the_ingest_trust_is_pinned_to_one_workflow_file():
    doc = _policy_doc("trust-source-ingest.json")
    like = doc["Statement"][0]["Condition"]["StringLike"]
    assert "token.actions.githubusercontent.com:job_workflow_ref" in like, (
        "only source-ingest.yml may assume the write role; a new workflow must "
        "not be able to acquire it")


def test_no_static_aws_key_appears_anywhere_in_the_iac():
    for base, _dirs, files in os.walk(IAC):
        for f in files:
            with open(os.path.join(base, f), encoding="utf-8") as fh:
                text = fh.read()
            assert "aws_access_key_id" not in text.lower()
            assert "secret_key" not in text.lower() or f.endswith(".md"), f


def test_the_terraform_enables_object_lock_at_creation_and_versioning():
    main = open(os.path.join(IAC, "main.tf"), encoding="utf-8").read()
    assert "object_lock_enabled = true" in main, (
        "Object Lock cannot be added to an existing bucket")
    assert "aws_s3_bucket_versioning" in main and 'status = "Enabled"' in main
    assert "prevent_destroy = true" in main
    assert "aws_s3_bucket_public_access_block" in main


def test_the_administrator_list_requires_two_and_names_nobody():
    variables = open(os.path.join(IAC, "variables.tf"), encoding="utf-8").read()
    assert "length(var.admin_principal_arns) >= 2" in variables
    assert 'variable "admin_principal_arns"' in variables
    # No default at all: a default administrator list would be an invented one.
    block = variables.split('variable "admin_principal_arns"', 1)[1]
    block = block.split('variable "', 1)[0]
    assert not re.search(r"^\s*default\s*=", block, re.MULTILINE), (
        "admin_principal_arns must have no default; this repository names nobody")


# ── 10. the release bundle ───────────────────────────────────────────────────
def test_release_fetch_places_the_artifact_in_the_source_offer_directory(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    release = sa.SourceArchive(store, policy, index_path=str(tmp_path / "i.json"),
                               index=arch.index, log=lambda _m: None)
    offer = tmp_path / "correlix-1.2.3" / "source-offer"
    release.release_fetch([pin_entry()], str(offer))
    placed = offer / "thing-1.0.tar.gz"
    assert placed.is_file()
    assert hashlib.sha256(placed.read_bytes()).hexdigest() == SHA


def test_the_installer_release_mode_never_falls_back_to_upstream():
    """The wiring, read from the shipped script itself."""
    text = open(INSTALLER, encoding="utf-8").read()
    assert "CORRELIX_SOURCE_RELEASE_MODE" in text
    assert "source-archive.py" in text and "release-fetch" in text
    body = text.split("write_source_offer() {", 1)[1].split("\n}", 1)[0]
    archive_branch = body.split('elif [ "$release_mode" = "1" ]', 1)[1]
    archive_branch = archive_branch.split("\n    else\n", 1)[0]
    assert "curl" not in archive_branch, (
        "release mode must contain no upstream fetch")
    assert "does not fall back" in archive_branch


def test_the_installer_refuses_release_mode_with_no_archive_configured(tmp_path):
    env = dict(os.environ)
    env["CORRELIX_SOURCE_RELEASE_MODE"] = "1"
    env.pop("CORRELIX_SOURCE_ARCHIVE_BUCKET", None)
    proc = subprocess.run(
        ["bash", INSTALLER, "--source-offer-only", "--out", str(tmp_path)],
        capture_output=True, text=True, check=False, env=env, cwd=ROOT)
    assert proc.returncode != 0
    assert "CORRELIX_SOURCE_ARCHIVE_BUCKET" in proc.stderr, proc.stderr


def test_the_release_manifest_names_every_artifact_and_its_location(
        store, policy, tmp_path):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    digest = "sha256:" + "b" * 64
    doc = arch.release_manifest("v1.2.3", [pin_entry()], image_digests=[digest])
    assert doc["release"] == "v1.2.3"
    assert doc["image_digests"] == [digest]
    art = doc["artifacts"][0]
    for field in ("component", "component_version", "source_package",
                  "source_version", "sha256", "upstream_url", "location",
                  "verification", "retention", "license"):
        assert art.get(field), f"the release manifest omits {field}"
    assert art["location"].startswith("s3://")
    rel = arch.index["releases"][0]
    assert rel["release"] == "v1.2.3" and rel["artifacts"] == [SHA]


def test_the_audit_trace_resolves_release_to_bytes(store, policy, tmp_path,
                                                   capsys, monkeypatch):
    arch = archive(store, policy, tmp_path, fetcher=RecordingFetcher(BODY))
    arch.ingest([pin_entry()])
    arch.release_manifest("v1.2.3", [pin_entry()])
    arch.save_index()

    monkeypatch.setenv("CORRELIX_SOURCE_ARCHIVE_INDEX", arch.index_path)
    rc = sa.main(["audit", "v1.2.3", "--offline", "--policy", POLICY])
    out = capsys.readouterr().out
    assert rc == 0, out
    for expected in ("release v1.2.3", "thing 1.0", SHA,
                     sa.object_key(SHA, "thing-1.0.tar.gz"),
                     "provenance, not retention", "GOVERNANCE until"):
        assert expected in out, f"the audit trace omits {expected!r}\n{out}"


def test_the_audit_fails_on_a_release_it_cannot_trace(tmp_path, monkeypatch,
                                                      capsys):
    idx = sa.empty_index()
    idx["releases"] = [{"release": "v9.9.9", "manifest_key": "releases/v9.9.9/x",
                        "artifacts": ["d" * 64], "recorded": "2026-09-05"}]
    path = tmp_path / "index.json"
    path.write_text(json.dumps(idx), encoding="utf-8")
    monkeypatch.setenv("CORRELIX_SOURCE_ARCHIVE_INDEX", str(path))
    # An index whose release references an unknown digest must not even load.
    rc = sa.main(["audit", "v9.9.9", "--offline", "--policy", POLICY])
    assert rc == 2
    assert "provides" in capsys.readouterr().err


# ── 11. materialisation: the CI acquisition path ─────────────────────────────
# 2026-09-07: the blocking `supply-chain` workflow went red because the source
# offer was fetched from busybox.net on every run and that host stopped
# answering (curl 28 after 20 s). The gate was verifying what Correlix SHIPS
# against a third party's uptime. What is proven here is the corrected
# dependency direction:
#
#     RETAINED COPY → PREPARED MIRROR DIR → PINNED URL → ALTERNATE MIRRORS,
#     no network at all for anything retained, and the sha256 gate on EVERY path.
class CountingFetcher(sa.Fetcher):
    """Serves only the URLs it is told about; records every URL tried."""

    def __init__(self, payload: bytes, serves: tuple[str, ...] = ()) -> None:
        self.payload = payload
        self.serves = serves
        self.tried: list[str] = []

    def fetch(self, url, dest_path, *, max_bytes=sa.MAX_ARTIFACT_BYTES):
        self.tried.append(url)
        if self.serves and not any(s in url for s in self.serves):
            raise sa.FetchError(f"cannot fetch {url}: simulated connect timeout")
        with open(dest_path, "wb") as fh:
            fh.write(self.payload)
        return len(self.payload)


MIRROR_URL = "https://mirror.invalid/thing-1.0.tar.gz"


def mirrored_entry(**over) -> dict:
    return pin_entry(mirrors=[{"url": MIRROR_URL, "why": "the alternate host"}],
                     **over)


def test_a_retained_artifact_is_materialised_without_touching_the_network(
        tmp_path, monkeypatch):
    """The whole point of the fix. A component Correlix already holds must not
    be able to fail CI because someone else's server is down — so the fetcher it
    is handed is one whose every call raises."""
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(BODY)
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    fetcher = CountingFetcher(BODY)

    res = sa.materialise([mirrored_entry(retained_in_git="retained/thing-1.0.tar.gz")],
                         str(tmp_path / "offer"), fetcher=fetcher, log=lambda _m: None)

    assert res["network_used"] == 0
    assert fetcher.tried == [], "a retained artifact reached for the network"
    assert res["placed"][0]["source"] == sa.SOURCE_RETAINED
    placed = tmp_path / "offer" / "thing-1.0.tar.gz"
    assert hashlib.sha256(placed.read_bytes()).hexdigest() == SHA


def test_the_preference_order_is_retained_then_mirror_dir_then_upstream(
        tmp_path, monkeypatch):
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "thing-1.0.tar.gz").write_bytes(BODY)

    # 2. no retained copy → the prepared mirror directory, still no network.
    fetcher = CountingFetcher(BODY)
    res = sa.materialise([mirrored_entry()], str(tmp_path / "b"),
                         mirror_dir=str(prepared), fetcher=fetcher,
                         log=lambda _m: None)
    assert res["placed"][0]["source"] == sa.SOURCE_MIRROR_DIR
    assert fetcher.tried == []

    # 3. neither → upstream, and only then.
    res = sa.materialise([mirrored_entry()], str(tmp_path / "c"),
                         fetcher=fetcher, log=lambda _m: None)
    assert res["placed"][0]["source"] == sa.SOURCE_UPSTREAM
    assert fetcher.tried == [pin_entry()["url"]]


def test_an_alternate_mirror_is_used_when_the_pinned_host_is_unreachable(tmp_path):
    """busybox.net, exactly: the pinned URL times out and the identical bytes
    are one host away. The pin still decides whether they are the right bytes."""
    fetcher = CountingFetcher(BODY, serves=("mirror.invalid",))
    res = sa.materialise([mirrored_entry()], str(tmp_path / "offer"),
                         fetcher=fetcher, log=lambda _m: None)
    assert fetcher.tried == [pin_entry()["url"], MIRROR_URL], (
        "the pinned URL must be tried first and the mirror only as a fallback")
    assert res["placed"][0]["detail"] == MIRROR_URL
    assert res["placed"][0]["sha256"] == SHA


def test_materialisation_fails_when_no_host_has_the_artifact(tmp_path):
    fetcher = CountingFetcher(BODY, serves=("nowhere.invalid",))
    with pytest.raises(sa.ArchiveError) as exc:
        sa.materialise([mirrored_entry()], str(tmp_path / "offer"),
                       fetcher=fetcher, log=lambda _m: None)
    # Every host tried is named: "could not fetch <one hostname>" would hide
    # that two were asked (§16.1 — a failure is reported in full).
    assert "2 pinned location(s)" in str(exc.value)
    assert MIRROR_URL in str(exc.value)
    assert not (tmp_path / "offer" / "thing-1.0.tar.gz").exists()


def test_a_mirror_that_serves_the_wrong_bytes_is_refused_and_left_nowhere(tmp_path):
    """A mirror is a retrieval host, never an authority. Widening acquisition
    must not widen trust."""
    fetcher = CountingFetcher(b"these are not the pinned bytes")
    with pytest.raises(sa.ComplianceFailure) as exc:
        sa.materialise([mirrored_entry()], str(tmp_path / "offer"),
                       fetcher=fetcher, log=lambda _m: None)
    assert "source-mirror.json pins" in str(exc.value)
    assert "never adjust the checksum to match a download" in str(exc.value)
    assert not (tmp_path / "offer" / "thing-1.0.tar.gz").exists(), (
        "unverified bytes were left for a later step to pick up")


def test_a_retained_copy_that_no_longer_hashes_to_its_pin_is_refused(
        tmp_path, monkeypatch):
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(b"tampered in the working tree")
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    with pytest.raises(sa.ComplianceFailure,
                       match="Local provenance is not trusted provenance"):
        sa.materialise([pin_entry(retained_in_git="retained/thing-1.0.tar.gz")],
                       str(tmp_path / "offer"), fetcher=CountingFetcher(BODY),
                       log=lambda _m: None)


def test_materialisation_is_idempotent_and_re_verifies_in_place(tmp_path):
    offer = tmp_path / "offer"
    fetcher = CountingFetcher(BODY)
    sa.materialise([pin_entry()], str(offer), fetcher=fetcher, log=lambda _m: None)
    res = sa.materialise([pin_entry()], str(offer), fetcher=fetcher,
                         log=lambda _m: None)
    assert res["placed"][0]["source"] == sa.SOURCE_PRESENT
    assert len(fetcher.tried) == 1, "a populated directory was re-downloaded"

    (offer / "thing-1.0.tar.gz").write_bytes(b"corrupted between runs")
    res = sa.materialise([pin_entry()], str(offer), fetcher=fetcher,
                         log=lambda _m: None)
    assert res["placed"][0]["source"] == sa.SOURCE_UPSTREAM, (
        "a corrupted file already in the directory must be re-acquired, not trusted")


def test_no_network_mode_refuses_to_reach_upstream_at_all(tmp_path):
    with pytest.raises(sa.ComplianceFailure, match="--no-network"):
        sa.materialise([pin_entry()], str(tmp_path / "offer"),
                       fetcher=sa.NoFetcher("--no-network was requested"),
                       log=lambda _m: None)


def test_transient_errors_are_retried_and_not_here_fails_over_immediately():
    """`curl --retry 5 --retry-all-errors`, with one deliberate difference: an
    HTTP status meaning "this host does not have it" is not transient, and four
    more waits only delay the mirror that does."""
    class Flaky(sa.HttpsFetcher):
        def __init__(self, permanent: bool) -> None:
            super().__init__(attempts=5, sleep=lambda _d: None)
            self.permanent = permanent
            self.tries = 0

        def fetch_once(self, url, dest_path, *, max_bytes=sa.MAX_ARTIFACT_BYTES):
            self.tries += 1
            raise sa.FetchError(f"cannot fetch {url}", permanent=self.permanent)

    transient = Flaky(permanent=False)
    with pytest.raises(sa.FetchError):
        transient.fetch("https://upstream.invalid/x", "/dev/null")
    assert transient.tries == 5

    gone = Flaky(permanent=True)
    with pytest.raises(sa.FetchError):
        gone.fetch("https://upstream.invalid/x", "/dev/null")
    assert gone.tries == 1

    for code, permanent in ((404, True), (403, True), (500, False), (429, False)):
        assert (code in sa.FETCH_PERMANENT_STATUSES) is permanent, code


def test_a_mirror_must_be_https_and_the_pin_table_is_validated_at_load():
    with pytest.raises(sa.ArchiveError, match="not an https URL"):
        sa.acquisition_urls({"name": "thing", "url": "https://a.invalid/x",
                             "mirrors": ["http://plaintext.invalid/x"]})
    urls = sa.acquisition_urls(mirrored_entry())
    assert urls == [pin_entry()["url"], MIRROR_URL]


def test_the_busybox_and_musl_pins_carry_the_alternate_mirror_that_answers():
    """The regression that closed the 2026-09-07 CI failure, asserted on the
    committed pin table rather than remembered."""
    with open(PINS, encoding="utf-8") as fh:
        pins = json.load(fh)
    for filename in ("busybox-1.37.0.tar.bz2", "musl-1.2.5.tar.gz"):
        entry = next(c for c in pins["components"] if c["file"] == filename)
        mirrors = [m["url"] for m in entry.get("mirrors", [])]
        assert mirrors, f"{filename} has no alternate mirror; busybox.net was enough once"
        assert any(u.startswith("https://distfiles.alpinelinux.org/distfiles/")
                   for u in mirrors), mirrors
        assert all(u.endswith(filename) for u in mirrors), (
            f"a mirror for {filename} must name the same artifact")
        assert entry.get("mirrors_note"), (
            "an alternate host is a reviewed decision and says why it is trusted")


def test_neither_busybox_nor_musl_may_be_quietly_retained_in_git():
    """Retention was re-examined on 2026-09-07 and refused: both exceed the
    owner-owned git/S3 cut line. Moving that line to make a CI failure go away
    is the re-decision the policy file exists to prevent."""
    with open(POLICY, encoding="utf-8") as fh:
        policy = json.load(fh)
    threshold = policy["scope"]["git_retention_threshold_bytes"]
    assert threshold == 524288, (
        "the git/S3 cut line changed; that is an owner decision and this test is "
        "the reminder that CI convenience is not a reason to move it")
    with open(PINS, encoding="utf-8") as fh:
        pins = json.load(fh)
    for filename in ("busybox-1.37.0.tar.bz2", "musl-1.2.5.tar.gz"):
        entry = next(c for c in pins["components"] if c["file"] == filename)
        assert entry["size_bytes"] > threshold
        assert not entry["retained_in_git"]
        assert not os.path.exists(
            os.path.join(ROOT, "compliance", "corresponding-sources", filename))


def test_ci_materialises_before_the_installer_and_the_installer_holds_no_url():
    """The workflow wiring, read from the workflow itself: the acquisition step
    runs first and the installer is pointed at its output, so `--source-offer-only`
    resolves everything locally."""
    wf = os.path.join(ROOT, "..", ".github", "workflows", "supply-chain.yml")
    with open(wf, encoding="utf-8") as fh:
        text = fh.read()
    assert "source-archive.py materialise --all" in text
    mat = text.index("source-archive.py materialise")
    installer = text.index("make-installer.sh --source-offer-only")
    assert mat < installer, (
        "the source must be materialised BEFORE the installer builds the offer")
    tail = text[mat:installer]
    assert "CORRELIX_SOURCE_MIRROR_DIR: ${{ runner.temp }}/source-mirror" in tail, (
        "the installer must be pointed at the materialised mirror, not at the "
        "network")


# ── the full loop against a real S3 implementation (opt-in) ─────────────────
E2E = os.environ.get("CORRELIX_SOURCE_ARCHIVE_E2E") == "1"


@pytest.mark.skipif(not E2E, reason=(
    "needs an S3-compatible endpoint with Object Lock. Run a local stand-in "
    "and set CORRELIX_SOURCE_ARCHIVE_E2E=1 plus the CORRELIX_SOURCE_ARCHIVE_* "
    "variables; NEVER point this at a personal AWS account."))
def test_end_to_end_against_a_real_s3_implementation(tmp_path):
    """ingest → Object Lock → verify → dead upstream → release, for real.

    Proves the SigV4 signing, the Object Lock headers and the read-back against
    an actual S3 server, which no in-memory store can do.
    """
    store = sa.store_from_env()
    # Create the bucket if the stand-in has none. Object Lock is CREATE-TIME on
    # AWS and on MinIO alike: a bucket made without it cannot acquire it later.
    try:
        resp = store._request("PUT", "", payload_sha=sa.EMPTY_SHA256,
                              extra={"x-amz-bucket-object-lock-enabled": "true",
                                     "content-length": "0"})
        assert getattr(resp, "code", getattr(resp, "status", 0)) == 200
    except sa.ArchiveError as exc:
        assert "AlreadyOwnedByYou" in str(exc) or "AlreadyExists" in str(exc), exc

    policy = sa.RetentionPolicy.load(POLICY)
    arch = sa.SourceArchive(store, policy, fetcher=RecordingFetcher(BODY),
                            index_path=str(tmp_path / "index.json"),
                            index=sa.empty_index(), log=lambda _m: None)
    arch.ingest([pin_entry()])
    head = store.head(sa.object_key(SHA, "thing-1.0.tar.gz"))
    assert head and head["lock_mode"] == policy.mode
    assert head["retain_until"]

    release = sa.SourceArchive(store, policy, fetcher=DeadUpstreamFetcher(),
                               index_path=str(tmp_path / "index.json"),
                               index=arch.index, log=lambda _m: None)
    offer = tmp_path / "source-offer"
    release.release_fetch([pin_entry()], str(offer))
    assert hashlib.sha256((offer / "thing-1.0.tar.gz").read_bytes()).hexdigest() == SHA


# ── H-3.8-12: the manifest may not claim a verification it did not perform ───
#
# `release_manifest` stamped `status: verified`, `method: git-retained+sha256`
# and a `measured_sha256` taken verbatim off the PIN, on the strength of
# `os.path.isfile` alone. `release_fetch` re-hashes the identical copy, which is
# what makes the asymmetry a defect rather than a design choice: the tool knew
# how to check and the manifest — the auditor's entry point — said it had.
# ─────────────────────────────────────────────────────────────────────────────

def test_the_manifest_refuses_a_git_retained_copy_whose_bytes_are_wrong(
        store, policy, tmp_path, monkeypatch):
    """The file is present at the recorded path and is NOT the pinned source.
    Presence was the whole of the old check, so this used to produce a manifest
    stamped `verified` with a digest nobody measured."""
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(b"not the source we pinned")
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    entry = pin_entry(retained_in_git="retained/thing-1.0.tar.gz")

    arch = archive(store, policy, tmp_path)
    with pytest.raises(sa.ComplianceFailure) as exc:
        arch.release_manifest("v1.0.0", [entry], upload=False)
    text = str(exc.value)
    assert "retained in git" in text and "hashes to" in text, text
    assert SHA in text, "the failure must name the pin it was measured against"
    assert arch.index.get("releases", []) == [], (
        "a refused manifest must not leave a release recorded in the index")


def test_the_manifest_records_a_digest_it_actually_measured(
        store, policy, tmp_path, monkeypatch):
    """And the good path: `verified` is only ever written after a real read."""
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(BODY)
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    entry = pin_entry(retained_in_git="retained/thing-1.0.tar.gz")

    arch = archive(store, policy, tmp_path)
    doc = arch.release_manifest("v1.0.0", [entry], upload=False)
    ver = doc["artifacts"][0]["verification"]
    assert ver["status"] == sa.STATUS_VERIFIED
    assert ver["measured_sha256"] == SHA
    assert "re-hashed" in ver["detail"]

    # The proof that it is a MEASUREMENT and not a copy of the pin: change the
    # bytes on disk and the same call must stop saying verified.
    (retained / "thing-1.0.tar.gz").write_bytes(BODY + b"tampered")
    with pytest.raises(sa.ComplianceFailure):
        arch.release_manifest("v1.0.0", [entry], upload=False)


def test_the_manifest_will_not_invent_a_verification_for_an_unverified_record(
        store, policy, tmp_path):
    """A record with no verification block and no retained copy has nothing to
    measure. The old default stamped `verified` on it anyway."""
    fetcher = RecordingFetcher(BODY)
    arch = archive(store, policy, tmp_path, fetcher=fetcher)
    arch.ingest([pin_entry()])
    arch.index["artifacts"][0].pop("verification")
    with pytest.raises(sa.ComplianceFailure) as exc:
        arch.release_manifest("v1.0.0", [pin_entry()], upload=False)
    assert "did not happen" in str(exc.value), str(exc.value)


def test_a_release_of_only_git_retained_source_is_a_valid_record(
        store, policy, tmp_path, monkeypatch):
    """The two homes are recorded separately.

    An artifact small enough to live in git has no S3 object, so listing it
    under the release's `artifacts` would make the index fail its own
    referential check — a valid release looking like a dangling reference.
    """
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "thing-1.0.tar.gz").write_bytes(BODY)
    monkeypatch.setattr(sa, "ROOT", str(tmp_path))
    entry = pin_entry(retained_in_git="retained/thing-1.0.tar.gz")

    arch = archive(store, policy, tmp_path)
    doc = arch.release_manifest("v1.0.0", [entry], upload=False)
    assert doc["artifacts"][0]["location"] == "git:retained/thing-1.0.tar.gz"

    rel = arch.index["releases"][0]
    assert rel["artifacts"] == []
    assert rel["retained_in_git"] == [SHA]
    assert sa.validate_index(arch.index, arch.index_path) == [], (
        "a release whose source is entirely retained in git must still validate")
    arch.save_index()
