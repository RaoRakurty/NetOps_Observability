# The Correlix corresponding-source archive

**Owner decision, 2026-09-05 (tracker 262).** If Correlix distributes a binary
whose licence requires corresponding source, the exact retained source artifact
must exist in **Correlix-controlled storage** for the required retention period.
That storage is **AWS S3 with Versioning and Object Lock**, in a
**Correlix company-controlled AWS account** — never a personal one.

> **Status: the tooling is complete and proven; the account is not.** There is no
> Correlix AWS account, bucket or role yet. Everything below is implemented,
> tested, and was proven end to end against a local S3-compatible stand-in
> (MinIO with Object Lock). Every AWS-dependent step is reported as
> **NOT RUN — no company account** and is switched off behind an explicit guard,
> not left to fail on a missing secret. See §11.

| | |
|---|---|
| tool | `scripts/source-archive.py` (stdlib only) |
| policy | `scripts/source-retention-policy.json` (owner-owned period) |
| git-side record | `docs/compliance/source-archive-index.json` |
| pin table | `scripts/source-mirror.json` (unchanged; still the one pin table) |
| infrastructure | `deployment/aws/compliance-archive/` (Terraform, NOT applied) |
| ingest workflow | `.github/workflows/source-ingest.yml` (disabled: `if: false`) |
| release path | `scripts/make-installer.sh` `write_source_offer()`, release mode |
| tests | `tests/test_source_archive.py` |

---

## 1. Why an upstream URL is not retention

`scripts/make-installer.sh` mirrors 35 corresponding-source artifacts into every
release bundle's `source-offer/`, each verified against a pinned sha256. Nine of
them are **fetched per release from a pinned upstream URL** — busybox, syslog-ng,
gettext, libgcrypt, libgpg-error, libidn2, libunistring, musl, and libseccomp's
`.orig` tarball. That is a checksum-verified **acquisition**. It is not
retention, for three reasons that are already facts in this repository, not
hypotheticals:

* **Upstream pools rotate.** The two `base-files` versions Correlix ships
  (`12.4+deb12u14`, `13.8+deb13u5`) had already left Debian's live pool by the
  time the 2026-09-05 audit went looking, and had to be recovered from
  `snapshot.debian.org`.
* **Upstream can refuse us specifically.** `gitlab.alpinelinux.org` answers
  GitHub-hosted runners with HTTP 418 (bot filter, observed 2026-09-05).
* **A build host's `dist/` is not a record.** A release bundle on a laptop, or a
  GitHub Release asset, is a distribution channel. Neither is a store Correlix
  can point an auditor at in year eight of a retention period.

The obligation runs to *the recipient of the binary*, for years after the
release. An artifact whose only long-term home is somebody else's web server is
an obligation Correlix does not actually control.

**So: upstream URLs are PROVENANCE and an ACQUISITION SOURCE. They are never the
compliance evidence.** That sentence is the whole design.

---

## 2. Separate INGEST from RELEASE

This is the architectural change, and everything else follows from it.

```
INGEST  (rare · deliberate · reviewer-gated · needs the network · WRITE role)
    pin table coordinates
        → HTTPS fetch from the pinned URL  (or a byte-identical retained copy)
        → verify the PINNED sha256                    ← mismatch: FAIL, archive nothing
        → PutObject, content-addressed, under Object Lock
        → VERIFY THE STORED BYTES: HeadObject + re-download + re-hash
                                                      ← mismatch: FAIL, record nothing
        → write components/<component>/<version>/metadata.json
        → record it in docs/compliance/source-archive-index.json

RELEASE (every release · READ role · NO network beyond the archive)
    pin table
        → the copy retained in git, if there is one   (re-hashed, always)
        → else the archive index → GetObject → verify sha256
        → place into the bundle's source-offer/
                                                      ← miss: FAIL THE RELEASE
```

Two properties are load-bearing:

1. **`PutObject` returning 200 proves nothing.** Ingest reads the object back
   and hashes it before it will record `verified`. `verified` is never written
   for a check that did not happen.
2. **The release path holds no upstream fetcher at all.** It is constructed with
   `NoFetcher`, whose every call raises. "The release did not touch the
   internet" is a property of the object graph, not a promise in a comment —
   `tests/test_source_archive.py::test_the_release_path_holds_no_fetcher_at_all`.

A missing archived artifact during a production release **FAILS**. There is no
silent upstream fallback; the error names the ingest command that fixes it.

---

## 3. Storage layout — content-addressed, deduplicated

```
sources/sha256/<ab>/<full-sha256>/<filename>      the bytes
components/<component>/<version>/metadata.json    human/component metadata
releases/<release>/source-manifest.json           what one release shipped
```

**Bytes decide identity, never names.**

* Two releases that ship the same tarball reference **one object**. The archive
  never holds a copy per release.
* An upstream that re-cuts a release under the same file name produces
  **different bytes → a different digest → a different object**, stored beside
  the first. The first is never overwritten, and Object Lock means it cannot be:
  it is the corresponding source of a binary Correlix already shipped.
* The key **states the digest an auditor has to reproduce**. Given only an
  object key you can verify the object without the manifest. The index refuses
  to record a key that does not contain its own sha256.

Small archives (≤ ~500 KB) **stay in git** (`compliance/corresponding-sources/`)
— that is Correlix-controlled retention too, and it costs nothing. Large
tarballs go to S3. Git always keeps the manifest, the index and the checksums
needed to **locate and verify** the large objects.

---

## 4. What is recorded, and what is never claimed

Every archived artifact carries, in
`docs/compliance/source-archive-index.json` and in its S3 metadata object:

| field | |
|---|---|
| `component`, `component_version` | the binary/package this discharges |
| `source_package`, `source_version` | the source identity |
| `source_identity_basis` | **how we know that** — see below |
| `file`, `sha256`, `size_bytes` | the artifact |
| `object_key`, `archive.uri`, `archive.version_id` | where the bytes are |
| `upstream_url`, `upstream_verified_against` | provenance, and whether the digest is upstream-published or our own measurement |
| `license`, `correspondence` | the obligation and how exactly the source matches the binary |
| `distro_package` | distribution patches / packaging / build configuration, where a distribution is the source |
| `image_digests`, `releases` | which images and releases reference it |
| `verification` | status, method, timestamp, measured digest, object version |
| `retention` | mode, `retain_until`, policy version, and the calculation |
| `retained_in_git` | the git copy, when there is one |

**Never claim exact correspondence on incomplete evidence.** Where the pin table
does not distinguish a distribution source package from the upstream component,
the record says so in `source_identity_basis` rather than asserting a
correspondence nobody established. `oci-compliance.py` makes the same
distinction in its `correspondence` field (`distro-exact` vs `upstream-release`
vs `distro-packaging-unverified`); this file does not weaken it.

---

## 5. Retention

`scripts/source-retention-policy.json` holds **one owner-owned field**:

```json
"owner_decision": { "retention_years": 10, "counsel_confirmed": false }
```

The tooling does **arithmetic only**. It never encodes a legal rule — not
"end-of-support + 3 years", not anything else. GPL-2.0 §3(b) names three years;
GPL-3.0 §6(b) names three years or the life of the product's support, whichever
is longer; neither answers what a court expects of the company that shipped the
binary. **Counsel confirms the legal requirement**; until
`counsel_confirmed` is `true` and `counsel_confirmed_by` names a real reviewer,
every trace this tool prints says the period is a conservative engineering
default, and no document generated from it claims otherwise.

Ten years is chosen because the error is asymmetric: over-retaining costs
storage, under-retaining is a licence violation that cannot be repaired
afterwards, because the bytes are gone.

**Retention is monotonic.** A computed date earlier than one already stamped is
discarded and the existing date kept, and the run says so. Editing the period
downwards changes only what *future* ingests stamp. Ordinary CI cannot reduce a
retention at all: the read role has neither `s3:PutObjectRetention` nor
`s3:BypassGovernanceRetention`, and the ingest role has the first but not the
second.

### GOVERNANCE now, COMPLIANCE later

| mode | who can shorten or delete before expiry |
|---|---|
| **GOVERNANCE** (today) | only a principal holding `s3:BypassGovernanceRetention` — restricted by the bucket policy to the named human administrators |
| **COMPLIANCE** (after validation) | **nobody.** Not the ingest role. Not an administrator. Not the AWS account root user. Not AWS Support. |

COMPLIANCE mode is **intentionally impossible to override during the retention
period**, and that is the reason it is not the default: an object written with a
wrong 10-year COMPLIANCE lock occupies paid storage for ten years with no
appeal. Switching requires (1) the full ingest → verify → release path proven
against the real bucket, (2) a counsel-confirmed period, (3) an owner decision
recorded in the policy file. `RetentionPolicy` refuses to load a policy that says
COMPLIANCE without `compliance_mode_authorised: true`, so the switch cannot
happen by editing one word.

---

## 6. Credentials: OIDC, short-lived, and separated

**No long-lived AWS key exists anywhere in this design.** GitHub mints an OIDC
token for a workflow run; STS exchanges it for credentials that expire in an
hour. Nothing to rotate, nothing to leak, nothing that still works after the
workflow that used it is deleted.

```
ci-read        every release build     GetObject · HeadObject · prefix-scoped ListBucket
                                       explicitly DENIED every mutation
source-ingest  source-ingest.yml only  PutObject · PutObjectRetention (extend) · read-back
                                       no delete · no bypass · no bucket administration
administrators >= 2 NAMED HUMANS       the only bypass / legal-hold / configuration path
```

* The trust policies are scoped to **one repository and one GitHub Environment**
  — never `repo:<org>/*`, which any workflow in any repository of the org could
  assume. A fork PR cannot reach a protected environment, so it gets nothing.
* The ingest role is additionally pinned to **one workflow file** via the
  `job_workflow_ref` claim, so a new workflow cannot quietly acquire write
  access to the compliance archive.
* Both roles carry a **permissions boundary** they cannot exceed whatever policy
  someone attaches later.
* **At least two administrators** — `var.admin_principal_arns` has no default
  and Terraform validates `length >= 2`. A single-employee dependency on
  compliance evidence is the failure that requirement exists to prevent.
  **This repository names nobody**: an invented administrator reads as a
  decision somebody made.
* **CloudTrail data events** on the bucket record who read, wrote, or attempted
  a retention change.

The IAM documents live in `deployment/aws/compliance-archive/policies/*.json` as
**data**, so `tests/test_source_archive.py` parses them and asserts what the read
role does not allow. A live IAM test is **NOT RUN** and cannot be until the
account exists.

### Rotating a role

Roles hold no material to rotate — the credential is minted per run. Rotation
means *changing what a role may do or who may assume it*: edit
`policies/*.json`, `terraform plan`, read the plan, apply. The tests fail if a
mutation appears in the read role's allow set or leaves its deny set.

---

## 7. Failure behaviour (a production release fails closed)

| condition | result |
|---|---|
| the archived source is missing | **FAIL** — the message names `source-archive.py ingest --file …` |
| the pinned sha256 does not match the upstream bytes | **FAIL at ingest**, nothing is archived |
| the stored object's bytes do not match the pin | **FAIL** — verify reports `invalid`, release refuses |
| the object is unreadable / access denied | **FAIL** — a denial is not an answer about whether the artifact exists |
| the archive index is invalid | **FAIL to load at all** — an index that does not validate is not a weaker record, it is no record |
| required metadata cannot be resolved | **FAIL** — `save_index` refuses to write an incomplete record |
| the source identity is ambiguous where exact identity is required | recorded as such, never asserted as exact |

`verified` is never reported for a check that was skipped. A `pinned` artifact
that was not materialised is `pinned-not-materialized`, not `verified`
(`oci-compliance.py`); an object that exists but whose bytes were not hashed is
`unverified`, not `verified` (`source-archive.py`).

**Security:** every retrieval is HTTPS (a plaintext endpoint is refused, and the
local-stand-in opt-out is refused outright for `*.amazonaws.com`); checksums are
verified before archival and again on the way out; file names are validated
against an allowlist so nothing from the pin table can traverse a directory or a
key prefix; downloads are bounded and temp directories removed on every path
including failure; no maintainer script or archive member is ever executed —
artifacts are moved as opaque bytes; and no AWS credential, session token or
signature reaches a log (`_redact`) or a committed file (asserted by test).

---

## 8. Using it

```bash
# what would be ingested, without touching anything
python3 scripts/source-archive.py ingest --all --dry-run

# ingest one artifact, or everything (INGEST ROLE)
python3 scripts/source-archive.py ingest --file busybox-1.37.0.tar.bz2
python3 scripts/source-archive.py ingest --all --release v1.2.3

# prove the archive still holds the pinned bytes (READ ROLE)
python3 scripts/source-archive.py verify --all            # downloads and re-hashes
python3 scripts/source-archive.py verify --all --method head   # weaker, faster

# what a release build does — archive first, never upstream
python3 scripts/source-archive.py release-fetch --all \
        --dest dist/correlix-1.2.3/source-offer

# the per-release record, and the auditor's trace
python3 scripts/source-archive.py release-manifest --release v1.2.3 --all \
        --image-digest sha256:…
python3 scripts/source-archive.py audit v1.2.3           # add --bytes to re-hash
python3 scripts/source-archive.py audit v1.2.3 --offline # committed record only

# what is retained, until when, and how the date was computed
python3 scripts/source-archive.py retention show

# schema checks
python3 scripts/source-archive.py validate
python3 scripts/oci-compliance.py --validate-archive
python3 scripts/source-archive.py --selftest
```

Environment (never a file in this repository):

```
CORRELIX_SOURCE_ARCHIVE_BUCKET / _REGION      required for any S3 verb
CORRELIX_SOURCE_ARCHIVE_ENDPOINT              an S3-compatible stand-in
CORRELIX_SOURCE_ARCHIVE_PREFIX                key prefix inside the bucket
CORRELIX_SOURCE_ARCHIVE_ADDRESSING            auto | virtual | path
CORRELIX_SOURCE_ARCHIVE_ALLOW_HTTP=1          LOCAL stand-in only; refused for AWS
CORRELIX_SOURCE_ARCHIVE_INDEX                 an alternative index path
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
```

### The release build

`scripts/make-installer.sh` `write_source_offer()` tries three sources in order:

1. **retained copies** (`CORRELIX_SOURCE_MIRROR_DIR`) — everything in
   `compliance/corresponding-sources/`, re-checksummed like a download;
2. **the Correlix archive** — `release-fetch`, only when
   `CORRELIX_SOURCE_RELEASE_MODE=1`;
3. **the pinned upstream URL** — development and daily CI only.

`CORRELIX_SOURCE_RELEASE_MODE=1` turns step 3 **off**. Every path ends at the
same sha256 gate: local provenance is not trusted provenance, and neither is
archived provenance.

---

## 9. For an auditor

You have a Correlix release. You want the corresponding source for a GPL
component, and you want to know it is the right source.

1. **The bundle already contains it.** `source-offer/` in the release bundle
   holds every artifact, with a `README` naming each component, its licence,
   its upstream URL and its sha256, and the bundle-wide `SHA256SUMS` covers the
   directory. No S3, OCI or ORAS knowledge is required, and nothing has to be
   requested from anybody. That is deliberate: GPL-2.0 §3(a) — ship the source
   with the binary — was chosen over §3(b)'s three-year written offer, because a
   promise outlives repositories and companies but a tarball in your hands does
   not.
2. **To trace it back to Correlix's record**, in git:
   `docs/compliance/oci-inventory.json` (release → image digest → component) →
   `scripts/source-mirror.json` (component → file, upstream URL, sha256) →
   `docs/compliance/source-archive-index.json` (sha256 → object key, verification,
   retention).
3. **To have Correlix reproduce the trace**:
   `scripts/source-archive.py audit <release> --bytes` prints
   release → manifest → component → sha256 → object → bytes → checksum, plus the
   retention decision and how its date was calculated.

---

## 10. Adding a new source package

1. Add the component to `scripts/source-mirror.json` with `file`, `url` (HTTPS),
   `sha256`, `size_bytes`, `license`, `verified_against` and `provides` — the
   same one pin table everything else uses. There is no second architecture.
2. If it is small (≤ ~500 KB), also commit the file to
   `compliance/corresponding-sources/` and set `retained_in_git`.
3. `python3 scripts/source-archive.py ingest --file <name> --dry-run`, read it,
   then run it for real (or dispatch `source-ingest.yml`).
4. Commit the updated `docs/compliance/source-archive-index.json`. **The archive
   is not usable by a release until the index records it** — that is the point
   of committing the index rather than trusting a bucket listing.
5. `python3 -m pytest tests/test_source_archive.py tests/test_source_offer.py -q`.

---

## 11. Proving it without an AWS account

Everything in this document except the AWS account itself has been executed.

**Proven in-process, on every commit** (`tests/test_source_archive.py`, no
credential anywhere): the ingest flow including read-back; a release blocked
when nothing is archived; an archive hit performing no upstream request; **a
release succeeding with every upstream URL dead**; an upstream checksum mismatch
archiving nothing; a corrupted stored object failing verification and blocking
the release; dedup across releases; different bytes becoming different objects;
Object Lock refusing a delete; the retention arithmetic and its monotonicity;
the IAM documents denying what a read role must never hold; the bundle placement.

**Proven against a real S3 implementation** (MinIO with Object Lock, run
locally on 2026-09-05/06): SigV4 signing, bucket creation with Object Lock,
`PutObject` with `x-amz-object-lock-mode`/`retain-until` and an
`x-amz-checksum-sha256`, `HeadObject` returning the lock and checksum,
`GetObject` read-back, all 35 pinned artifacts ingested and verified (BusyBox
fetched live from `busybox.net`, syslog-ng from GitHub, the Debian source
packages from the retained copies), a versioned `DELETE` of a locked object
refused by the server (`Object is WORM protected`), then a full
`make-installer.sh --source-offer-only` release-mode build with **every upstream
URL rewritten to an unreachable host**, producing a complete 35-artifact
`source-offer/`. `tests/test_source_archive.py::test_end_to_end_against_a_real_s3_implementation`
reruns the core of that (skipped unless `CORRELIX_SOURCE_ARCHIVE_E2E=1`).

**NOT RUN — no company account**: `terraform plan`/`apply`; creating the bucket,
roles and OIDC provider; any live IAM permission check; the OIDC credential
exchange in `source-ingest.yml` and `publish-images.yml`; the CloudTrail trail;
and therefore the real ingest that would populate
`docs/compliance/source-archive-index.json`, which is committed **empty**.

### Standing it up

`deployment/aws/compliance-archive/README.md` has the sequence. In short: create
the company AWS account, apply the Terraform, name at least two administrators,
set the repository Actions variables, remove the `if: false` from
`source-ingest.yml`, dispatch it with `dry_run: true`, then for real, and commit
the resulting index.

---

## 12. What this does not change

* **One pin table.** `scripts/source-mirror.json` is still the single reviewed
  list, and `scripts/oci-compliance.py` still evaluates obligations against it.
  This adds a durable home for the bytes; it does not add a second inventory.
* **The bundle still ships the source.** GitHub Releases and GHCR remain
  distribution channels and are **never** the sole retention store; the archive
  is the record behind them.
* **Small archives stay in git.** Nothing was moved out of
  `compliance/corresponding-sources/`.
* **Today's CI is unchanged.** With no bucket configured, `write_source_offer()`
  behaves exactly as before — retained copies first, pinned upstream after — and
  `--require-archive` is not passed. The new gates that always run are the index
  schema check and the offline test suite.

---

## 13. Cross-references

* `docs/compliance/OCI_SOURCE_COMPLIANCE.md` — how an obligation is discovered
  in the first place (final image → SBOM → licence → obligation → artifact).
* `compliance/corresponding-sources/README.md` — what is retained in git.
* `docs/security/LICENSE_AUDIT_2026-09-03.md` §4 D2 — the owner decision to ship
  source with the binary rather than offer it.
* `scripts/CLAUDE.md` §16 — why a release script is held to the same bar as the
  Go code.
