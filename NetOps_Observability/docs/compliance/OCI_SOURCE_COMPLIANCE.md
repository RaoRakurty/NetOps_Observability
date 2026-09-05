# OCI image compliance — the final image is the boundary

**Owner decision 2026-09-05 (tracker 238).** Supersedes the de-facto posture
§5 of `docs/security/LICENSE_AUDIT_2026-09-03.md` recorded for inherited base
layers. The six 2026-09-04 licence decisions (D1–D6) are unchanged.

> **Correlix owns source-availability compliance for applicable copyleft
> components contained anywhere in distributed container images, including
> inherited base-image layers.**
>
> **Upstream source availability may be recorded as provenance or used for
> retrieval, but Correlix release compliance requires an independently retained
> and verified source artifact whenever Correlix policy requires corresponding
> source.**

---

## 1. The defect this closes

Until 2026-09-05 Correlix's licence inventory was derived entirely from what
Correlix **declares**:

| source | what it models |
|---|---|
| `src/backend/vendor/modules.txt` | Go modules we vendor |
| `*/package-lock.json` | npm dependencies |
| `src/correlation/requirements.txt` | pinned Python packages |
| `deployment/docker/*.yml` `image:` | third-party images we run |
| every `Dockerfile` `FROM` | base images we build on |

A shipped container is none of those. It is

```
upstream base image  (BusyBox, musl/libc, OpenSSL, apk/dpkg, …)
   + whatever a package manager pulled in
   + Correlix's own layers
```

so any software that arrives inside an inherited layer and is named nowhere in
our tree was **invisible**. `deployment/docker/Dockerfile.frontend` says
`FROM nginx:1.27-alpine@sha256:6564…` and copies a built SPA on top; nothing in
the repository mentions BusyBox. Every `netops-frontend` and `netops-nginx`
image we distribute nevertheless contains `busybox`, `busybox-binsh` and
`ssl_client` — **GPL-2.0-only**, with a real corresponding-source obligation.

The `busybox` exception in `scripts/license-data.json` therefore matched no
inventoried component and could never be answered: the audit modelled image
*references*, and BusyBox is a base *layer*.

**The fix is the model, not the entry.** The compliance boundary is now the
final resolved OCI image, addressed by its immutable digest.

---

## 2. The chain

```
build the final OCI image
      │
      ▼
resolve its immutable digest              image@sha256:…   (tags are metadata)
      │
      ▼
scan the COMPLETE final image             Syft → CycloneDX
      │
      ▼
normalize the component inventory         name · version · licence · purl ·
      │                                   package type · supplier · source
      │                                   package · layer provenance · origin
      ▼
determine the licence                     SPDX expression / list / unknown
      │
      ▼
evaluate the source obligation            GPL · LGPL · AGPL families
      │
      ▼
locate a Correlix-RETAINED artifact       scripts/source-mirror.json `provides`
      │
      ▼
verify it                                 sha256 of the bytes on disk
      │
      ▼
compliance manifest                       per image, per component
      │
      ▼
PASS / FAIL the release
```

Every step fails closed. A missing SBOM, an unparsable SBOM, an SBOM with zero
components, a checksum that does not match, or an obligation with no recorded
posture is an **error with a reason** — never a quietly shorter inventory. A
scanner failure is never converted into "zero affected packages".

---

## 3. Final-image scanning

**Tool: Syft, via `anchore/sbom-action`.** This is not a new scanner:
`.github/workflows/publish-images.yml` has generated a CycloneDX SBOM of every
pushed image digest since SC-006. What changed is that something now *reads* it.

Trivy stays where it already is (`supply-chain.yml`, filesystem scanning for
CVEs, secrets and misconfiguration). Two tools, two jobs, no duplication.

**Why the SBOM is enough.** Syft's `apk-db-cataloger` and `dpkg-db-cataloger`
read the image's own package databases, which is exactly where the inherited
packages are recorded, and it carries through the metadata the compliance
question needs:

| CycloneDX field / property | used for |
|---|---|
| `name`, `version` | component identity |
| `licenses[].license.id` / `.name`, `expression` | licence determination |
| `purl` | package type, distribution, upstream qualifier |
| `publisher` | supplier |
| `syft:metadata:originPackage` | **source package** — the artifact match key |
| `syft:location:*:layerID` | layer provenance → origin |
| `syft:metadata:gitCommitOfApkPort` | Alpine's aports commit → exact source |

**Origin.** A component is `inherited-base-layer` when every layer holding it
belongs to the pinned base image, `correlix-layer` when it appears in a layer our
Dockerfile added, `first-party` when it is a Correlix module (derived from
`src/backend/go.mod`'s own `module` line), and `unknown` when the base image's
layer set was not supplied. **Provenance is never invented** — `unknown` is a
real answer and is reported as a limitation.

---

## 4. Licence policy

The obligation is a property of the **licence**, never of a package name. There
is no `if package == "busybox"` anywhere in `scripts/oci-compliance.py`.

Mapped as requiring corresponding source: `GPL-1.0-only`, `GPL-1.0-or-later`,
`GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`,
`LGPL-2.0-only`, `LGPL-2.0-or-later`, `LGPL-2.1-only`, `LGPL-2.1-or-later`,
`LGPL-3.0-only`, `LGPL-3.0-or-later`, `AGPL-3.0-only`, `AGPL-3.0-or-later`.

Three shapes of licence evidence, kept distinct because conflating them is how a
real obligation disappears:

| shape | example | verdict |
|---|---|---|
| **expression** | `GPL-2.0-only`, `MIT AND GPL-2.0-or-later`, `BSD-3-Clause OR GPL-2.0-or-later` | resolved. `OR` is taken on its most permissive branch (dual licensing is our choice to make); `AND` requires source if any term does |
| **list** | Debian: `MIT ; GPL-2.0-only ; BSD-3-Clause` | **manual-review** if any member is copyleft. A dpkg copyright file lists every licence appearing anywhere in a source package with no stated relationship, so `MIT AND GPL` and `MIT OR GPL` are indistinguishable — guessing either way is wrong |
| **unknown** | no licence recorded, or an id outside the tables | **manual-review**. An undetermined licence is never assumed obligation-free |

A reviewed fact in `scripts/license-data.json` takes precedence **only** where
the scan could not resolve the licence (Go modules carry no licence in the
compiled binary; PyPI metadata sometimes holds the entire licence body as free
text). It never overrules a clean determination.

`operating-system` components (`alpine 3.21.3`, `debian 12`) are the SBOM's
distribution marker, not shipped packages — stated as an explicit rule with the
row kept visible, never silently dropped.

---

## 5. Corresponding source: one mechanism, not two

`scripts/source-mirror.json` is the reviewed pin table
`scripts/make-installer.sh write_source_offer()` has mirrored into every release
bundle's `source-offer/` since owner decision 2026-09-04 (licence audit D2).
**BusyBox is not a special path** — it is entries in that same table, and
`make-installer.sh` needed no change to mirror it.

An entry declares what it `provides`:

```json
"provides": [
  {"package_type": "apk", "source_package": "busybox", "upstream_version": "1.37.0"}
]
```

Matching is on the **normalized source identity** — package type, source package
(apk `originPackage` / deb upstream), and the upstream version with the
distribution revision stripped (`1.37.0-r12` → `1.37.0`, `1:2.41-5` → `2.41`).
Consequences, both deliberate:

* `busybox`, `busybox-binsh` and `ssl_client` are three packages built from one
  origin, so **one artifact serves all three** — deduplicated, with every image
  digest still recorded against it.
* BusyBox **1.36.1** matches nothing and fails. A version-blind match would ship
  the wrong source and call it compliance.

### Exact-source correspondence

An upstream release tarball at a matching version is **not** automatically the
source a distribution built — distributions carry patches and build
configuration. Alpine's `busybox` 1.37.0-r12 applies 37 patches and its own
`busyboxconfig`.

So a component can be served by two artifacts:

| `role` | what it is |
|---|---|
| `corresponding-source` | the upstream release (`busybox-1.37.0.tar.bz2`) |
| `distro-packaging` | the distribution's complete packaging at the exact build reference (`busybox-1.37.0-r12-alpine-aports.tar.gz`: APKBUILD + all patches + build config) |

`correspondence` is then **computed, not asserted**:

| value | meaning |
|---|---|
| `distro-exact` | a `distro-packaging` artifact is pinned to the SAME build reference the image's own package database records. Alpine writes the aports commit into `/lib/apk/db/installed`; Syft carries it through, and the tool compares them |
| `upstream-release` | the right program at the right version, with no packaging artifact — exact correspondence with the distribution build is **not** asserted |
| `distro-packaging-mismatch` | packaging is retained but was built from a different reference |
| `distro-packaging-unverified` | packaging is retained but the image records nothing to check it against |

Claiming more than the evidence supports is worse than claiming less.

### Where the artifacts live

**Pin table + checksums + provenance in git; tarballs in the release artifact
store.** A 2.5 MB tarball per component per release does not belong in a git
history, and the obligation is to the *recipient of the binary*, so:

| artifact | location | retention |
|---|---|---|
| pin table, checksums, provenance, licence facts | `scripts/source-mirror.json` (git) | forever, in history |
| compliance manifests + inventory | `docs/compliance/` (git) | forever, in history |
| the source archives themselves | the release bundle's `source-offer/`, covered by its `SHA256SUMS`, and uploaded as GitHub Release assets by `release-bundle.yml` | **as long as the release they support** (§8) |

An air-gapped build host sets `CORRELIX_SOURCE_MIRROR_DIR` to a directory of
pre-fetched archives. The checksum gate applies there exactly as it does to a
download: local provenance is not trusted provenance.

### Source status

| status | meaning | production release |
|---|---|---|
| `not-required` | the licence carries no corresponding-source obligation | PASS |
| `verified` | an artifact was found and its sha256 matched the pin | **PASS** |
| `pinned-not-materialized` | pinned but not present to hash | FAIL (`--release`) |
| `manual-review` | an obligation may exist but the licence could not be resolved | FAIL unless a posture is recorded |
| `missing` | required, no artifact | **FAIL** |
| `invalid` | present, wrong bytes | **FAIL** |
| `unknown` | evaluation incomplete | **FAIL** |

Upstream availability alone never reaches `verified`.

---

## 6. The register of undischarged obligations

`scripts/source-mirror.json` has a second section, `deferred`: components with a
real source obligation for which Correlix has **not yet** produced a retained
artifact. It is DATA, not a decision — recording an obligation does not
discharge it.

* every entry is **version-pinned**, so a base-image bump stops matching and the
  gate asks again. A blanket rule would hide exactly the class of defect that
  produced tracker 238.
* they are printed loudly on every run of `scripts/oci-compliance.py` and by
  `scripts/license-audit.py --check`.
* they **FAIL `--release`**. A recorded posture is not a verified artifact.
* a component in **neither** section fails every mode. Silence is never a pass.

---

## 7. Release gate

```
component discovered in the final image
        │
        ▼
  source required? ──no──▶ continue
        │yes
        ▼
  retained artifact? ──no──▶ recorded posture? ──no──▶ FAIL
        │yes                        │yes
        ▼                           ▼
   verify checksum            FAIL on --release
        │
   bad ─┴─ good
    │       └──▶ PASS
    ▼
  FAIL
```

A failure names everything needed to act on it:

```
OCI compliance failure
  Image     : netops-frontend@sha256:1553db6f…
  Component : busybox 1.37.0-r12
  License   : GPL-2.0-only [expression]
  Origin    : inherited-base-layer
  Status    : missing
  Reason    : Corresponding source is required but no verified Correlix source
              artifact exists… Upstream availability alone does not satisfy
              Correlix release policy.
```

Exit codes: `0` PASS · `1` violation · `2` cannot run.

### Where it runs

| workflow | job | mode |
|---|---|---|
| `supply-chain.yml` | `OCI image compliance (inherited layers, blocking)` | builds the inherited-layer regression image, scans it and gates it; runs the offline regression suite. Blocking on every PR |
| `publish-images.yml` | `oci-compliance` | evaluates each **pushed image digest** against the SBOM already generated there, with the retained source materialised. `--release` |
| `release-bundle.yml` | bundle smoke | asserts `source-offer/` carries every pinned artifact and that `SHA256SUMS` covers them |

---

## 8. Historical auditability and retention

A release stays auditable after the upstream image, tag, URL, package or
distribution source disappears, because the trail lives in git and in the
release assets:

```
Correlix release  →  image digest        (docs/compliance/oci-inventory.json,
                                          the per-image compliance manifest)
                  →  component + version (the same manifest)
                  →  licence obligation  (licence + confidence + policy reason)
                  →  source artifact     (file name + sha256 + upstream URL +
                                          distro build ref, scripts/source-mirror.json)
                  →  the bytes           (source-offer/ in the release bundle,
                                          covered by its SHA256SUMS)
```

**Retention rule: corresponding source is never removed earlier than the binary
release it supports.** It is shipped *inside* the same bundle and published as
assets on the same GitHub Release, so the two cannot be separated by an
independent retention decision — deleting the source means deleting the release.

**Runtime images contain no source archives.** The release is: OCI images +
SBOMs + `THIRD_PARTY_LICENSES.md` + the compliance manifest + corresponding
sources. Runtime image size is unchanged, and
`tests/test_oci_compliance.py::test_no_source_archive_is_baked_into_a_runtime_image`
keeps it that way.

---

## 9. Notices

`docs/compliance/oci-inventory.json` is read by `scripts/license-audit.py` as a
sixth discovery source (`ecosystem: oci-layer`, `usage: inherited-base-layer`),
so inherited components now appear in the generated
`docs/THIRD_PARTY_LICENSES.md` grouped by the images they ship in, with their
licence, their source status and where the retained source is:

```
| `busybox` | 1.37.0-r12 | GPL-2.0-only | origin: inherited-base-layer;
  source: verified; corresponding source retained as
  source-offer/busybox-1.37.0.tar.bz2 (distro-exact) |
```

The written offer in `license-data.json` now names BusyBox under **source
shipped with the product**, alongside syslog-ng.

`license-audit.py` does **not** re-derive the verdict: it reads the
`source_status` the compliance evaluation already reached. One policy, one
answer. Its gate fails on an inherited component whose status is `missing` or
`invalid` with no recorded posture; the licence-class ladder (PERMISSIVE →
FORBIDDEN) is deliberately not applied to inherited layers, because a distro
copyright list is evidence, not a determination, and because a separate program
in the same filesystem is mere aggregation, never linking.

---

## 10. Running it

```bash
# 1. build the image, resolve its digest, list the pinned base's layers
docker build -f deployment/docker/Dockerfile.frontend -t netops-frontend .
docker image inspect netops-frontend --format '{{.Id}}'
docker image inspect nginx:1.27-alpine@sha256:6564… \
  --format '{{range .RootFS.Layers}}{{println .}}{{end}}' | sed '/^$/d' > base.txt

# 2. scan the FINAL image (the scanner publish-images.yml already uses)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  anchore/syft:v1.18.1 docker:netops-frontend:latest -o cyclonedx-json > fe.cdx.json

# 3. materialise the retained source (the existing generic mechanism)
bash scripts/make-installer.sh --source-offer-only

# 4. evaluate
python3 scripts/oci-compliance.py \
  --sbom fe.cdx.json --image netops-frontend --digest sha256:… \
  --base-layers base.txt --source-dir dist/correlix-*/source-offer \
  --manifest /tmp/netops-frontend.compliance.json
#   add --release for production-release strictness
#   add --record-deferred to print register entries for review

# 5. refresh the committed inventory from the per-image manifests
python3 scripts/oci-compliance.py --emit-inventory docs/compliance/oci-inventory.json \
  --manifest-in /tmp/netops-api.compliance.json \
  --manifest-in /tmp/netops-correlation.compliance.json \
  --manifest-in /tmp/netops-frontend.compliance.json \
  --manifest-in /tmp/netops-nginx.compliance.json

# 6. regenerate the notices, then the SPA's copy of them
python3 scripts/license-audit.py --notices
(cd src/frontend && node scripts/gen-licenses.mjs)

python3 scripts/oci-compliance.py --selftest
python3 -m pytest tests/test_oci_compliance.py -v
```

Regenerate the regression fixtures (`tests/fixtures/oci-regression/`) only when
the pinned Alpine bases change; the checked-in SBOMs are real Syft output and
keep the test suite offline.

---

## 11. Extending it

**A new copyleft licence.** Add the SPDX id to `SOURCE_REQUIRED` in
`scripts/oci-compliance.py` and to the table in §4 above. Add a case to
`test_every_mandated_copyleft_id_creates_an_obligation`.

**A new ecosystem** (RPM, Alpine on another arch, a language package manager).
Teach `upstream_version()` how that ecosystem spells a distribution revision,
and give the pin entry a `provides` with the matching `package_type`. Nothing
else changes: the policy and the gate are ecosystem-agnostic.

**Discharging a `deferred` entry.** Add a `components` entry with the upstream
source (and, for a distribution package, its packaging archive at the exact
build reference), then delete the `deferred` row. `make-installer.sh` will
mirror it into the next bundle with no code change.

**A base-image bump.** Rescan, regenerate the inventory, and re-review the
register: pinned versions will have moved and the gate will say so.

---

## 12. Known limitations

* **Debian licence fidelity.** dpkg copyright files are lists, not expressions,
  so most Debian components land in `manual-review`. This is honest rather than
  precise; resolving it needs per-package review, not a cleverer parser.
* **The committed inventory is a snapshot.** `docs/compliance/oci-inventory.json`
  records the digests of images built on the machine that ran the scan. The
  authoritative evaluation for a release runs in `publish-images.yml` against the
  digest actually pushed. The committed copy exists so the audit and the notices
  work offline, without a Docker daemon.
* **GitLab archive stability.** The Alpine packaging artifact is a generated
  GitLab archive. It was fetched twice and was byte-identical, and GitLab
  publishes no digest of its own, so the pin is our measurement. If a future
  GitLab archive-format change breaks it, the build FAILS rather than shipping
  unverified bytes — re-measure deliberately, or serve the retained copy from
  `CORRELIX_SOURCE_MIRROR_DIR`.
* **One architecture.** The scans are amd64. A multi-arch release would need one
  evaluation per platform digest.
