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

**Package entries vs FILE entries.** A CycloneDX document from an image can
contain both. A *package* entry (`busybox 1.37.0-r12`, `pkg:apk/alpine/busybox@…`)
is a distributed work with its own licence and its own obligation. A *file* entry
(`/etc/securetty`, `/lib/ld-musl-x86_64.so.1`, `/lib/apk/db/installed`) is one
file **inside** such a package: Syft's file catalogers list it with a name and a
digest and nothing else — no purl, no version, no licence, because a file does
not carry a licence of its own. Its licence is its owning package's, and that
package is inventoried in the same document.

Which of them a scan contains is a property of the **scanner**, not of the image:
Syft v1.18.1 reports 16 packages and no file entries for the regression image;
v1.42.3 reports the same 16 packages plus 82 file entries for the byte-identical
image. So file entries are **excluded from the obligation evaluation** — and
never silently dropped: they are counted in the verdict line (`files=N`) and
listed in the manifest under `skipped_file_entries`, with the owning package
whenever the document's own relationships name one (an owner is never inferred
from the path). An entry is a file entry only when its `type` is `file`, or when
it has no purl, no version **and** an absolute-path name; anything carrying a
purl or a version is a package claim and is evaluated as one. Nothing changes for
a PACKAGE whose licence is unknown or absent — that is still `manual-review` and
still fails closed.

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
| **list** | Debian: `MIT ; GPL-2.0-only ; BSD-3-Clause` | **manual-review** if any member is copyleft. A dpkg copyright file lists every licence appearing anywhere in a source package with no stated relationship, so `MIT AND GPL` and `MIT OR GPL` are indistinguishable — guessing either way is wrong. This is the shape a written review (§12) is allowed to settle |
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
| `distro-exact` | a `distro-packaging` artifact is pinned to the SAME build reference the image's own package database records. Each ecosystem spells that reference differently and neither spelling is guessed — Alpine writes the aports commit into `/lib/apk/db/installed`, Debian's is the SOURCE-package version (`<source name>_<source version>` names exactly one immutable source package in the archive). Syft carries both through (`gitCommitOfApkPort`, `sourceVersion`) and the tool compares them; the record says which kind it used (`distro_build_ref_kind`) |
| `upstream-release` | the right program at the right version, with no packaging artifact — exact correspondence with the distribution build is **not** asserted |
| `distro-packaging-mismatch` | packaging is retained but was built from a different reference |
| `distro-packaging-unverified` | packaging is retained but the image records nothing to check it against |

Claiming more than the evidence supports is worse than claiming less.

### Mirroring a Debian source package

For a Debian component the corresponding source is **the source package that
produced the shipped binary version**, not "the upstream project at roughly that
version". Retrieving it:

1. The image's own `/var/lib/dpkg/status` gives the binary version and, where it
   differs, the `Source:` name and version. Syft carries them as
   `syft:metadata:source` / `syft:metadata:sourceVersion`, which is what the pin
   is matched against.
2. `dists/<suite>/InRelease` is OpenPGP-signed by Debian and declares the sha256
   of `main/source/Sources.xz`; that index declares the sha256 of the `.dsc`,
   the `.orig.tar.*` and the `.debian.tar.*`. **That is the attestation chain**,
   and `verified_against` on each pin records which link it matched.
3. Fetch from `deb.debian.org/debian/pool/main/<prefix>/<source>/`. A *native*
   package (`hostname`, `netbase`, `base-files`) has no separate upstream
   tarball: the single `.tar.xz` is the whole corresponding source.
4. Pin the `.orig.tar.*` (or the native tarball) as `corresponding-source`, and
   the `.debian.tar.*` and `.dsc` as `distro-packaging` with
   `distro_package.build_ref` set to the SOURCE version. That is what earns
   `distro-exact`.

**The live pool is not an archive.** `base-files` proved it: the versions the
images ship (`12.4+deb12u14`, `13.8+deb13u5`) had already been superseded in
`pool/` by `u15`/`u6` and had to be recovered from `snapshot.debian.org` — whose
`/mr/package/<pkg>/<version>/srcfiles?fileinfo=1` gives the sha1 the file is
content-addressed by, and whose `.dsc` is signed and declares the tarball's
sha256. A recorded obligation is not a safe one; source availability decays.

### Where the artifacts live

**Pin table + checksums + provenance in git; tarballs in the release artifact
store.** A 2.5 MB tarball per component per release does not belong in a git
history, and the obligation is to the *recipient of the binary*, so:

| artifact | location | retention |
|---|---|---|
| pin table, checksums, provenance, licence facts | `scripts/source-mirror.json` (git) | forever, in history |
| compliance manifests + inventory | `docs/compliance/` (git) | forever, in history |
| small source archives (≤ ~500 KB: every Alpine packaging archive, the small Debian source packages, three small upstream tarballs) | `compliance/corresponding-sources/` (git) — taken FIRST by the installer via `CORRELIX_SOURCE_MIRROR_DIR` and re-checksummed exactly as a download would be | forever, in history |
| large upstream tarballs (gettext, libgcrypt, libgpg-error, libidn2, libunistring, musl, libseccomp's orig, busybox, syslog-ng) | **the Correlix corresponding-source archive** — AWS S3, Versioning + Object Lock, content-addressed by sha256 (`docs/compliance/SOURCE_ARCHIVE.md`, tracker 262); then the release bundle's `source-offer/`, covered by its `SHA256SUMS`, and uploaded as GitHub Release assets by `release-bundle.yml` | the retention period in `scripts/source-retention-policy.json`, enforced by Object Lock, and never shorter than the release they support (§8) |

An air-gapped build host sets `CORRELIX_SOURCE_MIRROR_DIR` to a directory of
pre-fetched archives. The checksum gate applies there exactly as it does to a
download: local provenance is not trusted provenance.

**Upstream URLs are provenance, not retention** (owner decision 2026-09-05,
tracker 262). Fetching a large tarball from `ftp.gnu.org` at release time is an
acquisition; it becomes evidence only once the bytes are in a Correlix-controlled
store. `scripts/source-archive.py` is that store's tooling and
`docs/compliance/SOURCE_ARCHIVE.md` its design: INGEST (fetch → verify → upload →
re-verify → record) is deliberately separate from RELEASE (archive lookup →
verify → bundle), and in release mode a missing archived artifact **fails the
build** rather than reaching for the internet. `--require-archive` makes this
evaluation fail an obligation whose corresponding source verified against its pin
but exists nowhere except an upstream URL.

The archive is a durable home for the SAME artifacts this pin table already
names — not a second inventory. `scripts/source-mirror.json` remains the one
reviewed list.

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

One more thing can fail a release without being a component status: a licence
review (§12) that this evaluation relied on and the owner has not signed off
(`review-not-signed-off`).

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
* every entry is **REVIEWED** (§12). Its `review` block says what the reviewer
  concluded and whether a human still has to look; a component whose review
  concluded that no obligation exists is not listed here at all.
* every Debian entry carries a `source_coordinates_ref` into
  `deferred_source_coordinates`, which names the exact source package, version,
  URL and **Debian-attested sha256** of every file that would discharge it, and
  its size. Mirroring is then mechanical, and the cost of doing it is a number
  in the file rather than an argument.
* they are printed loudly on every run of `scripts/oci-compliance.py` and by
  `scripts/license-audit.py --check`.
* they **FAIL `--release`**. A recorded posture is not a verified artifact.
* a component in **neither** section fails every mode. Silence is never a pass.

**State on 2026-09-05.** 21 inventory rows are `verified`, all of them
`distro-exact`: BusyBox and its two subpackages, the sixteen definite-copyleft
components the 2026-09-05 scan surfaced (`alpine-baselayout`(+`-data`),
`apk-tools`, `geoip`, `gettext-envsubst`, `libintl`, `libgcrypt`,
`libgpg-error`, `libidn2`, `libunistring`, `musl-utils`, `scanelf`, `hostname`,
`libseccomp2`, `netbase` ×2), and `base-files` ×2. 57 rows remain
recorded-and-unretained, essentially all of them the Debian surface of
`netops-correlation`; retaining them is ~228 MB across 38 source packages, which
is why the cheaper fix is to shrink that surface (tracker 263) rather than to
ship the archive. Whatever is shipped is retained in the Correlix
corresponding-source archive (tracker 262,
`docs/compliance/SOURCE_ARCHIVE.md`).

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
                  →  the archived object (object key + object version +
                                          verification + retain-until,
                                          docs/compliance/source-archive-index.json)
                  →  the bytes           (source-offer/ in the release bundle,
                                          covered by its SHA256SUMS; and the
                                          object in the Correlix S3 archive)
```

`scripts/source-archive.py audit <release>` walks that chain and prints it,
including how each retention date was calculated (tracker 262,
`docs/compliance/SOURCE_ARCHIVE.md`).

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
  anchore/syft:v1.42.3 docker:netops-frontend:latest -o cyclonedx-json > fe.cdx.json

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

# 7. what the licence review says, and what still needs a human
python3 scripts/oci-compliance.py --reviews

python3 scripts/oci-compliance.py --selftest
python3 -m pytest tests/test_oci_compliance.py tests/test_oci_digest_lock.py -v
```

Step 5 also refreshes the **base-image digest lock** (§13): the inventory
records every digest the build definitions pin, and `tests/test_oci_digest_lock.py`
fails if the tree moves without a fresh evaluation.

Regenerate the regression fixtures (`tests/fixtures/oci-regression/`) only when
the pinned Alpine bases change; the checked-in SBOMs are real Syft output and
keep the test suite offline. Two of them scan the SAME image with different Syft
versions on purpose — `sbom-a321.cdx.json` (v1.18.1, packages only) and
`sbom-a321-files.cdx.json` (v1.42.3, packages **plus** 82 file entries, the shape
CI produces) — so the suite proves the verdict is a property of the image and not
of the scanner's cataloger set. `.github/workflows/supply-chain.yml` pins the
Syft version it runs (`syft-version`), because a scanner that changes shape under
a gate is a gate that changes verdict without a change of evidence.

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
build reference — §5 has the Debian recipe), then delete the `deferred` row.
`make-installer.sh` will mirror it into the next bundle with no code change. If
the archive is ≤ ~500 KB, retain a copy in `compliance/corresponding-sources/`
and list it in that directory's README; otherwise leave it to be fetched per
release from its pinned URL.

**Answering a `manual-review` component.** Add an entry to
`scripts/source-review.json` (§12): the evidence file the image itself carries
with its sha256, the licences governing the shipped binary, the verdict, and one
sentence of rationale. A review that clears an obligation must be able to say
which files the copyleft stanzas cover and that this binary package does not
ship them.

**A base-image bump.** Rescan, regenerate the inventory, and re-review the
register: pinned versions will have moved and the gate will say so.

---

## 12. The licence review record

`scripts/source-review.json` is where the question a scanner cannot answer gets
answered by a person, in writing.

**The question.** A Debian `copyright` file is an unordered **list** of every
licence appearing anywhere in a *source* package. It states no relationship
between the members (so `MIT AND GPL` and `MIT OR GPL` are indistinguishable)
and it does not say which of them govern the *binary* package the image
installs. `libselinux1` ships one file, `libselinux.so.1`, from a
`Files: *  License: public-domain` tree — and its copyright file also contains a
GPL-2 stanza, for `utils/avcstat.c`, which lives in a different binary package.
Guessing either way is wrong, so the policy lands all of them in
`manual-review` and fails closed.

**The answer.** One entry per (component, version, package type):

| field | what it holds |
|---|---|
| `evidence` | a file **the image itself carries** — `/usr/share/doc/<pkg>/copyright`, the Alpine `APKBUILD` at the exact aports commit the apk database records, the apk database record itself, or an in-image licence text — with its `sha256`, so the determination can be re-checked against the same bytes |
| `governing_licences` | the licences governing the **shipped binary**, not every licence in the source tree |
| `source_required` | `true`, `false`, or `"unclear"` |
| `needs_human` | set whenever the evidence did not settle it — mandatory when `source_required` is `"unclear"` |
| `rationale` | one sentence saying *why*, naming the stanza and (where it mattered) the package's own file list in the image |
| `reviewer`, `reviewed`, `owner_signoff` | who, when, and whether the owner has signed it |

**What a review may and may not do.**

* `false` turns a `manual-review` component into `not-required`, **with the
  review recorded in the compliance manifest as the evidence**.
* `"unclear"` keeps it in manual review, with `needs_human` set.
* `true` leaves the obligation standing; the component stays in `deferred`.
* It may only answer a shape the scan could not resolve (a licence list, an
  unknown id, an absent licence, an unversioned copyleft family, an opaque
  expression). **A review that contradicts a RESOLVED copyleft expression is a
  conflict and aborts the run (exit 2)** — never a quiet downgrade.

**Owner sign-off.** Every review is `owner_signoff: false` until the owner sets
it to `true` by editing that file. `--release` refuses while any review it
relied on is unsigned — in **both** directions, including reviews that merely
confirmed an obligation, because signing is how the owner accepts the pass as a
whole. An automated first pass can make a daily build honest; it cannot clear a
customer release on its own.

```bash
python3 scripts/oci-compliance.py --reviews      # counts + every needs_human item
```

**State on 2026-09-06.** 17 review entries. 95 were written on 2026-09-05, but 82
of them described `netops-correlation`'s Debian userland and the CPython build
that sat on it; tracker 263 moved that image to `python:3.12-alpine` and those
packages are no longer shipped, so their reviews were deleted with them (a review
of bytes nobody distributes rots exactly the way the register does — `git show`
recovers them if a past release has to be re-audited). What remains: 2 Debian
reviews for `netops-api`, 9 Alpine reviews for `netops-frontend`/`netops-nginx`,
the CPython interpreter re-reviewed at its new 3.12.14 version (the licence text
is byte-identical to 3.12.13's, same sha256 — only the version moved), and three
new Alpine reviews for the packages whose metadata the scan could not resolve
(`.python-rundeps`, a virtual meta-package that installs zero files;
`sqlite-libs`, licence id `blessing`; `xz-libs`, whose origin package's licence
LIST includes GPL-2.0-or-later but whose own file list is `liblzma.so.5` alone).
**All 17 are awaiting owner sign-off.** `dash 0.5.12-12` — the other 2026-09-05
`unclear` — went away with the Debian base; the remaining unclear one:

* **`Simple Launcher 1.1.0.14`** — six **Windows** PE stubs vendored inside pip
  (`pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe`). They cannot
  execute in a Linux image and nothing links them, but the image ships no
  licence text beside them, and Correlix does not assert a licence it cannot
  read out of the artifact it ships. Note that *which package type* they are
  reported under is a property of the scanner (`binary` from the PE cataloger,
  `nuget` when a .NET cataloger names them first), so both spellings are
  recorded — a scanner-shape difference must never drop an obligation.

---

## 13. Bumping a base image (the digest lock)

A compliance evaluation is a statement about **specific bytes**. Which packages
are present, which licences they carry, which retained source matches which
binary — all of it is a property of the base images the build pinned when the
scan ran. Bump a `FROM …@sha256:` and the whole inventory silently becomes a
claim about an image nobody ships.

So the digests are locked. `--emit-inventory` writes every image the build
definitions pin by digest into `docs/compliance/oci-inventory.json` as
`pinned_base_images` (image, digest, and the file:line it is pinned in), and
**`tests/test_oci_digest_lock.py` fails when the tree and that record
disagree**. There is exactly one way for them to diverge: a re-pin without a
re-scan.

**The procedure.** Never hand-edit the inventory.

```bash
# 1. re-pin the base image, rebuild the affected Correlix images
# 2. re-scan each one and re-evaluate (§10 steps 1–4)
# 3. regenerate the inventory (this refreshes the digest lock)
# 4. RE-REVIEW THE REGISTER — this is the step the lock exists to force:
python3 scripts/oci-compliance.py --record-deferred …   # what is newly unrecorded
python3 scripts/oci-compliance.py --reviews             # what the review still covers
```

Step 4 matters because both the register and the review table are
**version-pinned**. A base-image bump moves package versions, so recorded
postures and reviews stop matching and the components fall back to failing
closed — which is the point. Re-record and re-review them deliberately, then
regenerate the notices (§10 step 6).

---

## 14. Known limitations

* **Debian licence fidelity.** dpkg copyright files are lists, not expressions,
  so Debian components cannot be resolved mechanically. That is now answered by
  per-package review (§12) rather than left as a shrug — but the reviews are an
  automated first pass over the evidence and are not a legal opinion until the
  owner signs them.
* **The residue was a surface problem, and the surface was cut (2026-09-06,
  tracker 263).** 58 of the 60 recorded obligations were the Debian userland of
  `netops-correlation` (`python:3.12-slim`) — glibc, bash, coreutils, dpkg, apt,
  perl-base, util-linux — none of it executed by the correlation engine, and
  retaining its source was ~228 MB across 38 source packages in every release
  bundle, forever. The service moved to `python:3.12-alpine`; the packages left
  the image and the obligation left with them. The register now holds **18**
  rows for that image: 12 Alpine packages (10 origin packages) and the 6
  `Simple Launcher` spellings. Those 12 are recorded the same way, with
  `deferred_source_coordinates` naming the aports packaging archive at the exact
  commit the image records (`c:` in `/lib/apk/db/installed`, self-measured
  sha256 — GitLab publishes no digest of its own, so it was fetched twice and
  required to be byte-identical) plus every upstream file with the sha512
  Alpine's own APKBUILD declares. The Correlix-controlled archive (tracker 262,
  `docs/compliance/SOURCE_ARCHIVE.md`) is where they get RETAINED; ingesting
  them is mechanical, and now roughly a tenth of the size.
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
