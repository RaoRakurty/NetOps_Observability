# Retained corresponding source (Correlix-owned copies)

Files here are **Correlix's retained copies** of corresponding source that a GPL/LGPL/AGPL/Sleepycat
component shipped in a Correlix image obliges us to make available (tracker 238, owner decision
2026-09-05: "if Correlix ships the binary, Correlix retains the compliance artifacts"). Each file is
pinned by name, upstream URL, size and sha256 in `scripts/source-mirror.json`; the installer
(`scripts/make-installer.sh`, `CORRELIX_SOURCE_MIRROR_DIR`) takes the copy from here first and
re-verifies the checksum exactly as it would a fresh download. Upstream URLs are provenance and a
retrieval source, never the compliance evidence.

**Why retention is not optional.** `base-files` is the proof: the exact versions our images ship
(`12.4+deb12u14`, `13.8+deb13u5`) had already been superseded in Debian's live pool and had to be
recovered from `snapshot.debian.org`. Upstream availability decays; a pinned URL is a retrieval
hint, not an archive.

**What is kept here and what is not.** Archives up to ~500 KB live in git — every Alpine packaging
archive, the small Debian source packages, and three small upstream tarballs. Larger upstream
tarballs belong to the **Correlix corresponding-source archive**: AWS S3 with Versioning and Object
Lock, content-addressed by sha256, in a company-controlled account (owner decision 2026-09-05,
tracker 262 — design in `docs/compliance/SOURCE_ARCHIVE.md`, tooling in
`scripts/source-archive.py`, git-side record in `docs/compliance/source-archive-index.json`).

Ingest is separate from release: an artifact is fetched from its pinned URL, verified, uploaded
under an Object Lock retention stamp and **read back and re-hashed** once; every release afterwards
reads it from the archive and never from upstream, and a missing artifact FAILS the release. Both
locations are Correlix-controlled retention — git history for the small ones, Object Lock for the
large ones — and neither is trusted without its checksum.

**The archive is empty today.** The company AWS account, bucket and roles do not exist yet (tracker
262 is blocked on the owner), so the table at the bottom of this file is still fetched per release
from its pinned URL. That is exactly the gap the archive closes, and it is why nothing was moved
out of this directory.

## Retained here (26 files, 1121 KB total)

| file | what it is | size | licence |
|---|---|---|---|
| `alpine-baselayout-3.6.8-r1-alpine-aports.tar.gz` | Alpine packaging of alpine-baselayout 3.6.8-r1 at aports commit 5f0cd78 — APKBUILD + patches + build config | 7 KB | GPL-2.0-only |
| `apk-tools-2.14.6-r3-alpine-aports.tar.gz` | Alpine packaging of apk-tools 2.14.6-r3 at aports commit 41847d6 — APKBUILD + patches + build config | 6 KB | GPL-2.0-only |
| `apk-tools-v2.14.6.tar.gz` | upstream release of apk-tools 2.14.6 | 194 KB | GPL-2.0-only |
| `base-files_12.4+deb12u14.dsc` | Debian source-package manifest for base-files 12.4+deb12u14 (bookworm) — the OpenPGP-signed .dsc that names and checksums the tarball | 1 KB | GPL-2.0-or-later |
| `base-files_12.4+deb12u14.tar.xz` | complete Debian source package for base-files 12.4+deb12u14 (native package) | 64 KB | GPL-2.0-or-later |
| `base-files_13.8+deb13u5.dsc` | Debian source-package manifest for base-files 13.8+deb13u5 (trixie) — the OpenPGP-signed .dsc that names and checksums the tarball | 1 KB | GPL-2.0-or-later |
| `base-files_13.8+deb13u5.tar.xz` | complete Debian source package for base-files 13.8+deb13u5 (native package) | 67 KB | GPL-2.0-or-later |
| `busybox-1.37.0-r12-alpine-aports.tar.gz` | Alpine packaging of busybox 1.37.0-r12 at aports commit 9c49608 — APKBUILD + patches + build config | 67 KB | GPL-2.0-only — the packaging is distributed under the package's own licence |
| `geoip-1.6.12-r5-alpine-aports.tar.gz` | Alpine packaging of geoip 1.6.12-r5 at aports commit fc95c59 — APKBUILD + patches + build config | 1 KB | LGPL-2.1-or-later |
| `GeoIP-1.6.12.tar.gz` | upstream release of geoip 1.6.12 | 462 KB | LGPL-2.1-or-later |
| `gettext-0.22.5-r0-alpine-aports.tar.gz` | Alpine packaging of gettext 0.22.5-r0 at aports commit c49ded5 — APKBUILD + patches + build config | 2 KB | GPL-3.0-or-later AND LGPL-2.1-or-later AND MIT |
| `hostname_3.25.dsc` | Debian source-package manifest for hostname 3.25 (trixie) — the OpenPGP-signed .dsc that names and checksums the tarball | 1 KB | GPL-2.0-only |
| `hostname_3.25.tar.xz` | complete Debian source package for hostname 3.25 (native package) | 12 KB | GPL-2.0-only |
| `libgcrypt-1.10.3-r1-alpine-aports.tar.gz` | Alpine packaging of libgcrypt 1.10.3-r1 at aports commit 40176cc — APKBUILD + patches + build config | 2 KB | LGPL-2.1-or-later AND GPL-2.0-or-later |
| `libgpg-error-1.51-r0-alpine-aports.tar.gz` | Alpine packaging of libgpg-error 1.51-r0 at aports commit 59a563e — APKBUILD + patches + build config | 1 KB | GPL-2.0-or-later AND LGPL-2.1-or-later |
| `libidn2-2.3.7-r0-alpine-aports.tar.gz` | Alpine packaging of libidn2 2.3.7-r0 at aports commit 1cdcdd0 — APKBUILD + patches + build config | 1 KB | GPL-2.0-or-later OR LGPL-3.0-or-later |
| `libseccomp_2.6.0-2.debian.tar.xz` | Debian packaging for libseccomp 2.6.0-2 (trixie) — patches, rules and control | 20 KB | LGPL-2.1-only |
| `libseccomp_2.6.0-2.dsc` | Debian source-package manifest for libseccomp 2.6.0-2 (trixie) — the OpenPGP-signed .dsc that names and checksums the tarball | 2 KB | LGPL-2.1-only |
| `libunistring-1.2-r0-alpine-aports.tar.gz` | Alpine packaging of libunistring 1.2-r0 at aports commit c4c6785 — APKBUILD + patches + build config | 1 KB | GPL-2.0-or-later OR LGPL-3.0-or-later |
| `musl-1.2.5-r9-alpine-aports.tar.gz` | Alpine packaging of musl 1.2.5-r9 at aports commit efd4d5d — APKBUILD + patches + build config | 15 KB | MIT AND BSD-2-Clause AND GPL-2.0-or-later |
| `netbase_6.4.dsc` | Debian source-package manifest for netbase 6.4 (bookworm) — the OpenPGP-signed .dsc that names and checksums the tarball | 1 KB | GPL-2.0-only |
| `netbase_6.4.tar.xz` | complete Debian source package for netbase 6.4 (native package) | 31 KB | GPL-2.0-only |
| `netbase_6.5.dsc` | Debian source-package manifest for netbase 6.5 (trixie) — the OpenPGP-signed .dsc that names and checksums the tarball | 1 KB | GPL-2.0-only |
| `netbase_6.5.tar.xz` | complete Debian source package for netbase 6.5 (native package) | 31 KB | GPL-2.0-only |
| `pax-utils-1.3.8-r1-alpine-aports.tar.gz` | Alpine packaging of pax-utils 1.3.8-r1 at aports commit 398a5ae — APKBUILD + patches + build config | 1 KB | GPL-2.0-only |
| `pax-utils-1.3.8.tar.xz` | upstream release of pax-utils 1.3.8 | 120 KB | GPL-2.0-only |

## Pinned but NOT retained here — for the Correlix S3 archive (tracker 262)

Until that archive exists these are fetched per release from the URL in `scripts/source-mirror.json`
and checksum-verified. Once it does, `scripts/source-archive.py ingest --all` puts them there and
the release reads them from it instead.

| file | size |
|---|---|
| `busybox-1.37.0.tar.bz2` | 2.6 MB |
| `gettext-0.22.5.tar.xz` | 10.3 MB |
| `libgcrypt-1.10.3.tar.bz2` | 3.8 MB |
| `libgpg-error-1.51.tar.bz2` | 1.1 MB |
| `libidn2-2.3.7.tar.gz` | 2.2 MB |
| `libseccomp_2.6.0.orig.tar.gz` | 0.7 MB |
| `libunistring-1.2.tar.xz` | 2.5 MB |
| `musl-1.2.5.tar.gz` | 1.1 MB |
| `syslog-ng-4.7.1.tar.gz` | 6.9 MB |
