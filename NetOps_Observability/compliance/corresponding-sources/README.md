# Retained corresponding source (Correlix-owned copies)

Files here are **Correlix's retained copies** of corresponding source that a GPL/LGPL/AGPL
component shipped in a Correlix image obliges us to make available (tracker 238, owner decision
2026-09-05: "if Correlix ships the binary, Correlix retains the compliance artifacts"). Each file is
pinned by name, upstream URL, size and sha256 in `scripts/source-mirror.json`; the installer
(`scripts/make-installer.sh`, `CORRELIX_SOURCE_MIRROR_DIR`) takes the copy from here first and
re-verifies the checksum exactly as it would a fresh download. Upstream URLs are provenance and a
retrieval source, never the compliance evidence.

Only small archives are kept in git (Alpine packaging: APKBUILD + patches + config, tens of KB).
Large upstream tarballs (BusyBox, syslog-ng) are fetched by the release build from their pinned
URL and shipped in every release bundle's `source-offer/`; a Correlix-controlled artifact store for
those is tracker 238's open residue.

| file | component | pinned in |
|---|---|---|
| `busybox-1.37.0-r12-alpine-aports.tar.gz` | Alpine packaging of busybox 1.37.0-r12 at aports commit 9c49608 (`distro-exact` provenance for netops-frontend / netops-nginx) | `scripts/source-mirror.json` |
