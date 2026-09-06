#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# Build the Correlix offline installer bundle (#97 Phase 1).
#
# Produces a directory a client can install from with NOTHING but Docker +
# Compose v2 + zstd on the target host — no Node, no registry access, no PyPI:
#
#   dist/correlix-<version>/
#     install-correlix.sh                THE customer entry point (one command)
#     correlix-source-<version>.tar.gz   source tree (compose, configs, installer)
#     correlix-images-core-<version>.tar.zst        base appliance images
#     correlix-addon-<name>-<version>.tar.zst       optional add-on packs
#     SHA256SUMS                         integrity manifest
#     MANIFEST                           version, git sha, profile, image list
#     README.md                          customer quickstart (run one command)
#     ADVANCED.md                        external-Kafka + advanced settings
#     TROUBLESHOOTING.md                 customer-safe fixes
#     correlix-setup                     graphical installer (7b)
#     correlix-debug                     pipeline debugger CLI (7c)
#     correlix-licence                   licence verify/show CLI (7d)
#     LICENSES.md                        third-party distribution notices
#                                        (GENERATED from docs/THIRD_PARTY_LICENSES.md
#                                         by scripts/license-audit.py — never hand-written)
#     LICENSE                            Correlix's OWN licence — the concise
#                                        mixed-licence notice (Apache-2.0 core +
#                                        LicenseRef-Correlix-Enterprise), never
#                                        the bare Apache text,
#     LICENSING.md                       which directory is core vs commercial,
#     LICENSES/                          both SPDX texts,
#     NOTICE                             third-party attributions + source offers
#                                        — all copied verbatim from the repo
#                                        root; LICENSES.md's footer points at all
#                                        four, so they ship or the footer is a
#                                        dangling reference
#     source-offer/                      corresponding source for the copyleft
#                                        components we redistribute (GPL/LGPL),
#                                        mirrored per release — see write_source_offer()
#     README.txt                         START HERE — plain text, one page, no
#                                        markdown, for the person who has just
#                                        untarred this on a server console
#     OPERATIONS.md                      sizing, upgrade, rollback, uninstall
#     SUPPORT.txt                        how to get help + what to send
#     RELEASE-NOTES.md                   what changed, generated from the log
#     docs/index.html                    the FULL product documentation, built
#                                        static and readable with no network
#     CHECKSUMS.sha256                   the integrity manifest under the name
#                                        customers look for (a symlink to
#                                        SHA256SUMS, which stays canonical)
#
# Client install (the whole thing):
#   ./install-correlix.sh
#
# Usage (from anywhere in the repo):
#   scripts/make-installer.sh [--core] [--out DIR]
#     --core   base appliance archive ONLY (skip the add-on packs) — smallest
#              possible bundle for demo/eval. Default builds base + all packs.
#     --out    output directory (default: <repo>/dist)
#     --licenses-only
#              regenerate + gate the third-party notices, write LICENSES.md and
#              stop (no images, no tarballs). What CI runs to prove the customer
#              notice matches the tree.
#
# Prereqs on the BUILD host: docker+compose v2, zstd, node/npm (frontend dist),
# python3 (licence notices), git. The frontend dist/ and docs portal are built if missing (they are
# gitignored — the classic stale-dist trap — so the bundle never depends on a
# developer having built them recently: REBUILD_FRONTEND=1 forces both).
#
# LICENSING (see docs/design/packaging-strategy.md §4 + bundle LICENSES.md):
# gate CLOSED 2026-07-03 — bus = Apache Kafka (Apache-2.0, replaced Redpanda
# BSL), cache = Valkey (BSD-3, replaced Redis RSAL). Guards below hard-fail
# the build if a flagged image ever reappears in the bundle set.

set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
PROFILE="full"
LICENSES_ONLY=0
SOURCE_OFFER_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --core) PROFILE="core"; shift ;;
    --out)  OUT="$2"; shift 2 ;;
    # Dry-run for the licence path: regenerate + gate the third-party notices
    # and write the bundle's LICENSES.md, then stop. No Docker, no npm, no
    # tarballs — so CI can assert the customer notice is correct on every
    # commit instead of only when someone cuts a bundle.
    --licenses-only) LICENSES_ONLY=1; shift ;;
    # Dry-run for the GPL/LGPL source-offer path: mirror the corresponding
    # source tarballs into the bundle and stop. Same shape as --licenses-only,
    # so CI (and tests/test_source_offer.py) can prove the source offer is
    # honoured without cutting a whole bundle.
    --source-offer-only) SOURCE_OFFER_ONLY=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# python3 generates the third-party notices (and gates their licences) below.
command -v python3 >/dev/null || { echo "python3 is required (third-party licence notices)" >&2; exit 1; }
# date+sha, not `git describe` — the repo's tags are milestone markers, not
# release tags, and produce unusable bundle names. Product release tags
# (v-prefixed) win when present.
VERSION="$(git -C "$ROOT" describe --tags --match 'v[0-9]*' --always 2>/dev/null | grep -E '^v[0-9]' || true)"
[ -n "$VERSION" ] || VERSION="$(date +%Y.%m.%d)-g$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GITSHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUNDLE_DIR="$OUT/correlix-$VERSION"
COMPOSE_DIR="$ROOT/deployment/docker"
mkdir -p "$BUNDLE_DIR"

# --- Third-party notices: GENERATED, never hand-written -----------------------
# What used to live here was a hand-maintained heredoc, and it had rotted
# exactly the way hand-maintained licence lists do: it listed 14 container
# images and ZERO of the libraries actually linked into our own artifacts (no
# Go module, no npm package, no Python package — including elkjs (EPL-2.0),
# four OFL-1.1 font families and certifi (MPL-2.0), all three carrying real
# notice obligations), it omitted Keycloak (which SHIPS — `sso` is in
# BASE_PROFILES), curl and kafka-exporter, and it misstated syslog-ng as
# GPL-3.0. syslog-ng OSE 4.7.1 is LGPL-2.1-or-later for the core and
# GPL-2.0-or-later for modules/ and scl/ (verified against COPYING at tag
# syslog-ng-4.7.1), with NO OpenSSL linking exception. See
# docs/security/LICENSE_AUDIT_2026-09-03.md §2.5.
#
# The inventory is now DERIVED from the tree by scripts/license-audit.py and
# regenerated on every bundle build, so the customer notice cannot drift from
# what the bundle actually contains.
write_licenses() {
  echo "-- regenerating third-party licence notices"
  python3 "$ROOT/scripts/license-audit.py" --notices \
    || { echo "FATAL: could not regenerate docs/THIRD_PARTY_LICENSES.md" >&2; exit 1; }
  # The gate must be GREEN before we ship: a component whose licence nobody has
  # reviewed, or one that is source-available/forbidden, must never leave here.
  python3 "$ROOT/scripts/license-audit.py" --check \
    || { echo "FATAL: licence audit is not green — a bundle must never ship a component whose licence is unreviewed or forbidden (CLAUDE.md §6). Run: python3 scripts/license-audit.py --check" >&2; exit 1; }

{
printf '# Correlix %s — Third-party distribution notices\n\n' "$VERSION"
cat <<'HDR'
Exact pinned image versions/digests: see MANIFEST. The full licence texts for
the components that require them also ship inside the images themselves and are
served by the running product at `/licenses/`.

HDR
# Drop the generator's editor-facing "do not hand-edit" banner (the leading
# blockquote) and its own H1, which this file already carries with the version
# in it. Only that banner uses blockquote syntax, and a changed H1 would simply
# reappear as a duplicate heading rather than losing content; the content guard
# below fails the build if anything substantive goes missing.
grep -v -e '^> ' -e '^# Correlix — Third-party licences$' "$ROOT/docs/THIRD_PARTY_LICENSES.md"
cat <<'FTR'

## Resolved licensing history

| Component | Status |
|---|---|
| Redis | **removed** — replaced by Valkey (BSD-3-Clause). Redis >= 7.4 is RSALv2/SSPL-licensed and is not distributed with Correlix. Closed. |
| Redpanda | **removed from customer distribution** — the event bus is Apache Kafka. Redpanda (BSL) is not shipped in any Correlix bundle. |
| Prometheus | **removed** — metrics are stored in VictoriaMetrics; no Prometheus image ships in any bundle. |

## Correlix's own code

Correlix is open core (owner decision 2026-09-04). The statement of record is:

Correlix core is licensed under the Apache License, Version 2.0. Commercial add-on modules are licensed under the Correlix Enterprise License (LicenseRef-Correlix-Enterprise) — see LICENSING.md.

The full texts ship beside this file: LICENSE (the mixed-licence notice),
LICENSING.md (which directory is which), LICENSES/ (both licence texts, by SPDX
id) and NOTICE (attributions and written source offers).

No component above places any disclosure, relicensing or network-use obligation
on Correlix's own code under either licence: nothing under a copyleft licence is
linked into, or bundled into, any binary Correlix builds.
FTR
} > "$BUNDLE_DIR/LICENSES.md"

  # Content guard (§16.1 — a silently shorter notice file is the exact defect
  # this replaced). Each string below is one of the things the old hand-written
  # file got wrong or left out; if the generator or the grep above ever drops
  # them, the build stops instead of shipping incomplete attribution.
  # The 2026-09-04 owner decisions add three more things the customer notice
  # must SAY, not merely imply: Grafana's AGPL posture (D1), the Red Hat UBI
  # EULA Keycloak ships under (D6), and where the GPL source actually is (D2).
  for want in 'syslog-ng' 'keycloak' 'elkjs' 'certifi' 'fontsource' 'jackc/pgx' \
              'Written offer' 'Affero' 'Universal Base Image' 'source-offer/'; do
    grep -qi -- "$want" "$BUNDLE_DIR/LICENSES.md" \
      || { echo "FATAL: bundle LICENSES.md is missing '$want' — the generated third-party notices are incomplete" >&2; exit 1; }
  done
  # syslog-ng is LGPL-2.1-or-later / GPL-2.0-or-later. The only GPL-3 family
  # licence in the product is Grafana's AGPL-3.0 in the optional add-on pack;
  # a GPL-3.0 claim with no Grafana behind it is the old misstatement returning.
  if grep -q 'GPL-3.0' "$BUNDLE_DIR/LICENSES.md" && ! grep -qi 'grafana' "$BUNDLE_DIR/LICENSES.md"; then
    echo "FATAL: bundle LICENSES.md claims a GPL-3.0 licence with no component to justify it (syslog-ng is LGPL-2.1+/GPL-2.0+, NOT GPL-3.0)" >&2; exit 1
  fi
  echo "   third-party notices generated ($(wc -l < "$BUNDLE_DIR/LICENSES.md") lines, licence gate green)"

  # The project's OWN licence, shipped beside the third-party notices — because
  # LICENSES.md's footer now points at it. A licence statement that names a file
  # the customer did not receive is worse than no statement: it reads as a
  # deliberate omission. Copied, never generated: these are the authoritative
  # texts, and a bundle-local rewrite of a licence is exactly the drift the
  # open-core decision (2026-09-04) exists to prevent.
  # NOTICE travels with them: licensing-policy.json's artifact_requirements
  # names it as a file the installer bundle MUST ship, and it is the only place
  # the third-party attributions and written source offers are stated in the
  # project's own voice. Shipping the licence notice without it would satisfy
  # the Apache-2.0 §4(d) obligation nowhere the customer can see.
  for f in LICENSE LICENSING.md NOTICE; do
    [ -f "$ROOT/$f" ] \
      || { echo "FATAL: $ROOT/$f is missing — the bundle's LICENSES.md footer points at it (open-core decision 2026-09-04)" >&2; exit 1; }
    cp "$ROOT/$f" "$BUNDLE_DIR/$f"
  done
  [ -d "$ROOT/LICENSES" ] \
    || { echo "FATAL: $ROOT/LICENSES/ is missing — the bundle must carry both SPDX licence texts" >&2; exit 1; }
  rm -rf "$BUNDLE_DIR/LICENSES"
  cp -R "$ROOT/LICENSES" "$BUNDLE_DIR/LICENSES"
  # Both texts, by SPDX id, or the footer's third claim is false too.
  for t in Apache-2.0 Correlix-Enterprise; do
    [ -s "$BUNDLE_DIR/LICENSES/$t.txt" ] \
      || { echo "FATAL: bundle LICENSES/$t.txt is missing or empty" >&2; exit 1; }
  done
  echo "   project licence shipped (LICENSE, LICENSING.md, LICENSES/, NOTICE)"
}

# --- GPL/LGPL corresponding source: MIRRORED, not merely offered ------------
# Licence audit D2, owner decision 2026-09-04 (docs/security/LICENSE_AUDIT_2026-09-03.md
# §4 D2). We redistribute syslog-ng as an unmodified upstream container image.
# syslog-ng OSE 4.7.1 is LGPL-2.1-or-later for the core and GPL-2.0-or-later for
# modules/ and scl/ (verified against COPYING at tag syslog-ng-4.7.1), with NO
# OpenSSL linking exception. GPL-2.0 §3 lets a distributor discharge the source
# obligation either by shipping the corresponding source WITH the binary (§3a) or
# by a written offer good for three years (§3b). The owner chose §3a: mirror the
# exact upstream tarball into every release. A three-year offer is a promise that
# outlives repos, renames and companies; a tarball in the customer's hands is not.
#
# FAIL CLOSED (scripts/CLAUDE.md §16.1). No pin, no network, a short read or a
# checksum mismatch is a HARD BUILD FAILURE. A bundle must never carry a
# source-offer directory that does not contain the source it claims to — that is
# worse than having no directory at all, because it reads as compliance.
#
# The pin table is scripts/source-mirror.json (reviewed, checked in; it records
# that upstream publishes no checksum of its own, so the sha256 there is our own
# measurement, taken once and enforced forever). Air-gapped build hosts point
# CORRELIX_SOURCE_MIRROR_DIR at a directory of pre-fetched tarballs; the checksum
# gate applies to those exactly as it does to a download, so the offline path is
# a convenience, never a bypass.
#
# THREE ACQUISITION MODES, in the order this function tries them:
#
#   1. RETAINED COPIES (CORRELIX_SOURCE_MIRROR_DIR) — everything in
#      compliance/corresponding-sources/, taken from the repository itself.
#   2. THE CORRELIX ARCHIVE (release mode only) — scripts/source-archive.py
#      release-fetch, which reads the Correlix-controlled S3 store and NEVER
#      touches upstream.
#   3. THE PINNED UPSTREAM URL — development and daily CI only.
#
# CORRELIX_SOURCE_RELEASE_MODE=1 turns step 3 OFF. That is the point of tracker
# 262: an upstream URL is provenance, not retention, and a production release
# must not depend on ftp.gnu.org, gnupg.org, musl.libc.org, dev.gentoo.org or
# deb.debian.org still serving those exact bytes. Two `base-files` versions
# Correlix shipped had already left Debian's live pool by the time the
# 2026-09-05 audit looked for them. In release mode an artifact that is neither
# retained in git nor archived FAILS the build, loudly, with the ingest command
# to run.
#
# Every path ends at the SAME sha256 gate below. Local provenance is not trusted
# provenance, and neither is archived provenance.
write_source_offer() {
  echo "-- mirroring GPL/LGPL corresponding source"
  local pins="${CORRELIX_SOURCE_PINS:-$ROOT/scripts/source-mirror.json}"
  local release_mode="${CORRELIX_SOURCE_RELEASE_MODE:-0}"
  if [ "$release_mode" = "1" ]; then
    [ -n "${CORRELIX_SOURCE_ARCHIVE_BUCKET:-}" ] || {
      echo "FATAL: CORRELIX_SOURCE_RELEASE_MODE=1 but no CORRELIX_SOURCE_ARCHIVE_BUCKET is configured. Release mode reads corresponding source from the Correlix archive and refuses to fall back to upstream; with no archive configured it can honour neither half of that. See docs/compliance/SOURCE_ARCHIVE.md." >&2
      exit 1
    }
    echo "   release mode: retained copies + the Correlix archive only, NO upstream fetch (bucket $CORRELIX_SOURCE_ARCHIVE_BUCKET)"
  fi
  [ -f "$pins" ] || { echo "FATAL: source-offer pin table not found at $pins — refusing to build a bundle whose GPL source offer cannot be honoured" >&2; exit 1; }

  local offer="$BUNDLE_DIR/source-offer"
  mkdir -p "$offer"

  # One tab-separated line per component. python3 is already a hard requirement
  # above; a malformed pin table aborts here by name rather than yielding an
  # empty loop that would silently ship no source at all.
  local rows
  rows="$(python3 - "$pins" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)
except (OSError, ValueError) as exc:
    print(f"pin table unreadable: {exc}", file=sys.stderr)
    raise SystemExit(1)
comps = data.get("components") or []
if not comps:
    print("pin table declares no components", file=sys.stderr)
    raise SystemExit(1)
for c in comps:
    missing = [k for k in ("name", "version", "file", "url", "sha256", "license") if not c.get(k)]
    if missing:
        print(f"component {c.get('name', '?')} is missing {missing}", file=sys.stderr)
        raise SystemExit(1)
    # The file name becomes a path under the bundle and the URL is fetched.
    # Both are reviewed and checked in, but a pin table is still input: a
    # traversing name or a plaintext URL must fail here, not be written.
    if "/" in c["file"] or c["file"].startswith("."):
        print(f"component {c['name']} has an unsafe file name {c['file']!r}", file=sys.stderr)
        raise SystemExit(1)
    if not c["url"].startswith("https://"):
        print(f"component {c['name']} must be fetched over TLS, got {c['url']!r}", file=sys.stderr)
        raise SystemExit(1)
    if len(c["sha256"]) != 64 or not all(ch in "0123456789abcdef" for ch in c["sha256"]):
        print(f"component {c['name']} has a malformed sha256", file=sys.stderr)
        raise SystemExit(1)
    print("\t".join((c["name"], c["version"], c["file"], c["url"], c["sha256"], c["license"], c.get("notes", ""))))
PYEOF
)" || { echo "FATAL: could not read the source-offer pin table ($pins)" >&2; exit 1; }

  local readme="$offer/README"
  {
    printf 'Corresponding source for the copyleft components Correlix redistributes\n'
    printf '=====================================================================\n\n'
    cat <<'OFFERHDR'
Correlix ships some third-party software under the GNU General Public License
and the GNU Lesser General Public License. Those licences require that anyone
who receives the binaries can also get the source they were built from.

THIS DIRECTORY IS THAT SOURCE. Each archive below is the complete, unmodified
upstream source release for the exact version of the component this bundle
contains. Nothing here has been patched, stripped or re-packaged by Correlix —
the checksums are recorded so you can confirm that yourself.

You may use, study, modify and redistribute each component under the terms of
its own licence, independently of Correlix. The licence texts ship inside the
component's own archive (COPYING / GPL.txt / LGPL.txt) and the components are
listed in LICENSES.md at the root of this bundle.

Correlix's own source code is NOT placed under these licences and is not
included here: every copyleft component runs as its own separate, unmodified
container process, so no Correlix code is combined with or derived from it.

OFFERHDR
    printf 'Components\n----------\n\n'
    printf '%s\n' "$rows" | while IFS="$(printf '\t')" read -r name version file url sha license notes; do
      printf '  %s %s\n' "$name" "$version"
      printf '    file     : %s\n' "$file"
      printf '    licence  : %s\n' "$license"
      printf '    upstream : %s\n' "$url"
      printf '    sha256   : %s\n' "$sha"
      [ -n "$notes" ] && printf '    note     : %s\n' "$notes"
      printf '\n'
    done
    cat <<'OFFERFTR'
Verifying
---------

    sha256sum -c ../SHA256SUMS 2>/dev/null | grep source-offer

(The bundle-wide SHA256SUMS covers every file in this directory.)

Questions about these components, or a source request for a component not
listed here, can be sent to the address in the bundle's LICENSES.md.
OFFERFTR
  } > "$readme"

  # Fetch + verify. A `while read` loop would run the body in a subshell, where
  # `exit 1` cannot fail the build — so iterate in the parent shell instead.
  local line name version file url sha license notes dest got
  local n=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    IFS="$(printf '\t')" read -r name version file url sha license notes <<<"$line"
    dest="$offer/$file"

    if [ -n "${CORRELIX_SOURCE_MIRROR_DIR:-}" ] && [ -f "$CORRELIX_SOURCE_MIRROR_DIR/$file" ]; then
      # Air-gapped/offline build host: take the local copy, then verify it the
      # same way. Local provenance is not trusted provenance.
      echo "   $name $version <- $CORRELIX_SOURCE_MIRROR_DIR/$file (local mirror)"
      cp "$CORRELIX_SOURCE_MIRROR_DIR/$file" "$dest"
    elif [ "$release_mode" = "1" ]; then
      # RELEASE: the Correlix-controlled archive, and nothing else. source-archive.py
      # verifies the sha256 of what it places; the gate below verifies it again,
      # because a release bundle's source offer is checked by the thing that ships
      # it, not by the thing that fetched it.
      echo "   $name $version <- Correlix source archive"
      python3 "$ROOT/scripts/source-archive.py" release-fetch --quiet \
              --pins "$pins" --file "$file" --dest "$offer" \
        || { echo "FATAL: $name $version ($file) is not in the Correlix corresponding-source archive, and a release does not fall back to $url. Ingest it first: scripts/source-archive.py ingest --file $file  (see docs/compliance/SOURCE_ARCHIVE.md)" >&2; exit 1; }
    else
      echo "   $name $version <- $url"
      command -v curl >/dev/null || { echo "FATAL: curl is required to mirror $name's corresponding source (or set CORRELIX_SOURCE_MIRROR_DIR to a directory holding $file)" >&2; exit 1; }
      # Bounded + retried (§16.3 / CLAUDE.md §9). stderr stays visible so a real
      # network failure is readable rather than inferred from a missing file.
      # A named User-Agent: gitlab.alpinelinux.org answers curl's default UA with
      # HTTP 418 (bot filter, seen on GitHub-hosted runners 2026-09-05).
      curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors \
           -A "correlix-source-mirror/1.0 (corresponding-source fetch; +https://github.com/correlix)" \
           --connect-timeout 20 --max-time 600 -o "$dest" "$url" \
        || { echo "FATAL: could not fetch $name $version corresponding source from $url. A GPL/LGPL binary must never ship without its source (licence audit D2). Fix the network, or pre-fetch the file and set CORRELIX_SOURCE_MIRROR_DIR." >&2; exit 1; }
    fi

    got="$(sha256sum "$dest" | awk '{print $1}')"
    if [ "$got" != "$sha" ]; then
      # Do not leave the bad bytes behind for a later step to pick up.
      rm -f "$dest"
      echo "FATAL: checksum mismatch for $file — expected $sha, got $got. Refusing to ship an unverified source tarball (scripts/source-mirror.json is the reviewed pin; if upstream legitimately re-cut the release, re-measure and update that file deliberately)." >&2
      exit 1
    fi
    echo "     sha256 OK ($sha)"
    n=$((n + 1))
  done <<<"$rows"

  [ "$n" -gt 0 ] || { echo "FATAL: source-offer mirrored zero components — the pin table resolved nothing" >&2; exit 1; }
  echo "   source offer complete ($n component(s) in $offer)"
}

if [ "$LICENSES_ONLY" = "1" ]; then
  write_licenses
  echo "== licences-only run: $BUNDLE_DIR/LICENSES.md"
  exit 0
fi

if [ "$SOURCE_OFFER_ONLY" = "1" ]; then
  write_source_offer
  echo "== source-offer-only run: $BUNDLE_DIR/source-offer/"
  exit 0
fi

# Everything past here builds real archives. (--licenses-only exits above and
# needs no compressor, so the zstd requirement is checked here, not earlier.)
command -v zstd >/dev/null || { echo "zstd is required (apt-get install zstd)" >&2; exit 1; }


echo "== correlix installer bundle $VERSION ($PROFILE) -> $BUNDLE_DIR"

# 1. Frontend dist + docs portal (gitignored build artifacts the frontend image
#    COPYs). ALWAYS rebuild for a bundle: dist/ is gitignored and long-lived, so
#    a "build only if missing" check silently ships a STALE UI whenever a dev's
#    dist predates their source edits — exactly what shipped four bundles' worth
#    of un-scrubbed UI on 2026-07-04. Correctness over the ~30s build cost.
#    (REBUILD_FRONTEND=0 can force-skip only if you KNOW dist is fresh.)
if [ "${REBUILD_FRONTEND:-1}" != "0" ]; then
  echo "-- building frontend dist/ (fresh)"
  (cd "$ROOT/src/frontend" && npm ci --silent && npm run build)
fi

# The customer BASE = the appliance every install gets (embedded Apache Kafka
# bus + prober + all always-on services, including Keycloak — SSO is
# default-on, owner decision 2026-08-04, GUI-configured; costs ~the Keycloak
# image in bundle size, a known #148 counterweight). Optional capability ships
# as ADD-ON PACKS — a small image archive per pack, enabled post-install with
# `./install-correlix.sh enable <addon>` (which flips the compose profile).
# Lab/dev profiles (mock-*, netbox, seal, flowgen) stay out of client
# bundles by construction.
BASE_PROFILES=(--profile embedded-bus --profile prober --profile sso)
ADDONS="log-search-ui:osd self-monitoring:self-monitoring"   # name:profile
[ "$PROFILE" = "core" ] && ADDONS=""   # --core: base appliance only, no packs

# 2. Build every application image at the pinned bases (all profiles, so
#    add-on packs can be cut from the same build).
echo "-- docker compose build"
# A CI runner has no .env; compose interpolation needs the :?-guarded vars.
export KAFKA_CLUSTER_ID="${KAFKA_CLUSTER_ID:-bundle-resolve-only-000000}"
(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" --profile osd --profile self-monitoring build --quiet)

# 3. Resolve the image sets. `config --images` honours pinned digests; an
#    add-on pack's set = (base + its profile) minus base.
echo "-- resolving image list"
IMAGES="$(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" config --images | sort -u)"
COUNT="$(printf '%s\n' "$IMAGES" | grep -c .)"
echo "   $COUNT base images"

# 3a. LICENSING GUARDS (#97): a customer bundle must never ship Redpanda (BSL)
#     and must ship Apache Kafka (bus) + Valkey (cache). Redis (RSAL) and
#     Prometheus are REMOVED components — permanently out of the product —
#     and must never reappear in any bundle. Hard build failures.
if printf '%s\n' "$IMAGES" | grep -qi 'redpanda'; then
  echo "FATAL: redpanda image in bundle set — BSL-licensed, not redistributable" >&2; exit 1
fi
if printf '%s\n' "$IMAGES" | grep -Eqi 'redis|prometheus'; then
  echo "FATAL: redis/prometheus image in bundle set — removed components (#97) must not ship" >&2; exit 1
fi
# Gotenberg (the `pdf` profile) must NEVER enter a customer bundle — owner
# decision 2026-09-04, licence audit D6. Gotenberg's own code is MIT, but the
# image bundles PDFtk (GPL-2.0-or-later), LibreOffice (MPL-2.0),
# ttf-mscorefonts-installer (a PROPRIETARY Microsoft EULA that restricts
# redistribution) and, on amd64, Google Chrome (proprietary, not Chromium). It
# is also pinned to a floating `:8` major tag, so what it bundles can change
# under us between rebuilds. This was a written convention until now; a
# convention is worth nothing the day someone adds `--profile pdf` to
# BASE_PROFILES, so it is a build failure instead.
if printf '%s\n' "$IMAGES" | grep -qi 'gotenberg'; then
  echo "FATAL: gotenberg image in bundle set — the pdf profile carries a proprietary Microsoft font EULA, PDFtk (GPL-2.0+) and Google Chrome, and must never ship to a customer (licence audit D6). Switch to a slim variant without msttcorefonts/PDFtk and re-audit before reversing this." >&2; exit 1
fi
printf '%s\n' "$IMAGES" | grep -q '^apache/kafka:' \
  || { echo "FATAL: apache/kafka missing from bundle image set" >&2; exit 1; }
printf '%s\n' "$IMAGES" | grep -q '^valkey/valkey:' \
  || { echo "FATAL: valkey missing from bundle image set" >&2; exit 1; }
echo "   licensing guards passed (kafka+valkey in; redpanda/redis/prometheus/gotenberg out)"

# 3b. Ensure every bundled image exists locally. App images were just built;
#     third-party ones are digest-pinned pulls that a dev host has but a fresh
#     CI runner does not — `docker save` hard-fails on any missing reference.
#     Pull AFTER the core filter so a trimmed bundle never downloads images it
#     won't ship.
for img in $IMAGES; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "-- pulling $img"; docker pull -q "$img"; }
  # Pulls by digest don't create the plain tag, and we SAVE by tag (a digest
  # ref saves untagged — see §4). Ensure the tag exists locally; metadata-only.
  case "$img" in *@sha256:*) docker tag "$img" "${img%%@*}" ;; esac
done

# 4. Save + compress. zstd -3 multi-threaded: ~2x smaller than the raw save
#    at near-disk-speed compression. Bundle keeps the historical "core" name
#    for the base archive (install-correlix.sh globs correlix-images-*.tar.zst).
#
#    CRITICAL: save by TAG, never by tag@digest — `docker save ref@sha256:...`
#    exports the image UNTAGGED (empty RepoTags), so a virgin host loads
#    anonymous images and compose can't match anything (second virgin-host
#    finding, 2026-07-04). On this build host the tag resolves to the exact
#    digest-pinned image we just built/pulled, so the bytes are identical.
strip_digests() { sed 's/@sha256:[0-9a-f]*$//' | sort -u; }

# verify_archive_tags <archive.tar.zst> — every image in the archive must
# carry a RepoTag, or a fresh host cannot use it. Build-time hard failure.
verify_archive_tags() {
  zstd -dc "$1" | tar -xOf - manifest.json | python3 -c '
import json,sys
ms=json.load(sys.stdin)
bad=[m.get("Config","?") for m in ms if not m.get("RepoTags")]
if bad:
    print(f"FATAL: {len(bad)} untagged image(s) in archive — virgin hosts cannot use them", file=sys.stderr)
    sys.exit(1)
print(f"   archive tag check: {len(ms)} images, all tagged")'
}

IMG_OUT="$BUNDLE_DIR/correlix-images-core-$VERSION.tar.zst"
echo "-- docker save (base) -> $IMG_OUT"
SAVE_REFS="$(printf '%s\n' "$IMAGES" | strip_digests)"
# shellcheck disable=SC2086
docker save $SAVE_REFS | zstd -q -T0 -3 -f -o "$IMG_OUT"
verify_archive_tags "$IMG_OUT"

# 4b. Add-on packs: per pack, the images its profile adds on top of base.
ADDON_MANIFEST=""
for spec in $ADDONS; do
  name="${spec%%:*}"; prof="${spec##*:}"
  PACK_IMAGES="$(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" --profile "$prof" config --images | sort -u | comm -13 <(printf '%s\n' "$IMAGES") -)"
  [ -n "$PACK_IMAGES" ] || { echo "FATAL: addon $name resolved no images" >&2; exit 1; }
  if printf '%s\n' "$PACK_IMAGES" | grep -Eqi 'redpanda|redis|prometheus'; then
    echo "FATAL: forbidden image (redpanda/redis/prometheus — removed components) in addon $name" >&2; exit 1
  fi
  # Same rule for add-on packs: an add-on is still something the customer
  # receives (licence audit D6).
  if printf '%s\n' "$PACK_IMAGES" | grep -qi 'gotenberg'; then
    echo "FATAL: gotenberg image in addon $name — proprietary Microsoft font EULA + PDFtk (GPL-2.0+) + Chrome; must never ship (licence audit D6)" >&2; exit 1
  fi
  for img in $PACK_IMAGES; do
    docker image inspect "$img" >/dev/null 2>&1 || { echo "-- pulling $img"; docker pull -q "$img"; }
    case "$img" in *@sha256:*) docker tag "$img" "${img%%@*}" ;; esac
  done
  PACK_OUT="$BUNDLE_DIR/correlix-addon-$name-$VERSION.tar.zst"
  echo "-- docker save (addon $name) -> $PACK_OUT"
  PACK_REFS="$(printf '%s\n' "$PACK_IMAGES" | strip_digests)"
  # shellcheck disable=SC2086
  docker save $PACK_REFS | zstd -q -T0 -3 -f -o "$PACK_OUT"
  verify_archive_tags "$PACK_OUT"
  ADDON_MANIFEST="$ADDON_MANIFEST$(printf 'addon %s (profile %s):\n' "$name" "$prof"; printf '%s\n' "$PACK_IMAGES" | sed 's/^/  - /')
"
done

# 5. Source tree (dist/ and .env are gitignored and intentionally absent: the
#    client neither builds the frontend nor inherits our secrets — install.py
#    generates fresh secrets on their host).
SRC_OUT="$BUNDLE_DIR/correlix-source-$VERSION.tar.gz"
echo "-- git archive -> $SRC_OUT"
git -C "$ROOT" archive --format=tar.gz --prefix=NetOps_Observability/ -o "$SRC_OUT" HEAD

# 5b. Lab-leak guard (audit 2026-07-20): the tarball is git-archive-of-HEAD, so
#     a single mistaken commit can ship lab infrastructure to a customer. Fail
#     the build if any lab marker appears in the archive's paths or contents.
#     `healthchecks.io` and `ntfy.sh` stopped being lab markers on 2026-08-13:
#     the stack watchdog (stack-watchdog.sh + env.example + install-watchdog.sh)
#     now SHIPS in customer bundles (owner decision) and its docs must name
#     those services. The credential-bearing forms remain fatal: `hc-ping`
#     (the ping-URL domain — a live check UUID) and the lab topic id.
LAB_MARKERS='10\.70\.245\.120|rao123|correlix-faultlab|hc-ping|8d0f8a4e-c36e'
LAB_PATHS='scripts/lab/|scripts/bundle-autoupdate|scripts/host-hygiene|docs/GTM_PLAN|docs/TRACKER|mock-servicenow/|mock-nms/|brand-samples/'
# grep -v '/$': git archive emits a bare DIRECTORY entry for a tree whose
# files are all export-ignored (mock-nms/, scripts/lab/, ...) — an empty dir
# ships no content, so only match actual files.
if tar -tzf "$SRC_OUT" | grep -v '/$' | grep -qE "$LAB_PATHS"; then
  echo "FATAL: lab-only path leaked into the customer source archive:" >&2
  tar -tzf "$SRC_OUT" | grep -v '/$' | grep -E "$LAB_PATHS" | head >&2
  exit 1
fi
if tar -xzOf "$SRC_OUT" 2>/dev/null | grep -qaE "$LAB_MARKERS"; then
  echo "FATAL: lab identifier leaked into customer source archive contents:" >&2
  for f in $(tar -tzf "$SRC_OUT" | grep -v '/$'); do
    tar -xzOf "$SRC_OUT" "$f" 2>/dev/null | grep -qaE "$LAB_MARKERS" && echo "  $f" >&2
  done
  exit 1
fi
echo "-- lab-leak guard: clean"

# 6. Manifest + checksums + client instructions.
{
  echo "product:  Correlix (NetOps Observability)"
  echo "version:  $VERSION"
  echo "git_sha:  $GITSHA"
  # The PROFILE actually built, not a constant. Until 2026-09-03 this line was
  # hard-coded "core" while the default build (no --core) also produces the
  # add-on packs listed below it — a MANIFEST that contradicted its own
  # contents. "core" = base appliance only; "full" = base + add-on packs.
  # (The base image archive keeps its historical correlix-images-core-* name in
  # BOTH profiles; install-correlix.sh globs it.)
  echo "profile:  $PROFILE"
  echo "built:    $(date -Is)"
  echo "images:"
  printf '%s\n' "$IMAGES" | sed 's/^/  - /'
  [ -n "$ADDON_MANIFEST" ] && printf '%s' "$ADDON_MANIFEST"
} > "$BUNDLE_DIR/MANIFEST"

# 7. The appliance installer + customer docs. install-correlix.sh at the
#    bundle root is THE customer entry point — one command, no choices.
cp "$ROOT/scripts/install-correlix.sh" "$BUNDLE_DIR/install-correlix.sh"
cp "$ROOT/scripts/prepare-host.sh" "$BUNDLE_DIR/prepare-host.sh"
chmod +x "$BUNDLE_DIR/install-correlix.sh" "$BUNDLE_DIR/prepare-host.sh"

# The bundle ships THREE Go binaries (7b, 7c, 7d). Check the toolchain once, by
# name,
# instead of letting `go: command not found` surface as an opaque set -e abort
# in the middle of a 20-minute build (§16.1/§16.2: a missing tool is reported by
# name, never inferred from a broken build). There is no "skip the binary"
# branch on purpose — a bundle silently missing a shipped artifact is the exact
# omission this section exists to prevent.
command -v go >/dev/null \
  || { echo "FATAL: go toolchain not found on the build host — correlix-setup (7b), correlix-debug (7c) and correlix-licence (7d) are shipped bundle artifacts and must never be silently omitted. Install Go (see go.mod's toolchain pin) and rerun." >&2; exit 1; }

# 7b. The graphical installer (correlix-setup): a static stdlib-only Go binary
#     serving the embedded setup wizard. Built here so the customer host needs
#     nothing — launched via `./install-correlix.sh gui` (or directly).
echo "-- building correlix-setup (graphical installer)"
( cd "$ROOT/scripts/installer-gui" && \
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUNDLE_DIR/correlix-setup" . )
chmod +x "$BUNDLE_DIR/correlix-setup"

# 7c. The pipeline debugger (correlix-debug): the host-side operator CLI that
#     traces ONE marked synthetic record through the whole pipeline and writes
#     one log file per module. Design docs/design/PIPELINE_DEBUGGER_2026-09-04.md
#     §1; runbook docs/runbooks/pipeline-debug.md.
#
#     WHY IT SHIPS IN A CUSTOMER BUNDLE (the question §16.5 forces us to answer
#     for every shipped artifact): the design of record says "shipped in the
#     bundle next to the installer", and the reason is the 2026-09-02 outage —
#     telemetry went in and did not come out for three hours while every
#     container read `healthy`. Answering "which hop lost it?" has to be
#     possible ON the customer's host; telling a customer to install a Go
#     toolchain and build from the source tarball is not an answer. Shipping it
#     grants no new authority: the four /api/debug routes it drives are
#     requirePlatformAdmin + audited, and the CLI must log in as that admin, so
#     the binary is useless to anyone who is not already a platform admin. It
#     therefore stays OUT of LAB_PATHS (which is the operator-only exclude list)
#     and IS covered by SHA256SUMS below, like correlix-setup.
#
#     Build convention: identical to correlix-setup above — host toolchain,
#     CGO_ENABLED=0 (static, no glibc dependency on the customer host),
#     -trimpath -ldflags="-s -w", and NO GOOS/GOARCH override. That is this
#     bundle's established convention for its Go binaries; the build host is the
#     release host and the supported customer platform is Linux x86_64 (README).
#     Pinning a different target for this one binary would make the bundle's two
#     executables disagree about what a bundle runs on.
echo "-- building correlix-debug (pipeline debugger)"
( cd "$ROOT/src/backend" && \
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUNDLE_DIR/correlix-debug" ./cmd/correlix-debug )
chmod +x "$BUNDLE_DIR/correlix-debug"
# Prove the artifact actually runs HERE rather than on the customer's host.
# `--help` exits 0 and touches nothing (no .env, no network, no stack), so this
# is a pure liveness check on the bytes we are about to ship. stdout is noise we
# have inspected (the usage text); stderr is left visible so a real failure is
# readable (§16.1).
"$BUNDLE_DIR/correlix-debug" --help >/dev/null \
  || { echo "FATAL: the freshly built correlix-debug does not run (--help failed) — refusing to ship an unusable binary" >&2; exit 1; }

# 7d. The licence tool (correlix-licence): the host-side CLI that VERIFIES and
#     PRINTS a Correlix licence file. Design docs/design/LICENSING_MODEL_2026-09-04.md;
#     operator runbook docs/runbooks/licensing.md.
#
#     WHY IT SHIPS IN A CUSTOMER BUNDLE (the question §16.5 forces us to answer
#     for every shipped artifact): the product is now licence-gated, so "is this
#     licence file valid, whose is it, when does it expire, what does it grant?"
#     is a question a customer WILL ask — typically at 02:00, when a ceiling
#     refusal (HTTP 402) has just appeared and the api may be the thing that is
#     down. `verify` and `show` answer it offline, from the file alone, using
#     the SAME internal/licence code the api verifies with, so the answer on the
#     host cannot disagree with the answer in the product.
#
#     It grants no authority and leaks no secret. The binary embeds only the
#     PUBLIC verification key; `keygen`/`sign` are issuer-side subcommands that
#     are useless without the private signing key, which is not in this repo and
#     never enters a bundle (§16.5). It therefore stays OUT of LAB_PATHS and IS
#     covered by SHA256SUMS below, exactly like correlix-setup and correlix-debug.
#
#     Build convention: identical to 7b/7c — host toolchain, CGO_ENABLED=0,
#     -trimpath -ldflags="-s -w", no GOOS/GOARCH override.
echo "-- building correlix-licence (licence verification tool)"
( cd "$ROOT/src/backend" && \
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUNDLE_DIR/correlix-licence" ./cmd/correlix-licence )
chmod +x "$BUNDLE_DIR/correlix-licence"
# Same liveness proof as correlix-debug: `--help` exits 0, reads no file, opens
# no socket and needs no licence, so this measures the bytes we are about to
# ship and nothing else. stdout is the usage text (inspected noise); stderr
# stays visible so a real failure is readable (§16.1).
"$BUNDLE_DIR/correlix-licence" --help >/dev/null \
  || { echo "FATAL: the freshly built correlix-licence does not run (--help failed) — refusing to ship an unusable binary" >&2; exit 1; }

cat > "$BUNDLE_DIR/README.md" <<EOF
# Correlix — Quick Start ($VERSION)

1. Prepare the host (installs Docker, Compose v2, zstd, kernel settings —
   one time, needs your package mirror):

       sudo ./prepare-host.sh

   then log out and back in. (Hosts that already run Docker can skip this;
   the installer verifies everything either way.)
2. Extract this bundle (you have, if you can read this).
3. Run the setup console and choose Install (or just let it run —
   scripted/non-interactive runs install directly):

       ./install-correlix.sh

   Prefer a browser? Launch the graphical installer instead — it walks
   through check → prepare → install with live logs, from any machine on
   your network:

       ./install-correlix.sh gui

   then open the tokened URL it prints.

4. Open the UI URL printed at the end.
5. Sign in with the generated credentials shown on screen.

That's it. The installer checks your host, verifies the bundle, loads the
software, starts everything, waits until it's healthy, and prints where to go.

Host guidance: Linux x86_64 · 4 vCPU / 16 GB RAM / 100 GB disk recommended
(2 vCPU / 8 GB / 40 GB minimum for evaluation). No internet access needed.

Day-to-day:

    ./install-correlix.sh status            service health
    ./install-correlix.sh logs [service]    recent logs
    ./install-correlix.sh stop | start      stop/start (data kept)
    ./install-correlix.sh uninstall         remove (add --purge to delete data)
    ./install-correlix.sh reset-demo-data   fresh evaluation state, same login

Optional add-ons (not started by default; enable any time):

    ./install-correlix.sh enable log-search-ui     power-user log forensics UI
    ./install-correlix.sh enable self-monitoring   Grafana + container/host metrics

Something not working? See TROUBLESHOOTING.md.
Larger deployments and advanced configuration: ADVANCED.md.
Third-party license information: LICENSES.md.
Source code for the GPL/LGPL components we redistribute: source-offer/.
EOF

cat > "$BUNDLE_DIR/ADVANCED.md" <<EOF
# Correlix — Advanced Configuration

Most installations should use the default \`./install-correlix.sh\` and never
read this file.

## Recovering a lost admin password

If the \`admin\` password is lost (or the value in \`.env\` no longer
authenticates — the installer's post-install self-test will tell you), reset
it without losing any data:

1. Edit \`NetOps_Observability/deployment/docker/.env\` and set
   \`ADMIN_RESET_PASSWORD=<new password>\`.
2. Apply it to the running API:
   \`cd NetOps_Observability/deployment/docker && docker compose up -d --force-recreate api\`
3. Sign in as \`admin\` with the new password, then REMOVE the
   \`ADMIN_RESET_PASSWORD\` line from \`.env\` (it is a one-shot bootstrap
   knob, not a place to keep a live credential) and update
   \`ADMIN_INITIAL_PASSWORD\` to match so the documented credential stays true.

## Event bus modes

Correlix moves telemetry internally over a Kafka-compatible event bus.

1. **Embedded (default).** The bundle includes Apache Kafka (Apache-2.0),
   run as a single-node service inside the appliance. It is internal-only
   (never exposed on a host port), sized for evaluation and small
   deployments, and needs no configuration.

2. **External Kafka-compatible broker (enterprise).** Point Correlix at a
   broker cluster you operate instead of starting the embedded one:

       ./install-correlix.sh install --external-kafka \\
           --broker-urls broker1:9092,broker2:9092

   Requirements: Kafka-compatible API (Apache Kafka 3.x/4.x or compatible),
   reachable from this host's Docker network, PLAINTEXT listener (TLS/SASL
   support: contact us). Correlix creates/uses topics under the \`netops.\`
   prefix. All services resolve the bus through the single BROKER_URLS
   setting in \`NetOps_Observability/deployment/docker/.env\`.

## Host preparation & preflight

- \`sudo ./prepare-host.sh\` — one-time host setup: Docker Engine + Compose v2
  (Docker official repo), zstd/python3, docker daemon baseline (live-restore,
  log caps, no-new-privileges), dedicated \`correlix\` service account, kernel
  settings (incl. \`vm.max_map_count\` the log store requires), time sync,
  unattended security updates. Add \`--firewall\` for a UFW profile scoped to
  Correlix's ports.
- \`sudo ./prepare-host.sh --check\` — read-only audit (PASS/FIX per item);
  the installer runs this automatically and REFUSES to install on an
  unready host.
- Supported platforms: Ubuntu 22.04+ / Debian 12, x86_64. Other Linux may
  work (set \`CORRELIX_SKIP_OS_CHECK=1\` to bypass the gate) but is not
  validated.

## Pipeline diagnostics (\`correlix-debug\`)

When telemetry "goes in and does not come out", \`correlix-debug\` (shipped
next to the installer) sends ONE marked synthetic record through the real
ingest path and reports, hop by hop, where it was last seen:

    ./correlix-debug --help
    ./correlix-debug trace --root NetOps_Observability --kind syslog --device <device-id>

It writes one log file per module under
\`NetOps_Observability/data/debug/<timestamp>-trace-<id>/\`. Package that
session for support with:

    ./correlix-debug bundle --root NetOps_Observability --last 1

It signs in as the platform administrator, never writes to a device, tags
everything it injects as synthetic (so it is excluded from your log search),
and any log level it raises reverts automatically.

## Licence file (\`correlix-licence\`)

Correlix reads its entitlements from a signed licence file. \`correlix-licence\`
(shipped next to the installer) answers "is this file valid, and what does it
grant?" offline — from the file alone, without the product running:

    ./correlix-licence show    <licence.json>
    ./correlix-licence verify  <licence.json>

\`show\` prints the customer, tier, expiry, ceilings and features. \`verify\`
checks the signature and the dates and exits non-zero if the file is not valid
for this product, which is the check to run BEFORE installing one. Install the
file itself from the product's Administration → Licence page.

It uses the same verification code the product uses, so its answer and the
product's cannot disagree. It never contacts Correlix and never phones home.

## Other settings

- UI port: \`./install-correlix.sh install --ui-port 9443\`
- All tunables live in \`NetOps_Observability/deployment/docker/.env\`
  (generated at install; treat it as a secret).
EOF

cat > "$BUNDLE_DIR/TROUBLESHOOTING.md" <<EOF
# Correlix — Troubleshooting

**The installer said a check failed.** The message names the fix (install
Docker, free a port, more RAM/disk). Re-running \`./install-correlix.sh\` is
always safe.

**A service shows "not running" or "unhealthy" in status.**
Look at its logs: \`./install-correlix.sh logs <service>\` — then
\`./install-correlix.sh stop && ./install-correlix.sh start\`. Most one-off
startup issues clear on a restart.

**The UI URL doesn't load.** Check the Web Front Door and Correlix UI rows in
\`./install-correlix.sh status\`; confirm the port isn't firewalled
(\`curl http://localhost:<port>/\` from the host itself).

**I lost the admin password.** It's stored in
\`NetOps_Observability/deployment/docker/.env\` (ADMIN_INITIAL_PASSWORD) —
valid until you change it in Settings.

**I want a clean slate.** \`./install-correlix.sh reset-demo-data\` wipes
collected data but keeps your URL and login.

**Slow on small hosts.** 8 GB RAM is the evaluation floor; give the VM
16 GB / 4 vCPU for real use.
EOF

# 7e. OPERATIONS.md — the questions a customer asks on day 2, not day 1:
#     how big a host does this need, how do I upgrade, how do I go back, how do
#     I remove it. Kept out of README.md on purpose: the quickstart earns its
#     value by being short.
cat > "$BUNDLE_DIR/OPERATIONS.md" <<EOF
# Correlix — Operations ($VERSION)

## Host requirements

| | Evaluation | Production (recommended) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB | 100 GB+ (telemetry retention) |
| OS | Ubuntu 22.04+ / Debian 12, x86_64 | same |
| Network | none required | none required |

Correlix runs entirely on this host. It never contacts Correlix, and it needs
no internet access to install or to run.

Disk is the setting that matters: telemetry retention is what fills it. Give
the volume room to grow, and keep it under 85% — the log store stops accepting
writes when the filesystem gets close to full.

## Sizing to your workload

The installer sizes the stack to the host it finds. To size it to your
WORKLOAD instead, drop a \`correlix-sizing.yaml\` next to this file declaring
devices, flows/s, events/s, retention, users and tenants, then install. The
planner refuses, with a report, when the workload cannot safely fit the host —
that refusal is the feature.

    ./install-correlix.sh install          # size to the detected host
    CORRELIX_NO_SIZING=1 ./install-correlix.sh install    # opt out entirely

## Upgrading

1. Read RELEASE-NOTES.md in the NEW bundle.
2. Take a backup (below). An upgrade is not a substitute for one.
3. Extract the new bundle into its own directory — never over this one.
4. Run \`./install-correlix.sh\` from the NEW directory. It loads the new
   images, keeps your \`.env\`, your data and your login, and restarts the
   services in place.
5. Confirm with \`./install-correlix.sh status\` and sign in.

Your configuration and data live outside the bundle
(\`NetOps_Observability/deployment/docker/.env\` and
\`NetOps_Observability/data/\`), which is why an upgrade is a fresh directory
plus one command.

## Rolling back

1. \`./install-correlix.sh stop\` in the new directory.
2. \`./install-correlix.sh\` in the PREVIOUS bundle directory — its images are
   still in the bundle, so this needs no download.
3. \`./install-correlix.sh status\` to confirm.

Roll back only to the version you came from. Data written by a newer version is
not guaranteed readable by an older one, which is what step 2 of the upgrade is
for.

## Backups

Back up two things while the stack is stopped, or from a filesystem snapshot:

    NetOps_Observability/deployment/docker/.env     your secrets — treat as one
    NetOps_Observability/data/                      everything Correlix stores

Restore is the reverse: put both back, then \`./install-correlix.sh start\`.

## Uninstalling

    ./install-correlix.sh uninstall            # remove the services, KEEP data
    ./install-correlix.sh uninstall --purge    # remove the services AND data

\`--purge\` is irreversible. It deletes \`data/\` and every collected record.
EOF

# 7f. README.txt — the one file that assumes nothing. Plain text, one page, no
#     markdown syntax to read past, for someone on a server console who has
#     just untarred this and does not yet know what Correlix is.
cat > "$BUNDLE_DIR/README.txt" <<EOF
CORRELIX $VERSION - START HERE
$(printf '=%.0s' $(seq 1 $((22 + ${#VERSION}))))

WHAT THIS IS
  Correlix watches your network, correlates what it sees, and tells you what
  broke and why. Everything runs on YOUR server. No internet access needed,
  at install time or afterwards.

BEFORE YOU START
  A Linux x86_64 server (Ubuntu 22.04+ or Debian 12) you have sudo on.
  Recommended: 4 CPU, 16 GB RAM, 100 GB disk.
  Evaluation minimum: 2 CPU, 8 GB RAM, 40 GB disk.

INSTALL - THREE COMMANDS
  1)  sha256sum -c CHECKSUMS.sha256     confirm the download is intact
  2)  sudo ./prepare-host.sh            installs Docker; skip if you have it
  3)  ./install-correlix.sh             asks: graphical, or terminal?

  Log out and back in after step 2 - it adds you to the docker group.

  GRAPHICAL opens a setup wizard in your browser. It asks which management
  address to serve on, and serves it over HTTPS behind a one-time token that
  is printed in this terminal. Nothing else is exposed.

  TERMINAL walks the same install from a numbered menu, right here.

  Both paths run the same installer. Neither can do anything the other cannot.

WHEN IT FINISHES
  The installer prints your dashboard URL and the administrator password.
  The password is shown once. It is also written into
  NetOps_Observability/deployment/docker/.env - treat that file as a secret.

DAY TO DAY
  ./install-correlix.sh status          service health
  ./install-correlix.sh logs [service]  recent logs
  ./install-correlix.sh stop | start    stop/start, your data is kept
  ./install-correlix.sh uninstall       remove (add --purge to delete data)

WHAT ELSE IS IN THIS FOLDER
  README.md            the same quickstart, formatted
  OPERATIONS.md        sizing, upgrade, rollback, backup, uninstall
  ADVANCED.md          external Kafka, ports, licence file, diagnostics
  TROUBLESHOOTING.md   the usual first-day problems and their fixes
  SUPPORT.txt          how to reach us, and what to send
  RELEASE-NOTES.md     what changed in this version
  docs/index.html      the full product documentation, offline
  MANIFEST             exactly what this bundle contains
  CHECKSUMS.sha256     integrity manifest (the same file as SHA256SUMS)
  LICENSE LICENSING.md LICENSES/ LICENSES.md NOTICE
  source-offer/        source for the GPL/LGPL components we redistribute
EOF

# 7g. SUPPORT.txt — what to do before contacting anyone, and exactly what to
#     send when you do. Every tool it names ships in this folder.
cat > "$BUNDLE_DIR/SUPPORT.txt" <<EOF
CORRELIX $VERSION - SUPPORT
$(printf '=%.0s' $(seq 1 $((19 + ${#VERSION}))))

BEFORE YOU CONTACT ANYONE
  1) ./install-correlix.sh status    which service is unhappy?
  2) TROUBLESHOOTING.md              the usual first-day problems
  3) docs/index.html                 the full documentation, offline

COLLECT A DIAGNOSTIC BUNDLE
  ./install-correlix.sh support-bundle

  Writes one .tar.zst holding compose state, container logs, health, and store
  and bus summaries. Secret values are stripped. It carries no packet payloads
  and no telemetry records. Read its MANIFEST before you send it.

IF TELEMETRY GOES IN AND NOTHING COMES OUT
  ./correlix-debug trace --root NetOps_Observability --kind syslog --device ID
  ./correlix-debug bundle --root NetOps_Observability --last 1

  This sends one marked synthetic record through the real ingest path and
  reports, hop by hop, where it was last seen. It writes to no device, and
  everything it injects is tagged synthetic.

LICENCE QUESTIONS
  ./correlix-licence show   licence.json     customer, tier, expiry, ceilings
  ./correlix-licence verify licence.json     valid for this product? exit code

  Both work offline, from the file alone, with the product stopped.

WHAT TO SEND
  * the support bundle
  * this bundle's MANIFEST (it carries the version and the exact build)
  * what you expected, what happened, and when - with the timezone

WHERE TO SEND IT
  Your Correlix support contact, or the address in your agreement.
  Correlix never phones home. Nothing leaves your network unless you send it.
EOF

# 7h. RELEASE-NOTES.md — generated from the log, never hand-written, so it
#     cannot claim a change that is not in this build. Scope is the SHIPPABLE
#     paths (the same set bundle-staleness.sh measures drift over), and only
#     feat()/fix() subjects: a customer note is not a commit dump.
echo "-- generating release notes"
{
  printf '# Correlix %s — release notes\n\n' "$VERSION"
  printf 'Built %s from %s. Generated from the commit log; nothing here is\nhand-written.\n\n' "$(date -Is)" "$GITSHA"
  since="$(git -C "$ROOT" describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^ 2>/dev/null || true)"
  if [ -n "$since" ]; then
    printf 'Changes since %s.\n\n' "$since"
    range="$since..HEAD"
  else
    printf 'Changes in the most recent 120 commits (no previous release tag).\n\n'
    range="HEAD~120..HEAD"
  fi
  notes="$(git -C "$ROOT" log --no-merges --format='%s' "$range" -- src deployment scripts telemetry-catalog 2>/dev/null \
    | grep -E '^(feat|fix)(\([^)]*\))?!?: ' | head -200 || true)"
  if [ -z "$notes" ]; then
    printf 'No customer-visible changes were recorded for this build.\n'
  else
    printf '%s\n' "$notes" | sed 's/^/- /'
  fi
} > "$BUNDLE_DIR/RELEASE-NOTES.md"
# The lab-leak guard covers the source archive; release notes are a SECOND
# customer-facing surface generated from repo content, so it gets the same
# treatment rather than being trusted because it is "only text" (§16.5).
if grep -qE "$LAB_MARKERS" "$BUNDLE_DIR/RELEASE-NOTES.md"; then
  echo "FATAL: a lab identifier reached the generated release notes" >&2; exit 1
fi

# 7i. The offline documentation portal. docs-portal/build is a gitignored
#     build artifact that the frontend image COPYs, so `docker compose build`
#     above has already failed if it were missing — but a bundle silently
#     shipping no documentation is exactly the omission §16.1 forbids, so this
#     is checked by name rather than inferred.
[ -d "$ROOT/docs-portal/build" ] \
  || { echo "FATAL: docs-portal/build is missing — the customer bundle ships the documentation portal offline. Build it (cd docs-portal && npm ci && npm run build) and rerun." >&2; exit 1; }
[ -f "$ROOT/docs-portal/build/index.html" ] \
  || { echo "FATAL: docs-portal/build has no index.html — refusing to ship a documentation portal with no entry point" >&2; exit 1; }
echo "-- copying the offline documentation portal"
rm -rf "$BUNDLE_DIR/docs"
cp -a "$ROOT/docs-portal/build" "$BUNDLE_DIR/docs"

write_licenses
# The GPL/LGPL corresponding source ships in the SAME hand-over as the binaries
# it belongs to (GPL-2.0 §3a) — see write_source_offer() above. It is mirrored
# AFTER the notices so LICENSES.md's written offer and the tarballs it points at
# are produced by the same build, and BEFORE SHA256SUMS so the integrity manifest
# covers them.
write_source_offer

# Customer-doc licensing guard: nothing customer-facing mentions Redpanda
# outside LICENSES.md's "not shipped" statement.
if grep -qi 'redpanda' "$BUNDLE_DIR/README.md" "$BUNDLE_DIR/ADVANCED.md" "$BUNDLE_DIR/TROUBLESHOOTING.md"; then
  echo "FATAL: customer-facing bundle docs mention redpanda" >&2; exit 1
fi

# --- Release signing (#97, owner-gated) --------------------------------------
# Key custody is an OWNER decision: the product signing key is owner-held and
# lives OUTSIDE the repo and outside CI — NEVER generate or embed a signing
# key in this script or in a workflow. When CORRELIX_SIGNING_KEY (a GPG key id
# or fingerprint) is exported and its SECRET key exists in the local keyring,
# the bundle gains SHA256SUMS.asc (detached, ASCII-armored) and MANIFEST
# records the signing-key fingerprint. The fingerprint goes into MANIFEST
# BEFORE checksumming, so the signed SHA256SUMS covers the fingerprint claim.
# Unset ⇒ checksum-only bundle — unchanged behavior, announced loudly below so
# an unsigned release is a visible choice, never an accident. Set-but-missing
# key is a hard failure (§16.1): the operator asked for a signed bundle;
# silently shipping unsigned would be worse than failing the build.
SIGNING_FPR=""
if [ -n "${CORRELIX_SIGNING_KEY:-}" ]; then
  command -v gpg >/dev/null || { echo "FATAL: CORRELIX_SIGNING_KEY is set but gpg is not installed" >&2; exit 1; }
  # `|| true` + discarded stderr are justified (§16.1): a missing key makes
  # gpg exit non-zero with noisy chatter, and that exact failure is handled
  # LOUDLY on the next line as a FATAL with a clearer message than gpg's.
  SIGNING_FPR="$(gpg --batch --with-colons --list-secret-keys "$CORRELIX_SIGNING_KEY" 2>/dev/null \
    | awk -F: '$1 == "fpr" { print $10; exit }')" || true
  [ -n "$SIGNING_FPR" ] || { echo "FATAL: CORRELIX_SIGNING_KEY='$CORRELIX_SIGNING_KEY' has no secret key in the GPG keyring" >&2; exit 1; }
  printf 'signing-key %s\n' "$SIGNING_FPR" >> "$BUNDLE_DIR/MANIFEST"
fi

# Integrity manifest covers EVERY shipped artifact, including the
# correlix-setup binary (design gui-installer-2026-08.md §5 H6 — a binary
# outside SHA256SUMS is an unverifiable execution path on the customer host)
# and, for the same reason, correlix-debug (7c) and correlix-licence (7d).
# LICENSE, NOTICE and LICENSES/*.txt are listed explicitly: LICENSING.md is
# caught by ./*.md, but the extensionless notices and the two licence TEXTS the
# bundle's notice points at would otherwise sit outside the integrity manifest.
# It also covers ./source-offer/* (licence audit D2): the mirrored GPL/LGPL
# corresponding source is a compliance artifact, and a customer must be able to
# prove the tarball they received is the one we measured.
# ./*.txt covers README.txt and SUPPORT.txt.
(cd "$BUNDLE_DIR" && sha256sum ./*.tar.* ./*.md ./*.txt LICENSE NOTICE ./LICENSES/*.txt MANIFEST install-correlix.sh prepare-host.sh correlix-setup correlix-debug correlix-licence ./source-offer/* > SHA256SUMS)
# The documentation portal is a TREE, so it is appended rather than globbed: a
# documentation set the customer cannot verify is one an attacker can edit, and
# the offline portal is what a customer reads when the product will not start.
(cd "$BUNDLE_DIR" && find ./docs -type f -print0 | sort -z | xargs -0 sha256sum >> SHA256SUMS)

# CHECKSUMS.sha256 is the name a customer looks for; SHA256SUMS is the name the
# installer and every existing runbook use. A symlink gives both without a
# second file that can drift from the first.
ln -sfn SHA256SUMS "$BUNDLE_DIR/CHECKSUMS.sha256"

if [ -n "$SIGNING_FPR" ]; then
  gpg --batch --yes --local-user "$SIGNING_FPR" --armor \
    --output "$BUNDLE_DIR/SHA256SUMS.asc" --detach-sign "$BUNDLE_DIR/SHA256SUMS"
  # Self-check the fresh signature: an agent/passphrase hiccup must fail the
  # build HERE, not on the customer host (stderr left visible on purpose).
  gpg --batch --verify "$BUNDLE_DIR/SHA256SUMS.asc" "$BUNDLE_DIR/SHA256SUMS" \
    || { echo "FATAL: self-verification of fresh SHA256SUMS.asc failed" >&2; exit 1; }
  echo "== signed SHA256SUMS (key fingerprint $SIGNING_FPR — recorded in MANIFEST)"
else
  echo "NOTE: CORRELIX_SIGNING_KEY unset — bundle is CHECKSUM-ONLY (no SHA256SUMS.asc; key custody is an owner decision, #97)."
fi

echo "== done"
du -sh "$BUNDLE_DIR"/* | sed 's/^/   /'
