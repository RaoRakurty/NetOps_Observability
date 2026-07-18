#!/usr/bin/env bash
# bundle-autoupdate.sh — daily customer-bundle lockstep (#97, owner directive
# 2026-07-18): as the code is built every day, the customer package rebuilds
# itself to match. Cron-driven sibling of stack-watchdog.sh, and the LOCAL
# counterpart of release-bundle.yml (which only fires on pushes to main /
# v-tags — day-to-day work lives on a feature branch, so without this the
# dist/ bundle silently ages, exactly the 300-commit drift the 2026-07-17
# audit found).
#
#   * runs bundle-staleness.sh; exits 0 quietly when the bundle already
#     matches HEAD's shippable code (docs-only days never rebuild);
#   * when stale: `make bundle` (full bundle: base + add-on packs) at HEAD;
#   * prunes old bundles, keeping the newest KEEP_BUNDLES (default 2) —
#     bundles are multi-GB and this host has had a disk-full incident;
#   * optional phone ping via the watchdog's ntfy topic on success/failure
#     (reads scripts/stack-watchdog.env; silent if absent);
#   * flock guard so a long build never overlaps the next cron firing.
#
# Install (daily, 03:30, after the nightly builds settle):
#   30 3 * * * /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/bundle-autoupdate.sh --quiet >> /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/bundle-autoupdate.log 2>&1

set -u -o pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
LOCK="$ROOT/dist/.bundle-autoupdate.lock"
KEEP_BUNDLES="${KEEP_BUNDLES:-2}"
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

say() { [ "$QUIET" = 1 ] || echo "$@"; echo "$(date -u +%FT%TZ) $*" >&2; }

# ntfy ping reuses the watchdog's topic — the bundle aging silently is exactly
# the class of quiet failure the watchdog exists for.
notify() {
  local msg="$1"
  # shellcheck disable=SC1091
  [ -f "$DIR/stack-watchdog.env" ] && . "$DIR/stack-watchdog.env"
  [ -n "${NTFY_TOPIC:-}" ] && curl -fsS -m 10 -d "$msg" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1
  return 0
}

mkdir -p "$ROOT/dist"
exec 9>"$LOCK"
if ! flock -n 9; then
  say "bundle-autoupdate: previous run still building — skipping"
  exit 0
fi

# Fresh? bundle-status exits non-zero when the newest bundle lags shippable code.
if bash "$DIR/bundle-staleness.sh" >/dev/null 2>&1; then
  say "bundle-autoupdate: bundle already matches HEAD's shippable code"
  exit 0
fi

# Disk preflight BEFORE any build: artifacts are bounded by the prune policy,
# but a build needs transient scratch — refusing loudly beats dying halfway
# (this 80G host has no free LVM extents; growth = hypervisor disk resize).
MIN_FREE_GB="${MIN_FREE_GB:-15}"
free_gb=$(( $(df -Pk "$ROOT/dist" | awk 'NR==2{print $4}') / 1024 / 1024 ))
if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
  say "bundle-autoupdate: SKIPPED — only ${free_gb}GiB free (< ${MIN_FREE_GB}GiB)"
  notify "Correlix bundle auto-update SKIPPED: ${free_gb}GiB free — clean disk or grow the VM disk"
  exit 1
fi

head_sha="$(git -C "$ROOT" rev-parse --short HEAD)"
say "bundle-autoupdate: stale — rebuilding customer bundle at $head_sha"
# Call the installer script directly, not `make bundle` — make is not
# installed on every host this cron runs on (caught first run, 2026-07-17).
if ! bash "$DIR/make-installer.sh" >>"$DIR/bundle-autoupdate.build.log" 2>&1; then
  say "bundle-autoupdate: BUILD FAILED at $head_sha (see bundle-autoupdate.build.log)"
  notify "Correlix bundle auto-update FAILED at $head_sha"
  exit 1
fi

# Prune: keep the newest KEEP_BUNDLES bundle dirs + their tar/sha256 siblings.
mapfile -t bundles < <(ls -1dt "$ROOT"/dist/correlix-*/ 2>/dev/null)
if [ "${#bundles[@]}" -gt "$KEEP_BUNDLES" ]; then
  for old in "${bundles[@]:$KEEP_BUNDLES}"; do
    base="${old%/}"
    say "bundle-autoupdate: pruning $(basename "$base")"
    rm -rf "$base" "$base"-bundle.tar "$base"-bundle.tar.sha256 \
      "$base"-bundle.tar.part-* 2>/dev/null
  done
fi

newest="$(ls -1dt "$ROOT"/dist/correlix-*/ 2>/dev/null | head -1)"
say "bundle-autoupdate: OK — $(basename "${newest%/}") now matches $head_sha"
notify "Correlix customer bundle auto-updated to $head_sha"

# VM appliance images ride the same lockstep: rebuild from the fresh bundle so
# a demo always has a bootable image. Disk-growth policy on this 80G host:
# NIGHTLY = qcow2 only (the demo default, ~⅓ the footprint and scratch);
# SUNDAYS = the full qcow2/vmdk/vhdx set, so VMware/Hyper-V artifacts are
# never more than a week old (or on demand: VM_FORMATS="..." make-vm-image.sh).
# VM_IMAGES=0 opts out; make-vm-image.sh preflights disk and fails loudly.
if [ "${VM_IMAGES:-1}" = 1 ]; then
  if [ -z "${VM_FORMATS:-}" ]; then
    if [ "$(date +%u)" = 7 ]; then VM_FORMATS="qcow2 vmdk vhdx"; else VM_FORMATS="qcow2"; fi
  fi
  export VM_FORMATS
  if bash "$DIR/make-vm-image.sh" >>"$DIR/bundle-autoupdate.build.log" 2>&1; then
    say "bundle-autoupdate: VM images rebuilt for $head_sha"
    notify "Correlix VM images (qcow2/vmdk/vhdx) updated to $head_sha"
  else
    say "bundle-autoupdate: VM IMAGE BUILD FAILED at $head_sha (see bundle-autoupdate.build.log)"
    notify "Correlix VM image auto-update FAILED at $head_sha"
    exit 1
  fi
fi
exit 0
