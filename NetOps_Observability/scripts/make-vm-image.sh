#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# make-vm-image.sh — build the Correlix APPLIANCE VM images from the newest
# customer bundle (#97 VM leg, owner directive 2026-07-18: demo-ready install
# artifacts in every virtualization format, always in sync with the build).
#
# What it produces (in dist/vm/):
#   correlix-<version>.qcow2   — KVM / Proxmox / OpenStack
#   correlix-<version>.vmdk    — VMware (streamOptimized)
#   correlix-<version>.vhdx    — Hyper-V
#   SHA256SUMS
#
# How: Ubuntu 24.04 cloud image + libguestfs (inside the vm-image-builder
# container — the host needs only Docker):
#   1. grow a copy of the base cloud image to APPLIANCE_DISK_GB;
#   2. apt-install docker.io + docker-compose-v2 + zstd INSIDE the image
#      (Ubuntu archive only — no third-party repos, licensing posture intact);
#   3. copy in the newest bundle + a one-shot systemd unit that runs
#      install-correlix.sh install on FIRST BOOT (secrets are generated
#      per-appliance at that moment — never baked into the image, same rule
#      as the bundle: secrets NEVER enter build artifacts);
#   4. compress to qcow2, convert to vmdk/vhdx, checksum.
#
# Formats: VM_FORMATS="qcow2 vmdk vhdx" (override to build fewer).
# Disk preflight: a build needs scratch ≈ 2× the final set. Aborts with a
# clear message below MIN_FREE_GB (default 25) — an automation run on a full
# host must fail loudly, not die halfway through image surgery.
#
#   ./scripts/make-vm-image.sh            # build (uses newest dist/ bundle)
#   ./scripts/make-vm-image.sh --check    # preflight only: report readiness

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
OUT="$ROOT/dist/vm"
CACHE="$ROOT/dist/.cache"
BUILDER_TAG="correlix-vm-image-builder"
BASE_URL="${UBUNTU_CLOUD_IMG_URL:-https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img}"
APPLIANCE_DISK_GB="${APPLIANCE_DISK_GB:-80}"
MIN_FREE_GB="${MIN_FREE_GB:-25}"
VM_FORMATS="${VM_FORMATS:-qcow2 vmdk vhdx}"
KEEP_VM_IMAGES="${KEEP_VM_IMAGES:-2}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

die() { echo "make-vm-image: ERROR: $*" >&2; exit 1; }
say() { echo "make-vm-image: $*"; }

# ── preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null || die "docker is required (the toolchain runs containerized)"

bundle_dir="$(ls -1dt "$ROOT"/dist/correlix-*/ 2>/dev/null | head -1 || true)"
[ -n "$bundle_dir" ] || die "no customer bundle in dist/ — run scripts/make-installer.sh (or bundle-autoupdate.sh) first"
bundle_dir="${bundle_dir%/}"
version="$(basename "$bundle_dir" | sed 's/^correlix-//')"

free_gb=$(( $(df -Pk "$ROOT/dist" | awk 'NR==2{print $4}') / 1024 / 1024 ))
if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
  die "only ${free_gb}GiB free under dist/ — need ${MIN_FREE_GB}GiB. Free space or point VM_IMG_SCRATCH/dist at a bigger volume."
fi

if bash "$DIR/bundle-staleness.sh" >/dev/null 2>&1; then
  say "bundle $version matches HEAD's shippable code"
else
  say "WARNING: bundle $version is STALE vs HEAD — the image will match the bundle, not HEAD (run bundle-autoupdate.sh first for lockstep)"
fi

if [ "$CHECK_ONLY" = 1 ]; then
  say "check OK — bundle=$version free=${free_gb}GiB formats='$VM_FORMATS' disk=${APPLIANCE_DISK_GB}G"
  exit 0
fi

mkdir -p "$OUT" "$CACHE"

# ── toolchain container (cached after first build) ───────────────────────────
docker build -q -t "$BUILDER_TAG" "$ROOT/deployment/docker/vm-image-builder" >/dev/null

# ── base cloud image (cached; sha-checked against the published SHA256SUMS) ──
base="$CACHE/$(basename "$BASE_URL")"
if [ ! -f "$base" ]; then
  say "downloading Ubuntu 24.04 cloud image"
  curl -fSL --retry 3 -o "$base.part" "$BASE_URL" && mv "$base.part" "$base"
fi

# ── first-boot payload ───────────────────────────────────────────────────────
work="$(mktemp -d "$ROOT/dist/.vmbuild.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cat > "$work/correlix-firstboot.service" <<'UNIT'
[Unit]
Description=Correlix appliance first-boot install
After=network-online.target docker.service
Wants=network-online.target
ConditionPathExists=!/opt/correlix/.installed

[Service]
Type=oneshot
TimeoutStartSec=0
WorkingDirectory=/opt/correlix/bundle
# Secrets (.env) are generated HERE, on the customer's appliance, first boot —
# never in the shipped image. The wrapper paints install progress on tty1 and
# leaves the access URL + credentials on the login screen (easy-install, owner
# requirement — a bare headless install looked like a hang).
ExecStart=/usr/bin/bash /opt/correlix/firstboot.sh
ExecStartPost=/usr/bin/touch /opt/correlix/.installed

[Install]
WantedBy=multi-user.target
UNIT

cat > "$work/firstboot.sh" <<'FIRSTBOOT'
#!/usr/bin/env bash
# Correlix appliance first-boot: run the bundle installer with a visible
# self-install screen on the VM console, then pin the access details to the
# login banner. Credentials shown here are the appliance's own first-boot
# generated secrets — the customer is told to change them at first sign-in.
set -uo pipefail
TTY=/dev/tty1
say() { printf '\n  %s\n' "$*" > "$TTY" 2>/dev/null || true; }

clear > "$TTY" 2>/dev/null || true
printf '\n\n   ██████╗ CORRELIX appliance — self-install\n' > "$TTY" 2>/dev/null || true
say "Installing… this can take several minutes on first boot."
say "Progress: journalctl -fu correlix-firstboot (from another console)"

phase() { say "▸ $1"; }
phase "Generating appliance secrets + loading container images"
if bash /opt/correlix/bundle/install-correlix.sh install; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ADMIN_USER="$(grep -m1 '^ADMIN_USERNAME=' /opt/correlix/bundle/.env 2>/dev/null | cut -d= -f2)"
  ADMIN_PASS="$(grep -m1 '^ADMIN_INITIAL_PASSWORD=' /opt/correlix/bundle/.env 2>/dev/null | cut -d= -f2)"
  cat > /etc/issue <<BANNER

  ┌────────────────────────────────────────────────────────────┐
    CORRELIX is ready.

    Open:      http://${IP:-<appliance-ip>}:8000
    Sign in:   ${ADMIN_USER:-admin} / ${ADMIN_PASS:-<see /opt/correlix/bundle/.env>}

    Change the password at first sign-in.
    Docs: README.md + TROUBLESHOOTING.md in /opt/correlix/bundle
  └────────────────────────────────────────────────────────────┘

BANNER
  say "✓ Correlix is ready → http://${IP:-<appliance-ip>}:8000"
  say "  Sign in: ${ADMIN_USER:-admin} (password on this screen after reboot, or /opt/correlix/bundle/.env)"
else
  RC=$?
  cat > /etc/issue <<BANNER

  CORRELIX first-boot install FAILED (exit $RC).
  Inspect:  journalctl -u correlix-firstboot
  Retry:    rm -f /opt/correlix/.installed && reboot

BANNER
  say "✗ Install failed (exit $RC) — see journalctl -u correlix-firstboot"
  exit "$RC"
fi
FIRSTBOOT
chmod +x "$work/firstboot.sh"

# ── assemble the appliance qcow2 ─────────────────────────────────────────────
say "building appliance image (this takes a while — libguestfs without kvm)"
img="$work/correlix-$version.qcow2.raw"
# --dns: the appliance's user-net DNS forwards to the CONTAINER's resolver;
# docker's default 127.0.0.11 loopback is unreachable from the qemu guest, so
# the guest's apt could not resolve (caught 2026-07-18). Real resolvers fix it.
docker run --rm --dns 1.1.1.1 --dns 8.8.8.8 -v "$ROOT/dist:/dist" -v "$work:/work" -v "$CACHE:/cache" "$BUILDER_TAG" bash -euo pipefail -c "
  # OFFLINE guest install: the libguestfs appliance has no reliable DNS (slirp
  # cannot reach docker's loopback resolver — three failed attempts 2026-07-18),
  # and the guest should not need internet anyway. Resolve + download the full
  # .deb closure HERE in the container (same noble/amd64 archive) and dpkg it
  # into the guest — deterministic, and matches the platform's offline ethos.
  apt-get -q update
  apt-get -q -y --download-only --no-install-recommends install docker.io docker-compose-v2 zstd
  mkdir -p /work/debs && cp /var/cache/apt/archives/*.deb /work/debs/

  qemu-img create -f qcow2 -F qcow2 -b /cache/$(basename "$base") /work/overlay.qcow2 ${APPLIANCE_DISK_GB}G
  virt-customize -a /work/overlay.qcow2 \
    --hostname correlix \
    --run-command 'growpart /dev/sda 1 || true' \
    --run-command 'resize2fs /dev/sda1 || true' \
    --mkdir /opt/correlix-staging \
    --copy-in /work/debs:/opt/correlix-staging \
    --run-command 'DEBIAN_FRONTEND=noninteractive dpkg -i /opt/correlix-staging/debs/*.deb && dpkg -s docker.io docker-compose-v2 zstd >/dev/null && rm -rf /opt/correlix-staging' \
    --mkdir /opt/correlix/bundle \
    --copy-in '/dist/$(basename "$bundle_dir")':/opt/correlix/ \
    --run-command 'mv /opt/correlix/$(basename "$bundle_dir")/* /opt/correlix/bundle/ && rmdir /opt/correlix/$(basename "$bundle_dir")' \
    --copy-in /work/correlix-firstboot.service:/etc/systemd/system/ \
    --copy-in /work/firstboot.sh:/opt/correlix/ \
    --run-command 'chmod +x /opt/correlix/firstboot.sh' \
    --run-command 'systemctl enable docker correlix-firstboot' \
    --run-command 'truncate -s 0 /etc/machine-id'
  # flatten overlay -> standalone compressed qcow2
  qemu-img convert -O qcow2 -c /work/overlay.qcow2 '/work/$(basename "$img" .raw)'
  rm -f /work/overlay.qcow2
  # container runs as root — hand the scratch dir back to the invoking user so
  # the host-side trap cleanup can remove it (exit-1-after-successful-build bug)
  chown -R $(id -u):$(id -g) /work
"

# ── emit requested formats + checksums ───────────────────────────────────────
final_q="$work/correlix-$version.qcow2"
for fmt in $VM_FORMATS; do
  case "$fmt" in
    qcow2) cp "$final_q" "$OUT/correlix-$version.qcow2" ;;
    vmdk)  docker run --rm -v "$work:/work" -v "$OUT:/out" "$BUILDER_TAG" \
             qemu-img convert -O vmdk -o subformat=streamOptimized "/work/$(basename "$final_q")" "/out/correlix-$version.vmdk" ;;
    vhdx)  docker run --rm -v "$work:/work" -v "$OUT:/out" "$BUILDER_TAG" \
             qemu-img convert -O vhdx "/work/$(basename "$final_q")" "/out/correlix-$version.vhdx" ;;
    *) die "unknown format '$fmt' (qcow2|vmdk|vhdx)" ;;
  esac
  say "built $fmt"
done
# Per-file checksums + PER-FORMAT pruning: nightly runs build only qcow2, the
# weekly run builds all three — pruning by set would delete the still-current
# vmdk/vhdx the morning after the weekly build. Keeping the newest
# KEEP_VM_IMAGES of EACH format preserves every format's latest artifact.
for f in "$OUT"/correlix-"$version".*; do
  case "$f" in *.sha256) continue ;; esac
  (cd "$OUT" && sha256sum "$(basename "$f")" > "$(basename "$f").sha256")
done
# Retention (owner policy 2026-07-18): 2 newest of each format stay LOCAL;
# older ones move to archive-outbox/ for cloud archive (Google Drive) instead
# of deletion. The uploader drains the outbox when the Drive destination is
# configured (owner to provide) — until then the outbox is the archive, and
# it still counts toward disk, so the uploader should land soon.
outbox="$OUT/archive-outbox"
for fmt in qcow2 vmdk vhdx; do
  mapfile -t have < <(ls -1t "$OUT"/correlix-*."$fmt" 2>/dev/null)
  if [ "${#have[@]}" -gt "$KEEP_VM_IMAGES" ]; then
    mkdir -p "$outbox"
    for old in "${have[@]:$KEEP_VM_IMAGES}"; do
      say "archiving $(basename "$old") → archive-outbox/ (cloud upload pending)"
      mv "$old" "$old.sha256" "$outbox/" 2>/dev/null || true
    done
  fi
done

say "OK — dist/vm/correlix-$version.{$(echo "$VM_FORMATS" | tr ' ' ',')} ready (first boot self-installs, generates secrets on the appliance)"
