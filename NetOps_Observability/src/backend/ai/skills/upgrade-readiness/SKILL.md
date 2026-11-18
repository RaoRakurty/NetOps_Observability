---
name: upgrade-readiness
layer: platform
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-config-mgmt/SKILL.md
when_to_use: ready to upgrade, ready for an upgrade, upgrade readiness, pre-upgrade check, pre upgrade check, safe to upgrade, can i upgrade, before the upgrade, before upgrading, software upgrade check, image upgrade check, issu upgrade, issu capable, upgrade window
symptom_kinds: upgrade, change
tools: get_device_state, get_device_health, get_active_major_incidents, get_recent_changes, get_rca_verdict
gather:
  - get_device_state(device_id, area=upgrade)
  - get_device_health(device)
  - get_rca_verdict(correlation_id)
  - get_active_major_incidents()
  - get_recent_changes(device, window=7d)
look_for:
  - The version the device runs and the image it booted, read live, next to the target version the operator named. Correlix compares the two strings only; it does not check the vendor's compatibility or upgrade-path rules, and says so.
  - Room on the boot filesystem. Under 2 GiB free is short for a current IOS-XE image and its install-mode expansion; the operator must still check the target image's real size against the free space the device printed.
  - Where the device will boot from — the boot variable and, on IOS-XE, whether it boots packages.conf (install mode) or a single bundle file. An upgrade that leaves the boot variable pointing at the old image boots the old image.
  - Whether a second control processor can carry traffic while the active one is upgraded. A single control processor means the upgrade takes the device out of service, so it needs a maintenance window and the traffic it carries needs another path.
  - The device's health right now — CPU and memory from its telemetry, and uptime from the version read. Upgrading a box that is already under pressure, or that reloaded on its own today, mixes two problems.
  - Active incidents touching the device, and configuration changes in the last week. An upgrade on top of an open incident or an unfinished change makes either one harder to read afterwards; a change that merely preceded a symptom is correlated, not proven cause.
  - A read the device did not answer is CANNOT TELL, never ready.
decisions:
  - next=log-confirmation when state:collect=not_wired the device could not be read live, so its own log lines are the only evidence left and readiness cannot be judged
  - next=log-confirmation when state:collect=unsupported no read-only command is established for this platform, so readiness cannot be judged from the device and its own log lines are the only evidence left
  - next=platform-health when state:reload=recent the device came up within the last day, so why it reloaded has to be explained before any upgrade is planned
  - verdict=say READY, NOT READY with each reason, or CANNOT TELL with each read that was not collected; quote the current version, the boot image, the free space and the redundancy the device printed, compare the current version with the target the operator named, and state plainly that no change has been made and that Correlix does not check the vendor's compatibility rules
  - escalate=the change owner with the version, free space, redundancy and any open incident quoted when the device is not ready
---

# Upgrade readiness

Before a device is upgraded, read what the upgrade depends on — from the device
itself, read-only. Nothing in this method changes the device: no image is
copied, no boot variable is set, nothing is reloaded. It answers one question:
is this device ready for the upgrade someone is planning?

**Read, never assume.** The version, the boot image, the free space and the
redundancy state come from the device's own read-only commands. A figure the
device did not print is unknown, and an unknown makes the verdict CANNOT TELL,
not READY.

**Compare, do not certify.** Correlix compares the version the device runs
with the target the operator named. It does not know the vendor's supported
upgrade paths or image compatibility, and the verdict says so.

**Room, boot path, redundancy.** A new image needs room on the filesystem the
device boots from (under 2 GiB free is short for a current IOS-XE image). The
device must be told to boot the new image. And with a single control processor
the upgrade is an outage, so it needs a window.

**Health and timing.** A device under CPU or memory pressure, or one that
reloaded on its own today, should be explained before it is upgraded. An open
incident on the device or a change still settling makes the upgrade's effect
impossible to read afterwards.

**Take a baseline first.** Ask Iris to take a baseline of the device before the
change and to compare against it afterwards: interfaces, neighbours, routes and
tunnels before and after, side by side.

Method re-expressed from NetClaw's change-management (pre-change baseline,
post-change verification, rollback readiness — never its deployment step),
change-review and switch-system skills (Apache-2.0, see NOTICE).
