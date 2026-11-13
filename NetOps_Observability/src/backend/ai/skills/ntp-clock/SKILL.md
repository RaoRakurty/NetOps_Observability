---
name: ntp-clock
layer: services
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-health-check/SKILL.md
when_to_use: ntp synchronized, ntp not synchronized, ntp unsynchronized, ntp status, ntp sync, clock sync, clock wrong, time wrong, timestamps wrong, clock drift, clock offset, stratum 16, are the clocks right, log times do not match
symptom_kinds: clock, synchronization
tools: get_device_state, search_logs, get_recent_changes, get_rca_verdict
gather:
  - get_device_state(device_id, area=platform)
  - get_rca_verdict(correlation_id)
  - search_logs(device, query=NTP, window=24h)
  - get_recent_changes(device, window=24h)
look_for:
  - The synchronization state the device prints, read live — synchronized or not, the stratum, the reference it names, and the offset. A device whose NTP read could not be parsed is UNKNOWN, never in sync.
  - Stratum 16 or no reference at all means the device has no usable time source.
  - The offset against its reference. Under 100 ms keeps logs and events lined up across devices; past it, timelines built from this device's timestamps start to drift; past a second they are unreliable.
  - When synchronization was lost. The device's own NTP log lines pin the moment, and a configuration change in the same window — a server address, an access list, a source interface — is the classic cause, though a change that merely preceded it is correlated, not proven cause.
  - Whether every device lost sync together. That points at the shared time source or the path to it, not at one router.
decisions:
  - next=log-confirmation when state:collect=not_wired the clock could not be read live, so the device's own NTP log lines are the only evidence left
  - next=log-confirmation when state:clock=unsynced the clock is not synchronized, so the device's log must pin when it lost its time source and which server stopped answering
  - verdict=say whether the clock is synchronized, quote the stratum, the reference and the offset the device printed, and say what that means for timestamps from this device
  - escalate=the owner of the time source with the reference and the loss time quoted when several devices lost synchronization together
---

# NTP and the device clock

Every timeline Correlix builds lines events up by their timestamps. A device
whose clock is wrong puts its events in the wrong place, and the cause of an
incident can appear to come after its effect.

**Read the device's own word.** Synchronized or not, the stratum, the reference
and the offset come from the device's NTP status, read live. When the read could
not be made or parsed, the clock state is unknown — say so.

**Two thresholds.** A synchronized clock within 100 ms of its reference is fine
for correlation. Beyond 100 ms it is worth fixing; beyond a second, treat this
device's timestamps as approximate in any timeline.

**Lost sync has a moment.** The device's log records when it lost its time
source; that moment, next to the configuration history, is what turns "the clock
is wrong" into a cause.

**One device or all of them.** If every device lost synchronization at once, the
shared time source or the path to it is the fault — not each router.

Method re-expressed from NetClaw's device health check, NTP step (Apache-2.0,
see NOTICE).
