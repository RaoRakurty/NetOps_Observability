---
name: platform-health
layer: platform
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-health-check/SKILL.md
when_to_use: high cpu, cpu high, cpu spike, cpu utilization, memory high, memory leak, out of memory, memory utilization, platform health, did it reload, rebooted, recent reload, reload reason, crashed, control plane busy
symptom_kinds: reload, crash
tools: get_device_state, get_device_health, search_logs, get_recent_changes, get_rca_verdict
gather:
  - get_device_state(device_id, area=platform)
  - get_device_health(device)
  - get_rca_verdict(correlation_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - The device's own readings, read live: CPU over the last five seconds, one minute and five minutes; processor memory used against total; uptime and the reason it last came up. A reading the device did not report is UNKNOWN, never healthy.
  - A busy CPU over five minutes, not one busy five-second sample. Short spikes are routing churn or a burst of management polling; a sustained high average is a process that needs naming.
  - Memory that is high AND climbing. A router that sits at a steady high figure is sized that way; one that rises toward the top over hours is leaking.
  - A recent reload. Uptime under a day reframes every other symptom — adjacencies, counters and logs all restarted with it. Say what the device names as the reload reason, quoted, and whether it reads as planned or as a crash.
  - Whether the clock is synchronized. A device off by seconds makes its log times disagree with every other device, so any timeline built from them is suspect.
  - Whether the device's configuration changed shortly before the symptom — a change that merely preceded it is correlated, not proven cause.
decisions:
  - next=log-confirmation when state:collect=not_wired the device's health could not be read live, so its own log lines are the only evidence left
  - next=log-confirmation when state:platform=cpu_high the CPU is pinned, so the device's log must name the process or the event that drove it
  - next=log-confirmation when state:platform=mem_high memory is near exhaustion, so the device's log must show allocation failures or the process holding it
  - next=log-confirmation when state:reload=recent the device came up within the last day, so its log must say why it reloaded and what restarted with it
  - next=ntp-clock when state:clock=unsynced the device's clock is not synchronized, so its timestamps cannot be lined up with any other device
  - verdict=name the reading that is out of bounds (CPU, memory, uptime or clock) with the device's own figure, and say plainly when every reading is within bounds
  - escalate=the platform owner with the CPU or memory figures and the reload reason quoted when the device keeps reloading or holds high memory
---

# Platform health

Before blaming a link or a protocol, read the box itself. A router with a
pinned CPU drops hellos and looks like it lost a neighbour; a router that
reloaded an hour ago looks like it had every fault at once.

**Read, never assume.** CPU, memory, uptime and clock come from the device's own
read-only commands. A figure the device did not print is unknown — say so; never
call an unread CPU calm.

**Thresholds are the device's figures against fixed lines.** CPU and memory are
reported above 90% as pressure. Uptime under a day is a recent reload. A clock
that is not synchronized, or off its reference by more than 100 ms, is a clock
problem. Everything else is reported as read.

**One busy sample is not a busy box.** Prefer the five-minute CPU average over
the five-second one; a spike that does not hold is noise.

**A reload changes the question.** When the device came up recently, the next
question is why it reloaded — the device's own log and its reload reason answer
that, not the counters, which restarted at zero.

Method re-expressed from NetClaw's device health check (Apache-2.0, see NOTICE).
