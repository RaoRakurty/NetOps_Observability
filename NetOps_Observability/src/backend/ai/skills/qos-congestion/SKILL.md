---
name: qos-congestion
layer: physical
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-troubleshoot/SKILL.md
when_to_use: congestion, congested, slow link, wan slow, choppy, voice choppy, jitter, output drops, drops on the interface, packet drops, queue drops, qos, queueing, link full, saturated, bandwidth exhausted, who is using the bandwidth
symptom_kinds: congestion, queueing
tools: get_device_state, get_metric_anomalies, get_top_talkers, get_flow_summary, get_rca_verdict, search_logs
gather:
  - get_device_state(device_id, area=interfaces, target=@interface)
  - get_rca_verdict(correlation_id)
  - get_metric_anomalies()
  - get_top_talkers()
  - get_flow_summary()
  - search_logs(device, window=6h)
look_for:
  - The interface's own counters, read live — input and output drops, the queue figures, and the error counters beside them. Without a named interface the live counters cannot be read; say which interface would answer it.
  - Drops with clean error counters. That is queueing — more traffic is offered than the link or its queue can take — not a faulty link.
  - Errors or CRCs beside the drops. Those accuse the physical link, and a congestion reading on top of a bad link is premature.
  - Whether the drops track traffic. Utilization or traffic anomalies in the same window, and the heaviest conversations from flow data, say who filled the link.
  - Whether the drops are one-sided. Output drops are this device sending more than the link carries; input drops are this device unable to take what arrives.
decisions:
  - next=log-confirmation when state:collect=not_wired the interface counters could not be read live, so the device's own log lines are the only evidence left
  - next=optics-degraded when state:if_faults=present the interface is counting errors or CRCs, so the link itself must be cleared before congestion is blamed
  - next=interface-down when state:if_oper=down the interface is operationally down, so this is a link failure rather than congestion
  - verdict=name the interface, the drop counters and their direction, say whether the error counters are clean, and name the heaviest conversations when flow data has them
  - escalate=the capacity owner with the interface, its drop counters and the top conversations attached when the drops persist with clean errors
---

# QoS and congestion

"The link is slow" has two very different causes: too much traffic for the link,
or a link that is corrupting what it carries. The counters tell them apart.

**Drops alone mean queueing.** A port that drops packets but counts no input
errors, no output errors and no CRCs is being offered more than it can send.
That is a capacity or QoS problem, and flow data names who is filling it.

**Errors change the question.** The moment error or CRC counters are rising next
to the drops, the physical link is the first suspect — check it before calling
anything congestion.

**Name the interface.** Live counters are read per interface; without one, say
which interface would answer and use the traffic anomalies and flow data meanwhile.

**Direction matters.** Output drops: this device is sending more than the link
carries. Input drops: this device cannot take what arrives.

Method re-expressed from NetClaw's troubleshooting method, slow-performance steps
(Apache-2.0, see NOTICE).
