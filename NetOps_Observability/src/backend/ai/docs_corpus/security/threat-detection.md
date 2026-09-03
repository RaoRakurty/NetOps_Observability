---
title: Review threat detections
description: "Work the two threat sub-views: device-log detections from the findings store, and flow-derived network behaviour computed from records already collected."
page_type: task
sidebar_position: 9
---

# Review threat detections

Threat Detection answers one question, "is something acting on this estate",
from two different bodies of evidence. Both are triage starting points that
ground into the correlation engine, and neither is a verdict on its own.

## Before you begin

- A role with `infrastructure:read`.
- For **Detections**, at least one completed scan with the `threat` family
  rules enabled. See [Enable a detection rule](/security/detection-rules).
- For **Network Behavior**, flow records arriving from your exporters. No new
  collection is required: the panels are computed from the flows already
  collected for traffic analytics.

## Steps

1. Go to **Security → Threat Detection**.
2. Select **Detections** for device-log and rule-engine verdicts, or **Network
   Behavior** for the flow-derived panels.
3. On **Detections**, sort by **Severity**, **Detection**, **Asset**,
   **Technique** or **Detected**, then select a row to open its detail.
4. On **Network Behavior**, set the global time range in the top bar. Every
   panel recomputes for the window you choose.
5. Cross-check a suspect against both sub-views before escalating.

## What you see

### Detections

Current findings whose evidence class is `signal`, rendered with the same
detail as any other finding. The columns are **Severity**, **Detection**,
**Asset**, **Technique** and **Detected**. The **Technique** column carries the
MITRE ATT&CK technique ids the rule maps to, and renders `untagged` when the
detection carries none.

The status line reads `N current device-log detections`.

When nothing has fired, the page says why rather than showing a reassuring
blank: no rule matched what was ingested, which does not mean the estate is
clean. Check **Network Behavior** for flow-derived activity, and the
[Detection Rules](/security/detection-rules) page for which detections are
enabled.

### Network Behavior

Four flow-derived panels for the selected window:

| Panel | What it ranks |
|---|---|
| Horizontal scan suspects | Distinct destination hosts per source, a network sweep signature |
| Vertical scan suspects | Distinct destination ports per source, a port-scan signature |
| Traffic to high-risk destination ports (bytes) | Bytes reaching ports associated with legacy management and lateral movement |
| All top destination ports | The busiest destination ports in the window, with high-risk ones marked |

Bars turn red at 25 or more distinct hosts or ports. That threshold is a
starting default. A management station, a backup server or a vulnerability
scanner will exceed it legitimately, so treat a new entrant to the list as the
finding rather than the list itself.

When no flow reached a high-risk port, the panel states
`No traffic to known high-risk ports (FTP/Telnet/SMB/RDP/VNC/DB/…) in this
window`. When the window holds no flows at all, the ports panel states
`No flow data in this window`. Those are different facts and the page does not
collapse them.

## Result

You can name, for the window you chose, which device-log detections fired and
on which assets, and which sources look like they are scanning. A source ranked
high on both fan-out panels, with real bytes moving to a high-risk port, has
progressed from reconnaissance to access.

Correlix is observability, not enforcement. Contain the source through your own
controls; the traffic stopping is what you will see here afterwards.

## What this is not

Correlix is not a SIEM. Threat Detection covers the network estate: device
logs, device configurations and flow records. Server, endpoint and
cloud-workload detection routes out to a partner SIEM, and there is no host
agent, no log-retention product and no user-behaviour analytics here.

A detection is evidence, not a verdict. Detections ground into the correlation
engine and surface as [exposure stories](/security/exposure-stories) when they
land on the same entity and seam as other telemetry.

## Related

- [Enable a detection rule](/security/detection-rules)
- [Exposure stories](/security/exposure-stories)
- [Investigate a security finding](/security/investigate-a-finding)
- [Security section overview](/security/overview)
