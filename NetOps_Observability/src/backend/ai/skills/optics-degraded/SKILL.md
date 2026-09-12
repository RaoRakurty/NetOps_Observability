---
name: optics-degraded
layer: physical
version: 1
when_to_use: crc errors, input errors, optics, ddm, light level, transceiver, sfp, dirty fibre, errors climbing, fcs errors, packet corruption
symptom_kinds: physical, errors, degradation
tools: get_device_state, get_device_health, get_metric_anomalies, get_topology_context, search_logs
gather:
  - get_device_state(device_id, area=interfaces)
  - get_device_health(device)
  - get_metric_anomalies()
  - get_topology_context(device_id)
  - search_logs(device, query=error, window=24h)
look_for:
  - The device's own counters and transceiver readings, read live: Rx/Tx power, bias, temperature and the error columns. A reading the device did not report is UNKNOWN, never zero.
  - Error counters that are RISING, not merely non-zero. A lifetime counter with no recent delta is history, not a fault.
  - Which direction the errors are on. Receive-side errors accuse the far end and the fibre; transmit-side errors accuse this device.
  - Whether the error rate tracks traffic volume. Errors proportional to load are usually a marginal optic; errors independent of load are usually the fibre or a connector.
  - Whether the link ever went down. Errors without a link transition are a brownout, and a brownout hurts applications long before it trips an alarm.
decisions:
  - next=interface-down when state:if_oper=down the port is operationally down, so this is a link failure rather than a brownout
  - next=log-confirmation when state:collect=not_wired the optics could not be read live, so the device's own alarms are the only evidence left
  - next=interface-down when the link has since transitioned
  - next=path-seam-handoff when the degraded link is the provider handoff
  - next=app-edge-5xx when the errors are too few to explain the reported application impact
  - next=log-confirmation when the device's own optic alarms would confirm the reading
  - verdict=name the interface, the error type, the rate of change and the direction
  - escalate=field engineering for a clean-and-reseat when receive errors persist across a reseat of the local optic
---

# Optics and error degradation

The fault operators most often miss, because nothing goes down. A link passing
traffic with a rising error rate is a brownout: retransmits, jitter, and an
application team that is certain the network is fine because every interface is
green.

**Rate, not total.** Report errors per interval over a stated window. "412,000
CRC errors" is meaningless without the window; "roughly 900 CRC per minute and
climbing since 02:10" is a finding.

**Direction names the owner.** Receive errors mean corrupted frames arrived —
look outward at the fibre, the connector, and the far-end transmitter.
Transmit errors and drops mean the local device could not send — look at
congestion and at this device.

**Correlate with load.** If the error rate rises and falls with utilisation, the
optic is marginal at speed. If it is flat regardless of load, suspect the
physical plant.

**Say what you could not see.** If digital diagnostics (light levels,
temperature) are not in the collected evidence, say so instead of implying the
optic was measured.
