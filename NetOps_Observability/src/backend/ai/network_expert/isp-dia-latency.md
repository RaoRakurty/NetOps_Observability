---
id: isp-dia-latency
title: ISP / DIA Egress Latency
fault_domains: provider, isp, wan, dia, egress
signals: probe_rtt_anomaly, probe_loss, interface_errors, wan_edge, dia-egress
keywords: latency, dia, isp, provider, egress, wan, packet loss, rtt, jitter, slow internet, circuit
owner: Network / Provider
---

# ISP / DIA Egress Latency

## Symptoms
- Probe RTT increase and/or loss toward internet / DIA destinations.
- Application slowness for users whose path egresses the affected WAN edge.
- Impact tracks one provider circuit, not the whole fabric.

## Common fault domains
- Provider backbone / last-mile circuit degradation.
- Local WAN-edge interface (errors, congestion, optics).
- Egress policy / NAT / firewall on the DIA path.

## Correlix evidence to check
- Active-measurement probe RTT/loss on the DIA path (STAMP / synthetics).
- WAN-edge interface counters: in/out errors, discards, utilization.
- Flow impact: which apps/users traverse the affected egress.
- Correlation object owner_domain = Provider / seam_type = DIA.

## Supporting evidence
- Loss/latency confined to one circuit while an alternate path is clean.
- Provider-facing interface error or discard rate rising in the same window.

## Contradicting evidence
- All paths degraded equally → look at a shared core/overlay element, not the circuit.
- Clean probe RTT but app slowness → suspect app/DB tier, not the WAN.

## Missing evidence
- No alternate-path baseline to compare against.
- No provider-side telemetry (expected — escalate with your measurements).

## Recommended owner
Network / Provider team.

## Next actions
1. Confirm the loss/latency window and magnitude from probe data.
2. Check provider-facing interface for errors/discards/optics.
3. Compare the alternate path's health for the same window.
4. Confirm real application/user impact (flows + service view).
5. Prepare a provider escalation note with timestamps and measurements.

## Escalation note
Escalate to the circuit provider with: circuit id, affected window (UTC), measured one-way/round-trip latency and loss, and the clean alternate-path comparison.

## ITSM note template
Provider circuit <id> showing <loss>% loss / <rtt>ms RTT since <start UTC> on the DIA egress at <wan-edge>. Alternate path clean. Customer impact: <apps>. Provider escalation prepared.
