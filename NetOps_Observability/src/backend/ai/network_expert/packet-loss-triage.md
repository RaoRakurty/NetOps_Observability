---
id: packet-loss-triage
title: Packet Loss Triage
fault_domains: forwarding, interface, qos, wan, lan
signals: device_if_in_errors, device_if_in_discards, device_if_out_discards, probe_loss, device_optic_rx_power_dbm
keywords: packet loss, drops, discards, errors, crc, congestion, queue, taildrop, loss, retransmit
owner: Network / Triage
---

# Packet Loss Triage

## Symptoms
- Probe loss or application retransmissions without an obvious device-down.
- Interface discard/error counters incrementing.

## Common fault domains
- Physical: CRC/input errors, bad optic/cable (errors, not discards).
- Congestion: output discards / tail-drops on an oversubscribed queue.
- Policy: ACL/policer/QoS drop.
- Upstream/provider loss (local interfaces clean).

## Correlix evidence to check
- device_if_in_errors / in_discards / out_discards rates on the path interfaces.
- device_if_crc_errors and optic Rx power for physical faults.
- Utilization vs. capacity for congestion (out_discards with high util).
- Probe loss to localize the lossy segment.

## Supporting evidence
- CRC/input errors rising → physical (optic/cable).
- Output discards with >80% utilization → congestion.

## Contradicting evidence
- All local interfaces clean but probe loss present → upstream/provider segment.
- Loss only for one app/port → policy/QoS, not the link.

## Missing evidence
- Per-queue drop visibility may be absent (only aggregate discards).
- No hop-by-hop probe to pinpoint the exact lossy segment.

## Recommended owner
Network / Triage (route to physical, capacity, or provider owner per finding).

## Next actions
1. Separate errors (physical) from discards (congestion/policy).
2. For errors, check optic Rx power and the cable/transceiver.
3. For discards, check utilization vs. capacity and queue config.
4. Use probe loss to localize the segment.
5. Hand off to the matching owner (optics / capacity / provider / policy).

## Escalation note
Loss on <path/interface> since <start UTC>: errors=<rate>, discards=<rate>, util=<pct>. Classified as <physical | congestion | policy | upstream>.

## ITSM note template
Packet loss on <device>/<if> since <start UTC>. Type: <physical/congestion/policy/upstream>. Errors <rate>, discards <rate>. Impact: <apps/users>.
