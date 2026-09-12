---
id: sdwan-underlay-vs-overlay
title: SD-WAN Underlay vs Overlay
fault_domains: sdwan, overlay, wan, tunnel, provider
signals: tunnel_status, bfd_down, probe_loss, underlay_circuit, overlay_path
keywords: sdwan, sd-wan, underlay, overlay, tunnel, bfd, ipsec, transport, brownout, path selection, fabric
owner: Network / SD-WAN
---

# SD-WAN Underlay vs Overlay

## Symptoms
- SD-WAN tunnel/BFD down or brownout; application steered to a worse path.
- Loss/latency on one transport while another is healthy.
- Overlay reports degraded but the device is up.

## Common fault domains
- Underlay transport circuit (the provider link the tunnel rides).
- Overlay control / BFD timers / tunnel encapsulation.
- Path-selection policy reacting to brownout (intended, but worth confirming).

## Correlix evidence to check
- Tunnel/BFD status and overlay path metrics (loss/latency/jitter).
- Underlay circuit health (the WAN edge interface and probe on that transport).
- Whether a sibling transport is healthy (steering target).

## Supporting evidence
- Underlay circuit loss/latency mirrors the overlay degradation → underlay-driven.
- BFD down with a clean underlay → overlay/control issue.

## Contradicting evidence
- Both transports degraded → shared edge/device, not a single transport.
- Overlay clean but app slow → not the SD-WAN path.

## Missing evidence
- Provider-side underlay telemetry (expected) — use your measurements.
- Vendor controller state may be outside Correlix.

## Recommended owner
Network / SD-WAN (escalate the underlay to the circuit provider when it's the cause).

## Next actions
1. Separate underlay (transport) health from overlay (tunnel/BFD) state.
2. If underlay-driven, treat as a provider-circuit issue (see ISP/DIA playbook).
3. If overlay-driven, check BFD timers / tunnel config.
4. Confirm path-selection steered correctly to a healthy transport.
5. Validate application recovery on the selected path.

## Escalation note
SD-WAN degradation at <site> since <start UTC>: transport <t> <loss/latency>, overlay/BFD <state>. Classified <underlay | overlay>. Steered to <transport>.

## ITSM note template
SD-WAN <site> degraded since <start UTC>. Cause: <underlay transport | overlay/BFD>. Sibling transport <state>. Impact: <apps>. Provider escalation: <yes/no>.
