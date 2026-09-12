---
id: mtu-fragmentation
title: MTU / Fragmentation Issue
fault_domains: forwarding, mtu, overlay, vpn, wan
signals: pmtud_blackhole, tcp_mss, frag_needed, overlay_mtu
keywords: mtu, mss, fragmentation, pmtud, jumbo, df bit, overlay, vxlan, gre, ipsec, tunnel, large packets
owner: Network / Routing
---

# MTU / Fragmentation Issue

## Symptoms
- Small transfers / handshakes work, large transfers stall (classic PMTUD black hole).
- Overlay/tunnel (VXLAN/GRE/IPsec) breaks for large payloads.
- TLS handshakes or app payloads hang after the first packets.

## Common fault domains
- Path MTU smaller than endpoints assume; PMTUD ICMP blocked.
- Overlay encapsulation overhead not accounted for (tunnel MTU/MSS).
- Inconsistent MTU on a transit link.

## Correlix evidence to check
- The "small works, large fails" pattern in flows / app behavior.
- Interface MTU consistency along the path.
- ICMP "fragmentation needed" being filtered (PMTUD black hole).
- Overlay/tunnel config vs. underlay MTU.

## Supporting evidence
- Failures only above a packet-size threshold.
- A tunnel/overlay in the path with default MTU and no MSS clamp.

## Contradicting evidence
- Both small and large packets fail equally → not MTU; suspect loss/reachability.
- No overlay and uniform MTU → less likely MTU.

## Missing evidence
- Per-hop MTU not always observable; infer from the size threshold.
- ICMP filtering not directly visible.

## Recommended owner
Network / Routing.

## Next actions
1. Confirm the size-dependent failure pattern.
2. Check MTU consistency end-to-end, including overlay overhead.
3. Verify PMTUD ICMP isn't filtered.
4. Apply MSS clamp / correct tunnel MTU as appropriate.
5. Validate large-transfer success after the change.

## Escalation note
Size-dependent failure for <flow/app> since <start UTC>; threshold ~<bytes>. Overlay <type> in path. Suspected MTU/MSS or PMTUD black hole.

## ITSM note template
MTU/fragmentation issue on <path/app> since <start UTC>. Large packets fail (~<bytes> threshold). Overlay <type>. Fix: <MSS clamp | tunnel MTU | unblock PMTUD>.
