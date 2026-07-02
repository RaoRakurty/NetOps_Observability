# Failure-signature catalog — wave 3 (owner spec, 2026-07-02): 20 non-duplicative families

> Owner-provided third batch. Core rule: **a new signature is only allowed if it
> proves a DIFFERENT FAULT BOUNDARY with different required evidence** — vendor
> subtypes are valid only when they add ≥1 hard-required evidence item.
> Implementation dedupe against the shipped catalog (89 templates after waves
> 1–2, `790c512`) is below; full field detail (required/supporting/contradicting
> evidence, phrases, sample_evidence fixtures) is in the owner's YAML — mirror
> entries in `src/correlation/catalog.py`.

## Dedupe verdict vs shipped catalog

| Wave-3 id | Verdict |
|---|---|
| lan.stp-loop-broadcast-storm | NEW (storm/loop ≠ existing stp-topology-change: adds broadcast/CPU + MAC-move-rate required) |
| lan.path-mtu-discovery-blackhole | EXISTS in wave-2 backlog (`access.pmtud-blackhole`) → **PROMOTE to enabled** |
| wan.ipsec-gre-mtu-mss-blackhole | EXISTS enabled (`wan-edge.tunnel-mtu-blackhole`) |
| wan.qos-marking-policy-mismatch | NEW backlog (marking/classification ≠ policing drops) |
| wan.bfd-timer-instability | EXISTS in wave-2 backlog (`bfd-false-failover`) |
| wan.route-preference-leak-wrong-egress | NEW backlog |
| dc.kube-proxy-rules-desync | NEW backlog (endpoints EXIST, proxy path broken — ≠ endpoint-empty) |
| dc.csi-volume-attach-conflict | NEW backlog |
| security.fw-activeactive-session-owner-mismatch | **NEW enabled** (ownership/sync ≠ post-failover drift) |
| security.fw-zone-binding-policy-drift | NEW backlog |
| security.tls-inspection-trust-break | NEW backlog (middlebox trust ≠ server cert; lab Versa MITM is literally this) |
| security.proxy-pac-wpad-distribution-failure | **NEW enabled** (PAC/WPAD delivery ≠ proxy egress outage) |
| carrier.interconnect-mtu-mismatch | EXISTS in wave-2 backlog (`interconnect-jumbo-mtu-mismatch`) → **PROMOTE to enabled** |
| carrier.expressroute-arp-vlan-macsec-misconfig | EXISTS in wave-2 backlog (`expressroute-arp-unresolved`) → **PROMOTE + enrich (VLAN/MACsec kinds)** |
| cloud.private-dns-forwarding-ruleset-gap | **NEW enabled** (ruleset/link GAP ≠ forwarding LOOP in backlog) |
| cloud.private-dns-overlapping-zone-shadow | NEW backlog (zone precedence shadowing) |
| cloud.lb-health-check-source-blocked | EXISTS enabled (wave-2 `lb-probe-source-blocked`) |
| cloud.lb-health-check-protocol-host-header-mismatch | **NEW enabled** (probe SEMANTICS ≠ probe source) |
| cloud.lb-snat-hotspot-imbalance | **NEW enabled** (per-member skew ≠ global NAT exhaustion) |
| security.waf-body-inspection-limit-block | **NEW enabled** (size boundary ≠ rule false positive) |

Net: **7 new enabled + 3 backlog promotions (+1 enrichment) + 7 new backlog**.

## Uniqueness controls (owner) — adopted

- **Similarity lint**: no two enabled templates may share
  `(sorted seams, deployment_scope, sorted required kind-set)` — CI test.
- **Vendor subtype rule**: provider-specific variants must add a hard-required
  kind (enforced in review; ExpressRoute entry adds `macsec_or_vlan_mismatch`).
- **Contradiction ceiling / confirmed-needs-independent-modalities**: already
  engine-enforced (discriminator penalty; independence gate).
- **Negative fixtures**: the discriminator fixtures serve this today (look-alike
  scenarios asserting the OTHER signature wins); full per-signature negative
  fixture matrix = follow-up.
- Schema fields `fault_boundary` / `uniqueness_anchor` / `nearest_existing_signature`
  are ROADMAP (the discriminator's `else_prefer` currently records the nearest
  neighbor machine-readably).

## Composition flows (owner)

- BGP up + size-sensitive failure → interconnect-mtu-mismatch; BGP down →
  private-interconnect-bgp-down; both roll into "private interconnect
  data-plane impairment".
- LB 5xx: frontend reachable? → direct backend healthy? → probe source
  allowed? (source-blocked) → probe shape wrong? (host-header/protocol) →
  else target-health family.

## Midnight questions ↔ signature bindings + phrasing (owner)

Preserved verbatim intent: operator dialect = seam + strongest evidence +
missing evidence; manager dialect = scope + confidence posture. Rejected:
ownership claims from one plane ("root cause is ISP" from one probe,
"confirmed" from a single telemetry plane, "network issue" when WAF/TLS/DNS
evidence dominates).
