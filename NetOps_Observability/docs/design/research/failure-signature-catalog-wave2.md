# Failure-signature catalog — wave 2 (owner spec, 2026-07-02)

> Owner-provided second batch (39 families in v0/v1/v2 waves) + the catalog
> design/non-overlap rules. Companion to `midnight-noc-questions.md` (wave 1,
> shipped `e919e5f`). This doc records the spec and the implementation mapping;
> the catalog itself lives in `src/correlation/catalog.py`.

## Non-overlap rules (uniqueness contract — enforced by authoring discipline + discriminators)

A new family must differ from every reserved one in: **fault domain**, **first
discriminator** (best next check — same first evidence object ⇒ merge),
**blast radius** (testable spread), **contradiction set** (≥1 different hard
contradiction), and **operator action** (same CLI/API check resolving both ⇒
not distinct).

## Disambiguation table (encoded as discriminators where the neighbor exists)

| New family | Nearest reserved | Hard discriminator |
|---|---|---|
| dupip.arp-flux | access.local-link-fault | link stays UP; ARP/MAC ownership flips |
| portsecurity.errdisable | access.local-link-fault | admin error-disabled with explicit cause |
| stp.tcn-storm | **already exists** (access.stp-topology-change) | — mapped, not re-added |
| fhrp.split-brain | access.fhrp-failover / path-asymmetry | TWO actives for one VIP; subnet partition |
| sdwan.control-connection-loss | sdwan-tunnel-degraded | controller control-plane down, data tunnels may pass |
| ipsec.rekey-proposal-mismatch | bgp-peer-flap | IKE/IPsec negotiation fails, not routing adjacency |
| mpls.vrf-route-target-mismatch | private-interconnect-missing-prefix | provider/CE-PE VRF membership, not cloud advertisement |
| lb.probe-source-blocked | lb-target-health-failure | backend healthy DIRECT; probe source ranges denied |
| private-endpoint-dns-mismatch | dns-failover-wrong-target | should resolve private IP, returns public/no override |
| k8s.pod-ip-exhaustion | k8s-service-endpoint-empty | pods cannot SCHEDULE (address capacity), not readiness |
| mesh.mtls-cert-rotation-failure | tls-cert-expired | east-west workload identity, not north-south edge cert |

## Waves (implementation status)

- **v0 (ENABLED + fixtures):** dupip.arp-flux, portsecurity.errdisable,
  fhrp.split-brain, sdwan.control-connection-loss, ipsec.rekey-proposal-mismatch,
  lastmile.circuit-flap, dx-optics-crossconnect-degrade,
  interconnect.vlan-tag-mismatch, lb.probe-source-blocked,
  private-endpoint-dns-mismatch, k8s.pod-ip-exhaustion,
  mesh.mtls-cert-rotation-failure. (stp.tcn-storm deduped → existing.)
- **v1 (backlog, DISABLED):** lan pmtud-blackhole, duplex/speed mismatch,
  nac/radius admission outage, bfd false-failover, mpls vrf/rt mismatch,
  sdwan app-id classification drift, anycast-gateway inconsistency,
  overlay-underlay MTU mismatch, tcam/fib exhaustion, expressroute ARP
  unresolved, gcp proxy-arp wrong-MAC, lb backend-bind mismatch,
  k8s ingress-class/annotation drift.
- **v2 (backlog, DISABLED):** internet pmtud-blackhole, mac-mobility storm,
  stale ARP/ND suppression, microburst buffer drops, server-bonding mismatch,
  adc probe-source block, interconnect jumbo-MTU mismatch, tgw route-propagation
  missing, provider-maintenance impact, interconnect LAG member loss,
  node-pressure NotReady churn, api rate-limit throttling, secret/config drift
  after deploy, private-DNS forwarding loop.

## Engine invariants (owner) — all test-pinned

1. Confirmed NEVER from one modality (`test_confirmed_impossible_from_single_plane` + gate).
2. Contradictions always reduce confidence (`test_contradiction_lowers_confidence…`).
3. A new signature must not attach when its reserved neighbor passes the same
   first discriminator — encoded as `discriminators` (absent/else_prefer) per
   the table above; the contradicted look-alike stays visible as the
   "ruled out because…" row.

## Confidence ladder (schema 0.2 intent → current engine mapping)

Owner's ladder (suspected: ≥1 strong or ≥2 weak, no hard contradiction /
likely: all required + ≥2 independent modalities + no hard contradiction /
confirmed: likely + ≥3 modalities + topology grounding + consistent blast
radius) maps onto the engine as: suspected = required matched; likely =
`confidence_label` (all required + supporting + uncontradicted); confirmed =
the independence gate (≥2 modalities/observers + independent pair + required
modalities witnessed) with topology grounding via the seam inventory. The
≥3-modality confirmed bar and blast-radius consistency check are ROADMAP
(needs the grounding context to carry blast-radius spread).

## Voice contract (unchanged from wave 1) — approved/rejected examples

Operator approved: "BGP is stable, but the affected private subnet is missing
from propagated routes." Rejected: "Cloud routing is broken." Manager approved:
"The private cloud path exists, but DNS is sending users to the public
endpoint." Rejected: "Azure DNS is down." Insufficiency is stated, never
hidden: "Evidence is insufficient to confirm root cause; missing TGW
propagation table and probe logs."
