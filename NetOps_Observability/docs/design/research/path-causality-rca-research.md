# Path-Causality RCA — Grounding Research

**Purpose.** Ground the implementation of *path-causality RCA* (design:
`docs/design/path-causality-rca.md`). Core idea: RCA = discover the SRC→DST traffic
path from live telemetry, classify each segment by *pattern* (cloud / LAN / WAN / DC
/ WAN-seam / internet), then attribute an app symptom to the **broken link on that
path**. We do **not** statically define topology — we discover it and classify it.

**Method.** Web research against primary sources (vendor docs, RFCs, SIGCOMM/NSDI
papers, engineering blogs), adversarially sanity-checked, plus a read of the existing
engine (`src/correlation/path_graph.py`, `path_direction.py`,
`src/backend/seam_bootstrap.go`, `cloud_enrich.go`, `verdicts.py`,
`rca_path_view.go`). Every non-obvious claim is cited inline. Where prior art is thin
or cloud opacity blocks something, this report says so plainly.

**Bottom line up front.** Most of the *plumbing* already exists in the repo — a
measured-path direction oracle with ECMP `AMBIGUOUS` handling (`path_direction.py`),
a typed-segment path graph with provenance ranks and `unknown_hops`
(`path_graph.py`), a telemetry-driven seam classifier (`seam_bootstrap.go`), and a
default-closed `suspected`/`confirmed` verdict model (`verdicts.py`). The **net-new
work** is: (1) an **address-space segment classifier** (provider CIDR feeds + ASN +
RFC1918/6598 + rDNS + device-role), which the repo does *not* yet have; (2) wiring
that classifier into path assembly so every hop/segment gets a *type* + *confidence*;
and (3) an **on-path attribution walk** that restricts RCA candidates to devices on
the discovered path and lifts/caps the verdict by on-path corroboration. The academic
prior art (Sherlock / NetMedic / Shrink / SCORE) gives us the attribution math; the
honest caveat is that all of it assumes a topology we only *partially* see in cloud —
so we attribute precisely on the segments we can see and abstract opaque cloud
segments to a single "path element" rather than faking hop-level blame.

---

## Area 1 — End-to-end path discovery from telemetry

### Proven methods & the signals they yield

**A. Path tracing (traceroute family) — measured forwarding path, hop-ordered.**
The workhorse: send probes with increasing IP TTL; each router that decrements TTL to
0 replies ICMP Time Exceeded, revealing its interface IP; hop order = forwarding
order ([ThousandEyes, *How Path Trace Works*](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace)).

- **Classic traceroute is *wrong* on ECMP.** Varying any field in the first four
  octets of the transport header (which classic traceroute does per-probe, e.g. UDP
  dst-port) changes the flow identifier, so a per-flow load balancer sprays
  consecutive probes down *different* paths — producing phantom links, missing hops,
  and impossible topologies ([Augustin et al., IMC 2006, *Avoiding traceroute
  anomalies with Paris traceroute*](https://conferences.sigcomm.org/imc/2006/papers/p15-augustin.pdf);
  [Kentik, *The Power of Paris Traceroute*](https://www.kentik.com/blog/the-power-of-paris-traceroute-for-modern-load-balanced-networks/)).
- **Paris traceroute** fixes this by holding the flow-identifier 5-tuple **constant**
  across probes (for UDP: src/dst IP, protocol, src/dst port; for ICMP: src/dst IP,
  protocol, type/code/checksum), so every probe follows one consistent path — and can
  deliberately vary the flow-id to *enumerate* the ECMP diamonds
  ([paris-traceroute.net](https://paris-traceroute.net/about/)).
- **Dublin traceroute** adds **NAT detection** and multipath enumeration on top of the
  Paris technique ([dublin-traceroute.net](https://dublin-traceroute.net/)).
- **Can see:** responsive L3 interface IPs, per-hop RTT/loss, path changes over time.
  **Cannot see:** hops that block ICMP Time Exceeded (rendered as `* * *` /
  "white/unresponsive" nodes), L2 switches (invisible to TTL), and the *inside* of
  MPLS/cloud clouds unless the operator leaks TTL (see Area 4). ThousandEyes renders
  unresponsive interfaces as white nodes and shows a dotted `?` link when it can't
  even count the hidden hops ([ThousandEyes Path Visualization](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization)).

**B. Flow records — passive SRC→DST edges (5-tuples).** NetFlow / IPFIX / sFlow from
devices, and cloud VPC/NSG flow logs, give observed conversations without probing.

- **AWS VPC Flow Logs** yield `srcaddr`/`dstaddr`/`srcport`/`dstport`/`protocol`/
  `action`(ACCEPT/REJECT)/bytes/packets per ENI. **Critical limitation for path
  work:** `srcaddr`/`dstaddr` are the *two interfaces that communicated directly* — so
  traffic through an ELB shows only the *ELB's* IP, not the original client. You must
  use the v3+ `pkt-srcaddr`/`pkt-dstaddr` fields to recover the original packet
  endpoints across NAT gateways, load balancers, and transit gateways
  ([AWS, *Flow log records*](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html);
  [AWS, *Flow log limitations*](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)).
  Also not captured: AWS DNS/NTP/IMDS/DHCP, and some records are silently sampled out
  under capacity pressure. **Flow logs give edges, never hop order** — they tell you
  A↔B talked, not what was between them.
- **Azure NSG/VNet flow logs** and **GCP VPC flow logs** are analogous (endpoint
  5-tuples + action, subject to sampling).

**C. eBPF socket/connection tracing — host-side dependency edges.** Datadog's Cloud
Network Monitoring (formerly NPM) uses **eBPF kprobes** on Linux (kernel 4.4+) to hook
socket syscalls and conntrack-table insertions, attributing every TCP/UDP connection
to a process/container with low overhead ([eBPF Foundation case study](https://ebpf.foundation/case-study-datadog-uses-ebpf-to-improve-network-observability-accuracy-and-performance/);
[Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)).
It also runs agent-side **traceroutes (TCP/UDP/ICMP)** as "Network Path", and
**dynamic tests auto-discover paths from observed traffic** rather than manual config
([Datadog Network Path](https://docs.datadoghq.com/network_monitoring/network_path/)).
Cloud integrations then decorate the graph with managed entities (ELB, App Gateway).

**D. BGP / route collectors — AS-level path.** Public route-view data (RIPE RIS,
RouteViews) and per-device BGP tables give the AS-PATH and next-hop, i.e. the
*inter-domain* path skeleton where traceroute goes dark. Team Cymru's IP↔ASN service
maps any IP to its origin ASN + prefix and even to **peer ASNs one hop away**
(`v4-peer.whois.cymru.com`), useful for inferring upstreams
([Team Cymru IP-to-ASN](https://www.team-cymru.com/ip-asn-mapping)).

**E. DNS resolution chains.** The client's name→IP resolution (CNAME chains,
GeoDNS/anycast answers) is the *first segment* of many app paths and explains why two
runs hit different frontends. Treat the resolved chain as path evidence, not just
metadata.

### What leading tools do

- **ThousandEyes (Cisco):** agent-based Paris-style Deep Path Analysis, hop-by-hop
  with unresponsive-node and MPLS rendering; the reference bar for path viz
  ([docs](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization)).
- **Kentik:** flow-record-centric (NetFlow/IPFIX/sFlow/VPC) at ISP scale + synthetic
  Paris traceroute; strong AS-level and cloud rendering
  ([Kentik Paris blog](https://www.kentik.com/blog/the-power-of-paris-traceroute-for-modern-load-balanced-networks/)).
- **Catchpoint:** synthetic vantage-point probes + traceroute from a large external
  fleet (outside-in).
- **Datadog CNM/Network Path:** eBPF passive edges + agent traceroute + cloud-API
  entity discovery; "dynamic tests" auto-derive paths from real traffic
  ([Datadog](https://docs.datadoghq.com/network_monitoring/network_path/)).
- **Dynatrace Smartscape:** agent (OneAgent) process/host/service dependency graph
  built from observed comms — dependency-first, not hop-first.
- **NetBrain:** discovers device configs/routing tables and *calculates* the path
  from the control plane (route/ACL simulation), complementary to measured traceroute.
- **Cisco AI Canvas / ThousandEyes:** fuses owned-network telemetry with the
  ThousandEyes Internet/cloud path view for cross-domain correlation.

### Pitfalls

- ECMP (fix with Paris flow-id pinning); ICMP-blocking hops (`* * *`); L2 invisibility;
  NAT rewriting endpoints (need `pkt-*` fields / Dublin NAT detection); flow-log
  sampling and "direct-interface-only" endpoints; asymmetric routing (forward ≠ reverse
  path); rate-limited ICMP replies inflating apparent loss.

### Recommendation for our Go + Python engine

- **Reuse, don't rebuild.** `src/correlation/path_direction.py` is already a
  **precedence-1 measured-path oracle**: it resolves ordered hop IPs → devices and
  emits `A_UPSTREAM`/`B_UPSTREAM`, returning **`AMBIGUOUS` when a pair is seen in both
  orders (ECMP/loop)** and abstaining (`UNKNOWN`) on unresolved hops. Keep this as the
  top-ranked discovery source. Confirm the probe collector (`collectors/traceroute.go`,
  `FEATURE_TRACEROUTE`) is Paris-consistent (constant flow-id per path) — the codebase
  already pins `golang.org/x/net` ipv4+icmp for per-packet TTL control, which is
  exactly what a Paris implementation needs.
- **Fuse four discovery sources with explicit precedence** (this mirrors
  `seam_bootstrap.go`'s multi-source rules and `path_graph.py`'s provenance ranks):
  `measured traceroute (rank 1) > flow-derived edges (rank 3–4) > cloud-inventory
  edges LB→backend/SG→subnet (rank 4–5) > BGP/route-inferred (rank 6, supporting
  only)`. `path_graph.py` already encodes `OBSERVED` (may establish an edge) vs
  `INFERRED` (supporting/explanatory only) and forbids an edge without an
  `evidence_ref` — keep that discipline for every discovered edge.
- **For cloud, prefer inventory + provider verdict over probing.** VPC flow logs and
  cloud APIs give LB→backend and SG↔subnet↔host edges we can trust; intra-cloud
  traceroute is largely opaque. `cloud_enrich.go` already lets the provider's own
  status check win — extend that: the cloud segment's *edges* come from inventory, its
  *health* from provider telemetry + our active checks.
- **Always capture the DNS/resolved-frontend as the path head** so ECMP/anycast
  frontend variation is explained, not treated as a discovery failure.

---

## Area 2 — Segment / hop classification (cloud vs LAN vs WAN vs DC vs internet)

This is the **biggest net-new component** — the repo has telemetry-driven seam
suggestion (`seam_bootstrap.go`) and boundary labels (`BOUNDARY_OF_KIND` in
`path_graph.py`) but **no address-space classifier**. Below are the concrete signals,
each with strength and failure modes, and how to fuse them default-closed.

### Signal 2.1 — Cloud-provider published IP-range feeds (strongest for CLOUD)

- **AWS `ip-ranges.json`** — `https://ip-ranges.amazonaws.com/ip-ranges.json`.
  Structure: `syncToken`, `createDate`, `prefixes[]` (each with `ip_prefix`, `region`,
  `network_border_group`, `service`), `ipv6_prefixes[]`. `service` values include
  `AMAZON`, `EC2`, `S3`, `CLOUDFRONT`, `ROUTE53`, etc.; **every specific range is also
  listed under `AMAZON`**, so match the most specific service first. Authoritative,
  generated from AWS's system-of-record, **changes several times per week** — must be
  refreshed on a cron ([AWS blog](https://aws.amazon.com/blogs/aws/aws-ip-ranges-json/);
  [AWS syntax docs](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html)).
- **Azure Service Tags** — weekly JSON ("Azure IP Ranges and Service Tags – Public
  Cloud", plus per-cloud files for Gov/China) with `values[]`, each a tag object:
  `name`, `id`, `properties.region`, `properties.systemService`,
  `properties.addressPrefixes[]`, plus per-subsection `changeNumber` for change
  detection. No auto-serving CDN URL — download by ID, or use the **Service Tag
  Discovery REST API** / `Get-AzNetworkServiceTag` on a cron
  ([MS Download 56519](https://www.microsoft.com/en-us/download/details.aspx?id=56519);
  [Azure service tags overview](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview)).
- **GCP** — `https://www.gstatic.com/ipranges/cloud.json` (GCP prefixes, with
  `service`/`scope` region metadata) and `goog.json` (all of AS15169 incl.
  consumer properties; a superset of `cloud.json` with **no** service/region
  metadata). Public CDN, no auth. The legacy `_cloud-netblocks.googleusercontent.com`
  **DNS TXT/SPF** chain still resolves but is **incomplete** — Google now says read
  `cloud.json` ([GCP IP ranges guide](https://sanj.dev/2020/10/gcp-ip-ranges/);
  [Google App Engine outbound IPs](https://docs.cloud.google.com/appengine/docs/standard/outbound-ip-addresses)).
- **Strength:** authoritative for "is this IP in provider X, which region, which
  service." **Failure modes:** feeds go stale (refresh weekly+); `goog.json` has no
  region/service; a customer's own IP announced into the cloud (BYOIP) won't match;
  overlap between `AMAZON` and specific services requires longest-service-match.

### Signal 2.2 — ASN / BGP / IRR (transit vs cloud vs eyeball)

Map hop IP → origin ASN via **Team Cymru** DNS/WHOIS/bulk interface (aggregates all 5
RIRs; ~10k IPs/minute; also exposes peer-ASN one hop away)
([Team Cymru](https://www.team-cymru.com/ip-asn-mapping)). Maintain a small curated
table of **cloud ASNs** (AWS 16509/14618, Google 15169/396982, Azure 8075, etc.) and
**major transit/Tier-1 ASNs**. ASN class → segment hint: cloud ASN ⇒ CLOUD, transit
ASN ⇒ WAN/Internet, unknown public ASN ⇒ Internet.
**Strength:** good coverage where CIDR feeds miss (transit backbones).
**Failure modes:** ASN ≠ operator intent (leased space), sibling ASNs, and ASN alone
never distinguishes DC-LAN from cloud (both may be RFC1918 internally).

### Signal 2.3 — RFC1918 / RFC6598 address-space detection (LAN/DC vs CGNAT)

- **RFC1918 private space** (`10/8`, `172.16/12`, `192.168/16`) ⇒ on-prem LAN/DC
  fabric (or intra-VPC — disambiguate with cloud context).
- **RFC6598 shared/CGNAT space** `100.64.0.0/10` ⇒ a **carrier/SP** segment
  (ISP-side of a CGN, distinct from RFC1918) — a strong WAN/Internet-edge signal, not
  a private LAN ([RFC 6598](https://datatracker.ietf.org/doc/html/rfc6598)).
- Loopback/link-local/multicast/reserved ⇒ drop or mark non-topological.
  **Strength:** deterministic and free. **Failure modes:** RFC1918 is ambiguous between
  on-prem DC and cloud-internal — it *must* be combined with cloud context (Signal 2.1)
  or CDP/LLDP fabric evidence (Signal 2.6) to split LAN/DC from intra-cloud.

### Signal 2.4 — Reverse-DNS (PTR) naming heuristics

PTR names often encode provider, region, and role: `ec2-3-23-155-245.us-east-2.
compute.amazonaws.com` (AWS region-encoded), `*.1e100.net` (Google), plus carrier
router names encoding POP/geo/role. Router-fingerprinting and rDNS-geolocation work
extracts these via regex/dictionaries and produces **candidate labels with confidence
scores**, and treats multiple interfaces sharing a hostname as aliases of one router
([rDNS geolocation, arXiv 1811.04288](https://arxiv.org/pdf/1811.04288);
[AWS EC2 reverse DNS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Elastic_Addressing_Reverse_DNS.html)).
**Strength:** cheap corroboration, sometimes reveals role. **Failure modes:** PTR is
frequently absent, stale, generic, or spoofable — **never trust it alone** (matches the
existing `service_infer` "a lone hostname is weak" discipline).

### Signal 2.5 — TTL / latency signatures

Observed **initial TTL** (64 Linux, 128 Windows, 255 many network OSes) fingerprints
device family; **RTT step-changes** across consecutive hops flag a **long-haul WAN
segment boundary** (e.g. a +40 ms jump = a continental hop). **Strength:** useful
segment-boundary hint. **Failure modes:** TTL rewriting, queuing jitter, and
asymmetric return paths make latency a *hint*, never a classifier on its own.

### Signal 2.6 — Device-role inference (LAN/DC roles + service devices)

- **LLDP/CDP neighbors** ⇒ this node is inside a switched fabric (LAN/DC), and the
  neighbor graph gives role (leaf/spine/edge).
- **SNMP `sysObjectID`** → vendor/model via the enterprise OID tree; **`sysDescr`**
  parse → OS/family; **ENTITY-MIB** → chassis/module structure. These map a device to
  role (switch/router/firewall/LB). The repo already ships 9-vendor SNMP profiles and
  a sysObjectID→vendor detection map.
- **Strength:** authoritative role for *our own* managed devices. **Failure modes:**
  none of this exists for cloud-managed or third-party hops — hence default-closed.

### Combining weak signals (the classifier core)

Use **weighted evidence with default-closed to `unknown`** — the same posture as the
existing verdict model:

1. **Deterministic wins first:** provider-CIDR match (2.1) or RFC6598 (2.3) →
   high-confidence CLOUD / CGNAT-WAN. RFC1918 → LAN/DC *candidate* pending
   disambiguation.
2. **Corroborate with ASN (2.2)** and **device-role (2.6)** — agreement raises
   confidence, disagreement caps it.
3. **rDNS (2.4), TTL/latency (2.5)** are **tie-breakers/hints only**, never sole basis.
4. **Score → tier:** require ≥2 independent signals for a *confident* type; a single
   weak signal yields a *low-confidence* label; **no matching signal ⇒ `unknown`
   segment with a stated reason** — never guessed as a specific type and never assumed
   healthy. This is exactly the design doc's default-closed rule and matches
   `path_graph.py`'s "an edge that cannot state its evidence is not emitted."

### What leading tools do

Kentik/ThousandEyes tag hops by ASN + provider CIDR + rDNS and group by network;
Datadog decorates paths with cloud-API entity identity; NetBrain uses discovered
device configs for role. None publish a magic classifier — they all **fuse
address-space + ASN + naming + inventory**, which is what we should do.

### Recommendation

- Build a **`segment_classifier`** module (Python `src/correlation/` for the
  path-assembly side; a Go mirror in `src/backend/` for enrichment at ingest). Inputs:
  hop IP (+ optional device id). Output: `{segment_type, device_role, confidence,
  signals[], reason}`. **Segment types reuse the existing vocabulary**
  (`BOUNDARY_OF_KIND`: LAN, SD-WAN/WAN, CARRIER, CLOUD, UNKNOWN; plus WAN-seam kinds
  already in `seams.go`: `ipsec`/`dx`/`vpn`/`nva`/`transit`).
- **Feeds as data, not code** (design doc §3 "new provider CIDR sets are data"): a
  refresher job pulls AWS/Azure/GCP feeds on a weekly cron into a compact,
  longest-prefix-match structure (a radix/patricia trie of CIDR→{provider,region,
  service}); ship a **bundled snapshot** so a clean offline build still classifies
  (matches the repo's offline-build rule), refresh live when reachable.
- **Curated ASN + cloud-ASN table** checked in; Team Cymru lookups cached per-tenant
  with TTL. **RFC1918/6598 ranges** as constants. **Per-tenant** classification cache
  (isolation — never share a classification row across tenants).
- **Default-closed and multi-signal enforced in tests** — one pattern-per-test, an
  `unknown` test, and a "single weak signal never confident" test (mirrors
  `test_classify_probe.py`).

---

## Area 3 — Path-causality / dependency-based fault localization (the RCA core)

Two prior-art traditions, and we need both: **dependency *discovery*** (learn "A
depends on B" from traffic/timing — Orion, eXpose, NetMedic, OTel service graphs) to
build the path, and **topology/risk-model *localization*** (invert observations to the
fewest/most-likely on-path causes — Shrink, SCORE, Sherlock) to attribute.

### Per-system mechanism

- **Sherlock (SIGCOMM 2007).** Builds an **inference graph** of root-cause nodes,
  per-(client×service) observation nodes, and **meta-nodes** modeling propagation:
  `noisy-max` (any parent down ⇒ child likely down), `selector` (load balancer picks 1
  of N), `failover` (redundancy — needs *all* down). Every node is **tri-state:
  up / troubled / down** — the "troubled" state captures *partial degradation*, the
  common app symptom. The **Ferret** algorithm scores candidate assignment vectors by
  P(observed | assignment) and ranks them; it explicitly handles **multiple
  simultaneous faults** (bounded ≥2-abnormal vectors). An observation is only explained
  by causes **on its dependency chain** — off-path causes can't raise its failure
  probability ([MSR page](https://www.microsoft.com/en-us/research/publication/towards-highly-reliable-enterprise-network-services-via-inference-of-multi-level-dependencies/);
  tri-state/meta-node mechanics confirmed in derived patent
  [US8015139](https://patents.google.com/patent/US8015139)).
- **NetMedic (SIGCOMM 2009).** Fine-grained dependency graph (processes, machines,
  **network paths**, config), each component a **multi-variable state vector**.
  Estimates edge weight = **likelihood source is currently impacting destination**
  using **joint history** (find past windows where source looked like it does now; did
  the destination then look like it does now?) — no semantic knowledge required. A
  culprit must (a) have a high-impact edge path to the affected component **and** (b)
  its own abnormality **not be explained by anything further upstream** — the
  **explaining-away / "buck stops here"** rule that walks blame to the true origin and
  avoids blaming a mid-path victim ([PDF](https://www.sysnet.ucsd.edu/sysnet/miscpapers/netmedic-sigcomm09.pdf)).
- **SCORE / MinSetCover + Shrink.** The cleanest statement of on-path Occam reasoning.
  Model a physical cause → the set of logical links that fail together (SRLG) as a
  **bipartite graph** (cause → observation). **SCORE**: the smallest cause-set covering
  all failed observations (minimum hitting set, greedy) — pure Occam. **Shrink**:
  upgrades to a **Bayesian network** over the same graph, returning the *most likely*
  cause-set weighted by each cause's **prior failure probability**, and **tolerant of
  noisy/incomplete observations** (<2% error where MinSetCover hit 20%) — the central
  lesson being *your topology map will be wrong; attribution must be robust to it*
  ([Shrink PDF](https://groups.csail.mit.edu/netmit/wordpress/wp-content/themes/netmit/papers/shrink.pdf);
  [SCORE, NSDI'05](https://dl.acm.org/doi/10.5555/1251203.1251208)).
- **Orion / eXpose — dependency discovery.** Orion infers "A depends on B" from
  **typical delay-spike signatures** in the A↔B traffic-delay distribution, passively
  from packet headers ([MSR](https://www.microsoft.com/en-us/research/publication/automating-network-application-dependency-discovery-experiences-limitations-and-new-solutions/)).
  eXpose learns communication rules `X ⇒ Y` scored by **JMeasure** (information-
  theoretic significance, base-rate-corrected so constant background traffic isn't
  mistaken for a dependency) — a rigorous **gate** for "is this edge real or
  coincidence?" ([eXpose PDF](https://groups.csail.mit.edu/netmit/wordpress/wp-content/themes/netmit/papers/eXpose.pdf)).
- **Groot (eBay, 5,000 services, 2021) — modern industrial anchor.** Real-time
  **event-causality graph** (nodes = metric-deviation/status/**deploy** events), edges
  added **only where domain rules match**, ranked by customized **PageRank**. Exhibits
  exactly the behavior we want: a service with *two* loud alerts is **eliminated**
  because no causal rule links its event types to the symptom (**severity ≠
  causality**), and an anomaly in a **different data center** is dropped as off-path
  (**locality check**) ([arXiv 2108.00344](https://arxiv.org/pdf/2108.00344)).
- **Modern causal-discovery RCA (PC/FCI + random walk) — cautions.** Detect anomalies
  → infer causal graph via conditional-independence tests → rank with random walk. Two
  documented pitfalls we must design against: **unobserved confounders create spurious
  edges and false root-cause alarms** (PC assumes none; FCI tolerates latent
  confounders), and causal discovery **degrades badly at scale** — so **pre-scope to
  the on-path subgraph** before any causal inference
  ([arXiv 2408.13729](https://arxiv.org/html/2408.13729v1)).

### Synthesized on-path attribution principles (what to implement)

1. **Candidate set = devices ON the discovered path, only.** An anomaly not on the
   SRC→DST path cannot be the cause of *this* symptom, regardless of severity (shared
   invariant of Sherlock, NetMedic, Shrink).
2. **On-path corroboration raises confidence; off-path coincidence is discounted.**
   Confidence scales with how many independent on-path symptoms a device explains and
   how well its own state explains them; off-path / wrong-locality / no-causal-rule
   anomalies are dropped even when loudest (Groot's two eliminations).
3. **Minimal-set-cover + priors (Occam).** Prefer the smallest on-path cause-set that
   explains all symptoms (SCORE), weighted by prior failure likelihood (Shrink). One
   on-path fault explaining ten symptoms beats ten off-path attributions.
4. **Explaining-away ("buck stops here").** Name X only if X is on-path **and** X's own
   abnormality isn't explained by something further upstream (NetMedic) — prevents
   blaming a mid-path victim.
5. **Gate every dependency edge with a significance test** (eXpose JMeasure / Orion
   delay-spikes) so background co-occurrence doesn't manufacture a path.
6. **Multiple faults: allowed but bounded.** Assume one on-path cause first; add a
   second only when a single cause leaves symptoms unexplained; cap cardinality.
7. **Model partial degradation (tri-state), not up/down.** "DST is slow" must be
   attributable — Sherlock's up/troubled/down is what enables that; binary risk models
   miss brownouts (the common cloud symptom).

### Pitfalls

Correlation≠causation / confounders (prefer FCI-style handling or **domain-rule
gating** à la Groot over naive correlation); loudest-symptom bias; stale/noisy
topology (Shrink's lesson — be robust, don't assume a perfect graph); causal-discovery
scale collapse (pre-scope to the path); victim-vs-instigator confusion (needs
explaining-away).

### Recommendation

- This **extends the existing grounding/verdict model, it doesn't replace it.** The
  repo already has an evidence-accounting model, an observer registry, independence
  grouping, and a `suspected`/`confirmed` gate (`verdicts.py` `assess()`,
  `rca_accounting.go`, `rca_observer_registry.go`, `confirmability.py`). Implement
  on-path attribution as a **pre-filter + confidence modifier** on that pipeline:
  1. Build the typed path (Areas 1–2). Compute the **on-path device set**.
  2. **Restrict RCA candidates to on-path devices** (principle 1) — this is the single
     highest-value change; it turns "saas-degraded, suspected" into "LB 5xx on the
     client→app path" by *excluding* off-path coincidences.
  3. Treat an **on-path device fault as an independent corroborating witness** in the
     existing coverage model (raises toward `confirmed`); an off-path fault is not a
     witness for this symptom.
  4. Apply **minimal-set-cover + priors** when multiple on-path devices carry fault
     signals; apply **explaining-away** to walk to the upstream-most on-path cause.
  5. **Honesty caps (already in `verdicts.py`):** partial/unknown path ⇒ cap at
     `suspected` with `evidence_missing` naming the unknown segment; never `confirmed`
     when the fault localizes to an opaque cloud segment.
- **Do not deploy general causal-discovery (PC/FCI) at fabric scale** — use it, if at
  all, only on the small pre-scoped on-path subgraph. Prefer **domain-rule gating**
  (Groot-style: event-type→symptom rules, locality/DC match) which is auditable and
  matches the repo's existing rule-catalog approach (`catalog.py`, 103 signature
  templates).

---

## Area 4 — Partial-visibility abstraction ("the essence")

The design doc's core insight — RCA needs the **segment-type sequence + key devices**,
not exact hops — is well supported by how real tools survive cloud/MPLS opacity.

### Proven methods

- **Unresponsive-hop honesty.** ThousandEyes renders ICMP-silent interfaces as white
  nodes and, when it can't even count hidden hops, draws a **dotted `?` link** — it
  represents *"we don't know how many hops"* explicitly rather than fabricating a
  straight line ([Path Visualization](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization);
  [reasons for missing info](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization)).
- **MPLS visibility is tiered by what the operator leaks.** With **RFC 4950** ICMP
  MPLS label-stack extensions + TTL-propagate enabled, tunnels are **Explicit** (full
  hops + labels shown). Without them, ThousandEyes classifies tunnels as **Implicit**
  or **Opaque** and infers their presence via deep path analysis
  ([ThousandEyes MPLS tunnel inference](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/mpls-tunnel-inference-using-deep-path-analysis);
  [RFC 4950](https://datatracker.ietf.org/doc/html/rfc4950)). Lesson: **an opaque
  tunnel is a single typed segment with known ingress/egress, not a set of fake hops.**
- **AS-level / provider-level summarization.** When intra-domain hops are invisible,
  Kentik-style tooling collapses to the **ASN/provider** granularity — the path becomes
  `client → ISP-AS → provider-AS → app`, honest at the level actually observed.
- **Cloud is endpoints + inventory, not hops.** VPC flow logs give only the *two
  directly-communicating interfaces* ([AWS limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)),
  so the intra-cloud path is reconstructed from **inventory edges** (LB→target group→
  instances, SG↔subnet↔ENI) + **provider health**, then abstracted to one CLOUD
  segment with labeled role-devices (DNS·WAF·LB·FW·app).

### Honest limits (state these plainly)

- Inside a cloud provider's backbone and inside an opaque MPLS core, **you cannot see
  the hops, full stop.** No technique recovers them from a tenant vantage. The correct
  behavior is a **typed "unknown/opaque segment"** with a stated reason and a **capped
  verdict**, not a guessed device.
- Emerging prior art for this exact regime ("RCA with partially observed data",
  [arXiv 2407.05869](https://arxiv.org/html/2407.05869v1)) is thin — treat cloud
  partial-visibility attribution as *"fault is on the AWS-internal path between LB and
  RDS, not further resolvable"* rather than false precision.

### Recommendation

- The repo is **already built for this.** `path_graph.py` carries `unknown_hops`
  (missing/filtered hops *inside* a segment) on every relation, a `stale` flag, and an
  `UNKNOWN` boundary; `path_direction.py` **abstains** on unresolved hops. Wire the
  segment classifier so that:
  - a run of unresolvable hops between two typed anchors becomes **one typed segment
    with `unknown_hops` populated and a `reason`**, never a straight fabricated edge;
  - an opaque cloud/MPLS core is a **single `CLOUD`/`opaque` segment element** with
    known ingress/egress role-devices;
  - the **verdict cap already in `verdicts.py`** fires whenever the attributed fault
    sits in (or behind) an `unknown`/opaque segment — `suspected`, with
    `evidence_missing` naming the opaque segment.
- **Render the essence:** the Cloud Service View draws the **typed segment sequence**
  (design §5) with the broken link highlighted; opaque segments render greyed with
  their reason — honest, and exactly the "essence over exact hops" the owner asked for.

---

## Area 5 — Representation & scale (typed, time-windowed, per-tenant causal path graphs)

### Proven techniques

- **Directed typed property graph, edges carrying provenance + validity.** The repo's
  `path_graph.py` relations already model this: `edge_type`, `method`, `rank`,
  `evidence_class`, `confidence`, `observed_at`, `seam_id`, `transformation`,
  `stale`, `unknown_hops`, and a `valid_at(when)` temporal predicate. This is the right
  shape — a **time-windowed property graph** where each edge is valid over an interval
  and can go `stale` out of its freshness window.
- **Build edges from streaming telemetry via windowed matching.** The canonical
  pattern is OpenTelemetry's **service-graph connector**: it matches **client/server
  span pairs** in an **in-memory store with TTL + max_items**, emitting a directed edge
  (client→server) with request/error/latency per edge, and **virtual nodes** for
  uninstrumented peers (DB, external API) ([OTel service graph connector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/connector/servicegraphconnector/README.md)).
  Our analog: tumbling/sliding windows over flow/probe/inventory streams produce path
  edges; unmatched half-edges expire by TTL; "virtual nodes" = opaque cloud segments.
- **Storage: columnar for the firehose, materialized projection for hot reads.** The
  repo's ClickHouse read-path gotcha is directly reusable: **hot reads come from a
  `corr_current`-style projection, never the raw fold** (see
  `netops-ch-corr-read-path-gotcha`, `bounded_io_test`). Store path-edge observations
  append-only in ClickHouse (time-windowed, high volume), and serve the **current typed
  path** from a small materialized/projected "latest edges per (tenant, path)" view.
  Postgres (`migrations/0023_service_path_graph.sql`, `path_graph_store.go`) holds the
  durable path definitions/seams with **FORCE-RLS tenant isolation**.
- **Freshness / decay / dedup.** Edges expire out of their window (`stale`), dedup by
  `(tenant, src, dst, method, window)`; temporal-decay of corroboration is already a
  solved pattern in the codebase (STAMP corroboration temporal-decay fix).

### Algorithms

- **Path assembly from edges:** order by measured hop-order (precedence-1
  `path_direction.py`) where available, else topological order over
  observed>inferred edges; collapse consecutive same-type hops into typed segments
  (the "essence" reduction).
- **ECMP diamonds:** keep both branches as a diamond sub-structure; the direction
  oracle already returns `AMBIGUOUS` rather than picking one — carry that into the
  graph as parallel edges, don't flatten.
- **On-path walk / reachability:** bounded DAG walk from SRC to DST to compute the
  on-path device set for attribution (Area 3); cap depth; memoize per window.
- **Incremental update:** apply new edges to the current-window graph; recompute only
  affected paths (per-tenant, per-service scoping keeps this cheap).

### Scale & isolation posture

- **Per-tenant everything** (CLAUDE.md §3a, and the repo's hard-won
  RLS-blind-boot-import bug): path graphs, classification caches, and edge stores are
  tenant-scoped in the store itself — no unscoped "list all paths." The existing
  `path_graph_isolation_test.go` is the template; ship one with the new classifier and
  path-assembly code.
- **Bounded IO / budgets** on the hot path (reuse `bounded_io_test`, hot_ui/background
  CH profiles). Streaming refresh, not full recompute.

### What leading tools do

OTel/Grafana/Dynatrace keep a **service-graph in memory / span-metrics store** and
materialize a dependency map; blast-radius tooling (Causely) walks the dependency graph
for impact. None store the raw firehose for interactive reads — they **pre-aggregate to
edges**, which is exactly the ClickHouse-projection posture above.

### Recommendation

Reuse the existing shape end-to-end: **ClickHouse append-only path-edge observations
(time-windowed) → materialized "current typed path" projection → Postgres/RLS durable
path+seam definitions → Go API (`rca_path_view.go`, `path_graph_api.go`) → React
render.** Add only: the windowed edge-builder (OTel-service-graph pattern) feeding the
classifier, and the on-path-walk query. Keep provenance, `valid_at`, `unknown_hops`,
`stale`, and tenant-RLS on every edge — they already exist and are exactly right.

---

## Prioritized implementation blueprint

Ordered to match the design doc's build order (classifier → discovery → attribution →
render), each step naming the concrete repo touch-points.

**P0 — Segment/device classifier (Area 2, the missing keystone).**
- New `src/correlation/segment_classifier.py` (+ Go mirror for ingest enrichment).
  Input hop-IP(+device), output `{segment_type, device_role, confidence, signals[],
  reason}` using the existing type vocabulary (`BOUNDARY_OF_KIND`, `seams.go` kinds).
- Feed refresher cron: AWS `ip-ranges.json`, Azure Service Tags, GCP `cloud.json` →
  bundled snapshot + live weekly refresh → longest-prefix-match trie
  (provider/region/service). Curated cloud/transit **ASN table** + Team Cymru cache.
  RFC1918/RFC6598 constants. rDNS + TTL/latency as **hints only**.
- **Default-closed, multi-signal**: ≥2 independent signals for a confident type; no
  match ⇒ `unknown` + reason. Tests: one-per-pattern, `unknown`, "single weak signal
  never confident," **per-tenant isolation**.

**P1 — Path discovery / assembly wiring (Area 1 + 4).**
- Fuse the four sources with precedence (measured `path_direction.py` rank-1 > flow >
  cloud-inventory > BGP-inferred), each emitting evidence-bearing edges into
  `path_graph.py` relations. Ensure the traceroute collector is Paris-consistent.
- Run the P0 classifier over every hop/segment during assembly; collapse same-type
  hops into typed segments; populate `unknown_hops`/`reason` for opaque runs; keep ECMP
  as `AMBIGUOUS` diamonds. Capture DNS-resolved frontend as the path head.

**P2 — On-path RCA attribution (Area 3).**
- Compute the on-path device set (bounded DAG walk). **Restrict RCA candidates to
  on-path devices** — the single highest-value change. Feed an on-path device fault as
  a corroborating witness into the existing `verdicts.py`/`rca_accounting.go` coverage
  model; discount off-path/wrong-locality/no-rule anomalies (Groot-style gating).
- Apply minimal-set-cover + priors for multiple on-path faults; explaining-away to the
  upstream-most cause. **Honesty caps** already in `verdicts.py`: partial/opaque path ⇒
  `suspected` + `evidence_missing`.

**P3 — Render the path-first Cloud Service View (design §5).**
- Extend `rca_path_view.go` / `RcaPathView.tsx` / `NetworkPathView.tsx`: typed segments
  (distinct treatment per CLOUD/LAN/WAN/DC/WAN-seam), role-labeled key devices,
  per-segment health, **broken-link highlight**, opaque segments greyed with reason,
  device-in-path drill → family-tagged Cloud Logs. RCA reads as path causality:
  "client→app broke at CLOUD/WAF (block rule X)."

**Cross-cutting:** per-tenant RLS + isolation test with *every* new store/classifier
(§3a); bounded-IO budgets on hot reads (ClickHouse projection, not raw fold); bundled
offline feed snapshot for clean-build parity.

---

## Honest assessment — where this is hard or thin

- **Cloud opacity is real and unfixable from a tenant vantage.** Intra-cloud and
  provider-backbone hops are invisible; VPC flow logs show only directly-communicating
  interfaces. We attribute precisely on segments we can see (our edge, VPC topology,
  discovered app dependencies) and abstract opaque cloud/MPLS cores to a **single typed
  segment** — never a fabricated device. This is a feature (the "essence"), enforced by
  a capped verdict.
- **Prior art assumes more visibility than we have.** Sherlock/Shrink/SCORE assume a
  known topology/SRLG map; NetMedic assumes deep host instrumentation; Orion/eXpose
  assume observable traffic. All degrade across a cloud boundary. Their **math**
  (on-path candidate restriction, minimal-set-cover, explaining-away, tri-state) is
  sound and adoptable; their **completeness assumptions** are not — hence default-closed
  + verdict caps.
- **Causal discovery (PC/FCI) does not scale and invites confounder-driven false
  alarms** — use domain-rule gating on the pre-scoped on-path subgraph instead.
- **rDNS / TTL / hostname signals are weak and spoofable** — corroboration only, never
  a sole classifier (consistent with the existing `service_infer` discipline).

---

## Curated sources

**Path discovery / traceroute**
- [Augustin et al., *Avoiding traceroute anomalies with Paris traceroute*, IMC 2006](https://conferences.sigcomm.org/imc/2006/papers/p15-augustin.pdf) — why classic traceroute breaks on ECMP; flow-id pinning.
- [paris-traceroute.net — About](https://paris-traceroute.net/about/) — Paris technique / constant flow-id.
- [dublin-traceroute.net](https://dublin-traceroute.net/) — Paris + NAT detection + multipath enumeration.
- [Kentik — The Power of Paris Traceroute](https://www.kentik.com/blog/the-power-of-paris-traceroute-for-modern-load-balanced-networks/) — vendor treatment of ECMP path tracing.
- [ThousandEyes — How Path Trace Works](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace) — TTL mechanics.
- [ThousandEyes — Path Visualization](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization) — unresponsive/white nodes, dotted `?` links.
- [Datadog — Network Path](https://docs.datadoghq.com/network_monitoring/network_path/) & [Cloud Network Monitoring setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/) — agent traceroute + dynamic path discovery + cloud-entity decoration.
- [eBPF Foundation — Datadog eBPF network observability case study](https://ebpf.foundation/case-study-datadog-uses-ebpf-to-improve-network-observability-accuracy-and-performance/) — eBPF conntrack/socket edges.
- [AWS — VPC Flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html) & [Flow log limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html) — 5-tuple fields, `pkt-*` original endpoints, direct-interface-only limitation, sampling.

**Segment classification**
- [AWS — AWS IP ranges (blog)](https://aws.amazon.com/blogs/aws/aws-ip-ranges-json/) & [JSON syntax](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html) — `ip-ranges.json` structure, service/region, refresh cadence.
- [Microsoft — Azure IP Ranges and Service Tags (Download 56519)](https://www.microsoft.com/en-us/download/details.aspx?id=56519) & [Service tags overview](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview) — service-tag JSON structure, weekly cadence, discovery API.
- [GCP IP Ranges — cloud.json / goog.json guide](https://sanj.dev/2020/10/gcp-ip-ranges/) & [Google App Engine outbound IPs](https://docs.cloud.google.com/appengine/docs/standard/outbound-ip-addresses) — cloud.json vs goog.json, `_cloud-netblocks` TXT is incomplete.
- [Team Cymru — IP to ASN Mapping](https://www.team-cymru.com/ip-asn-mapping) — DNS/WHOIS/bulk IP→ASN + peer-ASN.
- [RFC 6598 — Shared Address Space (100.64.0.0/10)](https://datatracker.ietf.org/doc/html/rfc6598) — CGNAT range, distinct from RFC1918.
- [rDNS geolocation, arXiv 1811.04288](https://arxiv.org/pdf/1811.04288) — PTR naming heuristics + confidence scoring.
- [SNMPv3 router fingerprinting, arXiv 2109.15095](https://arxiv.org/pdf/2109.15095) — sysObjectID/device fingerprinting context.
- [AWS EC2 reverse DNS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Elastic_Addressing_Reverse_DNS.html) — region-encoded EC2 PTR pattern.

**Fault localization / dependency RCA**
- [Sherlock — MSR](https://www.microsoft.com/en-us/research/publication/towards-highly-reliable-enterprise-network-services-via-inference-of-multi-level-dependencies/) & [patent US8015139](https://patents.google.com/patent/US8015139) — inference graph, tri-state, meta-nodes, Ferret.
- [NetMedic — PDF](https://www.sysnet.ucsd.edu/sysnet/miscpapers/netmedic-sigcomm09.pdf) — joint-history impact weighting, explaining-away.
- [Shrink — MIT CSAIL PDF](https://groups.csail.mit.edu/netmit/wordpress/wp-content/themes/netmit/papers/shrink.pdf) — SRLG bipartite model, Bayesian MLE, noise robustness.
- [SCORE — IP Fault Localization via Risk Modeling, NSDI'05](https://dl.acm.org/doi/10.5555/1251203.1251208) — minimal-set-cover origin.
- [Orion — MSR](https://www.microsoft.com/en-us/research/publication/automating-network-application-dependency-discovery-experiences-limitations-and-new-solutions/) — delay-spike dependency discovery.
- [eXpose — MIT CSAIL PDF](https://groups.csail.mit.edu/netmit/wordpress/wp-content/themes/netmit/papers/eXpose.pdf) — JMeasure significance gate for edges.
- [Groot — arXiv 2108.00344](https://arxiv.org/pdf/2108.00344) — event-causality graph, rule-gated edges + locality check, PageRank; severity≠causality.
- [RCA for Microservices via Causal Inference: How Far Are We? — arXiv 2408.13729](https://arxiv.org/html/2408.13729v1) — PC/FCI confounders + scale limits.
- [RCA with Partially Observed Data — arXiv 2407.05869](https://arxiv.org/html/2407.05869v1) — closest prior art to cloud partial-visibility.

**Partial visibility / MPLS**
- [ThousandEyes — MPLS Tunnel Inference](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/mpls-tunnel-inference-using-deep-path-analysis) — Explicit/Implicit/Opaque tunnels.
- [RFC 4950 — ICMP Extensions for MPLS](https://datatracker.ietf.org/doc/html/rfc4950) — label-stack in Time Exceeded.

**Representation & scale**
- [OpenTelemetry — Service Graph Connector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/connector/servicegraphconnector/README.md) — client/server span pairing, in-memory TTL store, virtual nodes, per-edge metrics.
- [Causely — how it works](https://docs.causely.ai/getting-started/how-causely-works/) — dependency-graph blast-radius (parity reference).

**Repo touch-points (existing, to reuse):** `src/correlation/path_graph.py`,
`path_direction.py`, `verdicts.py`, `confirmability.py`, `catalog.py`;
`src/backend/seam_bootstrap.go`, `cloud_enrich.go`, `rca_path_view.go`,
`path_graph_api.go`, `path_graph_store.go`, `rca_accounting.go`,
`rca_observer_registry.go`, `migrations/0023_service_path_graph.sql`;
`src/frontend/.../topology/components/NetworkPathView.tsx`,
`components/rca/RcaPathView.tsx`.
