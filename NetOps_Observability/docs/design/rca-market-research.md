# RCA & Correlation Market Research — How Incumbents Do It, What the Science Says, Where the White Space Is

> Provenance: deep-research workflow `wf_304c05b7-603`; synthesis step failed and was recovered manually 2026-06-11 from the verified corpus (22 sources, 5 search angles, 3-voter adversarial verification).

**Research question:** how modern full-stack network+application observability / AIOps
correlation platforms are architected — correlation & RCA techniques and their
real-world effectiveness, active measurement, passive-source unification, L1–L7 fault
isolation, UX patterns, and exploitable gaps.

**Evidence legend** (used on every factual claim):
- **✅ (n-m)** — adversarially confirmed: survived 3-voter verification with the vote shown.
- **◻** — extracted from the source but not adversarially verified (includes 0-0 entries the verifier never reached; treat as plausible, sourced, unverified).
- **✗ (n-m)** — genuinely refuted in verification (real losing vote).
- **➤** — our inference / design-team judgment, clearly not a corpus fact.

---

## 1. TL;DR

1. **The serious vendors already reject time-window statistics.** Dynatrace's documented position: "time correlation alone is not sufficient" for RCA ✅(3-0); Davis runs on a pre-built topology model (Smartscape), not statistical dependency inference at analysis time ✅(3-0). Our grounded-edges constraint is the same bet — made stricter.
2. **Generic causal discovery fails at scale.** PC/FCI/Granger/LiNGAM/GES/fGES/PCMCI/NTLR reconstruct causal graphs at F1 0.1–0.54, degrading sharply from 10→50 nodes ✅(3-0); full causal-discovery RCA pipelines performed **no better than random** root-cause selection on real microservice fault data ✅(3-0). "Learn the causal graph from data" is a dead end; the graph must be *given* (topology + domain knowledge).
3. **Cheap statistics win the benchmark but are timing-fragile.** NSigma (z-score) was among the *top* RCA performers at ~0.01s — but collapsed from 0.98 to 0.15 Avg@5 with a 60-second failure-time misspecification ✅(3-0). Keep z-score as the detection layer; never let it be the RCA layer; persistent episodes (not instant windows) are the antidote to timing fragility.
4. **Domain-knowledge-constrained inference beats generic stats in production.** NetBouncer's accuracy comes from a provably link-identifiable probing plan plus a model whose regularization *encodes troubleshooting domain knowledge* ✅(3-0) — the strongest academic validation of the failure-signature-catalog approach.
5. **Gray failures are invisible to device telemetry.** They exhibit "differential observability" — perceived differently by end-hosts vs switches; SNMP/NetFlow polling cannot see them ✅(3-0); active probing from vantage points localizes them without any switch cooperation ✅(3-0). Validates STAMP + vantage-point/cloud-collector agents as non-optional.
6. **Topology-grounded model-based inference is fast enough.** Flock made Bayesian PGM fault localization >10,000× faster than prior PGM work, datacenter-scale ✅(3-0). Causal-model RCA is not inherently too slow — *unconstrained discovery* is what's slow (minutes to >2h timeout ✅(3-0)).
7. **Richer causal graphs are not free.** Completeness-vs-complexity: more complete causality graphs *reduce both efficiency and accuracy* ✅(2-1). This genuinely challenges naive "model everything" entity graphs — our seam-scoped, admission-gated edge set is the mitigation, and graph size discipline must be a tracked metric.
8. **Selector is the closest architectural competitor**: data-hypervisor normalization layer + live knowledge graph doing cause-and-effect reasoning + cross-domain network/cloud/app correlation with purpose-built network ML — all ✅(3-0). What it is not (per corpus): self-hosted, practitioner-auditable rules, or seam/ownership-aware.
9. **Nobody can prove their RCA works.** No standardized benchmark for AI/LLM RCA exists; buyers can't distinguish products from hype ◻ (monitoring2.substack.com). Replayable, deterministic correlation objects + per-signature replay fixtures = a *verifiability* differentiator no incumbent claims.
10. **The on-prem↔cloud↔underlay seam is unowned.** Each cluster covers a fragment — ThousandEyes the internet path ✅(3-0), Dynatrace the app-to-cloud-entity stack ◻, Kentik unified flow records ◻ — but no corpus vendor models ownership-transition seams as first-class causal objects or assigns "carrier ticket vs our edge" direction. That is #67/#68 white space.

---

## 2. How incumbents architect correlation/RCA

### 2.1 Dynatrace — Davis AI + Smartscape (topology-causal, agent-fed)

- Explicitly rejects pure temporal/statistical correlation: "To identify the root cause of problems, time correlation alone is not sufficient." ✅(3-0) [docs.dynatrace.com/...davis-ai/root-cause-analysis/concepts](https://docs.dynatrace.com/docs/discover-dynatrace/platform/davis-ai/root-cause-analysis/concepts)
- Causal RCA is grounded in a **pre-built dependency/topology model** (Smartscape) populated from OneAgent instrumentation and cloud integrations — not inferred statistically at analysis time ✅(3-0) [same source].
- Correlates anomaly events along **two topology axes** — horizontal (service→service calls) and vertical (application→infrastructure stack) — combined with temporal proximity ✅(3-0) [same source].
- Alert dedup is a designed RCA *output*: all anomalies sharing a root cause merge into one "problem" entity ◻; causal analysis runs in a bounded window (problem sits in "Processing" up to ~3 min) — an explicit speed-vs-completeness trade-off ◻ [same source].
- Data model: every telemetry observation (metric/trace/log/event) stores a reference to its monitored entity — **the entity model is the join key for all telemetry**, not an overlay ◻; built-in topology covers 100+ *well-known IT/software* entity types only; custom entities arrive via shared dimensional tags ◻ [docs.dynatrace.com/...extend-topology](https://docs.dynatrace.com/docs/ingest-from/extend-dynatrace/extend-topology).
- 2026 Smartscape: real-time dependency graph queryable via DQL multi-hop traversal in Grail ◻; now ingests **cloud network entities** (security groups, VPCs, load balancers, subnets) as native graph entities, agentlessly ◻; claims millions of entities/relationships in real time ◻ [dynatrace.com/news/blog/new-smartscape-...](https://www.dynatrace.com/news/blog/new-smartscape-make-better-decisions-with-real-time-dependency-graph-of-digital-systems/). ➤ This is the incumbent move most directly eroding our cloud-side white space — see §5.1.

### 2.2 ThousandEyes — active path + BGP fusion (vantage-point SaaS)

- Hop-by-hop path discovery rendered as one topologically correlated multipoint view of all agent→target paths; this is its core mechanism for localizing application-experience issues to underlay/transit segments ✅(3-0) [thousandeyes.com/product/platform](https://www.thousandeyes.com/product/platform).
- BGP data from dozens of global route collectors is **overlaid on path/test data** — control-plane fused with active measurement in one view ✅(3-0); Internet Insights does AI-based aggregation across the fleet to detect/attribute global provider outages ✅(3-0) [same source].
- Path-trace mechanics: classic TTL-expiry; **3 traces per round by default to uncover ECMP alternates**; unique random source port per trace so load balancers hash traces onto different paths; their docs point to Paris traceroute as the reference methodology ◻ [docs.thousandeyes.com/...path-trace](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace).
- Operational fault-isolation method = overlaying control-plane route-change timelines with data-plane loss and L7 HTTP availability on one timeline (Microsoft AS8075 flap; Telstra/Quad9 hijack detected via per-prefix origin-AS monitors; first-hop-ASN allowlist alerts; DDoS-mitigation verification via BGP path) ◻ [thousandeyes.com/blog/4-real-bgp-troubleshooting-scenarios](https://www.thousandeyes.com/blog/4-real-bgp-troubleshooting-scenarios).
- Claims "AI-driven RCA that pinpoints root cause and recommends next actions" with **zero algorithmic detail** — the public architecture story is marketing-level ◻ [platform page]. Passive flows (Traffic Insights) come only via on-prem Enterprise Agents and embedded Cisco-device integrations ◻.

### 2.3 Datadog — Watchdog RCA (learned topology, narrow cause vocabulary)

- Builds a **learned** topology/dependency map of apps + infra and uses it (not pure statistical correlation) to identify probable root cause ◻; separates "root cause" from "critical failure" (first sign of failure in the causal chain) — an internal causal-chain event model ◻ [datadoghq.com/blog/datadog-watchdog-automated-root-cause-analysis](https://www.datadoghq.com/blog/datadog-watchdog-automated-root-cause-analysis/).
- The 2021/2022 root-cause vocabulary is a **small closed set**: faulty deployments, client traffic increases, AWS instance failures, disk exhaustion (CPU/memory listed as future) — not a general cross-domain network RCA engine ◻ [same source].
- Documented failure mode: if required telemetry (traces/logs/profiles/infra metrics) is missing, no causal relationship can be established and **no root cause is produced** ◻; pairs RCA with a separate Impact Analysis layer (which services/users are affected) ◻ [same source].

### 2.4 Kentik — unified flow repository (UDR + KDE), enrichment-at-ingest

- Universal Data Records: core platform modified to ingest **arbitrary data elements in arbitrary formats** (application ID, user ID, NAT translations, vendor fields) beyond fixed NetFlow/sFlow/IPFIX schemas ◻; introduced specifically so cloud sources (AWS/GCP VPC Flow Logs, Kubernetes/Istio) live in the **same record model** as on-prem flow ◻; firewall telemetry (ASA, Palo Alto) as flow-like records; roadmap converged SNMP/streaming-telemetry/MPLS/SD-WAN/syslog onto the one record model ◻ [kentik.com/blog/going-beyond-the-netflow-...](https://www.kentik.com/blog/going-beyond-the-netflow-introducing-universal-data-records/).
- Kentik Data Engine is a **purpose-built columnar datastore** (not off-the-shelf) ◻; flow records are enriched at ingest (GeoIP, BGP) and stored **denormalized** rather than joined at query time ◻; heterogeneous telemetry is normalized pre-storage, which is what enables cross-source analytics/ML ◻; exposed to customers via ANSI-SQL/PostgreSQL protocol ◻ [kentik.com/blog/modernizing-data-analytics-...](https://www.kentik.com/blog/modernizing-data-analytics-with-a-unified-data-repository/).
- Stated rationale: ML correlation quality depends directly on data unification — cross-source detection requires consolidating telemetry that otherwise lives in per-tool silos ◻; some processing must happen at distributed ingestion points before the central store ◻; full visibility requires unifying logs+metrics+traces+flows ◻ [kentik.com/blog/understanding-data-platform-needs-...](https://www.kentik.com/blog/understanding-data-platform-needs-to-support-network-observability/). ➤ Corpus contains **no Kentik causal/RCA-engine claims** — it is a unification-and-analytics story, not a causality story.

### 2.5 Selector — data hypervisor + knowledge graph (closest competitor)

- Four-service architecture: Collection, **Data Hypervisor** (normalizes heterogeneous telemetry into one consistent model *before* correlation), Knowledge, Collaboration ✅(3-0) [selector.ai/platform](https://www.selector.ai/platform/).
- Knowledge Service builds a **live knowledge graph used for cause-and-effect reasoning**, combining baselines, rules, and ML ✅(3-0); claims cross-domain correlation spanning network, cloud, and application layers using purpose-built models trained on real network telemetry ✅(3-0) [same source].
- Agentless collection, 300+ sources incl. Splunk/NetBox/ThousandEyes, edge-side caching/enrichment ◻; RCA output expresses explicit **directional causality between events** (link-flap → LACP interface-down) ◻ [same source].

### 2.6 Others in corpus

- **IODA (CAIDA/Georgia Tech)** — internet outage detection by fusing three independent signals (BGP from ~500 RouteViews/RIPE RIS monitors, darknet background radiation at a /8 telescope, active probing of routable IPv4 from Ark vantage points at /24 granularity), alerting **only when combined signals corroborate** ◻ [caida.org/projects/ioda](https://www.caida.org/projects/ioda/). Macroscopic (AS/country) scope, but the multi-signal-corroboration pattern transfers directly.
- **LLM-agent wave (2024)** — first-wave AIOps anomaly detection was a mixed failure: false-positive night pages led orgs to disable ML features ◻; a startup category (Parity, Cleric, k8sgpt, …) now joins heterogeneous sources **through an LLM instead of a normalized entity/topology model** ◻; no standardized RCA benchmark exists, so buyers can't separate products from hype ◻ (Parity's SREBench is a first attempt ◻) [monitoring2.substack.com/p/ai-agents-invade-observability](https://monitoring2.substack.com/p/ai-agents-invade-observability). ➤ LLM-as-correlation-layer is the exact "AI mush" the #67 admission gate exists to prevent.

---

## 3. What the research says about RCA algorithms

### 3.1 Causal discovery at scale: measured failure

The ASE 2024 evaluation [arxiv.org/html/2408.13729v1](https://arxiv.org/html/2408.13729v1) is the strongest negative result in the corpus, fully adversarially confirmed:

- Standard causal discovery (PC, FCI, Granger, LiNGAM, GES, fGES, PCMCI, NTLR) reconstructs causal graphs at **F1 0.1–0.54**, degrading sharply as graphs grow 10→50 nodes ✅(3-0).
- Causal-discovery RCA pipelines (those algorithms + PageRank/random-walk localization) performed **no better than random** root-cause selection on real microservice fault datasets ✅(3-0).
- Overall conclusion: existing causal-inference RCA is **not yet effective for large-scale systems**, and methods needing a precisely specified failure time are impractical in real deployments ✅(3-0).
- Synthetic-benchmark performance does not transfer to real systems (RCD scores well on its own synthetic data, poorly on CIRCA's) ◻.

### 3.2 The statistical baseline paradox and timing fragility

- NSigma (z-score scoring) and BARO were **among the top-performing RCA methods**, at ~0.01 s, while causal-discovery methods took minutes to a >2-hour timeout on a 212-metric system — *but* NSigma collapsed 0.98 → 0.15 Avg@5 under a 60-second failure-time misspecification ✅(3-0) [arxiv.org/html/2408.13729v1]. ➤ Read both halves: cheap stats are a strong *detector* and a brittle *localizer*; the fragile input is the onset timestamp — exactly what persistent episode objects with explicit onset tracking de-risk.

### 3.3 Completeness vs complexity

- More complete causality graphs **reduce both efficiency and accuracy** ✅(2-1, one dissenting voter) [arxiv.org/html/2408.00803v1]. Two related claims from the same survey were **refuted** in verification and must not be leaned on: "single-modality RCA is structurally insufficient" ✗(1-2) and "PC-style call-graph construction suffers ambiguous upstream/downstream correspondences causing misjudgments" ✗(0-3).
- Supporting (unverified): ~three-quarters of production failures are **recurring** ◻ (justifies fingerprinting/known-issue matching as a first-class RCA layer); RCA effectiveness is bounded by observability coverage — undetectable anomalies cannot be localized by any algorithm ◻ [arxiv.org/html/2408.00803v1].

### 3.4 Gray failures, differential observability, active probing (NetBouncer, Flock)

- **NetBouncer** (NSDI'19, Azure production): localizes device and link failures by end-host active probing with IP-in-IP bounced packets, no switch CPU involvement — proof that active probing alone can localize gray failures that switch-queried monitoring misses ✅(3-0); gray failures show **differential observability** (end-hosts vs switches perceive them differently; SNMP/NetFlow can't see them) ✅(3-0); accuracy comes from a **provably link-identifiable probing plan + domain-knowledge-encoding regularization** — domain-constrained inference beats generic statistical correlation ✅(3-0) [usenix.org/system/files/nsdi19spring_tan_prepub.pdf](https://www.usenix.org/system/files/nsdi19spring_tan_prepub.pdf).
- NetBouncer production stats (unverified): three years across Azure, zero false positives, detection within ~60 s per 5-min epoch, one instance handling tens of thousands of switches ◻. Documented blind spot: probes assume probe packets share app-traffic fate — broken by NIC-specific DHCP drops and a narrow ACL misconfig ◻. ➤ This is a standing caveat on any STAMP-only story.
- **Flock** (PACMNET'23): Bayesian PGM maximum-likelihood fault localization made **>10,000× faster** than prior PGM (Sherlock), datacenter scale, on end-to-end measurements ✅(3-0). Unverified: 1.19–11× more accurate than 007/NetBouncer, 1.2–55× with passive telemetry ◻; adding passive NetFlow/IPFIX cut localization error up to 5.3× **but requires modeling ECMP path uncertainty** (only a path *set* is known per flow) ◻; 88K links / 9.5M flows / 3.5M hypotheses scanned in 17 s ◻; silent inter-switch drops were 50% of faults taking >3 h to diagnose in a prior production study ◻ [pbg.cs.illinois.edu/papers/harsh23flock.pdf](https://pbg.cs.illinois.edu/papers/harsh23flock.pdf).

### 3.5 Topology-aggregated alarm RCA (Hawkes/HPCI+CPBE) — all unverified

From the Huawei telecom-alarm paper [ar5iv.labs.arxiv.org/html/2105.03092](https://ar5iv.labs.arxiv.org/html/2105.03092), all claims 0-0 (verifier never reached them; treat as plausible, unverified): Hawkes-process + conditional-independence pipeline with influence maximization hit 61.8% top-1 / 96.1% top-5 on 672,639 real alarms ◻; beat Pearson correlation 0.618 vs 0.407 top-1 ◻; **aggregates alarms within connected topology sub-graphs before causal inference** ◻; Hawkes alone produces spurious edges, needing CI-test pruning ◻; results are sensitive to correlation-window sizing ◻.

### 3.6 Partial observability (PORCA) and AIOps-in-practice

- Most causal-RCA methods assume causal sufficiency; unmonitored entities act as unobserved confounders creating spurious edges and false alarms ◻; confounder-aware variants (FCI-based) measurably beat causal-sufficiency methods (~6% PR@5) ◻ [arxiv.org/pdf/2407.05869](https://arxiv.org/pdf/2407.05869).
- AIOps survey: topology-aware correlation reduces redundant alert patterns and exposes hidden dependencies ◻; **even at major cloud providers, telemetry quality/quantity is insufficient for ML-based AIOps**, compounded by scarce labels ◻; published anomaly-detection F1s can be inflated by train/test contamination ◻; 20–40% of incident reports are duplicates ◻ [arxiv.org/html/2404.01363v1](https://arxiv.org/html/2404.01363v1).

### 3.7 Active measurement standards (context for our existing layer)

- **STAMP / RFC 8762**: one-way + round-trip delay/jitter/loss; Session-Sender/Reflector over UDP; control plane out of scope; a **stateful reflector can attribute loss to forward vs reverse path** via sequence-gap comparison; authenticated mode = HMAC-SHA-256 truncated to 128 bits; NTPv4 timestamps MUST, PTP MAY ◻ [datatracker.ietf.org/doc/rfc8762](https://datatracker.ietf.org/doc/rfc8762/).
- **Paris traceroute / MDA**: a billion+ multipath traces since 2006-07 — the de facto standard for load-balancer-aware path discovery ◻; MDA-Lite cuts probing cost with bounded miss probability ◻; load-balancing fan-out grew beyond all prior surveys by 2018, so single-path traceroute increasingly misrepresents real forwarding ◻ [dl.acm.org/doi/10.1145/3278532.3278536](https://dl.acm.org/doi/10.1145/3278532.3278536).

### 3.8 Synthesis of the academic picture ➤

The evidence triangulates one conclusion: **the causal graph must come from explicit
structure (topology, probing plans, domain rules), not from data mining.** Generic
discovery fails (§3.1, ✅); cheap stats localize poorly under realistic timing error
(§3.2, ✅); the systems that work in production (NetBouncer ✅, Flock ✅, HPCI ◻,
Davis ✅, Selector ✅) all start from a *given* structural model and constrain
inference with domain knowledge. That is, verbatim, the #67 design bet.

---

## 4. Validation map: research → Correlix design decisions

| Finding (evidence) | Correlix design element | Verdict |
|---|---|---|
| Time correlation alone insufficient — Dynatrace's own doctrine ✅(3-0); causal-discovery pipelines ≈ random ✅(3-0) | **Grounded-edges hard constraint** (correlation-engine.md §4.2: no edge without seam/topology grounding; ungrounded co-occurrence counted, surfaced, never admitted) | **Validates** — and goes one step beyond Davis, which trusts its own auto-discovered topology silently |
| Domain-knowledge-constrained inference beats generic stats (NetBouncer ✅(3-0)); purpose-built network models over generic AIOps (Selector ✅(3-0)) | **Failure-signature catalog as declarative rule base** (corr_hypothesis_templates, practitioner-authored symptom→evidence-chain→discriminators→verdict) | **Validates** — strongest single validation in the corpus; our catalog is the regularizer, as data not code |
| Davis correlates along horizontal + vertical topology axes ✅(3-0); HPCI aggregates alarms within connected sub-graphs pre-inference ◻ | **Seam-relative correlation** (#67 §4.4: five canonical ownership-transition seams as candidate boundary nodes; visibility caps direction confidence) | **Validates + differentiates** — no corpus vendor models *ownership transitions*; seams add the "who owns the fix" dimension topology axes lack |
| Gray failures invisible to SNMP/NetFlow, differential observability ✅(3-0); active probing localizes without switch cooperation ✅(3-0); IODA multi-signal corroboration ◻ | **Vantage-point probe agents / cloud collector T2** (#68: in-cloud STAMP/ICMP/HTTP bracketing the middle mile from the far end) | **Validates** — differential probing across a seam is exactly the differential-observability exploit, productized |
| Probe blind spot: probe packets ≠ app-traffic fate (NIC DHCP drops, narrow ACLs) ◻ | Same probing layer | **Challenges** — probes alone miss traffic-class-specific faults. Mitigation already designed: passive flow evidence joins probes in every signature's evidence chain; keep it mandatory for data-plane verdicts |
| Passive flows cut localization error up to 5.3× but **require ECMP path-uncertainty modeling** ◻ (Flock) | **Materialized CH attribution** (flow→path/service attribution with selector_version) | **Challenges (refines)** — attribution must store a path *set* / uncertainty weight per flow, not a single resolved path; do not pretend ECMP determinism we don't have |
| NSigma top-tier but collapses on 60 s timing error ✅(3-0); precise-failure-time requirement impractical ✅(3-0) | Persistent correlation objects with episode lifetimes + onset tracking; z-score stays as detector | **Validates** — episodes make onset a first-class estimated quantity instead of an assumed input |
| Completeness-vs-complexity: richer causal graphs reduce accuracy & efficiency ✅(2-1) | Entity graph (event↔flow↔path↔service) | **Challenges — honest flag.** Bigger graph ≠ better RCA. Mitigations: admission gate caps edge growth, seam-scoped subgraphs bound inference, top-K hypotheses bound search. Add a tracked metric for graph size/density per object; prune aggressively |
| RCA bounded by observability coverage ◻; Watchdog produces nothing when telemetry is missing ◻; unobserved confounders create spurious edges ◻ (PORCA) | **Explainable health score + coverage labels** (#68 honest coverage tiers: "unrun ≠ covered"; blind seams capped) | **Validates** — declared blindness (visibility full/partial/blind, stale-topology declared) is our answer to the confounder problem: we can't observe everything, so we *say so* in the verdict |
| ~75% of production failures recurring ◻; 20–40% incident duplicates ◻ | Signature catalog + meta-alert dedup loop (P3) | **Validates** — recurring-failure matching is the high-yield path; novel-anomaly causal inference is the fallback, not the core |
| No RCA benchmark exists; buyers can't verify claims ◻ | Deterministic replay (same inputs + engine version ⇒ same object) + per-signature lab replay fixtures | **Validates** — turns an industry credibility gap into a demo: we can *prove* our RCA on recorded incidents; no corpus vendor claims replayability |
| Dynatrace 2026 Smartscape ingests VPCs/SGs/LBs as native graph entities, agentless ◻ | #68 cloud ingestion 3-tier model | **Challenges** — the cloud-entity-graph gap is closing. Our remaining edge is below their floor: underlay path measurement, middle-mile bracketing, flow protocols, carrier seams. Ship #68 T1/T2 before this narrows further |

---

## 5. Gap analysis: white space → why incumbents can't close it → our execution path

### 5.1 The on-prem ↔ cloud ↔ underlay seam (incl. colo/POP middle mile)

**The gap.** Every corpus vendor covers a fragment: ThousandEyes sees the internet
path from its agents ✅(3-0) but its passive flows require on-prem Enterprise Agents
or embedded Cisco devices ◻; Dynatrace sees app→cloud-entity topology ✅(3-0)/◻ but
nothing in the corpus shows underlay path measurement, flow-protocol ingestion, or
carrier-segment modeling; Kentik unifies flow records across cloud and on-prem ◻ but
the corpus contains no causal engine on top; Watchdog's cause vocabulary is
app/infra-only (deploys, AWS instances, disk) ◻. **No corpus source models the
ownership transition itself** — the colo cross-connect, the DX/ER hand-off, the
carrier middle mile — as a causal object with an owner and a visibility class.

**Why they can't.** ➤ grounded in corpus: ThousandEyes' business is a global SaaS
agent fleet — its unit of value is the vantage point it owns, not the customer's
seam inventory; its RCA story is marketing-level ◻. Dynatrace's RCA quality is
explicitly bounded by what OneAgent + cloud integrations feed Smartscape ✅(3-0) —
the carrier middle mile has no agent to install and no cloud API to call, so it is
structurally outside their topology model. Kentik's architecture is
enrich-at-ingest-then-analyze ◻ — without a causal engine there is nothing to
*assign* a seam verdict.

**Our path.** #68's tiered cloud ingestion (T0 NVA syslog → T1 read-only API role
for TGW/DX/ER BGP state, VPN, NAT, LB seam metrics → T2 cloud collector with
in-cloud STAMP/ICMP/HTTP probes bracketing the middle mile from the far end), the
canonical five-seam inventory, and #67's seam-relative correlation where a seam's
`control_plane_owner` makes "open carrier ticket" vs "our edge" an assignable
verdict. STAMP's stateful-reflector forward/reverse loss attribution ◻ (RFC 8762)
gives directionality across a seam from one probe pair.

### 5.2 Causal, topology-grounded RCA vs time-window statistics

**The gap.** The market splits into (a) statistical/ML correlation that practitioners
turned off for false-positive pages ◻, (b) topology-causal engines that are closed
and unauditable (Davis ✅, Selector ✅ — both claim it, neither exposes the rule
base), and (c) LLM-joins-everything agents with no entity model at all ◻. The
academic record says generic discovery fails ✅(3-0)×2 and domain-constrained
structure wins ✅(3-0).

**Why they can't.** ➤ SaaS incumbents must make one auto-discovered model work
across thousands of heterogeneous tenants, which forces generic inference and
forbids admitting uncertainty (their products *must* produce an answer). Davis's
3-minute bounded processing window ◻ and Watchdog's closed cause vocabulary ◻ are
both symptoms: breadth forces shallow, fixed cause sets. Nobody can ship a
practitioner-auditable rule base because their models are the product.

**Our path.** #67: grounded-edge admission gate (the anti-AI-mush firewall),
hypothesis templates as *data* (the architect-authored signature catalog —
symptom → per-layer evidence chain → discriminators vs look-alikes → L1–L7 verdict +
first-3-steps + owner), competing hypotheses maintained and re-scored rather than
collapsed, and calibrated `confidence_rank` honesty (never "probability"). The
completeness-paradox finding ✅(2-1) is our standing discipline: track and bound
graph size; seam-scoped subgraphs, not global graphs.

### 5.3 Prescriptive L1–L7 fault direction

**The gap.** Watchdog names four cause types ◻; ThousandEyes "recommends next
actions" with no disclosed mechanism ◻; the LLM-agent crop is unbenchmarkable ◻.
Nobody in the corpus outputs a per-layer verdict with discriminators against
look-alike failures and a named owner.

**Why they can't.** ➤ A prescriptive verdict requires encoded operational expertise
that generalizes poorly across tenant environments — a SaaS vendor's catalog would
be wrong somewhere for everyone, and admitting per-environment rules undercuts the
"AI does it" positioning. The absence of any RCA benchmark ◻ means incumbents have
no pressure to be verifiably right, so they optimize for plausible, not falsifiable.

**Our path.** The signature catalog *is* the product moat (P3 in #67's build order:
catalog loaded as templates, per-signature lab replay fixtures). Replayability turns
each signature into a falsifiable test — exploiting the no-benchmark gap from the
credibility side. The ~75%-recurring-failures finding ◻ says this covers the bulk of
real incidents, with the grounded causal engine handling the novel remainder.

### 5.4 Self-hosted multi-tenant

**The gap.** Every commercial vendor in the corpus is SaaS. Kentik built a custom
columnar store (KDE) ◻ and Dynatrace runs Grail ◻ — proprietary data planes that are
their hosting business.

**Why they can't.** ➤ Their unified datastores are custom, operationally heavy, and
monetized as hosted services; shipping them on-prem would mean supporting their
hardest internal infrastructure inside customer environments and cannibalizing
consumption pricing. (Inference from the KDE/Grail architecture claims ◻ — the
corpus contains no vendor statement about refusing self-hosting.)

**Our path.** Already real: ClickHouse/VictoriaMetrics/OpenSearch on Compose, Go
stdlib backend, tenant RLS, per-tenant encryption, operator-visibility restriction.
Kentik's denormalized enrich-at-ingest pattern ◻ and Dynatrace's
entity-reference-on-every-observation pattern ◻ are both directly portable to our
ClickHouse schemas (and partially present in the #67 signal spine).

### 5.5 Verifiable RCA (cross-cutting)

No benchmark exists ◻; synthetic benchmarks overstate effectiveness ◻; published F1s
can be inflated by data contamination ◻. ➤ #67's deterministic replay + versioned
append-only objects make "show me it works on last month's incident" a sales motion
no corpus vendor can match. Low cost, high differentiation; keep replay
non-negotiable in implementation.

---

## 6. Sources

Quality tags from the corpus; **✅ n claims confirmed** = adversarially verified claims from that source.

| Source | Quality | Date | Verification |
|---|---|---|---|
| [Dynatrace Davis RCA concepts](https://docs.dynatrace.com/docs/discover-dynatrace/platform/davis-ai/root-cause-analysis/concepts) | primary | 2026-06-09 | **✅ 3 claims confirmed (3-0)** |
| [Dynatrace extend-topology docs](https://docs.dynatrace.com/docs/ingest-from/extend-dynatrace/extend-topology) | primary | 2026-01-28 | unverified |
| [Dynatrace new Smartscape blog](https://www.dynatrace.com/news/blog/new-smartscape-make-better-decisions-with-real-time-dependency-graph-of-digital-systems/) | blog | 2026-01-28 | unverified |
| [ThousandEyes platform page](https://www.thousandeyes.com/product/platform) | primary | undated (2026 footer) | **✅ 3 claims confirmed (3-0)** |
| [ThousandEyes path-trace docs](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace) | primary | undated | unverified |
| [ThousandEyes 4 BGP scenarios](https://www.thousandeyes.com/blog/4-real-bgp-troubleshooting-scenarios) | blog | ~2021–2023 | unverified |
| [Datadog Watchdog RCA blog](https://www.datadoghq.com/blog/datadog-watchdog-automated-root-cause-analysis/) | blog | 2021-01 (upd. 2022-04) | unverified |
| [Kentik UDR](https://www.kentik.com/blog/going-beyond-the-netflow-introducing-universal-data-records/) | primary | 2019-05-23 | unverified |
| [Kentik unified data repository](https://www.kentik.com/blog/modernizing-data-analytics-with-a-unified-data-repository/) | blog | 2023-05-11 | unverified |
| [Kentik data-platform needs](https://www.kentik.com/blog/understanding-data-platform-needs-to-support-network-observability/) | blog | 2023-02-15 | unverified |
| [Selector platform](https://www.selector.ai/platform/) | primary | undated (2026 refs) | **✅ 3 claims confirmed (3-0)** |
| [Eval of causal RCA at scale, ASE'24 (arXiv 2408.13729)](https://arxiv.org/html/2408.13729v1) | primary | 2024-08 | **✅ 4 claims confirmed (3-0)** |
| [Microservice RCA survey (arXiv 2408.00803)](https://arxiv.org/html/2408.00803v1) | primary | 2024-08 | **✅ 1 confirmed (2-1)**; **✗ 2 refuted (1-2, 0-3)** |
| [NetBouncer, NSDI'19](https://www.usenix.org/system/files/nsdi19spring_tan_prepub.pdf) | primary | 2019-02 | **✅ 3 claims confirmed (3-0)** |
| [Flock, PACMNET'23](https://pbg.cs.illinois.edu/papers/harsh23flock.pdf) | primary | 2023 | **✅ 1 claim confirmed (3-0)**; 2 unverified (0-0) |
| [HPCI/CPBE alarm RCA (arXiv 2105.03092)](https://ar5iv.labs.arxiv.org/html/2105.03092) | primary | 2021-05 | all unverified (0-0) |
| [PORCA (arXiv 2407.05869)](https://arxiv.org/pdf/2407.05869) | primary | 2024-07 | unverified |
| [AIOps survey (arXiv 2404.01363)](https://arxiv.org/html/2404.01363v1) | primary | 2024-04 | unverified |
| [RFC 8762 STAMP](https://datatracker.ietf.org/doc/rfc8762/) | primary | 2020-03 | unverified (standards text) |
| [Paris traceroute MDA-Lite, IMC'18](https://dl.acm.org/doi/10.1145/3278532.3278536) | primary | 2018-09 | unverified |
| [CAIDA IODA](https://www.caida.org/projects/ioda/) | primary | ongoing | unverified |
| [monitoring2: AI agents invade observability](https://monitoring2.substack.com/p/ai-agents-invade-observability) | blog | 2024-09-18 | unverified |

Search angles covered: vendor-architectures, academic-rca-algorithms,
active-measurement-standards, passive-telemetry-unification,
practitioner-fault-isolation-and-gaps. Additional URLs surfaced by searchers but
without extracted claims (Cilium docs, NIST pub, Packet Pushers TNO008, LogicMonitor
BGP cheat sheet, ThousandEyes BGP-route-viz docs, shankar0123/network-observability-platform)
are not cited above and contributed no facts to this report.
