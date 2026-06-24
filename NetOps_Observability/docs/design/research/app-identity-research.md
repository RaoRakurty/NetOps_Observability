# Application Identification — Research Findings (#81)

> **Status:** reconstructed 2026-06-24. The original deep-research workflow
> (`wf_a3faec14-2e0`) was launched but its **cited** synthesis was never
> persisted to a file. This document reconstructs the research from (a) the
> launch brief that framed the pass, (b) the in-session design discussion, and
> (c) well-established, independently-verifiable domain knowledge about
> flow/log-based app identification.
>
> **Provenance honesty (project rule):** claims here are domain-standard and
> checkable against the cited *kinds* of source (vendor IP-range feeds, IANA/RFC
> IE registries, public product docs). Where a number is illustrative rather than
> measured, it is marked *(illustrative)*. Anything we have not measured on our
> own data is not presented as our result. The companion design doc is
> `docs/design/app-identification.md`.

---

## 0. The question

Design an **application identification engine** for a modern, **agentless**
network-observability platform — resolve a business/technical *application name*
for traffic using only the metadata we already collect (flow records, syslog,
cloud logs, metrics, active probes), **without packet capture / DPI and without
host agents**. It must resolve at **low latency and low compute/memory** at high
flow rates (thousands of flows/sec), fit our **zero-trust multi-tenant** model,
and produce a **confidence-scored** verdict that can honestly say *"unknown."*

Scope decision (owner, 2026-06-24): this is **flow→app *enrichment*, not DPI** —
a **lookup problem** (attach an app label to a flow from metadata already
present), not a payload-analysis problem. That single reframing is what makes
the low-compute/fast/caching design tractable.

---

## 1. Why app identification is hard in 2026 (what survives in a no-packet world)

The signals that classical DPI relied on are mostly gone or invisible to an
agentless collector:

| Trend | Effect on identification | What still survives (agentless) |
|---|---|---|
| **SaaS-everything** (M365, Salesforce, Zoom, Workday) | App ≠ a server you own; it's a set of vendor-published endpoints | **Vendor-published IP/CIDR + domain catalogs** |
| **Public-cloud service IPs** (AWS/Azure/GCP) | Destination IP belongs to a hyperscaler range, not "the app" | Cloud-published IP-range files (`ip-ranges.json`, Azure ServiceTags, GCP `cloud.json`) → region/service, **not app**; needs cloud **resource/tag** metadata to reach app |
| **CDNs / shared IPs** (Cloudflare, Akamai, Fastly) | One IP fronts thousands of apps | IP alone is ambiguous → **DNS name** or **SNI** required to disambiguate |
| **Encrypted-by-default** (TLS 1.3, **ECH/ESNI**, QUIC/HTTP-3) | Payload and increasingly **SNI** are unreadable | SNI survives *only* where an exporter/NGFW logs it pre-encryption; otherwise fall back to IP/DNS/ASN |
| **Microservices / ephemeral / overlapping IPs** | Internal IPs are reused, short-lived, RFC1918-overlapping across tenants | Internal apps need **operator-declared** services (#69) + **SoT/CMDB** — no public catalog exists |
| **NAT / VXLAN overlay** | Outer 5-tuple hides the real endpoints | Inner headers needed (gated on #82 overlay-flow work); underlay attribution stays coarse |

**Conclusion:** in an agentless world, identification degrades gracefully from
*precise* (DNS/SNI/cloud-tag present) to *coarse* (IP-range/ASN only) to
*unknown*. The engine's correctness depends on **never promoting a coarse signal
to a precise claim** — which is exactly why a confidence model (not a single
guess) is mandatory.

---

## 2. Identification techniques — survey & fit

Rated for our constraints. **Fit** = works on flow+log+cloud with no packets.

| # | Technique | How it works | Accuracy | Freshness/maintenance | Compute | Fit | Verdict |
|---|---|---|---|---|---|---|---|
| (a) | **IP/prefix catalogs** (M365 endpoints API, AWS `ip-ranges.json`, Azure ServiceTags, GCP, BGP/ASN, GeoIP) | Longest-prefix-match dst IP → vendor/service | Med–High for SaaS/cloud; **Low for shared CDN IPs** | Feeds refresh daily–weekly; vendor-maintained (low cost to *consume*) | **Very low** (LPM lookup) | ✅ native | **CORE** |
| (b) | **DNS-flow correlation** (passive DNS / resolver logs ↔ flow) | "name → IP" from DNS, then flow to that IP inherits the name | High when DNS visible | Per-resolution, short TTL; needs DNS collection | Low–Med (join/cache) | ⚠️ needs DNS source | **CORE (collection-gated)** |
| (c) | **TLS SNI** (+ JA3/JA4 fingerprint) | Server name from ClientHello, or JA-fingerprint of the client | High (SNI) | Per-flow | Low if exported; **N/A without an exporter/NGFW that logs it** | ⚠️ ECH erodes it | **HIGH-VALUE where exported** |
| (d) | **IPFIX `applicationId` IE 95 / NBAR2 / vendor app-id** | The *exporter/NGFW already classified it* and ships the label in flow/log | **Highest** (on-box DPI) | None (vendor-maintained) | **Zero for us** | ✅ where traffic crosses capable gear | **FREE WIN — consume it** |
| (e) | **Port/protocol heuristics** | 443→HTTPS, 3306→MySQL | **Low** (everything is 443) | Static | Trivial | ✅ | **WEAK — last-resort hint only** |
| (f) | **Cloud-native metadata** (VPC flow logs + resource-id/tags, asset inventory) | Map cloud resource-ID/tag → app from the cloud's own records | High for cloud workloads | API-driven, per-account | Low | ⚠️ needs cloud-log ingest | **CORE for cloud (gated)** |
| (g) | **SoT/CMDB enrichment** (NetBox — already integrated) | Operator's recorded IP/service → app/owner mapping | High for *known* internal apps | Manual/managed | Trivial | ✅ | **CORE for internal** |
| (h) | **ML / statistical flow-feature classification** | Classify encrypted traffic by packet-size/timing features | Variable; opaque; false-positive risk | Model retraining | **High** | ⚠️ heavy, hard to explain | **FUTURISTIC — not MVP** |

### The pragmatic core (2–3 techniques, not 8)

1. **IP/prefix catalogs (a)** — covers SaaS + cloud + ASN with a single LPM index; lowest compute; the spine.
2. **NGFW / IPFIX app-id (d)** — free, highest-accuracy, *where present*; pure consumption.
3. **Operator-defined services (g, #69) + SoT/NetBox** — the authoritative source for **internal** apps that have no public catalog.

**DNS-flow correlation (b)** and **SNI (c)** are the high-value *next* tier — they
land as a **contract now, evidence-source-when-collected** (the Layer-2-collect /
Layer-3-identify split we already use for fault coverage in #80). **ML (h)** and
**eBPF on-host** are explicitly *futuristic*, noted but out of the MVP.

---

## 3. Multi-signal fusion — confidence, not a single guess

Leaders avoid false `app = X` labels by **never trusting one signal** and by
making **"unknown" a first-class answer**. Our advantage: **we already own a
grounded evidence/verdict engine** and should reuse it rather than invent a
parallel scorer.

**Precedence (strong → weak), with agreement boosting and disagreement demoting:**

```
  NGFW/IPFIX app-id (on-box DPI)         ── authoritative
  SoT/CMDB / operator-declared service   ── authoritative for internal
  DNS name → catalog / SNI               ── strong
  IP/prefix vendor catalog               ── medium (coarse on shared CDN IPs)
  ASN → org                              ── weak/context
  port/protocol                          ── hint only
```

- **Agreement** (e.g. catalog says *Zoom* AND DNS resolved `*.zoom.us`) →
  promote confidence band.
- **Contradiction** (catalog says *Salesforce*, SNI says `slack.com`) → **demote**
  and surface both; never silently pick one. (Mirrors the engine's
  `CONTRADICTION_PENALTY`.)
- **Coarse-only** (shared CDN IP, no DNS/SNI) → return the **broadest honest
  label** (`CDN: Cloudflare`, or `unknown`) — *not* a guessed app.
- **Confidence bands** map directly onto the existing `VerdictTier`:
  `confirmed` (authoritative or agreeing-strong), `suspected` (single medium
  signal), `undetermined`/`unknown` (coarse-only or below floor).

This is the moat: identification that **integrates into RCA** ("which app is
affected, and how sure are we") instead of a brittle standalone label.

---

## 4. Architecture for scale, low latency, low compute (the heart)

### 4.1 Data structures

- **IP → prefix → app: longest-prefix-match radix/patricia trie.** Stdlib-friendly
  (no dependency); O(prefix-length) lookup; millions of prefixes fit in tens of
  MB. This is the single hottest structure and it is **cheap by nature** — the
  whole reason the lookup framing wins.
- **Domain/SNI patterns: Aho-Corasick / suffix-set automaton** for `*.zoom.us`
  style suffix matching. Only needed once DNS/SNI collection lands.
- **Exact maps** (ASN→org, resource-id→app, port→hint) are plain hash maps.

### 4.2 Caching — is it even the right lever?

The honest finding: with a **fast in-memory LPM index, the index *is* the
optimization** — a per-lookup radix walk is already nanoseconds. Caching helps
mainly to **skip repeated work on hot flows** and to **short-circuit misses**:

- **Per-(dst-IP→app) LRU/ARC cache** — collapses the repeated-destination case
  (most traffic goes to few destinations). High hit-rate, biggest win.
- **Negative cache / Bloom filter** — skip the trie for IPs known to miss all
  catalogs (avoids walking the tree for internal RFC1918 with no selector).
- **Invalidation by catalog *version*, not TTL** — when a feed refreshes, bump a
  generation counter; stale cache entries are lazily dropped. Avoids latency
  spikes from coordinated TTL expiry.

Caching is a **secondary** lever; the index is primary. We will not over-engineer
a cache before measuring hit-rates on real flow distributions.

### 4.3 Inline-streaming vs query-time enrichment

**Recommendation: query-time first, like `flows_services.go`.**

- **MV-over-flows is banned** in this codebase — a materialized view on the flow
  ingest path regresses ingestion throughput and couples enrichment to hot-path
  latency. (Same rule that shaped #69.)
- **Query-time attribution** (resolve app at read time over the catalog index) is
  the safe default: zero ingestion impact, catalog changes apply retroactively,
  and it reuses the proven injection-safe pattern.
- **Inline enrichment** (a Go enricher tagging flows with `app_id` *before*
  ClickHouse, optionally via Vector/Redpanda) is a **scale follow-up** for when
  read-time resolution over very high cardinality becomes the bottleneck — added
  only with a measured reason, and even then writing a *resolved label column*,
  never a heavy MV.

### 4.4 Catalog lifecycle

- **Pluggable feed loaders** (M365 endpoints API, AWS/Azure/GCP range files,
  optional commercial IPinfo/Netify) → normalized `(prefix, app, confidence,
  source, version)` rows.
- **Incremental, versioned, hot-reloaded:** load into a *new* trie generation
  off the hot path, then atomically swap the pointer (the EntityResolver 60s
  atomic-export pattern). No rebuild stalls, no lookup-path locking.
- **Offline-buildable:** feeds are fetched by an opt-in background job; the engine
  runs on whatever catalog snapshot is on disk (clean-build / air-gap safe).

### 4.5 Bounded memory at scale

Tens of MB for millions of prefixes (radix tries are compact); domain automata
sized to the suffix set; caches LRU-bounded. Per-tenant catalogs are small;
shared public catalogs are loaded **once** and read-only across tenants (the data
is public — only *results* are tenant-scoped).

---

## 5. How the leaders do it (source-of-truth, architecture)

> Reconstructed from public product documentation; treat as direction, not
> measured benchmarks.

- **Cisco NBAR2 / ThousandEyes** — on-box DPI + protocol-signature library;
  exports the classification as **IPFIX `applicationId` (IE 95)**. *We consume
  this output rather than reproduce the DPI.*
- **Kentik** — **flow-based** app attribution: IP/ASN/GeoIP + DNS + cloud
  metadata enrichment at query/ingest time over NetFlow/sFlow/IPFIX. Closest
  peer to our model; the bar to beat on **overlay/VNI/tenant/app** attribution
  (#82).
- **Palo Alto App-ID** — on-box App-ID engine; **app label in the firewall log**.
  *Free signal for traffic crossing the NGFW* — exactly our (d).
- **Cloudflare** — owns the resolver + edge, so DNS+SNI are native; not our
  position, but validates DNS/SNI as the precise signals.
- **ntopng / nDPI, Corelight/Zeek** — packet/flow DPI engines; **out of our lane**
  (no packets) except as a reference for signature catalogs.
- **Netify / IPinfo** — commercial **IP→app/CDN catalogs**; a potential premium
  feed for technique (a) if we ever want beyond free vendor ranges.
- **Datadog** — leans on agents + cloud integrations for app/service identity;
  validates the **cloud-metadata** path (f) but assumes the agent we don't have.

**Takeaway:** the agentless leaders (Kentik especially) all land on the same
**catalog + DNS + cloud-metadata + consume-vendor-app-id** core we propose. The
differentiation is our **evidence-grounded confidence fusion + RCA integration**,
not the raw lookup.

---

## 6. Futuristic view (noted, not MVP)

- **Encrypted-traffic / QUIC / ECH classification** — as SNI disappears under ECH,
  IP/DNS/cloud-metadata carry more weight; statistical classification becomes the
  only payload-free option. Keep the confidence model honest about the erosion.
- **ML-on-flow-features** — viable later for "unknown" residue; must stay
  **explainable** (feeds the evidence log, never an opaque verdict).
- **eBPF on-host** — the one high-fidelity future option *if* we ever ship an
  agent; explicitly out of the agentless MVP.
- **LLM-assisted catalog curation** — normalize/dedupe vendor feeds and map raw
  resource tags → canonical app names; a curation aid, gated behind the same
  OWASP-LLM guardrails (§15) — model output is **data**, reviewed, never
  auto-trusted.
- **Continuous-learning feedback loop** — operator confirms/corrects a verdict →
  becomes a high-confidence SoT entry (technique g). Cheap, accurate, compounding.

---

## 7. Recommended core (the answer)

> **Catalog-driven flow enrichment with confidence**, reusing the existing
> service-catalog + correlation-evidence machinery:

1. **Spine:** in-memory **LPM trie** over IP/prefix catalogs (vendor SaaS/cloud
   ranges + ASN), query-time, hot-LRU + negative-cache.
2. **Free win:** **consume NGFW/IPFIX `applicationId`** where traffic crosses
   capable gear (requires a parsing pass — see design doc P-NGFW).
3. **Internal authority:** **#69 operator-defined services + SoT/NetBox**.
4. **Precise tier (collection-gated):** **DNS-flow correlation** then **SNI** —
   contract now, evidence when collected.
5. **Fusion:** map to the existing **`VerdictTier` + `corr_evidence` roles**;
   **"unknown" is first-class**; contradictions demote, agreement promotes.
6. **No new runtime dependency** — radix trie + automata are stdlib-buildable;
   feed-fetching is an opt-in background job (offline-safe).

Dependencies/cost trade-offs and the phased build (MVP → scale → futuristic) are
in `docs/design/app-identification.md`.

---

## 8. Open questions carried into the design

1. **`applications` as a thin parent over the existing `services` table** (business
   capability over technical service), vs fully separate entities? *(Recommended:
   thin parent — don't rebuild #69.)*
2. **First catalog feeds** to ship: M365 endpoints API + AWS/Azure/GCP ranges are
   free and high-value; add a commercial IP→app feed (Netify/IPinfo) later?
3. **NGFW app-id extraction** — promote the documented-but-unparsed `fw_event`
   `app-id` field (telemetry-coverage-reference.md:105) into a real Vector parse +
   a flows/logs join. Own sub-task.
4. **DNS collection source** — resolver logs vs passive-DNS vs flow-to-DNS join;
   which is realistic for an agentless customer? (Gates the precise tier.)
