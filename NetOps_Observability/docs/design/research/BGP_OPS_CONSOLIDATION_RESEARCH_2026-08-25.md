# Protocol Monitoring / BGP Operations — consolidation research (2026-08-25)

Commissioned by the owner (frontend/product wave item 10): consolidate the
NOC's BGP-outage tooling (email, Salesforce, looking glasses, whois, RIR
databases) into one page; train the AI on these sources. Researched by a
web-research agent against live endpoints/official docs; "not found" = could
not be verified. This is the design authority for the BGP operations build.

## 0. "netomics" identified

**netomics.com is FastNetMon Inc's own routing-analytics product** (footer:
"FastNetMon Inc <support@fastnetmon.com>") — Prefix/ASN Observatory, live
routing feed, AS-path visualization, ASPA display, RFC 8805 geofeeds. So the
owner's two references are one vendor family: FastNetMon = flow DDoS detector
using BGP as mitigation actuator; netomics = its BGP-monitoring product.
Pricing/API: not published.

## (a) Source → API table (licensing verdicts bolded)

| Source | Access | Freshness | Limits | Commercial use |
|---|---|---|---|---|
| RIPE RIS Live | `wss://ris-live.ripe.net/v1/ws/` (filter prefix/ASN/type) | seconds | none; slow consumers dropped | **YES with attribution** (logo+link, revocable) |
| RIS raw MRT | data.ris.ripe.net — RIB 8h, updates 5min, 25 RRCs | 5min–8h | none | same grant |
| RIPEstat Data API | stat.ripe.net/data/<call>/ — routing-status, bgp-updates, routing-history, rpki-validation, looking-glass | minutes | 8 concurrent/IP; >1k/day → register sourceapp | **YES** |
| RouteViews | MRT (RIB 2h/upd 15min) + **public Kafka BMP `stream.routeviews.org:9092`** | Kafka near-realtime | none documented | "freely available" — **confirm via help@routeviews.org** |
| CAIDA BGPStream v2 | lib (C/Python), multiplexes RIS+RouteViews incl. live | source-dependent | public broker | software BSD-2; data per upstream |
| BGPKit | Rust/Python broker+parser+monocle | same | none | permissive |
| bgp.tools | whois:43 bulk, table.jsonl (~30min), mandatory UA | ~30min | ≥2h cache | free tier personal only; **ASK admin@** for commercial; no historical/streaming API |
| Qrator Radar | api.radar.qrator.net (OpenAPI live): leaks, hijacks, bogons, invalid-ROA per ASN | realtime | auth details not found | **unknown — contact radar@qrator.net** |
| Cloudflare Radar | radar/bgp/* incl. confidence-scored hijack/leak events, ASPA snapshots | near-realtime | 1200 req/5min | **NO — CC BY-NC 4.0** |
| PCH | daily snapshots | daily | none | **NO — CC BY-NC-SA** |
| RDAP (5 RIRs) | per-RIR endpoints; RFC 9224 bootstrap from data.iana.org/rdap/ | live | RIPE 1k/day on personal data | ops use yes; ARIN ToU forbids republishing datasets — cache, don't redistribute; **don't use rdap.org in prod** |
| IRR (RADB/RIPE/ARIN/NTTCOM/LEVEL3) | whois:43; daily dumps; NRTMv3 + **NRTMv4** (RIPE prod live) | dumps daily; v4 per-minute | none | querying free (RADB $595/yr is for PUBLISHING); NTTCOM+LEVEL3 still alive; ARIN-NONAUTH gone |
| IRRexplorer | irrexplorer.nlnog.net/api/prefixes/prefix/<pfx> | live | community | **self-host it** (open source) |
| PeeringDB | /api/ net/org/ix/poc; local sync hourly max | live | anon 20/min (poc hidden); key 40/min | **NOT CC0**; AUP allows troubleshooting, excludes "other commercial application"; bundled mirror needs written OK support@peeringdb.com |
| Geofeeds | RFC 8805 CSVs via RFC 9632 discovery + RFC 9877 (RDAP); aggregate via geofeed-finder (BSD-3) or geolocatemuch.com | daily | polite | yes |
| rpki-client | cron → JSON; **ASPA by default**, `expires` field; v9.9 | 15–60min | self-hosted | **ISC — yes** |
| Routinator | HTTP API: POST /api/v1/validity (batch), /json-delta/notify long-poll, RTR | ~10min | self-hosted | BSD-3 |
| Hosted RPKI JSON | rpki.cloudflare.com/rpki.json (~103MB, 30–60min) | 30–60min | none | no terms/SLA — bootstrap only; history: rpkiviews.org |
| Looking glasses | **NLNOG RING LG JSON API** (incl. RPKI+communities); **alice-lg REST at DE-CIX/AMS-IX (live, unauth)**; PeeringDB looking_glass as directory; long tail human-only | live | community | on-demand verification plane only, never a feed; CAIDA Periscope dead |

**Clean commercial backbone:** RIS Live + RIS MRT + RIPEstat (attribution) +
self-hosted rpki-client + direct RDAP + IRR local mirror + geofeed-finder.
Ask-first: RouteViews, bgp.tools, Qrator, PeeringDB-as-mirror. Blocked:
Cloudflare Radar, PCH.

## (b) The one-page incident view (top to bottom)

1. **Verdict bar** — prefix+origin, incident class (visibility loss / origin
   hijack / path change / leak / RPKI-invalid), start time, global visibility
   gauge ("seen by 214/335 full-feed RIS peers, was 331") from OUR consumer.
2. **Current paths from N vantage points** — AS-path graph grouped by
   upstream, diffed vs pre-incident baseline; broken segments in RCA red.
3. **Updates timeline** — 24–72h announce/withdraw stream from the local
   buffer with burst annotations; RIPEstat beyond the buffer.
4. **RPKI panel** — Valid/Invalid(origin/maxLength/AS0)/NotFound from our
   rpki-client snapshots, plus Kentik's refinement "would this actually be
   dropped?" (covering less-specific), ROA-expiring-soon. ASPA: read-only
   chip labeled draft (~2,768 ASPAs globally vs ~385k ROAs — absence renders
   neutral).
5. **Ownership & contacts** — RDAP (authoritative), PeeringDB (NOC/policy
   contacts, IXPs, LG url); one-click "who to call" for the seam-owner AS
   (matches the seam-ownership RCA philosophy).
6. **IRR consistency strip** — route objects across IRRs vs BGP origin vs ROA
   (leak-attribution evidence).
7. **On-demand verification** — buttons firing NLNOG / alice-lg / target-AS
   LG queries; inline results, never pre-fetched.
8. **Geofeed panel** — declared vs observed geography.
9. **Third-party corroboration** (license-gated) — Qrator/bgp.tools chips.
10. **AI narrative + actions** — evidence-linked summary with honest
    "possibly because of" phrasing; draft outreach email to RDAP/PeeringDB
    contacts.

## (c) Build vs fetch

- Live updates: **BUILD** — own RIS Live consumer → event bus → ClickHouse
  72h buffer per tenant prefix (the "what changed in the last 30 min"
  question is only answerable locally). RouteViews Kafka BMP as feed #2
  after email OK.
- Visibility/RIB state: **BUILD (derived)**, seeded from MRT bview.
- History/deep: **FETCH RIPEstat** (sourceapp + cache).
- Hijack/leak detection: **PORT BGPalerter's monitor patterns** (BSD-3;
  connector→monitor→report maps onto our bus). Own detection is the
  defensible IP; Cloudflare's API is NC-licensed.
- RPKI: **BUILD** rpki-client timer → timestamped snapshots ("was it invalid
  at incident time"); optional Routinator for batch validity.
- RDAP: **FETCH live, cache 24h–7d**, own IANA bootstrap.
- IRR: **BUILD local mirror** (daily dumps + NRTMv4).
- PeeringDB: **FETCH keyed + cache**; bundled-mirror decision awaits AUP
  answer.
- Geofeeds: **BUILD** daily geofeed-finder cron.
- Looking glasses: **FETCH on demand only**; no aggregator, no scraping.
- Customer-side truth (v2 moat): **BMP from customer routers** (GoBMP).

## (d) v1 scope

v1: [M] RIS Live consumer + tenant prefix state + 72h buffer (§3a scoped) ·
[M] incident panels 1–3 · [S] rpki-client + RPKI panel · [S] RDAP client +
contact card · [S] RIPEstat integration · [S] BGPalerter-pattern monitors
(visibility loss, new origin, RPKI-invalid) → existing alerting · [S] RIPE
attribution footer (license condition).
v1.5: PeeringDB keyed · IRR mirror + consistency strip · geofeeds ·
on-demand LG buttons · ASPA chip.
v2: RouteViews BMP + MRT backfill · customer BMP (GoBMP) [L] · leak/path
monitors (needs CAIDA AS-relationships, monthly) · AI narrative.

**§6 allowlist note:** RIS Live is plain websocket (stdlib-adjacent but an
honest gate discussion for a ws client lib); Kafka has no stdlib path — either
amend the table (franz-go / segmentio) or route ingestion through the existing
bus-facing components that already speak Kafka (preferred).

## (e) AI/assistant plan

Precedents: Kentik AI Advisor (agentic investigation over own stores),
ThousandEyes GenAI summaries + official MCP server, Selector.ai copilot;
academic BEAR (arXiv:2506.04514), TypoNet (arXiv:2607.22947) — the winning
split is **deterministic detectors compute, the LLM narrates/orchestrates** —
exactly Correlix's engine+copilot architecture. OSS MCP servers to crib:
taihen/mcp-ripestat, duksh/peerglass (5-RIR RDAP + RPKI + visibility).
White space: nobody ships automatic RCA narratives from routing data.

**No fine-tuning for v1** — tool access over local caches + live fetchers:
cache continuously (tenant baseline, RIS 72h buffer, RPKI snapshots 15–60min,
PeeringDB hourly-daily, IRR daily+NRTMv4, RDAP lazy-TTL, CAIDA AS-rel monthly,
geofeeds daily; evaluate IIJ Internet Yellow Pages); fetch live (RIPEstat, LG
APIs, validator now-state, corroboration links).

Example queries → sources: "why is X unreachable" (local visibility +
RIPEstat + AS-rel + baseline); "who leaked our route" (buffer AS-paths +
valley-free check + IRR + RDAP/PeeringDB); "was our ROA valid at 14:00"
(local snapshot series); "who owns AS64500 / NOC contact" (RDAP→PeeringDB);
"what changed in 30 min" (strictly local buffer — the reason the consumer
exists). All under CLAUDE.md §15 copilot guardrails.

**Corrections vs common assumptions:** BGPalerter is BSD-3; NLNOG LG is
OpenBGPD-backed with a real JSON API; NTTCOM+LEVEL3 IRRs alive; PeeringDB not
CC0; Cloudflare Radar hijack API non-commercial; ASPA still IETF-draft
(display, don't alert); Catchpoint BGP monitoring now inside LogicMonitor.
