# BGP Operations page — capability tracker (owner list, 2026-09-02)

Owner asked for the status of each capability on the BGP operations page.
Statuses verified against code at `c96b55da` (routes in `main.go`, page
`src/frontend/src/pages/BgpOps.tsx` + `pages/bgp/`, backend `bgp_ops.go`,
`internal/bgpdepth`, `internal/bmp`, `collectors/traceroute.go`).
✅ built · 🟡 partial · ❌ not built · ⛔ not planned (reason given).

| # | Capability | Status | What exists today | What is missing / next step |
|---|---|---|---|---|
| 1 | Bogon route listing | ❌ | Nothing. | Static bogon/martian set (RFC 1918/6598/5737/3849, unallocated space) + the Team Cymru full-bogon text feed (free, stdlib fetch, cached) checked against the watchlist, the polled feed and BMP updates; a "Bogons seen" table with peer/vantage and first-seen. |
| 2 | Graph v4/v6 path view | 🟡 | AS-path graph per prefix (`/api/bgp/aspath-graph`, `AsPathGraphPanel`) from RIS `bgp-state` with `looking-glass` fallback; accepts IPv4 and IPv6 prefixes. | Explicit v4/v6 toggle and side-by-side view for a dual-stack resource; path-length histogram / visibility gauge polish from the `91df4f62` design. |
| 3 | Asymmetric path analysis | ❌ | Outbound Paris traceroute collector exists (`FEATURE_TRACEROUTE`, ICMP + TCP-SYN); inbound AS paths exist (RIS/BMP). | Join the two: our forward hop path (traceroute → ASN via RDAP/whois cache) vs the inbound AS path seen by collectors; flag the asymmetry per prefix pair. |
| 4 | Peers tab — adjacency and transit issues | 🟡 | BMP sessions API (`/api/bgp/bmp/sessions`: peer up/down, counters, per tenant, dormant behind `FEATURE_BMP`); device-side `device_bgp_peer_state` series on device pages; persistent not-Established rule being added in the engine (wave 2). | A Peers tab on the BGP page: BMP sessions + device peer state in one table, transit set per prefix (upstream ASN changes over time), "peer flapping" / "transit changed" chips. |
| 5 | Prefixes tab — leak and hijack tracking | 🟡 | Watchlist per prefix with RIS visibility, RPKI Valid/Invalid/Unknown (Invalid rendered as "possible hijack"), update churn (8h), ownership/contacts. | Origin-change detection vs the expected origin set; route-leak heuristic (valley-free / unexpected transit in the path, upstream not in the declared set); an incident class per prefix (visibility loss / origin change / leak / RPKI flip) with history. |
| 6 | Looking-glass servers | 🟡 | RIPE RIS looking-glass API used for paths. | On-demand queries to public looking glasses (NLNOG ring, alice-lg instances, target-AS LGs) from the research §(b)7; results shown beside RIS. |
| 7 | Traceroute — MTR and Paris | 🟡 | Paris-consistent traceroute collector (constant flow identifiers, ICMP and TCP-SYN), remote-vantage pushes (`POST /api/probe/paths`), shown on the Network Path page. Needs `CAP_NET_RAW`. | MTR-style continuous mode (per-hop loss/latency over N probes) and a "Trace from here" control on the BGP page that runs to the prefix and overlays hops on the AS-path graph. |
| 8 | scapy | ⛔ | — | Not planned. The stack is Go stdlib + `x/net` icmp/ipv4 by allowlist; custom probes belong in the traceroute collector. Crafting arbitrary packets toward the internet from the platform is a liability we do not want. |
| 9 | Live NetFlow ↔ BGP path map | ❌ | Flows carry `src_as`/`dst_as` (goflow2 → ClickHouse); AS-path graph exists. | Overlay: top talkers by destination ASN joined to the current AS path for those destinations, on the same graph, per tenant; "traffic to AS X now takes path Y". |
| 10 | Alerting — route leaks, hijacks, major outages | ❌ | No BGP-specific alert rule exists (vmalert has none; the watchlist evaluates but emits nothing). | Watchlist evaluator → notifications for: RPKI flips to Invalid, visibility drop below threshold, origin change, upstream/transit change, bogon seen. Route through the existing notify channels and, as a symptom rule, into the engine so an outage correlates with the seam. |
| 11 | Route Views | ❌ | Not integrated (RIPEstat is RIS-only). | RouteViews MRT archives (RIB + updates) parsed with the BGP UPDATE parser already in `internal/bmp`; second vantage set beside RIS. |
| 12 | RIPEstat | ✅ | Data spine: `routing-status`, `bgp-state`, `looking-glass`, `bgp-updates`, `rpki-validation`, `whois`, `announced-prefixes`, plus RDAP ownership. | — |
| 13 | RPKI | ✅ | Per-prefix validation with fetched-at; unknown status can never render as valid. | — |
| 14 | ASPA | 🟡 | Honest "no ASPA source configured" card + pluggable `BGP_ASPA_PROVIDER_URL`. No public per-ASN ASPA API exists (verified). | Wire a provider when one exists (or a local rpki-client dump). |
| 15 | Geofeed (RFC 8805/9092) | ✅ | Discovery from whois, conservative CSV parse, cached. | — |
| 16 | Near-live BGP feed | ✅ | Per-tenant 2000-entry ring over a bounded RIPEstat poller (`FEATURE_BGP_LIVE_FEED`). RIS Live (WebSocket) not used: no websocket module on the §6 allowlist. | Surface BMP updates in the same panel when `FEATURE_BMP` is on. |
| 17 | BMP receiver (RFC 7854) | ✅ backend | Parser + listener + per-tenant store + 3 read routes; dormant by default. | UI (see #4). |
| 18 | AI over BGP tools | 🟡 | Iris BGP read tools being added (wave 2). | — |

**Recommended build order for the gaps:** 10 (alerting) → 5 (leak/hijack classes)
→ 4 (Peers tab) → 1 (bogons) → 9 (flow↔path map) → 3 (asymmetry) → 7 (MTR + trace
from page) → 6 (looking glasses) → 11 (Route Views) → 2 (v4/v6 polish).
