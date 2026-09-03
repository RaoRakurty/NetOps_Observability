# BGP Operations page — capability tracker (owner list, 2026-09-02)

Owner asked for the status of each capability on the BGP operations page.
Statuses verified against code at `c96b55da` (routes in `main.go`, page
`src/frontend/src/pages/BgpOps.tsx` + `pages/bgp/`, backend `bgp_ops.go`,
`internal/bgpdepth`, `internal/bmp`, `collectors/traceroute.go`).
✅ built · 🟡 partial · ❌ not built · ⛔ not planned (reason given).

| # | Capability | Status | What exists today | What is missing / next step |
|---|---|---|---|---|
| 1 | Bogon route listing | ✅ | `internal/bgpwatch/bogon.go`: an embedded IANA/RFC special-purpose set (IPv4 + IPv6 special-purpose registries per RFC 6890, transcribed 2026-09-02, source + date served on the API) plus the RFC 4291 rule that IPv6 outside `2000::/3` is undelegated; the OPTIONAL Team Cymru full-bogons text feed (https-only, bounded, cached 6h, retried with jitter, `FEATURE_BGP_BOGON_FEED`, default off) layers over it and a feed outage never un-flags anything. Checked against the watchlist (a watched bogon is an incident class), the BMP update ring and the near-live poller ring (`Runtime.Peek`, which reads without keeping a poller alive). `GET /api/bgp/bogons` serves the per-tenant sightings (block, source, peer, origin, first/last seen, count) plus the set in force; the Bogons tab renders them grouped by matched block. | IPv4 has no unallocated-unicast half to embed (the IANA free pool was exhausted 2011-02-03) — that is stated on the API rather than shipped as a table that would age. |
| 2 | Graph v4/v6 path view | 🟡 | AS-path graph per prefix (`/api/bgp/aspath-graph`, `AsPathGraphPanel`) from RIS `bgp-state` with `looking-glass` fallback; accepts IPv4 and IPv6 prefixes. | Explicit v4/v6 toggle and side-by-side view for a dual-stack resource; path-length histogram / visibility gauge polish from the `91df4f62` design. |
| 3 | Asymmetric path analysis | ❌ | Outbound Paris traceroute collector exists (`FEATURE_TRACEROUTE`, ICMP + TCP-SYN); inbound AS paths exist (RIS/BMP). | Join the two: our forward hop path (traceroute → ASN via RDAP/whois cache) vs the inbound AS path seen by collectors; flag the asymmetry per prefix pair. |
| 4 | Peers tab — adjacency and transit issues | ✅ | `src/pages/bgp/PeersPanel.tsx`, mounted as a tab on the BGP page: BMP sessions (`/api/bgp/bmp/sessions`) and device-side `device_bgp_peer_state` (through the tenant-scoped `/api/metrics/query`) merged into ONE table, each row naming which witness is talking; a BMP row wins for the same (device, peer) because only it carries the transition reason and the counters. Only the BGP4-MIB `established` value renders up; an unreadable sample is `unknown`, never up. Five honest states (receiver off · nothing exporting · sessions with no observed peer state · rows · read failed). Transit set per watched prefix with the origin-adjacent upstream marked, plus "transit changed" / "flapping" chips driven by the same incident classes as the Prefixes tab. | Nothing outstanding for this row. A persistent not-Established engine rule is separate (wave 2). |
| 5 | Prefixes tab — leak and hijack tracking | ✅ | ONE classifier, `internal/bgpwatch/classify.go`, drives both the page and the pager: per watched prefix it computes `visibility_loss \| origin_change \| rpki_invalid \| route_leak \| bogon \| none \| unknown`, with evidence (the named collector vantage points that agree, the supporting AS paths, the observed origins, the measured RIS fraction, the matched bogon block) and `first_seen`/`since`/`last_seen`. False-positive guards are explicit: every path-derived class needs ≥ `min_vantages` (default 2) DISTINCT collector peers, and a near-miss is reported as a `corroboration_shortfall` rather than hidden. The route-leak heuristic is derived from the tenant's DECLARED upstream set only — unexpected transit adjacent to the origin, and a valley where one of our own upstreams carries the prefix for a third party; with no declared set it does not run rather than guessing one. An undeclared origin baseline is LEARNED and labelled as learned. The verdicts ride on the existing watchlist response (`incidents`), so there is no second prefix list. | Full valley-free validation needs AS provider/customer relationships no free per-ASN source publishes; that limitation is stated in the evidence text, not papered over. |
| 6 | Looking-glass servers | 🟡 | RIPE RIS looking-glass API used for paths. | On-demand queries to public looking glasses (NLNOG ring, alice-lg instances, target-AS LGs) from the research §(b)7; results shown beside RIS. |
| 7 | Traceroute — MTR and Paris | 🟡 | Paris-consistent traceroute collector (constant flow identifiers, ICMP and TCP-SYN), remote-vantage pushes (`POST /api/probe/paths`), shown on the Network Path page. Needs `CAP_NET_RAW`. | MTR-style continuous mode (per-hop loss/latency over N probes) and a "Trace from here" control on the BGP page that runs to the prefix and overlays hops on the AS-path graph. |
| 8 | scapy | ⛔ | — | Not planned. The stack is Go stdlib + `x/net` icmp/ipv4 by allowlist; custom probes belong in the traceroute collector. Crafting arbitrary packets toward the internet from the platform is a liability we do not want. |
| 9 | Live NetFlow ↔ BGP path map | ❌ | Flows carry `src_as`/`dst_as` (goflow2 → ClickHouse); AS-path graph exists. | Overlay: top talkers by destination ASN joined to the current AS path for those destinations, on the same graph, per tenant; "traffic to AS X now takes path Y". |
| 10 | Alerting — route leaks, hijacks, major outages | ✅ backend | `internal/bgpwatch` — a per-tenant, bounded, jittered evaluator (`FEATURE_BGP_ALERTS`, default off; TryLock so a pass never overlaps, ≤50 prefixes/run, 200-alert history ring). It alerts on TRANSITIONS and RESOLVES when a class clears, with a stable dedup key and a cool-down (suppressed alerts are counted, never lost). Two emissions per transition: (a) a notification through the existing `notify.Dispatcher` channels, and (b) a generic evidence event on `netops.bgp` in the exact envelope `internal/secbus` emits and `signals.evidence_signal_from_event` consumes — kinds `bgp_rpki_invalid`, `bgp_visibility_loss`, `bgp_origin_change`, `bgp_transit_change`, `bgp_bogon_seen`, `bgp_peer_down`; entity = the prefix (`EntityType.PREFIX`) or, for a peer-down, the device; tenant-keyed. Policy (expected origins, upstream set, thresholds) is PG FORCE-RLS (migration 0041) with a FileStore fallback. Routes: `GET /api/bgp/alerts`, `GET/PUT /api/bgp/alerts/config`. `netops_bgpwatch_*` metrics. | **GROUNDED (2026-09-02).** All three engine-side steps are done and the lane is live end to end. (a) One `EVIDENCE_CLASSES` row registers the `bgp` class on `netops.bgp` — six kinds, `Source.BGP`, `ModalityClass.CONTROL_PLANE` (deliberately the EXISTING plane: bgpwatch reads the routing control plane and shares its blind spot, so a collector view and the device's own BGP syslog cannot 'confirm' each other), `EntityType.PREFIX` by default with peer-down grounding on the device, witness `bgp:bgp-watch` (`ObserverType.PLATFORM`, never the device under question). All six map to `CausalLayer.NETWORK`. (b) `netops.bgp` joins the default `CORR_EVIDENCE_TOPICS` derivation as an OPTIONAL lane — absent or ungranted it is dropped-and-re-probed, never a startup gate. (c) The correlation principal holds Read+Describe (`kafka/apply-acls.sh`, 15 topics); the produce side needs no grant — bgpwatch writes through the Vector bus bridge under the aggregator's prefixed `netops.` ACL. Tests: `test_bgp_grounding.py` (envelope→Signal per kind, uuid5 idempotence, malformed→dead-letter, §10a cap, removability, the absent-lane drop/re-probe, tenant isolation) + `tests/test_security_lane.py` (compose + ACL contract). **No catalog template was authored**, so `catalog_version` and the `FIXTURE_GOLDEN` replay pin did not move; the six kinds are declared `coverage.INTENTIONAL_BLIND` (they ground and corroborate, no signature requires one) until a BGP story family is written as its own change with its own re-freeze proof. **Still owed:** the ClickHouse enum trio — `source` `Enum8` must gain `'bgp'=15` in `deployment/docker/clickhouse/init.sql` AND `src/backend/internal/chschema/corr_schema.go` (`TestCorrSignalEnumsConsistent`, correlation-data-contract.md §6.5). Until then a bgp signal grounds, scores and reaches a verdict in process but cannot be PERSISTED; the gap is pinned by a strict-xfail in `test_bgp_grounding.py`. |
| 11 | Route Views | ❌ | Not integrated (RIPEstat is RIS-only). | RouteViews MRT archives (RIB + updates) parsed with the BGP UPDATE parser already in `internal/bmp`; second vantage set beside RIS. |
| 12 | RIPEstat | ✅ | Data spine: `routing-status`, `bgp-state`, `looking-glass`, `bgp-updates`, `rpki-validation`, `whois`, `announced-prefixes`, plus RDAP ownership. | — |
| 13 | RPKI | ✅ | Per-prefix validation with fetched-at; unknown status can never render as valid. | — |
| 14 | ASPA | 🟡 | Honest "no ASPA source configured" card + pluggable `BGP_ASPA_PROVIDER_URL`. No public per-ASN ASPA API exists (verified). | Wire a provider when one exists (or a local rpki-client dump). |
| 15 | Geofeed (RFC 8805/9092) | ✅ | Discovery from whois, conservative CSV parse, cached. | — |
| 16 | Near-live BGP feed | ✅ | Per-tenant 2000-entry ring over a bounded RIPEstat poller (`FEATURE_BGP_LIVE_FEED`). RIS Live (WebSocket) not used: no websocket module on the §6 allowlist. | Surface BMP updates in the same panel when `FEATURE_BMP` is on. |
| 17 | BMP receiver (RFC 7854) | ✅ backend | Parser + listener + per-tenant store + 3 read routes; dormant by default. | UI (see #4). |
| 18 | AI over BGP tools | 🟡 | Iris BGP read tools being added (wave 2). | — |
| 19 | One-page outage view (research §(b)) | ✅ | **Rebuilt 2026-09-03 (owner: "put all the data into one page so that a NOC admin gets a single view during an outage without clicking so much").** The tab switcher is GONE. `src/pages/BgpOps.tsx` is one screen: a PINNED verdict bar (resource, incident class + since, announced/origin, visibility gauge, RPKI verdict, watch toggle), then a dense two-column grid — left `paths` (AS-path graph + grouped collector-path table) and `updates` (churn strip + near-live feed); right `rpki`, `incidents` (watchlist with class/evidence + alert history), `peers` (BMP + device peer state + transit), `bogons` (set in force + sightings), `ownership` (RDAP), `geofeed`, `aspa`. That is exactly the ordering of research §(b) with the 2026-09-02 panels slotted into the right column. Every section renders ON LOAD — nothing is behind a tab — and the page auto-opens on the WORST-classified watched resource (`pickInitial`, worst-first, `unknown` ranked above `none`); the watchlist stays the selector (chips + the free-form lookup) and picking one drives every section. The panels are now section components over one shared shell (`pages/bgp/Section.tsx`: `role="region"` + a stable `data-section` id, a per-section "last updated" stamp, and `useCap`/`ShowAll` so a long list shows its first N rows with an explicit control for the rest); the graph and the feed render `bare` inside the page-owned `paths`/`updates` sections. Tenant scope, every honest state and every panel's independent failure are unchanged. Perf: a new `bgp-ops` render-budget scenario (50 watched prefixes · 500 buffered updates · 30 peers · 20 sightings) — the whole screen is **1 571 DOM nodes vs 4 727** for the old page's DEFAULT TAB ALONE, and 45 ms vs 153 ms per refresh, because the row caps replaced "render everything". Tests: `BgpOps.test.tsx` (section order, verdict content, selector drives sections, honest states, `pickInitial`) plus section-identity guards on the real panels in `panels.test.tsx` / `alertPanels.test.tsx` so the page's ordering test cannot drift onto a mock. | **Three items of research §(b) are deliberately ABSENT rather than faked, and the page footer says so:** §(b)6 the IRR consistency strip (no IRR mirror is built — row 11-adjacent; there is nothing to be consistent with), §(b)7 on-demand looking-glass verification (row 6, not built), and §(b)9 third-party corroboration (Cloudflare Radar is NC-licensed, Qrator/bgp.tools need written permission — see research §(a)). Also still missing: the visibility GAUGE and path-length HISTOGRAM from the visualization addendum (row 2), and §(b)10 the AI narrative (row 18). |

**Recommended build order for the gaps:** ~~10 (alerting) → 5 (leak/hijack
classes) → 4 (Peers tab) → 1 (bogons)~~ — **all four built (`internal/bgpwatch`
+ the Prefixes/Peers/Bogons tabs); see rows 1/4/5/10 for what is proven and what
is still engine-side.** Remaining: 9 (flow↔path map) → 3 (asymmetry) → 7 (MTR +
trace from page) → 6 (looking glasses) → 11 (Route Views) → 2 (v4/v6 polish).

---

## Storage backends and deployment shape (2026-09-03)

**The watchlist is durable on BOTH backends.** It used to be Postgres-only:
`main.go` built the store only under `platformdb.ActivePG()`, so a single-box
install with no `DATABASE_URL` answered `GET /api/bgp/watchlist` with a 503
("requires the relational store"), the RPKI-over-watchlist and near-live-feed
views had nothing to read, and the whole evaluator in row 10 could never see a
prefix — the feature was dead on exactly the deployment most people run first.

`bgpWatchStore` is now an interface with two implementations, chosen the same
way the alert-policy store (row 10) chooses its own:

| backend | store | selected when |
|---|---|---|
| Postgres | `bgpWatchPGStore` (migration `0035_bgp_watchlist.sql`, `tenant_iso` FORCE-RLS, scoped through `WithTenant`) | `platformdb.ActivePG()` |
| file | `bgpwatch.WatchFileStore` — tenant-keyed JSON via the platform KV seam (atomic temp-file + rename), `BGP_WATCHLIST_FILE`, default `/data/bgp_watchlist.json` | everything else |

It is never nil. §3a rule 4 is held by EACH implementation, not by the handler:
Postgres by RLS plus an explicit `tenant_id` predicate, the file store by its
tenant-keyed map. Neither exposes an unscoped list — the only cross-tenant read
is `List(..., cross=true)`, which the API boundary sets solely for the platform
owner's Global view (the mirror of the `app.tenant_id = '*'` RLS scope) — and
both refuse `""` and `"*"` on every write. A resource another tenant watches is
a 404, not a deletion. The cross-backend contract is asserted by one table in
`bgp_watchlist_isolation_test.go` that runs against every implementation the
environment can construct (Postgres joins when `DATABASE_URL_TEST` is set).

The file backend caps one tenant at `MaxWatchEntriesPerTenant` (500) — the
evaluator makes one bounded outbound measurement per watched prefix per pass, so
an unbounded list is an unbounded work queue. A corrupt file starts EMPTY and
says so in the log; it is never silently treated as "nothing watched".

**Feature flags are now actually passed to the api.** `docker-compose.yml`
carried only a COMMENT naming `FEATURE_BGP_LIVE_FEED` / `FEATURE_BGP_ALERTS` /
`FEATURE_BGP_BOGON_FEED`, so no `.env` value could enable any of them. All three
are passthroughs (default `false`), templated commented-out by `install.py`,
reconciled by `update.sh`, and guarded by
`tests/test_compose_new_modules.py::test_bgp_feature_flags_are_fully_plumbed_to_the_api`,
which reads the packages' own `Env*` constants so a renamed flag cannot go
un-plumbed.

**Bogon sightings are registered on arrival, not on the tick.** `NoteSighting`
had no callers: sightings reached `/api/bgp/bogons` only through the evaluator's
sweep, and that sweep sat AFTER two per-tenant reads that both return on error —
so on a stack whose watchlist read failed it never ran once (observed live:
real BMP bytes for a bogon prefix in the store, "bogons seen" empty). Two fixes:
the sweep now runs first and unconditionally (it depends on neither the policy
nor the watchlist), and both live sources push directly —
`internal/bmp` reports announced prefixes tenant-stamped through
`Applied.Announced` → `Deps.OnAnnounce`, and `internal/bgpdepth` reports each
poll's new ring entries through `Options.OnUpdates`. Both paths write the same
`(prefix, source, peer)` key the sweep writes, so an update seen twice is ONE
sighting with a bumped count, and neither path is load-bearing for the other.
