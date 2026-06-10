# Build order — follow-along checklist

I build top-to-bottom, **one item at a time**, committing each so you can follow.
Status: ⬜ todo · �doing · ✅ done. Telemetry/IPFIX-first; onboarding before
placeholders so a "no-telemetry-yet" enterprise isn't staring at blank boards.

## A. Onboarding / robustness (boards must guide a from-zero customer)
1. ✅ **Onboarding-aware empty states** — replace generic "No data" across the
   board framework with guided hints ("enable SNMP", "point NetFlow here",
   "forward syslog") + link to onboarding. So empty ≠ broken.
2. ✅ **Data Source Coverage view** — per device, which collection methods are
   live & fresh (SNMP · flow · syslog · trap · gNMI). New Infrastructure leaf.

## B. No-new-collection wires (data already in the stores)
3. ✅ **Device Health** (Flows board) — real interface health from SNMP counters.
4. ✅ **Traffic insights** (Device Monitoring) — flow tiles (top talkers/exporters).
5. ✅ **Per-interface flows** (Interface Performance) — flows by in_if/out_if.
6. ✅ **IPsec VPN tunnels** (Device Monitoring) — wired: live `TunnelOverlay`
   section (StatStrip + heat-tinted DataTable from `/api/tunnels`) replaces the
   stub; `ENABLE_TUNNEL_DISCOVERY` now wired in compose (default on) so the
   IF-MIB/TUNNEL-MIB collector actually runs; mock seed rows purged from
   `netops.tunnels`; onboarding-aware `tunnels` empty-state kind added.

## C. IPFIX / pipeline builds (touch ingest + schema)
7. ✅ **TCP Flags** — `tcp_flags UInt16` column (init.sql + self-healing ALTER in
   `ensureCHRowPolicies` so live deployments converge), vector-router int
   coercion, `/api/flows/flags` (combos by flows, proto=6, tenant/filter-aware),
   Flows "Flags" section: combo bar/table + SYN-only/RST heuristics computed
   over flag-bearing flows, honest note when exporters don't fill
   tcpControlBits (the lab's v9 exporters don't — verified in goflow2 JSON).
8. ✅ **Geo IP** — query-time enrichment via a ClickHouse `ip_trie` dictionary
   (`netops.geoip_country`, lazy, hot-reloads on file mtime) over an
   operator-supplied CSV — licensing forbids bundling GeoIP data, so
   `scripts/geoip-prepare.py` (stdlib) converts a GeoLite2-Country zip or
   DB-IP Lite CSV into `data/clickhouse/user_files/geoip/country.csv`.
   Chosen over Vector-ingest mmdb so the stack runs without the file,
   enrichment applies retroactively to stored flows, and no pipeline restart
   is needed. `/api/flows/geo?dim=src|dst` (probe → `geo_enabled:false` +
   onboarding UI when unprovisioned); Flows Geo section: initiator/responder
   country panels (browser-native names+flags via Intl.DisplayNames),
   public-traffic-share stat, honest private-only note. Device Geomap stays
   stubbed — lab devices are RFC 1918, so a geomap needs site metadata from
   inventory, not GeoIP (revisit with #14/NetBox intent data).

## D. Composition / UI
9. ✅ **New Monitor** — guided wizard (`pages/NewMonitor.tsx`): template gallery
   (12 signals across Availability/Resources/Interfaces/Routing/Path-SLA, all
   backed by collected metrics, + Custom PromQL) → condition (device-regex
   scope, threshold, hold-for, severity) → review with **live instant-query
   preview** ("would fire on N series right now"). Three engine-correctness
   fixes shipped with it: (a) `Rule.For` JSON was decoded as *nanoseconds* —
   now pinned to seconds-or-duration-string both directions; (b) `for` was
   never enforced — Prometheus-style pending→firing gating added (condition
   must hold continuously; flap resets the clock; tick-grained); (c) API-created
   rules vanished on restart — now kv-persisted (`rules_user.go`, PG/file via
   the store backend) and re-fed at boot, with validation (name/severity/size
   caps, 409 on dup), `DELETE /api/rules?name=` for `origin=ui` rules only,
   and source badges + delete in the Monitors table. Engine got `evalFn`/`now`
   test seams + unit tests (for-gating, flap reset, JSON round-trip, remove).
10. ⬜ **Dashboard List** — curate the named dashboards as links to the real
    boards (Device Metrics→Device Monitoring, Interface Metrics→Interface
    Performance, BGP Metrics→BGP/OSPF, …) + Bandwidth / WAN-circuit.
11. ⬜ **Command Center** (Incident Response) — incidents + notify + chat.

## E. New collector / external feeds (heaviest, last)
12. ✅ **Active-probe pipeline** — STAMP sender+reflector (RFC 8762) + Paris traceroute (ICMP/TCP) + Network Path UI. Flow Trace & Path/synthetics stubs now real. — Flow Trace / Network Path + ICMP/HTTP
    synthetics (new probe runner). Fills Flow Trace + Path & synthetics stubs.
13. ⬜ **Vulnerability Management** — device OS (SNMP sysDescr) × CVE/PSIRT feed.
14. ⬜ **Compliance Monitoring** — config baselines vs NetBox intent.

---
Already shipped this run (context): BGP/OSPF Overview + collection, Troubleshooting,
Threat Detection (IPFIX), Events, Quality. See [[placeholder-buildout]] +
[[device-monitoring-dashboards]].
