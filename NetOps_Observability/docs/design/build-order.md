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
6. ⬜ **IPsec VPN tunnels** (Device Monitoring) — wire /api/tunnels.

## C. IPFIX / pipeline builds (touch ingest + schema)
7. ⬜ **TCP Flags** — goflow2 `tcpControlBits` → `netops.flows.tcp_flags` column
   → flags endpoint → Flows panel.
8. ⬜ **Geo IP** — GeoLite2 enrichment → Flows Geo IP + Device Geomap.

## D. Composition / UI
9. ⬜ **New Monitor** — guided monitor creation over the rules engine.
10. ⬜ **Dashboard List** — curate the named dashboards as links to the real
    boards (Device Metrics→Device Monitoring, Interface Metrics→Interface
    Performance, BGP Metrics→BGP/OSPF, …) + Bandwidth / WAN-circuit.
11. ⬜ **Command Center** (Incident Response) — incidents + notify + chat.

## E. New collector / external feeds (heaviest, last)
12. ⬜ **Active-probe pipeline** — Flow Trace / Network Path + ICMP/HTTP
    synthetics (new probe runner). Fills Flow Trace + Path & synthetics stubs.
13. ⬜ **Vulnerability Management** — device OS (SNMP sysDescr) × CVE/PSIRT feed.
14. ⬜ **Compliance Monitoring** — config baselines vs NetBox intent.

---
Already shipped this run (context): BGP/OSPF Overview + collection, Troubleshooting,
Threat Detection (IPFIX), Events, Quality. See [[placeholder-buildout]] +
[[device-monitoring-dashboards]].
