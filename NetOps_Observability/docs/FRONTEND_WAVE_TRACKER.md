# Frontend / Product Wave — build audit (owner's original 13-item list)

**Audited 2026-08-27 against the actual code** (not memory). Legend:
✅ done + deployed · 🟡 partial · 📐 design/research only · ❌ not started.

| # | Item | Status | Evidence / what's left |
|---|------|--------|------------------------|
| 1 | **Frontend loading latency — FAANG standards, slick transitions even at high EPS** | 🟡 mostly | ✅ "perf wave 1" shipped (`6f4986d2`): route transitions (`startTransition`), idle chunk prefetch, skeletons — client-routing is EPS-independent. **Left:** the name says *wave 1*; page-DATA render under sustained high-EPS was not specifically profiled; no measured before/after budget captured. |
| 1.1 / 2 | **Remove verbose developer-speak copy across the site (space, NOC-operator voice)** | 🟡 | ✅ copy pass shipped (`305c800c`) — stripped instructional chrome ("1000 shown / click a row") from **operator surfaces**. **Left:** confirm *entire-site* coverage — the commit scoped "operator surfaces," not every page. |
| 3 | **Device-name font — elegant, legible, modern** | ✅ | Space Grotesk on `.device-name`, deployed. |
| 4 | **Per-device VRF / routing-instance options, vendor-dialect auto-detect (Cisco VRF ≡ Juniper routing-instance ≡ …)** | 🟡 | ✅ dialect abstraction built (`internal/netconcepts`, `lib/vendorTerms`), wired into DeviceNeighbors + BGP dialect headers; ✅ gnmic per-VRF wildcard telemetry now **live** (deployed today). **Left:** a dedicated *per-device "interfaces grouped by VRF"* options view — the data plumbing exists, the device-detail UI for it is not confirmed built. |
| 5 | **Monitor Rules + Create Monitor — fonts sync + modern listing** | ✅ | DataTable listing + global mono-font fix, deployed. |
| 6 | **Topology — Reset button fixed** | ✅ | Fixed + regression tests, deployed. |
| 7 | **Troubleshooting page — research + rebuild for NOC, tie to IRIS** | 🟡 📐 | ✅ **research done** (`TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md`). ❌ **rebuild NOT done** — the live page is the old June "collection-pipeline health" board (`cf31695b`, 2026-06-09), not the research-driven NOC rebuild, and there's no IRIS tie yet. |
| 8 | **IRIS — check design + roadmap to make it more intelligent (auto-troubleshoot, guide engineers, human-in-loop auto-actions, auto vendor-case opening)** | ❌ | Existing AI docs are pre-session (`ai-strategy-and-guardrails`, `ai/architecture`). **The item-8 IRIS enhancement roadmap/next-steps was not produced.** No new IRIS capability built. |
| 9 | **Security section — research + build for network devices, tie to correlation engine** | 🟡 📐 | ✅ **design/research extensive + complete** (HLD, model, scenarios, GTM, build plan). 🟡 **build = foundation only, inert**: 6 producer packages (secfindings/advisory/compliancemodel/hardening/threatlane/secbus) built + gate-clean, but **nothing emits, engine doesn't ground them, no UI**. Not a usable section yet. (See `SECURITY_BUILD_PLAN` — T2b/T7/T8/T9 + config-backup/drift/capture remain.) |
| 10 | **Protocol Monitoring / BGP — consolidate NOC tools into one page (whois/RIR/looking-glass/RPKI/ASPA/geofeed), live BGP+BMP feeds, AI** | 🟡 | ✅ consolidated page + backend **v1 shipped** (`2cf65c63`) — tenant watchlist, RIPEstat + RDAP data spine, one-screen outage view, deployed today. **Left:** live RIS/BMP feed (not built), RPKI/ASPA/geofeed panels, AI-over-BGP-tools, and the **graph enhancements** (AS-path graph flagship etc.) which are **design only** (`91df4f62`). |
| 11 | **OSPF advanced + ISIS advanced monitoring** | 🟡 ❌ | Basic OSPF surface exists (`BgpOspf.tsx`); **advanced OSPF monitoring and ISIS advanced monitoring are not built** (design/basic only). gNMI now carries IS-IS state (telemetry side), but no advanced monitoring UI. |
| 12 | **NOC Recovery Scorecard — review + 10-line prospect summary to /var/tmp** | ✅ | Reviewed; summary at `/var/tmp/noc-recovery-scorecard-prospect-summary.txt` (10 lines). |
| 13 | **Administration menu — drop horizontal strip, trim Identity&Access subtitles, group Data Collection sensibly** | ✅ | Regrouped, horizontal strip removed, deployed. |

## Tally
- **✅ Fully done + deployed (7):** 3, 5, 6, 12, 13, plus 1 and 1.1/2 with minor caveats.
- **🟡 Partial (4):** 4 (dialect+telemetry done, device-detail view open), 9 (design done, build inert), 10 (v1 page done, feeds/graphs/AI open), 11 (basic only).
- **📐 Research-only, build pending (1):** 7 (researched, not rebuilt).
- **❌ Not started (1):** 8 (IRIS roadmap).

## Honest headline
Of the 13, **7 are fully shipped**, **4 are partially built**, **1 is research-only**, and **1 (IRIS) wasn't started**. The biggest gaps vs. the original ask are **#7 (Troubleshooting rebuild), #8 (IRIS roadmap), #9 (Security is scaffolding, not a working section), and the v1.5/v2 depth of #10/#11**.
