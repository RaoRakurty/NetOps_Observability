# Correlix — Terminology / IP Audit (BRAND-1)

**Date:** 2026-06-29 · **Status:** owner approved → recommendations APPLIED (UI strings only; route ids unchanged).

## ✅ Applied 2026-06-29 (user-facing display strings; route ids/components/CSS unchanged)

| Was | Now | Where |
|---|---|---|
| Log Explorer | **Log Search** | nav (Metrics → Logs) |
| Metrics Explorer | **Metric Workbench** | Metrics tab heading |
| App Observability | **Service View** | nav (Event Management) — chose this over "Application Insight" because that itself collides with **Azure Application Insights** |
| Topology Canvas | **Topology Map** | nav (Infrastructure → Maps) |
| Fleet pulse & reachability | **Fleet vitals & reachability** | Device Monitoring panel |

**Deferred (need careful per-occurrence review — broad/internal, low demo benefit):**
- **Watchdog** (`scripts/stack-watchdog`) — internal cron script, no UI surface; rename optional (→ Stack Sentinel) when convenient.
- **"Canvas"** (125 code refs) / **"Pulse"** (20) / **"Fleet"** as a noun — blanket renames risk breaking component/class names; left for a deliberate pass.
- **Time Intelligence** — already not user-facing (only code comments); UI already says "Incident Time Decomposition".

---

**Original proposal (for reference):**

Goal: make sure Correlix's product vocabulary isn't (a) a trademarked feature
name of another observability/network vendor, or (b) so strongly associated with
one vendor that we read as a clone. Generic technical terms (BGP, Flows, Devices,
Syslog, Latency, Topology) are **not** flagged — they're industry-standard and
safe. This audits the *coined / marketing* terms only.

Severity:
- 🔴 **High** — exact match with a named/trademarked vendor feature; rename advised.
- 🟠 **Medium** — strong single-vendor association or partial match; consider rename.
- 🟡 **Low** — common/descriptive; defensible, but a more distinctive term would help us stand out.
- 🟢 **Clear** — distinctive to us / safe.

---

## 🔴 High — exact matches with named vendor features

| Term (where) | Collides with | Why it matters | Proposed replacements |
|---|---|---|---|
| **Log Explorer** (`nav`: Logs) | **Datadog "Log Explorer"** + **Google Cloud "Logs Explorer"** — both exact, both flagship | Reads as a direct lift of Datadog/GCP's log UI | **Log Search**, **Log Lens**, **Signal Log**, **Log Workbench**, **LogScope** |
| **Metrics Explorer** (Metrics tab) | **Datadog "Metric Explorer"** (exact, trademarked feature) | Same | **Metric Workbench**, **Metric Lens**, **Signal Metrics**, **Metric Studio** |
| **Watchdog** (`scripts/stack-watchdog`) | **Datadog "Watchdog"** — trademarked AI anomaly feature | Internal-only today (cron script), but if it ever surfaces in UI it's a clear conflict | **Sentinel**, **Heartbeat Monitor**, **Stack Sentry**, **Keepalive** |
| **Time Intelligence** (#84 RCA time decomposition) | **Microsoft Power BI "Time Intelligence"** (named DAX function family) | Strong Microsoft association; we mean something different (incident phase timing) | **Incident Time Decomposition**, **Time-to-Restore Breakdown**, **Phase Timing**, **MTTR Anatomy** |

## 🟠 Medium — strong single-vendor association

| Term (where) | Collides with | Notes | Proposed replacements |
|---|---|---|---|
| **Fleet Pulse** / **Pulse** (dashboards) | **Pulse Secure / Ivanti Pulse** (VPN/security brand); "Pulse" also AWS/others | "Pulse" is a recognized security brand; combined with our network/security scope it's muddy | **Fleet Vitals**, **Fleet Signal**, **Fleet Live**, **Heartbeat**, **Fleet Cadence** |
| **Fleet** (Fleet Pulse, fleet cockpit, Fleet aggregates) | **FleetDM ("Fleet")** — open-source device/osquery management | "Fleet" = a known device-management product; we use it loosely for "all devices" | Keep **Fleet** as a generic noun (defensible) **but** drop compound product-names like "Fleet Pulse"; prefer **Estate**, **Inventory**, **Network Estate** for the noun |
| **(Operating / Topology) Canvas** (topology) | **Kibana "Canvas"** + **Grafana "Canvas" panel** — both named features | "Canvas" is an established Elastic/Grafana feature name | **Topology Map**, **Operating Map**, **Network Canvas → Network Map**, **Operations Board**, **Live Map** |
| **App Observability** (nav) | Datadog / Dynatrace **"Application Observability"** category | Descriptive category, not trademarked, but reads as their wording | **Application Insight**, **Service View**, **App Signals**, **Application Health** |

## 🟡 Low — common/descriptive (defensible; distinctiveness optional)

| Term | Note | Optional distinctive alt |
|---|---|---|
| **Command Center** | Widely used generically (SolarWinds, others); not owned, but not distinctive | **Operations Cockpit**, **Mission Deck**, **NOC Command** |
| **Action Queue** | Generic; fine | **Work Queue**, **Triage Queue** |
| **Recovery Scorecard** | "Scorecard" is common (Microsoft, others) but the pairing is distinctive | keep, or **Restore Scorecard**, **Resilience Scorecard** |
| **Threat Detection / Vulnerability Management** | Industry-standard category names; safe | keep |
| **Source of Truth** | Industry-standard (NetBox community); safe | keep |
| **Incident Response** | Industry-standard (PagerDuty etc.); safe | keep |

## 🟢 Clear — distinctive to Correlix (keep)

- **Correlix** / **Correlix AI** — the brand (assumed cleared by owner).
- **Evidence** / **Evidence engine** — our anti-black-box RCA concept; distinctive in this framing.
- **Witness** / **Blast radius** — "blast radius" is common in SRE but our *Witness* lane + evidence framing is ours; fine.
- **RCA Auto-Ticketing**, **Path Health**, **Link Quality**, **Attribution** — descriptive, safe.

---

## Recommendation (for owner)

1. **Rename the 🔴 High four first** — they're the ones a Datadog/Power-BI-literate
   buyer will recognize instantly. Lowest-risk, highest-credibility win:
   - Log Explorer → **Log Search** (or Log Lens)
   - Metrics Explorer → **Metric Workbench** (or Metric Lens)
   - Watchdog (internal) → **Stack Sentinel**
   - Time Intelligence → **Incident Time Decomposition** (already the feature's real name in the tracker)
2. **Then the 🟠 Medium set** — drop the "Pulse" and "Canvas" product-names; keep
   "Fleet" only as a generic noun (or move to "Estate").
3. **Leave 🟡/🟢** unless we want extra distinctiveness.

> No code changes made. On your pick of replacements I'll do the renames as a
> single isolated pass (UI strings + nav labels + any *_LABEL maps), keeping route
> ids stable so deep links don't break. — agent

**Caveat:** vendor feature names change; treat 🔴/🟠 as "verify before launch" —
a quick trademark search on the finalists is worth doing before print/marketing.
