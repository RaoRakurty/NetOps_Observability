# Correlix tiering plan — what is free, what is licensed (draft for owner decision, 2026-09-03)

**Owner ask:** "Which items of the whole solution should be free tier, and licensed
tiers. Come up with a plan." Cut lines decided by the owner on 2026-09-04 (Community: 25
devices, 5 watched prefixes; security findings in Team; dialects + SIEM export in
Enterprise). Licensing model: **Apache-2.0 open core + source-available commercial
add-ons** — see `LICENSING.md`. It follows the pricing model already on record: **price per device,
retention as the upsell, burst is an SLO not a billing event**, and security as a
per-tenant paid service (see the capacity-and-pricing memo and the VulnHunter note).

## 1. Principles
1. **The free tier must be genuinely useful to one network engineer with one site** — it is
   the funnel, not a demo. It runs the real engine on real telemetry; nothing in it is a
   crippled fake.
2. **Charge for what costs us or saves them money at scale:** devices, retention, tenants,
   the security evidence class, the BGP internet-facing intelligence, and the AI narrator's
   provider spend. Never charge for honesty features (coverage cards, "not collected"
   states, isolation) — those are the product's character in every tier.
3. **Enforce by data, not by hiding code.** One binary, one image set; tiers are a signed
   licence file that sets device/tenant/retention/feature ceilings, checked at the same
   gates that already enforce tenant isolation. Over-limit degrades honestly ("licence
   ceiling reached: N devices not monitored — list"), never silently.
4. **Open-source obligations stay clean** (licence audit in flight): the free tier ships the
   same third-party components as paid tiers, so obligations do not change by tier.

## 2. Proposed tiers

| Capability (as built today) | Community (free) | Team | Enterprise | Notes |
|---|---|---|---|---|
| Discovery + multi-protocol telemetry (SNMP, gNMI, syslog, traps, flows, probes) | ✅ discovery unlimited; up to **25 MONITORED devices** (owner ✅ 2026-09-04; unit resolved 2026-09-05) | up to 250 monitored | unlimited per licence | **the MONITORED device is the priced unit, not the inventory row** (owner C4, 2026-09-05): a device consumes one entitlement when at least one monitoring/collector configuration is enabled for it. Discovery finds 500 → 500 inventory rows → enable 12 → 12/25. Several telemetry methods on one device = one entitlement; unreachability does not release it. Implemented in `internal/devmon` (the definition), `internal/discovery` (the state + the ceiling, under one lock) |
| Correlation engine + RCA (verdicts, causality path, seams, evidence classes) | ✅ full engine | ✅ | ✅ | never tiered — it is the product |
| Retention (logs/flows/metrics/findings) | 7 days | 30 days | 90 days + archive | the upsell axis on record |
| Tenants / organisations | 1 tenant | 1 org, 5 tenants | unlimited, org hierarchy | MSP/design-partner cut |
| Investigation surface + protocol diagnostics (catalog, analyze, TAC bundle) | ✅ | ✅ | ✅ | keep free: it is how engineers fall in love |
| Live SSH collect / state battery / config capture | ✅ read-only, on the 25 monitored devices | ✅ | ✅ | same device ceiling; the config sweep and the security lane read the MONITORED set |
| Iris co-pilot: skills, chaining, memory, evidence-only answers | ✅ evidence-only (no provider) | ✅ + BYO provider key | ✅ + hosted provider quota | provider spend is the cost driver |
| Owner-doc ingestion (skills from customer runbooks) | — | ✅ 10 skills | ✅ unlimited + services | services attach here |
| IGP depth, VRF views, interface intelligence | ✅ | ✅ | ✅ | monitoring depth stays free |
| BGP operations: looking glass (RIS), RPKI, AS-path graph, geofeed | ✅ | ✅ | ✅ | public data; keep free |
| BGP watchlist + alerting (leak/hijack/visibility/bogon classes), near-live feed, BMP receiver | 5 watched prefixes, evaluator on (owner ✅ 2026-09-04) | 100 prefixes + BMP | unlimited + Route Views/LG queries when built | internet-intelligence tier line |
| Security CTEM: findings lane, exposures, hardening dialects, compliance frameworks, config drift, packet capture, threat detection, advisory | Hardening + exposure for the device ceiling, 800-53 + CIS v8 only | + HIPAA/PCI/CSF frameworks, drift, pcap, threat lane, advisory feed | + all frameworks, multi-vendor dialects, findings export to SIEM, retention 90d | owner ✅ 2026-09-04: **findings in Team; dialects + SIEM export in Enterprise** |
| Alerting delivery (ntfy/Slack/Teams/SNS/webhook), host-monitoring page | ✅ ntfy + webhook | ✅ all channels | ✅ + digest/escalation policies | |
| Reports, scheduled exports, PDF | — | ✅ | ✅ | |
| SSO (OIDC/SAML), LDAP, session policies | local users + OIDC | + LDAP | + SAML, SCIM when built | |
| API keys with administrative scopes, GraphQL explorer | read keys | + write | + admin | tracker 226 gap must close first |
| Support / SLA | community | business hours | 24×7 + named engineer | |

## 3. What must be built to enforce it (small, because the gates exist)
- **Licence file**: signed JSON (ed25519, stdlib) with tier, ceilings, expiry, customer id;
  loaded at boot; a platform-admin page shows it; grace period + honest degradation.
- **Ceilings at existing chokepoints**: monitored-device count at the monitoring transition
  (`PUT /api/devices/{id}/monitoring`, `POST /api/devices`, and a source reporting a device
  that would default to monitored) — never at discovery admission, which is free, tenant count at `POST /api/tenants`, retention in the ISM/TTL
  bootstraps (values already env-driven), frameworks in the per-tenant enablement API
  (being built), watched prefixes in the watchlist store, provider quota in the copilot
  budget (already bounded per day).
- **Metering** for the per-device price: a daily count per tenant, exported as a metric
  and a signed usage report (no phone-home unless the customer opts in).
- **Free-tier install path**: the same installer with `--tier community` producing a
  licence-less run at community ceilings, so trials need no key.

## 4. Sequencing
Not before the ship-readiness items (release, licence audit, docs). Then: licence file +
ceilings (1 wave), metering + admin page (1 wave), tier docs + pricing page copy. The
cut lines above are the owner's call; everything else in this doc is executable as is.

## 9. Commercial strategy of record (owner feedback, 2026-09-05) — supersedes §§2–4 where they differ
Source: `docs/design/research/LICENSING_TIERING_STRATEGY_2026-09-05.md` (owner-supplied; market
anchors: Datadog NDM $7/device, SolarWinds self-hosted $8/node, LogicMonitor HU $16, New Relic /
Grafana perpetual free tiers). Decisions:

| Topic | Decision |
|---|---|
| Runtime tiers | Community / Team / Enterprise ONLY in code, plus an **Enterprise MSP contract profile** on the Enterprise entitlement (pooled monitored devices across tenants). No Starter/Pro/Business tiers. |
| Unit | **Monitored device** (C4, landed 1feb8fad): a canonical device with ≥1 qualifying collector intentionally enabled; counted once whatever the telemetry mix; discovery/inventory never consume; configured intent, not recent telemetry. Supersedes "enforced at discovery admission". |
| Community | $0 forever, no expiry, no phone-home, 25 monitored devices, unlimited discovery, 1 tenant, 7-day retention, 5 watched prefixes; full discovery/topology/correlation/RCA/diagnostics; **processors and redaction free**; OIDC; evidence-only Iris. Hard block at the 26th activation (published free ceiling). |
| Team | 250 devices, 1 org / 5 tenants, 30 days, 100 prefixes; findings, frameworks, drift, pcap, reports, all notification channels, shared investigations, BMP, threat/advisory lane, BYO AI, limited owner-doc skills. **Soft overage + alerts (80/90/100 %)**, never a kill switch during an incident. |
| Enterprise | contracted capacity, org hierarchy, 90 days + archive, unlimited prefixes; dialects, SIEM export, SAML/SCIM/LDAP, hosted AI quota, governance/export, session policy, archival/restorability, 24×7. Soft overage as Team. |
| Enterprise MSP | pooled monitored devices, many tenants, fleet console, delegated admin, pooled entitlement, customer reports, provider API, optional branding. Tenant count = broad plan ceiling, never a per-tenant tax. Tenant ISOLATION is never an MSP feature. |
| Never gated | discovery, topology, correlation/RCA, coverage/"not collected" honesty, **all processors** (filter/redact/mask/transform/route/sample), sensitive-data protection (encryption, isolation, RLS, authz, deletion, transport), OIDC. Premium data-protection = governance workflows only (audited reveal, CMK, legal hold, classification policy, approval workflows, compliance reporting). |
| Retention | keep 7/30/90 for launch; TEST in interviews; fallback on-prem monetization = retention lifecycle/archive/restore drills/legal hold. |
| SAML | stays Enterprise for launch; record `lost_due_to_saml_gate` in win/loss; move to Team if it costs deals. |
| Pricing (hypotheses, order-form only — NEVER in the licence file) | Team $4–6 / monitored device / month annual, preferably **starter pack $249/mo incl. 50 devices then ~$4/device to 250**; Enterprise $6–9/device-equivalent, $18k–30k ARR floor, volume discounts; MSP $3–6 pooled, $24k+ floor (e.g. 500 pooled devices, 25–50 tenants). Design partners: 12-month price protection, 30–40 % expiring launch discount, never a permanently low list. |
| Paid expiry / grace (adopted) | paid: 30-day administrative grace; trials: shorter; after grace, paid-only creation/configuration actions become unavailable, existing data stays viewable/exportable, over-ceiling state is listed; **never delete data or weaken a security property; never silently pick which devices disappear**. |
| Trials | 30-day signed Team/Enterprise evaluation licence, no card, offline after issuance; Community and trial coexist. |
| Metering (separate from entitlement) | daily per-tenant: unique + peak monitored devices, tenants/orgs, watched prefixes, effective retention; diagnostic meters for samples/log/flow/trace bytes, DEM checks, AI tokens, processor in/out ratio; **signed downloadable usage report**, no phone-home; customer and Correlix derive the same counts. |
| SaaS (future) | device entitlement + included telemetry envelope + narrow overage (logs, flows, DEM, hosted AI), metered on **post-processor accepted** data; region as a first-class tenant property before production; migration: $0 transfer, 100 % unused-term credit, free config migration, one 60–90-day dual run, optional history. |
| DEM (decided 2026-09-05) | **No `FeatureDEM` gate.** Advanced DEM stays on the monetizable roadmap; network-side DEM rides the monitored-device unit; DEM sessions/journeys/checks are a diagnostic meter on-prem and a possible narrow SaaS overage meter later; no RUM unit at launch. |
| Onboarding message | "Inventory: N discovered · Monitoring: M / 25 Community monitored devices · Discovery does not consume your monitoring allowance." Measure time-to-first-useful-RCA. |

Implementation workstreams from this decision are tracker rows 257–260 (grace/expiry + trial issuance +
usage warnings; metering + signed usage report; production signing-key ceremony; pricing/GTM copy). Legal
boundary (counsel-approved commercial licence + CLA) remains the owner's, never drafted here.
