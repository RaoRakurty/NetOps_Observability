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
