package backend

// route_isolation_test.go — the isolation COVERAGE GUARD (CLAUDE.md §3a).
//
// It extracts every /api/* route registered in main.go and fails if any route is
// not classified in routeIsolationLedger below. A new data endpoint therefore
// cannot ship unclassified — the author MUST consciously declare how it is
// isolated (and, for tenant-scoped data, back it with an isolation test). This is
// the structural backstop that would have caught the unscoped sites endpoint on
// day one.
//
// Categories (the declared isolation posture of each route):
//   scoped      — per-tenant DATA: must filter by principalTenant(claims); a
//                 cross-org isolation test is expected (org_isolation_test.go).
//   adminScoped — identity/admin data scoped to the caller's tenant/org by the
//                 handler (users, tenants, orgs, bindings, audit, policy).
//   platform    — platform-GLOBAL plumbing, platform-owner only
//                 (requirePlatformAdmin / requireCrossTenant / isPlatformOwner).
//   globalRef   — platform-wide reference data, readable by admins, mutated only
//                 by the platform owner (roles, snmp profiles, region catalog).
//   infra       — stack-wide infrastructure monitoring, intentionally global,
//                 platform/cross gated (collectors, stack health, probe paths).
//   selfScoped  — the caller's OWN identity only (me, mfa, scopes, permissions).
//   token       — capability-link / token-authenticated, not principal-scoped
//                 (export links, report view, inbound webhooks).
//   public      — unauthenticated or pure auth-flow; returns no tenant data.
//
// To add a route: add it here with the right category. If it returns tenant data,
// use `scoped` and add/extend a cross-org isolation test.

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

var routeIsolationLedger = map[string]string{
	// ── per-tenant data (scoped) ──
	// Iris AI: /ask is tenant DATA — the orchestrator reads only via the
	// tenant-scoped aiDataSource (corr_objects/flows/findings row policies; scope
	// from chTenantScope), proven by ai/orchestrator_test.go cross-tenant tests.
	// /modules lists the caller's enabled modules (tenant config).
	"/api/ai/ask":     "scoped",
	"/api/ai/modules": "scoped",
	// Per-tenant AI settings (P4a): the record read/written is ALWAYS the
	// caller's own tenant (principalTenant, §3a.2 — tenant never taken from the
	// request); the BYO key is write-only and sealed under the tenant DEK.
	// Cross-tenant isolation proven by ai_tenant_config_test.go.
	"/api/ai/tenant-config": "scoped",
	// Static, identical-for-everyone reference: the slash-command registry + the
	// caller's own answer feedback (audited). No tenant data crosses these.
	"/api/ai/commands":             "selfScoped",
	"/api/ai/commands/suggestions": "selfScoped",
	"/api/ai/feedback":             "scoped", // POST own rating (tenant-stamped); GET tenant-scoped aggregate (store RLS)
	"/api/alerts":                  "scoped",
	// BGP Operations (item 10): the watchlist is per-tenant DATA (the prefixes/
	// ASNs a tenant watches), owner stamped from the RLS GUC, cross-org
	// isolation proven by TestBGPWatchlistTenantIsolationPG. The resource proxy
	// returns PUBLIC internet routing facts (RIPEstat/RDAP) identical for every
	// tenant — global reference, gated by requirePerm(infrastructure), no tenant
	// data crosses it (same shape as /api/cloud/providers, /api/snmp/profiles).
	"/api/bgp/watchlist": "scoped",
	"/api/bgp/resource":  "globalRef",
	// BMP receiver (internal/bmp) — the live BGP feed half of item 10. All
	// three are per-tenant DATA: a BMP session is one customer's router
	// pushing one customer's Adj-RIB-In, and the tenant is stamped at CONNECT
	// time from the inventory device the source address resolves to (§3a.2 —
	// never from anything the router said; an unresolvable source is refused
	// outright rather than stored under tenant ""). The store itself takes a
	// (tenant, cross) pair on every read and has NO unscoped "list all", so a
	// handler cannot forget the filter; a principal with no tenant and no
	// cross grant reads nothing. Filters (?prefix=/?peer=/?session=) NARROW
	// within that scope and can never widen it. Cross-org isolation proven by
	// bmp_deps_test.go, which exercises all three paths through the production
	// s.bmpAuthz / s.bmpResolveDevice wiring.
	"/api/bgp/bmp/sessions": "scoped",
	"/api/bgp/bmp/updates":  "scoped",
	"/api/bgp/bmp/stats":    "scoped",
	// BGP depth (item 10 completion, internal/bgpdepth).
	//   /api/bgp/rpki — with no ?resource it validates the CALLER'S OWN
	//     watchlist prefixes, read through the same FORCE-RLS store, so the
	//     answer's very CONTENTS are tenant data (which prefixes a tenant
	//     watches). scoped, isolation proven by TestBGPDepthRPKIIsWatchlistScoped.
	//   /api/bgp/feed — the near-live update ring is keyed BY TENANT and a
	//     cross-tenant principal is refused outright (a platform owner must
	//     scope in with the switcher), same shape as the watchlist write.
	//     Proven by TestBGPDepthFeedIsPerTenantAndRefusesCross.
	//   /api/bgp/aspa, /api/bgp/geofeed, /api/bgp/aspath-graph — PUBLIC internet
	//     facts about an explicitly named resource (registry ASPA, an RFC 8805
	//     geofeed, RIS collector paths), identical for every tenant and gated by
	//     requirePerm(infrastructure, read): the /api/bgp/resource category. The
	//     graph consults the caller's watchlist ONLY to MARK its own ASNs — that
	//     highlight never filters or widens the public graph, and is proven
	//     tenant-invariant by TestBGPDepthASPathGraphTenantOnlyMarks.
	"/api/bgp/rpki":         "scoped",
	"/api/bgp/feed":         "scoped",
	"/api/bgp/aspa":         "globalRef",
	"/api/bgp/geofeed":      "globalRef",
	"/api/bgp/aspath-graph": "globalRef",
	// BGP alerting + bogons (tracker #1/#5/#10, internal/bgpwatch). All three
	// are per-tenant DATA:
	//   /api/bgp/alerts        — the tenant's own alert history and the incident
	//     class per WATCHED prefix. Which prefixes a tenant watches, and what is
	//     wrong with them, is tenant information; the evaluator's state is keyed
	//     by tenant and has no unscoped read (not even an internal one).
	//   /api/bgp/alerts/config — the tenant's DECLARED intent (expected origins,
	//     upstream set, thresholds). PG FORCE-RLS (migration 0041) through
	//     WithTenant on the Postgres build, a tenant-keyed map on the file
	//     build; the owner is stamped from the token, never the body.
	//   /api/bgp/bogons        — the embedded set is public reference, but the
	//     SIGHTINGS are per-tenant observations from that tenant's own BMP feed
	//     and update ring, so the route is scoped as a whole.
	// All three refuse a cross-tenant principal outright (a platform owner must
	// scope in with the switcher) — the /api/bgp/feed precedent. Cross-org
	// isolation proven by bgp_alerts_isolation_test.go, which drives the
	// production s.bgpWatchAuthz wiring.
	"/api/bgp/alerts":        "scoped",
	"/api/bgp/alerts/config": "scoped",
	"/api/bgp/bogons":        "scoped",
	// DEM (S17) — Digital Experience. Per-tenant data end to end: the module
	// refuses a cross-tenant principal, scopes every catalogue read/write to
	// ONE concrete tenant, answers 404 for another tenant's target id, and
	// filters every experience query on the series' own `tenant` label.
	"/api/dem/targets":    "scoped",
	"/api/dem/targets/":   "scoped",
	"/api/dem/experience": "scoped",
	// The DEM causality layer (internal/dem/experience). Per-tenant data end to
	// end: the module refuses a cross-tenant principal, scopes every read and
	// write to ONE concrete tenant, answers 404 for another tenant's journey,
	// change or incident id, and derives incidents ONLY from that tenant's own
	// evidence — the derivation reads no store the scoping did not already
	// narrow. Proven by dem_experience_isolation_test.go.
	"/api/dem/overview":            "scoped",
	"/api/dem/incidents":           "scoped",
	"/api/dem/incidents/":          "scoped",
	"/api/dem/journeys":            "scoped",
	"/api/dem/journeys/":           "scoped",
	"/api/dem/synthetics/coverage": "scoped",
	"/api/dem/changes":             "scoped",
	"/api/dem/data-health":         "scoped",
	// The experience-event INGEST lane (tracker 254). Per-tenant data even
	// though it is write-only: the owner is stamped from the caller's
	// credential (demIngestAuthz refuses a credential with no concrete
	// tenant), the wire types carry no tenant field, and the decoder refuses
	// unknown fields — so a body cannot ask to be filed under another tenant.
	"/api/dem/events":          "scoped",
	"/api/dem/business-events": "scoped",
	// Protocol diagnostics (Troubleshooting item 7, protocol_diagnostics.go):
	// catalog is the version-pinned 15-issue ruleset, identical for every tenant
	// (?vendor= only picks the rendered command dialect), behind
	// requirePerm(infrastructure, read) — global reference, the /api/bgp/resource
	// shape. Analyze is the same category, not "scoped": it is a STATELESS
	// computation — it reads no store, persists nothing, and its response is
	// derived solely from the caller's own request body plus the version-pinned
	// ruleset, so it is tenant-invariant (identical input → identical output for
	// every tenant) and there is no held data for "scoped"'s isolation
	// obligations (cross-tenant id → 404, own-only list) to even apply to. The
	// token-derived tenant stamp on the built Collection is §3a.2 hygiene, and a
	// tenant in the body is REJECTED (DisallowUnknownFields) — both pinned, with
	// the tenant-invariance property, by
	// TestProtocolDiagAnalyzeTenantInvariantAndBodyTenantRejected. If analyze
	// ever starts persisting collections or resolving devices from inventory,
	// reclassify it "scoped" and give it a real cross-org isolation test.
	// Collect resolves the subject device through the principal-scoped inventory
	// (cross-tenant/unknown id → 404, existence never revealed) and stamps the
	// Collection's tenant from the RESOLVED device; cross-org isolation proven
	// by protocol_diagnostics_isolation_test.go.
	// The catalog itself is version-pinned reference data identical for every
	// tenant, but ?device= now resolves through the CALLER'S OWN inventory to
	// pick the dialect (D-5) and echoes that device's platform string — so the
	// route is tenant-scoped and carries a cross-org isolation test
	// (TestProtocolDiagCatalogDeviceCrossOrgIsolation).
	"/api/troubleshoot/protocol-diagnostics/catalog": "scoped",
	"/api/troubleshoot/protocol-diagnostics/analyze": "globalRef",
	"/api/troubleshoot/protocol-diagnostics/collect": "scoped",
	// Export is request-scoped over operator-SUPPLIED text, exactly like
	// analyze: it reads no store, resolves no device and reveals nothing the
	// caller did not send. Same classification for the same reason.
	"/api/troubleshoot/protocol-diagnostics/export": "globalRef",
	// TAC escalation pack (docs/design/TAC_ESCALATION_2026-09-05.md,
	// internal/tac). All six /tac routes are per-tenant DATA. The chain is the
	// protocol-diagnostics one: requirePerm (infrastructure read, write for the
	// two that act) → {id} resolved through the caller's OWN incident register
	// (incidents.Get(tenant, cross, id)) and/or the correlation object read at
	// chTenantScope, so a foreign id and an absent id answer the SAME 404 and
	// the subtree is not an existence oracle → the subject device resolved
	// through the principal-scoped inventory (canSeeDevice) with its tenant
	// STAMPED onto the escalation → bundles written under a TENANT-KEYED
	// directory (data/tac/<tenant>/<incident>, 0700) that has no cross-tenant
	// listing at all. Cross-org isolation proven by tac_isolation_test.go.
	"/api/incidents/{id}/tac":          "scoped",
	"/api/incidents/{id}/tac/classify": "scoped",
	"/api/incidents/{id}/tac/plan":     "scoped",
	"/api/incidents/{id}/tac/collect":  "scoped",
	"/api/incidents/{id}/tac/bundle":   "scoped",
	"/api/incidents/{id}/tac/case":     "scoped",
	// The Iris → Knowledge coverage view is version-pinned REFERENCE DATA: the
	// issue-class taxonomy and the per-dialect command plans, identical for
	// every tenant, naming no device, no incident and no tenant. It reads no
	// store. Same classification, for the same reason, as the diagnostics
	// analyze/export routes.
	"/api/troubleshoot/tac/knowledge": "globalRef",
	// TAC command templates (tracker 250). The collection and the item routes
	// are per-tenant DATA: the command sets a tenant saved. Isolation is in the
	// STORE (a tenant-keyed bucket / PG `tac_templates` with the tenant_iso
	// FORCE-RLS policy, migration 0045, queried only through WithTenant), the
	// owner is stamped from the token — the wire type has no tenant field at all
	// — and another tenant's id answers the same 404 an absent one does. A
	// cross-tenant principal must scope into one tenant before it may read or
	// write. Cross-org isolation proven by tac_templates_isolation_test.go.
	//
	// /defaults and /validate are globalRef: the defaults are GENERATED from the
	// authored plans, identical for every tenant, immutable; validate is a pure
	// computation over the caller's own text that reads and stores nothing.
	// Both are still authenticated — a command set is product knowledge — and
	// neither can return a row belonging to anyone.
	"/api/tac/templates":          "scoped",
	"/api/tac/templates/":         "scoped",
	"/api/tac/templates/defaults": "globalRef",
	"/api/tac/templates/validate": "globalRef",
	// OSPF / IS-IS advanced monitoring (Project 4 D item 11, internal/igpmon).
	// All six are per-tenant DATA and read NOTHING that is not already
	// collected. The chain is the pcap/configstore one: requirePerm
	// (infrastructure:read) → ?device= resolved through the principal-scoped
	// inventory (a foreign id and an absent id answer the SAME 404, so the
	// subtree is not an existence oracle) → the adjacency-change events read at
	// chTenantScope, which is what the tenant_iso FORCE row policies on
	// corr_signals / corr_signals_archive enforce on ("" / "__none__" reads
	// nothing) → every VictoriaMetrics read carries the caller's device
	// boundary as extra_filters[], and a SCOPED principal with no boundary is
	// refused the read rather than served the fleet. Cross-org isolation proven
	// by igpmon_deps_test.go plus internal/igpmon/http_test.go.
	"/api/protocols/ospf/adjacencies": "scoped",
	"/api/protocols/ospf/summary":     "scoped",
	"/api/protocols/ospf/health":      "scoped",
	"/api/protocols/isis/adjacencies": "scoped",
	"/api/protocols/isis/summary":     "scoped",
	"/api/protocols/isis/health":      "scoped",
	// Alert episodes (Wave 2 #6): list mirrors the /api/alerts visibility rule
	// (own tenant + device-less platform rows); triage is own-tenant-only with
	// cross-tenant ids → 404. Proven by alert_episodes_isolation_test.go.
	"/api/alerts/episodes":             "scoped",
	"/api/alerts/episodes/":            "scoped", // POST {id}/(ack|assign|mute|snooze|notes), alerts:write + tenant match
	"/api/alerts/maintenance-windows":  "scoped", // planned-work windows (item 121), alerts:read/write + tenant filter
	"/api/alerts/maintenance-windows/": "scoped", // GET|PUT|DELETE {id}, cross-tenant id → 404
	"/api/pipeline/processors":         "scoped", // per-tenant processor rules (item 121), administration:admin + tenant filter
	"/api/pipeline/processors/":        "scoped", // GET|PUT|DELETE {id} · POST preview, cross-tenant id → 404
	"/api/compliance":                  "scoped",
	// ── Security (CTEM), Project 3 P3-API ──
	// All per-tenant DATA. The findings routes read ONLY the caller's own
	// OpenSearch index pattern (oslog.TenantIndexPattern) with the per-doc
	// oslog.TenantFilter clause on top — the applogs/flows chokepoint pair — so
	// another tenant's document is unreachable even if a query filter were ever
	// dropped, and a cross-tenant id answers 404 rather than revealing that it
	// exists. The rules/views control-plane state is tenant_iso FORCE-RLS in PG
	// (migration 0037) or tenant-keyed in the file store, with the owner stamped
	// from the principal. /exposure-stories delegates to the correlations
	// surface, which reads at chTenantScope. Proven by
	// security_findings_isolation_test.go.
	"/api/security/findings":          "scoped",
	"/api/security/findings/facets":   "scoped",
	"/api/security/findings/trend":    "scoped",
	"/api/security/findings/":         "scoped", // GET {id}; cross-tenant id -> 404
	"/api/security/posture":           "scoped",
	"/api/security/exposure-stories":  "scoped",
	"/api/security/exposure-stories/": "scoped", // delegates to handleCorrelationByID (ownership pre-read)
	"/api/security/rules":             "scoped", // GET catalog + tenant state; PUT administration:write, owner from the token
	"/api/security/frameworks":        "scoped", // GET catalogue + tenant selection; PUT administration:write, owner from the token
	"/api/security/compliance":        "scoped", // per-framework scorecards over the caller's own findings
	"/api/security/views":             "scoped",
	"/api/security/views/":            "scoped", // DELETE {id}; cross-tenant id -> 404
	// P3-EMIT producer lane (internal/seclane). Both are per-tenant: the status
	// list is filtered by principalTenant (a tenant admin sees ONLY its own row;
	// the cross-tenant platform admin sees every tenant), and the manual trigger
	// enqueues a scan for the CALLER'S OWN tenant only — a cross-tenant caller is
	// refused (400) rather than allowed to scan on someone else's behalf.
	// Isolation proven by security_lane_isolation_test.go.
	"/api/security/lane/status": "scoped",
	"/api/security/scan":        "scoped",
	// Parser coverage (programme A6, parsercov/). The stats route is
	// platform-GLOBAL plumbing — engine counters for the whole fleet's parser,
	// not one tenant's rows — so it takes requirePlatformAdmin (§3a rule 3: a
	// scope-blind requireAdmin would be satisfied by a tenant admin). The two
	// /api/telemetry routes are per-tenant DATA read through
	// oslog.TenantIndexPattern + TenantFilter; the propose route drafts a
	// catalog row as TEXT and applies nothing. Isolation proven by
	// parsercov/http_test.go.
	"/api/admin/parser/stats":      "platform",
	"/api/telemetry/unrecognized":  "scoped",
	"/api/telemetry/unrecognized/": "scoped",
	"/api/correlations":            "scoped",
	// SUBRESOURCE WARNING (2026-08-04): this prefix entry covers MANY handlers,
	// and a prefix classification is NOT evidence that each one enforces tenant
	// scope. {id}/replay was classified "scoped" by this very line while
	// proxying a caller-supplied id to the (unauthenticated, __all__-reading)
	// correlation service with NO ownership check — a live cross-tenant leak.
	// Audited 2026-08-04: every OTHER subresource funnels through loadCorrSlice
	// / buildRcaReportForID, which read at chTenantScope(r) and 404 on zero rows
	// (correlations.go:578-579). {id}/replay now performs the same ownership
	// pre-read (correlations_replay_isolation_test.go pins it).
	// Adding a NEW subresource here? It must reach data through a tenant-scoped
	// loader or do its own ownership check — this line does not do it for you.
	"/api/correlations/": "scoped", // incl. {id}/time-metrics + {id}/time-events (#84) + {id}/rca-promotion (#113 point 3, rca_promotion_test) + {id}/replay (ownership pre-read, 2026-08-04): chRows(chTenantScope) reads + tenant-stamped RLS writes (store isolation test); manual writes audited; {id}/feedback (Project 2 P7 operator verdicts) resolves the object under chTenantScope FIRST (cross-tenant id -> 404) and stamps the OBJECT's owning tenant (rca_feedback_isolation_test.go)
	// Project 2 P7 operator verdict feedback. The windowed summary is per-tenant
	// DATA (a tenant's own false-positive rate): store-scoped by
	// principalTenant + tenant_iso FORCE-RLS (migration 0036) / tenant-keyed
	// file store; the per-case POST/GET ride the /api/correlations/ prefix
	// below behind a ClickHouse ownership pre-read. Proven by
	// rca_feedback_isolation_test.go.
	"/api/correlations/feedback/summary": "scoped",
	"/api/correlations/rca-reports":      "scoped", // #113 management library: chTenantScope prefilter + shared report pipeline + tenant-keyed manual-promotion union (TestRcaLibraryTenantIsolation)
	"/api/correlations/stats":            "scoped",
	"/api/correlations/summary":          "scoped", // window rollup counts: chRows(chTenantScope) over corr_current — a tenant counts only its OWN objects (correlations_summary_test.go)
	// Per-tenant display preference (a281c7a): GET/PUT always the CALLER's own
	// tenant record (principalTenant; PUT behind requireAdmin, audited) — the
	// tenant id never comes from the request (tenant_display_test.go).
	"/api/settings/display": "scoped",
	// Active Verification opt-in + read-only SSH credential (RCA spec item 8):
	// keyed by principalTenant in the store itself; PUT behind requireAdmin,
	// audited, secrets vault-sealed and never returned. Cross-tenant isolation
	// covered by verify_http_test.go (TestVerifySettingsTenantScopedAndSecretsWriteOnly,
	// TestVerifyCrossTenantIsolation).
	"/api/settings/verification": "scoped",
	// Per-tenant governance settings (Wave 4 #11): the record read/written is
	// ALWAYS the caller's own tenant (principalTenant; PUT behind requireAdmin,
	// audited) — the tenant id never comes from the request
	// (tenant_governance_test.go).
	"/api/settings/required-tags":          "scoped",
	"/api/settings/rca-window":             "scoped",
	"/api/settings/attribution-precedence": "scoped",
	"/api/settings/seam-owners":            "scoped",
	// Read-only recent-changes view over the governance settings writes:
	// requireAdmin + auditScopedList (the same scoping as /api/audit), filtered
	// to the settings actions (tenant_governance_test.go).
	"/api/settings/governance-audit":           "adminScoped",
	"/api/correlations/undetermined-frequency": "scoped", // #80: chRows(chTenantScope) over corr_current — a tenant ranks only its OWN undetermined gaps
	"/api/rca/": "scoped", // Service Path Graph §7 ordered spine: principalTenant → pathgraph.Store (tenant-keyed store / RLS+row-policy) + chTenantScope for the corr→path lookup; two-tenant isolation test = path_graph_isolation_test.go
	// RCA Time Intelligence reliability rollups (#84) — aggregate ONLY the caller's
	// own incidents: chRows injects chTenantScope, ClickHouse row policies enforce it
	// (TestChTenantScope). A tenant never sees another tenant's MTTI/MTBF/offenders.
	"/api/reliability/rollups":           "scoped",
	"/api/reliability/trends":            "scoped",
	"/api/reliability/chronic-offenders": "scoped",
	// GET lists the caller's OWN persisted snapshots (principalTenant + store
	// default-closed filter / RLS); POST triggers the cross-tenant backfill worker
	// behind requirePlatformAdmin. The data surface is tenant-scoped.
	"/api/reliability/time-metrics": "scoped",
	// Platform-GLOBAL integration posture (which provider credentials / feature
	// flags the stack was started with) — no tenant data. requirePlatformAdmin,
	// because a tenant/org admin holds administration:admin (§3a rule 3).
	// credentials_gate_test.go pins the 403/200 boundary.
	"/api/credentials": "platform",
	// Feature flags only — no tenant data, no credential/integration posture, so
	// there is nothing to scope. Authenticated-only by design (see handleFeatures):
	// it exists so gating /api/credentials to the platform owner does not make
	// optional UI surfaces silently vanish for everyone else.
	"/api/features": "infra",
	"/api/devices":  "scoped",
	// "/api/devices/" also carries the Config Backup subtree (P3-CFG,
	// internal/configstore): {id}/config/versions, {id}/config/versions/{sha},
	// {id}/config/diff, {id}/config/backup, {id}/config/golden and
	// {id}/config/status are dispatched from handleDeviceByID via
	// configAPI.ServeDeviceSubroute, so they inherit this "scoped"
	// classification (they are not separate mux.HandleFunc registrations and
	// therefore cannot be separate ledger keys — TestEveryRouteClassified
	// rejects a ledger key that is not a live mux route). Each one is per-tenant
	// DATA: the device is resolved through the principal-scoped inventory FIRST
	// (foreign or absent id → 404 alike, existence never revealed) and the
	// version rows are then read through the store's own tenant filter (PG
	// tenant_iso FORCE-RLS, migration 0038) as an independent second line.
	// Cross-org isolation proven by config_backup_isolation_test.go.
	//
	// It ALSO carries the Packet Capture subtree (internal/pcap):
	// {id}/pcap (GET list, POST start), {id}/pcap/{capture_id} (GET status,
	// DELETE) and {id}/pcap/{capture_id}/download, dispatched the same way from
	// handleDeviceByID via pcapAPI.ServeDeviceSubroute and inheriting this
	// "scoped" classification for the same reason (no separate mux.HandleFunc,
	// so no separate ledger key). These are per-tenant DATA of the most
	// sensitive kind — a PCAP is customer PAYLOAD — so the chain is: device
	// resolved through the principal-scoped inventory FIRST (foreign or absent
	// id → 404 alike), then the capture row read through the store's own tenant
	// filter (PG tenant_iso FORCE-RLS, migration 0039), then the sealed blob
	// opened under an AAD bound to (tenant, device, capture) so a blob that
	// somehow crossed tenants is unreadable rather than mis-served. The gate is
	// deliberately SPLIT: list/status are infrastructure:read, but start,
	// download (a reveal of payload) and delete are infrastructure:write.
	// Cross-org isolation proven by pcap_isolation_test.go plus
	// internal/pcap/{http,store}_test.go.
	"/api/devices/": "scoped",
	// Per-device interfaces grouped by routing instance (frontend-wave item 4,
	// internal/ifgroup). Per-tenant DATA: interface oper/admin state,
	// utilisation and error rates for ONE device. Unlike the config/pcap
	// subtrees this one IS its own mux pattern (a wildcard route, more specific
	// than "/api/devices/", so ServeMux prefers it) and therefore gets its own
	// ledger key. The chain is the igpmon one: requirePerm(infrastructure:read)
	// → {id} resolved through the principal-scoped inventory FIRST (a foreign
	// id and an absent id answer the SAME 404, so the subtree is not an
	// existence oracle) → EVERY VictoriaMetrics read carries the caller's
	// device boundary as extra_filters[], and a SCOPED principal with no
	// boundary is refused the read rather than served the fleet. Read-only; it
	// collects nothing and writes nothing. Cross-org isolation proven by
	// ifgroup_deps_test.go plus internal/ifgroup/http_test.go.
	"/api/devices/{id}/interfaces/by-vrf": "scoped",
	// Port Intelligence (#94): every port/interface/optics read is tenant DATA,
	// scoped by requirePerm(infrastructure:read) + the portStore RLS/tenant
	// filter (cross-tenant get → 404); proven by port_handlers_test.go.
	"/api/infrastructure/interfaces":          "scoped",
	"/api/infrastructure/interfaces/":         "scoped",
	"/api/infrastructure/port-summary":        "scoped",
	"/api/infrastructure/port-filter-options": "scoped",
	// Static reference (identical for everyone; no tenant data).
	"/api/infrastructure/module-types":    "selfScoped",
	"/api/infrastructure/port-signatures": "selfScoped",
	"/api/events":                         "scoped",
	"/api/events/feed":                    "scoped",
	"/api/findings":                       "scoped",
	"/api/flows/by-proto":                 "scoped",
	"/api/flows/by-type":                  "scoped",
	"/api/flows/fanout":                   "scoped",
	"/api/flows/flags":                    "scoped",
	"/api/flows/geo":                      "scoped",
	"/api/flows/services":                 "scoped",
	"/api/flows/timeseries":               "scoped",
	"/api/flows/top":                      "scoped",
	"/api/flows/topn":                     "scoped",
	"/api/geomap":                         "scoped",
	"/api/graphql":                        "scoped",
	"/api/health/score":                   "scoped",
	"/api/incidents":                      "scoped",
	"/api/incidents/":                     "scoped",
	// RCA auto-ticketing #78 P3: incident policies + outbox/audit are per-tenant
	// data — requirePerm + principalTenant scope, tenant stamped from token, store
	// isolation + HTTP cross-tenant tests (ticketing_isolation_test/ticketing_http_test).
	"/api/incident-policies":  "scoped",
	"/api/incident-policies/": "scoped",
	"/api/tickets/audit":      "scoped",
	"/api/tickets/outbox":     "scoped",
	// #103 UX-1 notified-via read: per-tenant ticket links (requirePerm +
	// principalTenant; store-level scope). Cross-org test: ticketing_links_test.go.
	"/api/tickets/links": "scoped",
	"/api/integrations":  "scoped",
	"/api/integrations/": "scoped",
	// NMS vendor-controller integrations (#95): per-tenant config/health/state,
	// tenant stamped from the principal, cross-tenant id → 404. Cross-org
	// isolation test: nms_isolation_test.go (TestNMSCrossOrgIsolation).
	"/api/nms/integrations":  "scoped",
	"/api/nms/integrations/": "scoped",
	// #128 wireless canonical inventory: read-only, store-enforced tenant scope
	// (mem tenant-keyed / PG FORCE-RLS), cross-tenant id → 404. Cross-org
	// isolation test: wireless_isolation_test.go (TestWirelessCrossTenantIsolation).
	"/api/wireless/controllers":  "scoped",
	"/api/wireless/controllers/": "scoped",
	"/api/wireless/aps":          "scoped",
	"/api/wireless/aps/":         "scoped",
	"/api/wireless/wlans":        "scoped",
	"/api/wireless/bssids":       "scoped",
	// #128 Phase 8 guarded remediation: tenant-scoped action requests, 404 when
	// FEATURE_WIRELESS_ACTIONS is off (default). Isolation coverage:
	// wireless_actions_test.go exercises "/api/wireless/actions" cross-tenant.
	"/api/wireless/actions":  "scoped",
	"/api/wireless/actions/": "scoped",
	"/api/itsm/jira":         "scoped",
	"/api/itsm/servicenow":   "scoped",
	// #103 tenant RCA policy destinations: per-tenant connection config (routing
	// key / webhook are write-only secrets, tenant from the principal). Isolation
	// coverage: ticketing_pagerduty_test.go (two-tenant key isolation) +
	// ticketing_http_test.go.
	"/api/itsm/pagerduty-rca":     "scoped",
	"/api/itsm/slack-rca":         "scoped",
	"/api/logs/export":            "scoped",
	"/api/logs/export/rows":       "scoped",
	"/api/logs/indices":           "scoped",
	"/api/logs/retention":         "scoped", // retention floor over the SAME logsScope surface as search: tenant index pattern + osTenantFilter + applogs owner gate (logs_retention_test.go)
	"/api/logs/search":            "scoped",
	"/api/metrics":                "scoped",
	"/api/metrics/forecast":       "scoped",
	"/api/metrics/names":          "scoped",
	"/api/metrics/query":          "scoped",
	"/api/metrics/query_range":    "scoped",
	"/api/notify/contact-points":  "scoped",
	"/api/notify/contact-points/": "scoped",
	"/api/notify/itsm":            "scoped",
	"/api/regions/topology":       "scoped",
	"/api/reports/executions":     "scoped",
	"/api/reports/executions/":    "scoped",
	"/api/reports/preview":        "scoped",
	"/api/reports/run":            "scoped",
	"/api/reports/runs":           "scoped",
	"/api/rules":                  "scoped",
	"/api/saved":                  "scoped",
	"/api/saved/":                 "scoped",
	"/api/search/global":          "scoped",
	// Wave 6 #20 unified search: every sub-search re-scopes to the principal
	// (visibleDevices, tenant-keyed cloud/connector stores, chTenantScope for
	// cases) — proven by search_unified_isolation_test.go.
	"/api/search":            "scoped",
	"/api/seams":             "scoped",
	"/api/seams/":            "scoped",
	"/api/seams/groups":      "scoped",
	"/api/seams/groups/":     "scoped",
	"/api/services":          "scoped",
	"/api/services/":         "scoped",
	"/api/sites":             "scoped",
	"/api/sites/":            "scoped",
	"/api/sot/import":        "scoped",
	"/api/snmp/credentials":  "scoped",
	"/api/snmp/credentials/": "scoped",
	"/api/snmp/options":      "scoped",
	"/api/tunnels":           "scoped",
	"/api/wan/interfaces":    "scoped",
	"/api/wan/endpoints":     "scoped",
	"/api/wan/circuits":      "scoped",
	"/api/wan/policy":        "scoped",
	"/api/topology/links":    "scoped",
	"/api/topology/view":     "scoped",
	"/api/topology/graph":    "scoped",
	"/api/topology/cloud":    "scoped",
	"/api/vulns":             "scoped",
	"/api/apikeys":           "scoped",
	"/api/apikeys/":          "scoped",
	"/api/sessions":          "scoped",
	"/api/sessions/":         "scoped",
	"/api/copilot/chat":      "scoped",

	// ── Application Identification + Cloud App Observability (#81), tenant-scoped ──
	// appid resolve/status reflect the caller's tenant view (operator overrides +
	// NGFW + cloud identity-map are all default-closed per tenant); cloud inventory
	// + applications are principalTenant-scoped with store isolation tests
	// (TestCloudStoreIsolation, appid_isolation_test.go, cloud_appid_resolver_test.go).
	"/api/appid/resolve":       "scoped",
	"/api/appid/resolve/batch": "scoped", // #81 P3G — isolation test: appid_batch_isolation_test.go
	// The coverage read is per-tenant: the firewall + cloud attribution counts
	// are taken from the CALLER'S bucket (countFor/CountFor) and the response
	// labels the reading scope:"tenant"|"platform" — the platform-wide sum is
	// the platform owner's cross view only (tracker 244). Isolation test:
	// appid_status_isolation_test.go, which also covers the override rows below.
	"/api/appid/status":        "scoped",
	"/api/appid/fusion/status": "scoped",
	"/api/appid/catalog":       "scoped",
	"/api/appid/catalog/":      "scoped",
	"/api/applications":        "scoped",
	"/api/applications/":       "scoped",
	"/api/flows/apps":          "scoped",
	"/api/cloud/apps":          "scoped",
	"/api/cloud/resources":     "scoped",
	// Wave 6 #20 permanent resource page read: store-scoped GetResource,
	// cross-tenant / unknown id → identical 404 (search_unified_isolation_test.go).
	"/api/cloud/resources/":           "scoped",
	"/api/cloud/identity-map":         "scoped",
	"/api/cloud/attribution/coverage": "scoped",
	"/api/cloud/app-rca":              "scoped",
	// Cloud Network Overview roll-up (P1): tenant DATA — inventory via
	// principalTenant-scoped cloud store, issues via tenant_scope row policies;
	// cross-org proof in cloud_network_overview_test.go.
	"/api/cloud/network/overview": "scoped",
	// Business Service mapping + manual overrides (migration 0024): tenant DATA,
	// requirePerm + principalTenant + FORCE-RLS; cross-org proof in
	// business_service_isolation_test.go.
	"/api/cloud/business-services":  "scoped",
	"/api/cloud/business-services/": "scoped",
	"/api/cloud/resource-mappings":  "scoped",
	"/api/cloud/resource-mappings/": "scoped",
	// #81 P3H cloud telemetry reads — every query carries the caller's tenant_scope,
	// which the corr_signals / corr_signals_archive / corr_objects FORCE row policies
	// enforce in ClickHouse (see cloud_signals.go, cloud_ingestion.go).
	"/api/cloud/ingestion": "scoped",
	"/api/cloud/health":    "scoped",
	"/api/cloud/changes":   "scoped",
	"/api/cloud/evidence":  "scoped",
	// Wave 5 #16: security rollup / provider-incident / seam-telemetry reads —
	// every query carries the caller's tenant_scope (corr_signals FORCE row
	// policy); scope-clause + bounded-read contract proven by cloud_security_test.go.
	"/api/cloud/security":        "scoped",
	"/api/cloud/provider-events": "scoped",
	"/api/cloud/seam-telemetry":  "scoped",
	// Daily provider-billed cost records (Wave 5 #18): the one query carries the
	// caller's tenant_scope, enforced by the STRICT tenant_iso_cloud_costs row
	// policy (cloud_costs.go; isolation contract proven by cloud_costs_test.go).
	"/api/cloud/costs": "scoped",
	// Change→incident correlation (Wave 4 #12): both reads carry tenant_scope
	// (cross-tenant id → no visible row → 404); scope-clause + bounded-read
	// contract proven by cloud_investigation_changes_test.go.
	"/api/cloud/investigations/": "scoped",
	// Service dependency map (#9): both CH reads carry the caller's tenant_scope
	// (corr_signals FORCE row policy); endpoint resolution uses only the caller's
	// principalTenant-scoped identity map + inventory. Isolation contract proven
	// by cloud_service_map_test.go (scope literal + fail-closed cases).
	"/api/cloud/service-map": "scoped",
	// Cloud metric charts (Wave 5 #14): PromQL selector built server-side from
	// the caller's principalTenant inventory ids only; cross-tenant id → 404.
	// Cross-org proof in cloud_metrics_series_isolation_test.go.
	"/api/cloud/metrics/series": "scoped",
	// Per-tenant SLOs (Wave 5 #14 slice 2): tenant-keyed file store, PUT is
	// requireAdmin + principal-stamped. Cross-org proof in cloud_slo_isolation_test.go.
	"/api/cloud/slos": "scoped",
	// Per-tenant cloud monitors (Wave 5 #14 slice 3): tenant-keyed store,
	// alerts:write CRUD, id resolved inside the caller's bucket only (foreign
	// id → 404). Cross-org proof in cloud_monitors_isolation_test.go.
	"/api/cloud/monitors":  "scoped",
	"/api/cloud/monitors/": "scoped",

	// ── Cloud Connector framework ──
	// Connectors are per-tenant DATA (each tenant's cloud connections); scoped +
	// backed by cloud_connectors_isolation_test.go.
	"/api/cloud/connectors":  "scoped",
	"/api/cloud/connectors/": "scoped",
	// Provider/method/capability-pack catalog: static, platform-wide reference
	// data (identical for every tenant), infra-read gated.
	"/api/cloud/providers": "globalRef",

	// ── identity/admin, scoped to caller's tenant/org by the handler ──
	"/api/audit": "adminScoped",
	// SEC-021.1 posture: tenant admins get ONLY device lanes + own fleet count
	// (scoped by principal); the full table + validator require the platform
	// identity. Isolation test: transport_posture_isolation_test.go.
	"/api/security/transport-posture": "adminScoped",
	// The export enumerates every internal hop — platform identity only.
	"/api/security/transport-posture/export": "platform",
	"/api/users":                             "adminScoped",
	"/api/users/":                            "adminScoped",
	"/api/users/mfa-reset":                   "adminScoped",
	"/api/tenants":                           "adminScoped",
	"/api/tenants/":                          "adminScoped",
	"/api/orgs":                              "adminScoped",
	"/api/orgs/":                             "adminScoped",
	"/api/bindings":                          "adminScoped",
	"/api/bindings/":                         "adminScoped",
	"/api/access/explain":                    "adminScoped",
	"/api/security-settings":                 "adminScoped",
	"/api/policy/catalog":                    "adminScoped",
	"/api/policy/document":                   "adminScoped",
	"/api/policy/documents":                  "adminScoped",
	"/api/policy/effective":                  "adminScoped",
	"/api/policy/validate":                   "adminScoped",

	// ── platform-GLOBAL plumbing, platform-owner only ──
	// AI entitlement per tenant is platform PACKAGING (which tenants get the
	// assistant / the agent loop) — requirePlatformAdmin, a tenant admin must
	// never grant itself investigations (§3a.3).
	"/api/ai/tenants":         "platform",
	"/api/ai/tenants/":        "platform",
	"/api/auth/ldap/config":   "platform",
	"/api/auth/ldap/test":     "platform",
	"/api/auth/tacacs/config": "platform",
	"/api/auth/tacacs/test":   "platform",
	"/api/auth/oidc/config":   "platform",
	"/api/auth/sso/idp":       "platform", // GUI-configurable SSO IdPs (Keycloak reconcile); requirePlatformAdmin
	"/api/auth/sso/idp/":      "platform", // {alias} CRUD + {alias}/test probe; requirePlatformAdmin
	"/api/auth/sso/config":    "platform",
	"/api/auth/token-policy":  "platform",
	"/api/copilot/config":     "platform",
	// Per-tenant ingestion service surface (Wave 1 #2): the cloud-ingest poller's
	// platform credential (ingest:cloud API key in the global realm). It fans one
	// poller across EVERY tenant's connectors, so it is platform plumbing by
	// definition — requireCloudIngestService fails tenant-bound principals closed
	// (cloud_ingest_service_test.go covers the isolation matrix).
	"/api/cloud/ingest/connectors":    "platform",
	"/api/cloud/ingest/connectors/":   "platform",
	"/api/cloud/ingest/source-status": "platform", // poller error reports (Wave 2 #4) — same service credential
	"/api/system/network":             "platform",
	"/api/system/backup":              "platform", // DR config + status; requirePlatformAdmin
	"/api/system/backup/snapshots":    "platform", // #150 SM policy view/control; requirePlatformAdmin (gate test: data_protection_routes_test.go)
	// Data Protection rebuild (2026-09-03). Platform-GLOBAL backup plumbing, NOT
	// tenant data: every route is gated by requirePlatformAdmin and every write
	// is audited on both outcomes. A tenant/org admin holds full
	// administration:admin, so a scope-blind requireAdmin here would hand every
	// tenant the platform's backup posture and the ability to DELETE its restore
	// points (§3a rule 3). There is deliberately no org-isolation test: no
	// tenant rows cross these routes at all.
	// Gate + mux tests: data_protection_routes_test.go (TestSystemBackupOpsGate
	// covers every route below); the domain itself lives in
	// internal/dataprotect and is tested there.
	"/api/system/backup/coverage":    "platform", // per-engine coverage table; requirePlatformAdmin
	"/api/system/backup/snapshots/":  "platform", // list/create/delete/restore/verify subtree; requirePlatformAdmin
	"/api/system/backup/operations":  "platform", // async operation ring; requirePlatformAdmin
	"/api/system/backup/operations/": "platform", // one operation by id; requirePlatformAdmin
	// Licence (2026-09-04; GET split tenant-readable 2026-09-05). SPLIT by verb,
	// and the split is the isolation posture:
	//
	//   PUT/DELETE — platform-GLOBAL commercial plumbing. requirePlatformAdmin
	//     (licenceGate), audited on both outcomes: there is one licence file per
	//     installation and it covers every tenant on it, so a scope-blind
	//     requireAdmin would let any tenant license the whole platform (§3a
	//     rule 3).
	//   GET — per-tenant DATA, hence "scoped". requireAdmin (licenceReadGate) +
	//     principalTenant: a cross-tenant caller gets the provider view; every
	//     other admin gets a TENANT PROJECTION whose usage is counted only over
	//     rows that tenant owns (canSeeDevice / the watchlist store's own
	//     (tenant, cross) read), and which carries no customer, licence id, key
	//     material or file path. The tenant comes from the token, never from the
	//     body or query (§3a rule 2); `as_tenant` is honored by the auth
	//     middleware and can only NARROW.
	//
	// Gate + grammar tests: licence_routes_test.go. Cross-org isolation:
	// TestLicenceTenantViewCrossOrgIsolation (tenant A's usage never counts
	// tenant B's devices or prefixes; as_tenant into another org is ignored).
	"/api/system/licence": "scoped", // GET: tenant projection (requireAdmin); PUT/DELETE: requirePlatformAdmin
	// METERING (tracker 258) — recorded per-tenant USAGE, and its signed report.
	// Per-tenant DATA: the store takes a (tenant, cross) pair on every read and
	// has NO unscoped "list all", so a handler cannot forget the filter; the
	// installation row's key is the empty string, which a tenant-scoped read can
	// never match. `?tenant=` may only NARROW and only for a cross-tenant
	// caller — a scoped caller naming another tenant gets 404, never a 403 that
	// would confirm the other tenant exists. Cross-org isolation proven by
	// metering_isolation_test.go.
	"/api/system/licence/usage":        "scoped",
	"/api/system/licence/usage/report": "scoped",
	// MEASURED bytes on disk per store (tracker 204, internal/storagemeter).
	// scoped, not platform: a tenant admin may see ITS OWN bytes — how much
	// storage a tenant's own telemetry occupies is that tenant's data — and the
	// cross-tenant grant is what widens the view to every tenant. Volume is
	// business intelligence, so another tenant's bytes are exactly the kind of
	// thing §3a keeps in its own lane.
	//
	// The scope comes from the TOKEN and from nowhere else: the handler reads no
	// tenant selector at all (no `?tenant=`, no `as_tenant`), so there is
	// nothing for a scoped caller to widen itself with. The narrowing is applied
	// at the STORAGE layer for both tenant-partitioned stores — the OpenSearch
	// `_cat` pattern is oslog.TenantCatPattern (the same derivation log search
	// uses) and the ClickHouse read carries a partition-prefix WHERE clause —
	// and the readings are filtered AGAIN on the way out (§3a.4 defense in
	// depth). The four stores that are not tenant-partitioned on disk
	// (VictoriaMetrics, PostgreSQL, the api file store, Kafka) return a scoped
	// caller a NIL and the reason, never a pro-rata share. Cross-org isolation
	// proven by storage_measured_isolation_test.go.
	"/api/system/storage/measured": "scoped",
	"/api/system/network/test":     "platform",
	"/api/automation/netbox":       "platform",
	"/api/automation/netbox/sync":  "platform",
	"/api/discovery/config":        "platform", // subnet-scan scope: directs the platform prober (#91)
	"/api/notify/smtp":             "platform",
	"/api/notify/smtp/test":        "platform",
	"/api/notify/slack":            "platform",
	"/api/notify/slack/test":       "platform",
	"/api/notify/twilio":           "platform",
	"/api/notify/twilio/test":      "platform",
	"/api/notify/ntfy":             "platform",
	"/api/notify/ntfy/test":        "platform",
	"/api/notify/pagerduty":        "platform",
	"/api/notify/pagerduty/test":   "platform",
	"/api/notify/teams":            "platform",
	"/api/notify/teams/test":       "platform",
	"/api/notify/sns":              "platform",
	"/api/notify/sns/test":         "platform",
	// The channel enumeration is over the SAME platform-global notify integrations
	// as /api/notify/* — a tenant admin must not enumerate operator channel names
	// (requirePlatformAdmin; report_scheduler.go handleReportChannels).
	"/api/reports/channels": "platform",
	"/api/exports/policy":   "platform",
	"/api/breakglass":       "platform",
	"/api/breakglass/":      "platform",
	"/api/onboard":          "platform",
	// SNMP config generator — platform-owner action that mints a credential.
	"/api/onboard/snmp-config":    "platform",
	"/api/discovery/refresh":      "platform",
	"/api/integrations/reconcile": "platform",
	// F-11 seal-or-quarantine (D5): the quarantine holds OTHER tenants'
	// unattributable events by definition — platform-owner only, and
	// reattribute additionally demands sensitive_data:admin (the
	// unseal-equivalent capability). Gate tests: quarantine_api_test.go.
	"/api/quarantine":             "platform",
	"/api/quarantine/reattribute": "platform",

	// ── platform-wide reference data (admin-readable, owner-mutated) ──
	"/api/roles":          "globalRef",
	"/api/roles/":         "globalRef",
	"/api/snmp/profiles":  "globalRef",
	"/api/snmp/profiles/": "globalRef",
	"/api/regions":        "globalRef",

	// ── stack-wide infrastructure monitoring (intentionally global) ──
	"/api/collectors":   "infra",
	"/api/stack/health": "infra",
	"/api/health":       "infra",
	"/api/paths/health": "infra",
	"/api/probe/paths":  "infra",
	// Registry STORAGE posture (tracker 245): which backend kind holds each
	// registry, whether it persists, whether it can serve. Deployment-wide and
	// identical for every tenant — no tenant rows, no counts, no DSN — but read
	// by any principal with infrastructure:read, because the Registries page
	// must tell THAT operator whether what they are looking at is durable.
	"/api/registries/status": "infra",

	// ── caller's OWN identity only ──
	"/api/auth/me":              "selfScoped",
	"/api/auth/change-password": "selfScoped",
	"/api/auth/permissions":     "selfScoped",
	"/api/auth/mfa/activate":    "selfScoped",
	"/api/auth/mfa/disable":     "selfScoped",
	"/api/auth/mfa/setup":       "selfScoped",
	"/api/auth/mfa/status":      "selfScoped",
	"/api/scopes":               "selfScoped",

	// ── capability-link / token-authenticated (not principal-scoped) ──
	"/api/exports/":              "token",
	"/api/exports/view/":         "token",
	"/api/reports/view/":         "token",
	"/api/integrations/webhook/": "token",
	// NMS controller webhook: JWT-exempt; authenticated by opaque path token +
	// the connector's signature verification, tenant derived from the token row.
	"/api/nms/webhook/": "token",
	// vmalert Alertmanager-v2 webhook: JWT-exempt, authenticated by the
	// VMALERT_WEBHOOK_TOKEN shared secret (Bearer/Basic, constant-time), and
	// platform-GLOBAL plumbing — it is NOT principal-scoped and carries no
	// tenant data: an alert arriving with a tenant/tenant_id/org label is
	// DROPPED rather than laundered onto the global operator channels (§3a,
	// proven by internal/alertwebhook's isolation test).
	"/api/internal/vmalert/": "token",
	// NMS connector catalog: static vendor specs (no tenant data, auth required).
	"/api/nms/connectors": "globalRef",

	// ── unauthenticated / pure auth-flow (no tenant data) ──
	"/api/auth/login":           "public",
	"/api/auth/logout":          "public",
	"/api/auth/methods":         "public",
	"/api/auth/refresh":         "public",
	"/api/auth/console-gate":    "public",
	"/api/auth/osd-gate":        "public",
	"/api/auth/password-policy": "public",
	"/api/auth/sso/callback":    "public",
	"/api/auth/sso/login":       "public",
	"/api/auth/ldap/login":      "public",
	"/api/auth/tacacs/login":    "public",
	"/api/auth/mfa/login":       "public",
	// Config Backup & Drift (P3-CFG, internal/configstore + internal/configdrift).
	// Per-tenant DATA: version rows and the drift badge are stamped with the
	// DEVICE's tenant and read through the store's own tenant filter (PG
	// tenant_iso FORCE-RLS, migration 0038); a cross-tenant device or version id
	// answers 404 and a cursor cannot page out of the caller's tenant. The
	// /api/devices/{id}/config/* subtree is dispatched from handleDeviceByID (it
	// inherits /api/devices/'s classification); this is the one new mux route.
	// Isolation proven by config_backup_isolation_test.go plus
	// internal/configstore/{http,store}_test.go and internal/configdrift/http_test.go.
	"/api/config/drift": "scoped",
	"/api/openapi.json": "public",
	// Pipeline debugger (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §4). All
	// five are PLATFORM plumbing, requirePlatformAdmin (s.debugAuthz), NOT
	// requireAdmin: a trace injects a marked synthetic record into the stack's
	// own ingress and reads it back out of the SHARED stores, and a log-level
	// change alters every tenant's service. A tenant/org admin holds full
	// administration:admin, so a scope-blind gate here would be a privilege
	// leak (§3a rule 3), which is why these are not "scoped".
	//
	// The `tenant` selector on /api/debug/trace and /api/debug/stage NARROWS a
	// cross-tenant principal (the as_tenant shape) and can never widen a scoped
	// one: effectiveTenant refuses a request naming a tenant other than the
	// caller's own, and the trace status route 404s a marker outside the
	// caller's scope rather than confirming it exists. Proven by
	// internal/pipedebug/http_test.go.
	"/api/debug/trace":    "platform",
	"/api/debug/trace/":   "platform",
	"/api/debug/loglevel": "platform",
	"/api/debug/stage/":   "platform",
	// The parser decision-trace switch is platform for a second, stronger
	// reason than the gate: the filter it arms is ONE process-global needle
	// inside the traced services (internal/parsetrace), so an armed marker
	// records the parse decisions of EVERY tenant's records that match it.
	// There is no per-tenant instance of it to scope, and inventing one would
	// be a lie about what the switch does. Hence platform-admin-only, bounded
	// (30-minute hard cap) and auto-disarming, and the audit trail records the
	// needle's LENGTH rather than the needle (a message fragment is a
	// customer's log line, §8). Gate + grammar + PII tests:
	// internal/pipedebug/w2_test.go.
	"/api/debug/parsemarker": "platform",
	// The session viewer (W3). PLATFORM for the same reason as the trace that
	// writes them, and one more: a session directory holds the per-module log
	// files of whatever the trace crossed, so a single module file can carry a
	// tenant's own log line. The routes are requirePlatformAdmin, every read is
	// audited, the id and the module name are closed grammars before any path
	// is joined, and a session whose manifest names another tenant is a 404 to
	// a scoped principal — the same 404 an absent one gets, so an id's
	// existence is never confirmed to a caller who may not read it (§3a rule
	// 1). Proven by internal/pipedebug/sessions_test.go.
	"/api/debug/sessions":  "platform",
	"/api/debug/sessions/": "platform",
}

var validRouteCategories = map[string]bool{
	"scoped": true, "adminScoped": true, "platform": true, "globalRef": true,
	"infra": true, "selfScoped": true, "token": true, "public": true,
}

// registeredAPIRoutes parses main.go for every mux.HandleFunc("/api/...") pattern.
func registeredAPIRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(/api/[^"]+)"`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryRouteClassified — the guard. Every registered /api route MUST be in the
// ledger with a valid category; every ledger entry MUST still be a real route.
func TestEveryRouteClassified(t *testing.T) {
	routes := registeredAPIRoutes(t)
	if len(routes) == 0 {
		t.Fatal("no /api routes parsed from main.go — guard would be a no-op")
	}
	live := map[string]bool{}
	for _, r := range routes {
		live[r] = true
		cat, ok := routeIsolationLedger[r]
		if !ok {
			t.Errorf("UNCLASSIFIED ROUTE %q — classify it in routeIsolationLedger "+
				"(CLAUDE.md §3a): tenant DATA → \"scoped\" + a cross-org isolation test; "+
				"platform plumbing → \"platform\"; else infra/globalRef/selfScoped/token/public with intent.", r)
			continue
		}
		if !validRouteCategories[cat] {
			t.Errorf("route %q has unknown category %q", r, cat)
		}
	}
	// Stale ledger entries (route removed/renamed) — keep the ledger honest.
	for r := range routeIsolationLedger {
		if !live[r] {
			t.Errorf("STALE ledger entry %q — no longer registered in main.go; remove it.", r)
		}
	}
}
