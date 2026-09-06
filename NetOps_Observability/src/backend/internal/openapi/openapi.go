package openapi

import ()

// openapi.go — a self-describing OpenAPI 3.0 document for the public REST API.
//
// It is assembled from a small in-code route registry so it can't drift far
// from reality, and served at GET /api/openapi.json. The Administration → API
// Access page renders a reference from it; any OpenAPI client (Swagger UI,
// Postman, codegen) can consume it directly. See docs/API_ACCESS.md.

// apiRoute is one documented operation.
type apiRoute struct {
	method  string
	path    string
	tag     string
	summary string
}

// apiRoutes is the curated surface we advertise. It deliberately omits internal
// /admin/* probes and the WebSocket hub.
var apiRoutes = []apiRoute{
	{"POST", "/api/auth/login", "Auth", "Exchange username/password for an access + refresh token"},
	{"POST", "/api/auth/refresh", "Auth", "Rotate a refresh token for a fresh access token"},
	{"POST", "/api/auth/logout", "Auth", "Revoke a refresh token"},
	{"GET", "/api/auth/me", "Auth", "Current principal"},
	{"GET", "/api/auth/permissions", "Auth", "Effective module→level permission grid"},
	{"GET", "/api/auth/sso/config", "Auth", "SSO availability + provider buttons"},
	{"GET", "/api/auth/sso/login", "Auth", "Begin the OIDC Authorization Code flow"},
	{"GET", "/api/devices", "Inventory", "List devices visible to the caller's tenant"},
	{"POST", "/api/devices", "Inventory", "Create/update a device (scoped to the caller's tenant)"},
	{"GET", "/api/devices/{id}", "Inventory", "Fetch a device by id"},
	{"DELETE", "/api/devices/{id}", "Inventory", "Delete a device"},
	{"GET", "/api/devices/{id}/monitoring", "Inventory", "Whether Correlix is collecting from this device, why, and which telemetry methods are configured (infrastructure:read; 404 outside the caller's tenant)"},
	{"PUT", "/api/devices/{id}/monitoring", "Inventory", "Turn monitoring on or off for one device ({\"enabled\": true|false}; infrastructure:write). Monitored devices are the unit the licence counts — enabling the first one past the ceiling answers the structured 402, disabling releases the entitlement, and the device, its history and its topology are untouched either way"},
	{"GET", "/api/collectors", "Inventory", "Collector pool status"},
	{"GET", "/api/alerts", "Alerts", "Active alerts visible to the caller's tenant"},
	{"GET", "/api/rules", "Alerts", "Alert rules"},
	{"POST", "/api/rules", "Alerts", "Add an alert rule"},
	{"GET", "/api/findings", "Alerts", "Correlation findings (ClickHouse)"},
	// BGP Operations — item 10. The watchlist is per-tenant; the resource proxy
	// and the depth panels are public internet routing facts about a named
	// resource. The feed is the per-tenant near-live ring buffer.
	{"GET", "/api/bgp/watchlist", "BGP", "The caller's tenant watchlist of prefixes and ASNs"},
	{"POST", "/api/bgp/watchlist", "BGP", "Watch a prefix or ASN (tenant stamped from the token)"},
	{"DELETE", "/api/bgp/watchlist", "BGP", "Stop watching a resource (?resource=)"},
	{"GET", "/api/bgp/resource", "BGP", "Routing status, RPKI verdict, collector paths or registry ownership for one resource (?view=status|updates|whois)"},
	{"GET", "/api/bgp/rpki", "BGP", "RPKI origin validation for the caller's watchlist prefixes, or for one ?resource= prefix"},
	{"GET", "/api/bgp/aspa", "BGP", "ASPA record for an ?resource=ASn — honest 'not configured' unless BGP_ASPA_PROVIDER_URL names a provider (no public per-ASN ASPA API exists)"},
	{"GET", "/api/bgp/geofeed", "BGP", "RFC 8805 geofeed published for a prefix or ASN, discovered per RFC 9092 from the registry object"},
	{"GET", "/api/bgp/aspath-graph", "BGP", "AS-path node-link graph for ?prefix= from RIS collector state (deduped, edges capped at 500)"},
	{"GET", "/api/bgp/feed", "BGP", "Near-live BGP updates for the caller's watchlist from a bounded per-tenant ring buffer (?since= cursor); requires FEATURE_BGP_LIVE_FEED"},
	{"GET", "/api/dem/targets", "Digital Experience", "The caller's tenant's synthetic experience targets (icmp | tcp | dns | http) with their site/app labels and latency/availability budgets; enabled:false plus an explanation when FEATURE_DEM is off"},
	{"POST", "/api/dem/targets", "Digital Experience", "Declare an experience target. The owning tenant is stamped from the token — a tenant in the body is not merely ignored, it cannot be expressed"},
	{"GET", "/api/dem/targets/{id}", "Digital Experience", "One experience target. A target id owned by another tenant answers 404, never 403 — an id is never confirmed to exist"},
	{"PUT", "/api/dem/targets/{id}", "Digital Experience", "Patch an experience target (edit, or pause it without deleting its history). The kind and the owning tenant are immutable"},
	{"DELETE", "/api/dem/targets/{id}", "Digital Experience", "Remove an experience target. Its recorded series are unaffected and simply stop growing"},
	{"GET", "/api/dem/experience", "Digital Experience", "The experience score over a 1h or 24h window: availability against the error budget, p95 latency against the declared budget and path stability, per target and rolled up per site and per app. A window with no measurement returns measured:false and a reason — never a fabricated zero"},
	// The causality layer (internal/dem/experience, S17 slice 1–4). Every one of
	// these is per-tenant DATA: a cross-tenant principal must scope in with the
	// tenant switcher, and a foreign id answers 404.
	{"GET", "/api/dem/overview", "Digital Experience", "The Experience overview over a 1h or 24h window (?window=): the published, decomposable experience score with its policy version, declared journeys and their measured health, open experience incidents, recent changes, hotspots and per-source telemetry confidence. A dimension nothing measured contributes nothing and is reported as not-measured with its reason; below the evidence minimum no score is published at all"},
	{"GET", "/api/dem/incidents", "Digital Experience", "Experience incidents derived from the window's evidence, worst first (?window=, ?severity=, ?app=, ?journey=, ?limit=, ?offset=). Each row carries the leading cause, its confidence and verdict tier, the owning seam and the impact dimensions that were NOT measured"},
	{"GET", "/api/dem/incidents/{id}", "Digital Experience", "One experience incident: impact, ranked hypotheses with their confidence factors and gate reasons, supporting and contradicting evidence, missing evidence, correlation-ranked changes, ownership, recommended actions and the recovery-verification plan. An unknown or another tenant's id answers 404"},
	{"GET", "/api/dem/incidents/{id}/evidence", "Digital Experience", "The incident's evidence: every item with its stance, modality class, observer, reliability and provenance, plus the missing-evidence records that lower confidence and can block confirmation"},
	{"GET", "/api/dem/incidents/{id}/timeline", "Digital Experience", "The incident's single timeline — impact, evidence and changes on one axis, each entry stating whether it was observed or inferred"},
	{"POST", "/api/dem/incidents/{id}/promote", "Digital Experience", "Promote a DERIVED experience incident into the platform incident record (source_type experience), persisting the DEM evidence packet beside it. infrastructure:write; the owning tenant is stamped from the token. Idempotent — the derived id is the dedup key, so a second promotion folds into the same incident and escalates its severity rather than raising a twin. Answers 409 when the deployment has no incident system of record (it is Postgres-only), never a 202 for an incident nobody raised"},
	{"GET", "/api/dem/incidents/{id}/path", "Digital Experience", "The immutable path-observation reference for the incident, to be rendered through the service path graph API (the single source of hop order). Returns measured:false with a reason when no forward path was observed — never a clean path nobody measured"},
	{"GET", "/api/dem/journeys", "Digital Experience", "The tenant's declared user journeys with their measured health over the window (?window=): per-step success against the objective, the failing step, and the coverage behind the number"},
	{"POST", "/api/dem/journeys", "Digital Experience", "Declare a journey (branching steps, optional steps, loops, business importance, SLO, step→target bindings). The owning tenant is stamped from the token — a tenant in the body cannot be expressed"},
	{"GET", "/api/dem/journeys/{id}", "Digital Experience", "One journey definition and its measured health. Another tenant's id answers 404"},
	{"PUT", "/api/dem/journeys/{id}", "Digital Experience", "Replace a journey definition; the version increments so an observation recorded against the old one is never silently re-attributed"},
	{"DELETE", "/api/dem/journeys/{id}", "Digital Experience", "Remove a journey definition. The measurements its steps were bound to are unaffected"},
	{"GET", "/api/dem/synthetics/coverage", "Digital Experience", "The synthetic COVERAGE model (?window=): per declared user action, how many checks protect it, from how many vantages, when one last succeeded, and whether it is protected, thinly protected, untested, stale or broken. An action nothing measures is untested, never healthy"},
	{"GET", "/api/dem/changes", "Digital Experience", "The normalized change feed over the window (?window=, ?type=, ?app=, ?site=, ?limit=, ?offset=): deployments, config, feature flags, cloud, network, security policy, DNS and route changes on one timeline"},
	{"POST", "/api/dem/changes", "Digital Experience", "Record a change event. Immutable: a repeated id is idempotent and never rewrites what was recorded. The owning tenant is stamped from the token"},
	{"GET", "/api/dem/data-health", "Digital Experience", "Per-source experience telemetry health (?window=): configured, state, last seen, freshness, volume, coverage, whether the source can anchor a confirmed verdict, and how much its current state is lowering diagnostic confidence. UNKNOWN and NO DATA are never reported as healthy"},
	{"POST", "/api/dem/events", "Digital Experience", "Ingest first-party experience events (RUM beacons, agent and API-client events). WRITE-ONLY, and gated by the dedicated tenant-bound `ingest:experience` API-key scope or an operator's infrastructure:write — the owning tenant is stamped from the credential and cannot be expressed in the body. user_ref must be a pseudonymous per-tenant reference; a direct identifier is REFUSED, never silently hashed. A full queue answers 503 with Retry-After rather than 202 for events with nowhere to go"},
	{"POST", "/api/dem/business-events", "Digital Experience", "Ingest business outcomes (purchase, booking, claim, or whatever this tenant's business does — the type is a free string). Same credential, bounds and tenant-stamping as /api/dem/events. A value with no currency is refused: an unlabelled number is not an amount"},
	{"GET", "/api/bgp/alerts", "BGP", "The caller's BGP alert history plus the current incident class per watched prefix (visibility_loss | origin_change | rpki_invalid | route_leak | bogon | none | unknown) with the vantage points and paths that support it; answers enabled:false with an explanation unless FEATURE_BGP_ALERTS is on — an empty list is never rendered as 'all clear'"},
	{"GET", "/api/bgp/alerts/config", "BGP", "The caller's declared alert policy: expected origin ASNs, upstream (transit) set and the visibility/corroboration thresholds, per prefix or as a tenant default"},
	{"PUT", "/api/bgp/alerts/config", "BGP", "Replace the caller's alert policy (infrastructure:write; the owner is stamped from the token, never the body). An empty expected-origin set means the baseline is LEARNED; an empty upstream set disables the route-leak heuristic rather than guessing a transit set"},
	{"GET", "/api/bgp/bogons", "BGP", "Bogon prefixes seen on the caller's own BMP feed and update ring, with first/last seen and the peer, plus the set actually in force: the embedded IANA/RFC special-purpose blocks (source + transcription date included) and the OPTIONAL Team Cymru full-bogons feed when FEATURE_BGP_BOGON_FEED is on"},
	{"POST", "/api/correlations/{id}/feedback", "RCA", "Record an operator verdict on an RCA case (correct | wrong | partial, with the wrong part)"},
	{"GET", "/api/correlations/{id}/feedback", "RCA", "List the operator verdicts on an RCA case, newest first (caller's tenant only)"},
	{"GET", "/api/correlations/feedback/summary", "RCA", "Windowed verdict counts + false-positive RCA rate for the caller's tenant"},
	// Security (CTEM) — Project 3 P3-API. Findings are read from the per-tenant
	// OpenSearch index through TenantIndexPattern + TenantFilter; the rules and
	// views routes are the small per-tenant control-plane state.
	{"GET", "/api/security/findings", "Security", "List security findings (cursor-paged; current=true collapses to the latest verdict per finding identity)"},
	{"GET", "/api/security/findings/{id}", "Security", "Fetch one finding (404 outside the caller's tenant)"},
	{"GET", "/api/security/findings/facets", "Security", "Facet counts by severity/status/seam/framework/evidence class"},
	{"GET", "/api/security/findings/trend", "Security", "Verdict trend over time (date histogram by status)"},
	{"GET", "/api/security/posture", "Security", "CTEM funnel, assessment coverage and last scan for the caller's tenant"},
	{"GET", "/api/security/exposure-stories", "Security", "Correlation objects grounded on security evidence"},
	{"GET", "/api/security/exposure-stories/{id}", "Security", "One exposure story (delegates to the correlation detail)"},
	{"GET", "/api/security/rules", "Security", "Detection catalog with the tenant's enable state (mitre is an ARRAY of ATT&CK technique ids, omitted when the rule carries none)"},
	{"PUT", "/api/security/rules", "Security", "Enable/disable detections for the caller's tenant (administration:write)"},
	{"GET", "/api/security/frameworks", "Security", "Compliance framework catalogue (id, name, version, base vs projection-of-800-53, scope) with the caller tenant's enable state, plus the published CIS device benchmarks and the section each hardening rule cites. `configured:false` means the tenant has not chosen and the shipped default set (NIST 800-53 Rev5 + CIS Controls) is shown"},
	{"PUT", "/api/security/frameworks", "Security", "Choose which compliance frameworks the caller's tenant is assessed against (administration:write; body is [{framework_id, enabled}] over a closed vocabulary; the owner is stamped from the token and the cross-tenant view is refused)"},
	{"GET", "/api/security/compliance", "Security", "One independent scorecard per ENABLED framework, computed by projecting the tenant's current findings onto that framework's requirements through the canonical 800-53 control. score_percent is null (never 0%) when nothing in a framework's scope was assessed"},
	{"GET", "/api/security/views", "Security", "Saved findings filter sets for the caller's tenant"},
	{"POST", "/api/security/views", "Security", "Save a findings filter set (infrastructure:write)"},
	{"DELETE", "/api/security/views/{id}", "Security", "Delete a saved filter set (404 outside the caller's tenant)"},
	// P3-EMIT producer lane (internal/seclane). Registered ONLY when
	// FEATURE_SECURITY_LANE=true, so a flag-off deployment 404s both.
	{"GET", "/api/security/lane/status", "Security", "Security producer lane status: last scan id/time/outcome per tenant (own-only; cross-tenant for the platform admin)"},
	{"POST", "/api/security/scan", "Security", "Queue a bounded security scan for the caller's own tenant (administration:write; 429 when one is already queued or running)"},
	// Config Backup & Drift (P3-CFG, internal/configstore + internal/configdrift).
	// Registered ONLY when FEATURE_CONFIG_BACKUP=true, so a flag-off deployment
	// 404s every one of them. Version text and diffs are SECRET-REDACTED and the
	// read is audited with a `sensitive` tag; the sealed copy keeps the original.
	{"POST", "/api/devices/{id}/config/backup", "Config Backup", "Queue a running-configuration capture for one device over the SSH gateway (infrastructure:write; 202 + job id, 429 when one is already running)"},
	{"GET", "/api/devices/{id}/config/versions", "Config Backup", "List a device's stored configuration versions, newest first (infrastructure:read; 404 outside the caller's tenant)"},
	{"GET", "/api/devices/{id}/config/versions/{sha}", "Config Backup", "Fetch one stored configuration version as secret-redacted text (infrastructure:read; audited as a sensitive read)"},
	{"GET", "/api/devices/{id}/config/diff", "Config Backup", "Bounded, secret-redacted unified diff between two configuration versions (from, to)"},
	{"POST", "/api/devices/{id}/config/golden", "Config Backup", "Mark a stored version as the device's golden baseline (infrastructure:write)"},
	{"GET", "/api/devices/{id}/config/status", "Config Backup", "One device's configuration sync status: in_sync | changed | drifted | unknown"},
	{"GET", "/api/config/drift", "Config Backup", "Configuration drift across the caller's devices, paged and filterable by state (infrastructure:read)"},
	// Packet Capture (internal/pcap). Registered ONLY when
	// FEATURE_PACKET_CAPTURE=true, so a flag-off deployment 404s every one of
	// them and the feature is not enumerable. A PCAP is customer PAYLOAD: every
	// capture is bounded (<=60 s, <=10 000 packets, <=25 MiB, one per device at
	// a time), sealed under the tenant DEK at rest, and start/download/delete
	// are audited with a `sensitive` tag. Download is deliberately
	// infrastructure:WRITE, not read — revealing payload is not a read-level act.
	{"POST", "/api/devices/{id}/pcap", "Packet Capture", "Start a bounded on-device packet capture on one interface (infrastructure:write; 202 + capture id, 409 when one is already running, 400 naming the bound on a guardrail breach)"},
	{"GET", "/api/devices/{id}/pcap", "Packet Capture", "List a device's captures, newest first (infrastructure:read; 404 outside the caller's tenant)"},
	{"GET", "/api/devices/{id}/pcap/{capture_id}", "Packet Capture", "One capture's status: running | stored | failed, with packets, bytes and the filter it ran with"},
	{"GET", "/api/devices/{id}/pcap/{capture_id}/download", "Packet Capture", "Stream the unsealed capture as application/vnd.tcpdump.pcap (infrastructure:write; audited as a sensitive reveal)"},
	{"DELETE", "/api/devices/{id}/pcap/{capture_id}", "Packet Capture", "Delete a capture and its sealed blob (infrastructure:write; audited)"},
	// Interfaces grouped by routing instance (frontend-wave item 4,
	// internal/ifgroup). READ-ONLY: it collects nothing and invents nothing.
	// The routing-instance concept is carried by NO interface series on either
	// transport today — SNMP IF-MIB (the owner of every device_if_* family) has
	// no VRF column, and the gNMI interface subscriptions sit outside the
	// /network-instances tree that carries the instance name. So the response
	// reports coverage.vrf_labels=false and returns the interfaces UNGROUPED
	// with a note; it never fabricates a "default" group, because "every
	// interface is in the default instance" is a claim about the device that no
	// collected series supports. vrf_labels is PROBED per request, so the
	// grouping lights up by itself the day a deployment does collect it.
	{"GET", "/api/devices/{id}/interfaces/by-vrf", "Inventory", "One device's interfaces grouped by routing instance, in the device's own dialect (VRF | routing-instance | VPRN | VPN instance), with per-interface oper/admin state, in/out utilisation and error rates over ?window= (1m..24h, default 5m). Carries an honest coverage block: vrf_labels says whether any interface series actually carried a vrf label, transport names the lane (snmp is INFERRED from an absent transport stamp), and every absent measurement is null with a note rather than zero (infrastructure:read; 404 outside the caller's tenant, identical to an absent device)"},
	// Routing-protocol diagnostics (Troubleshooting item 7, internal/protocoldiag).
	// A version-pinned, hand-authored ruleset: 15 issues across BGP/OSPF/IS-IS,
	// each with a curated READ-ONLY command bundle rendered in the device's
	// dialect. Collect runs the bundle against one of the caller's OWN devices
	// (infrastructure:write, cross-tenant id → 404, audited `sensitive`) and
	// returns SECRET-REDACTED output; analyze and export are stateless
	// computations over operator-supplied text.
	{"GET", "/api/troubleshoot/protocol-diagnostics/catalog", "Troubleshooting", "The 15-issue BGP/OSPF/IS-IS matrix: symptoms, dialect coverage and the per-issue read-only command bundle. The rendered CLI dialect is chosen by ?vendor=<platform string> OR by ?device=<id> resolved in the caller's own inventory (cross-tenant/unknown id → 404); supplying both, or any other query parameter, is a 400 — a selector that changes which commands an operator is shown is never silently ignored"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/analyze", "Troubleshooting", "Run the failure signatures over supplied `show` output; returns the verdict + cause + remediation, or an honest \"no known signature matched\" (infrastructure:read). `analyzed:false` with `not_analyzed` set is the DISTINCT state for a request that carried no output at all — nothing was scored, so the protocol's state is unknown rather than clean"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/collect", "Troubleshooting", "Run an issue's read-only command bundle against one of the caller's own devices; output is secret-redacted (infrastructure:write; 503 when no command source is wired)"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/export", "Troubleshooting", "Assemble the redacted \"Send to TAC\" bundle from supplied outputs, optionally with the signature analysis folded in (infrastructure:read; audited)"},
	// TAC escalation pack (docs/design/TAC_ESCALATION_2026-09-05.md, internal/tac).
	// The six-step escalation an operator drives when an RCA is not confirmed:
	// classify from evidence Correlix already holds, plan the vendor commands,
	// collect them read-only, bundle the redacted evidence, open the case.
	// {id} is an incident id OR a correlation id, resolved in the CALLER'S OWN
	// scope — a foreign id and an unknown id answer the same 404.
	{"GET", "/api/incidents/{id}/tac", "Troubleshooting", "The escalation's state for one incident: classification, plan, collection job with per-command progress, stored bundles, case outcome, and the case connectors this tenant can actually use (infrastructure:read). An escalation started before an api restart is not resumed, and the response says so rather than showing an empty one"},
	{"POST", "/api/incidents/{id}/tac/classify", "Troubleshooting", "Classify the incident into the closed issue-class taxonomy from evidence Correlix already holds — RCA hypotheses, alerts, matched protocol signatures, the selected Iris skill, log excerpts. Returns the class, the exact evidence that scored it, every alternative that scored, and the full class list so an operator can override to any class. Nothing matched is an ANSWER (the `generic` class, stated plainly), not an error (infrastructure:read; audited)"},
	{"POST", "/api/incidents/{id}/tac/plan", "Troubleshooting", "Build the read-only command plan for a class on one of the caller's own devices: the vendor baseline set, the class deep-dive set, Correlix's own topology context, the size/time ceiling and the redaction note — shown BEFORE anything runs. Intents this dialect does not bind are listed as unbound; a platform with no authored plan runs nothing and says so rather than rendering another vendor's commands (infrastructure:read; audited)"},
	{"POST", "/api/incidents/{id}/tac/collect", "Troubleshooting", "Start the read-only collection over the SSH gateway, or fold in operator-pasted outputs, or cancel a running one. `steps[]` carries the operator-REVIEWED command list (with an optional `template_id`, whose name/version the server looks up so provenance cannot be forged): every line is re-validated here against the output-only policy and the read-only grammar, and ONE refused line fails the WHOLE request naming it — a collection never silently drops a command and runs the rest. Asynchronous: returns the job, whose per-command progress is polled from GET …/tac. One collection per device at a time (409); 503 when no read-only transport is wired — never a fabricated capture (infrastructure:write; audited)"},
	{"GET", "/api/incidents/{id}/tac/bundle", "Troubleshooting", "Download the redacted evidence bundle as a zip: MANIFEST.json, the problem statement written under the evidence-only rule, per-command outputs, the incident's evidence timeline, topology, device facts and SHA256SUMS. ?profile=full|email|link_only picks how much it carries; the email profile trims the largest outputs first and names every omission in the manifest (infrastructure:read; audited as sensitive)"},
	{"POST", "/api/incidents/{id}/tac/case", "Troubleshooting", "Pre-fill the vendor/ITSM case form (submit:false) or perform the human-approved submission (submit:true). Case creation is never automatic. A connector without a create capability returns the paste-ready portal text and says so — a successful outcome, not a failure (infrastructure:write; audited)"},
	// TAC command templates (tracker 250, owner 2026-09-05). The NOC admin sees
	// the exact command list before collect, edits it, and saves the set per
	// vendor dialect. Correlix ships defaults generated from the authored plans;
	// a tenant's own sets are per-tenant data. EVERY command, default or
	// customer-written, passes the output-only policy (config/restart/daemon
	// refused by name) and the read-only grammar before it can be saved or run.
	{"GET", "/api/tac/templates", "Troubleshooting", "This tenant's saved TAC command templates plus Correlix's read-only defaults, optionally narrowed to one CLI dialect with ?dialect=. Per-tenant data: a cross-tenant principal must scope into a tenant first, and another tenant's template is never listed (infrastructure:read)"},
	{"POST", "/api/tac/templates", "Troubleshooting", "Save a command set for one dialect. The owner is stamped from the token — the body has no tenant field — and every command is validated server-side before the row exists: config/restart/daemon commands are refused BY NAME with the family and the rule that hit, a ping/traceroute must be inside the bounded-probe limits, and everything else must pass the read-only grammar. A refusal returns per-line verdicts, never a bare \"invalid\" (infrastructure:write; audited)"},
	{"PUT", "/api/tac/templates/{id}", "Troubleshooting", "Replace a template's commands, name or description. Identity is immutable (id, owner, author, creation time, source) and the version increments, so a bundle can name the exact revision that ran. A Correlix default is read-only — 403 with the reason, and the operator saves a copy instead. Another tenant's id is a 404 (infrastructure:write; audited)"},
	{"GET", "/api/tac/templates/{id}", "Troubleshooting", "One template, with `diff_vs_default` when it was forked from a Correlix default and that default still ships. A cross-tenant or unknown id answers the same 404 (infrastructure:read)"},
	{"DELETE", "/api/tac/templates/{id}", "Troubleshooting", "Remove one of this tenant's templates. Correlix defaults cannot be deleted — they are generated from the authored plans, not stored rows (infrastructure:write; audited)"},
	{"GET", "/api/tac/templates/defaults", "Troubleshooting", "Correlix's own command templates, generated deterministically from the authored per-dialect plans: one baseline set per dialect plus one per issue class that dialect binds commands for. Reference data, identical for every tenant, immutable. ?dialect= narrows it; a platform with no authored plan honestly returns none rather than another vendor's commands (infrastructure:read)"},
	{"POST", "/api/tac/templates/validate", "Troubleshooting", "Per-line verdicts for a command list on one dialect — what the review step calls as the operator types. Each line reports ok/refused, the forbidden family and rule when the output-only policy refused it, and the origin of an accepted line: `catalog` (a rendering of an authored Correlix command) or `custom` (written by your team, output-only and read-only, never verified by Correlix on this platform). It reads nothing and stores nothing; the authoritative check still runs on the way into a template and on the way into a collection (infrastructure:read)"},
	{"GET", "/api/troubleshoot/tac/knowledge", "Troubleshooting", "Iris's TAC coverage: the issue-class taxonomy, the intent vocabulary, and per vendor dialect which intents are bound, which commands are verified against a real capture versus taken from vendor documentation, and which recognised platforms have NO authored plan at all. Version-pinned reference data, identical for every tenant (infrastructure:read)"},
	// OSPF / IS-IS advanced monitoring (Project 4 D item 11, internal/igpmon).
	// READ-ONLY: the module collects nothing and invents nothing. Adjacency
	// HISTORY comes from the typed syslog/trap adjacency-change signals on the
	// correlation spine (always available); adjacency STATE NOW comes from the
	// live series, which exists only where a collector actually emits one
	// (device_isis_adj_state over gNMI, device_ospf_nbr_state over SNMP
	// OSPF-MIB) — so on a deployment with no such device there is no live OSPF
	// series at all. LSDB/LSP counts, OSPF areas and IS-IS area addresses are
	// collected by NOTHING today.
	//
	// The coverage contract: every response carries coverage{events,
	// live_series, lsdb} and a `notes` list. A source that is not collected is
	// reported ABSENT — null plus a note naming why — NEVER as a zero and never
	// as "healthy". A fabricated "0 adjacencies down" from a protocol nobody is
	// watching is exactly the number an operator would wrongly act on.
	//
	// All three are per-tenant reads (infrastructure:read): events are read at
	// the caller's ClickHouse tenant_scope and every metrics read carries the
	// caller's device boundary as extra_filters[]. ?device= resolves through the
	// principal-scoped inventory, so a foreign id and an absent id both answer
	// 404 and existence is never revealed.
	{"GET", "/api/protocols/{proto}/adjacencies", "Protocols", "Per-adjacency OSPF/IS-IS view for {proto} = ospf | isis: live state where a series exists, plus the windowed change timeline from syslog/trap events, keyset-paged (?device=, ?since= 1m..7d, ?limit= 1..1000, ?cursor=). `up` is null for an event-only adjacency — history is not evidence of the state right now"},
	{"GET", "/api/protocols/{proto}/summary", "Protocols", "Fleet roll-up per device for {proto} = ospf | isis, worst-first by flap count (?since= 1m..7d, ?limit= 1..500). `adjacencies` / `down_adjacencies` are LIVE counts and are null without a live series; a partial roll-up says so in `notes` and `truncated`"},
	{"GET", "/api/protocols/{proto}/health", "Protocols", "One device's IGP health for {proto} = ospf | isis: neighbour/up/down counts (null without a live series), IS-IS levels, adjacency changes, flap count and a stability score that always carries the basis it was computed from. plus the depth blocks `lsdb` / `areas` / `spf_runs` / `timers`, each with its own coverage flag and each null + a note naming the absent series when nothing collects it — never 0 (?device= required, ?since= 1m..7d)"},
	// BMP receiver (internal/bmp) — the live BGP feed. Registered ONLY when
	// FEATURE_BMP=true, so a flag-off deployment 404s all three and the feature
	// is not enumerable. A router is configured (by a human, on the router) to
	// PUSH its Adj-RIB-In to the platform over TCP; nothing here configures a
	// device, and the whole surface is read-only.
	//
	// The honesty contract, carried as a `coverage` block on every response:
	// this is a BOUNDED MONITORING FEED of recent updates, NOT a converged RIB.
	// A prefix that is absent has simply not been seen recently. With no router
	// exporting, the answer is an empty feed that SAYS SO — never a zero-route
	// "converged" verdict. Dropped records (bounded ring), skipped frames and
	// undecoded address families are each counted and reported, so an
	// incomplete view is never presented as a complete one.
	//
	// All three are per-tenant reads (infrastructure:read). A session's tenant
	// is stamped at connect time from the inventory device its source address
	// resolves to; a source that resolves to nothing is refused rather than
	// stored untenanted. Only IPv4/IPv6 unicast is decoded (RFC 7854 +
	// RFC 4760); VPN/EVPN/flowspec families and ADD-PATH NLRI are counted as
	// unsupported, never partially decoded.
	{"GET", "/api/bgp/bmp/sessions", "Protocols", "BMP sessions the caller's routers have opened to the platform: router identity, up/closed state, per-peer BGP state (up | down | unknown — never an assumed up), message counts, dropped-update and parse-error counters"},
	{"GET", "/api/bgp/bmp/updates", "Protocols", "Recent per-prefix BGP updates from those sessions, newest first (?prefix= matches a prefix or anything inside it, ?peer=, ?session=, ?limit= 1..1000, ?cursor= opaque keyset). Announcements carry AS_PATH (AS4-merged), NEXT_HOP, ORIGIN, MED, LOCAL_PREF and communities incl. RFC 8092 large; a withdrawal carries none, because it has none"},
	{"GET", "/api/bgp/bmp/stats", "Protocols", "The caller's own BMP aggregate — sessions, peers, messages by type, updates held/dropped, parse errors — plus the receiver's hard bounds, so a non-zero dropped count can be read against what it was measured against"},
	{"GET", "/api/tunnels", "Telemetry", "Overlay tunnel telemetry (IPsec/SD-WAN/GRE)"},
	{"GET", "/api/flows/top", "Telemetry", "Top talkers (NetFlow/ClickHouse)"},
	{"POST", "/api/logs/search", "Telemetry", "Search logs (OpenSearch)"},
	{"GET", "/api/metrics/query", "Telemetry", "Instant PromQL query"},
	{"GET", "/api/metrics/query_range", "Telemetry", "Range PromQL query"},
	// Parser coverage (programme A6, parsercov/). The stats route is
	// platform-GLOBAL plumbing — engine counters for the whole fleet's parser,
	// not one tenant's rows — so it takes the platform-admin gate, while the
	// two /api/telemetry routes are per-tenant data read through
	// TenantIndexPattern + TenantFilter. The propose route APPLIES NOTHING: it
	// returns a drafted catalog row as text, which a human lands by pull
	// request against telemetry-catalog/events.yaml.
	// Pipeline debugger (design PIPELINE_DEBUGGER_2026-09-04). Platform admin
	// only; every trace record is tagged synthetic and excluded from the
	// customer-facing log search.
	{"POST", "/api/debug/trace", "Telemetry", "Inject ONE marked synthetic record (kind=syslog|trap|flow) into the stack's own ingress — never a device — and start the async follow; kind=gnmi is PASSIVE-ONLY (passive:true, device, since_seconds) and injects nothing, because a gNMI update originates on the device; returns the marker and a receipt (platform admin)"},
	{"GET", "/api/debug/trace/{marker}", "Telemetry", "Poll a trace's per-stage status: seen | not_seen | not_observable (with the reason) for the bus, the three stores, correlation and the api (platform admin)"},
	{"PUT", "/api/debug/loglevel", "Telemetry", "Raise one module to debug for a BOUNDED window (hard cap 30 minutes) with an auto-revert armed in the module's own process; a module with no runtime switch answers applied:false and says why, never a faked success (platform admin)"},
	{"GET", "/api/debug/stage/{stage}", "Telemetry", "One stage's evidence for a marker (kafka|opensearch|victoria|clickhouse|correlation|api, plus parser and ui on demand), with the exact query used (platform admin)"},
	{"PUT", "/api/debug/parsemarker", "Telemetry", "Arm the parser decision-trace filter on a needle for a BOUNDED window (hard cap 30 minutes) so a REAL, unmarked record's parse decisions are recorded; default-off and auto-disarming inside the traced process. An injected record carrying its own cx_debug marker is traced without this (platform admin)"},
	{"GET", "/api/debug/parsemarker", "Telemetry", "Report whether the parser decision-trace filter is armed and when it auto-disarms (platform admin)"},
	{"GET", "/api/debug/loglevel", "Telemetry", "Report each module's runtime log level and its armed auto-revert time — a LIVE reading for the switch this process owns, the last change requested through this api for the others, and the honest reason for a module that cannot be switched at runtime at all (platform admin)"},
	{"GET", "/api/debug/sessions", "Telemetry", "List the debug session directories this api has written, newest first: id, verb, kind, device, tenant, start time and the per-session verdict tally. An empty list always carries the reason it is empty (platform admin)"},
	{"GET", "/api/debug/sessions/{id}", "Telemetry", "One debug session: its manifest, timeline and human stage table, plus the module log files it holds (platform admin)"},
	{"GET", "/api/debug/sessions/{id}/module/{module}", "Telemetry", "One module's log file from a session, bounded in bytes and lines, with truncation stated rather than silent (platform admin)"},
	{"GET", "/api/debug/sessions/{id}/bundle", "Telemetry", "Download a session as a redacted, checksummed tar.gz — SHA256SUMS inside the archive and the body's own digest in X-Correlix-Bundle-SHA256 (platform admin)"},
	{"GET", "/api/admin/parser/stats", "Telemetry", "Parser rule corpus, per-rule hit counts, promotion rate and ingest pre-filter split, summed across the correlation replicas (platform admin)"},
	{"GET", "/api/telemetry/unrecognized", "Telemetry", "Mined templates of the caller's log lines the parser would not admit (days, limit, lane)"},
	{"POST", "/api/telemetry/unrecognized/{template_id}/propose", "Telemetry", "Draft a telemetry-catalog rule row and fixture for one unrecognized template — returned as text, applied nowhere (alerts:write)"},
	{"GET", "/api/users", "Identity", "List users (administration:admin)"},
	{"POST", "/api/users", "Identity", "Create a user (administration:admin)"},
	{"GET", "/api/roles", "Identity", "List roles + modules (administration:admin)"},
	{"GET", "/api/tenants", "Identity", "List tenants (administration:admin)"},
	{"GET", "/api/orgs", "Identity", "List organizations (administration:admin)"},
	{"POST", "/api/orgs", "Identity", "Create an organization (platform owner)"},
	{"GET", "/api/regions", "Identity", "List data-residency regions (administration:admin)"},
	{"GET", "/api/bindings", "Identity", "List role bindings the caller may see (administration:admin)"},
	{"POST", "/api/bindings", "Identity", "Grant a role binding — principal→role→scope (platform owner / org-admin)"},
	{"POST", "/api/breakglass", "Identity", "Open a time-boxed, audited break-glass session into a restricted tenant (platform operator)"},
	{"GET", "/api/apikeys", "Identity", "List API keys (administration:admin)"},
	{"POST", "/api/apikeys", "Identity", "Mint a scoped API key (administration:admin)"},
	{"GET", "/api/policy/catalog", "Security Policy", "NIST-aligned security-control catalog (administration:admin)"},
	{"GET", "/api/policy/effective", "Security Policy", "Resolve effective policy for a subject — the Policy Simulator (administration:admin)"},
	{"GET", "/api/policy/documents", "Security Policy", "List override documents visible to the caller (administration:admin)"},
	{"PUT", "/api/policy/document", "Security Policy", "Set a validated override at a scope; system/global = platform owner"},
	{"POST", "/api/policy/validate", "Security Policy", "Dry-run a proposed override against the write gate (administration:admin)"},
	{"GET", "/api/itsm/servicenow", "ITSM", "ServiceNow connector status + open tickets"},
	{"GET", "/api/itsm/jira", "ITSM", "Jira connector status + open issues"},
	// Data Protection — platform-GLOBAL backup plumbing, every route gated by
	// requirePlatformAdmin and every write audited (CLAUDE.md §3a rule 3: a
	// tenant/org admin holds administration:admin, so a scope-blind requireAdmin
	// on the platform's backup posture would be a privilege leak). Ledger
	// category "platform" in route_isolation_test.go.
	//
	// The whole group exists because of the 2026-08-27 incident: the snapshot
	// repository's blob tree was deleted out from under a registered repository
	// and NOTHING noticed for seven days — the GUI showed a policy, the policy
	// showed runs, and every restore point was silently unrestorable. So the
	// contract here is: the page can SEE the truth (per-engine coverage,
	// per-snapshot restorable-verified), and it can ACT on it (take, delete,
	// restore, verify, schedule) without an operator ever needing the admin
	// certificate or raw OpenSearch. The api proxies with the service identity;
	// the browser never talks to OpenSearch.
	//
	// Every long operation is ASYNC: the POST validates, enqueues and returns
	// 202 with an Operation, and the caller polls /api/system/backup/operations
	// /{id}. Nothing here blocks an HTTP handler on a multi-GiB restore.
	//
	// Honesty contract on every payload: a field we do not measure is `null`
	// with a sibling `*_detail` saying why. Never a fabricated zero, never a
	// blank that reads as "fine".
	{"GET", "/api/system/backup", "Data Protection", "Data-protection intent + live DR status (platform admin)"},
	{"PUT", "/api/system/backup", "Data Protection", "Update the off-host destination, transport, full-backup schedule and bundle retention (retain_count: how many artifacts the host keeps, 0..365, 0 = pruning off; OMIT the field to leave the stored retention unchanged — it is never cleared by a partial write). The host applier writes it to BACKUP_KEEP (platform admin, audited)"},
	{"GET", "/api/system/storage/measured", "Data Protection", "MEASURED bytes on disk, per store and per tenant where the store is tenant-partitioned at rest (tracker 204). Every number is read back from the store that owns the bytes by the query named in each reading's `source` — OpenSearch `_cat/indices` store.size (with `_nodes/stats/indices/store` as a platform-total-only fallback when the api's search account lacks indices:monitor/stats), ClickHouse `system.parts` bytes_on_disk grouped by table and partition (which carries the owning tenant, so the attribution is exact, and data_uncompressed_bytes beside it gives a MEASURED compression ratio), VictoriaMetrics' own vm_data_size_bytes, pg_database_size()/pg_total_relation_size(), and a walk of the api's own data directory. Kafka's log-directory size is NOT measurable from the api and says so. A store that could not be measured returns bytes_on_disk null plus a detail explaining why — never a zero, and never a figure derived from a rate times an assumed bytes-per-row; the derived sizing model lives in scripts/resource_planner.py and is labelled an estimate there. total_measured_bytes is a LOWER BOUND whenever unmeasured_stores is non-empty. Scoped: a tenant admin sees only its own tenant's bytes; a platform principal sees every tenant"},
	{"GET", "/api/system/backup/coverage", "Data Protection", "Per-engine backup coverage: OpenSearch snapshots, the Correlix system bundle, ClickHouse, Postgres, VictoriaMetrics, sealed secrets/TLS material and device config backups. Each engine reports covered yes|no|not_applicable|unknown WITH a reason, schedule + whether the GUI governs it, last attempt and last SUCCESS, last restorability verification, size, retention, target (local|remote|offsite|none) with immutable/encrypted flags, and the achieved RPO (age of the last good copy) judged against TWO separately-published numbers — rpo_target_hours, measured from the engine's own schedule, and rpo_objective_hours, the platform's DECLARED objective (24h per data store; 0 for the sealed custody material, whose envelope is change-driven rather than time-driven). Per-engine last_verified comes from the BUNDLE restore drill (scripts/backup-drill.sh), which restores a real artifact into disposable containers: a skipped or absent leg leaves the proof null with its reason, never green. Each store's row reflects its OWN component verdict inside the last bundle run (pass | partial | fail | skip), so a night on which only one store's copy failed no longer reports the rest as failed — or that one as covered. Anything not measured is null plus a *_detail explaining why — never a zero"},
	{"GET", "/api/system/backup/snapshots", "Data Protection", "The netops-daily Snapshot Management policy as the GUI renders it — enabled, schedule cron, retention (max_count / max_age_days), last run and next trigger — plus the repository's registration/verification state and, when the schedule is off, who turned it off and when"},
	{"PUT", "/api/system/backup/snapshots", "Data Protection", "Partial update of the snapshot schedule: enabled (rides the SM plugin's _start/_stop), schedule_cron (5 fields), retention_max_count (1..365), retention_max_age_days (0..3650, 0 = count-only). The stored GUI intent is authoritative — the opensearch-init bootstrap no longer re-enables a deliberately disabled policy (platform admin, audited)"},
	{"GET", "/api/system/backup/snapshots/list", "Data Protection", "Inventory of the repository's snapshots, newest first: name, state, indices, shard totals/failures with reasons, started/ended, duration, size, and the restorability verdict (verified true|false|null with when and why)"},
	{"POST", "/api/system/backup/snapshots/create", "Data Protection", "Take one snapshot now. The name is generated server-side against a closed grammar — never client-supplied. Returns 202 + an Operation to poll (platform admin, audited)"},
	{"POST", "/api/system/backup/snapshots/delete", "Data Protection", "Delete one snapshot. Type-to-confirm: `confirm` must equal `snapshot` exactly, the same guard the tenant delete uses. Returns 202 + an Operation (platform admin, audited)"},
	{"POST", "/api/system/backup/snapshots/restore", "Data Protection", "Restore a snapshot, or named indices from it. mode=renamed (default) restores under rename_prefix so nothing live is touched; mode=in_place overwrites the live indices and therefore REQUIRES the type-to-confirm token. Returns 202 + an Operation (platform admin, audited)"},
	{"POST", "/api/system/backup/snapshots/verify", "Data Protection", "Run the restorability probe on demand: restore the smallest index of the snapshot under a temporary name, compare doc counts against the source, delete the temporary index. Omit `snapshot` to probe the newest SUCCESS. Returns 202 + an Operation (platform admin, audited)"},
	{"GET", "/api/system/backup/operations", "Data Protection", "Recent snapshot operations (bounded ring, newest first) — kind, state, actor, target, progress, result, error"},
	{"GET", "/api/system/backup/operations/{id}", "Data Protection", "One operation's status; the poll target for every 202 above"},

	// ── Licence ──────────────────────────────────────────────────────────────
	// The signed licence file (ed25519, verified offline, no activation server
	// and no phone-home) that sets this deployment's commercial ceilings and
	// feature switches. There is ONE file per installation and it covers every
	// tenant on it, so the WRITES are platform-global (requirePlatformAdmin,
	// audited on both outcomes) while the READ is tenant-scoped
	// (requireAdmin): a tenant admin sees what that licence puts in force for
	// THEM — a projection with their own tenant's usage and none of the
	// provider's commercial or key material.
	//
	// Everywhere ELSE in this API, a capability the licence does not include
	// answers 402 with {error, ceiling|feature, unit, current, limit, tier,
	// lifted_by, licence_state, message} — never 403 (authorization is a
	// different question) and never a silently empty body. Ceilings that are
	// carried in the file but not enforced by this build say so in the payload
	// rather than being displayed as limits that bite.
	//
	// EXPIRY, GRACE AND OVERAGE (owner decision, 2026-09-05). `licence_state` on
	// a 402 is valid | in_grace | post_grace. In grace nothing changes at all.
	// Past grace, only CREATION and CONFIGURATION of paid capability refuse —
	// every GET/list/export of a licensed feature keeps working, so existing
	// data stays viewable and exportable, and the over-ceiling state is listed
	// rather than acted on. On Team and Enterprise the monitored-device ceiling
	// is SOFT: activation beyond it is allowed and recorded for true-up, never
	// refused; Community keeps the hard block at the 26th activation. No licence
	// state can affect isolation, RLS, authorization, integrity or sign-in.
	{"GET", "/api/system/licence", "Licence", "The licence in force, in ONE of two scopes decided by the caller, never by the request. scope=platform (the cross-tenant platform owner): customer, tier, ceilings with PLATFORM-WIDE usage and whether each is soft, the closed feature vocabulary with what is entitled, the expiry phase (valid | in_grace | post_grace) with days_to_expiry and grace_days_left, whether the licence is a trial, the over-ceiling items LISTED with when each overage began and the over-ceiling DEVICES named, the trusted public keys and the offline verification recipe. scope=tenant (any administration:admin caller, including a tenant/org admin, and the owner narrowed with as_tenant): tier, entitled features, the same ceilings with THIS TENANT'S OWN usage beside them, expiry state and managed_by — no customer, no licence id, no key material, no file path. No licence installed is a normal state and reports the Community ceilings, not an error"},
	{"PUT", "/api/system/licence", "Licence", "Install a licence document. The signature is verified BEFORE anything is written, so a refused upload never displaces a working licence and the exact reason is returned verbatim — an unknown signing key, a modified file and a malformed one are three different answers (platform admin, audited on both outcomes)"},
	{"DELETE", "/api/system/licence", "Licence", "Remove the installed licence and return to the Community ceilings. Nothing is deleted from the platform itself; devices and data over a Community ceiling are listed as not covered, never removed (platform admin, audited)"},
	{"GET", "/api/system/licence/usage", "Licence", "Recorded USAGE for a period — a separate data contract from the licence itself: entitlement says what a customer may do, this says what they actually consumed. Daily per-tenant rows (UTC day) with unique and peak monitored devices counted from CONFIGURATION rather than from telemetry activity, watched prefixes, tenant/org counts and the configured retention windows, plus diagnostic meters (metric samples and series, log and flow records accepted after processing, experience checks, hosted-AI tokens, pipeline in/out ratio). A meter with no counter on this installation is null with the reason beside it, never a zero. Scope is decided by the caller, never by the request: a tenant/org admin gets their own tenant, the platform owner gets every tenant plus the installation row and may narrow with ?tenant=; a scoped caller naming another tenant gets 404. from/to are UTC days and default to the last 30. Nothing is ever sent anywhere: there is no phone-home"},
	{"GET", "/api/system/licence/usage/report", "Licence", "The same period as a SIGNED JSON document, for download. Carries the daily rows as well as the totals so the arithmetic can be redone independently, the meter definitions so it explains its own columns, and an ed25519 signature over canonical bytes (sorted keys, no whitespace, UTF-8) made by a per-INSTALLATION key generated at first use and stored beside the licence — never Correlix's licence signing key, which does not exist on a customer host. The public key travels in the document, so `correlix-licence usage-verify <file>` checks it offline with nothing else. Same scoping as the usage read; a tenant's report carries no customer name and no licence id. Audited on both outcomes"},
	{"POST", "/api/graphql", "Query", "GraphQL endpoint (devices/alerts/findings/health)"},
	{"POST", "/api/internal/vmalert/api/v2/alerts", "Internal", "Alertmanager-v2 webhook receiver for the vmalert evaluator (shared-secret; platform-global, not a tenant surface)"},
}

// Spec builds the OpenAPI document. Pure: it takes the build version rather
// than reading a package-main global, so the document can be generated and
// asserted without standing up a server. The HTTP handler stays in package
// main, where the routing layer belongs (CLAUDE.md §2).
func Spec(version string) map[string]any {
	paths := map[string]any{}
	for _, rt := range apiRoutes {
		op := map[string]any{
			"tags":    []string{rt.tag},
			"summary": rt.summary,
			"responses": map[string]any{
				"200": map[string]any{"description": "OK"},
				"401": map[string]any{"description": "Unauthorized"},
			},
		}
		entry, ok := paths[rt.path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[rt.path] = entry
		}
		entry[lowerMethod(rt.method)] = op
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "NetOps Observability API",
			"version":     version,
			"description": "API-first network observability. Authenticate with a Bearer JWT (interactive) or a scoped API key via Authorization: Bearer ntk_… / X-API-Key.",
		},
		"servers": []any{map[string]any{"url": "/"}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
				"apiKey":     map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key"},
			},
		},
		"security": []any{
			map[string]any{"bearerAuth": []any{}},
			map[string]any{"apiKey": []any{}},
		},
		"paths": paths,
	}
	return doc
}

func lowerMethod(m string) string {
	switch m {
	case "GET":
		return "get"
	case "POST":
		return "post"
	case "PUT":
		return "put"
	case "PATCH":
		return "patch"
	case "DELETE":
		return "delete"
	default:
		return "get"
	}
}
