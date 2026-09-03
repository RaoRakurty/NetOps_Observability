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
	{"GET", "/api/troubleshoot/protocol-diagnostics/catalog", "Troubleshooting", "The 15-issue BGP/OSPF/IS-IS matrix: symptoms, dialect coverage and the per-issue read-only command bundle (?vendor= picks the rendered dialect)"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/analyze", "Troubleshooting", "Run the failure signatures over supplied `show` output; returns the verdict + cause + remediation, or an honest \"no known signature matched\" (infrastructure:read)"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/collect", "Troubleshooting", "Run an issue's read-only command bundle against one of the caller's own devices; output is secret-redacted (infrastructure:write; 503 when no command source is wired)"},
	{"POST", "/api/troubleshoot/protocol-diagnostics/export", "Troubleshooting", "Assemble the redacted \"Send to TAC\" bundle from supplied outputs, optionally with the signature analysis folded in (infrastructure:read; audited)"},
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
