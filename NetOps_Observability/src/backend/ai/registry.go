// Package ai is the Correlix AI platform: an application-aware, evidence-grounded
// NOC assistant. It turns a natural-language question into a governed plan
// (intent → module routing → read-only tool selection → cited evidence bundle →
// LLM answer in a typed answer-mode schema), enforcing tenant/RBAC + module
// availability throughout. See docs/design/correlix-ai-hld.md.
//
// Design notes:
//   - The package depends only on INTERFACES (LLMClient, DataSource), never on
//     the http server, so it imports cleanly and is unit-testable with mocks.
//   - v1 is strictly READ-ONLY. No write/device tools live here; controlled
//     actions are a separate, human-gated subsystem (HLD P6) the model can't call.
//   - "copilot" is being retired as a name; user-facing is "Correlix AI".
package ai

import "strings"

// Freshness states how current a module's/tool's data is, so the router can pick
// tools by what the question needs (live status vs. historical postmortem).
type Freshness string

const (
	FreshnessLive       Freshness = "live"       // current health, active incidents, topology status
	FreshnessRecent     Freshness = "recent"     // last 15m/1h/24h telemetry/flow summaries
	FreshnessHistorical Freshness = "historical" // reports, prior problems, postmortems
	FreshnessConfig     Freshness = "config"     // tenant settings, integrations, availability
)

// Sensitivity tags how careful we must be with a module's data in a prompt.
type Sensitivity string

const (
	SensitivityOperational Sensitivity = "operational"
	SensitivitySensitive   Sensitivity = "sensitive"
	SensitivityRestricted  Sensitivity = "restricted"
)

// Availability marks whether a module's product surface exists yet.
type Availability string

const (
	AvailabilityStable Availability = "stable" // real surface backed by repo data
	AvailabilityFuture Availability = "future" // registered placeholder; answers with a clean "not available yet"
)

// Module is one entry in the Application Knowledge Layer: what a Correlix module
// is, what it owns, what questions it answers, and which governed tools + perms
// it exposes. This is code (not docs) so the orchestrator routes against it.
type Module struct {
	ID                 string       `json:"module_id"`
	DisplayName        string       `json:"display_name"`
	Description        string       `json:"description"`
	Entities           []string     `json:"entities"`
	QuestionCategories []string     `json:"question_categories"`
	Tools              []string     `json:"tools"`
	Permissions        []string     `json:"permissions"` // RBAC/PBAC gate (any-of)
	Freshness          Freshness    `json:"freshness"`
	Sensitivity        Sensitivity  `json:"sensitivity"`
	Availability       Availability `json:"availability"`
	AvailabilityFlag   string       `json:"availability_flag,omitempty"` // env flag; "" = always on
	CrossModule        []string     `json:"cross_module"`
	ResponseModes      []string     `json:"response_modes"`
}

// FlagLookup answers "is this feature flag on for this tenant?" The server wires
// it to real feature flags / tenant config; tests pass a stub.
type FlagLookup func(flag string) bool

// modules is the Module Registry. P1 implements the correlations_rca tools for
// real; other modules are registered so the router knows they exist and can route
// (their tools stub cleanly until their phase lands — HLD P2–P4).
var modules = []Module{
	{
		ID: "command_center", DisplayName: "Command Center",
		Description:        "The NOC's at-a-glance state: current health, active major incidents, the priority action queue, and top impacted services/sites.",
		Entities:           []string{"health_summary", "action_item", "priority_queue", "impacted_service", "impacted_site"},
		QuestionCategories: []string{"current_state", "noc_priority", "active_incidents", "top_impacted"},
		Tools:              []string{"get_current_health_summary", "get_active_major_incidents", "get_noc_priority_queue", "get_top_impacted_services", "get_top_impacted_sites"},
		Permissions:        []string{"correlations:read", "infrastructure:read"},
		Freshness:          FreshnessLive, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"correlations_rca", "event_management", "topology", "itsm"},
		ResponseModes: []string{"current_state_summary", "module_health_summary"},
	},
	{
		ID: "event_management", DisplayName: "Event Management",
		Description:        "Events, incidents, anomalies, correlations, and RCA problem groups.",
		Entities:           []string{"event", "incident", "anomaly", "correlation_group", "problem"},
		QuestionCategories: []string{"active_incidents", "problem_explanation", "outage_summary", "event_noise", "missing_evidence", "recommended_owner"},
		Tools:              []string{"get_active_major_incidents", "get_problem", "get_problem_timeline", "get_problem_evidence", "get_related_events", "get_recommended_owner"},
		Permissions:        []string{"events:read", "correlations:read"},
		Freshness:          FreshnessLive, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"correlations_rca", "topology", "itsm", "app_identification"},
		ResponseModes: []string{"problem_explanation", "current_state_summary", "missing_evidence_explanation"},
	},
	{
		ID: "correlations_rca", DisplayName: "Correlations & RCA",
		Description:        "Root-cause analysis: correlation groups (problems), their evidence ledger, timeline, candidate root domains, missing evidence, and recommended owner.",
		Entities:           []string{"problem", "correlation_group", "evidence", "hypothesis", "owner"},
		QuestionCategories: []string{"problem_explanation", "evidence", "missing_evidence", "recommended_owner", "root_domain"},
		Tools:              []string{"get_problem", "get_problem_timeline", "get_problem_evidence", "get_candidate_root_domains", "get_missing_evidence", "get_recommended_owner"},
		Permissions:        []string{"correlations:read"},
		Freshness:          FreshnessLive, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"topology", "telemetry", "flow_analytics", "itsm"},
		ResponseModes: []string{"problem_explanation", "evidence_explanation", "missing_evidence_explanation"},
	},
	{
		ID: "topology", DisplayName: "Topo",
		Description:        "Network/service topology: paths, neighbors, dependency maps, and blast radius for an incident.",
		Entities:           []string{"node", "link", "path", "service_dependency", "blast_radius"},
		QuestionCategories: []string{"topology_path", "blast_radius", "neighbors", "dependency"},
		Tools:              []string{"get_topology_path", "get_entity_neighbors", "get_service_dependency_map", "get_blast_radius", "explain_topology_path"},
		Permissions:        []string{"infrastructure:read"},
		Freshness:          FreshnessLive, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"correlations_rca", "flow_analytics"},
		ResponseModes: []string{"topology_path_explanation", "investigation_plan"},
	},
	{
		ID: "cloud_app_observability", DisplayName: "Cloud App Observability",
		Description:        "SaaS / cloud application health, dependency paths, and anomalies.",
		Entities:           []string{"cloud_app", "saas_dependency", "cloud_anomaly"},
		QuestionCategories: []string{"cloud_app_health", "saas_impact", "cloud_dependency"},
		Tools:              []string{"get_cloud_app_health", "get_saas_impact_summary", "get_cloud_dependency_path", "get_cloud_app_anomalies"},
		Permissions:        []string{"applications:read"},
		Freshness:          FreshnessRecent, Sensitivity: SensitivityOperational, Availability: AvailabilityFuture,
		AvailabilityFlag: "ENABLE_CLOUD_APP_OBS",
		CrossModule:      []string{"app_identification", "flow_analytics", "topology"},
		ResponseModes:    []string{"module_health_summary", "investigation_plan"},
	},
	{
		ID: "app_identification", DisplayName: "App Identification",
		Description:        "Application identity enrichment: app-name matches, confidence, vendor catalog matches.",
		Entities:           []string{"app_identity", "confidence_match", "vendor_match"},
		QuestionCategories: []string{"app_identity", "low_confidence", "vendor_match"},
		Tools:              []string{"get_app_identity_summary", "get_low_confidence_app_matches", "explain_app_identification", "get_vendor_catalog_match"},
		Permissions:        []string{"applications:read"},
		Freshness:          FreshnessRecent, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"flow_analytics", "cloud_app_observability"},
		ResponseModes: []string{"module_health_summary", "evidence_explanation"},
	},
	{
		ID: "telemetry", DisplayName: "Telemetry",
		Description:        "Device telemetry: metric anomalies, syslog, SNMP traps, probe health, interface health.",
		Entities:           []string{"metric", "syslog", "snmp_trap", "probe", "interface"},
		QuestionCategories: []string{"metric_anomaly", "syslog_summary", "trap_summary", "probe_health", "interface_health"},
		Tools:              []string{"get_metric_anomalies", "get_syslog_summary", "get_snmp_trap_summary", "get_probe_health", "get_interface_health"},
		Permissions:        []string{"infrastructure:read"},
		Freshness:          FreshnessRecent, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"correlations_rca", "topology"},
		ResponseModes: []string{"module_health_summary", "investigation_plan"},
	},
	{
		ID: "flow_analytics", DisplayName: "Flow Analytics",
		Description:        "NetFlow/IPFIX/sFlow analytics: flow summaries, app-to-DB flows, top talkers, east-west anomalies, retransmissions.",
		Entities:           []string{"flow", "talker", "conversation", "app_to_db_flow"},
		QuestionCategories: []string{"flow_summary", "app_to_db", "top_talkers", "east_west_anomaly", "retransmission"},
		Tools:              []string{"get_flow_summary", "get_app_to_db_flow_summary", "get_top_talkers", "get_east_west_flow_anomalies", "get_retransmission_or_retry_summary"},
		Permissions:        []string{"flows:read"},
		Freshness:          FreshnessRecent, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"app_identification", "topology", "correlations_rca"},
		ResponseModes: []string{"module_health_summary", "investigation_plan"},
	},
	{
		ID: "itsm", DisplayName: "ITSM",
		Description:        "IT service management: related tickets, ticket status, sync status, and ITSM-ready updates.",
		Entities:           []string{"ticket", "incident_record", "sync_status"},
		QuestionCategories: []string{"related_tickets", "ticket_status", "itsm_update", "sync_status"},
		Tools:              []string{"get_related_tickets", "get_ticket_status_summary", "generate_itsm_update", "get_ticket_sync_status"},
		Permissions:        []string{"incident:read"},
		Freshness:          FreshnessLive, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"correlations_rca", "integrations"},
		ResponseModes: []string{"itsm_update", "module_health_summary"},
	},
	{
		ID: "reports", DisplayName: "Reports",
		Description:        "Operational reports: shift summaries, daily summaries, executive summaries.",
		Entities:           []string{"report", "summary"},
		QuestionCategories: []string{"shift_summary", "daily_summary", "executive_summary"},
		Tools:              []string{"generate_shift_summary", "generate_daily_summary", "generate_executive_summary"},
		Permissions:        []string{"reports:read"},
		Freshness:          FreshnessHistorical, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"command_center", "correlations_rca", "itsm"},
		ResponseModes: []string{"shift_handoff", "executive_summary", "time_range_outage_summary"},
	},
	{
		ID: "integrations", DisplayName: "Integrations",
		Description:        "Connector health: ServiceNow / Slack / PagerDuty sync + delivery status.",
		Entities:           []string{"integration", "connector", "delivery"},
		QuestionCategories: []string{"integration_health", "servicenow_sync", "slack_delivery", "pagerduty_sync"},
		Tools:              []string{"get_integration_health", "get_servicenow_sync_status", "get_slack_delivery_status", "get_pagerduty_sync_status"},
		Permissions:        []string{"administration:read"},
		Freshness:          FreshnessConfig, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		CrossModule:   []string{"itsm"},
		ResponseModes: []string{"module_health_summary"},
	},
	{
		ID: "tenant_admin", DisplayName: "Tenant Administration",
		Description:        "Tenant-scoped administration surface (configuration & module availability).",
		Entities:           []string{"tenant", "module_availability", "setting"},
		QuestionCategories: []string{"module_availability", "tenant_settings"},
		Tools:              []string{"get_enabled_modules", "get_tenant_ai_usage"},
		Permissions:        []string{"administration:read"},
		Freshness:          FreshnessConfig, Sensitivity: SensitivitySensitive, Availability: AvailabilityStable,
		CrossModule:   []string{"audit"},
		ResponseModes: []string{"module_health_summary"},
	},
	{
		ID: "audit", DisplayName: "Audit",
		Description:        "AI audit + policy events: who asked what, which tools ran, policy decisions.",
		Entities:           []string{"ai_audit", "policy_event"},
		QuestionCategories: []string{"ai_audit", "policy_events", "ai_usage"},
		Tools:              []string{"get_ai_audit_summary", "get_tenant_ai_usage", "get_policy_events"},
		Permissions:        []string{"administration:read"},
		Freshness:          FreshnessRecent, Sensitivity: SensitivitySensitive, Availability: AvailabilityStable,
		CrossModule:   []string{"tenant_admin"},
		ResponseModes: []string{"module_health_summary"},
	},
	{
		ID: "product_navigation", DisplayName: "Product Navigation",
		Description:        "Helps users find features: maps a capability to its UI route, required permission, and a short explanation.",
		Entities:           []string{"feature", "ui_route"},
		QuestionCategories: []string{"where_is", "how_do_i", "navigation"},
		Tools:              []string{"find_feature"},
		Permissions:        nil, // navigation help itself needs no data permission
		Freshness:          FreshnessConfig, Sensitivity: SensitivityOperational, Availability: AvailabilityStable,
		ResponseModes: []string{"product_navigation_help"},
	},
}

var moduleIndex = func() map[string]Module {
	m := make(map[string]Module, len(modules))
	for _, mod := range modules {
		m[mod.ID] = mod
	}
	return m
}()

// Modules returns a copy of the Module Registry (the Application Knowledge Layer).
func Modules() []Module {
	out := make([]Module, len(modules))
	copy(out, modules)
	return out
}

// ModuleByID looks up a module; ok=false if unknown.
func ModuleByID(id string) (Module, bool) {
	m, ok := moduleIndex[id]
	return m, ok
}

// IsModuleEnabled reports whether a module is available for this tenant: it must
// be a stable surface AND (if it gates on a feature flag) that flag must be on.
// Future-marked modules are never "enabled" (they answer with a disclosure).
func IsModuleEnabled(id string, flags FlagLookup) bool {
	m, ok := moduleIndex[id]
	if !ok || m.Availability != AvailabilityStable {
		return false
	}
	if m.AvailabilityFlag != "" {
		if flags == nil {
			return false
		}
		return flags(m.AvailabilityFlag)
	}
	return true
}

// EnabledModules returns the ids of modules currently available to the tenant.
func EnabledModules(flags FlagLookup) []string {
	var out []string
	for _, m := range modules {
		if IsModuleEnabled(m.ID, flags) {
			out = append(out, m.ID)
		}
	}
	return out
}

// ProductNavEntry maps a feature to where it lives in the UI.
type ProductNavEntry struct {
	Feature       string `json:"feature"`
	UIRoute       string `json:"ui_route"`
	RequiredPerm  string `json:"required_permission"`
	Explanation   string `json:"explanation"`
	RelatedModule string `json:"related_module"`
}

// productNav is the static navigation map (HLD §3.3) — real route ids so the AI
// can answer "where do I …?" with a clickable deep link.
var productNav = []ProductNavEntry{
	{"Correlation evidence / RCA", "#/monitoring/correlations", "correlations:read", "Open an RCA candidate to see its evidence ledger and verdict.", "correlations_rca"},
	{"Missing evidence", "#/monitoring/correlations", "correlations:read", "A candidate lists exactly which evidence streams are missing.", "correlations_rca"},
	{"Topology path for an incident", "#/infrastructure/topology-canvas", "infrastructure:read", "Open Topo and focus the incident's path.", "topology"},
	{"Command Center / NOC queue", "#/dashboards/home", "correlations:read", "The action queue with RCA verdict, owner and ticket state.", "command_center"},
	{"Generate a report", "#/monitoring/reports", "reports:read", "Use Guided Report Setup to pick an outcome, schedule and recipients.", "reports"},
	{"Configure ServiceNow", "#/incident/integrations", "administration:read", "Set up the ServiceNow connector under Incident Response → Integrations.", "integrations"},
	{"App identification confidence", "#/monitoring/appobs", "applications:read", "Service View shows app-identity matches and confidence.", "app_identification"},
	{"Flow analytics", "#/flows", "flows:read", "Top talkers, conversations, ports, protocols and geo.", "flow_analytics"},
	{"Logs", "#/explore/logs", "logs:read", "Log Search over syslog, traps, app logs and flows.", "telemetry"},
	{"Devices / inventory", "#/infrastructure/devices", "infrastructure:read", "Inventory with live health; click a device for its status.", "telemetry"},
}

// FindFeature returns nav entries whose feature/explanation match the query terms.
func FindFeature(query string) []ProductNavEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	var out []ProductNavEntry
	for _, e := range productNav {
		hay := strings.ToLower(e.Feature + " " + e.Explanation + " " + e.RelatedModule)
		match := false
		for _, t := range terms {
			if strings.Contains(hay, t) {
				match = true
				break
			}
		}
		if match {
			out = append(out, e)
		}
	}
	return out
}
