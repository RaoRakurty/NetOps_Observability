package main

// rca_observer_registry.go — the observer classification registry (Phase B).
//
// Every observer of a signal is classified into exactly one KIND so the evidence
// accounting can say, honestly, how many logical vantages vs control-plane
// sources vs collectors an incident actually rests on. The registry is the ONE
// place that decides kind; the accounting and (later) presentation layers consume
// its verdict — they never re-infer from a name.
//
// Owner constraints this file enforces (rca-evidence-accounting-plan.md):
//   - Constraint 1: an UNCLASSIFIED observer renders as explicitly `unknown`,
//     NEVER silently a collector or a vantage. `unknown` is default-closed — it
//     can never inflate a vantage or independence count.
//   - Hard rule: `api`, collector/transport identities and worker/process names
//     can NEVER be `logical_vantage`, even if a policy tries to say so. A logical
//     vantage is a real measurement origin (a probe agent at a real location), not
//     the platform's own API container or a data-collection worker.
//
// Policy precedence (canonical → default):
//  1. per-tenant STRUCTURED policy (canonical; injected — UI editor deferred);
//  2. global env/config defaults;
//  3. structural default derived from (modality, probe authority);
//  4. otherwise `unknown`.
// The never-vantage hard rule is applied AFTER precedence: a policy or default
// that maps a denylisted identity to a vantage is downgraded to `collector`.

import (
	"os"
	"strings"
)

// observerKind is the classification of a signal observer. The four kinds are a
// closed set — anything not positively one of the first three is `unknown`.
type observerKind string

const (
	// observerLogicalVantage — a real measurement origin: a probe/synthetic agent
	// running at a real (customer/enterprise/cloud) location. Only these count as
	// "vantages" in the report. NEVER the API container or a collector.
	observerLogicalVantage observerKind = "logical_vantage"
	// observerControlPlaneSource — a device/controller reporting protocol or
	// tunnel/routing state (control_plane / management_plane modality).
	observerControlPlaneSource observerKind = "control_plane_source"
	// observerCollector — the platform's own data collection/transport identity
	// (api, vector/telegraf/goflow, snmp/gnmi/netconf pollers, flow exporters,
	// device-telemetry readers). A legitimate evidence source, but not a vantage.
	observerCollector observerKind = "collector"
	// observerUnknown — identity/kind could not be established. Default-closed:
	// counts as neither a vantage nor a control-plane source; never confirm-eligible
	// on kind alone (constraint 1).
	observerUnknown observerKind = "unknown"
)

// observerFacts is the minimal, provenance-only view of an observer the registry
// classifies from. All fields come from the stored signal (never invented).
type observerFacts struct {
	ObserverID     string // corr_signals.observer_id
	ObserverType   string // corr_signals.observer_type (a HINT only — api is mis-stamped vantage_agent)
	Modality       string // corr_signals.modality_class
	ProbeAuthority string // attrs.probe_authority (high|medium|low|debug_only) — probe lanes only
}

// observerRegistry classifies observers per tenant. The per-tenant policy is the
// canonical source; env/config supplies global defaults only. Safe for
// concurrent reads (all maps are built once at construction and never mutated).
type observerRegistry struct {
	// perTenant[tenant][observerID] = kind — the canonical structured policy.
	// A tenant only ever sees its OWN entry; policies never leak across tenants.
	perTenant map[string]map[string]observerKind
	// defaults[observerID] = kind — global env/config default overrides.
	defaults map[string]observerKind
	// neverVantage — identities that can NEVER be a logical vantage (hard rule):
	// exact ids plus substring markers (worker/collector/process names).
	neverVantageIDs     map[string]bool
	neverVantageMarkers []string
}

// defaultNeverVantageIDs — platform/collector identities that are never a logical
// vantage. `api` is the canonical case (mis-stamped observer_type=vantage_agent at
// ingest — wave #7 dropped its TRUST, not its TYPE). Overridable via env.
var defaultNeverVantageIDs = []string{
	"api", "backend", "correlation", "collector",
	"vector", "telegraf", "goflow", "goflow2",
	"snmp", "gnmi", "netconf", "syslog", "otel", "otel-collector",
}

// defaultNeverVantageMarkers — substring markers of collector/worker/process
// identities. A vantage is a place; a worker is a process — the latter never a
// vantage.
var defaultNeverVantageMarkers = []string{
	"-worker", "worker-", "collector", "-exporter", "exporter-",
	"-poller", "poller-", "-agent-internal", "sidecar",
}

// newObserverRegistry builds the registry. `perTenant` is the canonical per-tenant
// policy (may be nil). Global defaults + the never-vantage denylist are read from
// env: CORR_OBSERVER_KIND_DEFAULTS ("id:kind,id:kind") and
// CORR_NEVER_VANTAGE_OBSERVERS ("id,id"). Env only ADDS to the built-in denylist.
func newObserverRegistry(perTenant map[string]map[string]observerKind) *observerRegistry {
	r := &observerRegistry{
		perTenant:           map[string]map[string]observerKind{},
		defaults:            map[string]observerKind{},
		neverVantageIDs:     map[string]bool{},
		neverVantageMarkers: append([]string{}, defaultNeverVantageMarkers...),
	}
	for t, m := range perTenant {
		cp := make(map[string]observerKind, len(m))
		for id, k := range m {
			cp[strings.ToLower(strings.TrimSpace(id))] = k
		}
		r.perTenant[t] = cp
	}
	for _, id := range defaultNeverVantageIDs {
		r.neverVantageIDs[id] = true
	}
	for _, id := range splitEnvList(os.Getenv("CORR_NEVER_VANTAGE_OBSERVERS")) {
		r.neverVantageIDs[id] = true
	}
	for _, pair := range splitEnvList(os.Getenv("CORR_OBSERVER_KIND_DEFAULTS")) {
		id, kind, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		if k, valid := parseObserverKind(kind); valid {
			r.defaults[strings.ToLower(strings.TrimSpace(id))] = k
		}
	}
	return r
}

// splitEnvList parses a comma-separated env value into a lowercased, trimmed,
// non-empty slice.
func splitEnvList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseObserverKind validates a kind string. Only the three positively-assignable
// kinds are accepted from policy/config — `unknown` is never *assigned*, only
// derived by absence.
func parseObserverKind(s string) (observerKind, bool) {
	switch observerKind(strings.ToLower(strings.TrimSpace(s))) {
	case observerLogicalVantage:
		return observerLogicalVantage, true
	case observerControlPlaneSource:
		return observerControlPlaneSource, true
	case observerCollector:
		return observerCollector, true
	}
	return observerUnknown, false
}

// isNeverVantage reports whether an identity is barred from being a logical
// vantage (the hard rule). Case-insensitive; matches exact ids and process markers.
func (r *observerRegistry) isNeverVantage(observerID string) bool {
	id := strings.ToLower(strings.TrimSpace(observerID))
	if r.neverVantageIDs[id] {
		return true
	}
	for _, m := range r.neverVantageMarkers {
		if strings.Contains(id, m) {
			return true
		}
	}
	return false
}

// classify returns the kind of one observer for one tenant. Deterministic and
// side-effect free. Applies policy precedence, then the never-vantage hard rule.
func (r *observerRegistry) classify(tenant string, f observerFacts) observerKind {
	id := strings.ToLower(strings.TrimSpace(f.ObserverID))
	kind := observerUnknown

	// 1) per-tenant canonical policy (only THIS tenant's map is consulted).
	if pol, ok := r.perTenant[tenant]; ok {
		if k, ok := pol[id]; ok {
			kind = k
		}
	}
	// 2) global default override.
	if kind == observerUnknown {
		if k, ok := r.defaults[id]; ok {
			kind = k
		}
	}
	// 3) structural default from modality + probe authority.
	if kind == observerUnknown {
		kind = r.structuralKind(f)
	}

	// 4) hard rule (constraint): a denylisted identity can never be a vantage,
	// whatever policy/default/structure said. Downgrade to collector — a
	// misconfigured policy can weaken a claim, never inflate one.
	if kind == observerLogicalVantage && r.isNeverVantage(id) {
		kind = observerCollector
	}
	return kind
}

// structuralKind is the fail-closed default when nothing classified the observer.
//   - control_plane / management_plane → control_plane_source
//   - device_telemetry / passive_flow → collector
//   - active_probe with a trusted (high/medium) authority AND not denylisted →
//     logical_vantage; a low/debug/unclassified probe → `unknown` (we cannot tell
//     whether it is a real vantage; constraint 1 forbids guessing it is one).
//   - anything else → unknown.
func (r *observerRegistry) structuralKind(f observerFacts) observerKind {
	switch strings.ToLower(strings.TrimSpace(f.Modality)) {
	case "control_plane", "management_plane":
		return observerControlPlaneSource
	case "device_telemetry", "passive_flow", "active_verification":
		// active_verification (RCA spec item 8): the witness is the answering
		// device (or the platform executor for reach probes) — never a
		// logical vantage.
		return observerCollector
	case "active_probe":
		if r.isNeverVantage(f.ObserverID) {
			return observerCollector
		}
		switch strings.ToLower(strings.TrimSpace(f.ProbeAuthority)) {
		case "high", "medium":
			return observerLogicalVantage
		default:
			return observerUnknown
		}
	}
	return observerUnknown
}
