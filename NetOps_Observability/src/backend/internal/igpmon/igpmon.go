// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ── protocol ────────────────────────────────────────────────────────────────

// Proto is one of the two interior gateway protocols this module serves.
type Proto string

const (
	// ProtoOSPF is OSPFv2 — event-covered everywhere, live-series covered only
	// where an SNMP device answers OSPF-MIB ospfNbrTable.
	ProtoOSPF Proto = "ospf"
	// ProtoISIS is IS-IS — event-covered everywhere, live-series covered on the
	// gNMI fabric (Nokia SR Linux native adjacency state).
	ProtoISIS Proto = "isis"
)

// ProtoFrom parses a URL path segment into a Proto. Unknown values are refused
// rather than defaulted: guessing which protocol the operator meant is how a
// dashboard ends up showing IS-IS health under an OSPF heading.
func ProtoFrom(s string) (Proto, bool) {
	switch Proto(strings.ToLower(strings.TrimSpace(s))) {
	case ProtoOSPF:
		return ProtoOSPF, true
	case ProtoISIS:
		return ProtoISIS, true
	default:
		return "", false
	}
}

// Kind is the corr_signals `kind` the protocol's adjacency changes are typed as.
func (p Proto) Kind() string {
	if p == ProtoOSPF {
		return "ospf_adjacency_change"
	}
	return "isis_adjacency_change"
}

// AdjMetric is the canonical adjacency-state series name (normalization.yaml /
// the SNMP standard profile). It may legitimately have ZERO series on a given
// deployment — that is what coverage.live_series reports.
func (p Proto) AdjMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_nbr_state"
	}
	return "device_isis_adj_state"
}

// LSDBMetric is the series name an LSDB/LSP-count would land under IF a
// collector ever emitted one. Nothing emits it today on either transport, so
// the query is expected to return no series and the response reports
// coverage.lsdb=false. It is queried rather than hardcoded to false so the
// feature lights up by itself the day the series exists — with no code change
// and, critically, no window in which the UI shows a fabricated count.
func (p Proto) LSDBMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_lsdb_count"
	}
	return "device_isis_lsp_count"
}

// AreaMetric is the canonical area-membership INFO series: one sample per area
// the router participates in, the area itself carried in the `area` label and
// the value a constant placeholder (1 on the gNMI lane, the OSPF-MIB RowStatus
// on the SNMP one). Consumers read the LABEL and must never read the value as a
// measurement.
func (p Proto) AreaMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_area"
	}
	return "device_isis_area"
}

// SPFMetric is the canonical SPF-run counter. It is monotonic as collected and
// scoped: per OSPF area (OSPF-MIB has no router-wide ospfSpfRuns) or per IS-IS
// level.
func (p Proto) SPFMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_spf_runs_total"
	}
	return "device_isis_spf_runs_total"
}

// HoldMetric is the IS-IS per-adjacency REMAINING hold time (a countdown reset
// by every received hello). It is empty for OSPF, which has no per-neighbour
// timer to collect — see HelloMetric/DeadMetric.
func (p Proto) HoldMetric() string {
	if p == ProtoOSPF {
		return ""
	}
	return "device_isis_adj_hold_seconds"
}

// HelloMetric / DeadMetric are the OSPF per-INTERFACE configured intervals
// (OSPF-MIB ospfIfHelloInterval / ospfIfRtrDeadInterval). They are empty for
// IS-IS, whose collected timer is per-adjacency instead.
func (p Proto) HelloMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_if_hello_seconds"
	}
	return ""
}

func (p Proto) DeadMetric() string {
	if p == ProtoOSPF {
		return "device_ospf_if_dead_seconds"
	}
	return ""
}

// ScopeLabel is the series label the protocol's counts are scoped by: the OSPF
// area (ospfAreaTable's index) or the IS-IS level. The two vocabularies are
// deliberately NOT unified — an area is not a level, and rendering one under
// the other's heading is the kind of quiet mislabelling this package refuses.
func (p Proto) ScopeLabel() string {
	if p == ProtoOSPF {
		return "area"
	}
	return "isis_level"
}

// TimerScopeKind names what a timer row identifies for this protocol:
// "adjacency" (IS-IS, per-neighbour) or "interface" (OSPF, per ospfIfTable row).
func (p Proto) TimerScopeKind() string {
	if p == ProtoOSPF {
		return "interface"
	}
	return "adjacency"
}

// PeerLabel is the series label carrying the neighbour identity: the IS-IS
// system-id (canon-tags renames adjacency_neighbor-system-id → isis_neighbor)
// or the OSPF-MIB ospfNbrTable index label.
func (p Proto) PeerLabel() string {
	if p == ProtoOSPF {
		return "neighbor"
	}
	return "isis_neighbor"
}

// stateName decodes a canonical adjacency-state value. Both protocols were
// normalized onto their MIB numerics (gnmic canon-isis-enums / OSPF-MIB
// ospfNbrState), so one decoder per protocol is the whole vocabulary.
func (p Proto) stateName(v float64) string {
	n := int(v)
	if p == ProtoOSPF {
		switch n {
		case 1:
			return "down"
		case 2:
			return "attempt"
		case 3:
			return "init"
		case 4:
			return "twoWay"
		case 5:
			return "exchangeStart"
		case 6:
			return "exchange"
		case 7:
			return "loading"
		case 8:
			return "full"
		}
		return "unknown"
	}
	switch n {
	case 1:
		return "down"
	case 2:
		return "init"
	case 3:
		return "up"
	case 4:
		return "failed"
	}
	return "unknown"
}

// isUp reports whether a decoded state value means a fully-formed adjacency:
// OSPF full(8), IS-IS up(3). Anything else is NOT up — including "unknown",
// which must never be rounded up to healthy.
func (p Proto) isUp(v float64) bool {
	if p == ProtoOSPF {
		return int(v) == 8
	}
	return int(v) == 3
}

// ── injected collaborators ──────────────────────────────────────────────────

// Gate is the permission a route needs. This package states WHAT; the
// integrator maps it onto the RBAC model. Every route here is a READ.
type Gate int

// GateRead is per-tenant operator read access.
const GateRead Gate = 0

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Device is the inventory row this module needs — id and name, because a series
// may be labelled with either (`device` carries the collector's device id on the
// SNMP lane and the target name on the gNMI lane).
type Device struct {
	ID       string
	Name     string
	TenantID string
}

// Sample is one VictoriaMetrics instant-query result row.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// EventQuery is a bounded request for typed adjacency-change signals.
type EventQuery struct {
	Kind string // corr_signals kind, e.g. "isis_adjacency_change"
	// Devices restricts entity_id. Empty means "every device the tenant scope
	// admits" — the row policy is still the enforcing boundary.
	Devices []string
	SinceMS int64 // absolute lower bound, unix millis
	// Cursor is the keyset position (ts DESC, signal_id DESC); zero = first page.
	CursorMS int64
	CursorID string
	Limit    int // already clamped
}

// Event is one typed adjacency-change signal, flattened from corr_signals.
type Event struct {
	TSMillis int64  `json:"-"`
	TS       string `json:"ts"`
	SignalID string `json:"signal_id"`
	Device   string `json:"device"`
	Peer     string `json:"peer,omitempty"`
	IfName   string `json:"ifname,omitempty"`
	State    string `json:"state"`    // up | down | unknown (the parser's vocabulary)
	Severity string `json:"severity"` // info | warn | high | crit
	Source   string `json:"source"`   // syslog | trap
}

// Deps are the module's injected collaborators (§5: no ambient authority —
// this package cannot reach ClickHouse, VictoriaMetrics, the inventory or the
// audit log except through these). New refuses an incomplete Deps.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time

	// Authz authorizes the caller at the given gate and returns the resolved
	// principal. It has already written the error response when ok is false.
	// Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)

	// LookupDevice resolves one device id from the inventory. ok=false means
	// "no such device" — the handler renders that identically to a foreign id.
	// Required.
	LookupDevice func(deviceID string) (Device, bool)

	// CanSee reports whether the principal may see the device. Required: this
	// is the §3a rule-1 boundary and the module refuses to guess it.
	CanSee func(d Device, p Principal) bool

	// Scope returns the ClickHouse tenant_scope literal for the request
	// (chTenantScope). "__all__" = platform cross-tenant, a tenant id = that
	// tenant, "" / "__none__" = nothing. Required.
	Scope func(r *http.Request) string

	// CHQuery runs ONE tenant-scoped ClickHouse read and returns parsed rows.
	// Required.
	CHQuery func(ctx context.Context, scope, sql string) ([]map[string]any, error)

	// ScopeFilters returns the caller's VictoriaMetrics `extra_filters[]` device
	// boundary (metricsScopeFilters over the principal's visible devices). It
	// returns nil ONLY for a cross-tenant principal, for whom no restriction
	// applies; a scoped principal ALWAYS gets at least one matcher (the
	// no-visible-device sentinel). Required.
	ScopeFilters func(r *http.Request, p Principal) []string

	// VMQuery runs one VictoriaMetrics instant query with the given
	// extra_filters[]. Required.
	VMQuery func(ctx context.Context, query string, filters []string) ([]Sample, error)

	// Metrics is the Prometheus counter surface. Optional (nil = no counters).
	Metrics *Metrics

	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)

	// LogWarn is the structured logger (§10). Required.
	LogWarn func(msg string, fields map[string]any)
}

func (d Deps) validate() error {
	missing := make([]string, 0, 12)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("Authz", d.Authz != nil)
	check("LookupDevice", d.LookupDevice != nil)
	check("CanSee", d.CanSee != nil)
	check("Scope", d.Scope != nil)
	check("CHQuery", d.CHQuery != nil)
	check("ScopeFilters", d.ScopeFilters != nil)
	check("VMQuery", d.VMQuery != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	if len(missing) > 0 {
		return fmt.Errorf("igpmon: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// API is the module's HTTP surface.
type API struct{ deps Deps }

// New builds the API over the injected Deps, failing CLOSED on an incomplete
// Deps rather than returning a handler set that silently reads unscoped.
func New(d Deps) (*API, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &API{deps: d}, nil
}

// Metrics exposes the counter set for the /metrics writer.
func (a *API) Metrics() *Metrics {
	if a == nil {
		return nil
	}
	return a.deps.Metrics
}

// errScopeless is the fail-closed condition: a scoped principal reached a
// VictoriaMetrics read with no device boundary to attach. It is a programming
// error in the wiring, never a reason to read the fleet.
var errScopeless = errors.New("igpmon: scoped principal has no metrics device filter")
