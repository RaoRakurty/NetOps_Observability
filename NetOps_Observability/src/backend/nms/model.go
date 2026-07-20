// Package nms is Correlix's vendor-controller intelligence framework — it
// harvests INTELLIGENCE (metrics, state, events) from third-party network
// management systems (Meraki, Catalyst Center, vManage, NDFC, Versa, Prime, …)
// and normalizes it into RCA evidence. It is NOT "vendor log ingestion": a
// controller is a domain expert whose computed state/metrics/topology/health we
// reconcile against direct telemetry (design docs/design/nms-integration-framework.md).
//
// The framework core (this package) is vendor-neutral and stdlib-only. Vendor
// specifics live in per-vendor connector modules that implement Connector; the
// canonical model here stays stable so adding a vendor never touches the core,
// the normalization contract, or the correlation engine.
package nms

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// SignalClass is the routing decision every normalized datum carries. A
// connector routes each vendor response into exactly one class (never forcing
// everything into events).
type SignalClass string

const (
	// ClassMetric — continuous time-series (tunnel latency/loss/jitter, BFD
	// stats, app QoE, interface util, device CPU/mem). Rides VictoriaMetrics.
	ClassMetric SignalClass = "controller_metric"
	// ClassState — current operational state with flap history (BFD/OMP/control-
	// connection/tunnel/BGP up-down, reachability, oper status, deploy status).
	// Rides the state table; a transition optionally emits an event.
	ClassState SignalClass = "controller_state"
	// ClassEvent — alarms, audit logs, config/policy changes, controller
	// incidents. Rides netops.controller_events → corr_signals.
	ClassEvent SignalClass = "controller_event"
)

// Plane / authority constants — these MAP ONTO the correlation engine's existing
// axes (Source.CONTROLLER, ModalityClass.MANAGEMENT_PLANE, ObserverType.
// CONTROLLER). They are carried for audit/UI; they are not a second correlation
// model. The independence gate makes a lone management-plane witness cap at
// "suspected" — controller-alone-cannot-confirm is enforced for free.
const (
	Plane     = "management_plane"
	Authority = "vendor_controller"
)

// EvidenceRole is how RCA should weigh a datum relative to direct telemetry.
type EvidenceRole string

const (
	RoleSupporting     EvidenceRole = "supporting"     // corroborates telemetry
	RoleContradicting  EvidenceRole = "contradicting"  // conflicts with telemetry (surfaced in Inspector)
	RoleDiscriminating EvidenceRole = "discriminating" // distinguishes between hypotheses (e.g. a policy change)
)

// ControllerMetric is one time-series sample harvested from a controller (§3.1).
type ControllerMetric struct {
	TenantID      string
	IntegrationID string
	SourceSystem  string
	Name          string // normalized metric name (controller_metric_*)
	Value         float64
	Unit          string
	Time          time.Time
	// Tags are the mandatory join keys (device, site, interface, tunnel,
	// transport, app, …) plus normalized labels. Kept sorted for a stable line.
	Tags map[string]string
}

// ControllerState is a current operational-state snapshot (§3.2). The runtime
// maintains first/last-seen + flap_count by diffing against the prior snapshot.
type ControllerState struct {
	TenantID      string
	IntegrationID string
	SourceSystem  string
	EntityKey     string // normalized entity id (device/tunnel/peer/interface)
	StateKind     string // bfd | omp | control_conn | tunnel | bgp | reachability | intf_oper | deploy | fabric_node
	CurrentState  string // up | down | reachable | unreachable | success | ...
	DeviceID      string
	SiteID        string
	Time          time.Time
	Data          map[string]any
}

// ControllerEvent is a discrete alarm/audit/change/incident (§3.3). Field set
// matches the design's canonical schema. The snake_case JSON tags are the WIRE
// CONTRACT with the correlation consumer (controller_events.py reads exactly
// these keys off netops.controller_events) — do not rename one side alone.
type ControllerEvent struct {
	TenantID            string            `json:"tenant_id"`
	IntegrationID       string            `json:"integration_id"`
	SourceSystem        string            `json:"source_system"`
	Vendor              string            `json:"vendor"`
	Product             string            `json:"product"`
	EventID             string            `json:"event_id"` // vendor's own event id (raw dedup key input)
	EventTime           time.Time         `json:"event_time"`
	IngestTime          time.Time         `json:"ingest_time"`
	EventType           string            `json:"event_type"`            // vendor-native type
	NormalizedEventType string            `json:"normalized_event_type"` // controller_alarm | controller_tunnel_state | ...
	Severity            string            `json:"severity"`              // info | warn | high | crit
	Category            string            `json:"category"`
	DeviceID            string            `json:"device_id"`
	DeviceName          string            `json:"device_name"`
	SiteID              string            `json:"site_id"`
	SiteName            string            `json:"site_name"`
	InterfaceName       string            `json:"interface_name"`
	TunnelID            string            `json:"tunnel_id"`
	PeerID              string            `json:"peer_id"`
	Application         string            `json:"application"`
	Message             string            `json:"message"`
	RawPayload          []byte            `json:"raw_payload,omitempty"`
	DedupeKey           string            `json:"dedupe_key,omitempty"`
	Confidence          float64           `json:"confidence,omitempty"`
	EvidenceRole        EvidenceRole      `json:"evidence_role,omitempty"`
	CorrelationHints    map[string]string `json:"correlation_hints,omitempty"`
}

// Batch is what a Transformer returns for one raw response: the three classes,
// each routed to its own lane by the runtime. All-empty is valid (e.g. a poll
// that yielded nothing new).
type Batch struct {
	Metrics []ControllerMetric
	States  []ControllerState
	Events  []ControllerEvent
}

// DedupeKey computes a stable dedupe key from the identity-bearing parts of an
// event. If the vendor supplies a unique EventID we anchor on it; otherwise we
// hash the (integration, type, entity, time, message) tuple so re-delivered or
// re-polled duplicates collapse. Deterministic — same input, same key.
func DedupeKey(e ControllerEvent) string {
	if strings.TrimSpace(e.EventID) != "" {
		return e.IntegrationID + ":" + strings.TrimSpace(e.EventID)
	}
	parts := []string{
		e.IntegrationID, e.NormalizedEventType, e.DeviceID, e.InterfaceName,
		e.TunnelID, e.PeerID, e.EventTime.UTC().Format(time.RFC3339), e.Message,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return e.IntegrationID + ":h:" + hex.EncodeToString(sum[:12])
}

// StateEntityKey is the stable key for a state row (used for flap tracking).
func StateEntityKey(s ControllerState) string {
	return s.IntegrationID + ":" + s.StateKind + ":" + s.EntityKey
}

// MetricLine renders a ControllerMetric as a Prometheus-exposition line with
// sorted labels (stable output for tests + the VM import endpoint). Returns ""
// if the metric has no name.
func MetricLine(m ControllerMetric) string {
	if strings.TrimSpace(m.Name) == "" {
		return ""
	}
	keys := make([]string, 0, len(m.Tags))
	for k := range m.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(m.Name)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(sanitizeLabelValue(m.Tags[k]))
		b.WriteString(`"`)
	}
	b.WriteByte('}')
	b.WriteByte(' ')
	b.WriteString(formatFloat(m.Value))
	if !m.Time.IsZero() {
		b.WriteByte(' ')
		b.WriteString(formatInt(m.Time.UnixMilli()))
	}
	return b.String()
}
