package experience

// datahealth.go — DataSourceHealth (Phase C.14, §M.3).
//
// It EXTENDS the readiness vocabulary the platform already speaks — the appobs
// Data Sources tab's `flowing | stale | off | permission_denied | misconfigured
// | no_data | not_supported` — rather than inventing a second one, and adds the
// two fields that make it an EXPERIENCE source rather than an ingestion source:
//
//	Coverage           — what fraction of the subjects that need this source
//	                     actually have it. "Flowing" from one of forty sites is
//	                     not a healthy source.
//	ConfidenceInfluence— how much this source's state is currently moving
//	                     diagnostic confidence. This is the field that makes
//	                     the owner's rule H visible: a source problem must
//	                     VISIBLY reduce confidence, not silently.
//
// The rule the whole file exists to enforce: UNKNOWN and NO DATA are never
// HEALTHY. There is no code path here that renders an absent source as green.

import (
	"sort"
	"strings"
	"time"
)

// Source states — byte-identical to the appobs readiness vocabulary.
const (
	StateFlowing          = "flowing"
	StateStale            = "stale"
	StateOff              = "off"
	StatePermissionDenied = "permission_denied"
	StateMisconfigured    = "misconfigured"
	StateNoData           = "no_data"
	StateNotSupported     = "not_supported"
)

// Healthy reports whether a source state means the source is actually working.
// Exactly one state qualifies. Everything else — including "we have not looked"
// — is not healthy, and this function is the single place that decides it.
func Healthy(state string) bool { return state == StateFlowing }

// SourceHealth is one experience-evidence source's state.
type SourceHealth struct {
	// Source is a Provenance source (synthetic, pathgraph, rum, flow, …).
	Source string `json:"source"`
	Label  string `json:"label"`
	// IndependenceGroup is the modality class this source contributes. It is
	// here so the Data Health surface can say WHY a source being off matters:
	// "this is the only second opinion you have".
	IndependenceGroup string `json:"independence_group"`

	Configured bool   `json:"configured"`
	State      string `json:"state"`
	Detail     string `json:"detail,omitempty"`

	LastSeen            *time.Time `json:"last_seen,omitempty"`
	ExpectedIntervalSec int        `json:"expected_interval_sec,omitempty"`
	FreshnessSeconds    *int64     `json:"freshness_seconds,omitempty"`
	EventsInWindow      int        `json:"events_in_window"`
	LagSeconds          *int64     `json:"lag_seconds,omitempty"`
	Errors              int        `json:"errors,omitempty"`
	LastError           string     `json:"last_error,omitempty"`

	// Coverage is subjects-with-this-source / subjects-that-need-it, 0..1.
	// Nil = coverage is not knowable for this source, which is stated rather
	// than rendered as 100%.
	Coverage        *float64 `json:"coverage,omitempty"`
	CoverageCovered int      `json:"coverage_covered"`
	CoverageTotal   int      `json:"coverage_total"`

	// ConfidenceInfluence is how much this source's CURRENT state is lowering
	// diagnostic confidence, 0..1 (0 = none). It is derived, never declared.
	ConfidenceInfluence float64 `json:"confidence_influence"`
	// AnchorCapable says whether this source can anchor a CONFIRMED verdict.
	// A tenant with no anchor-capable second source can never reach confirmed,
	// and the surface must say so instead of leaving it to be discovered.
	AnchorCapable bool `json:"anchor_capable"`
}

// DataHealth is the whole picture for one tenant.
type DataHealth struct {
	Window  string         `json:"window"`
	Sources []SourceHealth `json:"sources"`

	// AnchorSourcesFlowing counts the anchor-capable sources actually working.
	// Below 2 the tenant CANNOT reach a confirmed verdict, whatever else is
	// true, and CanConfirm says so in one field.
	AnchorSourcesFlowing int  `json:"anchor_sources_flowing"`
	CanConfirm           bool `json:"can_confirm"`
	// Explanation is the sentence the overview renders under the confidence
	// panel. It is always populated.
	Explanation string `json:"explanation"`
}

// sourceLabels are the operator-facing names. Kept beside the vocabulary so a
// new source cannot ship without one.
var sourceLabels = map[string]string{
	SourceSynthetic:   "Synthetic checks",
	SourcePathGraph:   "Path measurement",
	SourceCorrelation: "Correlation engine",
	SourceConfigDrift: "Device configuration changes",
	SourceCloud:       "Cloud changes",
	SourceBGP:         "Internet routing (BGP)",
	SourceRUM:         "Real-user telemetry",
	SourceFlow:        "Flow records",
	SourceSDWAN:       "SD-WAN controller",
	SourceWireless:    "Wireless controller",
	SourceAgent:       "Endpoint agent",
	SourceServiceHTTP: "Service health",
	SourceManual:      "Operator input",
}

// SourceLabel is the operator-facing name of a source.
func SourceLabel(s string) string {
	if l, ok := sourceLabels[s]; ok {
		return l
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sourceModality maps a source onto the modality class its evidence carries.
var sourceModality = map[string]string{
	SourceSynthetic:   ModalityActiveProbe,
	SourcePathGraph:   ModalityActiveProbe,
	SourceRUM:         ModalityRealUser,
	SourceFlow:        ModalityPassiveFlow,
	SourceBGP:         ModalityControlPlane,
	SourceSDWAN:       ModalityManagementPlane,
	SourceWireless:    ModalityManagementPlane,
	SourceAgent:       ModalityDeviceTelemetry,
	SourceServiceHTTP: ModalityDeviceTelemetry,
	SourceCorrelation: ModalityManagementPlane,
	SourceConfigDrift: ModalityChangeRecord,
	SourceCloud:       ModalityChangeRecord,
	SourceManual:      ModalityManagementPlane,
}

// ModalityForSource returns the modality class a source's evidence carries.
func ModalityForSource(s string) string {
	if m, ok := sourceModality[s]; ok {
		return m
	}
	return ModalityManagementPlane // corroborating, never confirming — fail closed
}

// confidenceInfluence grades how much a source's state currently costs.
// Deliberately coarse and monotone: an absent source that could have anchored a
// verdict costs the most; one that could only ever corroborate costs less.
func confidenceInfluence(state string, anchor bool) float64 {
	if Healthy(state) {
		return 0
	}
	base := 0.2
	switch state {
	case StatePermissionDenied, StateMisconfigured, StateNoData:
		base = 0.4
	case StateStale:
		base = 0.3
	case StateOff, StateNotSupported:
		base = 0.15
	}
	if anchor {
		base += 0.2
	}
	return round2(clamp01(base))
}

// Grade fills the derived fields on one source: freshness, confidence influence
// and anchor capability. now is an argument, so every branch is a table test.
func (s *SourceHealth) Grade(now time.Time) {
	if s.Label == "" {
		s.Label = SourceLabel(s.Source)
	}
	if s.IndependenceGroup == "" {
		s.IndependenceGroup = ModalityForSource(s.Source)
	}
	s.AnchorCapable = MayAnchorVerdict(s.IndependenceGroup)
	if s.LastSeen != nil && !s.LastSeen.IsZero() {
		age := int64(now.Sub(*s.LastSeen).Seconds())
		if age < 0 {
			age = 0
		}
		s.FreshnessSeconds = &age
	}
	if s.CoverageTotal > 0 {
		c := round2(float64(s.CoverageCovered) / float64(s.CoverageTotal))
		s.Coverage = &c
	}
	s.ConfidenceInfluence = confidenceInfluence(s.State, s.AnchorCapable)
}

// BuildDataHealth grades every source and computes the tenant-level answer.
func BuildDataHealth(window string, sources []SourceHealth, now time.Time) DataHealth {
	out := DataHealth{Window: window, Sources: make([]SourceHealth, 0, len(sources))}
	for _, s := range sources {
		s.Grade(now)
		if s.AnchorCapable && Healthy(s.State) {
			out.AnchorSourcesFlowing++
		}
		out.Sources = append(out.Sources, s)
	}
	sort.SliceStable(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		if Healthy(a.State) != Healthy(b.State) {
			return !Healthy(a.State) // problems first
		}
		if a.AnchorCapable != b.AnchorCapable {
			return a.AnchorCapable
		}
		return a.Source < b.Source
	})
	out.CanConfirm = out.AnchorSourcesFlowing >= 2
	if out.CanConfirm {
		out.Explanation = "Two or more independent kinds of instrument are reporting, so a cause can be confirmed rather than only suspected."
	} else {
		out.Explanation = "Only " + plural(out.AnchorSourcesFlowing, "independent kind of instrument is", "independent kinds of instrument are") +
			" reporting. Correlix can suspect a cause but cannot confirm one: confirmation requires two independent observations, and that is a property of the evidence, not of the analysis."
	}
	return out
}

// MissingFrom derives the missing-evidence records an incident inherits from
// the tenant's data health. A source that is off, denied, stale or empty is a
// missing source for every incident in the window — which is exactly how a
// telemetry gap becomes a visible reduction in confidence rather than a silent
// one (Phase B rule H).
func (d DataHealth) MissingFrom() []MissingEvidence {
	out := make([]MissingEvidence, 0, len(d.Sources))
	for _, s := range d.Sources {
		if Healthy(s.State) {
			continue
		}
		reason := MissingNoData
		switch s.State {
		case StateOff:
			reason = MissingNotConfigured
		case StateStale:
			reason = MissingStale
		case StatePermissionDenied:
			reason = MissingPermissionDenied
		case StateMisconfigured:
			reason = MissingError
		case StateNotSupported:
			reason = MissingNotSupported
		}
		// Required — the absence that BLOCKS confirmation — is deliberately
		// narrow: a source that could have anchored a verdict, that is
		// configured, AND that HAS reported at least once. A source that has
		// never produced anything is a capability the deployment does not have,
		// and treating that as a blocking gap would make every incident in
		// every such deployment permanently unconfirmable — which is not
		// caution, it is a broken product. It still lowers confidence.
		out = append(out, MissingEvidence{
			Source: s.Source, IndependenceGroup: s.IndependenceGroup,
			Reason:   reason,
			Required: s.AnchorCapable && s.Configured && s.LastSeen != nil,
			Detail:   s.Label + " is not reporting (" + s.State + ")" + optDetail(s.Detail),
		})
	}
	return out
}

func optDetail(d string) string {
	if d == "" {
		return ""
	}
	return ": " + d
}
