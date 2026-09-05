package experience

// hypothesis.go — CausalHypothesis and the state machine that grades it.
//
// The owner's states (CANDIDATE → SUSPECTED → SUPPORTED → CONFIRMED/REJECTED)
// mapped onto the correlation engine's verdict tiers exactly as the design of
// record ratified it (§M.2):
//
//	CANDIDATE  ↔ undetermined  — below the confidence floor, or nothing supports it
//	SUSPECTED  ↔ suspected     — real support, but one modality or one observer
//	SUPPORTED  ↔ suspected     — corroborated across sources, still short of the gate
//	CONFIRMED  ↔ confirmed     — the INDEPENDENCE RULE is satisfied AND nothing
//	                             required is missing AND nothing contradicts
//	REJECTED   ↔ (contradicted)— a decisive contradiction: the cause did not act
//
// The gate is deliberately hard to pass. "Confirmed" is the word the product
// stakes its credibility on, and the acceptance scenario the design is measured
// against (the owner's Phase T) is one where the correct answer is CONFIRMED
// for the transit hypothesis and REJECTED for the deployment — reached by the
// evidence, never by a prior.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Hypothesis states.
const (
	StateCandidate = "CANDIDATE"
	StateSuspected = "SUSPECTED"
	StateSupported = "SUPPORTED"
	StateConfirmed = "CONFIRMED"
	StateRejected  = "REJECTED"
)

// Verdict tiers — the correlation engine's vocabulary, so the two graders speak
// one language on the wire (src/correlation/verdicts.py VerdictTier).
const (
	TierUndetermined = "undetermined"
	TierSuspected    = "suspected"
	TierConfirmed    = "confirmed"
)

// TierForState maps a hypothesis state onto the correlation verdict tier. A
// REJECTED hypothesis is undetermined as a VERDICT — it is a conclusion about
// what did NOT happen, and the object it belongs to is not thereby explained.
func TierForState(state string) string {
	switch state {
	case StateConfirmed:
		return TierConfirmed
	case StateSuspected, StateSupported:
		return TierSuspected
	default:
		return TierUndetermined
	}
}

// Cause classes — WHAT KIND of thing is being blamed. The list is closed
// because it drives ownership routing, and an unroutable cause is a cause
// nobody fixes. It deliberately does NOT collapse every cloud or application
// fault into "connectivity down" (Phase J's explicit warning).
const (
	CauseTransitDegradation = "transit_degradation"    // an ISP/carrier segment
	CauseLastMile           = "last_mile"              // site egress / access circuit
	CauseWANOverlay         = "wan_overlay"            // tunnel/SD-WAN overlay
	CauseLANAccess          = "lan_access"             // wired/wireless access layer
	CauseDNSResolution      = "dns_resolution"         // resolver or authoritative
	CauseTLSTermination     = "tls_termination"        // certificate/handshake
	CauseCloudEdge          = "cloud_edge"             // provider front door / LB / NVA
	CauseCloudPolicy        = "cloud_policy"           // security group / firewall / route table change
	CauseApplicationRegress = "application_regression" // a deploy/regression in the app tier
	CauseDependencyFailure  = "dependency_failure"     // a downstream service or database
	CauseCapacitySaturation = "capacity_saturation"
	CauseConfigChange       = "config_change" // a device/config change
	CauseRoutingChange      = "routing_change"
	CauseClientEndpoint     = "client_endpoint"    // the user's own device/session
	CauseSyntheticArtifact  = "synthetic_artifact" // the TEST is broken, not the service
	CauseUnknown            = "unknown"
)

var knownCauseClasses = map[string]bool{
	CauseTransitDegradation: true, CauseLastMile: true, CauseWANOverlay: true,
	CauseLANAccess: true, CauseDNSResolution: true, CauseTLSTermination: true,
	CauseCloudEdge: true, CauseCloudPolicy: true, CauseApplicationRegress: true,
	CauseDependencyFailure: true, CauseCapacitySaturation: true, CauseConfigChange: true,
	CauseRoutingChange: true, CauseClientEndpoint: true, CauseSyntheticArtifact: true,
	CauseUnknown: true,
}

// ValidCauseClass reports whether c is a declared cause class.
func ValidCauseClass(c string) bool { return knownCauseClasses[c] }

// Window is the time span a verdict is about, plus the two tolerances that
// decide whether a fact is "in" it.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// Tolerance widens the window for MEASUREMENTS: a probe recorded 30 s after
	// the window closed still describes it.
	Tolerance time.Duration `json:"-"`
	// ChangeLookback is how far BEFORE first impact a change may have happened
	// and still be a candidate cause. Beyond it, "there was a deploy yesterday"
	// is history, not evidence.
	ChangeLookback time.Duration `json:"-"`
}

// Default tolerances. Both are deliberately modest: a generous window is how a
// temporal coincidence becomes a "cause".
const (
	DefaultWindowTolerance = 2 * time.Minute
	DefaultChangeLookback  = 90 * time.Minute
)

// NewWindow builds a window with the default tolerances.
func NewWindow(start, end time.Time) Window {
	return Window{Start: start.UTC(), End: end.UTC(),
		Tolerance: DefaultWindowTolerance, ChangeLookback: DefaultChangeLookback}
}

// Aligns reports whether one item is temporally admissible for this window.
//
// A CHANGE is admissible only when it PRECEDES first impact and lies inside the
// lookback — the "change-before-effect" rule. A change after first impact is
// explicitly not aligned: it cannot have caused what had already started, and
// scoring it as if it might is the single most common way a dashboard blames
// the wrong team.
func (w Window) Aligns(it EvidenceItem, firstImpact time.Time) bool {
	tol := w.Tolerance
	if tol <= 0 {
		tol = DefaultWindowTolerance
	}
	if it.Kind == KindChange || it.IndependenceGroup == ModalityChangeRecord {
		look := w.ChangeLookback
		if look <= 0 {
			look = DefaultChangeLookback
		}
		ref := firstImpact
		if ref.IsZero() {
			ref = w.Start
		}
		at := it.EventAt
		return !at.After(ref.Add(tol)) && !at.Before(ref.Add(-look))
	}
	at := it.EventAt
	return !at.Before(w.Start.Add(-tol)) && !at.After(w.End.Add(tol))
}

// Hypothesis is one candidate explanation for an experience incident.
type Hypothesis struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	IncidentID string `json:"incident_id,omitempty"`

	CauseClass string `json:"cause_class"`
	// CauseEntity is the concrete thing blamed — an ASN, a seam id, a hop
	// address, a service name, a release id. Empty means the hypothesis names
	// no cause, and its specificity ceiling says so.
	CauseEntity string `json:"cause_entity,omitempty"`
	// Explanation is the operator sentence. It must read as a claim about
	// evidence ("the ISP-A transit segment lost 8% of probes from two sites"),
	// never as a verdict the evidence does not carry.
	Explanation string `json:"explanation"`

	// Seam / Owner are the OWNERSHIP answer: which handoff owns the fix, and
	// which team or provider that is. Empty owner is honest — it is rendered as
	// "owner not determined", never as a default team.
	Seam        string `json:"seam,omitempty"`
	Owner       string `json:"owner,omitempty"`
	BlastRadius string `json:"blast_radius,omitempty"`

	// FirstImpactAt anchors the change-before-effect rule.
	FirstImpactAt time.Time `json:"first_impact_at,omitempty"`

	// Alternatives names the competing hypothesis ids this one is ranked
	// against. Shown so an operator can see what else was considered.
	Alternatives []string `json:"alternative_hypothesis_ids,omitempty"`

	// ── graded fields: written by Grade, never by a caller ──
	State            string            `json:"state"`
	VerdictTier      string            `json:"verdict_tier"`
	Confidence       float64           `json:"confidence"`
	ConfidenceParts  []Factor          `json:"confidence_factors,omitempty"`
	Independence     Independence      `json:"independence"`
	SupportingIDs    []string          `json:"supporting_evidence_ids,omitempty"`
	ContradictingIDs []string          `json:"contradicting_evidence_ids,omitempty"`
	MissingEvidence  []MissingEvidence `json:"missing_evidence,omitempty"`
	// GateReasons say why the hypothesis is NOT confirmed. Empty on a confirmed
	// one. They are shown verbatim: "not confirmed" without a reason teaches an
	// operator to ignore the distinction.
	GateReasons []string `json:"gate_reasons,omitempty"`
}

// Validate normalizes the declared (non-graded) fields.
func (h *Hypothesis) Validate() error {
	h.ID = clip(strings.TrimSpace(h.ID), MaxIDBytes)
	if h.ID == "" {
		return errors.New("hypothesis: id is required")
	}
	h.TenantID = strings.ToLower(strings.TrimSpace(h.TenantID))
	h.IncidentID = clip(strings.TrimSpace(h.IncidentID), MaxIDBytes)
	h.CauseClass = strings.ToLower(strings.TrimSpace(h.CauseClass))
	if !ValidCauseClass(h.CauseClass) {
		return fmt.Errorf("hypothesis %s: unknown cause_class %q", h.ID, clip(h.CauseClass, 40))
	}
	h.CauseEntity = clip(strings.TrimSpace(h.CauseEntity), MaxIDBytes)
	h.Explanation = clip(strings.TrimSpace(h.Explanation), MaxDetailBytes)
	if h.Explanation == "" {
		return fmt.Errorf("hypothesis %s: an explanation is required", h.ID)
	}
	h.Seam = clip(strings.TrimSpace(h.Seam), MaxLabelBytes)
	h.Owner = clip(strings.TrimSpace(h.Owner), MaxLabelBytes)
	h.BlastRadius = clip(strings.TrimSpace(h.BlastRadius), MaxSummaryBytes)
	h.Alternatives = dedupIDs(h.Alternatives)
	return nil
}

// Grade computes the hypothesis's state from its evidence. PURE.
//
// items is the WHOLE evidence set for the incident; Grade selects the ones that
// name this hypothesis (or, for an unattached set, the ones whose stance is
// declared and whose hypothesis lists are empty — the single-hypothesis case).
// missing is the incident's missing-evidence record.
//
// Grade OVERWRITES every graded field, which is what stops a caller stamping a
// state the evidence does not support.
func (h *Hypothesis) Grade(items []EvidenceItem, missing []MissingEvidence, window Window, now time.Time) {
	mine := h.selectEvidence(items)
	h.SupportingIDs, h.ContradictingIDs = nil, nil
	decisive := false
	for _, it := range mine {
		switch it.Stance {
		case StanceSupports:
			h.SupportingIDs = append(h.SupportingIDs, it.ID)
		case StanceContradicts:
			h.ContradictingIDs = append(h.ContradictingIDs, it.ID)
			if it.Decisive {
				decisive = true
			}
		}
	}
	sort.Strings(h.SupportingIDs)
	sort.Strings(h.ContradictingIDs)
	h.MissingEvidence = missing

	conf := ComputeConfidence(*h, mine, missing, window, now)
	h.Confidence, h.ConfidenceParts = conf.Score, conf.Factors
	h.Independence = AssessIndependence(mine)

	// A decisive contradiction ends the argument. It is checked FIRST and
	// independently of the confidence number: a cause that demonstrably did not
	// act is rejected however much circumstantial support it accumulated.
	if decisive {
		h.State, h.VerdictTier = StateRejected, TierForState(StateRejected)
		h.GateReasons = []string{"a measured observation refutes it outright, so it is rejected regardless of what else points at it"}
		return
	}

	reasons := append([]string{}, h.Independence.Reasons...)
	for _, m := range missing {
		if m.Required {
			reasons = append(reasons, "a source required to confirm this reported nothing: "+m.Source+" ("+m.Reason+")")
		}
	}
	if len(h.ContradictingIDs) > 0 {
		reasons = append(reasons,
			plural(len(h.ContradictingIDs), "observation contradicts", "observations contradict")+" it, so it cannot be confirmed while they stand")
	}
	if h.Confidence < ConfirmConfidence {
		reasons = append(reasons, "confidence is below the bar confirmation requires")
	}

	switch {
	case len(h.SupportingIDs) == 0 || h.Confidence < ConfidenceFloor:
		h.State = StateCandidate
	case len(reasons) == 0:
		h.State = StateConfirmed
	case h.Independence.Satisfied() || len(h.Independence.Modalities) >= 2:
		// Corroborated across sources but short of the gate.
		h.State = StateSupported
	default:
		h.State = StateSuspected
	}
	h.VerdictTier = TierForState(h.State)
	if h.State == StateConfirmed {
		h.GateReasons = nil
	} else {
		h.GateReasons = dedupStrings(reasons)
	}
}

// selectEvidence returns the items that bear on this hypothesis. An item that
// names hypotheses explicitly is used ONLY for those; an item that names none
// is treated as bearing on every hypothesis in the set, which is the shape a
// single-hypothesis incident naturally has.
func (h Hypothesis) selectEvidence(items []EvidenceItem) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(items))
	for _, it := range items {
		named := len(it.SupportsHypotheses) > 0 || len(it.ContradictsHypotheses) > 0
		if !named {
			if it.Stance != StanceNeutral {
				out = append(out, it)
			}
			continue
		}
		if contains(it.SupportsHypotheses, h.ID) {
			c := it
			c.Stance = StanceSupports
			out = append(out, c)
			continue
		}
		if contains(it.ContradictsHypotheses, h.ID) {
			c := it
			c.Stance = StanceContradicts
			out = append(out, c)
		}
	}
	return out
}

// RankHypotheses grades every hypothesis and orders them by confidence,
// strongest first, with a deterministic tie-break on id. REJECTED hypotheses
// sort last but are NEVER dropped: "we considered the deploy and ruled it out"
// is one of the most valuable things the product can say.
func RankHypotheses(hs []Hypothesis, items []EvidenceItem, missing []MissingEvidence, window Window, now time.Time) []Hypothesis {
	out := make([]Hypothesis, len(hs))
	copy(out, hs)
	for i := range out {
		out[i].Grade(items, missing, window, now)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := out[i].State == StateRejected, out[j].State == StateRejected
		if ri != rj {
			return rj
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Leading returns the highest-confidence non-rejected hypothesis, and whether
// one exists. An incident with only rejected hypotheses has NO leading cause,
// and saying so is the honest answer.
func Leading(ranked []Hypothesis) (Hypothesis, bool) {
	for _, h := range ranked {
		if h.State != StateRejected && h.State != StateCandidate {
			return h, true
		}
	}
	return Hypothesis{}, false
}

// ── string helpers ──────────────────────────────────────────────────────────

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func joinWords(list []string) string {
	switch len(list) {
	case 0:
		return "nothing"
	case 1:
		return list[0]
	case 2:
		return list[0] + " and " + list[1]
	default:
		return strings.Join(list[:len(list)-1], ", ") + " and " + list[len(list)-1]
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
