package experience

// investigator.go — SLICE 6 CONTRACTS: the AI Investigator's bounded interface.
//
// The rule the whole file exists to enforce (Phase K, CLAUDE.md §15):
//
//	telemetry → normalized evidence → correlation → hypotheses → confidence
//	→ AI explanation
//
// and NEVER "model guess → look for supporting evidence". So the model is
// handed a CLOSED evidence packet built from an already-graded incident, its
// answer must validate against a schema, and any evidence id it cites that was
// not in the packet is REJECTED — the whole answer, not just the citation,
// because a model that invented one reference has demonstrated it will invent
// another.
//
// Three further hard rules, all enforced here rather than in a prompt:
//   - the AI may never assert CONFIRMED. [ValidateInvestigation] downgrades any
//     confirmed-shaped claim, because confirmation is a property of the
//     evidence and is decided by [Hypothesis.Grade], not by a sentence.
//   - nothing above `pseudonymous_user` leaves the platform: [BuildPacket]
//     drops it and RECORDS that it did, so the operator can see the packet was
//     redacted rather than wondering why the answer is thin.
//   - the answer always carries the attribution line, and the caller is
//     required to render it.
//
// No provider call lives in this package. The orchestrator (ai/*) owns that;
// this is the contract on both sides of it.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// AttributionLine is shown with every AI-generated conclusion, verbatim.
const AttributionLine = "AI-assisted analysis based on Correlix evidence"

// EnvInvestigatorFlag gates the DEM AI investigator. It is IN ADDITION to the
// platform copilot flag and the tenant's own AI configuration: a feature that
// can send evidence to a model gets its own switch.
const EnvInvestigatorFlag = "FEATURE_DEM_AI_INVESTIGATOR"

// Packet bounds. A packet is a briefing, not a data dump: an unbounded packet
// is an unbounded provider bill and an unbounded disclosure surface (LLM04).
const (
	MaxPacketEvidence   = 40
	MaxPacketHypotheses = 8
	MaxPacketChanges    = 12
	MaxAnswerBytes      = 8000
)

// PacketEvidence is one evidence item as the model sees it — deliberately a
// REDUCED projection of EvidenceItem. Raw payloads, provenance producer ids and
// anything above pseudonymous_user never appear.
type PacketEvidence struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Stance            string   `json:"stance"`
	Summary           string   `json:"summary"`
	Entity            string   `json:"entity,omitempty"`
	IndependenceGroup string   `json:"independence_group"`
	Observer          string   `json:"observer,omitempty"`
	Reliability       float64  `json:"reliability"`
	ObservedAt        string   `json:"observed_at"`
	Observation       string   `json:"observation"`
	Supports          []string `json:"supports_hypothesis_ids,omitempty"`
	Contradicts       []string `json:"contradicts_hypothesis_ids,omitempty"`
}

// PacketHypothesis is one graded hypothesis as the model sees it.
type PacketHypothesis struct {
	ID          string   `json:"id"`
	CauseClass  string   `json:"cause_class"`
	CauseEntity string   `json:"cause_entity,omitempty"`
	Explanation string   `json:"explanation"`
	State       string   `json:"state"`
	Confidence  float64  `json:"confidence"`
	Seam        string   `json:"seam,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	GateReasons []string `json:"gate_reasons,omitempty"`
}

// Packet is the closed briefing handed to the model.
type Packet struct {
	IncidentID string `json:"incident_id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Window     Window `json:"window"`

	Impact            Impact             `json:"impact"`
	Hypotheses        []PacketHypothesis `json:"hypotheses"`
	Evidence          []PacketEvidence   `json:"evidence"`
	MissingEvidence   []MissingEvidence  `json:"missing_evidence,omitempty"`
	Changes           []ChangeRelevance  `json:"changes,omitempty"`
	SourceHealth      []SourceHealth     `json:"source_health,omitempty"`
	AllowedActions    []string           `json:"allowed_actions"`
	PathObservationID string             `json:"path_observation_id,omitempty"`

	// Redacted counts what was withheld and why. An operator must be able to
	// see that the model was given less than the incident holds.
	Redacted []string `json:"redacted,omitempty"`
	// EvidenceIDs is the WHITELIST. It is the packet's own answer to "which
	// references are real", and [ValidateInvestigation] admits nothing else.
	EvidenceIDs []string `json:"evidence_ids"`
}

// BuildPacket projects a graded incident into a model briefing. PURE.
func BuildPacket(inc ExperienceIncident, health []SourceHealth) Packet {
	p := Packet{
		IncidentID: inc.ID, Title: inc.Title, Severity: inc.Severity,
		Window: inc.Window, Impact: inc.Impact,
		MissingEvidence: inc.MissingEvidence, PathObservationID: inc.PathObservationID,
		SourceHealth: health,
	}
	// Impact counts a model does not need to reason are dropped WITH the reason
	// rather than silently: the redaction list is part of the answer's honesty.
	for _, h := range inc.Hypotheses {
		if len(p.Hypotheses) >= MaxPacketHypotheses {
			p.Redacted = append(p.Redacted, "hypotheses beyond the first "+plural(MaxPacketHypotheses, "entry", "entries"))
			break
		}
		p.Hypotheses = append(p.Hypotheses, PacketHypothesis{
			ID: h.ID, CauseClass: h.CauseClass, CauseEntity: h.CauseEntity,
			Explanation: h.Explanation, State: h.State, Confidence: h.Confidence,
			Seam: h.Seam, Owner: h.Owner, GateReasons: h.GateReasons,
		})
	}
	withheld := 0
	for _, e := range inc.Evidence {
		if !MayLeaveThePlatform(e.DataClass) {
			withheld++
			continue
		}
		if len(p.Evidence) >= MaxPacketEvidence {
			p.Redacted = append(p.Redacted, "evidence beyond the first "+plural(MaxPacketEvidence, "item", "items"))
			break
		}
		p.Evidence = append(p.Evidence, PacketEvidence{
			ID: e.ID, Kind: e.Kind, Stance: e.Stance, Summary: e.Summary,
			Entity: e.Entity, IndependenceGroup: e.IndependenceGroup,
			Observer: e.Observer, Reliability: e.Reliability,
			ObservedAt:  e.ObservedAt.Format("2006-01-02T15:04:05Z07:00"),
			Observation: e.Observation,
			Supports:    e.SupportsHypotheses, Contradicts: e.ContradictsHypotheses,
		})
		p.EvidenceIDs = append(p.EvidenceIDs, e.ID)
	}
	if withheld > 0 {
		p.Redacted = append(p.Redacted,
			plural(withheld, "evidence item was", "evidence items were")+" withheld because their data classification does not permit leaving the platform")
	}
	for _, c := range inc.Changes {
		if len(p.Changes) >= MaxPacketChanges {
			break
		}
		p.Changes = append(p.Changes, c)
	}
	for _, a := range inc.RecommendedActions {
		p.AllowedActions = append(p.AllowedActions, a.Type)
	}
	p.AllowedActions = dedupIDs(p.AllowedActions)
	sort.Strings(p.EvidenceIDs)
	return p
}

// Investigation is the model's answer. The JSON tags ARE the output schema the
// model must produce (Phase K's required output list, unchanged).
type Investigation struct {
	Answer     string  `json:"answer"`
	Confidence float64 `json:"confidence"`

	Hypotheses []InvestigationHypothesis `json:"hypotheses"`

	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids"`
	ContradictingEvidenceIDs []string `json:"contradicting_evidence_ids"`
	MissingEvidence          []string `json:"missing_evidence"`
	RecommendedNextQueries   []string `json:"recommended_next_queries"`
	RecommendedActions       []string `json:"recommended_actions"`
	Assumptions              []string `json:"assumptions"`

	// Attribution is stamped by [ValidateInvestigation], never by the model.
	Attribution string `json:"attribution"`
	// Downgraded records that a confirmed-shaped claim was reduced. It is shown
	// to the operator: a model that overreached is a fact worth knowing.
	Downgraded bool `json:"downgraded,omitempty"`
}

// InvestigationHypothesis is one model-proposed explanation.
type InvestigationHypothesis struct {
	ID         string  `json:"id,omitempty"`
	Cause      string  `json:"cause"`
	Confidence float64 `json:"confidence"`
	State      string  `json:"state,omitempty"`
}

// ErrUnknownEvidence is returned when the answer cites an id the packet did not
// contain. It is a REJECTION of the whole answer.
var ErrUnknownEvidence = errors.New("the analysis referenced evidence that was not supplied to it")

// ValidateInvestigation enforces the schema, the evidence whitelist and the
// no-confirmation rule. It returns the CLEANED answer, or an error, and never
// a partially-accepted one.
func ValidateInvestigation(in Investigation, p Packet) (Investigation, error) {
	in.Answer = clip(strings.TrimSpace(in.Answer), MaxAnswerBytes)
	if in.Answer == "" {
		return Investigation{}, errors.New("the analysis returned no answer")
	}
	if in.Confidence < 0 || in.Confidence > 1 {
		return Investigation{}, fmt.Errorf("the analysis returned a confidence outside 0..1 (%v)", in.Confidence)
	}
	allowed := map[string]bool{}
	for _, id := range p.EvidenceIDs {
		allowed[id] = true
	}
	for _, list := range [][]string{in.SupportingEvidenceIDs, in.ContradictingEvidenceIDs} {
		for _, id := range list {
			if !allowed[strings.TrimSpace(id)] {
				return Investigation{}, fmt.Errorf("%w: %q", ErrUnknownEvidence, clip(id, 64))
			}
		}
	}
	hypIDs := map[string]bool{}
	for _, h := range p.Hypotheses {
		hypIDs[h.ID] = true
	}
	for i := range in.Hypotheses {
		h := &in.Hypotheses[i]
		h.ID = strings.TrimSpace(h.ID)
		if h.ID != "" && !hypIDs[h.ID] {
			return Investigation{}, fmt.Errorf("%w: hypothesis %q", ErrUnknownEvidence, clip(h.ID, 64))
		}
		h.Cause = clip(strings.TrimSpace(h.Cause), MaxSummaryBytes)
		if h.Confidence < 0 || h.Confidence > 1 {
			return Investigation{}, errors.New("the analysis returned a hypothesis confidence outside 0..1")
		}
		// The deterministic engine owns the state. A model-claimed CONFIRMED is
		// downgraded to SUSPECTED and the downgrade is recorded.
		if strings.EqualFold(h.State, StateConfirmed) {
			h.State = StateSuspected
			in.Downgraded = true
		}
	}
	allowedActions := map[string]bool{}
	for _, a := range p.AllowedActions {
		allowedActions[a] = true
	}
	kept := in.RecommendedActions[:0]
	for _, a := range in.RecommendedActions {
		if allowedActions[strings.TrimSpace(a)] {
			kept = append(kept, strings.TrimSpace(a))
		} else {
			in.Downgraded = true
		}
	}
	in.RecommendedActions = kept
	in.SupportingEvidenceIDs = dedupIDs(in.SupportingEvidenceIDs)
	in.ContradictingEvidenceIDs = dedupIDs(in.ContradictingEvidenceIDs)
	in.Attribution = AttributionLine
	return in, nil
}
