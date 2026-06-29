package ai

// Answer modes (HLD §6). The Response Builder validates the assistant's output
// into one of these typed schemas; the UI renders a card per mode. Every mode
// carries Citations + Disclaimers so answers are always grounded and honest
// about gaps / disabled modules.
type AnswerMode string

const (
	ModeProblemExplanation       AnswerMode = "problem_explanation"
	ModeCurrentStateSummary      AnswerMode = "current_state_summary"
	ModeTimeRangeOutageSummary   AnswerMode = "time_range_outage_summary"
	ModeModuleHealthSummary      AnswerMode = "module_health_summary"
	ModeTopologyPathExplanation  AnswerMode = "topology_path_explanation"
	ModeEvidenceExplanation      AnswerMode = "evidence_explanation"
	ModeMissingEvidenceExplained AnswerMode = "missing_evidence_explanation"
	ModeItsmUpdate               AnswerMode = "itsm_update"
	ModeShiftHandoff             AnswerMode = "shift_handoff"
	ModeExecutiveSummary         AnswerMode = "executive_summary"
	ModeProductNavigationHelp    AnswerMode = "product_navigation_help"
	ModeInvestigationPlan        AnswerMode = "investigation_plan"
	ModeUnavailable              AnswerMode = "unavailable" // module disabled / future
)

// Citation links an answer back to the evidence it used (clickable in the UI).
type Citation struct {
	ID    string `json:"id"`    // stable evidence id, e.g. "finding:ch:<id>"
	Kind  string `json:"kind"`  // finding | log | metric | ticket | topology | device
	Label string `json:"label"` // human label
	Href  string `json:"href"`  // UI deep link back into the source view
}

// Answer is the envelope returned to the UI. Mode selects the card; Text is the
// model's grounded narrative; the structured fields are built DETERMINISTICALLY
// from tools (not trusted to the model), with Citations + Disclaimers always set.
type Answer struct {
	Mode        AnswerMode          `json:"mode"`
	Intent      string              `json:"intent"`
	Modules     []string            `json:"modules"`
	Text        string              `json:"text"`              // model narrative (escaped on render)
	Problem     *ProblemExplanation `json:"problem,omitempty"` // for ModeProblemExplanation
	Navigation  []ProductNavEntry   `json:"navigation,omitempty"`
	Citations   []Citation          `json:"citations"`
	Disclaimers []string            `json:"disclaimers"`
	Provider    string              `json:"provider,omitempty"` // which LLM answered (audit)
}

// ProblemExplanation is the P1 RCA answer-mode schema. The narrative fields the
// model writes (Summary, RootCauseHypothesis) are grounded in the evidence we
// hand it; the factual fields below are filled from our tools, never the model.
type ProblemExplanation struct {
	ProblemID             string   `json:"problem_id"`
	Title                 string   `json:"title"`
	Verdict               string   `json:"verdict"`    // confirmed | suspected | undetermined
	Confidence            string   `json:"confidence"` // e.g. "82%"
	Summary               string   `json:"summary"`    // model narrative
	RootCauseHypothesis   string   `json:"root_cause_hypothesis"`
	Timeline              []string `json:"timeline"`
	SupportingEvidence    []string `json:"supporting_evidence"`
	ContradictingEvidence []string `json:"contradicting_evidence"`
	MissingEvidence       []string `json:"missing_evidence"`
	RecommendedOwner      string   `json:"recommended_owner"`
	ItsmNote              string   `json:"itsm_note"`
}
