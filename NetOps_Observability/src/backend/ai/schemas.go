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
	Mode         AnswerMode           `json:"mode"`
	Intent       string               `json:"intent"`
	Modules      []string             `json:"modules"`
	Text         string               `json:"text"`                    // model narrative (escaped on render)
	Problem      *ProblemExplanation  `json:"problem,omitempty"`       // for ModeProblemExplanation
	CurrentState *CurrentStateSummary `json:"current_state,omitempty"` // for ModeCurrentStateSummary
	Module       *ModuleHealthSummary `json:"module,omitempty"`        // for ModeModuleHealthSummary
	Navigation   []ProductNavEntry    `json:"navigation,omitempty"`
	Citations    []Citation           `json:"citations"`
	Disclaimers  []string             `json:"disclaimers"`
	Provider     string               `json:"provider,omitempty"` // which LLM answered (audit)
	// Universal Response-Quality fields (spec §6) — reusable across every answer
	// mode, rendered by the generic AI answer card as badges + sections.
	Status           string   `json:"status,omitempty"`           // NOC status word (Confirmed/Suspected/…)
	ConfidenceLabel  string   `json:"confidence_label,omitempty"` // "Not established"/"Low"/"High" (never bare 0%)
	RecommendedOwner string   `json:"recommended_owner,omitempty"`
	NextActions      []string `json:"next_actions,omitempty"`
	MissingEvidence  []string `json:"missing_evidence,omitempty"` // clean operational bullets
	ModeBadges       []string `json:"mode_badges,omitempty"`      // e.g. ["Evidence-only mode","Low evidence"]
	EvidenceOnly     bool     `json:"evidence_only,omitempty"`    // true → deterministic (no LLM) answer
}

// CurrentStateSummary is the P2 Command Center answer-mode schema: a NOC
// at-a-glance built deterministically from active correlations, with a
// model-written headline. Answers "what is going on right now / what should the
// NOC focus on first?"
type CurrentStateSummary struct {
	Summary          string   `json:"summary"` // model narrative
	ActiveIncidents  []string `json:"active_incidents"`
	Confirmed        int      `json:"confirmed"`
	Suspected        int      `json:"suspected"`
	Undetermined     int      `json:"undetermined"`
	ImpactedEntities []string `json:"impacted_entities"`
	RecommendedFocus []string `json:"recommended_focus"`
	FocusReason      string   `json:"focus_reason,omitempty"` // "why this is first"
	WatchNote        string   `json:"watch_note,omitempty"`   // grouped undetermined / evidence-gap note
	ActionableCount  int      `json:"actionable_count"`       // confirmed + suspected (need review)
	ConfidenceNotes  []string `json:"confidence_notes"`
	MissingData      []string `json:"missing_data"`
}

// ModuleHealthSummary is the P4 module-aware answer-mode schema: a focused,
// evidence-grounded read of ONE Correlix module (flow analytics, telemetry,
// app-identification, …) built deterministically from that module's governed
// read tools, with a model-written headline. Answers "show me top talkers",
// "any metric anomalies?", "what's flapping?" — scoped to the caller's tenant.
type ModuleHealthSummary struct {
	Module      string   `json:"module"`       // module id, e.g. "flow_analytics"
	DisplayName string   `json:"display_name"` // human label, e.g. "Flow Analytics"
	Headline    string   `json:"headline"`     // model narrative (escaped on render)
	Items       []string `json:"items"`        // bullet facts from the tools (cited)
	Notes       []string `json:"notes"`        // caps/freshness disclosures from tools
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
