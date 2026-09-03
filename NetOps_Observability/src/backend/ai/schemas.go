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
	ModeProductAnswer            AnswerMode = "product_answer" // answers a question ABOUT Correlix from product knowledge
	ModeInvestigationPlan        AnswerMode = "investigation_plan"
	// ModeTroubleshootFinding is the IRIS Phase-A skill answer: a grounded,
	// cited troubleshooting finding produced by a SKILL (skills/<name>/SKILL.md)
	// whose gather step ran governed read-only tools before the model narrated.
	// The card renders Text + NextActions + Citations, with the skill's
	// name/layer/version shown as provenance.
	ModeTroubleshootFinding AnswerMode = "troubleshoot_finding"
	// NOC-focus + status-breakdown answer modes (spec §4/§5). Both are backed by
	// the CurrentStateSummary schema (they read the same active-correlation set),
	// but render a recommendation-first / two-section card rather than the generic
	// current-state briefing.
	ModeNocFocusRecommendation  AnswerMode = "noc_focus_recommendation"
	ModeIncidentStatusBreakdown AnswerMode = "incident_status_breakdown"
	// ModeTopIncidentExplanation is a ROUTING mode (spec §4): "explain the top
	// incident" resolves rank #1 from the priority queue, then answers as a normal
	// ModeProblemExplanation card — so the produced Answer.Mode is
	// ModeProblemExplanation, this value only selects the resolve-first dispatch.
	ModeTopIncidentExplanation AnswerMode = "top_incident_explanation"
	ModeUnavailable            AnswerMode = "unavailable" // module disabled / future
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
	ModeBadges       []string `json:"mode_badges,omitempty"`      // e.g. ["Low evidence"] — status/provider live elsewhere
	EvidenceOnly     bool     `json:"evidence_only,omitempty"`    // true → deterministic (no LLM) answer
	// ProviderNote is the SINGLE, small provider-fallback line (spec §1/§8). It is
	// rendered once as a footer/badge — never as the main answer sentence, never
	// repeated in Text or Disclaimers. Empty when a live provider answered.
	ProviderNote string `json:"provider_note,omitempty"`
	// Title is the card-level heading for a mode (spec §2) — e.g. "Current
	// Operations Summary" — so the UI never labels the whole card with a single
	// incident's status.
	Title string `json:"title,omitempty"`
	// Counts is the normalized, labeled incident-count set (spec §6). One place
	// defines what each number means, so no two answers show conflicting counts.
	Counts *IncidentCounts `json:"counts,omitempty"`
	// Skill is the IRIS Phase-A provenance stamp: which troubleshooting method
	// (skills/<name>/SKILL.md, with its version) produced this answer. Set only
	// on ModeTroubleshootFinding; nil means the answer came from the classic
	// classify→mode path. The UI renders it so an operator can see — and audit —
	// which method was applied.
	Skill *SkillRef `json:"skill,omitempty"`
	// Chain is the IRIS Phase-A2 investigation path: every method the bounded
	// loop ran, in authored order, with the round it ran in and HOW it was
	// chosen (entry | rule | model). Skill above stays the LAST hop, so an
	// older UI that reads only `skill` is unaffected; a Phase-A2 UI renders the
	// chain as a breadcrumb so an operator can audit the path taken.
	Chain []SkillHop `json:"chain,omitempty"`
	// Lookups names the tools the skill's gather step actually ran, in order, so
	// the UI can show "investigated: N lookups" with the same provenance the
	// agent loop already returns.
	Lookups []string `json:"lookups,omitempty"`
	// AnswerID names THIS answer (IRIS Phase B). It is stamped only on a
	// concluded skill-chain answer, and exists so a later thumbs up/down can say
	// exactly which investigation it is judging — the judgement is what turns a
	// conclusion into an investigation-memory row. Opaque to the UI; echo it back
	// on POST /api/ai/feedback as `answer_id`.
	AnswerID string `json:"answer_id,omitempty"`
}

// IncidentCounts is the normalized incident-count set (spec §6). Every count
// category has ONE definition here, and CountsLegend() explains them, so a
// card can show several numbers without them reading as conflicting. Derived
// from the tenant-scoped active-correlation set — never fabricated.
type IncidentCounts struct {
	ActiveCorrelationGroups    int  `json:"active_correlation_groups"`      // all active correlation groups in the live RCA view
	ConfirmedCount             int  `json:"confirmed_count"`                //
	SuspectedCount             int  `json:"suspected_count"`                //
	CandidateCount             int  `json:"candidate_count"`                //
	UndeterminedCount          int  `json:"undetermined_count"`             // low-evidence, under investigation
	ActionableIncidentsCount   int  `json:"actionable_incidents_count"`     // confirmed + suspected (+ candidate) — the NOC queue
	LowEvidenceWatchItemsCount int  `json:"low_evidence_watch_items_count"` // == undetermined in our model
	Capped                     bool `json:"capped,omitempty"`               // true → counts are a lower bound (list was capped)
}

// CurrentStateSummary is the P2 Command Center answer-mode schema: a NOC
// at-a-glance built deterministically from active correlations, with a
// model-written headline. Answers "what is going on right now / what should the
// NOC focus on first?"
type CurrentStateSummary struct {
	Summary          string          `json:"summary"`          // model narrative
	Title            string          `json:"title,omitempty"`  // card heading (spec §2)
	Counts           *IncidentCounts `json:"counts,omitempty"` // normalized counts (spec §6)
	ActiveIncidents  []string        `json:"active_incidents"`
	Confirmed        int             `json:"confirmed"`
	Suspected        int             `json:"suspected"`
	Undetermined     int             `json:"undetermined"`
	ImpactedEntities []string        `json:"impacted_entities"`
	RecommendedFocus []string        `json:"recommended_focus"`
	FocusReason      string          `json:"focus_reason,omitempty"` // "why this is first"
	WatchNote        string          `json:"watch_note,omitempty"`   // grouped undetermined / evidence-gap note
	ActionableCount  int             `json:"actionable_count"`       // confirmed + suspected (need review)
	ConfidenceNotes  []string        `json:"confidence_notes"`
	MissingData      []string        `json:"missing_data"`
	// FocusStatus / FocusConfidence label the RECOMMENDED-FOCUS incident's status
	// and evidence confidence (spec §2). They are rendered INSIDE the focus section
	// ("Recommended focus status: Suspected"), never as the whole card's status —
	// only the one focus incident is suspected, not the entire live state.
	FocusStatus     string `json:"focus_status,omitempty"`
	FocusConfidence string `json:"focus_confidence,omitempty"`
	// SuspectedIncidents is the confirmed+suspected list rendered under an explicit
	// "Active suspected incidents" header (spec §5 breakdown; §4 noc-focus "other").
	// Kept SEPARATE from the undetermined watch note so the two never mix.
	SuspectedIncidents []string `json:"suspected_incidents,omitempty"`
	// WhyFirst are the bullet reasons the focus incident leads (spec §4/§5).
	WhyFirst []string `json:"why_first,omitempty"`
	// CountsLegend explains the count categories shown on this card (spec §6).
	CountsLegend []string `json:"counts_legend,omitempty"`
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
	WhyFirst              []string `json:"why_first,omitempty"` // "why this is the top incident" (spec §4)
}
