// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// statement_class.go — STATEMENT CLASSES and the grounding rules that check
// them (tracker 337 N-B4; design of record §3.2: the platform decides, the
// model narrates).
//
// Every sentence of a model-written answer is CLASSIFIED by the server and
// shipped beside the narrative as Answer.Statements:
//
//	OBSERVED        what a live read showed — device state, diagnostics, logs,
//	                metrics, topology, the case timeline, the change register
//	CORRELIX_RCA    the correlation engine's own conclusion (verdict, ranked
//	                causes, causal chain, owner, blast radius, confidence)
//	DERIVED         a computed result (a data query), or Iris's own reading of
//	                the evidence when the sentence cites none (then grounded=false)
//	HISTORICAL      a PRIOR investigation's conclusion — context, never proof
//	DOCUMENTATION   product docs, KB, vendor/TAC knowledge
//	RECOMMENDATION  a next step for the operator
//
// The class of every EVIDENCE item comes from the TOOL that produced it,
// recorded by the server when the tool returned — never parsed back out of a
// citation id and never taken from model text. Two grounding facts ride on the
// item itself, stamped where the engine's structured output is projected
// (EvidenceItem.CauseRole / .Change / .Verdict): whether the item is the
// engine's OWN leading cause or a ranked alternative, whether it describes a
// change, and — on the correlation object itself — the engine's verdict.
//
// WHERE IT RUNS: the problem explanation (one incident, one verdict), the
// skill chain (the verdict the verdict tool declared, plus the causal chain
// for changes), the live-state briefing (one verdict PER incident — a cause is
// judged against the incident it cites, and one cause merged across separate
// incidents is never the engine's), and the copilot agent loop
// (GroundAgentNarrative — the verdicts of the correlation objects it read).
// Evidence-only (model-free) text is classified as server text, never judged.
//
// THE RULES, in the order they run (after VerifyGrounding has stripped every
// citation id that is not in the turn's evidence — R1):
//
//	R5  CHANGE ≠ CAUSE. A sentence that uses cause wording about a cited
//	    CHANGE item — hedged or not — is rewritten by the server to say the
//	    change is "temporally correlated, not established as cause", with
//	    where it stands against Correlix's analysis (not in the causal chain /
//	    an unconfirmed candidate / step N of an unestablished sequence / the
//	    chain could not be read). It stands only when the ENGINE established
//	    the change as the cause.
//	--  the existing verdict-honesty gate (verify.go) drops certainty
//	    overclaims under a verdict that is not confirmed.
//	R2  OWN CAUSE ONLY. An unhedged cause sentence survives only when the
//	    engine's verdict is CONFIRMED and the sentence names the engine's OWN
//	    cause: it cites the engine's leading-cause evidence, cites no ranked
//	    alternative and no unestablished change, and does not name a change
//	    unless the engine's cause is one. Under a confirmed verdict for a
//	    DIFFERENT cause the sentence is removed just the same — closing the gap
//	    the tier-only honesty gate left (owner rule: the correlation engine
//	    alone owns the root-cause verdict).
//	R3  CLASS GROUNDING. A sentence that attributes its claim to a source —
//	    Correlix's analysis, a past investigation, documentation — must cite
//	    an item of that class. Without one it is kept but DOWNGRADED
//	    (grounded=false, with a per-sentence note) when it hedges or the turn
//	    holds such evidence, and REMOVED when the turn holds none (fabricated
//	    authority). Any other uncited sentence is downgraded to DERIVED, never
//	    silently presented as an observation. A cited sentence takes the class
//	    of what it cites (CORRELIX_RCA > OBSERVED > DERIVED > HISTORICAL >
//	    DOCUMENTATION); a next step is a RECOMMENDATION.
//	R6  COINCIDENT-CHANGE WORDING. With an incident in scope, a sentence citing
//	    a change the engine has not established as the cause carries the
//	    wording "temporally correlated, not established as cause" even when it
//	    states no cause.
//
// Every removal and rewrite is DISCLOSED and counted through the scorecard
// seam (score.go). The vocabularies below are CLOSED: a guardrail that fires
// on prose nobody can predict would be untestable, so growing one is a code
// change with a test.
//
// §3a: the statement context is built only from what the turn's tools
// returned under the caller's principal, and the one extra read it makes
// (readChangeChain) is the tenant-scoped RCAResult seam under the same Policy
// Engine decision as get_causal_chain — another tenant's incident reads as
// ErrNotFound and contributes nothing.

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Statement classes.
const (
	ClassObserved       = "OBSERVED"
	ClassCorrelixRCA    = "CORRELIX_RCA"
	ClassDerived        = "DERIVED"
	ClassHistorical     = "HISTORICAL"
	ClassDocumentation  = "DOCUMENTATION"
	ClassRecommendation = "RECOMMENDATION"
)

// Cause roles (EvidenceItem.CauseRole).
const (
	// CauseRoleEngine — the correlation engine's own leading cause for the
	// incident, or the direct evidence the engine holds for it.
	CauseRoleEngine = "engine"
	// CauseRoleCandidate — a ranked alternative the engine did not settle on.
	CauseRoleCandidate = "candidate"
)

// CoincidentChangeWording is the exact wording an answer carries for a change
// that happened around an incident but that the correlation engine has not
// established as its cause.
const CoincidentChangeWording = "temporally correlated, not established as cause"

// Statement is one sentence of the answer narrative, classified by the server.
// Text is the exact slice of Answer.Text (trailing whitespace included), so
// the statements, concatenated, reproduce the narrative.
type Statement struct {
	Text  string `json:"text"`
	Class string `json:"class"`
	// Grounded is true when the sentence cites evidence of its class (or is
	// a recommendation, or server-authored text). False marks a DOWNGRADED
	// sentence — kept, but disclosed as carrying no evidence of its own.
	Grounded  bool     `json:"grounded"`
	Citations []string `json:"citations,omitempty"`
	// Note is the server's per-sentence disclosure (why it is downgraded, or
	// that the server reworded it). Empty for an ordinary grounded sentence.
	Note string `json:"note,omitempty"`
}

// toolStatementClass is the CLOSED tool → class map. A tool that is not listed
// has no class, and its items support no class-specific claim (default-closed).
// TestEveryDeclaredToolHasAStatementClass keeps it in step with toolMetas.
var toolStatementClass = map[string]string{
	// Live reads — what a device, a collector or a register showed.
	"get_device_state":               ClassObserved,
	"run_protocol_diagnostic":        ClassObserved,
	"search_logs":                    ClassObserved,
	"get_metric_anomalies":           ClassObserved,
	"get_device_health":              ClassObserved,
	"get_topology_context":           ClassObserved,
	"get_case_timeline":              ClassObserved,
	"get_bgp_watchlist":              ClassObserved,
	"get_bgp_rpki":                   ClassObserved,
	"get_bgp_feed_recent":            ClassObserved,
	"get_security_findings":          ClassObserved,
	"get_recent_changes":             ClassObserved,
	"get_config_diff":                ClassObserved,
	"get_top_talkers":                ClassObserved,
	"get_flow_summary":               ClassObserved,
	"get_service_flow_summary":       ClassObserved,
	"get_app_identity_summary":       ClassObserved,
	"get_low_confidence_app_matches": ClassObserved,
	"get_integration_health":         ClassObserved,
	"get_ticket_status":              ClassObserved,
	"get_wireless_ap_inventory":      ClassObserved,
	"get_wireless_controllers":       ClassObserved,
	// The correlation engine's own conclusion.
	"get_rca_verdict":            ClassCorrelixRCA,
	"get_problem":                ClassCorrelixRCA,
	"get_problem_evidence":       ClassCorrelixRCA,
	"get_active_major_incidents": ClassCorrelixRCA,
	"get_actionable_incidents":   ClassCorrelixRCA,
	"get_incident_history":       ClassCorrelixRCA,
	"get_causal_chain":           ClassCorrelixRCA,
	"get_blast_radius":           ClassCorrelixRCA,
	"get_owner":                  ClassCorrelixRCA,
	"get_affected_entities":      ClassCorrelixRCA,
	"get_confidence_breakdown":   ClassCorrelixRCA,
	// A prior conclusion — context, never evidence of the present.
	"recall_investigations": ClassHistorical,
	// Reference material.
	"search_docs": ClassDocumentation,
	// A computed query result.
	"compile_query": ClassDerived,
}

// changeTools are the tools whose every item describes a CHANGE.
var changeTools = map[string]bool{"get_recent_changes": true, "get_config_diff": true}

// ToolStatementClass returns the statement class of a tool's evidence, or ""
// for a tool the map does not know (which then supports nothing).
func ToolStatementClass(tool string) string { return toolStatementClass[tool] }

// ---- grounding facts stamped at the source ---------------------------------

// engineChangeKinds are the correlation engine's CHANGE observation kinds, as
// the signature catalog names them (src/correlation/catalog.py: config_change,
// device_config_change, cloud_change, cloud_audit, deploy_event;
// evidence_language.go: controller_policy_change).
var engineChangeKinds = map[string]bool{
	"config_change": true, "device_config_change": true, "cloud_change": true,
	"cloud_audit": true, "deploy_event": true, "controller_policy_change": true,
}

// reChangeTitle recognises an ENGINE-AUTHORED hypothesis id or title that
// names a change ("config-change", "Configuration change on edge-1",
// "controller-change-induced", "Secret / config drift after deploy"). It reads
// engine data, never model text.
var reChangeTitle = regexp.MustCompile(`(?i)\b(?:config(?:uration)?|policy|software|firmware|release|route[- ]map|acl)[ _-]*(?:change|drift|push|update|upgrade|rollout|commit|edit)s?\b|\bchange[ _-]induced\b|\bdeploy(?:ment|ed|s)?\b|\b(?:config|device_config|cloud)_change\b|\bdeploy_event\b`)

// hypothesisNamesChange reports whether a ranked engine hypothesis IS a change:
// its id or title names one. A hypothesis that merely lists a change among its
// satisfied clauses is not itself a change (its controller item carries that).
func hypothesisNamesChange(h RankedHypothesis) bool {
	return hypothesisTitleNamesChange(h.ID) || hypothesisTitleNamesChange(h.Title)
}

// hypothesisTitleNamesChange is the title form, for the RCA-report projection.
func hypothesisTitleNamesChange(s string) bool {
	return strings.TrimSpace(s) != "" && reChangeTitle.MatchString(s)
}

// controllerReportsChange: one of the controller-reported clauses is a change.
func controllerReportsChange(clauses []string) bool {
	for _, c := range clauses {
		for _, alt := range strings.Split(c, "|") {
			if engineChangeKinds[strings.ToLower(strings.TrimSpace(alt))] {
				return true
			}
		}
	}
	return false
}

// ---- the turn's statement context ------------------------------------------

// stmtItem is one citable item as the grounding rules see it.
type stmtItem struct {
	class  string
	role   string
	change bool
	text   string
	orig   string // the citation id exactly as the tool wrote it
	// incident / verdict place an item in ONE incident of a multi-incident
	// answer (the live-state briefing): the incident's id and the engine's
	// verdict tier for it. Empty means "the turn's incident and verdict".
	incident string
	verdict  string
}

// statementContext is everything the statement rules read. It is built by the
// SERVER from what the tools returned; nothing in it comes from model text.
type statementContext struct {
	items map[string]stmtItem // keyed by lowercased citation id
	// verdict is the ENGINE's verdict tier for the turn, lowercased; "" when
	// no engine verdict is in scope.
	verdict string
	// incident: an incident is in scope (the problem path, or a skill turn
	// bound to a correlation) — R6 applies only then.
	incident bool
	// docsInTurn: reference material was shown to the model without a
	// citable id (the problem path's playbook / TAC guidance).
	docsInTurn bool
	// chain is where a change stands against the engine's causal chain (skill
	// path). Nil means it was not read.
	chain *changeChainView
	// authored are the sentences the SERVER wrote this turn (R5 rewrites),
	// keyed by their trimmed text, with the statement they classify as.
	authored map[string]Statement
	// perIncident: the answer has no single turn verdict — a briefing over
	// several incidents, or an agent-loop answer — so the turn-level
	// certainty gate does not run and R2 judges each cause against the
	// verdict of the incident it cites (an uncited cause has none).
	perIncident bool
}

// stampIncident records the engine's correlation object for ONE incident of a
// multi-incident answer: the engine's own conclusion for that incident, under
// that incident's verdict.
func (sc *statementContext) stampIncident(citationID, incidentID, verdict, text string) {
	id := strings.ToLower(strings.TrimSpace(citationID))
	if id == "" {
		return
	}
	if sc.items == nil {
		sc.items = map[string]stmtItem{}
	}
	if _, seen := sc.items[id]; seen {
		return
	}
	sc.items[id] = stmtItem{
		class: ClassCorrelixRCA, role: CauseRoleEngine, text: text, orig: strings.TrimSpace(citationID),
		incident: incidentID, verdict: strings.ToLower(strings.TrimSpace(verdict)),
	}
}

// itemConfirmed: the engine's verdict for the incident this item belongs to is
// confirmed.
func (sc *statementContext) itemConfirmed(it stmtItem) bool {
	return firstNonEmpty(it.verdict, sc.verdict) == "confirmed"
}

// anyConfirmed: some engine verdict in this answer is confirmed — so a cause
// sentence that does not name it names a DIFFERENT cause.
func (sc *statementContext) anyConfirmed() bool {
	if sc.confirmed() {
		return true
	}
	for _, it := range sc.items {
		if it.role == CauseRoleEngine && it.verdict == "confirmed" {
			return true
		}
	}
	return false
}

// stamp records one item. The FIRST stamp for an id wins, matching the
// evidence dedupe (the same row gathered twice is one fact).
func (sc *statementContext) stamp(ev EvidenceItem, tool string) {
	id := strings.ToLower(strings.TrimSpace(ev.CitationID))
	if id == "" {
		return
	}
	if sc.items == nil {
		sc.items = map[string]stmtItem{}
	}
	if _, seen := sc.items[id]; seen {
		return
	}
	sc.items[id] = stmtItem{
		class: toolStatementClass[tool], role: ev.CauseRole,
		change: ev.Change || changeTools[tool],
		text:   ev.Text, orig: strings.TrimSpace(ev.CitationID),
		verdict: strings.ToLower(strings.TrimSpace(ev.Verdict)),
	}
}

// classOf is the class of one citation id ("" when unknown).
func (sc *statementContext) classOf(id string) string {
	if sc == nil {
		return ""
	}
	return sc.items[strings.ToLower(strings.TrimSpace(id))].class
}

func (sc *statementContext) confirmed() bool { return sc.verdict == "confirmed" }

// hasClass reports whether the turn holds any item of a class.
func (sc *statementContext) hasClass(class string) bool {
	for _, it := range sc.items {
		if it.class == class {
			return true
		}
	}
	return false
}

// hasChange reports whether any gathered item describes a change.
func (sc *statementContext) hasChange() bool {
	for _, it := range sc.items {
		if it.change {
			return true
		}
	}
	return false
}

// engineCauseIsChange: the engine's own leading cause describes a change.
func (sc *statementContext) engineCauseIsChange() bool {
	for _, it := range sc.items {
		if it.role == CauseRoleEngine && it.change {
			return true
		}
	}
	return false
}

// changeEstablished reports whether the ENGINE established a change as the
// cause: its causal chain says so, or its confirmed leading cause is a change.
func (sc *statementContext) changeEstablished() bool {
	if sc.chain != nil && sc.chain.established {
		return true
	}
	return sc.confirmed() && sc.engineCauseIsChange()
}

// citedKnown returns the citation ids in one sentence that are items of this
// turn, lowercased, deduplicated, in order of appearance.
func (sc *statementContext) citedKnown(sentence string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reBracketRef.FindAllStringSubmatch(sentence, -1) {
		id := strings.ToLower(strings.TrimSpace(m[1]))
		if id == "" || seen[id] {
			continue
		}
		if _, ok := sc.items[id]; !ok {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (sc *statementContext) originals(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, sc.items[id].orig)
	}
	return out
}

// ---- the closed vocabularies -----------------------------------------------

// causeMarkers is the CLOSED vocabulary of cause wording: the cause-only
// constructions of verify.go's certaintyMarkers plus the plain causal verbs in
// both voices. `confirm` is deliberately absent: "the log lines confirm the
// transition [log:…]" is an honest observation, not a cause claim.
var causeMarkers = []*regexp.Regexp{
	regexp.MustCompile(`\broot[- ]cause\b`),
	regexp.MustCompile(`\b(?:the|its|their) cause\b`),
	regexp.MustCompile(`\bcaus(?:ed|es|ing)\b`),
	regexp.MustCompile(`\bdue to\b`),
	regexp.MustCompile(`\b(?:led|leads|leading) to\b`),
	regexp.MustCompile(`\btrigger(?:ed|s|ing) (?:the|a|an|this|that|its)\b`),
	regexp.MustCompile(`\bresult(?:ed|s|ing)? in\b`),
	regexp.MustCompile(`\bbecause of\b`),
	regexp.MustCompile(`\bresponsible for\b`),
	regexp.MustCompile(`\bstem(?:s|med|ming)? from\b`),
	regexp.MustCompile(`\battributable to\b`),
}

// reChangeMention: model prose that NAMES a change (the R2 own-cause check
// reads it so a cause sentence cannot cite the engine's cause and still blame
// a change the engine did not).
var reChangeMention = regexp.MustCompile(`\b(?:config(?:uration)?|policy|software|firmware|route[- ]map|acl)[ -]*(?:change|push|update|upgrade|rollout|commit|edit)s?\b|\b(?:the|that|this|a|recent) change\b|\bchange (?:was|were) (?:pushed|made|applied|committed|deployed)\b|\b(?:deploy(?:ment|ed)?|rollout|maintenance window)\b`)

// Source cues: a sentence that ATTRIBUTES its claim to a source.
var (
	reRCACue  = regexp.MustCompile(`\bcorrelix(?:'s|’s)? (?:analysis|verdict|rca|ranks|ranked|rates|rated|identified|identifies|concluded|concludes|confirmed|confirms|lists|listed|places|names|named|attributes|attributed|found|determined)\b|\bthe (?:correlation )?engine(?:'s|’s)? (?:analysis|verdict|conclusion|ranks|ranked|rates|rated|identified|identifies|concluded|concludes|confirmed|confirms|lists|listed|places|names|named|attributes|attributed|found|determined)\b`)
	reHistCue = regexp.MustCompile(`\b(?:past|prior|previous|earlier) (?:investigation|incident|case|occurrence|outage)s?\b|\blast time\b|\bhistorically\b|\bhappened before\b|\bseen (?:this |it )?before\b`)
	reDocCue  = regexp.MustCompile(`\b(?:according to|per) (?:the )?(?:documentation|docs|guide|manual|knowledge base|kb|runbook|vendor|tac|release notes)\b|\b(?:the )?(?:documentation|docs|manual|knowledge base|release notes|vendor guidance) (?:says|states|recommends|notes|describes|warns)\b|\bis documented\b|\bdocumented (?:behaviou?r|issue|limitation|bug)\b`)
)

// reRecommendation: a sentence that is a next step for the operator. Matched
// on the citation-stripped, lowercased sentence with any list marker removed.
var reRecommendation = regexp.MustCompile(`^(?:next(?: steps?)?\s*[:—–-]|recommend(?:ed|ation)?s?\b|(?:i|we) (?:recommend|suggest)\b|suggest(?:ed|ion)?\b|(?:you|operators?|the operator|the noc|the team|someone) (?:should|could|can|may want to)\b|to (?:confirm|verify|close|rule out|narrow)\b|(?:check|run|verify|confirm|compare|review|inspect|escalate|open|contact|roll back|rollback|revert|monitor|collect|capture|pull|look at|consider|investigate|validate|ask|engage|re-?run|restart|reset|replace|reseat|test|trace|clear|correlate)\b)`)

var (
	reListMarker = regexp.MustCompile(`^\s*(?:[-*•]|\d+[.)])\s+`)
	// reTemporalAlready: the sentence already says the change is only
	// correlated in time — R6 does not repeat it.
	reTemporalAlready = regexp.MustCompile(`\bcorrelat|\bcoincid|\bnot established\b|\bnot (?:the|its) cause\b|\bunrelated\b`)
)

// stripCitations removes every bracketed evidence id, so a lexical test reads
// the PROSE: a citation id like "hypothesis:ab12:0" must never act as a hedge.
func stripCitations(s string) string {
	return reBracketRef.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, ":") {
			return ""
		}
		return m
	})
}

// hasCauseWording reports whether one sentence (citations stripped) uses
// cause wording.
func hasCauseWording(bare string) bool {
	low := strings.ToLower(bare)
	for _, re := range causeMarkers {
		if re.MatchString(low) {
			return true
		}
	}
	return false
}

func isHedged(bare string) bool { return certaintyHedges.MatchString(strings.ToLower(bare)) }

func isRecommendation(bare string) bool {
	low := strings.ToLower(strings.TrimSpace(reListMarker.ReplaceAllString(bare, "")))
	return reRecommendation.MatchString(low)
}

// cueClass is the source a sentence attributes its claim to, or "".
func cueClass(bare string) string {
	low := strings.ToLower(bare)
	switch {
	case reRCACue.MatchString(low):
		return ClassCorrelixRCA
	case reHistCue.MatchString(low):
		return ClassHistorical
	case reDocCue.MatchString(low):
		return ClassDocumentation
	}
	return ""
}

// classPrecedence orders the classes a sentence's citations can give it: the
// engine's conclusion first, then what was observed, then what was computed,
// then context.
var classPrecedence = []string{ClassCorrelixRCA, ClassObserved, ClassDerived, ClassHistorical, ClassDocumentation}

func (sc *statementContext) citedClass(ids []string) string {
	have := map[string]bool{}
	for _, id := range ids {
		have[sc.items[id].class] = true
	}
	for _, c := range classPrecedence {
		if have[c] {
			return c
		}
	}
	return ""
}

func (sc *statementContext) citesClass(ids []string, class string) bool {
	for _, id := range ids {
		if sc.items[id].class == class {
			return true
		}
	}
	return false
}

// ---- R5: a change named as the cause ---------------------------------------

// changeChainView is where a CHANGE stands relative to the engine's causal
// chain. The zero value is "read, and not in the chain".
type changeChainView struct {
	step         int    // 1-based chain step that carries a change kind; 0 = none
	relation     string // that step's relation class (OBSERVED | INFERRED | …)
	contradicted bool   // the primary sequence is contradicted
	established  bool   // the engine established the change as the cause
	unread       bool   // an incident is in scope but its chain could not be read
}

// changePosition is the server's clause saying where the cited changes stand
// against Correlix's analysis. Only reached when no change is established.
func (sc *statementContext) changePosition(changes []string) string {
	if v := sc.chain; v != nil {
		switch {
		case v.unread:
			return "Correlix's causal chain for this incident could not be read"
		case v.step > 0 && v.contradicted:
			return "it is step " + strconv.Itoa(v.step) + " of a sequence the evidence contradicts"
		case v.step > 0:
			return "it is step " + strconv.Itoa(v.step) + " of Correlix's proposed sequence (" +
				strings.ToLower(firstNonEmpty(v.relation, RelationInferred)) + "), which Correlix has not established"
		default:
			return "it is not in Correlix's causal chain"
		}
	}
	for _, id := range changes {
		if sc.items[id].role == CauseRoleCandidate {
			return "Correlix ranks it only as an unconfirmed candidate cause"
		}
	}
	for _, id := range changes {
		if sc.items[id].role == CauseRoleEngine {
			return "Correlix has not confirmed the analysis it belongs to"
		}
	}
	switch {
	case sc.confirmed():
		return "the cause Correlix confirmed is a different fault"
	case sc.verdict != "":
		return "Correlix has not established a cause for this incident"
	}
	return "no Correlix analysis in scope names it as the cause"
}

// maxChangeDescChars bounds the change description R5 quotes back.
const maxChangeDescChars = 140

// reDescPrefix are the server's own item prefixes, dropped from a quoted
// description ("candidate cause: X — suspected" → "X").
var reDescPrefix = regexp.MustCompile(`^(?:candidate cause|controller reported|cause|change):\s*`)

// changeDesc is the server-written description of one change item: the first
// line of its text, without the server prefix or trailing qualifier, flattened
// and clamped, with nothing that could read as a citation or end a sentence.
func (sc *statementContext) changeDesc(id string) string {
	it := sc.items[id]
	if base, ok := strings.CutSuffix(id, ":diff"); ok { // a diff BODY quotes its header
		if hdr, has := sc.items[base]; has {
			it = hdr
		}
	}
	line, _, _ := strings.Cut(strings.TrimSpace(it.text), "\n")
	line = OneLine(line)
	line = reDescPrefix.ReplaceAllString(line, "")
	if i := strings.Index(line, " — "); i > 0 && it.role != "" {
		line = line[:i] // the engine's label after the dash is not part of the name
	}
	line = strings.NewReplacer("[", "(", "]", ")", "\"", "'").Replace(line)
	if loc := reSentenceEnd.FindStringIndex(line + " "); loc != nil && loc[0] < len(line) {
		line = line[:loc[0]]
	}
	line = strings.TrimRight(strings.TrimSpace(line), ".;:, ")
	if line == "" {
		return "A recorded change"
	}
	return clampText(line, maxChangeDescChars)
}

// rewriteChangeSentence writes the replacement for one sentence that named a
// change as the cause.
func (sc *statementContext) rewriteChangeSentence(s string, changes []string) string {
	trail := s[len(strings.TrimRight(s, " \t\n")):]
	refs := make([]string, 0, len(changes))
	for _, id := range changes {
		refs = append(refs, "["+sc.items[id].orig+"]")
	}
	return "\"" + sc.changeDesc(changes[0]) + "\" " + strings.Join(refs, " ") +
		" happened around this incident — " + CoincidentChangeWording + " (" + sc.changePosition(changes) + ")." + trail
}

// rewriteChangeCauses is R5. It returns the text and how many sentences it
// rewrote; each rewrite is registered as server-authored so the class pass
// classifies it as the server's statement, not the model's.
func rewriteChangeCauses(text string, sc *statementContext) (string, int) {
	if strings.TrimSpace(text) == "" || sc.changeEstablished() {
		return text, 0
	}
	var b strings.Builder
	n := 0
	for _, s := range splitSentences(text) {
		bare := stripCitations(s)
		if strings.TrimSpace(s) == "" || !hasCauseWording(bare) {
			b.WriteString(s)
			continue
		}
		var changes []string
		for _, id := range sc.citedKnown(s) {
			if sc.items[id].change {
				changes = append(changes, id)
			}
		}
		if len(changes) == 0 {
			b.WriteString(s)
			continue
		}
		rw := sc.rewriteChangeSentence(s, changes)
		if sc.authored == nil {
			sc.authored = map[string]Statement{}
		}
		sc.authored[strings.TrimSpace(rw)] = Statement{
			Class: firstNonEmpty(sc.citedClass(changes), ClassObserved), Grounded: true,
			Citations: sc.originals(changes),
			Note:      "Reworded by Correlix: a change that happened around an incident is " + CoincidentChangeWording + " unless Correlix's analysis establishes it.",
		}
		b.WriteString(rw)
		n++
	}
	return b.String(), n
}

// ---- R2 / R3 / R6: classify and judge every sentence ------------------------

// statementOutcome is what the class pass did.
type statementOutcome struct {
	text             string
	statements       []Statement
	unconfirmedCause int // R2: a cause with no confirmed engine verdict behind it
	foreignCause     int // R2: a cause other than the engine's confirmed one
	ungrounded       int // R3: a claim attributed to a source the turn lacks
	annotated        int // R6: coincident-change wording added
}

func (g statementOutcome) removed() int { return g.unconfirmedCause + g.foreignCause + g.ungrounded }

// ownCause is R2: may this unhedged cause sentence stand? foreign reports that
// a confirmed engine cause exists but the sentence names something else; when
// it is false and ok is false, no engine verdict behind the sentence is
// confirmed.
func (sc *statementContext) ownCause(ids []string, bare string) (ok, foreign bool) {
	confirmedSomewhere := sc.anyConfirmed()
	var engine []stmtItem
	for _, id := range ids {
		it := sc.items[id]
		switch {
		case it.role == CauseRoleCandidate:
			return false, confirmedSomewhere // a ranked alternative named as the cause
		case it.change && !sc.changeEstablished():
			return false, confirmedSomewhere // a change the engine did not establish
		case it.role == CauseRoleEngine, it.change:
			engine = append(engine, it)
		}
	}
	if len(engine) == 0 {
		return false, confirmedSomewhere // nothing ties the sentence to the engine's own cause
	}
	incidents := map[string]bool{}
	for _, it := range engine {
		if !sc.itemConfirmed(it) {
			return false, false // the engine has not confirmed this incident's cause
		}
		incidents[it.incident] = true
	}
	if len(incidents) > 1 {
		return false, true // one cause across separate incidents is not the engine's
	}
	if reChangeMention.MatchString(strings.ToLower(bare)) && !sc.changeEstablished() {
		return false, true // cites the engine's cause, but blames a change
	}
	return true, false
}

// groundStatements classifies every sentence of a MODEL narrative and applies
// R2, R3 and R6. Sentence boundaries come from splitSentences on the original
// text, so the kept statements concatenate back to the returned text exactly.
func groundStatements(text string, sc *statementContext) statementOutcome {
	out := statementOutcome{}
	var b strings.Builder
	for _, s := range splitSentences(text) {
		if strings.TrimSpace(s) == "" {
			attachTrailing(&out, &b, s)
			continue
		}
		if st, ok := sc.authored[strings.TrimSpace(s)]; ok {
			st.Text = s
			out.statements = append(out.statements, st)
			b.WriteString(s)
			continue
		}
		ids := sc.citedKnown(s)
		bare := stripCitations(s)
		hedged := isHedged(bare)
		st := Statement{Citations: sc.originals(ids)}

		if hasCauseWording(bare) && !hedged {
			ok, foreign := sc.ownCause(ids, bare)
			if !ok {
				if foreign {
					out.foreignCause++
				} else {
					out.unconfirmedCause++
				}
				continue
			}
			st.Class, st.Grounded = ClassCorrelixRCA, true
		} else if isRecommendation(bare) {
			st.Class, st.Grounded = ClassRecommendation, true
		} else if cue := cueClass(bare); cue != "" {
			st.Class = cue
			switch {
			case sc.citesClass(ids, cue):
				st.Grounded = true
			case cue == ClassCorrelixRCA && sc.citesClass(ids, ClassDocumentation):
				// How Correlix works, from its own documentation — a product
				// statement, not a claim about this incident's analysis.
				st.Class, st.Grounded = ClassDocumentation, true
			case hedged || sc.hasClass(cue) || (cue == ClassDocumentation && sc.docsInTurn):
				// Downgraded: kept, but disclosed as carrying no evidence of
				// the class it claims (it hedges, or the turn holds such
				// evidence and the sentence did not cite it).
				st.Note = "This sentence cites no " + classNoun(cue) + " evidence of its own."
			default:
				out.ungrounded++ // a source this turn holds no evidence from
				continue
			}
		} else if c := sc.citedClass(ids); c != "" {
			st.Class, st.Grounded = c, true
		} else {
			st.Class = ClassDerived
			st.Note = "No evidence cited — Iris's reading of the evidence, not an observation."
		}

		// R6: a change the engine has not established, cited with an incident
		// in scope, carries the coincident-change wording.
		if sc.incident && st.Class != ClassRecommendation && !sc.changeEstablished() &&
			citesChange(sc, ids) && !reTemporalAlready.MatchString(strings.ToLower(bare)) {
			s = appendBeforeTerminator(s, " ("+CoincidentChangeWording+")")
			out.annotated++
		}
		st.Text = s
		out.statements = append(out.statements, st)
		b.WriteString(s)
	}
	out.text = b.String()
	return out
}

func citesChange(sc *statementContext, ids []string) bool {
	for _, id := range ids {
		if sc.items[id].change {
			return true
		}
	}
	return false
}

// attachTrailing keeps a whitespace-only piece with the statement before it,
// so the statements still reproduce the text.
func attachTrailing(out *statementOutcome, b *strings.Builder, s string) {
	if n := len(out.statements); n > 0 {
		out.statements[n-1].Text += s
		b.WriteString(s)
	}
}

// appendBeforeTerminator inserts suffix before the sentence's closing
// punctuation and trailing whitespace.
func appendBeforeTerminator(s, suffix string) string {
	body := strings.TrimRight(s, " \t\n")
	trail := s[len(body):]
	core := strings.TrimRight(body, ".!?")
	return core + suffix + body[len(core):] + trail
}

func classNoun(class string) string {
	switch class {
	case ClassCorrelixRCA:
		return "Correlix analysis"
	case ClassHistorical:
		return "past-investigation"
	case ClassDocumentation:
		return "documentation"
	}
	return strings.ToLower(class)
}

// serverStatements classifies SERVER-WRITTEN text (an evidence-only summary,
// a fallback, the engine's own phrase): nothing is removed or rewritten; each
// sentence takes the class of what it cites, else defaultClass.
func serverStatements(text, defaultClass, note string, sc *statementContext) []Statement {
	var out []Statement
	for _, s := range splitSentences(text) {
		if strings.TrimSpace(s) == "" {
			if n := len(out); n > 0 {
				out[n-1].Text += s
			}
			continue
		}
		var ids []string
		if sc != nil {
			ids = sc.citedKnown(s)
		}
		st := Statement{Text: s, Class: defaultClass, Grounded: true, Note: note}
		if sc != nil {
			st.Citations = sc.originals(ids)
			if isRecommendation(stripCitations(s)) {
				st.Class = ClassRecommendation
			} else if c := sc.citedClass(ids); c != "" {
				st.Class = c
			}
		}
		out = append(out, st)
	}
	return out
}

// joinStatements is the narrative the statements spell.
func joinStatements(sts []Statement) string {
	var b strings.Builder
	for _, st := range sts {
		b.WriteString(st.Text)
	}
	return b.String()
}

// minSurvivingChars mirrors the honesty gate: below it, nothing usable is left.
const minSurvivingChars = 40

// applyStatementClasses runs R5, the verdict-honesty gate, and R2/R3/R6 over a
// MODEL narrative, discloses every change, counts each rule through the
// scorecard seam, and returns the shipped text with its statements. When
// nothing usable survives, the caller's deterministic summary takes over and
// is classified as server text under fallbackClass.
func (o *Orchestrator) applyStatementClasses(text, fallback, fallbackClass string, sc *statementContext, badges, disc []string) (string, []Statement, []string, []string) {
	text, rewritten := rewriteChangeCauses(text, sc)
	if rewritten > 0 {
		disc = append(disc, plural(rewritten, "sentence")+" naming a change as the cause "+pluralVerb(rewritten, "was", "were")+
			" reworded — a change that happened around an incident is "+CoincidentChangeWording+" unless Correlix's analysis establishes it.")
		badges = append(badges, "Verified")
		o.observeGuard(GuardChangeCausality, rewritten)
	}
	if !sc.perIncident {
		// One turn verdict: the certainty-marker gate runs on it. A briefing
		// over several incidents has none; R2 below judges each cause against
		// the verdict of the incident it cites.
		before := text
		text, badges, disc = o.enforceVerdictHonesty(text, sc.verdict, fallback, badges, disc)
		if strings.TrimSpace(text) == strings.TrimSpace(fallback) && strings.TrimSpace(before) != strings.TrimSpace(fallback) {
			return text, serverStatements(text, fallbackClass, "", sc), badges, disc
		}
	}
	g := groundStatements(text, sc)
	if g.unconfirmedCause > 0 {
		disc = append(disc, plural(g.unconfirmedCause, "sentence")+" stating a cause "+pluralVerb(g.unconfirmedCause, "was", "were")+
			" removed — Correlix has not confirmed a cause here, and only Correlix's analysis may name one.")
		o.observeGuard(GuardUnsupportedCause, g.unconfirmedCause)
	}
	if g.foreignCause > 0 {
		disc = append(disc, plural(g.foreignCause, "sentence")+" naming a cause other than the one Correlix confirmed "+
			pluralVerb(g.foreignCause, "was", "were")+" removed — only the correlation engine's own cause may be stated as the cause.")
		o.observeGuard(GuardUnsupportedCause, g.foreignCause)
	}
	if g.ungrounded > 0 {
		disc = append(disc, plural(g.ungrounded, "sentence")+" attributing a claim to a source this answer holds no evidence from "+
			pluralVerb(g.ungrounded, "was", "were")+" removed.")
		o.observeGuard(GuardUngroundedStatement, g.ungrounded)
	}
	if g.removed() > 0 {
		badges = append(badges, "Verified")
		if len(strings.TrimSpace(g.text)) < minSurvivingChars && strings.TrimSpace(fallback) != "" {
			disc = append(disc, "Nothing usable survived the grounding check, so the evidence-only summary is shown instead.")
			fb := strings.TrimSpace(fallback)
			return fb, serverStatements(fb, fallbackClass, "", sc), badges, disc
		}
	}
	return strings.TrimSpace(g.text), trimLastStatement(g.statements), badges, disc
}

// trimLastStatement drops the trailing whitespace of the last statement, so
// the statements match the trimmed text exactly.
func trimLastStatement(sts []Statement) []Statement {
	if n := len(sts); n > 0 {
		sts[n-1].Text = strings.TrimRight(sts[n-1].Text, " \t\n")
	}
	return sts
}

// trimStatements drops empty statements and trims the outer whitespace of the
// whole sequence, so joinStatements equals the trimmed narrative.
func trimStatements(sts []Statement) []Statement {
	out := sts[:0]
	for _, st := range sts {
		if strings.TrimSpace(st.Text) != "" {
			out = append(out, st)
		}
	}
	if len(out) > 0 {
		out[0].Text = strings.TrimLeft(out[0].Text, " \t\n")
	}
	return trimLastStatement(out)
}

// ---- the copilot agent loop -------------------------------------------------

// AgentToolEvidence is what one governed tool call returned on the copilot
// agent loop, with the tool that produced it (the source of every item's
// class).
type AgentToolEvidence struct {
	Tool  string
	Items []EvidenceItem
}

// AgentGrounding is the statement-class outcome for an agent-loop answer.
type AgentGrounding struct {
	Text        string
	Statements  []Statement
	Disclaimers []string
}

// agentFallbackText replaces an agent answer of which nothing usable
// survived the statement rules — honest, short, and pointing at the evidence.
const agentFallbackText = "Iris removed this answer's claims because Correlix's evidence and analysis do not support them. The cited lookups below are the evidence; open the incident for Correlix's own verdict."

// GroundAgentNarrative applies the statement rules (R5, the honesty gate, R2,
// R3, R6) to the copilot agent loop's final answer — the same rules the
// grounded engine runs, so the engine alone owns the cause on every path
// (tracker 337 N-A5 one brain, N-B4). evidence is what the governed tools
// returned THIS turn under the caller's principal; docIDs are the
// pre-retrieved documentation ids the model was shown. The turn's verdict is
// the engine's verdict on the correlation objects the loop read: one distinct
// tier is the turn's verdict, two different ones are no single verdict (and so
// never "confirmed").
func GroundAgentNarrative(text string, evidence []AgentToolEvidence, docIDs []string) AgentGrounding {
	sc := &statementContext{}
	for _, ev := range evidence {
		for _, it := range ev.Items {
			sc.stamp(it, ev.Tool)
		}
	}
	for _, id := range docIDs {
		sc.stamp(EvidenceItem{CitationID: id, Kind: "doc"}, "search_docs")
	}
	tiers := map[string]bool{}
	for _, it := range sc.items {
		if it.verdict != "" {
			tiers[it.verdict] = true
		}
	}
	if len(tiers) == 1 {
		for t := range tiers {
			sc.verdict = t
		}
	}
	sc.incident = sc.hasClass(ClassCorrelixRCA)
	// No single engine verdict: R2 judges each cause against the verdict of the
	// incident it cites, and the turn-level certainty gate (meant for one
	// incident's narrative) does not run on a general answer.
	sc.perIncident = sc.verdict == ""
	// No provider call is made here; the Redactor is wired anyway so the
	// orchestrator is fail-safe by construction (§15/LLM06), and there is no
	// scorecard seam on this path — the disclosures carry the record.
	o := &Orchestrator{Redactor: Redact}
	out, sts, _, disc := o.applyStatementClasses(text, agentFallbackText, ClassDerived, sc, nil, nil)
	return AgentGrounding{Text: out, Statements: sts, Disclaimers: disc}
}

// ---- the causal chain read (skill path) -------------------------------------

// changeChainFrom places a change relative to the engine's chain. The match is
// by KIND, because a change item's id (`config:<dev>:<sha>`) and the engine's
// observation ids live in different id spaces: the first step whose observed
// kinds include a change kind is the change's place in the sequence. The
// change is ESTABLISHED as the cause only when the engine itself says so — a
// confirmed analysis, an identified root cause, and that step directly
// OBSERVED. A contradicted primary sequence establishes nothing.
func changeChainFrom(res RCAResult) *changeChainView {
	for i, l := range res.CausalChain {
		for _, k := range l.Kinds {
			if !engineChangeKinds[strings.ToLower(strings.TrimSpace(k))] {
				continue
			}
			step := l.Number
			if step <= 0 {
				step = i + 1
			}
			v := &changeChainView{step: step, relation: l.Relation}
			if res.PrimaryContradicted {
				v.contradicted = true
				return v
			}
			v.established = strings.EqualFold(strings.TrimSpace(res.Verdict), "confirmed") &&
				res.RootCause.Identified && l.Relation == RelationObserved
			return v
		}
	}
	return &changeChainView{}
}

// readChangeChain reads the engine's causal chain ONCE for the turn, for R5.
// It runs only when a correlation is bound AND a change was gathered, and it
// is governed exactly like the causal-chain tool: the same gate-2 decision for
// the same principal, and the same tenant-scoped read, where ErrNotFound
// covers an unknown id and another tenant's id alike (§3a) and reads as "not
// in the chain". A read that is refused or fails is UNREAD — R5 then says the
// chain could not be read rather than claiming the change is not in it.
func (o *Orchestrator) readChangeChain(ctx context.Context, p Principal, ent skillEntitySet, sc *statementContext) *changeChainView {
	raw, bound := ent.get("correlation_id")
	if !bound || !sc.hasChange() {
		return nil
	}
	id, err := validIDArg("correlation_id", raw, 64)
	if err != nil {
		return nil // a malformed id names no incident, so there is no chain
	}
	if o.Troubleshoot.RCAResult == nil {
		return &changeChainView{unread: true}
	}
	if _, d, ok := o.Toolbox().Authorize("get_causal_chain", p); !ok || !d.Allow {
		return &changeChainView{unread: true}
	}
	res, err := o.Troubleshoot.RCAResult(ctx, p, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return &changeChainView{}
	case err != nil:
		return &changeChainView{unread: true}
	}
	return changeChainFrom(res)
}

func pluralVerb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
