package main

// rca_postmortem.go — Phase 2 of the RCA postmortem enhancements
// (docs/design/rca-postmortem-enhancements-spec.md, APPROVED 2026-07-19;
// Phase 1 models in rca_semantics.go / rca_impact_provenance.go).
//
// Three render-facing view models live here, each a PURE projection of what
// the report builder already derived — no engine re-decision, no new claims:
//
//  1. CAUSAL CHAIN (spec §4) — the top hypothesis's internal causal graph
//     rendered as a numbered primary sequence plus alternative-hypothesis
//     branches. Every step carries its claim, causal role, time interval,
//     epistemic state (observed / corroborated / inferred / reported /
//     unknown / contradicted), supporting evidence references and any
//     contradictions. Steps are joined by TEMPORAL language ("followed by")
//     — causal language appears only as the hypothesis's own proposal,
//     never as an established fact. No confidence percentages anywhere:
//     verdict tier + named reason only.
//
//  2. DETAILED TIMELINE (spec §1 layout) — every timestamped, source-carrying
//     stamp the report already holds (detection milestones, incident phases,
//     symptom onsets, cloud changes) merged chronologically. An entry exists
//     ONLY when both its timestamp and its source lineage exist.
//
//  3. GLOSSARY (spec §5) — dynamic: only terms actually used by THIS report
//     instance. The report-semantics terms (observed, inferred, confirmed,
//     suspected, independent evidence, recovery validation) are always
//     defined when they appear.

import (
	"fmt"
	"netops/backend/internal/noclabel"
	"sort"
	"strings"
)

// ---- causal chain (spec §4) ----------------------------------------------------

// Epistemic-state vocabulary for a causal step (spec §4).
const (
	epistemicObserved     = "observed"
	epistemicCorroborated = "corroborated"
	epistemicInferred     = "inferred"
	epistemicReported     = "reported"
	epistemicUnknown      = "unknown"
	epistemicContradicted = "contradicted"
)

// rcaCausalStep is one numbered step of the primary sequence.
type rcaCausalStep struct {
	Number int    `json:"number"`
	Claim  string `json:"claim"`
	// CausalRole: the step's position in the HYPOTHESIZED propagation —
	// "likely origin" or "propagation step", always qualified as hypothesized.
	CausalRole string `json:"causal_role"`
	// Link: how this step relates to the previous one. Temporal language only
	// ("followed by") — a causal link is the hypothesis's proposal, never a
	// rendered fact.
	Link string `json:"link,omitempty"`
	// EpistemicState: observed | corroborated | inferred | reported | unknown
	// | contradicted. Basis says why in operator words.
	EpistemicState string `json:"epistemic_state"`
	EpistemicBasis string `json:"epistemic_basis"`
	// Interval: the observed time span of this step's evidence ("18:12 → 18:46
	// UTC"), or an honest absence sentence.
	Interval string `json:"interval"`
	// Evidence: humanized references ("packet loss (9 observations from 2
	// sources)"). EvidenceIDs carries the underlying observation ids for the
	// workspace/JSON consumer; the rendered document shows the humanized form.
	Evidence       []string `json:"evidence,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	Contradictions []string `json:"contradictions,omitempty"`
}

// rcaCausalBranch is one alternative hypothesis, rendered as a branch off the
// primary sequence. Tier is the verdict WORD; no percentage exists or renders.
type rcaCausalBranch struct {
	Title          string   `json:"title"`
	Claim          string   `json:"claim"`
	CausalRole     string   `json:"causal_role"`
	EpistemicState string   `json:"epistemic_state"`
	Tier           string   `json:"tier,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	Contradictions []string `json:"contradictions,omitempty"`
}

// rcaCausalChainView is the report's causal-chain block.
type rcaCausalChainView struct {
	Available bool   `json:"available"`
	Note      string `json:"note"`
	// LanguageRule: the honesty rule the renderer enforces, stated on the
	// document so the reader knows what the arrows mean.
	LanguageRule string          `json:"language_rule,omitempty"`
	Steps        []rcaCausalStep `json:"steps,omitempty"`
	// PrimaryContradicted: the primary sequence's hypothesis has been
	// contradicted — the sequence stays visible for the record and says so.
	PrimaryContradicted bool              `json:"primary_contradicted,omitempty"`
	Branches            []rcaCausalBranch `json:"branches,omitempty"`
	BranchNote          string            `json:"branch_note,omitempty"`
}

const rcaCausalLanguageRule = "Steps are numbered in the proposed propagation order. Where only timing connects two steps, the document says \"followed by\" — sequence is not causation. The causal reading of the whole ladder is the hypothesis under investigation, not an established fact."

// buildCausalChainView projects the top hypothesis's causal chain plus the
// alternative hypotheses into the spec-§4 render model. Pure derivation over
// the ranking blob and the already-classified anomalous observations.
func buildCausalChainView(hb rcaHypBlob, hyps []rcaHypothesis, anomalous []map[string]any) rcaCausalChainView {
	out := rcaCausalChainView{}
	if len(hb.Ranking.Hypotheses) == 0 || len(hb.Ranking.Hypotheses[0].CausalChain) == 0 {
		out.Note = "No causal sequence is proposed for this case — the engine has not matched a propagation pattern, and none is invented."
		out.Branches, out.BranchNote = buildCausalBranches(hyps)
		return out
	}
	top := hb.Ranking.Hypotheses[0]
	out.Available = true
	out.LanguageRule = rcaCausalLanguageRule
	out.PrimaryContradicted = top.Contradicted
	out.Note = "Primary sequence — the leading hypothesis's proposed propagation, with each step's own evidence state."
	if top.Contradicted {
		out.Note = "Primary sequence — RULED OUT: the leading hypothesis has been contradicted; the sequence is retained for the record, not as a live explanation."
	}

	// Per-kind evidence index over the anomalous observations.
	type kindEv struct {
		ids       []string
		observers map[string]bool
		first     string
		last      string
		firstRaw  string
		lastRaw   string
		n         int
	}
	byKind := map[string]*kindEv{}
	for _, sig := range anomalous {
		k := fmt.Sprintf("%v", sig["kind"])
		ev := byKind[k]
		if ev == nil {
			ev = &kindEv{observers: map[string]bool{}}
			byKind[k] = ev
		}
		ev.n++
		if id := fmt.Sprintf("%v", sig["signal_id"]); id != "" && id != "<nil>" {
			ev.ids = append(ev.ids, id)
		}
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			ev.observers[o] = true
		}
		if ts, ok := parseChTS(fmt.Sprintf("%v", sig["ts"])); ok {
			raw := fmt.Sprintf("%v", sig["ts"])
			if ev.firstRaw == "" || raw < ev.firstRaw {
				ev.firstRaw, ev.first = raw, fmtUTC(ts)
			}
			if raw > ev.lastRaw {
				ev.lastRaw, ev.last = raw, fmtUTC(ts)
			}
		}
	}

	for i, c := range top.CausalChain {
		step := rcaCausalStep{
			Number: i + 1,
			Claim:  rcaSignalWordSweep.Replace(c.Stage),
		}
		if i > 0 {
			step.Link = "followed by"
		}
		if c.Root {
			step.CausalRole = "likely origin — hypothesized, not established"
		} else {
			step.CausalRole = "propagation step (hypothesized)"
		}
		// Gather this step's evidence across its declared observation kinds.
		var (
			evidence  []string
			ids       []string
			observers = map[string]bool{}
			first     string
			last      string
			total     int
		)
		for _, k := range c.Kinds {
			ev := byKind[k]
			if ev == nil {
				continue
			}
			total += ev.n
			label := noclabel.Kind(k)
			if len(ev.observers) > 1 {
				evidence = append(evidence, fmt.Sprintf("%s (%d observations from %d sources)", label, ev.n, len(ev.observers)))
			} else {
				evidence = append(evidence, fmt.Sprintf("%s (%s)", label, strings.ToLower(countNoun(ev.n, "observation"))))
			}
			ids = append(ids, firstN(ev.ids, 8)...)
			for o := range ev.observers {
				observers[o] = true
			}
			if first == "" || (ev.first != "" && ev.first < first) {
				first = ev.first
			}
			if ev.last > last {
				last = ev.last
			}
		}
		step.Evidence = evidence
		step.EvidenceIDs = firstN(ids, 8)
		switch {
		case first != "" && last != "" && first != last:
			step.Interval = first + " → " + last
		case first != "":
			step.Interval = first
		default:
			step.Interval = "no timestamped evidence for this step"
		}
		note := rcaSignalWordSweep.Replace(c.Note)
		switch {
		case !c.Witnessed:
			step.EpistemicState = epistemicUnknown
			step.EpistemicBasis = "not observed — part of the known propagation pattern, but it carried no evidence in this window and is not claimed"
			if note != "" {
				step.EpistemicBasis += " (" + strings.TrimRight(note, ".") + ")"
			}
		case len(observers) >= 2:
			step.EpistemicState = epistemicCorroborated
			step.EpistemicBasis = fmt.Sprintf("observed independently by %d sources", len(observers))
		case total > 0:
			step.EpistemicState = epistemicObserved
			step.EpistemicBasis = "observed by one source — a fact about this step, not independent confirmation"
		default:
			// witnessed by the engine's chain, but no per-observation rows are
			// attached to this rendering — reported, never upgraded.
			step.EpistemicState = epistemicReported
			step.EpistemicBasis = "reported by the analysis record; no per-observation rows are attached to this step"
			if note != "" {
				step.EpistemicBasis += " (" + strings.TrimRight(note, ".") + ")"
			}
		}
		if top.Contradicted {
			step.Contradictions = append(step.Contradictions, noclabel.HumanizeMissing(humanizeClauses(top.Contradictions))...)
		}
		out.Steps = append(out.Steps, step)
	}
	out.Branches, out.BranchNote = buildCausalBranches(hyps)
	return out
}

// buildCausalBranches projects the non-leading hypotheses as branches.
func buildCausalBranches(hyps []rcaHypothesis) ([]rcaCausalBranch, string) {
	var out []rcaCausalBranch
	for i, h := range hyps {
		if i == 0 {
			continue // the primary sequence
		}
		b := rcaCausalBranch{
			Title:          h.Title,
			Claim:          orDefault(h.Problem, h.Title),
			CausalRole:     strings.ReplaceAll(h.CausalRole, "_", " "),
			Tier:           strings.ToLower(h.Label),
			Evidence:       firstN(h.Supporting, 3),
			Contradictions: firstN(h.Contradicting, 3),
		}
		switch {
		case h.Contradicted:
			b.EpistemicState = epistemicContradicted
		case h.ObservationState == "confirmed":
			b.EpistemicState = epistemicObserved // the condition is a fact; its causal role is not
		case h.ObservationState == "observed":
			b.EpistemicState = epistemicObserved
		default:
			b.EpistemicState = epistemicUnknown
		}
		out = append(out, b)
	}
	note := ""
	if len(out) == 0 {
		note = "No alternative hypothesis carries evidence in this window."
	} else {
		note = "Alternative hypotheses — branches from the primary sequence; full detail under Root cause and contributing factors."
	}
	return out, note
}

// ---- detailed timeline ---------------------------------------------------------

// rcaTimelineEntry is one chronological row: timestamp + event + the source
// lineage of the stamp. An entry without either never exists.
type rcaTimelineEntry struct {
	TS     string `json:"ts"`
	Event  string `json:"event"`
	Source string `json:"source"`
}

const rcaTimelineMaxEntries = 60

// buildDetailedTimeline merges every timestamped, source-carrying stamp the
// report already holds into one chronological list.
func buildDetailedTimeline(rep *rcaReport) []rcaTimelineEntry {
	var out []rcaTimelineEntry
	add := func(ts, event, source string) {
		ts = strings.TrimSpace(ts)
		if ts == "" || event == "" || source == "" {
			return
		}
		if _, ok := parseChTS(strings.TrimSuffix(ts, " UTC")); !ok {
			return
		}
		out = append(out, rcaTimelineEntry{TS: ts, Event: event, Source: source})
	}
	for _, m := range rep.Semantics.Milestones {
		add(m.TS, m.Label, m.SourceLineage)
	}
	for _, p := range rep.Phases {
		add(p.StartAt, "Phase begins: "+strings.ReplaceAll(p.Type, "_", " ")+" — "+p.Summary,
			"derived from the observed evidence timeline (recovery reconciliation)")
		if p.EndAt != "" && p.EndAt != p.StartAt {
			add(p.EndAt, "Phase ends: "+strings.ReplaceAll(p.Type, "_", " "),
				"derived from the observed evidence timeline (recovery reconciliation)")
		}
	}
	for _, s := range rep.Evidence.Symptoms {
		src := "observed by " + orDefault(s.Source, "an attached evidence source")
		add(s.First, "Symptom onset: "+s.Label, src)
		if s.Last != "" && s.Last != s.First {
			add(s.Last, "Latest observation: "+s.Label, src)
		}
	}
	for _, c := range rep.CloudChanges {
		src := orDefault(c.EventSource, "provider change/audit stream")
		what := strings.TrimSpace(orDefault(c.Provider, "Provider") + " change event on " + orDefault(c.Resource, "an in-window resource"))
		if !c.Attached {
			what += " (in-window context — not attached to this case)"
		}
		add(c.At, what, src)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TS != out[j].TS {
			return out[i].TS < out[j].TS
		}
		return out[i].Event < out[j].Event
	})
	if len(out) > rcaTimelineMaxEntries {
		out = out[:rcaTimelineMaxEntries]
	}
	return out
}

// ---- glossary (spec §5) --------------------------------------------------------

type rcaGlossaryEntry struct {
	Term       string `json:"term"`
	Definition string `json:"definition"`
}

// rcaGlossaryDefs is the full term registry. Definitions are written for a NOC
// admin: plain words, no engine vocabulary.
var rcaGlossaryDefs = []rcaGlossaryEntry{
	{"observed", "Directly measured by an attached telemetry source inside this incident's window. An observed statement is a fact about what a source recorded — not an interpretation."},
	{"corroborated", "Observed independently by two or more sources that do not share a failure mode. Repetition from one source is persistence, never corroboration."},
	{"reported", "Stated by an analysis record or an external party without per-observation rows attached in this report. Reported statements are carried, not confirmed."},
	{"inferred", "Concluded from surrounding evidence rather than measured directly (for example, recovery inferred because the anomalous observations stopped). The report always says when a statement is inferred."},
	{"confirmed", "Established by independent, agreeing evidence sources — never by one source repeating, and never by timing alone."},
	{"suspected", "Supported by some evidence but not independently confirmed; alternative explanations remain open."},
	{"contradicted", "Ruled out: evidence exists that is inconsistent with the statement. Contradicted items stay visible for the record."},
	{"independent evidence", "Evidence from measurement systems with no shared failure mode (for example an active check, a routing-plane event and a traffic measurement). Their agreement is information; one system repeating is not."},
	{"synthetic check", "A scripted test transaction run from a monitoring vantage. A failed synthetic check proves the configured transaction failed from that vantage — it is never converted into a count of affected real users."},
	{"real-user impact", "Effect on actual user traffic, shown only by evidence from real sessions or the serving infrastructure itself. It is a separate question from synthetic-check failures and is never derived from them."},
	{"not measured", "No telemetry with valid provenance quantifies this value for this case. Not measured is stated as such — it is never rendered as zero, and it is not evidence of no impact."},
	{"coverage gap", "An interval where a telemetry class produced no data. A gap is absence of measurement, not evidence of health — nothing is concluded from it."},
	{"recovery validation", "A post-recovery observation window that checks the fault does not recur. Completing it without recurrence validates the recovery; a component coming back alone does not."},
	{"seam", "A handoff boundary between two responsible parties on the service path (for example, your network edge and a provider's network). Localizing a fault to a seam narrows ownership; it does not name the root cause."},
	{"vantage", "A distinct measurement viewpoint (a place observations are taken from). Two vantages seeing the same fault is breadth; one vantage repeating is not."},
	{"validation scenario", "A deliberately induced, non-production exercise. Its report documents the scenario and never claims production impact or severity."},
}

// buildRcaGlossary derives the dynamic glossary: only terms this report
// instance actually uses. The report-semantics terms (observed, inferred,
// confirmed, suspected, independent evidence, recovery validation) are always
// included when they appear anywhere in the rendered concepts.
func buildRcaGlossary(rep *rcaReport) []rcaGlossaryEntry {
	states := []string{
		rep.States.Analysis, rep.States.Symptom, rep.States.FaultDomain,
		rep.States.RootCauseState, rep.States.Impact, rep.States.ImpactSynthetic,
		rep.States.ImpactRealUser, rep.States.Recovery, rep.States.Incident,
	}
	hasState := func(v string) bool {
		for _, s := range states {
			if strings.Contains(s, v) {
				return true
			}
		}
		return false
	}
	stepState := func(v string) bool {
		for _, s := range rep.CausalChain.Steps {
			if s.EpistemicState == v {
				return true
			}
		}
		for _, b := range rep.CausalChain.Branches {
			if b.EpistemicState == v {
				return true
			}
		}
		return false
	}
	anyHyp := func(pred func(rcaHypothesis) bool) bool {
		for _, h := range rep.Hypotheses {
			if pred(h) {
				return true
			}
		}
		return false
	}
	impactStatus := func(v string) bool {
		for _, m := range rep.ImpactProvenance.Measures {
			if m.Status == v {
				return true
			}
		}
		return false
	}
	hasMilestone := func(key string) bool {
		for _, m := range rep.Semantics.Milestones {
			if m.Key == key {
				return true
			}
		}
		return false
	}
	coverageGap := false
	for _, l := range rep.Coverage {
		if l.State == "no_data" || l.MissingInterval != "" || l.Coverage == "partial" || l.Coverage == "none" {
			coverageGap = true
			break
		}
		if a := l.Assessment; a != nil && (a.LeadingGap != "" || a.TrailingGap != "" || a.InternalGapTotal != "") {
			coverageGap = true
			break
		}
	}
	seamUsed := len(rep.Scope.Seams) > 0 || strings.Contains(rep.FaultLocalization.ObjectType, "seam")
	for _, h := range rep.Topology.Hops {
		if h.SeamID != "" {
			seamUsed = true
		}
	}

	used := map[string]bool{
		// evidence exists ⇒ the document uses "observed" (symptom lineage, evidence
		// summary) and the "independent sources" headline.
		"observed":     rep.Evidence.Observations > 0 || len(rep.Evidence.Symptoms) > 0 || stepState(epistemicObserved),
		"corroborated": stepState(epistemicCorroborated),
		"reported":     stepState(epistemicReported),
		"inferred":     rep.States.Recovery == "inferred" || impactStatus(impactInferred) || stepState(epistemicInferred),
		"confirmed": hasState("confirmed") || anyHyp(func(h rcaHypothesis) bool {
			return h.ObservationState == "confirmed" || strings.EqualFold(h.Label, "confirmed")
		}),
		"suspected":            hasState("suspected") || anyHyp(func(h rcaHypothesis) bool { return strings.EqualFold(h.Label, "suspected") }),
		"contradicted":         rep.CausalChain.PrimaryContradicted || stepState(epistemicContradicted) || anyHyp(func(h rcaHypothesis) bool { return h.Contradicted }),
		"independent evidence": rep.Evidence.Observations > 0 || rep.Evidence.IndependentSources > 0,
		"synthetic check":      rep.Signals.Probe != nil || rep.States.ImpactSynthetic == "confirmed",
		"real-user impact":     rep.States.ImpactRealUser != "",
		"not measured":         impactStatus(impactNotMeasured),
		"coverage gap":         coverageGap,
		"recovery validation":  hasMilestone(msRecoveryValidation) || rep.Times.MonitoringUntil != "" || strings.HasPrefix(rep.States.Monitoring, "completed"),
		"seam":                 seamUsed,
		"vantage":              len(rep.Accounting.LogicalVantages) > 0 || rep.Topology.VantageID != "",
		"validation scenario":  rep.Validation,
	}
	var out []rcaGlossaryEntry
	for _, def := range rcaGlossaryDefs {
		if used[def.Term] {
			out = append(out, def)
		}
	}
	return out
}
