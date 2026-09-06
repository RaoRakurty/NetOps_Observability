// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// incident.go — ExperienceIncident: the one object the product is judged on.
//
// §M.2 IS THE ARCHITECTURE HERE. An ExperienceIncident is NOT a second incident
// store. It is the DEM evidence packet for the platform's existing incident:
// [ExperienceIncident.IncidentID] holds the internal/incident.Incident id once
// one exists, and everything else on the type is the packet that incident
// carries — impact, journeys, cohorts, hypotheses, evidence, changes,
// ownership, actions, verification. The RUM/synthetic/network/cloud/backend
// signals are EVIDENCE ON ONE INCIDENT, never five incidents (Phase B.B).
//
// DERIVATION, NOT A BACKGROUND WRITER. Incidents are computed from immutable
// evidence at read time by [Detect], which is PURE. That has three properties
// worth more than a persistence layer at this stage: the same bundle always
// yields the same incident (so the acceptance scenario is a table test), no
// background loop can drift from what the API returns, and there is no window
// in which a stored incident and its evidence disagree. Promotion to a durable
// incident record is a separate, deliberate act.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Incident severity — the platform's ladder (internal/incident.Severities), so
// a promoted experience incident needs no translation.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Impact is who and what is affected.
type Impact struct {
	// Users / Sessions / Transactions are nil when not measured. A nil user
	// count is rendered as "not measured", never as 0 — "no users affected" and
	// "we cannot count users" are opposite claims.
	Users        *int `json:"users,omitempty"`
	Sessions     *int `json:"sessions,omitempty"`
	Transactions *int `json:"transactions,omitempty"`

	// JourneySuccessPct / ErrorPct / P95Ms are the measured shape of the
	// degradation; each has a Measured twin because 0 is a real value.
	JourneySuccessPct    *float64 `json:"journey_success_pct,omitempty"`
	JourneySuccessBefore *float64 `json:"journey_success_before,omitempty"`
	ErrorPct             *float64 `json:"error_pct,omitempty"`
	P95Ms                *float64 `json:"p95_ms,omitempty"`

	BusinessValueLost *float64 `json:"business_value_lost,omitempty"`
	Currency          string   `json:"currency,omitempty"`

	// AffectedCohorts / UnaffectedCohorts are the CONTRAST. The unaffected list
	// is not decoration: it is what rules a deployment out, and an incident
	// that cannot state it says so rather than omitting it silently.
	AffectedCohorts   []Cohort `json:"affected_cohorts,omitempty"`
	UnaffectedCohorts []Cohort `json:"unaffected_cohorts,omitempty"`

	// NotMeasured lists the impact dimensions nothing produced, with the reason.
	NotMeasured []string `json:"not_measured,omitempty"`
}

// Remediation action types and lifecycle states (Phase C.13).
const (
	ActionTrafficShift     = "traffic_shift"
	ActionProviderEscalate = "provider_escalation"
	ActionRollback         = "rollback"
	ActionConfigRevert     = "config_revert"
	ActionFailover         = "failover"
	ActionInvestigate      = "investigate"
	ActionOpenTicket       = "open_ticket"
	ActionFixSynthetic     = "fix_synthetic"

	ApprovalNotRequired = "not_required"
	ApprovalRequired    = "required"
	ApprovalGranted     = "granted"
	ApprovalRefused     = "refused"

	ExecutionProposed  = "proposed"
	ExecutionQueued    = "queued"
	ExecutionRunning   = "running"
	ExecutionSucceeded = "succeeded"
	ExecutionFailed    = "failed"
)

// RemediationAction is a PROPOSAL. Nothing in this package executes anything —
// the platform's Action Queue owns execution, approval and audit; this type is
// the proposal it receives, and every field an operator needs to judge the
// proposal before approving it is required.
type RemediationAction struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// Target is what would be acted on (a circuit, a release, a device).
	Target string `json:"target,omitempty"`
	// ProposedBy is "correlix" for a rule-derived proposal and the AI's
	// identifier for an AI-suggested one. It is ALWAYS shown: an operator must
	// know whether a model or a rule proposed the change.
	ProposedBy string `json:"proposed_by"`

	Summary         string   `json:"summary"`
	ExpectedOutcome string   `json:"expected_outcome"`
	Risk            string   `json:"risk"` // low | medium | high
	Reversible      bool     `json:"reversible"`
	RollbackPlan    string   `json:"rollback_plan,omitempty"`
	EvidenceIDs     []string `json:"evidence_ids,omitempty"`

	ApprovalState  string `json:"approval_state"`
	ExecutionState string `json:"execution_state"`
	// VerificationPlan names what would have to become true for the action to
	// count as having worked. An action with no verification plan cannot be
	// verified, and recovery would then be a guess.
	VerificationPlan string `json:"verification_plan"`
}

// Verification is the "did it actually recover" answer (Phase F, SECTION VERIFY).
type Verification struct {
	// Attempted is false before any remediation has been verified.
	Attempted bool `json:"attempted"`
	// Recovered is set ONLY when the evidence agrees. Correlix does not mark an
	// experience recovered because an action completed: an action completing is
	// a fact about the action, not about the experience.
	Recovered bool   `json:"recovered"`
	Detail    string `json:"detail"`
	// Checks are the individual verification results (synthetic recovered, RUM
	// cohort returning to baseline, path clean, service telemetry unchanged).
	Checks []VerificationCheck `json:"checks,omitempty"`
}

// VerificationCheck is one recovery test.
type VerificationCheck struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Measured bool   `json:"measured"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
}

// TimelineEntry is one dated fact on the incident's single timeline.
type TimelineEntry struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"` // detected | impact | change | evidence | action | recovery
	Summary string    `json:"summary"`
	Source  string    `json:"source,omitempty"`
	Ref     string    `json:"ref,omitempty"` // evidence id / change id / action id
	// Observation says whether this entry was observed or inferred — an
	// inferred entry on a timeline that looks measured is how a story becomes a
	// fact.
	Observation string `json:"observation"`
}

// Timeline entry kinds.
const (
	TimelineDetected = "detected"
	TimelineImpact   = "impact"
	TimelineChange   = "change"
	TimelineEvidence = "evidence"
	TimelineAction   = "action"
	TimelineRecovery = "recovery"
)

// ExperienceIncident is the DEM evidence packet for one experience problem.
type ExperienceIncident struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// IncidentID is the platform incident this packet belongs to. Empty means
	// the packet has not been promoted to a durable incident record — which is
	// stated, never hidden behind a synthesised id.
	IncidentID string `json:"incident_id,omitempty"`
	Promoted   bool   `json:"promoted"`

	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`

	DetectedAt    time.Time  `json:"detected_at"`
	FirstImpactAt time.Time  `json:"first_impact_at"`
	RecoveredAt   *time.Time `json:"recovered_at,omitempty"`
	Window        Window     `json:"window"`

	AffectedApps     []string `json:"affected_apps,omitempty"`
	AffectedJourneys []string `json:"affected_journeys,omitempty"`
	AffectedSites    []string `json:"affected_sites,omitempty"`

	Impact Impact `json:"impact"`
	// SLOImpact is how much of the objective this incident consumed, when an
	// objective was declared. Nil when none was — never a default budget.
	SLOImpact *float64 `json:"slo_impact_pct,omitempty"`

	Hypotheses          []Hypothesis `json:"hypotheses"`
	LeadingHypothesisID string       `json:"leading_hypothesis_id,omitempty"`
	// Confidence and VerdictTier are the LEADING hypothesis's. With no leading
	// hypothesis they are 0 / undetermined, and the UI says "no cause has
	// enough evidence yet" rather than showing the best of a bad set.
	Confidence  float64 `json:"confidence"`
	VerdictTier string  `json:"verdict_tier"`

	Evidence        []EvidenceItem    `json:"evidence"`
	MissingEvidence []MissingEvidence `json:"missing_evidence,omitempty"`
	Changes         []ChangeRelevance `json:"changes,omitempty"`

	// PathObservationID points at the immutable pathgraph observation the
	// incident's path section renders. The ordered spine itself is fetched from
	// the frozen path contract's own API — never copied here.
	PathObservationID string `json:"path_observation_id,omitempty"`

	Owner string `json:"owner,omitempty"`
	Seam  string `json:"seam,omitempty"`

	RecommendedActions []RemediationAction `json:"recommended_actions,omitempty"`
	Verification       Verification        `json:"verification"`
	Timeline           []TimelineEntry     `json:"timeline,omitempty"`

	// ScoreRef links the incident to the experience score that dropped, so the
	// two surfaces cannot disagree about which window they describe.
	ScoreRef string `json:"score_ref,omitempty"`
}

// Bundle is everything [Detect] reads. Assembling it is the adapters' job; the
// detector itself touches no store and no clock beyond the Now it is given.
type Bundle struct {
	TenantID string
	Window   Window
	Now      time.Time

	// Journeys and their measured health over the window.
	Journeys      []JourneyDefinition
	JourneyHealth []JourneyHealth

	// Evidence is every normalized observation in the window, already scoped
	// (App/Site/JourneyID) and already carrying its causal pointer.
	Evidence []EvidenceItem
	// Missing is the tenant's telemetry gaps, normally DataHealth.MissingFrom().
	Missing []MissingEvidence
	// Changes is every normalized change in the lookback.
	Changes []ChangeEvent
	// Reliability grades the synthetics behind the evidence, keyed by the
	// evidence item's Entity (the target/definition id). A flaky check's
	// failure is capped at a low severity (Phase H, and Phase O test 11).
	Reliability map[string]SyntheticReliability
}

// Detect derives the experience incidents in a bundle. PURE and deterministic.
//
// One incident per FAILING JOURNEY, plus one per application that has failing
// evidence but no journey declared — an application nobody modelled a journey
// for must still be able to have an incident, or the product would reward
// leaving journeys undeclared.
func Detect(b Bundle) []ExperienceIncident {
	out := []ExperienceIncident{}
	claimedApps := map[string]bool{}

	healthByID := map[string]JourneyHealth{}
	for _, h := range b.JourneyHealth {
		healthByID[h.JourneyID] = h
	}
	for _, def := range b.Journeys {
		h, ok := healthByID[def.ID]
		if !ok || !h.Measured || h.MeetsSLO {
			// A journey that is healthy, or that we could not measure, does not
			// get an incident. The unmeasured case is reported by the Journeys
			// surface as "not measured — reason"; inventing an incident for it
			// would be alarming on absence.
			continue
		}
		claimedApps[def.App] = true
		items := scopeEvidence(b.Evidence, def.App, def.ID)
		out = append(out, buildIncident(b, incidentSubject{
			Kind: "journey", ID: def.ID, Title: def.Name, App: def.App,
			Journey: &def, Health: &h,
		}, items))
	}

	// Applications with failing evidence but no failing journey.
	for _, app := range failingApps(b.Evidence) {
		if app == "" || claimedApps[app] {
			continue
		}
		items := scopeEvidence(b.Evidence, app, "")
		out = append(out, buildIncident(b, incidentSubject{
			Kind: "app", ID: app, Title: app, App: app,
		}, items))
	}

	sort.SliceStable(out, func(i, j int) bool {
		if si, sj := severityRank(out[i].Severity), severityRank(out[j].Severity); si != sj {
			return si > sj
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].ID < out[j].ID
	})
	return out
}

type incidentSubject struct {
	Kind    string
	ID      string
	Title   string
	App     string
	Journey *JourneyDefinition
	Health  *JourneyHealth
}

func buildIncident(b Bundle, subj incidentSubject, items []EvidenceItem) ExperienceIncident {
	inc := ExperienceIncident{
		ID:       IncidentID(b.TenantID, subj.Kind, subj.ID, b.Window.Start),
		TenantID: b.TenantID,
		Title:    incidentTitle(subj),
		Status:   "open",
		Window:   b.Window, DetectedAt: b.Now.UTC(),
		Evidence: items, MissingEvidence: b.Missing,
		VerdictTier: TierUndetermined,
	}
	if subj.App != "" {
		inc.AffectedApps = []string{subj.App}
	}
	if subj.Journey != nil {
		inc.AffectedJourneys = []string{subj.Journey.ID}
	}
	inc.FirstImpactAt = firstImpact(items, b.Window.Start)
	inc.AffectedSites = distinctSites(items)

	// Impact.
	inc.Impact = buildImpact(subj, items)

	// Hypotheses: generated from the evidence's own causal pointers plus the
	// changes that fall in the lookback, then graded by the SAME independence
	// rule the correlation engine uses.
	affected := dominantCohort(items, StanceSupports)
	inc.Impact.AffectedCohorts = cohortsOf(items, StanceSupports)
	inc.Impact.UnaffectedCohorts = cohortsOf(items, StanceContradicts)

	hyps := GenerateHypotheses(subj, items, b.Changes, inc.FirstImpactAt, b.Window, b.TenantID)
	items = attachChangeEvidence(items, hyps, b.Changes, inc.FirstImpactAt, b.Window, b.TenantID)
	inc.Evidence = items
	inc.Hypotheses = RankHypotheses(hyps, items, b.Missing, b.Window, b.Now)

	if lead, ok := Leading(inc.Hypotheses); ok {
		inc.LeadingHypothesisID = lead.ID
		inc.Confidence = lead.Confidence
		inc.VerdictTier = lead.VerdictTier
		inc.Owner, inc.Seam = lead.Owner, lead.Seam
		inc.RecommendedActions = RecommendActions(lead, items)
	}

	causes := make([]string, 0, len(inc.Hypotheses))
	for _, h := range inc.Hypotheses {
		causes = append(causes, h.CauseClass)
	}
	site := ""
	if len(inc.AffectedSites) > 0 {
		site = inc.AffectedSites[0]
	}
	inc.Changes = RankChanges(b.Changes, affected, subj.App, site, inc.Seam, inc.FirstImpactAt, b.Window, causes)

	inc.Severity = severityFor(subj, b.Reliability, items)
	inc.PathObservationID = pathObservationRef(items)
	inc.Verification = planVerification(inc)
	inc.Timeline = buildTimeline(inc)
	if subj.Health != nil {
		inc.ScoreRef = subj.Health.JourneyID + "@" + subj.Health.Window
		if subj.Health.BusinessImpact != nil {
			inc.Impact.BusinessValueLost = subj.Health.BusinessImpact
			inc.Impact.Currency = subj.Health.BusinessImpactCurrency
		}
		if subj.Journey != nil && subj.Journey.SLO.Declared() {
			d := round2(subj.Journey.SLO.SuccessPct - subj.Health.SuccessPct)
			if d < 0 {
				d = 0
			}
			inc.SLOImpact = &d
		}
	}
	return inc
}

// IncidentID is the deterministic identity of a derived incident: the same
// tenant, subject and window always produce the same id, so a link an operator
// shares keeps working and two API calls never disagree about which incident is
// which.
func IncidentID(tenant, kind, subject string, windowStart time.Time) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(tenant), kind, strings.ToLower(subject),
		windowStart.UTC().Format(time.RFC3339),
	}, "|")))
	return "exp-" + hex.EncodeToString(h[:10])
}

func incidentTitle(s incidentSubject) string {
	if s.Kind == "journey" {
		return s.Title + " journey degraded"
	}
	return s.Title + " experience degraded"
}

// GenerateHypotheses turns evidence's causal pointers and the in-window changes
// into candidate explanations. PURE.
//
// Two producers, and no third:
//   - every DISTINCT (cause_class, cause_entity) a supporting item points at
//     becomes one hypothesis, owned by the seam that item named;
//   - every change inside the lookback that touches the scope becomes one
//     hypothesis for its own cause class.
//
// There is deliberately no "default" hypothesis. An incident whose evidence
// implicates nothing has NO hypotheses, and the UI says so — a manufactured
// "unknown cause" hypothesis at 40% confidence is the exact failure mode this
// product exists to avoid.
func GenerateHypotheses(subj incidentSubject, items []EvidenceItem, changes []ChangeEvent,
	firstImpact time.Time, window Window, tenant string) []Hypothesis {

	byCause := map[string]Hypothesis{}
	order := []string{}
	for _, it := range items {
		if it.Stance != StanceSupports || it.CauseClass == "" {
			continue
		}
		key := it.CauseClass + "|" + it.CauseEntity
		if _, ok := byCause[key]; ok {
			continue
		}
		byCause[key] = Hypothesis{
			ID: hypothesisID(tenant, subj.ID, key), TenantID: tenant,
			CauseClass: it.CauseClass, CauseEntity: it.CauseEntity,
			Seam: it.Seam, Owner: it.Owner, FirstImpactAt: firstImpact,
			Explanation: it.Summary,
			BlastRadius: blastRadius(subj),
		}
		order = append(order, key)
	}

	out := make([]Hypothesis, 0, len(order)+len(changes))
	for _, k := range order {
		out = append(out, byCause[k])
	}

	for _, ch := range changes {
		if !window.Aligns(EvidenceItem{Kind: KindChange,
			IndependenceGroup: ModalityChangeRecord,
			Provenance:        Provenance{EventAt: ch.EventAt}}, firstImpact) {
			continue
		}
		if ch.App != "" && subj.App != "" && ch.App != subj.App && ch.Seam == "" {
			continue // a change in another application, touching no seam we care about
		}
		cause := CauseClassForChange(ch.Type)
		key := cause + "|" + ch.Object
		if _, dup := byCause[key]; dup {
			continue
		}
		out = append(out, Hypothesis{
			ID: hypothesisID(tenant, subj.ID, key), TenantID: tenant,
			CauseClass: cause, CauseEntity: ch.Object, Seam: ch.Seam,
			Owner: changeOwner(ch), FirstImpactAt: firstImpact,
			Explanation: ch.Summary + " — a change of this kind can produce this failure shape, and it happened before the first impact",
			BlastRadius: blastRadius(subj),
		})
	}

	// Every hypothesis knows what else was considered. It is what turns a
	// ranked list into an argument rather than an assertion.
	ids := make([]string, 0, len(out))
	for _, h := range out {
		ids = append(ids, h.ID)
	}
	for i := range out {
		alts := make([]string, 0, len(ids))
		for _, id := range ids {
			if id != out[i].ID {
				alts = append(alts, id)
			}
		}
		out[i].Alternatives = alts
	}
	return out
}

// attachChangeEvidence turns every hypothesis-relevant change into a change
// EVIDENCE item, and wires each contradicting item to the hypotheses whose
// cause class it refutes. This is the step that makes negative evidence
// mechanical rather than editorial.
func attachChangeEvidence(items []EvidenceItem, hyps []Hypothesis, changes []ChangeEvent,
	firstImpact time.Time, window Window, tenant string) []EvidenceItem {

	out := make([]EvidenceItem, 0, len(items)+len(changes))
	byCause := map[string][]string{}
	for _, h := range hyps {
		byCause[h.CauseClass] = append(byCause[h.CauseClass], h.ID)
	}
	for _, it := range items {
		if it.Stance == StanceContradicts && len(it.ContradictsCauses) > 0 && len(it.ContradictsHypotheses) == 0 {
			for _, c := range it.ContradictsCauses {
				it.ContradictsHypotheses = append(it.ContradictsHypotheses, byCause[c]...)
			}
			it.ContradictsHypotheses = dedupIDs(it.ContradictsHypotheses)
		}
		if it.Stance == StanceSupports && it.CauseClass != "" && len(it.SupportsHypotheses) == 0 {
			it.SupportsHypotheses = dedupIDs(byCause[it.CauseClass])
			if len(it.SupportsHypotheses) == 0 {
				// It points at a cause nothing here proposed. Leaving it
				// unnamed would make it bear on EVERY hypothesis, which is the
				// opposite of what it says; it becomes context instead —
				// rendered for the operator, scored against nothing.
				it.Stance = StanceNeutral
			}
		}
		out = append(out, it)
	}
	for _, ch := range changes {
		ev := EvidenceItem{
			ID: "chg-" + ch.ID, TenantID: tenant, Kind: KindChange,
			Entity: ch.Object, EntityKind: "change",
			Summary: ch.Summary, Stance: StanceSupports,
			IndependenceGroup: ModalityChangeRecord, Observer: ch.Source,
			Reliability: DefaultReliability(ch.Source),
			App:         ch.App, Site: ch.Site, Seam: ch.Seam, Cohort: ch.Cohort,
			CauseClass: CauseClassForChange(ch.Type), CauseEntity: ch.Object,
			Provenance: ch.Provenance,
		}
		if !window.Aligns(ev, firstImpact) {
			continue
		}
		ev.SupportsHypotheses = dedupIDs(byCause[ev.CauseClass])
		if len(ev.SupportsHypotheses) == 0 {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// RecommendActions proposes the safe next step for a hypothesis. The mapping is
// data, per cause class, and every proposal carries its verification plan — an
// action nobody can verify is not a recommendation, it is a hope.
func RecommendActions(h Hypothesis, items []EvidenceItem) []RemediationAction {
	base := RemediationAction{
		ID: "act-" + h.ID, ProposedBy: "correlix",
		ApprovalState: ApprovalRequired, ExecutionState: ExecutionProposed,
		EvidenceIDs: h.SupportingIDs,
	}
	switch h.CauseClass {
	case CauseTransitDegradation, CauseLastMile:
		base.Type, base.Target = ActionTrafficShift, h.CauseEntity
		base.Summary = "Move affected traffic off " + orUnnamed(h.CauseEntity) + " and raise it with the provider"
		base.ExpectedOutcome = "the failing hop leaves the path and the journey's success rate returns to its baseline"
		base.Risk, base.Reversible = "medium", true
		base.RollbackPlan = "restore the original preference once the provider confirms the segment is clean"
		base.VerificationPlan = "re-run the journey's synthetics from the affected site, confirm the path no longer traverses the failing hop, and confirm the affected cohort's success rate recovers"
	case CauseApplicationRegress:
		base.Type, base.Target = ActionRollback, h.CauseEntity
		base.Summary = "Roll back " + orUnnamed(h.CauseEntity)
		base.ExpectedOutcome = "the failing journey step succeeds again for the affected cohort"
		base.Risk, base.Reversible = "medium", true
		base.RollbackPlan = "re-deploy the release once the regression is understood"
		base.VerificationPlan = "confirm the failing step's synthetics pass and the affected cohort's error rate returns to baseline"
	case CauseCloudPolicy, CauseConfigChange, CauseRoutingChange:
		base.Type, base.Target = ActionConfigRevert, h.CauseEntity
		base.Summary = "Revert the change to " + orUnnamed(h.CauseEntity)
		base.ExpectedOutcome = "the blocked or re-routed traffic flows as it did before the change"
		base.Risk, base.Reversible = "medium", true
		base.RollbackPlan = "re-apply the change once its intent can be met without breaking the path"
		base.VerificationPlan = "confirm the path is restored and the journey's success rate recovers"
	case CauseSyntheticArtifact:
		base.Type, base.Target = ActionFixSynthetic, h.CauseEntity
		base.Summary = "Repair the check " + orUnnamed(h.CauseEntity) + " — its results are not trustworthy"
		base.ExpectedOutcome = "the check produces stable results, so a real failure can be told from a flapping test"
		base.Risk, base.Reversible = "low", true
		base.ApprovalState = ApprovalNotRequired
		base.VerificationPlan = "confirm the check's results stop flipping over a full window"
	default:
		base.Type = ActionInvestigate
		base.Summary = "Investigate " + orUnnamed(h.CauseEntity) + " before acting"
		base.ExpectedOutcome = "enough evidence to choose a safe action"
		base.Risk, base.Reversible = "low", true
		base.ApprovalState = ApprovalNotRequired
		base.VerificationPlan = "an independent second observation of the implicated segment"
	}
	// An unconfirmed hypothesis never proposes a change to production. It
	// proposes gathering the evidence that would confirm it.
	if h.State != StateConfirmed && base.Type != ActionInvestigate && base.Type != ActionFixSynthetic {
		return []RemediationAction{base, {
			ID: base.ID + "-verify", Type: ActionInvestigate, ProposedBy: "correlix",
			Summary:         "Confirm the cause before making the change above",
			ExpectedOutcome: "an independent second observation, which is what this conclusion is currently missing",
			Risk:            "low", Reversible: true,
			ApprovalState: ApprovalNotRequired, ExecutionState: ExecutionProposed,
			VerificationPlan: strings.Join(h.GateReasons, "; "),
			EvidenceIDs:      h.SupportingIDs,
		}}
	}
	return []RemediationAction{base}
}

// planVerification states what would have to become true for the incident to be
// called recovered. Nothing here declares recovery — that is a later act, made
// against these checks.
func planVerification(inc ExperienceIncident) Verification {
	v := Verification{Detail: "Recovery is marked only when the synthetic evidence, the path and — where it exists — the real-user evidence all agree. An action completing is not recovery."}
	v.Checks = []VerificationCheck{
		{Name: "The failing journey's checks pass again", Source: SourceSynthetic,
			Detail: "re-run after the action and compare with the same window before it"},
		{Name: "The implicated path no longer degrades", Source: SourcePathGraph,
			Detail: "a fresh path observation that does not traverse the failing hop, or traverses it cleanly"},
		{Name: "The affected cohort's experience returns to baseline", Source: SourceRUM,
			Detail: "requires first-party real-user telemetry, which is not collected yet — until it is, recovery rests on the synthetic and path evidence alone, and this check reports as not measured"},
	}
	return v
}

func buildTimeline(inc ExperienceIncident) []TimelineEntry {
	out := make([]TimelineEntry, 0, len(inc.Evidence)+len(inc.Changes)+2)
	out = append(out, TimelineEntry{At: inc.FirstImpactAt, Kind: TimelineImpact,
		Summary: "First measured impact on " + inc.Title, Observation: ObservationObserved})
	for _, e := range inc.Evidence {
		out = append(out, TimelineEntry{At: e.EventAt, Kind: TimelineEvidence,
			Summary: e.Summary, Source: e.Source, Ref: e.ID,
			Observation: e.Observation})
	}
	for _, c := range inc.Changes {
		out = append(out, TimelineEntry{At: c.Change.EventAt, Kind: TimelineChange,
			Summary: c.Change.Summary, Source: c.Change.Source, Ref: c.Change.ID,
			Observation: c.Change.Observation})
	}
	out = append(out, TimelineEntry{At: inc.DetectedAt, Kind: TimelineDetected,
		Summary: "Correlix opened this experience incident", Observation: ObservationObserved})
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > MaxListLen {
		out = out[:MaxListLen]
	}
	return out
}

// severityFor grades the incident. Two rules carry it:
//
//   - business importance and the size of the miss set the floor;
//   - a failure whose ONLY supporting evidence is an untrustworthy synthetic is
//     capped at `low`, whatever the miss looks like. That is Phase H's "a single
//     flaky synthetic must not automatically create a high-severity incident",
//     enforced here rather than left to a reviewer.
func severityFor(subj incidentSubject,
	reliability map[string]SyntheticReliability, items []EvidenceItem) string {

	sev := SeverityMedium
	if subj.Journey != nil {
		switch subj.Journey.BusinessImportance {
		case ImportanceCritical:
			sev = SeverityCritical
		case ImportanceHigh:
			sev = SeverityHigh
		case ImportanceLow:
			sev = SeverityLow
		}
	}
	if subj.Health != nil && subj.Journey != nil && subj.Journey.SLO.Declared() {
		miss := subj.Journey.SLO.SuccessPct - subj.Health.SuccessPct
		if miss < 1 && severityRank(sev) > severityRank(SeverityMedium) {
			sev = SeverityMedium // a marginal miss is not a page
		}
	}

	trustworthy, syntheticOnly := false, true
	for _, it := range items {
		if it.Stance != StanceSupports {
			continue
		}
		if it.IndependenceGroup != ModalityActiveProbe {
			syntheticOnly = false
			continue
		}
		r, ok := reliability[it.Entity]
		if !ok || r.Trustworthy() {
			trustworthy = true
		}
	}
	if syntheticOnly && !trustworthy {
		return SeverityLow
	}
	return sev
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ── small pure helpers ──────────────────────────────────────────────────────

func scopeEvidence(items []EvidenceItem, app, journeyID string) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(items))
	for _, it := range items {
		switch {
		case journeyID != "" && it.JourneyID == journeyID:
		case app != "" && it.App == app:
		case it.App == "" && it.JourneyID == "":
			// Unscoped evidence (a path observation, a cloud change) bears on
			// every incident in the window. It is INCLUDED rather than dropped:
			// dropping it is how a network fault stops being visible on the
			// application incident it caused.
		default:
			continue
		}
		out = append(out, it)
	}
	return out
}

func failingApps(items []EvidenceItem) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		if it.Stance == StanceSupports && it.App != "" && !seen[it.App] {
			seen[it.App] = true
			out = append(out, it.App)
		}
	}
	sort.Strings(out)
	return out
}

func firstImpact(items []EvidenceItem, fallback time.Time) time.Time {
	first := time.Time{}
	for _, it := range items {
		if it.Stance != StanceSupports || it.Kind == KindChange {
			continue
		}
		at := it.EventAt
		if first.IsZero() || at.Before(first) {
			first = at
		}
	}
	if first.IsZero() {
		return fallback.UTC()
	}
	return first.UTC()
}

func distinctSites(items []EvidenceItem) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		if it.Stance == StanceSupports && it.Site != "" && !seen[it.Site] {
			seen[it.Site] = true
			out = append(out, it.Site)
		}
	}
	sort.Strings(out)
	return out
}

func cohortsOf(items []EvidenceItem, stance string) []Cohort {
	seen := map[string]bool{}
	out := []Cohort{}
	for _, it := range items {
		if it.Stance != stance || it.Cohort.Empty() {
			continue
		}
		k := it.Cohort.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it.Cohort)
	}
	return out
}

func dominantCohort(items []EvidenceItem, stance string) Cohort {
	c := cohortsOf(items, stance)
	if len(c) == 0 {
		return Cohort{}
	}
	return c[0]
}

func buildImpact(subj incidentSubject, items []EvidenceItem) Impact {
	imp := Impact{}
	if subj.Health != nil && subj.Health.Measured {
		v := subj.Health.SuccessPct
		imp.JourneySuccessPct = &v
	}
	for _, it := range items {
		if it.Kind == KindRealUserMetric && it.Value != nil && imp.ErrorPct == nil && it.Unit == "%" {
			v := *it.Value
			imp.ErrorPct = &v
		}
	}
	// Users and sessions are countable only from real-user telemetry, which
	// this deployment does not collect yet. Saying so is the product; a 0 here
	// would read as "nobody is affected".
	imp.NotMeasured = append(imp.NotMeasured,
		"affected users and sessions — they can only be counted from first-party real-user telemetry, which is not collected yet")
	if imp.ErrorPct == nil {
		imp.NotMeasured = append(imp.NotMeasured, "error rate — no real-user or application error telemetry reached this window")
	}
	return imp
}

func pathObservationRef(items []EvidenceItem) string {
	for _, it := range items {
		if it.Kind == KindPathObservation || it.Kind == KindPathDegradation {
			if it.SourceObject != "" {
				return it.SourceObject
			}
		}
	}
	return ""
}

func blastRadius(subj incidentSubject) string {
	if subj.Journey != nil {
		return "everyone attempting the " + subj.Journey.Name + " journey" + appSuffix(subj.App)
	}
	return "users of " + orUnnamed(subj.App)
}

func appSuffix(app string) string {
	if app == "" {
		return ""
	}
	return " in " + app
}

func changeOwner(ch ChangeEvent) string {
	switch ch.Type {
	case ChangeApplicationDeploy, ChangeFeatureFlag:
		return "application team"
	case ChangeCloud, ChangeSecurityPolicy:
		return "cloud platform team"
	case ChangeRoute, ChangeNetwork, ChangeConfig, ChangeInfrastructure:
		return "network team"
	case ChangeDNS:
		return "DNS owner"
	default:
		return ""
	}
}

func orUnnamed(s string) string {
	if strings.TrimSpace(s) == "" {
		return "the implicated component"
	}
	return s
}

func hypothesisID(tenant, subject, key string) string {
	h := sha256.Sum256([]byte(strings.ToLower(tenant) + "|" + strings.ToLower(subject) + "|" + key))
	return "hyp-" + hex.EncodeToString(h[:8])
}

// ── promotion into the platform incident record (tracker 255) ───────────────
//
// An ExperienceIncident is DERIVED at read time: it is recomputed from the
// window's evidence on every request, so there is never a stored conclusion
// that contradicts the facts beneath it. That is the right default and it is
// not changing.
//
// But a derived object cannot be assigned, acknowledged, ticketed or resolved,
// and it disappears the moment its window rolls past. PROMOTION is the deliberate
// act of saying "this one is real": the platform's incident record
// (internal/incident.Incident, source_type "experience") is created or folded
// into, and the DEM evidence packet is persisted BESIDE it — the incident
// system holds the lifecycle, this package holds the evidence, and neither
// duplicates the other.
//
// KEEPING THE TWO FROM DISAGREEING is the hard half, and it is solved by making
// disagreement VISIBLE rather than by picking a winner. The stored packet is a
// snapshot of what the evidence said at promotion time; the derived incident is
// what it says now. [PromotionDrift] reports every field where they differ, so
// a reader is told "the severity was high when this was promoted and the
// evidence now supports medium" instead of being shown one number and left to
// assume it is the only one.

// PromotionSource is the incident record's source_type for a promoted
// experience incident (design §M.2). It is the value the incident surfaces
// filter on to show the DEM evidence class.
const PromotionSource = "experience"

// Promotion is the durable link between a derived ExperienceIncident and the
// platform incident record it became, plus the evidence packet as it stood when
// an operator decided it was real.
type Promotion struct {
	TenantID string `json:"tenant_id"`
	// ExperienceID is the DERIVED incident's deterministic id. It is the join
	// key and the dedup key, so promoting the same window twice folds into one
	// platform incident rather than creating a second.
	ExperienceID string `json:"experience_id"`
	// IncidentID is the platform incident's id. Never empty in a stored row: a
	// promotion that could not name its incident is not a promotion.
	IncidentID string `json:"incident_id"`

	PromotedAt time.Time `json:"promoted_at"`
	PromotedBy string    `json:"promoted_by"`

	// Packet is the evidence AS IT STOOD at promotion. Frozen on purpose: it is
	// what the operator acted on, and rewriting it on every later read would
	// erase the record of why the incident was raised.
	Packet ExperienceIncident `json:"packet"`
}

// Validate refuses a promotion that cannot state what it links.
func (p *Promotion) Validate() error {
	p.TenantID = normTenant(p.TenantID)
	if p.TenantID == "" || p.TenantID == "*" {
		return errors.New("promotion: a concrete tenant is required")
	}
	p.ExperienceID = clip(strings.TrimSpace(p.ExperienceID), MaxIDBytes)
	if p.ExperienceID == "" {
		return errors.New("promotion: the derived incident id is required")
	}
	p.IncidentID = clip(strings.TrimSpace(p.IncidentID), MaxIDBytes)
	if p.IncidentID == "" {
		return errors.New("promotion: the platform incident id is required (a promotion that cannot name its incident is not a promotion)")
	}
	p.PromotedBy = clip(strings.TrimSpace(p.PromotedBy), MaxIDBytes)
	if p.PromotedAt.IsZero() {
		return errors.New("promotion: promoted_at is required")
	}
	p.PromotedAt = p.PromotedAt.UTC()
	if p.Packet.TenantID != "" && normTenant(p.Packet.TenantID) != p.TenantID {
		return errors.New("promotion: the packet belongs to another tenant")
	}
	return nil
}

// PromotionInput is what the promoter needs to create or fold into the platform
// incident record. It is a VALUE, not the incident package's type: this package
// must not learn the incident system's shape (§2 no cross-domain calls), and
// the integrator adapts one to the other in a few lines.
type PromotionInput struct {
	TenantID string
	// SourceID / DedupKey are both the derived incident's id. Same value, two
	// jobs: the source id records what this incident came FROM, the dedup key
	// makes a second promotion of the same window fold into the first.
	SourceID string
	DedupKey string

	Title       string
	Description string
	Severity    string
	Owner       string
	Actor       string
}

// IncidentPromoter is the platform incident record's seam.
//
// nil is a legal wiring and is HONEST: the incident system of record is
// Postgres-only (the file backend has no incident store at all), so on a file
// deployment the promote route answers 409 with that reason rather than
// pretending to have raised something.
type IncidentPromoter interface {
	// Promote creates the incident or folds the detection into the active one
	// sharing the dedup key. `created` reports which happened — an operator who
	// promotes the same window twice is told it was already raised, not shown a
	// second incident.
	Promote(ctx context.Context, in PromotionInput) (incidentID string, created bool, err error)
}

// PromotionDrift is one field on which the frozen packet and the current
// derivation disagree.
type PromotionDrift struct {
	Field     string `json:"field"`
	AtPromote string `json:"at_promotion"`
	Now       string `json:"now"`
}

// DriftSince compares a promoted packet with the CURRENT derivation of the same
// incident. PURE.
//
// It reports only the fields an operator would act on differently: severity
// (does this still deserve the response it got), the leading hypothesis and its
// verdict tier (is it still the same cause), and recovery. Confidence is
// reported when it moved by more than a rounding amount — a hypothesis that
// slid from 0.81 to 0.42 is a different claim even under the same tier.
func DriftSince(promoted, current ExperienceIncident) []PromotionDrift {
	out := []PromotionDrift{}
	add := func(field, was, now string) {
		if was != now {
			out = append(out, PromotionDrift{Field: field, AtPromote: was, Now: now})
		}
	}
	add("severity", promoted.Severity, current.Severity)
	add("verdict_tier", promoted.VerdictTier, current.VerdictTier)
	add("leading_hypothesis_id", promoted.LeadingHypothesisID, current.LeadingHypothesisID)
	add("status", promoted.Status, current.Status)
	if math.Abs(promoted.Confidence-current.Confidence) > 0.05 {
		add("confidence", formatConfidence(promoted.Confidence), formatConfidence(current.Confidence))
	}
	wasRecovered, isRecovered := promoted.RecoveredAt != nil, current.RecoveredAt != nil
	if wasRecovered != isRecovered {
		add("recovered", boolWord(wasRecovered), boolWord(isRecovered))
	}
	return out
}

func formatConfidence(c float64) string {
	return strconv.FormatFloat(round2(c), 'f', -1, 64)
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ApplyPromotions stamps the durable linkage onto a freshly derived list, so
// the two surfaces cannot disagree about whether an incident was ever raised.
// PURE.
func ApplyPromotions(incidents []ExperienceIncident, byID map[string]Promotion) []ExperienceIncident {
	for i := range incidents {
		p, ok := byID[incidents[i].ID]
		if !ok {
			continue
		}
		incidents[i].IncidentID = p.IncidentID
		incidents[i].Promoted = true
	}
	return incidents
}
