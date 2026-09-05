package experience

// change.go — ChangeEvent: the normalized record of something a human or a
// system CHANGED, from any producer, on one timeline.
//
// "What changed?" is the question an operator asks second and a dashboard
// usually answers worst, because each producer keeps its own list. This type is
// the one list: config capture/drift, cloud resource and policy changes, BGP
// route changes, deployments and feature flags all normalize onto it, keep
// their own provenance, and are RANKED BY CORRELATION rather than by clock
// distance (Phase F: "rank nearby changes using actual correlation, not only
// temporal distance").

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Change types — the owner's Phase C.6 list, unchanged.
const (
	ChangeApplicationDeploy = "APPLICATION_DEPLOY"
	ChangeConfig            = "CONFIG_CHANGE"
	ChangeFeatureFlag       = "FEATURE_FLAG_CHANGE"
	ChangeCloud             = "CLOUD_CHANGE"
	ChangeNetwork           = "NETWORK_CHANGE"
	ChangeSecurityPolicy    = "SECURITY_POLICY_CHANGE"
	ChangeDNS               = "DNS_CHANGE"
	ChangeRoute             = "ROUTE_CHANGE"
	ChangeInfrastructure    = "INFRASTRUCTURE_CHANGE"
)

var knownChangeTypes = map[string]bool{
	ChangeApplicationDeploy: true, ChangeConfig: true, ChangeFeatureFlag: true,
	ChangeCloud: true, ChangeNetwork: true, ChangeSecurityPolicy: true,
	ChangeDNS: true, ChangeRoute: true, ChangeInfrastructure: true,
}

// ValidChangeType reports whether t is a declared change type.
func ValidChangeType(t string) bool { return knownChangeTypes[t] }

// causeClassForChange maps a change type onto the cause class a hypothesis
// blaming it would carry. Declared as data so the detector never invents a
// mapping inline.
var causeClassForChange = map[string]string{
	ChangeApplicationDeploy: CauseApplicationRegress,
	ChangeConfig:            CauseConfigChange,
	ChangeFeatureFlag:       CauseApplicationRegress,
	ChangeCloud:             CauseCloudEdge,
	ChangeNetwork:           CauseConfigChange,
	ChangeSecurityPolicy:    CauseCloudPolicy,
	ChangeDNS:               CauseDNSResolution,
	ChangeRoute:             CauseRoutingChange,
	ChangeInfrastructure:    CauseConfigChange,
}

// CauseClassForChange returns the cause class a hypothesis about this change
// carries, or CauseUnknown for a type nobody mapped.
func CauseClassForChange(t string) string {
	if c, ok := causeClassForChange[t]; ok {
		return c
	}
	return CauseUnknown
}

// Bounds on the before/after payloads. A change record is a POINTER to a diff,
// not a copy of a configuration: an unbounded blob here is how a credential
// ends up in a change feed.
const (
	MaxChangeValueBytes    = 2000
	MaxChangesPerTenant    = 20000
	DefaultChangePageLimit = 100
)

// ChangeEvent is one normalized change.
type ChangeEvent struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Type     string `json:"type"`

	// Actor is who or what made the change (a username, a pipeline, a
	// controller). Never a credential, never an email unless the tenant's data
	// policy allows one — the data_class on the provenance says which.
	Actor string `json:"actor,omitempty"`
	// Object is what was changed — a device id, a resource arn, a service name,
	// a flag key, a prefix.
	Object     string `json:"object"`
	ObjectKind string `json:"object_kind,omitempty"` // device | cloud_resource | service | flag | prefix | dns_record

	Summary string `json:"summary"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`

	ReleaseID   string `json:"release_id,omitempty"`
	RollbackRef string `json:"rollback_ref,omitempty"`

	// Site / App / Seam place the change on the experience map, which is what
	// lets the ranker ask "does this change even touch the failing path" rather
	// than only "did it happen recently".
	Site string `json:"site,omitempty"`
	App  string `json:"app,omitempty"`
	Seam string `json:"seam,omitempty"`

	// Cohort is the population the change reached. It is the field that makes
	// the owner's acceptance scenario decidable: a deploy whose cohort does NOT
	// intersect the affected cohort is contradicted, not merely unproven.
	Cohort Cohort `json:"cohort"`

	Provenance `json:"provenance"`
}

// Validate normalizes the record and refuses one that cannot be placed.
func (c *ChangeEvent) Validate() error {
	c.ID = clip(strings.TrimSpace(c.ID), MaxIDBytes)
	if c.ID == "" {
		return errors.New("change: id is required")
	}
	c.TenantID = strings.ToLower(strings.TrimSpace(c.TenantID))
	if c.TenantID == "" || c.TenantID == "*" {
		return errors.New("change: a concrete tenant is required")
	}
	c.Type = strings.ToUpper(strings.TrimSpace(c.Type))
	if !ValidChangeType(c.Type) {
		return fmt.Errorf("change %s: unknown type %q", c.ID, clip(c.Type, 40))
	}
	c.Actor = clip(strings.TrimSpace(c.Actor), MaxLabelBytes)
	c.Object = clip(strings.TrimSpace(c.Object), MaxIDBytes)
	if c.Object == "" {
		return fmt.Errorf("change %s: object is required (a change to nothing cannot be correlated)", c.ID)
	}
	c.ObjectKind = labelSafe(c.ObjectKind)
	c.Summary = clip(strings.TrimSpace(c.Summary), MaxSummaryBytes)
	if c.Summary == "" {
		return fmt.Errorf("change %s: a summary is required", c.ID)
	}
	c.Before = clip(strings.TrimSpace(c.Before), MaxChangeValueBytes)
	c.After = clip(strings.TrimSpace(c.After), MaxChangeValueBytes)
	c.ReleaseID = clip(strings.TrimSpace(c.ReleaseID), MaxIDBytes)
	c.RollbackRef = clip(strings.TrimSpace(c.RollbackRef), MaxIDBytes)
	c.Site, c.App, c.Seam = labelSafe(c.Site), labelSafe(c.App), labelSafe(c.Seam)
	return c.Provenance.Validate()
}

// ChangeRelevance is one change scored against an incident.
type ChangeRelevance struct {
	Change ChangeEvent `json:"change"`
	// Score is 0..1 — how much this change bears on THIS incident.
	Score float64 `json:"score"`
	// Reasons are the components of that score, in operator language. They are
	// the answer to "why is this change at the top of the list", which is the
	// question a purely chronological list can never answer.
	Reasons []string `json:"reasons"`
	// Precedes is false when the change happened AFTER first impact. Such a
	// change is still SHOWN (an operator wants to see what was done during the
	// incident) but it can never support a cause hypothesis.
	Precedes bool `json:"precedes_impact"`
	// TouchesAffectedCohort is false when the change's cohort demonstrably does
	// not include the affected population — the contradiction that rules a
	// deployment out.
	TouchesAffectedCohort bool `json:"touches_affected_cohort"`
}

// Change-relevance weights. Exported because a ranked list whose weights are
// secret is a ranked list nobody can argue with.
const (
	RelevanceProximity = 0.35 // how close in time, inside the lookback
	RelevanceScope     = 0.35 // does it touch the failing app / site / seam
	RelevanceCohort    = 0.20 // does its cohort include the affected one
	RelevanceClass     = 0.10 // is its type one that plausibly causes this shape
)

// RankChanges scores changes against an incident's scope and orders them.
//
// affected is the incident's cohort (possibly partly empty — an unrecorded
// dimension neither matches nor excludes), app/site/seam name the failing
// scope, and firstImpact anchors change-before-effect.
//
// The ordering is by SCORE, then by recency as a tie-break. A change that
// happened after first impact scores at most RelevanceScope+RelevanceCohort and
// is marked Precedes=false, so it can never top a list of candidate causes.
func RankChanges(changes []ChangeEvent, affected Cohort, app, site, seam string,
	firstImpact time.Time, window Window, causes []string) []ChangeRelevance {

	look := window.ChangeLookback
	if look <= 0 {
		look = DefaultChangeLookback
	}
	causeSet := map[string]bool{}
	for _, c := range causes {
		causeSet[c] = true
	}
	out := make([]ChangeRelevance, 0, len(changes))
	for _, ch := range changes {
		r := ChangeRelevance{Change: ch, TouchesAffectedCohort: true}
		score := 0.0

		gap := firstImpact.Sub(ch.EventAt)
		switch {
		case gap >= 0 && gap <= look:
			r.Precedes = true
			// Linear within the lookback: immediately before is full marks,
			// at the edge of the window it is worth nothing.
			prox := 1 - float64(gap)/float64(look)
			score += RelevanceProximity * prox
			r.Reasons = append(r.Reasons, "happened "+humanGap(gap)+" before the first impact")
		case gap < 0:
			r.Reasons = append(r.Reasons, "happened AFTER the first impact, so it cannot have caused it")
		default:
			r.Reasons = append(r.Reasons, "happened outside the window a change is considered in")
		}

		scope := 0.0
		hits := make([]string, 0, 3)
		if ch.App != "" && ch.App == app {
			scope, hits = scope+1, append(hits, "the failing application")
		}
		if ch.Site != "" && ch.Site == site {
			scope, hits = scope+1, append(hits, "the affected site")
		}
		if ch.Seam != "" && ch.Seam == seam {
			scope, hits = scope+1, append(hits, "the implicated seam")
		}
		if scope > 0 {
			score += RelevanceScope * clamp01(scope/2)
			r.Reasons = append(r.Reasons, "touches "+joinWords(hits))
		} else {
			r.Reasons = append(r.Reasons, "does not touch the failing application, site or seam that we can see")
		}

		switch cohortRelation(ch.Cohort, affected) {
		case cohortIncludes:
			score += RelevanceCohort
			r.Reasons = append(r.Reasons, "reached the affected population")
		case cohortExcludes:
			r.TouchesAffectedCohort = false
			r.Reasons = append(r.Reasons, "its cohort does not include the affected population — this change did not reach the users who are failing")
		default:
			// Unknown cohort: neither credited nor penalised. Saying "we do not
			// know who it reached" is the honest third answer.
			r.Reasons = append(r.Reasons, "we cannot tell which population it reached")
		}

		if causeSet[CauseClassForChange(ch.Type)] {
			score += RelevanceClass
			r.Reasons = append(r.Reasons, "is the kind of change that produces this failure shape")
		}

		r.Score = round2(clamp01(score))
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Change.EventAt.After(out[j].Change.EventAt)
	})
	return out
}

// cohort relation outcomes.
const (
	cohortUnknown = iota
	cohortIncludes
	cohortExcludes
)

// cohortRelation compares a change's cohort with the affected one.
//
// The rule is deliberately conservative: a dimension recorded on BOTH sides and
// differing means EXCLUDES; a dimension recorded on both and matching means
// INCLUDES; anything else is UNKNOWN. An empty cohort on either side can never
// exclude, because an unrecorded dimension is not evidence of anything.
func cohortRelation(change, affected Cohort) int {
	pairs := [][2]string{
		{change.Site, affected.Site},
		{change.ISP, affected.ISP},
		{change.Region, affected.Region},
		{change.DeviceType, affected.DeviceType},
		{change.Browser, affected.Browser},
		{change.AppVersion, affected.AppVersion},
		{change.NetworkType, affected.NetworkType},
		{change.FeatureFlag, affected.FeatureFlag},
	}
	comparable, match := 0, 0
	for _, p := range pairs {
		if p[0] == "" || p[1] == "" {
			continue
		}
		comparable++
		if strings.EqualFold(p[0], p[1]) {
			match++
		}
	}
	switch {
	case comparable == 0:
		return cohortUnknown
	case match == comparable:
		return cohortIncludes
	case match == 0:
		return cohortExcludes
	default:
		return cohortUnknown // partial overlap proves neither
	}
}

// humanGap renders a duration the way an operator says it.
func humanGap(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute", "minutes")
	default:
		return plural(int(d.Hours()), "hour", "hours")
	}
}
