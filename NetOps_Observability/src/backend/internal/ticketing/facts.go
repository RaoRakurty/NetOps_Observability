package ticketing

import "time"

// CorrFacts is the minimal, decision-relevant projection of one RCA
// object: enough for the policy to decide ticket-worthiness without re-running
// correlation. Derived from the same (meta, signals) the RCA view consumes;
// the projector (buildCorrTicketFacts) stays with the integrator because it
// reads rcaPathView.
type CorrFacts struct {
	Verdict           string // undetermined | suspected | confirmed
	Confidence        float64
	Internal          bool   // internal/debug-only monitoring (kept out of customer tickets)
	Validation        bool   // §11 validation/lab/fault-injection scenario — never production side effects
	ProbeOnly         bool   // every attached signal is an active probe
	LowAuthorityProbe bool   // probe-only AND no probe carried real authority
	PeakSeverity      string // info | warn | high | crit (max over attached signals)
	HasAffectedEntity bool   // a meaningful affected device/interface/path/app exists
	AffectedScope     string // human scope, e.g. "leaf1 → wan-r2" or "edge1 Gi0/1"
	AffectedEntities  []string
	ImpactedApps      []string
	Signature         string
	WindowStart       time.Time
	WindowEnd         time.Time
	// ConsistencyIssues: P1 fact-level contradictions found while projecting
	// the facts (rca.TicketFactConsistencyIssues — the emitter-side quality
	// gate). Non-empty holds every RCA-derived emission with an observable
	// reason.
	ConsistencyIssues []string
}

// PersistenceSeconds is how long the incident has been observed (window span).
func (f CorrFacts) PersistenceSeconds() int {
	if f.WindowStart.IsZero() || f.WindowEnd.IsZero() || !f.WindowEnd.After(f.WindowStart) {
		return 0
	}
	return int(f.WindowEnd.Sub(f.WindowStart).Seconds())
}
