package notify

import "netops/backend/models"

// SeverityGate wraps a channel so it only forwards alerts at or above a minimum
// severity. Used to wire "Critical alerts → email/SMS" without baking a
// threshold into each sender: the email/Twilio channels deliver everything they
// receive, and the gate decides what reaches them.
type SeverityGate struct {
	inner Channel
	min   int
}

// NewSeverityGate wraps inner, gating below minSeverity (e.g. "critical"). An
// empty/unknown minSeverity gates nothing (forwards all).
func NewSeverityGate(inner Channel, minSeverity string) *SeverityGate {
	return &SeverityGate{inner: inner, min: severityRank(minSeverity)}
}

func (g *SeverityGate) Name() string { return g.inner.Name() }

// Unguarded returns the wrapped channel, so an explicit DispatchTo (reports) can
// bypass the severity threshold that only applies to broadcast alert dispatch.
func (g *SeverityGate) Unguarded() Channel { return g.inner }

func (g *SeverityGate) Send(a models.Alert) error {
	if severityRank(a.Severity) < g.min {
		return nil // below threshold — not an error, just filtered
	}
	return g.inner.Send(a)
}
