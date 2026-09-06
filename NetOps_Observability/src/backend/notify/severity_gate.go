// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// SendResolve forwards a resolution when the wrapped channel supports it.
// Resolutions are NOT severity-gated: if the trigger passed the gate, its
// resolution must too (the same rank passes anyway); if it never triggered,
// the destination treats the resolve as a harmless no-op.
func (g *SeverityGate) SendResolve(a models.Alert) error {
	if rs, ok := g.inner.(ResolveSender); ok {
		return rs.SendResolve(a)
	}
	return nil
}

// Pages forwards the PageClassifier question to the wrapped channel, so the
// gate (which every configured channel is built behind) never hides the inner
// destination's page policy from the delivery layer.
func (g *SeverityGate) Pages(a models.Alert) bool { return channelPages(g.inner, a) }

// SeverityAtLeast reports whether sev meets or exceeds min (e.g. "warning"). An
// empty/unknown min admits everything. Exposes the same ranking the gate uses so
// non-Channel paths (e.g. incident action posts) can apply the same threshold.
func SeverityAtLeast(sev, min string) bool { return severityRank(sev) >= severityRank(min) }
