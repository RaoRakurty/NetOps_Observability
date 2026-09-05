package licence

import (
	"fmt"
	"io"
	"time"

	"netops/backend/internal/entitlement"
)

// Service is the licence-file implementation of entitlement.Service — the
// CENTRAL entitlement service the whole product asks.
//
// It is a thin projection of Store.State(): every answer comes from the
// evaluated state, so there is exactly one place where "what does this customer
// get" is decided, and it is the one place the admin page displays.
//
// Nil-safe throughout. A nil *Service answers Community, which is the
// fail-closed direction: a build that forgets to wire the licence subsystem
// grants nothing extra rather than everything.
type Service struct{ store Store }

// Compile-time proof that the licence file satisfies the core abstraction.
// If this ever fails to build, business code has been given a promise the
// licence layer no longer keeps.
var _ entitlement.Service = (*Service)(nil)

// NewService wraps a Store as the entitlement service.
func NewService(st Store) *Service { return &Service{store: st} }

// State is the current evaluated licence. Community when unwired.
func (s *Service) State() State {
	if s == nil || s.store == nil {
		return Community()
	}
	return s.store.State()
}

// Entitled reports whether feature f is granted right now.
//
// A degraded (post-grace) licence grants nothing, because evaluate() already
// emptied State.Features — the check below needs no special case for it, and
// that is deliberate: one place decides, one place is displayed.
func (s *Service) Entitled(f entitlement.Feature) bool {
	if !entitlement.ValidFeature(f) {
		return false
	}
	return s.State().Has(f)
}

// Ceiling returns the limit in force for a named ceiling and the lowest tier
// that raises it.
func (s *Service) Ceiling(name string) (int, entitlement.Tier) {
	st := s.State()
	limit, ok := st.Ceilings.Get(name)
	if !ok {
		// Outside the closed vocabulary: report zero, never "unlimited". The
		// caller's CheckCeiling turns this into a loud refusal.
		return 0, ""
	}
	return limit, entitlement.LiftedBy(name, limit, st.Tier)
}

// Tier is the tier in force. For DISPLAY and for the refusal body only —
// nothing outside internal/entitlement may branch on it.
func (s *Service) Tier() entitlement.Tier { return s.State().Tier }

// Overages lists the enforced ceilings the supplied usage exceeds.
func (s *Service) Overages(u Usage) []Overage { return s.State().Overages(u) }

// ─────────────────────────────────────────────────────────────────────────────
// Metrics
// ─────────────────────────────────────────────────────────────────────────────

// Metric names. Both are gauges, both are present from the first scrape (a
// Community deployment emits them too), so "no licence" is a VALUE and not a
// gap in the series — the alert rules can then distinguish "Community" from
// "the api is not reporting".
const (
	MetricDaysToExpiry = "netops_licence_days_to_expiry"
	MetricState        = "netops_licence_state"
)

// NoExpirySentinel is what MetricDaysToExpiry reports for a licence with no
// expiry (Community). A large positive number rather than 0 or -1 so no
// "expires soon" rule can ever fire on a deployment that has no licence to
// expire; the sentinel is documented in the rule file next to the threshold.
const NoExpirySentinel = 36500 // 100 years

// WriteMetrics emits the licence gauges in Prometheus text format. Nil-safe.
//
// netops_licence_state is a labelled 1/0 family with one series per (tier,
// degraded) combination rather than a single value, so a dashboard can graph
// the transition and vmalert can match on the label instead of decoding an
// enum. Every combination is emitted every scrape — a series that vanishes is
// indistinguishable from a scrape failure, and that ambiguity is exactly what
// the 2026-09-02 outage was made of.
func (s *Service) WriteMetrics(w io.Writer, now time.Time) {
	if s == nil || w == nil {
		return
	}
	st := s.State()

	days := NoExpirySentinel
	if d, ok := st.DaysToExpiry(now); ok {
		days = d
	}
	fmt.Fprintf(w, "# HELP %s Whole days until the installed licence expires (negative once expired; %d = no licence installed, nothing to expire).\n", MetricDaysToExpiry, NoExpirySentinel)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricDaysToExpiry)
	fmt.Fprintf(w, "%s %d\n", MetricDaysToExpiry, days)

	fmt.Fprintf(w, "# HELP %s 1 on the tier and degradation state in force, 0 on the others. in_grace is a third label so \"expired but still licensed\" is visible without decoding.\n", MetricState)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricState)
	for _, t := range entitlement.Tiers() {
		for _, degraded := range []bool{false, true} {
			for _, grace := range []bool{false, true} {
				v := 0
				if st.Tier == t && st.Degraded == degraded && st.InGrace == grace {
					v = 1
				}
				fmt.Fprintf(w, "%s{tier=%q,degraded=%q,in_grace=%q} %d\n",
					MetricState, t, boolLabel(degraded), boolLabel(grace), v)
			}
		}
	}
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
