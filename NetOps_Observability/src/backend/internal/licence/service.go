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
type Service struct {
	store Store
	// overage is the durable "since when are you over" register. Optional and
	// wiring-time only (SetOverageTracker); nil simply means no `since` is
	// recorded, which the page and the metrics state honestly rather than
	// inventing one.
	overage *OverageTracker
}

// Compile-time proof that the licence file satisfies the core abstraction.
// If this ever fails to build, business code has been given a promise the
// licence layer no longer keeps.
var _ entitlement.Service = (*Service)(nil)

// NewService wraps a Store as the entitlement service.
func NewService(st Store) *Service { return &Service{store: st} }

// SetOverageTracker attaches the durable overage register.
//
// WIRING TIME ONLY: call it in the composition root, before the service is
// shared with any handler. It is a setter rather than a constructor argument so
// the many existing call sites (and the licence-neutral test harness) keep
// working unchanged, and because a deployment without a register is a supported
// state — it loses `overage_since` and nothing else.
func (s *Service) SetOverageTracker(t *OverageTracker) {
	if s == nil {
		return
	}
	s.overage = t
}

// OverageTracker is the attached register, or nil.
func (s *Service) OverageTracker() *OverageTracker {
	if s == nil {
		return nil
	}
	return s.overage
}

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

// Overages lists the enforced ceilings the supplied usage exceeds, stamped with
// when each episode began where a register is attached.
//
// It is also what RECORDS the episode: reading the overage and remembering when
// it started are the same act, so there is no path that displays an overage the
// register did not see.
func (s *Service) Overages(u Usage) []Overage {
	return s.ObserveUsage(u, time.Now().UTC())
}

// ObserveUsage is Overages with an explicit clock, for tests and for the
// metrics path which already has one.
func (s *Service) ObserveUsage(u Usage, now time.Time) []Overage {
	// Nil-safe in both directions: State() answers Community for a nil service,
	// and a deployment with no register still gets the list — it just carries
	// no `since`.
	if s == nil || s.overage == nil {
		return s.State().Overages(u)
	}
	return s.overage.Observe(s.State(), u, now)
}

// ─────────────────────────────────────────────────────────────────────────────
// The expiry lifecycle (entitlement.Lifecycle)
// ─────────────────────────────────────────────────────────────────────────────

// Compile-time proof that the licence file answers the expiry half of the
// entitlement contract as well as the base one.
var _ entitlement.Lifecycle = (*Service)(nil)

// Phase is the expiry phase in force: valid, in_grace or post_grace.
//
// Community — no licence at all — is permanently `valid`: it has no expiry to
// be past, and a free-tier deployment must never read as a lapsed one.
func (s *Service) Phase() entitlement.Phase {
	p := s.State().Phase
	if !entitlement.ValidPhase(p) {
		// A state from before the phase field existed, or a fixture that never
		// set one. `valid` is the only safe answer: claiming a lapse the
		// document does not state would remove capability nobody asked to
		// remove.
		return entitlement.PhaseValid
	}
	return p
}

// EntitledForRead reports whether f's EXISTING data stays readable and
// exportable.
//
// It is Entitled widened by exactly one case — a licence that granted f and has
// lapsed past grace (State.LapsedFeatures) — which is the owner's 2026-09-05
// line: after grace, creation and configuration stop, what is already there
// stays visible. It can never grant a read for a feature no licence granted.
func (s *Service) EntitledForRead(f entitlement.Feature) bool {
	if !entitlement.ValidFeature(f) {
		return false
	}
	st := s.State()
	return st.Has(f) || st.HasLapsed(f)
}

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

	// The USAGE families (owner decision, 2026-09-05): the three numbers the
	// 80/90/100 % soft-overage rules divide, plus the overage itself.
	//
	// MetricCeiling and MetricUsage carry {ceiling,unit} so the ratio
	// `usage / ceiling` matches label-for-label. MetricCeilingSoft carries
	// {ceiling} alone so a rule can join on it with `and on(ceiling)` — it is
	// the COMMUNITY GUARD for the whole ceiling group: Community's ceilings are
	// hard, so it publishes 0 and no soft-overage rule can select it.
	MetricCeiling     = "netops_licence_ceiling"
	MetricUsage       = "netops_licence_usage"
	MetricCeilingSoft = "netops_licence_ceiling_soft"
	// MetricOverageDevices is the headline soft-overage number: monitored
	// devices above the licensed allowance. Always emitted, including as a
	// zero, so a vanished series means a scrape failure and not "we are fine".
	MetricOverageDevices = "netops_licence_overage_devices"
	// MetricOverageSince is the unix second an overage episode began, 0 when
	// there is none. It is the durable answer a true-up conversation needs and
	// the reason the register is written to disk at all.
	MetricOverageSince = "netops_licence_overage_since_seconds"
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

// ─────────────────────────────────────────────────────────────────────────────
// Usage and overage metrics
// ─────────────────────────────────────────────────────────────────────────────

// WriteUsageMetrics emits the ceiling/usage/soft/overage families AND records
// the overage episode, from one reading of the usage.
//
// Doing both in one call is deliberate: the number on the dashboard and the
// `overage_since` on the Licence page then come from the same observation, so
// they cannot disagree about when an episode started.
//
// WHAT IS EMITTED, AND WHAT IS NOT:
//
//   - every ENFORCED ceiling gets a `netops_licence_ceiling` and a
//     `netops_licence_ceiling_soft` series on every scrape, present as a value
//     even at Community, so nothing vanishes when a tier changes;
//   - `netops_licence_usage` is emitted ONLY for a ceiling that was actually
//     MEASURED. A ceiling nobody counted has no usage series, because a 0 there
//     would be a fabricated measurement and the alert rules would divide it. The
//     consequence — an unmeasured ceiling cannot fire a usage alert — is the
//     right failure direction: it is silent, not wrong;
//   - an UNLIMITED ceiling reports -1 (entitlement.Unlimited). The rules guard
//     with `> 0`, so no ratio is ever computed against the sentinel.
//
// Nil-safe.
func (s *Service) WriteUsageMetrics(w io.Writer, u Usage, now time.Time) {
	if s == nil || w == nil {
		return
	}
	st := s.State()
	over := s.ObserveUsage(u, now)
	byCeiling := make(map[string]Overage, len(over))
	for _, o := range over {
		byCeiling[o.Ceiling] = o
	}

	fmt.Fprintf(w, "# HELP %s The licensed limit for each ENFORCED ceiling (%d = unlimited).\n", MetricCeiling, entitlement.Unlimited)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricCeiling)
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			continue
		}
		limit, _ := st.Ceilings.Get(n)
		fmt.Fprintf(w, "%s{ceiling=%q,unit=%q} %d\n", MetricCeiling, n, entitlement.CeilingUnit(n), limit)
	}

	fmt.Fprintf(w, "# HELP %s Current usage against each ENFORCED ceiling. A ceiling this deployment does not measure has NO series here — a fabricated zero would be divided by the ceiling rules.\n", MetricUsage)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricUsage)
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			continue
		}
		cur, measured := u[n]
		if !measured {
			continue
		}
		fmt.Fprintf(w, "%s{ceiling=%q,unit=%q} %d\n", MetricUsage, n, entitlement.CeilingUnit(n), cur)
	}

	fmt.Fprintf(w, "# HELP %s 1 where exceeding the ceiling is allowed and recorded as overage (paid tiers), 0 where it is refused (Community). The soft-overage alert rules join on this, so a free-tier deployment fires none of them.\n", MetricCeilingSoft)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricCeilingSoft)
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			continue
		}
		soft := 0
		if entitlement.SoftCeiling(n, st.Tier) {
			soft = 1
		}
		fmt.Fprintf(w, "%s{ceiling=%q} %d\n", MetricCeilingSoft, n, soft)
	}

	devicesOver := 0
	if o, ok := byCeiling[entitlement.CeilingDevices]; ok {
		devicesOver = o.Over
	}
	fmt.Fprintf(w, "# HELP %s Monitored devices above the licensed allowance. Nothing is blocked, disabled or deleted at this number — on a paid tier it is recorded for true-up.\n", MetricOverageDevices)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricOverageDevices)
	fmt.Fprintf(w, "%s %d\n", MetricOverageDevices, devicesOver)

	fmt.Fprintf(w, "# HELP %s Unix second the current overage episode began, 0 when there is none or no register is kept.\n", MetricOverageSince)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricOverageSince)
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			continue
		}
		since := int64(0)
		if o, ok := byCeiling[n]; ok && !o.Since.IsZero() {
			since = o.Since.Unix()
		}
		fmt.Fprintf(w, "%s{ceiling=%q} %d\n", MetricOverageSince, n, since)
	}
}
