package licence

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/entitlement"
)

// Source says where a State came from, so the boot log and the admin page can
// tell "no licence installed" (a normal, supported, un-alarming state) from
// "a licence is installed".
type Source string

const (
	// SourceCommunity — no licence file. Not an error and not a warning: the
	// free tier is the funnel, not a degraded mode, and the boot log says so at
	// INFO.
	SourceCommunity Source = "community"
	// SourceFile — an authenticated licence document is installed.
	SourceFile Source = "file"
)

// State is the evaluated licence: what is permitted right now.
//
// Ceilings and Features are the EFFECTIVE values — past grace they are the
// Community ones with Degraded set and Reason saying so. Callers gate through
// entitlement.Service and never re-derive policy from a raw document.
type State struct {
	Source    Source                `json:"source"`
	Tier      entitlement.Tier      `json:"tier"`
	Ceilings  entitlement.Ceilings  `json:"ceilings"`
	Features  []entitlement.Feature `json:"features"`
	ExpiresAt time.Time             `json:"expires_at,omitzero"`
	InGrace   bool                  `json:"in_grace"`
	Degraded  bool                  `json:"degraded"`
	Reason    string                `json:"reason,omitempty"`

	// LicensedTier is the tier the FILE names. It differs from Tier only once a
	// licence has degraded, and keeping both is what lets the page say "your
	// Team licence expired; running at Community ceilings" instead of pretending
	// the customer was always Community.
	LicensedTier entitlement.Tier `json:"licensed_tier,omitempty"`

	Customer  string    `json:"customer,omitempty"`
	LicenceID string    `json:"licence_id,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitzero"`
	GraceDays int       `json:"grace_days,omitempty"`
	Support   Support   `json:"support,omitzero"`
	KeyID     string    `json:"key_id,omitempty"`

	// LoadError records why an INSTALLED licence is not in force — a corrupt
	// file, a signature that no longer verifies, a key we no longer trust. The
	// State is Community in that case (fail closed), but the operator is told
	// exactly what is wrong instead of silently losing their tier.
	LoadError string `json:"load_error,omitempty"`
}

// Community is the no-licence default: the free tier. 25 devices, 1 tenant,
// 7-day retention, 5 watched prefixes, the default two compliance frameworks,
// evidence-only Iris — from docs/design/TIERING_PLAN_2026-09-03.md §2, with the
// two ENFORCED numbers (devices, watched prefixes) owner-decided.
//
// It needs no key, no file and no network. It is also the fail-closed answer
// everywhere: an unreadable, unverifiable or absent licence lands here.
func Community() State {
	return State{
		Source:   SourceCommunity,
		Tier:     entitlement.TierCommunity,
		Ceilings: entitlement.CommunityCeilings(),
		Features: nil,
	}
}

// Has reports whether the state grants f.
func (s State) Has(f entitlement.Feature) bool {
	for _, g := range s.Features {
		if g == f {
			return true
		}
	}
	return false
}

// DaysToExpiry is whole days from now to expiry, negative once expired. ok is
// false for a state with no expiry (Community), so the metric writes a sentinel
// rather than a lie.
func (s State) DaysToExpiry(now time.Time) (days int, ok bool) {
	if s.ExpiresAt.IsZero() {
		return 0, false
	}
	d := s.ExpiresAt.Sub(now)
	days = int(d / (24 * time.Hour))
	// Truncate toward -inf so "12 hours past expiry" is -1 day, not 0.
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days, true
}

// Summary is the one-line boot log and the admin page's headline.
func (s State) Summary() string {
	if s.Source == SourceCommunity {
		base := fmt.Sprintf("none — Community ceilings (%d devices, %d watched prefixes)",
			s.Ceilings.Devices, s.Ceilings.WatchedPrefixes)
		if s.LoadError != "" {
			return base + " — an installed licence was REFUSED: " + s.LoadError
		}
		return base
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "%s, tier=%s, customer=%q, expires=%s, ceilings=%d devices/%d watched prefixes",
		s.LicenceID, s.LicensedTier, s.Customer, s.ExpiresAt.UTC().Format(time.RFC3339),
		s.Ceilings.Devices, s.Ceilings.WatchedPrefixes)
	if len(s.Features) > 0 {
		names := make([]string, 0, len(s.Features))
		for _, f := range s.Features {
			names = append(names, string(f))
		}
		fmt.Fprintf(b, ", features=%s", strings.Join(names, "+"))
	} else {
		b.WriteString(", features=none")
	}
	switch {
	case s.Degraded:
		fmt.Fprintf(b, " — DEGRADED: %s", s.Reason)
	case s.InGrace:
		fmt.Fprintf(b, " — IN GRACE: %s", s.Reason)
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// Honest degradation: what is over a ceiling
// ─────────────────────────────────────────────────────────────────────────────

// Overage is one ceiling the current usage exceeds. The design's honesty rule
// is that these are LISTED — "not monitored: licence ceiling" — never hidden,
// and nothing is ever deleted to make a number fit.
type Overage struct {
	Ceiling  string           `json:"ceiling"`
	Label    string           `json:"label"`
	Current  int              `json:"current"`
	Limit    int              `json:"limit"`
	Over     int              `json:"over"`
	LiftedBy entitlement.Tier `json:"lifted_by,omitempty"`
	Message  string           `json:"message"`
}

// Usage is the measured current value of each ceiling, keyed by the closed
// ceiling vocabulary. A ceiling absent from the map is NOT MEASURED and is
// omitted from the result rather than reported as zero — an unmeasured ceiling
// and an empty one are different facts, and only one of them is reassuring.
type Usage map[string]int

// Overages lists every ENFORCED ceiling the supplied usage exceeds, in the
// vocabulary's display order.
//
// Only enforced ceilings appear: reporting an overage on a limit nothing gates
// would be theatre, telling an operator they are over something that has no
// consequence.
func (s State) Overages(u Usage) []Overage {
	out := make([]Overage, 0, 2)
	for _, name := range entitlement.CeilingNames() {
		if !entitlement.Enforced(name) {
			continue
		}
		cur, measured := u[name]
		if !measured {
			continue
		}
		limit, _ := s.Ceilings.Get(name)
		if !entitlement.Exceeds(cur, limit) {
			continue
		}
		lifted := entitlement.LiftedBy(name, limit, s.Tier)
		msg := fmt.Sprintf("%d of %d %s are over the %s ceiling of %d — they are still here and nothing has been deleted, but %d are not covered by the licence",
			cur-limit, cur, entitlement.CeilingLabel(name), s.Tier.Label(), limit, cur-limit)
		if lifted != "" {
			msg += fmt.Sprintf("; the %s tier covers them", lifted.Label())
		}
		out = append(out, Overage{
			Ceiling: name, Label: entitlement.CeilingLabel(name),
			Current: cur, Limit: limit, Over: cur - limit,
			LiftedBy: lifted, Message: msg,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ceiling < out[j].Ceiling })
	return out
}
