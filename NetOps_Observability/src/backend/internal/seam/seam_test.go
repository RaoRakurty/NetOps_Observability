package seam

// seam_test.go — the pure lifecycle/validation/identity contracts: the
// suggest→confirm→active state machine, write normalization + enum validation,
// and the deterministic tenant-scoped seam id. The bootstrap RULES (traceroute
// boundary, BGP peers, tunnels, redundancy groups) are integrator logic and
// their tests stay in package main.

import (
	"strings"
	"testing"
)

func TestSeamTransitions(t *testing.T) {
	allowed := []struct{ from, to string }{
		{"suggested", "confirmed"}, {"suggested", "active"}, {"suggested", "rejected"},
		{"confirmed", "active"}, {"confirmed", "rejected"},
		{"active", "retired"}, {"retired", "active"},
		{"active", "active"}, // PATCH without a transition
	}
	for _, c := range allowed {
		if !TransitionAllowed(c.from, c.to) {
			t.Errorf("%s → %s should be allowed", c.from, c.to)
		}
	}
	denied := []struct{ from, to string }{
		{"rejected", "suggested"}, {"rejected", "active"}, // rejection is permanent memory
		{"active", "suggested"}, {"retired", "suggested"},
		{"active", "rejected"}, // reject only pre-activation; retire instead
	}
	for _, c := range denied {
		if TransitionAllowed(c.from, c.to) {
			t.Errorf("%s → %s must be denied", c.from, c.to)
		}
	}
}

func TestNormalizeSeamForWriteDefaults(t *testing.T) {
	s := Seam{SeamType: "cloud_backbone"}
	if err := NormalizeForWrite(&s); err != nil {
		t.Fatal(err)
	}
	if s.SeamType != "CLOUD_BACKBONE" {
		t.Error("seam_type must normalize to upper case")
	}
	if s.Visibility != "blind" {
		t.Errorf("CLOUD_BACKBONE must default to blind visibility (honesty), got %s", s.Visibility)
	}
	if len(s.ProbeStrategy) == 0 || s.ControlPlaneOwner != "enterprise" {
		t.Error("defaults not applied")
	}

	for _, bad := range []Seam{
		{SeamType: "MPLS"},
		{SeamType: "DX", Visibility: "perfect"},
		{SeamType: "DX", ControlPlaneOwner: "aliens"},
		{SeamType: "DX", Confidence: 1.5},
	} {
		b := bad
		if err := NormalizeForWrite(&b); err == nil {
			t.Errorf("expected validation error for %+v", bad)
		}
	}
}

func TestSeamIDForKeyDeterministic(t *testing.T) {
	a := IDForKey("acme", "r1:8.8.8.8")
	b := IDForKey("acme", "r1:8.8.8.8")
	c := IDForKey("other", "r1:8.8.8.8")
	if a != b {
		t.Error("same (tenant,key) must map to the same seam_id")
	}
	if a == c {
		t.Error("different tenants must not collide")
	}
	if !strings.HasPrefix(a, "sm-") || len(a) != 15 {
		t.Errorf("unexpected id shape %q", a)
	}
}

// The migration is the schema contract for everything above: the rejection
// memory and idempotency live in the partial-unique index, isolation in RLS.
// Pin their presence so a refactor can't silently drop them.
