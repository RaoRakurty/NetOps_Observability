package secpolicy

// In-package contract pins. The exhaustive branch suites (account lifecycle,
// password rules, persistence failure, HTTP shapes) live in main with the
// wiring they exercise; these pin the package's own invariants.

import (
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/users"
)

func TestSetClampsAndCoherence(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "ss.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Set("acme", Settings{
		MinPasswordLength: 1, LoginAttemptsAllowed: 0, ConcurrentLogin: "sideways",
		IdleTimeoutMinutes: 2, AbsoluteTimeoutMinutes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.MinPasswordLength != 4 || out.LoginAttemptsAllowed != 1 || out.ConcurrentLogin != "allow" {
		t.Fatalf("clamps not applied: %+v", out)
	}
	if out.IdleTimeoutMinutes != 5 || out.AbsoluteTimeoutMinutes < out.IdleTimeoutMinutes {
		t.Fatalf("session coherence broken: %+v", out)
	}
}

func TestNormalizeScopeGlobalIsProvider(t *testing.T) {
	for _, in := range []string{"", "global", " GLOBAL "} {
		if got := NormalizeScope(in); got != ScopeProvider {
			t.Fatalf("NormalizeScope(%q) = %q", in, got)
		}
	}
	if NormalizeScope(" Acme ") != "acme" {
		t.Fatal("tenant scope must normalize to lowercase")
	}
}

func TestValidatePasswordFloorAndClasses(t *testing.T) {
	if err := ValidatePassword("short", Rules{MinLength: 1}); err == nil {
		t.Fatal("global 8-char floor must hold even when rules are weaker")
	}
	if err := ValidatePassword("alllowercase", Rules{MinLength: 8, ComplexityClasses: 3}); err == nil {
		t.Fatal("complexity classes must be enforced")
	}
	if err := ValidatePassword("Str0ng!pass", Rules{MinLength: 8, ComplexityClasses: 4}); err != nil {
		t.Fatalf("valid password refused: %v", err)
	}
}

func TestAccountPolicyHardBeforeSoft(t *testing.T) {
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	ss := Settings{AccountValidityDays: 30, PasswordExpireEnabled: true, PasswordExpireDays: 1}
	u := users.User{
		CreatedAt:          now.AddDate(0, 0, -60),
		PasswordChangedAt:  now.AddDate(0, 0, -10),
		MustChangePassword: true,
	}
	d := EvaluateAccountPolicy(ss, u, now)
	if !d.Deny || d.Reason != ReasonAccountExpired {
		t.Fatalf("hard denial must win over soft: %+v", d)
	}
	// Federated accounts are exempt from the local-password soft rules.
	fed := users.User{AuthSource: "oidc", MustChangePassword: true}
	if d := EvaluateAccountPolicy(Settings{}, fed, now); d.Blocked() {
		t.Fatalf("federated account must not be password-gated: %+v", d)
	}
}

func TestPushPasswordHistoryBounded(t *testing.T) {
	h := []string{}
	for i := 0; i < HistoryDepth+3; i++ {
		h = PushPasswordHistory(h, "hash"+string(rune('a'+i)))
	}
	if len(h) != HistoryDepth {
		t.Fatalf("history not bounded: %d", len(h))
	}
}
