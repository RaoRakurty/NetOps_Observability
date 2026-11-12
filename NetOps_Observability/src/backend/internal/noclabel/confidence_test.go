// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package noclabel

import (
	"strings"
	"testing"
)

// The four phrases (owner D4) — strongest first, from tier + label only.
func TestConfidencePhraseMapping(t *testing.T) {
	cases := []struct {
		tier, label, cause, want string
	}{
		{"confirmed", "confirmed", "a WAN routing session flapping", "Confirmed cause"},
		{"suspected", "likely", "a WAN routing session flapping", "Likely cause"},
		{"suspected", "suspected", "A WAN routing session is flapping.", "Possibly because of a WAN routing session is flapping"},
		{"suspected", "suspected", "BGP peer down", "Possibly because of BGP peer down"},
		{"suspected", "suspected", "", "Cause not determined"},
		{"undetermined", "", "anything", "Cause not determined"},
		{"", "", "", "Cause not determined"},
		{"CONFIRMED", "", "", "Confirmed cause"},
		{"", "confirmed", "", "Confirmed cause"},
		{"bogus", "bogus", "x", "Cause not determined"},
	}
	for _, c := range cases {
		if got := ConfidencePhrase(c.tier, c.label, c.cause); got != c.want {
			t.Errorf("ConfidencePhrase(%q,%q,%q) = %q, want %q", c.tier, c.label, c.cause, got, c.want)
		}
	}
}

func TestConfidenceLevelForAnalysis(t *testing.T) {
	for in, want := range map[string]ConfidenceLevel{
		"confirmed": LevelConfirmed, "probable": LevelLikely, "suspected": LevelSuspected,
		"observed": LevelUndetermined, "inconclusive": LevelUndetermined, "": LevelUndetermined,
	} {
		if got := LevelForAnalysis(in); got != want {
			t.Errorf("LevelForAnalysis(%q) = %q, want %q", in, got, want)
		}
	}
}

// No phrase ever carries a percentage or the word "engine confidence".
func TestConfidencePhraseNeverAPercentage(t *testing.T) {
	for _, l := range []ConfidenceLevel{LevelConfirmed, LevelLikely, LevelSuspected, LevelUndetermined} {
		p := PhraseFor(l, "a fault")
		if strings.Contains(p, "%") || strings.Contains(strings.ToLower(p), "engine confidence") {
			t.Errorf("phrase %q carries a number", p)
		}
	}
}

// D1 — the engine flag wins; the fallback list covers pre-flag objects; the
// dated threat-signal story is NOT background.
func TestIsContextStory(t *testing.T) {
	if !IsContextStory("sig.ent.security.exposure-story", false) || !IsContextStory("sig.ent.security.hardening-drift-story", false) {
		t.Fatal("fallback ids must read as context stories")
	}
	if IsContextStory("sig.ent.security.threat-signal-story", false) {
		t.Fatal("a dated detection story is not a background story")
	}
	if !IsContextStory("sig.any.future-story", true) {
		t.Fatal("the engine flag must be honoured for any id")
	}
	if IsContextStory("sig.ent.wan-edge.bgp-peer-flap", false) {
		t.Fatal("a causal template is never background")
	}
}

// Every security template has a NOC title (never the raw template title, never
// the generic cascade).
func TestSecurityTemplatesHaveNocTitles(t *testing.T) {
	for _, id := range []string{
		"sig.ent.security.exposure-story", "sig.ent.security.hardening-drift-story",
		"sig.ent.security.threat-signal-story", "sig.ent.security.fw-policy-drop",
		"sig.ent.security.fw-ha-failover-drift", "sig.ent.security.fw-aa-session-owner-mismatch",
		"sig.ent.security.nat-snat-exhaustion", "sig.ent.security.waf-rule-false-positive",
		"sig.ent.security.waf-body-limit-block", "sig.ent.security.proxy-pac-wpad-failure",
	} {
		got := SignatureTitle(id)
		if got == "Security / policy change" || got == id || got == "" {
			t.Errorf("%s has no NOC title (got %q)", id, got)
		}
	}
	for _, k := range []string{"security_posture", "security_exposure", "security_signal"} {
		if strings.Contains(Kind(k), "_") || strings.EqualFold(Kind(k), strings.ReplaceAll(k, "_", " ")) {
			t.Errorf("Kind(%q) = %q — raw token", k, Kind(k))
		}
	}
}
