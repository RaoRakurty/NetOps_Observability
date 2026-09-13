// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package hardening

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/secfindings"
)

// dialect_recognize_test.go — the DialectPack.Recognize seam (tracker 296).
//
// A dialect's detections are patterns over a configuration grammar. Handed text
// in a shape those patterns do not know, every one of them fails to match, and
// "no insecure line found" is the input to a PASS — a device nothing could
// assess, reported hardened. The seam lets a pack say "I cannot read this", and
// the engine then owes the operator a non-verdict with a reason.
//
// These tests own the CORE half of the contract and use a synthetic pack, so
// they hold whatever any real dialect's shape test happens to do.

const recognizableMarker = "READABLE"

// recognizePack builds a one-rule pack whose detection trips on `TRIP`, and
// which (when shapeTested) can only read a config carrying the marker line.
func recognizePack(shapeTested bool) DialectPack {
	p := DialectPack{Vendor: VendorSRLinux, Bindings: map[string]VendorBinding{
		"telnet-vty-enabled": {
			Detect:      DetectPresent(`^TRIP$`, "no TRIP line"),
			Remediation: "stop tripping",
		},
	}}
	if shapeTested {
		p.Recognize = func(cfg *Config) (bool, string) {
			for _, ln := range cfg.Lines() {
				if strings.TrimSpace(ln) == recognizableMarker {
					return true, ""
				}
			}
			return false, "no statement in this test dialect's grammar"
		}
	}
	return p
}

func recognizeEvaluate(t *testing.T, pack DialectPack, raw string) []secfindings.Finding {
	t.Helper()
	eng := NewEngine(DefaultCatalog(pack),
		MemConfigSource{"d1": raw},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "mgmt"}}},
		WithClock(fixedClock()))
	fs, err := eng.Evaluate(context.Background(), Device{ID: "d1", Hostname: "spine1", Platform: "Nokia SR Linux 26.3", TenantID: "acme"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return fs
}

// TestUnreadableConfigIsUnknownNeverPass is the fail-closed contract: when the
// dialect cannot read the config, no control may reach a verdict, and the device
// gets ONE coverage finding that says why.
func TestUnreadableConfigIsUnknownNeverPass(t *testing.T) {
	fs := recognizeEvaluate(t, recognizePack(true), "some other platform's configuration\n")

	rule, ok := findingFor(fs, "telnet-vty-enabled")
	if !ok {
		t.Fatal("the bound rule was not emitted at all — an absent control reads as nothing to see")
	}
	if rule.StatusID != secfindings.StatusUnknown {
		t.Errorf("bound rule status = %s, want Unknown (fail-closed)", rule.StatusID)
	}
	for _, want := range []string{"does not parse as", "Nokia SR Linux", "no statement in this test dialect's grammar", "not assessed"} {
		if !strings.Contains(rule.Detail, want) {
			t.Errorf("rule detail %q does not carry %q", rule.Detail, want)
		}
	}

	cov, ok := findingFor(fs, RuleConfigDialectUnreadable)
	if !ok {
		t.Fatalf("no %q finding — nothing tells the operator at DEVICE level that we hold a config we cannot read", RuleConfigDialectUnreadable)
	}
	if cov.StatusID != secfindings.StatusUnknown {
		t.Errorf("coverage finding status = %s, want Unknown", cov.StatusID)
	}
	if cov.Category != CategoryCoverage {
		t.Errorf("coverage finding category = %q, want %q — it is not a hardening verdict and must not be scored as one", cov.Category, CategoryCoverage)
	}
	if !strings.Contains(cov.Detail, "unassessed") || !strings.Contains(cov.Detail, "no statement in this test dialect's grammar") {
		t.Errorf("coverage detail must say unassessed AND why: %q", cov.Detail)
	}
	if cov.Remediation == "" {
		t.Error("coverage finding carries no remediation — the operator is not told what to do about it")
	}
	if cov.TenantID != "acme" {
		t.Errorf("coverage finding tenant = %q, want the device record's tenant", cov.TenantID)
	}

	for _, f := range fs {
		if f.StatusID == secfindings.StatusPass || f.StatusID == secfindings.StatusFail {
			t.Errorf("rule %q reached a real verdict (%s) from a config the dialect cannot read", f.RawRuleID, f.StatusID)
		}
	}
}

// TestReadableConfigStillReachesAVerdict — the shape test must not become a
// blanket refusal: a config the dialect CAN read is assessed exactly as before,
// and no coverage finding is emitted.
func TestReadableConfigStillReachesAVerdict(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		want secfindings.StatusID
	}{
		{"clean", recognizableMarker + "\n", secfindings.StatusPass},
		{"tripped", recognizableMarker + "\nTRIP\n", secfindings.StatusFail},
	} {
		fs := recognizeEvaluate(t, recognizePack(true), c.raw)
		if got := findingStatus(t, fs, "telnet-vty-enabled"); got != c.want {
			t.Errorf("%s: status = %s, want %s", c.name, got, c.want)
		}
		if _, ok := findingFor(fs, RuleConfigDialectUnreadable); ok {
			t.Errorf("%s: a readable config produced an unreadable-config finding", c.name)
		}
	}
}

// TestDialectWithoutRecognizeIsUnchanged — the seam is OPT-IN. A pack that
// declares no shape test behaves exactly as it did before the seam existed, so
// adding it changed no dialect that did not ask for it.
func TestDialectWithoutRecognizeIsUnchanged(t *testing.T) {
	fs := recognizeEvaluate(t, recognizePack(false), "some other platform's configuration\n")
	if got := findingStatus(t, fs, "telnet-vty-enabled"); got != secfindings.StatusPass {
		t.Errorf("status = %s, want Pass — a pack with no Recognize must be evaluated as before", got)
	}
	if _, ok := findingFor(fs, RuleConfigDialectUnreadable); ok {
		t.Error("a pack that declares no shape test must not produce an unreadable-config finding")
	}
}

// TestMissingConfigWordingIsUnchanged guards the refactor that routed the
// missing-config case through the same fail-closed clause as the unreadable one:
// the operator-facing sentence for "we have no config" must not have drifted.
func TestMissingConfigWordingIsUnchanged(t *testing.T) {
	eng := NewEngine(DefaultCatalog(recognizePack(true)), MemConfigSource{},
		MemSeamResolver{"d1": {{SeamID: "s", SeamType: "mgmt"}}}, WithClock(fixedClock()))
	fs, err := eng.Evaluate(context.Background(), Device{ID: "d1", Platform: "Nokia SR Linux 26.3", TenantID: "acme"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	f, ok := findingFor(fs, "telnet-vty-enabled")
	if !ok {
		t.Fatal("no finding for the bound rule")
	}
	if f.StatusID != secfindings.StatusUnknown {
		t.Errorf("status = %s, want Unknown", f.StatusID)
	}
	if want := "running-config unavailable — control not assessed (fail-closed)"; f.Detail != want {
		t.Errorf("detail = %q, want %q", f.Detail, want)
	}
	// No config at all is not the same condition as a config we cannot read, and
	// it does not claim to be: the shape test never ran.
	if _, ok := findingFor(fs, RuleConfigDialectUnreadable); ok {
		t.Error("a device with NO config on file reported its config unreadable")
	}
}

// findingStatus is statusOf's local twin (this package's test helper set).
func findingStatus(t *testing.T, fs []secfindings.Finding, ruleID string) secfindings.StatusID {
	t.Helper()
	f, ok := findingFor(fs, ruleID)
	if !ok {
		t.Fatalf("no finding for rule %q", ruleID)
	}
	return f.StatusID
}
