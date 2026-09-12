// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// casenumber_test.go + the portal-only declaration.
//
// The case number is the ONE value on a manual escalation that Correlix cannot
// derive and cannot verify against the vendor, so the shape check at the
// keyboard is the only check there will ever be. These tests pin the three
// things that make it worth having: it is anchored, it is bounded, and a broken
// stored pattern degrades to the default rather than to a dead end.

func TestCaseNumberPatternIsAnchored(t *testing.T) {
	// The whole point: an unanchored pattern must not accept a sentence that
	// merely CONTAINS a case number.
	if err := ValidateCaseNumber(`\d{4}`, "please open 1234 for me"); err == nil {
		t.Fatal("a partial match must not pass for a whole case number")
	}
	if err := ValidateCaseNumber(`\d{4}`, "1234"); err != nil {
		t.Fatalf("the whole value matches the pattern: %v", err)
	}
	// A pattern that already anchors itself still means the same thing.
	if err := ValidateCaseNumber(`^TSR\d+$`, "TSR900123"); err != nil {
		t.Fatalf("a self-anchored pattern must still work: %v", err)
	}
}

func TestCaseNumberDefaultShapeRejectsProseAndAcceptsCaseIDs(t *testing.T) {
	for _, ok := range []string{"695123456", "TSR-900123", "INC0012345", "2026-09-08/1", "SR.4471"} {
		if err := ValidateCaseNumber("", ok); err != nil {
			t.Errorf("%q is a plausible case id and must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "  ", "no case yet", "https://portal.example/case/1", "a"} {
		if err := ValidateCaseNumber("", bad); err == nil {
			t.Errorf("%q must be refused by the default shape", bad)
		}
	}
}

func TestCaseNumberIsBounded(t *testing.T) {
	long := strings.Repeat("9", MaxCaseNumberLen+1)
	err := ValidateCaseNumber("", long)
	if err == nil {
		t.Fatal("an unbounded case number must be refused (§9)")
	}
	if !strings.Contains(err.Error(), "longer than") {
		t.Errorf("the refusal must name the bound, got %q", err)
	}
	if _, err := CompileCaseNumberPattern(strings.Repeat("a", MaxCaseNumberPatternLen+1)); !errors.Is(err, ErrCaseNumberPattern) {
		t.Errorf("an unbounded PATTERN must be refused, got %v", err)
	}
}

// A pattern an administrator broke must not become an operator's dead end in the
// middle of an incident: it is named at save time and degrades here.
func TestABrokenStoredPatternFallsBackToTheDefaultShape(t *testing.T) {
	if _, err := CompileCaseNumberPattern("([unclosed"); !errors.Is(err, ErrCaseNumberPattern) {
		t.Fatalf("a broken pattern must be reported at configuration time, got %v", err)
	}
	if err := ValidateCaseNumber("([unclosed", "695123456"); err != nil {
		t.Fatalf("a broken stored pattern must not block a real case number: %v", err)
	}
	if err := ValidateCaseNumber("([unclosed", "no case yet"); err == nil {
		t.Fatal("the fallback must still be the default shape, not 'anything'")
	}
}

// ── the portal-only declaration ──────────────────────────────────────────────

// The generic path opens nothing and can never be configured into opening
// something, so it declares itself MANUAL. The step chips it on this flag, and
// "Ready" beside a connector that opens cases is exactly what it must never say.
func TestPortalTextDeclaresItselfManual(t *testing.T) {
	info := NewPortalTextOpener().Info(t.Context(), "org-a-tenant")
	if !info.PortalOnly {
		t.Error("the portal text path must declare itself portal-only")
	}
	if info.Can(CapCreate) || info.Can(CapAttach) {
		t.Error("it claims neither create nor attach")
	}
	if !info.Configured {
		t.Error("it needs no credentials, so it is configured for every tenant")
	}
	if strings.Contains(strings.ToLower(info.Display), "copy") {
		t.Errorf("the mechanism belongs on the chip, not in the name: %q", info.Display)
	}
}

// PortalOnly is a fact about the VENDOR, and it survives the JSON the UI reads.
func TestPortalOnlyCrossesTheWire(t *testing.T) {
	in := ConnectorInfo{
		ID: "portal-nokia", Vendor: "nokia", VendorDisplay: "Nokia", PortalOnly: true,
		PortalURL: "https://customer.nokia.example/", CaseNumberPattern: `TSR\d+`,
	}
	out := roundTripJSON(t, in)
	if !out.PortalOnly || out.VendorDisplay != "Nokia" {
		t.Errorf("the manual declaration must reach the client: %+v", out)
	}
	if out.PortalURL != in.PortalURL || out.CaseNumberPattern != in.CaseNumberPattern {
		t.Errorf("the manual path's own details must reach the client: %+v", out)
	}
	// An ordinary connector says nothing, so the fields stay off the wire.
	plain := roundTripJSON(t, ConnectorInfo{ID: "servicenow", Configured: true})
	if plain.PortalOnly || plain.VendorDisplay != "" || plain.PortalURL != "" {
		t.Errorf("a connector that is not portal-only declares nothing: %+v", plain)
	}
}

// The manual path records the number a person read back off the portal — and
// only when it looks like one.
func TestPortalTextRecordsAValidatedCaseNumber(t *testing.T) {
	p := NewPortalTextOpener()
	res, err := p.SubmitCase(t.Context(), CaseRequest{
		Actor: "user:42",
		Form:  CaseForm{Description: "d", ExistingCaseNumber: "TSR-900123"},
	})
	if err != nil {
		t.Fatalf("a manual submit with a good number is a success: %v", err)
	}
	if res.CaseID != "TSR-900123" {
		t.Errorf("the number must be recorded, got %q", res.CaseID)
	}
	if _, err := p.SubmitCase(t.Context(), CaseRequest{
		Actor: "user:42",
		Form:  CaseForm{Description: "d", ExistingCaseNumber: "I have not opened it yet"},
	}); !errors.Is(err, ErrFormIncomplete) {
		t.Errorf("prose must be refused before it is filed on an incident, got %v", err)
	}
	// No number is not an error: the operator may not have opened it yet.
	res, err = p.SubmitCase(t.Context(), CaseRequest{Actor: "user:42", Form: CaseForm{Description: "d"}})
	if err != nil || res.CaseID != "" {
		t.Errorf("a manual submit without a number is still a complete outcome: %v %+v", err, res)
	}
}

// roundTripJSON serializes a ConnectorInfo and reads it back, which is exactly
// what the browser does with it.
func roundTripJSON(t *testing.T, in ConnectorInfo) ConnectorInfo {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ConnectorInfo
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
