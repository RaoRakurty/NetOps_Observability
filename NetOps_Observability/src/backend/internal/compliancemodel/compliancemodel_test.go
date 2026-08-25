package compliancemodel

import (
	"testing"
	"time"

	"netops/backend/internal/compliance"
	"netops/backend/internal/secfindings"
)

// staticConformance asserts the seed providers satisfy the abstract seam at
// compile time (§5h — frameworks are interchangeable providers behind the interface).
var (
	_ FrameworkProvider = (*StaticFrameworkProvider)(nil)
	_ FrameworkProvider = NewNISTCSFProvider()
	_ FrameworkProvider = NewCISProvider()
	_ FrameworkProvider = NewHIPAAProvider()
	_ FrameworkProvider = NewPCIProvider()
)

func TestDefaultCatalogSeed(t *testing.T) {
	cat := DefaultCatalog()

	// The 5 hub controls the 9 checks tag are all present and family-tagged.
	for _, id := range []string{ControlCM8, ControlCM2, ControlIA5, ControlSC8, ControlSI2} {
		ctrl, ok := cat.Control(id)
		if !ok {
			t.Fatalf("seed control %q missing", id)
		}
		if ctrl.Family == "" || ctrl.Version == "" {
			t.Errorf("control %q not fully populated: %+v", id, ctrl)
		}
	}

	// Every one of the 9 legacy checks maps to at least one control, with a valid
	// relationship — nothing is left unmapped (or it would contribute to no framework).
	checks := []string{
		checkSotRegistered, checkSotName, checkSotMgmtIP, checkSotSerial, checkSotPlatform,
		checkSnmpVersion, checkSnmpV3Weak, checkOSConsensus, checkKEV,
	}
	for _, ck := range checks {
		refs := cat.ControlsForCheck(ck)
		if len(refs) == 0 {
			t.Errorf("check %q maps to no control", ck)
		}
		for _, r := range refs {
			if !r.Relationship.Valid() {
				t.Errorf("check %q → %q has invalid relationship %q", ck, r.ControlID, r.Relationship)
			}
		}
	}

	// HasCheckForControl is the coverage primitive: seed controls are covered.
	if !cat.HasCheckForControl(ControlIA5) {
		t.Error("IA-5 should be check-covered")
	}
	// A control NOT tagged by any check is not covered (honest coverage input).
	if cat.HasCheckForControl("AC-3") {
		t.Error("AC-3 has no seed check and must not be check-covered")
	}

	// Returned slices are copies — mutating them must not corrupt the catalog.
	refs := cat.ControlsForCheck(checkSnmpVersion)
	refs[0].ControlID = "TAMPERED"
	if got := cat.ControlsForCheck(checkSnmpVersion); got[0].ControlID != ControlIA5 {
		t.Errorf("catalog mapping mutated through returned slice: %v", got)
	}
}

func TestConvertStampsOwnedFields(t *testing.T) {
	cat := DefaultCatalog()
	when := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	cf := compliance.Finding{
		Check:      "snmp-version",
		Title:      "Community-based SNMP in use",
		Class:      "policy",
		Severity:   "medium",
		Framework:  "CIS · NIST 800-53 IA-5",
		DeviceID:   "d1",
		DeviceName: "core-rtr-1",
		Observed:   "SNMP v2c",
		Intended:   "SNMPv3 authPriv",
	}

	f := cat.Convert(cf, EmitOptions{TenantID: "acme", ScanID: "scan-9", Now: when})

	// T1 converter behavior preserved: posture class, Fail verdict, device subject.
	if f.EvidenceClass != secfindings.EvidencePosture {
		t.Errorf("EvidenceClass = %q, want posture", f.EvidenceClass)
	}
	if f.StatusID != secfindings.StatusFail || f.Status != "Fail" {
		t.Errorf("status = %v/%q, want Fail", f.StatusID, f.Status)
	}
	if f.Source != secfindings.SourceCompliance {
		t.Errorf("Source = %q, want %q", f.Source, secfindings.SourceCompliance)
	}
	if f.RawRuleID != "snmp-version" {
		t.Errorf("RawRuleID = %q, want snmp-version", f.RawRuleID)
	}

	// Producer-assigned fields the mapping layer stamps:
	if f.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme (from principal)", f.TenantID)
	}
	if f.ScanID != "scan-9" || !f.Time.Equal(when) {
		t.Errorf("provenance not stamped: scan=%q time=%v", f.ScanID, f.Time)
	}
	if f.ControlID != ControlIA5 {
		t.Errorf("ControlID = %q, want %q (from mapping)", f.ControlID, ControlIA5)
	}
	if f.EvidenceRef == nil || f.EvidenceRef.Locator != "snmp-version" || f.EvidenceRef.RulesetVersion != CatalogVersion {
		t.Errorf("EvidenceRef not by-reference/version-pinned: %+v", f.EvidenceRef)
	}
}

func TestConvertZeroTimeDefaults(t *testing.T) {
	cat := DefaultCatalog()
	f := cat.Convert(compliance.Finding{Check: "kev-exposure"}, EmitOptions{})
	if f.Time.IsZero() {
		t.Error("zero Now should default to time.Now(), got zero time")
	}
	if f.ControlID != ControlSI2 {
		t.Errorf("ControlID = %q, want %q", f.ControlID, ControlSI2)
	}
}

func TestConvertAllPreservesOrder(t *testing.T) {
	cat := DefaultCatalog()
	in := []compliance.Finding{{Check: "snmp-version"}, {Check: "os-consensus"}, {Check: "kev-exposure"}}
	out := cat.ConvertAll(in, EmitOptions{TenantID: "t1"})
	if len(out) != 3 {
		t.Fatalf("got %d, want 3", len(out))
	}
	want := []string{ControlIA5, ControlCM2, ControlSI2}
	for i, w := range want {
		if out[i].ControlID != w {
			t.Errorf("out[%d].ControlID = %q, want %q", i, out[i].ControlID, w)
		}
		if out[i].TenantID != "t1" {
			t.Errorf("out[%d] tenant not stamped", i)
		}
	}
	if cat.ConvertAll(nil, EmitOptions{}) != nil {
		t.Error("ConvertAll(nil) should be nil")
	}
}
