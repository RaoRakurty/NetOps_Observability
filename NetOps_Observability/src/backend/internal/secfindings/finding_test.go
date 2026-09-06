// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secfindings

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/compliance"
)

// TestConstruction builds a Finding directly and asserts the field set holds,
// including the by-reference evidence pointer and the optional seam context.
func TestConstruction(t *testing.T) {
	ev := &EvidenceRef{Locator: "arf://scan-7/result-42", Kind: "oval-result", RulesetVersion: "ssg-0.1.73", Digest: "sha256:abc"}
	f := Finding{
		ID:            "find-1",
		TenantID:      "tenant-a",
		Source:        SourceOpenSCAP,
		ScanID:        "scan-7",
		Time:          time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		EvidenceClass: EvidencePosture,
		Standards:     []string{"CIS", "NIST 800-53 IA-5"},
		ControlID:     "IA-5",
		ControlTitle:  "root login disabled",
		Category:      "policy",
		Severity:      SeverityHigh,
		Resource:      Resource{DeviceID: "d1", DeviceName: "app-3", Hostname: "app-3.corp", Address: "10.0.0.3", Kind: KindHost, Platform: "Ubuntu 22.04"},
		Observed:      "PermitRootLogin yes",
		Intended:      "PermitRootLogin no",
		Detail:        "root SSH login permitted",
		Remediation:   "set PermitRootLogin no",
		EvidenceRef:   ev,
		RawRuleID:     "xccdf_org.ssgproject_rule_sshd_disable_root_login",
	}
	f.SetStatus(StatusFail)

	if f.StatusID != StatusFail || f.Status != "Fail" {
		t.Fatalf("SetStatus: got (%d,%q), want (3,Fail)", f.StatusID, f.Status)
	}
	if f.EvidenceRef == nil || f.EvidenceRef.Locator != "arf://scan-7/result-42" {
		t.Fatalf("evidence ref not carried by reference")
	}
	if f.EvidenceRef != ev {
		t.Fatalf("EvidenceRef must be the same pointer (by reference, not a copy)")
	}
	if f.Resource.Kind != KindHost {
		t.Fatalf("resource kind: got %q", f.Resource.Kind)
	}
}

// TestSeamContextOptional confirms the seam attribution is nil by default and
// carried when set (the §5e exposure lane).
func TestSeamContextOptional(t *testing.T) {
	var f Finding
	if f.SeamContext != nil {
		t.Fatalf("SeamContext must default to nil")
	}
	f.SeamContext = &SeamContext{SeamID: "seam-isp", SeamType: "ISP", InternetFacing: true}
	f.EvidenceClass = EvidenceExposure
	if !f.SeamContext.InternetFacing {
		t.Fatalf("seam context not carried")
	}
}

// TestStatusString covers every status name.
func TestStatusString(t *testing.T) {
	cases := map[StatusID]string{
		StatusUnknown:       "Unknown",
		StatusPass:          "Pass",
		StatusWarning:       "Warning",
		StatusFail:          "Fail",
		StatusNotApplicable: "NotApplicable",
		StatusError:         "Error",
		StatusID(99):        "Unknown",
	}
	for id, want := range cases {
		if got := id.String(); got != want {
			t.Errorf("StatusID(%d).String() = %q, want %q", id, got, want)
		}
	}
}

// TestParseStatusRoundTrip round-trips every canonical status through String →
// ParseStatus and checks a few case/spacing variants plus the error path.
func TestParseStatusRoundTrip(t *testing.T) {
	for _, id := range []StatusID{StatusUnknown, StatusPass, StatusWarning, StatusFail, StatusNotApplicable, StatusError} {
		got, err := ParseStatus(id.String())
		if err != nil {
			t.Errorf("ParseStatus(%q) errored: %v", id.String(), err)
		}
		if got != id {
			t.Errorf("round-trip StatusID(%d): got %d", id, got)
		}
	}
	variants := map[string]StatusID{
		"pass":           StatusPass,
		"  FAIL ":        StatusFail,
		"not applicable": StatusNotApplicable,
		"not-applicable": StatusNotApplicable,
		"":               StatusUnknown,
	}
	for in, want := range variants {
		got, err := ParseStatus(in)
		if err != nil {
			t.Errorf("ParseStatus(%q) errored: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseStatus(%q) = %d, want %d", in, got, want)
		}
	}
	if _, err := ParseStatus("bogus"); err == nil {
		t.Errorf("ParseStatus(bogus) should error")
	}
}

// TestNormalizeStatus covers each verdict class including NotApplicable, Error,
// and the unrecognized→Unknown default (nothing external is silently promoted).
func TestNormalizeStatus(t *testing.T) {
	cases := map[string]StatusID{
		"pass": StatusPass, "PASSED": StatusPass, "ok": StatusPass, "compliant": StatusPass, "fixed": StatusPass,
		"warning": StatusWarning, "warn": StatusWarning, "suggestion": StatusWarning, "informational": StatusWarning,
		"fail": StatusFail, "failed": StatusFail, "noncompliant": StatusFail, "violation": StatusFail,
		"notapplicable": StatusNotApplicable, "n/a": StatusNotApplicable, "notchecked": StatusNotApplicable, "notselected": StatusNotApplicable,
		"error": StatusError, "cannot-assess": StatusError,
		"": StatusUnknown, "weird-thing": StatusUnknown,
	}
	for raw, want := range cases {
		if got := NormalizeStatus(raw); got != want {
			t.Errorf("NormalizeStatus(%q) = %d, want %d", raw, got, want)
		}
	}
}

// TestFromComplianceFinding converts a legacy finding and round-trips every field
// that exists on the source, plus the semantic mappings the converter applies.
func TestFromComplianceFinding(t *testing.T) {
	c := compliance.Finding{
		Check:      "snmp-version",
		Title:      "Community-based SNMP in use",
		Class:      "policy",
		Severity:   "medium",
		Framework:  "CIS · NIST 800-53 IA-5",
		DeviceID:   "dev-1",
		DeviceName: "core-1",
		Observed:   "SNMP v2c (cleartext community)",
		Intended:   "SNMPv3 authPriv",
		Detail:     `Profile "x" authenticates with a cleartext community string.`,
	}
	f := FromComplianceFinding(c)

	if f.RawRuleID != c.Check {
		t.Errorf("Check→RawRuleID: got %q", f.RawRuleID)
	}
	if f.ControlTitle != c.Title {
		t.Errorf("Title→ControlTitle: got %q", f.ControlTitle)
	}
	if f.Category != c.Class {
		t.Errorf("Class→Category: got %q", f.Category)
	}
	if f.Severity != c.Severity {
		t.Errorf("Severity: got %q", f.Severity)
	}
	if f.Resource.DeviceID != c.DeviceID || f.Resource.DeviceName != c.DeviceName {
		t.Errorf("device fields not carried: %+v", f.Resource)
	}
	if f.Observed != c.Observed || f.Intended != c.Intended || f.Detail != c.Detail {
		t.Errorf("narrative fields not carried through")
	}
	// Semantic mappings.
	if f.Source != SourceCompliance {
		t.Errorf("Source: got %q, want %q", f.Source, SourceCompliance)
	}
	if f.EvidenceClass != EvidencePosture {
		t.Errorf("EvidenceClass: got %q, want posture", f.EvidenceClass)
	}
	if f.Resource.Kind != KindNetworkDevice {
		t.Errorf("Resource.Kind: got %q, want network-device", f.Resource.Kind)
	}
	if f.StatusID != StatusFail || f.Status != "Fail" {
		t.Errorf("legacy finding must map to Fail: got (%d,%q)", f.StatusID, f.Status)
	}
	// Framework → Standards split on the middle dot.
	want := []string{"CIS", "NIST 800-53 IA-5"}
	if len(f.Standards) != len(want) || f.Standards[0] != want[0] || f.Standards[1] != want[1] {
		t.Errorf("Framework→Standards: got %v, want %v", f.Standards, want)
	}
	// Fields with no source: left empty for the producer to stamp.
	if f.ID != "" || f.TenantID != "" || f.ScanID != "" || f.ControlID != "" || f.Remediation != "" || f.EvidenceRef != nil {
		t.Errorf("converter invented a field it should have left empty: %+v", f)
	}
}

// TestSplitStandardsSingle confirms a single-standard Framework yields one clean element.
func TestSplitStandardsSingle(t *testing.T) {
	if got := splitStandards("CISA BOD 22-01"); len(got) != 1 || got[0] != "CISA BOD 22-01" {
		t.Errorf("single standard: got %v", got)
	}
	if got := splitStandards("  "); got != nil {
		t.Errorf("blank framework should yield nil, got %v", got)
	}
	if got := splitStandards("A · · B"); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("empty segments should drop: got %v", got)
	}
}

// TestJSONRoundTrip marshals a fully-populated finding and unmarshals it back,
// asserting the OCSF-ish tags survive and the values are preserved.
func TestJSONRoundTrip(t *testing.T) {
	orig := Finding{
		ID:            "find-9",
		Source:        SourceNetRule,
		ScanID:        "scan-3",
		Time:          time.Date(2026, 8, 25, 9, 30, 0, 0, time.UTC),
		EvidenceClass: EvidenceExposure,
		Standards:     []string{"CIS", "NIST 800-53 SC-7"},
		ControlID:     "SC-7",
		ControlTitle:  "Telnet disabled",
		Category:      "policy",
		Severity:      SeverityCritical,
		Resource:      Resource{DeviceID: "d9", DeviceName: "core-01", Kind: KindNetworkDevice, Platform: "Cisco IOS-XE"},
		Observed:      "transport input telnet ssh",
		Intended:      "transport input ssh",
		Detail:        "Telnet reachable from the ISP seam",
		Remediation:   "line vty 0 4 / transport input ssh",
		EvidenceRef:   &EvidenceRef{Locator: "config://core-01/line-vty", Kind: "config-line", RulesetVersion: "netrule-1"},
		RawRuleID:     "net-telnet",
		SeamContext:   &SeamContext{SeamID: "seam-isp", SeamType: "ISP", InternetFacing: true},
	}
	orig.SetStatus(StatusFail)

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(b)
	for _, tag := range []string{`"status_id":3`, `"control":"SC-7"`, `"category_name":"policy"`, `"evidence_class":"exposure"`, `"status_detail":`, `"evidence_ref":`, `"seam":`, `"resource":`} {
		if !strings.Contains(blob, tag) {
			t.Errorf("expected OCSF tag %s in JSON: %s", tag, blob)
		}
	}

	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.Time.Equal(orig.Time) {
		t.Errorf("time not preserved: %v vs %v", back.Time, orig.Time)
	}
	if back.StatusID != StatusFail || back.ControlID != "SC-7" || back.EvidenceClass != EvidenceExposure {
		t.Errorf("core fields not preserved: %+v", back)
	}
	if back.EvidenceRef == nil || back.EvidenceRef.Locator != orig.EvidenceRef.Locator {
		t.Errorf("evidence ref not preserved")
	}
	if back.SeamContext == nil || back.SeamContext.SeamType != "ISP" {
		t.Errorf("seam context not preserved")
	}
	if len(back.Standards) != 2 || back.Resource.Platform != "Cisco IOS-XE" {
		t.Errorf("standards/resource not preserved: %+v", back)
	}
}

// TestTenantIDNeverSerialized is the §3a hygiene guarantee: TenantID is stamped
// from the principal server-side and must NEVER reach a client in JSON.
func TestTenantIDNeverSerialized(t *testing.T) {
	f := Finding{ID: "x", TenantID: "secret-tenant-42"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "secret-tenant-42") {
		t.Fatalf("TenantID leaked into JSON: %s", b)
	}
	if strings.Contains(strings.ToLower(string(b)), "tenant") {
		t.Fatalf("a tenant field appeared in JSON: %s", b)
	}
	// And it does not round-trip in (a client cannot set it either).
	var back Finding
	if err := json.Unmarshal([]byte(`{"uid":"x","TenantID":"injected"}`), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.TenantID != "" {
		t.Fatalf("TenantID must not be settable from JSON, got %q", back.TenantID)
	}
}

// ── platform identity (T9: the one vendor vocabulary) ───────────────────────

// TestResolvePlatform stamps the registry-resolved profile id from the
// free-form label, leaves the label itself untouched, and resolves an
// unrecognized platform to the honest EMPTY id rather than a fallback profile.
func TestResolvePlatform(t *testing.T) {
	cases := []struct {
		platform string
		want     string
	}{
		{"Cisco IOS-XE 17.9", "cisco/ios_xe"},
		{"cisco ios_xr NCS-5500", "cisco/ios"}, // "cisco" is the vendor's catch-all rule
		{"Juniper Junos 22.4R3", "juniper/junos"},
		{"Nokia SR OS 22.10", "nokia/sros"},
		{"Arista EOS 4.30.2F", "arista/eos"},
		{"Huawei VRP V800R021", "huawei/vrp"},
		{"Ubuntu 22.04", ""},  // a host, no network profile claims it
		{"Acme WidgetOS", ""}, // unknown: NEVER a fallback profile
		{"", ""},              // nothing to resolve
		{"   ", ""},           // nothing to resolve
	}
	for _, tc := range cases {
		got := Resource{Platform: tc.platform}.ResolvePlatform()
		if got.ProfileID != tc.want {
			t.Errorf("ResolvePlatform(%q).ProfileID = %q, want %q", tc.platform, got.ProfileID, tc.want)
		}
		if got.Platform != tc.platform {
			t.Errorf("ResolvePlatform must not rewrite the free-form label: %q → %q", tc.platform, got.Platform)
		}
	}
}

// TestResolvePlatformIsIdempotentAndNonDestructive: calling it twice changes
// nothing, and an id a caller already stamped is never overwritten.
func TestResolvePlatformIsIdempotentAndNonDestructive(t *testing.T) {
	once := Resource{Platform: "Cisco IOS-XE 17.9"}.ResolvePlatform()
	twice := once.ResolvePlatform()
	if once != twice {
		t.Fatalf("not idempotent: %+v vs %+v", once, twice)
	}
	pinned := Resource{Platform: "Cisco IOS-XE 17.9", ProfileID: "juniper/junos"}.ResolvePlatform()
	if pinned.ProfileID != "juniper/junos" {
		t.Fatalf("an already-stamped ProfileID must be kept, got %q", pinned.ProfileID)
	}
}

// TestFindingResolvePlatform is the provider-facing one-liner: it stamps the
// resource in place and leaves every other field alone.
func TestFindingResolvePlatform(t *testing.T) {
	f := Finding{
		ID:       "find-42",
		Resource: Resource{DeviceID: "d1", Kind: KindNetworkDevice, Platform: "SR Linux 23.3"},
	}
	f.ResolvePlatform()
	if f.Resource.ProfileID != "nokia/srlinux" {
		t.Fatalf("ProfileID = %q, want nokia/srlinux", f.Resource.ProfileID)
	}
	if f.ID != "find-42" || f.Resource.DeviceID != "d1" || f.Resource.Kind != KindNetworkDevice {
		t.Fatalf("ResolvePlatform disturbed another field: %+v", f)
	}
}

// TestProfileIDRoundTrips proves the new identity survives the wire and stays
// absent (omitempty) when nothing was resolved — an unidentified platform must
// not appear as an empty-string claim in the JSON.
func TestProfileIDRoundTrips(t *testing.T) {
	f := Finding{Resource: Resource{Platform: "Cisco IOS-XE 17.9"}.ResolvePlatform()}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"profile_id":"cisco/ios_xe"`) {
		t.Fatalf("profile id missing from JSON: %s", b)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Resource.ProfileID != "cisco/ios_xe" {
		t.Fatalf("profile id not preserved: %q", back.Resource.ProfileID)
	}

	unknown, err := json.Marshal(Finding{Resource: Resource{Platform: "Acme WidgetOS"}.ResolvePlatform()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(unknown), "profile_id") {
		t.Fatalf("an unresolved platform must not emit a profile_id key: %s", unknown)
	}
}
