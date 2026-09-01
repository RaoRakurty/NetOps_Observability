package secbus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

func postureFinding() secfindings.Finding {
	f := secfindings.Finding{
		TenantID:      "tenant-A",
		Source:        secfindings.SourceOpenSCAP,
		ScanID:        "scan-123",
		Time:          time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		EvidenceClass: secfindings.EvidencePosture,
		Standards:     []string{"CIS-1.2", "NIST-AC-2"},
		ControlID:     "xccdf_org.cis_rule_ssh_root",
		ControlTitle:  "Disable root SSH login",
		Category:      "hardening",
		Severity:      secfindings.SeverityHigh,
		Resource: secfindings.Resource{
			DeviceID: "dev-77", Hostname: "edge01.example", Kind: secfindings.KindNetworkDevice,
		},
		Observed:    "PermitRootLogin yes",
		Intended:    "PermitRootLogin no",
		Remediation: "set PermitRootLogin no",
		EvidenceRef: &secfindings.EvidenceRef{
			Locator: "oval:12345:res:1", Kind: "oval-result", RulesetVersion: "cis-8.0", Digest: "sha256:abc",
		},
		RawRuleID: "sshd_root_login",
	}
	f.SetStatus(secfindings.StatusFail)
	return f
}

func exposureFinding() secfindings.Finding {
	f := secfindings.Finding{
		TenantID:      "tenant-B",
		Source:        secfindings.SourceNetRule,
		ScanID:        "scan-999",
		Time:          time.Date(2026, 8, 27, 13, 30, 0, 0, time.UTC),
		EvidenceClass: secfindings.EvidenceExposure,
		ControlID:     "expose-telnet",
		Severity:      secfindings.SeverityCritical,
		Resource: secfindings.Resource{
			Hostname: "wan-gw", Kind: secfindings.KindNetworkDevice,
		},
		SeamContext: &secfindings.SeamContext{
			SeamID: "seam-isp-1", SeamType: "ISP", InternetFacing: true,
		},
	}
	f.SetStatus(secfindings.StatusFail)
	return f
}

func TestFromFinding_Posture(t *testing.T) {
	ev, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatalf("FromFinding: %v", err)
	}
	if ev.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", ev.SchemaVersion, SchemaVersion)
	}
	// entity_id populated per the engine convention (device uid, bare id).
	if ev.EntityID != "dev-77" {
		t.Errorf("entity_id = %q, want device uid dev-77", ev.EntityID)
	}
	if ev.EntityType != EntityTypeDevice {
		t.Errorf("entity_type = %q, want device", ev.EntityType)
	}
	if ev.Kind != KindPosture {
		t.Errorf("kind = %q, want %q", ev.Kind, KindPosture)
	}
	// tenant carried from the finding (§3a).
	if ev.TenantID != "tenant-A" {
		t.Errorf("tenant_id = %q, want tenant-A", ev.TenantID)
	}
	// entity_tokens carry bare id + device:/host: co-location keys, none forbidden.
	wantTokens := map[string]bool{"dev-77": true, "device:dev-77": true, "host:edge01.example": true}
	if len(ev.EntityTokens) != len(wantTokens) {
		t.Fatalf("entity_tokens = %v, want keys %v", ev.EntityTokens, wantTokens)
	}
	for _, tok := range ev.EntityTokens {
		if !wantTokens[tok] {
			t.Errorf("unexpected token %q", tok)
		}
		for _, bad := range []string{"tenant:", "org:", "global:", "all:"} {
			if strings.HasPrefix(tok, bad) {
				t.Errorf("token %q uses a forbidden tenant/org/global prefix", tok)
			}
		}
	}
	// severity carried raw (the engine's aliases map it) — not remapped here.
	if ev.Severity != secfindings.SeverityHigh {
		t.Errorf("severity = %q, want raw %q", ev.Severity, secfindings.SeverityHigh)
	}
	// evidence held BY REFERENCE — a locator/kind/version pointer, no payload.
	if len(ev.EvidenceRefs) != 1 || ev.EvidenceRefs[0].Locator != "oval:12345:res:1" {
		t.Fatalf("evidence_refs = %+v, want one locator pointer", ev.EvidenceRefs)
	}
	// classification rides in attrs; NO raw evidence / narrative / secret inlined.
	if ev.Attrs["control_id"] != "xccdf_org.cis_rule_ssh_root" {
		t.Errorf("attrs.control_id = %v", ev.Attrs["control_id"])
	}
	if ev.Attrs["status"] != "Fail" {
		t.Errorf("attrs.status = %v, want Fail", ev.Attrs["status"])
	}
	blob, _ := json.Marshal(ev)
	for _, leak := range []string{"PermitRootLogin", "set PermitRootLogin no", "Observed", "Remediation"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("wire event leaked raw evidence/narrative %q: %s", leak, blob)
		}
	}
	if strings.Contains(string(blob), `"-"`) {
		t.Errorf("tenant sentinel leaked")
	}
}

func TestFromFinding_ExposureSeam(t *testing.T) {
	ev, err := FromFinding(exposureFinding())
	if err != nil {
		t.Fatalf("FromFinding: %v", err)
	}
	if ev.Kind != KindExposure {
		t.Errorf("kind = %q, want %q", ev.Kind, KindExposure)
	}
	// falls back to hostname for entity_id when no device uid.
	if ev.EntityID != "wan-gw" {
		t.Errorf("entity_id = %q, want hostname wan-gw", ev.EntityID)
	}
	// seam attribution mapped to top-level + attrs; seam token present.
	if ev.SeamID != "seam-isp-1" || ev.SeamType != "ISP" || !ev.InternetFacing {
		t.Errorf("seam fields = %q/%q/%v", ev.SeamID, ev.SeamType, ev.InternetFacing)
	}
	if ev.Attrs["seam_id"] != "seam-isp-1" {
		t.Errorf("attrs.seam_id = %v", ev.Attrs["seam_id"])
	}
	var hasSeamTok bool
	for _, tok := range ev.EntityTokens {
		if tok == "seam:seam-isp-1" {
			hasSeamTok = true
		}
	}
	if !hasSeamTok {
		t.Errorf("expected seam co-location token, got %v", ev.EntityTokens)
	}
}

func TestFromFinding_Idempotent(t *testing.T) {
	f := postureFinding()
	a, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if a.NativeID != b.NativeID {
		t.Errorf("native_id not deterministic: %q vs %q", a.NativeID, b.NativeID)
	}
	if a.NativeID == "" || !strings.HasPrefix(a.NativeID, "security|"+KindPosture+"|") {
		t.Errorf("native_id = %q, want stable security|kind|... form", a.NativeID)
	}
}

func TestFromFinding_Refusals(t *testing.T) {
	// No evidence class → refused (never a guessed lane).
	if _, err := FromFinding(secfindings.Finding{
		Time: time.Now(), Resource: secfindings.Resource{DeviceID: "x"},
	}); err == nil {
		t.Error("expected error for missing evidence_class")
	}
	// No subject → refused (entity_id is mandatory).
	if _, err := FromFinding(secfindings.Finding{
		EvidenceClass: secfindings.EvidencePosture, Time: time.Now(),
	}); err == nil {
		t.Error("expected error for missing subject")
	}
	// Zero time → refused (event-time discipline).
	if _, err := FromFinding(secfindings.Finding{
		EvidenceClass: secfindings.EvidencePosture, Resource: secfindings.Resource{DeviceID: "x"},
	}); err == nil {
		t.Error("expected error for zero verdict time")
	}
}

// §3a: tenant is stamped from the finding, with no parameter to override it.
func TestFromFinding_TenantFromFindingOnly(t *testing.T) {
	f := postureFinding()
	f.TenantID = "tenant-Z"
	ev, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if ev.TenantID != "tenant-Z" {
		t.Errorf("tenant_id = %q, want tenant-Z (from finding)", ev.TenantID)
	}
}

// TestNativeID_PerFindingDiscriminator (#11): the native id carries the
// finding's own id, so two findings produced by ONE rule on ONE device in ONE
// scan get DISTINCT native ids — they must not collapse into a single
// signal downstream as "redeliveries" of each other — while a re-delivery of
// the SAME finding keeps the same id (§9 idempotency preserved).
func TestNativeID_PerFindingDiscriminator(t *testing.T) {
	a := postureFinding()
	a.ID = "sshd_root_login:dev-77:conv-1"
	b := postureFinding() // same control, device, scan — different finding
	b.ID = "sshd_root_login:dev-77:conv-2"

	evA, err := FromFinding(a)
	if err != nil {
		t.Fatal(err)
	}
	evB, err := FromFinding(b)
	if err != nil {
		t.Fatal(err)
	}
	if evA.NativeID == evB.NativeID {
		t.Fatalf("two distinct findings from one rule/device/scan collided: %q", evA.NativeID)
	}
	// Idempotency: the same finding re-delivered yields the same native id.
	evA2, err := FromFinding(a)
	if err != nil {
		t.Fatal(err)
	}
	if evA.NativeID != evA2.NativeID {
		t.Errorf("re-delivery changed native_id: %q vs %q", evA.NativeID, evA2.NativeID)
	}
	// The stable prefix contract holds for discriminated ids too.
	for _, id := range []string{evA.NativeID, evB.NativeID} {
		if !strings.HasPrefix(id, "security|"+KindPosture+"|") {
			t.Errorf("native_id = %q, want security|kind|... form", id)
		}
	}
	// A finding with no ID still grounds (identity degrades to assessment scope).
	c := postureFinding()
	evC, err := FromFinding(c)
	if err != nil {
		t.Fatal(err)
	}
	if evC.NativeID == "" || evC.NativeID == evA.NativeID {
		t.Errorf("empty-ID finding native_id = %q (a.ID variant = %q)", evC.NativeID, evA.NativeID)
	}
}

// TestNativeID_OverflowStaysDiscriminated (#11): when the joined form overflows
// the engine's 256-char cap and falls back to the hash, the per-finding
// discriminator must still separate two findings (it is inside the hash input).
func TestNativeID_OverflowStaysDiscriminated(t *testing.T) {
	long := strings.Repeat("x", 300)
	a := postureFinding()
	a.ControlID, a.ID = long, "f-1"
	b := postureFinding()
	b.ControlID, b.ID = long, "f-2"
	evA, err := FromFinding(a)
	if err != nil {
		t.Fatal(err)
	}
	evB, err := FromFinding(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(evA.NativeID) > 256 || len(evB.NativeID) > 256 {
		t.Fatalf("native_id over the 256-char cap: %d/%d", len(evA.NativeID), len(evB.NativeID))
	}
	if evA.NativeID == evB.NativeID {
		t.Fatal("hashed native ids collided across distinct finding ids")
	}
}
