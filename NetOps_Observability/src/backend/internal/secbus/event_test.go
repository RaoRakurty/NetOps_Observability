// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secbus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// ── §5g: the verdict REASON survives the bus ────────────────────────────────

// TestFromFinding_UnknownCarriesItsReason is the producer half of the
// 2026-09-03 "Unknown with no WHY" defect. On the lab stack every hardening
// verdict was Unknown and the indexed document carried only attrs.status — so
// the UI could say "unassessed" but never why, and the three reasons an
// operator has to tell apart (config unavailable / control not applicable on
// this platform / platform unresolved) were indistinguishable on the wire.
func TestFromFinding_UnknownCarriesItsReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status secfindings.StatusID
		detail string
	}{
		{"config unavailable", secfindings.StatusUnknown,
			"running-config unavailable — control not assessed (fail-closed)"},
		{"control not applicable", secfindings.StatusNotApplicable,
			"SR Linux has no telnet server in its model — SSHv2 only"},
		{"platform unresolved", secfindings.StatusUnknown,
			`unassessed: platform unresolved — the platform label "Acme WidgetOS 1.0" matches no vendor profile`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := postureFinding()
			f.Observed, f.Remediation = "", ""
			f.EvidenceRef = nil
			f.Detail = tc.detail
			f.SetStatus(tc.status)

			ev, err := FromFinding(f)
			if err != nil {
				t.Fatalf("FromFinding: %v", err)
			}
			if got := ev.Attrs["status_detail"]; got != tc.detail {
				t.Errorf("attrs.status_detail = %v, want %q", got, tc.detail)
			}
			if ev.Attrs["status"] != tc.status.String() {
				t.Errorf("attrs.status = %v, want %q", ev.Attrs["status"], tc.status)
			}
			// It must survive JSON encoding — this is what the router indexes.
			blob, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var back EvidenceEvent
			if err := json.Unmarshal(blob, &back); err != nil {
				t.Fatal(err)
			}
			if back.Attrs["status_detail"] != tc.detail {
				t.Errorf("status_detail did not round-trip: %v", back.Attrs["status_detail"])
			}
		})
	}
}

// TestFromFinding_NoReasonEmitsNoField: an empty Detail is omitted rather than
// written as "" — an absent reason must read as absent, never as a blank one.
func TestFromFinding_NoReasonEmitsNoField(t *testing.T) {
	f := postureFinding()
	f.Detail = "   "
	ev, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ev.Attrs["status_detail"]; ok {
		t.Errorf("attrs.status_detail present for an empty reason: %v", ev.Attrs["status_detail"])
	}
}

// TestFromFinding_ReasonIsBoundedAndUTF8Safe: producer prose is external input
// (§9 bounded IO), and these reasons are full of 3-byte em-dashes, so the cut
// must land on a rune boundary.
func TestFromFinding_ReasonIsBoundedAndUTF8Safe(t *testing.T) {
	f := postureFinding()
	f.Detail = strings.Repeat("— unassessed ", 200)
	ev, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ev.Attrs["status_detail"].(string)
	if utf8.RuneCountInString(got) != StatusDetailMax+1 { // +1 for the ellipsis
		t.Errorf("reason length = %d runes, want %d + ellipsis", utf8.RuneCountInString(got), StatusDetailMax)
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncated reason is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated reason does not say it was truncated: %q", got)
	}
}

// TestFromFinding_ReasonIsNotAnEvidenceLeak: the reason rides the wire, the raw
// evidence still does not. Finding.Observed IS the offending config excerpt and
// must stay off the bus (§5c / LLM06).
func TestFromFinding_ReasonIsNotAnEvidenceLeak(t *testing.T) {
	f := postureFinding()
	f.Detail = "running-config unavailable — control not assessed (fail-closed)"
	f.Observed = "snmp-server community s3cr3t RO"
	ev, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(ev)
	if strings.Contains(string(blob), "s3cr3t") {
		t.Errorf("wire event leaked the observed config excerpt: %s", blob)
	}
	if !strings.Contains(string(blob), "fail-closed") {
		t.Errorf("wire event dropped the verdict reason: %s", blob)
	}
}

// TestFindingIDMatchesTheRouterFormula is the D-09 producer half.
//
// The OpenSearch document `_id` is NOT assigned by Go: the vector-router's
// `security_identity` transform computes sha2(native_id | attrs.scan_id) into
// `.cx_finding_id`, and the secfindings sink (`id_key: cx_finding_id`) lifts it
// into the bulk action's `_id` and strips it from the body. FromFinding
// recomputes the SAME value from the SAME two inputs so the field also exists
// on the bus — this test pins that it is byte-identical to the router's
// formula, because a producer id that differed from the storage id would be
// worse than no id at all.
func TestFindingIDMatchesTheRouterFormula(t *testing.T) {
	ev, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatal(err)
	}
	scanID, _ := ev.Attrs["scan_id"].(string)
	if scanID == "" {
		t.Fatal("attrs.scan_id is empty — the id formula has no second half")
	}
	// The router's expression, spelled out independently of the implementation.
	sum := sha256.Sum256([]byte(ev.NativeID + "|" + scanID))
	want := hex.EncodeToString(sum[:])
	if ev.FindingID != want {
		t.Errorf("cx_finding_id = %q, want sha256(native_id|scan_id) = %q", ev.FindingID, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ev.FindingID) {
		t.Errorf("cx_finding_id = %q, want 64 lowercase hex chars (the router emits sha2 SHA-256)", ev.FindingID)
	}
	// It rides the wire under the name the router, the mapping and secapi's
	// FieldDocID all use.
	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["cx_finding_id"] != want {
		t.Errorf("wire cx_finding_id = %v, want %q", wire["cx_finding_id"], want)
	}
}

// TestFindingIDIsDeterministicAndScanScoped: same finding ⇒ same id (a replay
// UPSERTS instead of duplicating a verdict), a new scan ⇒ a new id (every
// scan's verdict is RETAINED, which is what makes trend/drift possible).
func TestFindingIDIsDeterministicAndScanScoped(t *testing.T) {
	f := postureFinding()
	a, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if a.FindingID != b.FindingID {
		t.Errorf("cx_finding_id not deterministic: %q vs %q", a.FindingID, b.FindingID)
	}
	next := postureFinding()
	next.ScanID = "scan-124"
	c, err := FromFinding(next)
	if err != nil {
		t.Fatal(err)
	}
	if c.FindingID == a.FindingID {
		t.Error("a second scan reused the first scan's document id — the newer verdict would overwrite the older one")
	}
}

// TestFindingIDIsOmittedWhenIdentityIsIncomplete mirrors the router: with
// native_id or attrs.scan_id missing the record is QUARANTINED rather than
// indexed under an invented id, so the producer must not hash an empty half
// either (that would mint an id the storage layer never uses).
func TestFindingIDIsOmittedWhenIdentityIsIncomplete(t *testing.T) {
	noScan := postureFinding()
	noScan.ScanID = ""
	ev, err := FromFinding(noScan)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ev.Attrs["scan_id"]; ok {
		t.Fatal("attrs.scan_id should be omitted when blank")
	}
	if ev.FindingID != "" {
		t.Errorf("cx_finding_id = %q, want empty — the router would have quarantined this record", ev.FindingID)
	}
	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "cx_finding_id") {
		t.Errorf("an incomplete identity still put cx_finding_id on the wire: %s", blob)
	}
	// Direct unit check of the helper's two guards.
	if got := findingDocIDOf("", map[string]any{"scan_id": "s"}); got != "" {
		t.Errorf("no native_id → %q, want empty", got)
	}
	if got := findingDocIDOf("n", map[string]any{"scan_id": 7}); got != "" {
		t.Errorf("non-string scan_id → %q, want empty", got)
	}
}

// ---- L-01: native_id is the FINDING identity, not the verdict identity ------

// TestNativeIDIsStableAcrossScans is L-01's core property. `current=true` and
// the compliance scorecards are a COLLAPSE on native_id, so a second scan of
// the same rule on the same device must reuse the first scan's native_id — or
// nothing is ever superseded and the Findings page accumulates every verdict
// ever recorded (measured live: 572 rows, 444 of them stale Unknowns).
func TestNativeIDIsStableAcrossScans(t *testing.T) {
	first := postureFinding()
	first.ScanID = "scan-100"
	first.Time = time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	first.SetStatus(secfindings.StatusFail)

	second := postureFinding()
	second.ScanID = "scan-200"
	second.Time = time.Date(2026, 9, 3, 5, 0, 0, 0, time.UTC)
	second.SetStatus(secfindings.StatusNotApplicable)

	a, err := FromFinding(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromFinding(second)
	if err != nil {
		t.Fatal(err)
	}
	if a.NativeID != b.NativeID {
		t.Fatalf("L-01 REGRESSION: two scans of the same finding minted different native_ids:\n %q\n %q\n"+
			"the newer verdict can never supersede the older one under the collapse", a.NativeID, b.NativeID)
	}
	if strings.Contains(a.NativeID, "scan-") {
		t.Errorf("native_id still carries a scan id: %q", a.NativeID)
	}
	// The scan identity is NOT lost — it rides in attrs, which is where the
	// per-run identity belongs and where the QA run keys scans on.
	if a.Attrs["scan_id"] != "scan-100" || b.Attrs["scan_id"] != "scan-200" {
		t.Errorf("the scan identity was lost: %v / %v", a.Attrs["scan_id"], b.Attrs["scan_id"])
	}
	// And the STORAGE identity stays per-scan-unique, so both verdicts are
	// retained (trend/drift read that history) and only the VIEW collapses.
	if a.FindingID == b.FindingID {
		t.Fatalf("two scans collapsed onto ONE document id %q — the older verdict would be overwritten "+
			"and the retained history the trend view reads would be destroyed", a.FindingID)
	}
}

// TestNativeIDDiscriminatesTenantDeviceAndRule: stable is only half the
// contract. Two findings that are genuinely different must NOT share an
// identity, or one would silently supersede the other under the collapse — and
// for the tenant segment, the cross-tenant platform view (which collapses with
// no tenant filter under it) would fold two tenants' devices into one row.
func TestNativeIDDiscriminatesTenantDeviceAndRule(t *testing.T) {
	base := postureFinding()
	baseEv, err := FromFinding(base)
	if err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(*secfindings.Finding){
		"tenant":         func(f *secfindings.Finding) { f.TenantID = "tenant-Z" },
		"device":         func(f *secfindings.Finding) { f.Resource.DeviceID = "dev-78" },
		"rule (f.ID)":    func(f *secfindings.Finding) { f.ID = "another-rule" },
		"control":        func(f *secfindings.Finding) { f.ControlID = "xccdf_other" },
		"evidence class": func(f *secfindings.Finding) { f.EvidenceClass = secfindings.EvidenceExposure },
	}
	for name, mut := range mutate {
		f := postureFinding()
		mut(&f)
		ev, err := FromFinding(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ev.NativeID == baseEv.NativeID {
			t.Errorf("a different %s reused native_id %q — the two findings would collapse onto one row",
				name, ev.NativeID)
		}
	}
	// Re-deriving the untouched finding is byte-stable (§9 idempotency).
	again, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatal(err)
	}
	if again.NativeID != baseEv.NativeID {
		t.Errorf("native_id is not byte-stable: %q vs %q", again.NativeID, baseEv.NativeID)
	}
}
