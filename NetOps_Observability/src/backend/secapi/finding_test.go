package secapi

// finding_test.go — the document → API projection, over the shape the router
// actually writes (the secbus EvidenceEvent) and over the direct
// secfindings.Finding shape a future writer may produce.

import (
	"encoding/json"
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

// busDoc is a verbatim bus-shaped document: classification in attrs, identity
// and seam at the top level, `ts` normalized to epoch millis by the router's
// &log_lane anchor.
const busDoc = `{
  "schema_version":"1","tenant_id":"acme","tenant_seg":"acme",
  "ts":1756684800000,"kind":"security_exposure",
  "entity_id":"rtr-1","entity_type":"device",
  "entity_tokens":["rtr-1","device:rtr-1","host:edge-rtr-1","seam:seam-7"],
  "severity":"critical","native_id":"security|security_exposure|exposure|AC-17|rtr-1|scan-9|f1",
  "seam_id":"seam-7","seam_type":"ISP","internet_facing":true,
  "evidence_refs":[{"locator":"cfg://rtr-1#L42","kind":"config-line","ruleset_version":"correlix-hardening-2026-08-27"}],
  "attrs":{"evidence_class":"exposure","provider_source":"correlix-netrule",
    "control_id":"AC-17","control_title":"Remote Access","category":"access-control",
    "raw_rule_id":"exp-telnet","scan_id":"scan-9","status":"Fail","status_id":3,
    "standards":["800-53:AC-17","CIS:1.2"],"seam_id":"seam-7","seam_type":"ISP"},
  "cx_finding_id":"abc123"
}`

func TestDecodeFindingFromBusShape(t *testing.T) {
	f, err := DecodeFinding(json.RawMessage(busDoc), "abc123")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.DocID != "abc123" {
		t.Errorf("id = %q", f.DocID)
	}
	if f.Scan != "scan-9" || f.ScanID != "scan-9" {
		t.Errorf("scan_id = %q / scan_uid = %q", f.Scan, f.ScanID)
	}
	if f.Native == "" {
		t.Error("native_id missing — the current-state collapse key must round-trip")
	}
	if want := time.UnixMilli(1756684800000).UTC(); !f.Time.Equal(want) {
		t.Errorf("time = %s, want %s", f.Time, want)
	}
	if f.Severity != "critical" || f.Status != "Fail" || f.StatusID != secfindings.StatusFail {
		t.Errorf("verdict = %s/%s/%d", f.Severity, f.Status, f.StatusID)
	}
	if f.ControlID != "AC-17" || f.ControlTitle != "Remote Access" || f.Category != "access-control" {
		t.Errorf("control fields wrong: %+v", f)
	}
	if len(f.Standards) != 2 || f.Standards[0] != "800-53:AC-17" {
		t.Errorf("standards = %v", f.Standards)
	}
	if f.EvidenceClass != "exposure" || f.Source != "correlix-netrule" || f.RawRuleID != "exp-telnet" {
		t.Errorf("provenance wrong: %+v", f)
	}
	if f.Resource.DeviceID != "rtr-1" {
		t.Errorf("resource.uid = %q", f.Resource.DeviceID)
	}
	if f.Resource.Hostname != "edge-rtr-1" {
		t.Errorf("hostname must be recovered from the host: co-location token, got %q", f.Resource.Hostname)
	}
	if f.SeamContext == nil || f.SeamContext.SeamType != "ISP" || !f.SeamContext.InternetFacing {
		t.Errorf("seam attribution lost: %+v", f.SeamContext)
	}
	if f.EvidenceRef == nil || f.EvidenceRef.Locator != "cfg://rtr-1#L42" ||
		f.EvidenceRef.RulesetVersion != "correlix-hardening-2026-08-27" {
		t.Errorf("evidence ref lost: %+v", f.EvidenceRef)
	}
}

// TestDecodeFindingNeverInventsNarrative pins the KNOWN GAP as behaviour: the
// bus carries no narrative (secbus keeps it off the wire by design), so those
// fields decode EMPTY and are omitted from the JSON. An empty string is honest;
// a fabricated summary would not be.
func TestDecodeFindingNeverInventsNarrative(t *testing.T) {
	f, err := DecodeFinding(json.RawMessage(busDoc), "abc123")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Observed != "" || f.Intended != "" || f.Detail != "" || f.Remediation != "" {
		t.Fatalf("narrative was invented from a document that carries none: %+v", f)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, absent := range []string{"observed", "intended", "status_detail", "remediation"} {
		if _, present := out[absent]; present {
			t.Errorf("%q must be OMITTED when the store carries none, not emitted empty", absent)
		}
	}
	// The contract's four identity fields are always present.
	for _, required := range []string{"id", "scan_id", "native_id", "time"} {
		if _, present := out[required]; !present {
			t.Errorf("contract field %q missing from the serialized finding", required)
		}
	}
	// §3a hygiene: the tenant is NEVER serialized to a client.
	if _, leaked := out["tenant_id"]; leaked {
		t.Fatal("TENANT LEAK: tenant_id was serialized onto a finding")
	}
}

// TestDecodeFindingPrefersDirectFields proves the fallback direction: when a
// document carries the direct secfindings.Finding names (the shape the index
// template also declares), those win over attrs.
func TestDecodeFindingPrefersDirectFields(t *testing.T) {
	const directDoc = `{
	  "ts":"2026-08-31T23:00:00Z","severity":"high","entity_id":"rtr-2",
	  "status":"Warning","status_id":2,"control":"CM-6","control_title":"Baseline",
	  "evidence_class":"posture","source":"openscap","standards":["CIS:2.1"],
	  "scan_uid":"scan-11","native_id":"n-2","category_name":"drift",
	  "observed":"telnet is enabled","intended":"telnet disabled",
	  "status_detail":"line vty 0 4 transport input telnet","remediation":"transport input ssh",
	  "resource":{"uid":"rtr-2","name":"edge2","hostname":"edge2.example","ip":"10.0.0.2","type":"network-device","platform":"IOS-XE 17.9"},
	  "seam":{"seam_id":"seam-9","seam_type":"mgmt","internet_facing":false},
	  "evidence_ref":{"locator":"oval://x","kind":"oval-result"},
	  "attrs":{"status":"Fail","control_id":"WRONG","evidence_class":"signal"}
	}`
	f, err := DecodeFinding(json.RawMessage(directDoc), "doc-2")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Status != "Warning" || f.StatusID != secfindings.StatusWarning {
		t.Errorf("direct status must win over attrs: %s/%d", f.Status, f.StatusID)
	}
	if f.ControlID != "CM-6" || f.EvidenceClass != "posture" {
		t.Errorf("direct control/class must win over attrs: %+v", f)
	}
	if f.Observed == "" || f.Remediation == "" {
		t.Error("narrative present on the document must be returned")
	}
	if f.Resource.Platform != "IOS-XE 17.9" || f.Resource.Address != "10.0.0.2" {
		t.Errorf("resource fields lost: %+v", f.Resource)
	}
	if f.SeamContext == nil || f.SeamContext.SeamType != "mgmt" || f.SeamContext.InternetFacing {
		t.Errorf("nested seam object not read: %+v", f.SeamContext)
	}
	if want := time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC); !f.Time.Equal(want) {
		t.Errorf("RFC3339 ts = %s, want %s", f.Time, want)
	}
}

// TestDecodeFindingWithNoTimeIsZeroNotNow — a verdict whose time we cannot read
// must not be dated to the moment it was read; that would put a stale finding
// at the top of a time-sorted list and into today's trend bucket.
func TestDecodeFindingWithNoTimeIsZeroNotNow(t *testing.T) {
	f, err := DecodeFinding(json.RawMessage(`{"severity":"low"}`), "x")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !f.Time.IsZero() {
		t.Fatalf("time = %s, want the zero instant", f.Time)
	}
}

// TestDecodeFindingDerivesStatusIDFromName keeps the pair consistent: the model
// forbids status and status_id disagreeing.
func TestDecodeFindingDerivesStatusIDFromName(t *testing.T) {
	f, err := DecodeFinding(json.RawMessage(`{"attrs":{"status":"NotApplicable"}}`), "x")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.StatusID != secfindings.StatusNotApplicable {
		t.Fatalf("status_id = %d, want NotApplicable derived from the name", f.StatusID)
	}
}
