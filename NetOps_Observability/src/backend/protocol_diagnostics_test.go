package backend

// protocol_diagnostics_test.go — handler-level tests for the routing-protocol
// diagnostics HTTP surface, driven through the REAL router + auth middleware
// (httptest). Covers: catalog shape, analyze happy path (signature fires +
// redaction present in the TAC export), analyze fail-closed (no invented cause),
// analyze input validation (oversized body, unknown protocol/issue, unknown spec
// id), collect happy path with a MOCK CommandRunner, and collect fail-closed
// (no runner configured → 503). The §3a cross-org isolation guard lives in
// protocol_diagnostics_isolation_test.go.

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

// pdMemCollector builds a Collector over the DefaultCatalog and a MemCommandRunner
// mapping RENDERED command text → output, for the given device/target/issue. It is
// the mock-device fixture for the collect tests (no real transport).
func pdMemCollector(t *testing.T, dev protocoldiag.Device, tgt protocoldiag.Target, issueID string, bySpec map[string]string) *protocoldiag.Collector {
	t.Helper()
	cat := protocoldiag.DefaultCatalog()
	issue, ok := cat.Issue(issueID)
	if !ok {
		t.Fatalf("unknown issue %q", issueID)
	}
	runner := protocoldiag.MemCommandRunner{}
	for _, spec := range issue.Bundle() {
		if out, ok := bySpec[spec.ID]; ok {
			runner[spec.Render(dev.Vendor(), tgt)] = out
		}
	}
	col, err := protocoldiag.NewCollector(cat, runner)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	return col
}

func TestProtocolDiagCatalog(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "GET", "/api/troubleshoot/protocol-diagnostics/catalog", admin, nil)
	if st != 200 {
		t.Fatalf("catalog: %d %s", st, b)
	}
	var resp struct {
		RulesetVersion string                   `json:"ruleset_version"`
		Vendor         string                   `json:"vendor"`
		Protocols      []string                 `json:"protocols"`
		Issues         map[string][]pdIssueView `json:"issues"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RulesetVersion != protocoldiag.RulesetVersion {
		t.Errorf("ruleset_version = %q, want %q", resp.RulesetVersion, protocoldiag.RulesetVersion)
	}
	total := 0
	for _, p := range []string{"bgp", "ospf", "isis"} {
		if len(resp.Issues[p]) != 5 {
			t.Errorf("protocol %s: %d issues, want 5", p, len(resp.Issues[p]))
		}
		total += len(resp.Issues[p])
	}
	if total != 15 {
		t.Fatalf("total issues = %d, want 15", total)
	}
	// Every issue must render a non-empty command bundle.
	for _, is := range resp.Issues["ospf"] {
		if len(is.Commands) == 0 {
			t.Errorf("issue %s has no commands", is.ID)
		}
		for _, c := range is.Commands {
			if strings.TrimSpace(c.Command) == "" {
				t.Errorf("issue %s spec %s rendered an empty command", is.ID, c.SpecID)
			}
		}
	}
}

func TestProtocolDiagCatalogRequiresAuth(t *testing.T) {
	srv, _ := newTestServerState(t)
	if st, _ := do(t, srv, "GET", "/api/troubleshoot/protocol-diagnostics/catalog", "", nil); st != 401 {
		t.Fatalf("unauthenticated catalog: %d, want 401", st)
	}
}

func TestProtocolDiagAnalyze_SignatureFiresAndRedacts(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// OSPF EXSTART neighbor + interface MTU line → the high-confidence
	// MTU-mismatch signature fires. The interface output also carries a secret so
	// we can assert the TAC export redacted it.
	body := map[string]any{
		"protocol": "ospf",
		"issue_id": "ospf-neighbor-stuck",
		"device":   map[string]string{"hostname": "core-01", "platform": "Cisco IOS-XE 17.9"},
		"outputs": []map[string]string{
			{"spec_id": "ospf-neighbor", "output": "Neighbor ID Pri State Dead Time Address Interface\n10.0.0.2 1 EXSTART/DR 00:00:35 10.0.0.2 GigabitEthernet0/0"},
			{"spec_id": "ospf-interface", "output": "GigabitEthernet0/0 is up\n  MTU is 1500 bytes\n  message-digest-key 1 md5 SuperSecretKey123"},
		},
	}
	st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", admin, body)
	if st != 200 {
		t.Fatalf("analyze: %d %s", st, b)
	}
	var resp struct {
		Matched   bool            `json:"matched"`
		Findings  []pdFindingView `json:"findings"`
		Unmatched string          `json:"unmatched"`
		TACExport string          `json:"tac_export"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Matched || len(resp.Findings) == 0 {
		t.Fatalf("expected a signature to fire, got matched=%v findings=%d", resp.Matched, len(resp.Findings))
	}
	if resp.Findings[0].SignatureID != "ospf-exstart-mtu" {
		t.Errorf("top finding = %q, want ospf-exstart-mtu", resp.Findings[0].SignatureID)
	}
	if resp.Findings[0].Evidence.Line == "" {
		t.Error("finding has no evidence line")
	}
	// Redaction: the secret value must be gone from the shareable export, but the
	// structure (the knob name) must remain.
	if strings.Contains(resp.TACExport, "SuperSecretKey123") {
		t.Error("TAC export leaked the message-digest key")
	}
	if !strings.Contains(resp.TACExport, "[REDACTED]") {
		t.Error("TAC export shows no redaction marker")
	}
	if !strings.Contains(resp.TACExport, "TAC EXPORT (redacted)") {
		t.Error("TAC export missing its header")
	}
}

func TestProtocolDiagAnalyze_FailClosedNoInventedCause(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Output that matches no signature → honest "no known signature matched",
	// never a fabricated verdict.
	body := map[string]any{
		"protocol": "bgp",
		"issue_id": "bgp-session-down",
		"outputs": []map[string]string{
			{"spec_id": "bgp-summary", "output": "Neighbor V AS MsgRcvd MsgSent State/PfxRcd\n10.0.0.2 4 65001 100 100 12"},
		},
	}
	st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", admin, body)
	if st != 200 {
		t.Fatalf("analyze: %d %s", st, b)
	}
	var resp struct {
		Matched   bool            `json:"matched"`
		Findings  []pdFindingView `json:"findings"`
		Unmatched string          `json:"unmatched"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Matched || len(resp.Findings) != 0 {
		t.Fatalf("expected no findings, got matched=%v findings=%d", resp.Matched, len(resp.Findings))
	}
	if !strings.Contains(resp.Unmatched, "no known signature matched") {
		t.Errorf("unmatched = %q, want the honest fail-closed message", resp.Unmatched)
	}
}

func TestProtocolDiagAnalyze_BadInput(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	cases := []struct {
		name string
		body map[string]any
	}{
		{"unknown issue", map[string]any{"protocol": "ospf", "issue_id": "does-not-exist"}},
		{"protocol/issue mismatch", map[string]any{"protocol": "bgp", "issue_id": "ospf-neighbor-stuck"}},
		{"unknown spec id", map[string]any{
			"protocol": "ospf", "issue_id": "ospf-neighbor-stuck",
			"outputs": []map[string]string{{"spec_id": "not-in-bundle", "output": "x"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", admin, tc.body); st != 400 {
				t.Fatalf("%s: %d %s, want 400", tc.name, st, b)
			}
		})
	}
}

func TestProtocolDiagAnalyze_OversizedBodyRejected(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A single output larger than the per-output cap → 400 (not a silent accept).
	huge := strings.Repeat("A", pdAnalyzeMaxOutput+1)
	body := map[string]any{
		"protocol": "ospf", "issue_id": "ospf-neighbor-stuck",
		"outputs": []map[string]string{{"spec_id": "ospf-neighbor", "output": huge}},
	}
	if st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", admin, body); st != 400 {
		t.Fatalf("oversized output: %d %s, want 400", st, b)
	}
}

func TestProtocolDiagCollect_NoRunnerConfigured(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	// Platform owner can see a global device; leave the collector nil.
	s.discovery.Upsert(pdTestDevice("dev-x", "", "Cisco IOS-XE"))

	body := map[string]any{"device_id": "dev-x", "issue_id": "ospf-neighbor-stuck"}
	if st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/collect", admin, body); st != 503 {
		t.Fatalf("collect with no runner: %d %s, want 503", st, b)
	}
}

func TestProtocolDiagCollect_HappyPathMockRunner(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	s.discovery.Upsert(pdTestDevice("dev-x", "", "Cisco IOS-XE"))

	pdDev := protocoldiag.Device{ID: "dev-x", Hostname: "dev-x", Platform: "Cisco IOS-XE", TenantID: ""}
	var tgt protocoldiag.Target
	s.protocolCollector = pdMemCollector(t, pdDev, tgt, "ospf-neighbor-stuck", map[string]string{
		"ospf-neighbor": "10.0.0.2 1 EXSTART/DR 00:00:35 10.0.0.2 Gi0/0",
	})

	body := map[string]any{"device_id": "dev-x", "issue_id": "ospf-neighbor-stuck"}
	st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/collect", admin, body)
	if st != 200 {
		t.Fatalf("collect: %d %s", st, b)
	}
	var resp struct {
		DeviceID string           `json:"device_id"`
		IssueID  string           `json:"issue_id"`
		Commands []map[string]any `json:"commands"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DeviceID != "dev-x" || resp.IssueID != "ospf-neighbor-stuck" {
		t.Fatalf("unexpected collection identity: %+v", resp)
	}
	if len(resp.Commands) == 0 {
		t.Fatal("collection has no commands")
	}
	// The ospf-neighbor command must carry the mocked output.
	found := false
	for _, c := range resp.Commands {
		if c["spec_id"] == "ospf-neighbor" && strings.Contains(c["output"].(string), "EXSTART") {
			found = true
		}
	}
	if !found {
		t.Error("mocked ospf-neighbor output not present in the collection")
	}
}

func TestProtocolDiagCollect_UnknownDeviceIs404(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	// Configure a runner so a 404 can only come from the device scope check.
	pdDev := protocoldiag.Device{ID: "ghost", Platform: "Cisco IOS-XE"}
	s.protocolCollector = pdMemCollector(t, pdDev, protocoldiag.Target{}, "ospf-neighbor-stuck", nil)

	body := map[string]any{"device_id": "ghost", "issue_id": "ospf-neighbor-stuck"}
	if st, _ := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/collect", admin, body); st != 404 {
		t.Fatalf("unknown device: %d, want 404", st)
	}
}

// pdTestDevice builds an inventory device whose OS string drives the dialect.
func pdTestDevice(id, tenant, platform string) models.Device {
	return models.Device{ID: id, Name: id, TenantID: tenant, OS: platform}
}
