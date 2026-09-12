// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// protocol_diagnostics_defects_test.go — regression suite for the defects the
// live QA run of 2026-09-03 filed against this surface
// (docs/qa/scenarios/troubleshooting-2026-09-03.md):
//
//	D-4  a TOTAL collection failure (every command rejected, 0 bytes) was
//	     reported as "no known signature matched" — i.e. as if the platform had
//	     looked and found the protocol healthy.
//	D-5  ?device= on the catalog route was silently ignored and the response
//	     fell back to the Cisco IOS-XE default, showing an operator commands for
//	     the wrong operating system while looking authoritative.
//	D-12 the documented POST …/export route was never registered and 404'd.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

// ── D-4 ─────────────────────────────────────────────────────────────────────

// pdAnalyzeShape is the analyze response's honesty contract on the wire.
type pdAnalyzeShape struct {
	Analyzed        bool            `json:"analyzed"`
	Matched         bool            `json:"matched"`
	OutputsReceived int             `json:"outputs_received"`
	OutputsSupplied int             `json:"outputs_supplied"`
	Unmatched       string          `json:"unmatched"`
	NotAnalyzed     string          `json:"not_analyzed"`
	Findings        []pdFindingView `json:"findings"`
	TACExport       string          `json:"tac_export"`
}

func pdAnalyze(t *testing.T, srv *httptest.Server, token string, body map[string]any) (int, pdAnalyzeShape, []byte) {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", token, body)
	var out pdAnalyzeShape
	if st == 200 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode analyze response: %v (%s)", err, b)
		}
	}
	return st, out, b
}

// TestProtocolDiagAnalyze_NothingCollectedIsNotNothingMatched is the D-4 guard.
// "no output was supplied" and "output was scored and nothing matched" are two
// different facts about the network and must never share a sentence.
func TestProtocolDiagAnalyze_NothingCollectedIsNotNothingMatched(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	cases := []struct {
		name    string
		outputs []map[string]string
	}{
		{"no outputs at all", nil},
		{"outputs present but every one empty", []map[string]string{
			{"spec_id": "isis-neighbors", "output": ""},
			{"spec_id": "isis-interface", "output": ""},
		}},
		{"outputs present but whitespace only", []map[string]string{
			{"spec_id": "isis-neighbors", "output": "   \n\t\n"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"protocol": "isis", "issue_id": "isis-adjacency-down"}
			if tc.outputs != nil {
				body["outputs"] = tc.outputs
			}
			st, resp, raw := pdAnalyze(t, srv, admin, body)
			if st != 200 {
				t.Fatalf("analyze: %d %s", st, raw)
			}
			if resp.Analyzed {
				t.Error("analyzed must be false — nothing was scored")
			}
			if resp.Matched || len(resp.Findings) != 0 {
				t.Errorf("an empty capture produced findings: %+v", resp.Findings)
			}
			if resp.OutputsSupplied != 0 {
				t.Errorf("outputs_supplied = %d, want 0", resp.OutputsSupplied)
			}
			if strings.TrimSpace(resp.NotAnalyzed) == "" {
				t.Fatal("not_analyzed must state why nothing was analysed")
			}
			// The exact defect: the old response said this.
			if strings.Contains(strings.ToLower(resp.Unmatched), "no known signature matched") {
				t.Errorf("unmatched claims the signatures were scored: %q", resp.Unmatched)
			}
			if strings.TrimSpace(resp.Unmatched) != "" {
				t.Errorf("unmatched must be empty when nothing was analysed, got %q", resp.Unmatched)
			}
			low := strings.ToLower(resp.NotAnalyzed)
			for _, want := range []string{"no command output was supplied", "not"} {
				if !strings.Contains(low, want) {
					t.Errorf("not_analyzed does not say %q: %q", want, resp.NotAnalyzed)
				}
			}
			// The TAC bundle is still produced: an operator must be able to hand
			// a failed capture to a vendor precisely when we could explain nothing.
			if strings.TrimSpace(resp.TACExport) == "" {
				t.Error("tac_export must still be assembled when nothing was analysed")
			}
		})
	}

	// Control: real output present → the ORIGINAL contract, unchanged.
	t.Run("collected but unmatched keeps its own honest wording", func(t *testing.T) {
		st, resp, raw := pdAnalyze(t, srv, admin, map[string]any{
			"protocol": "isis",
			"issue_id": "isis-adjacency-down",
			"outputs": []map[string]string{
				{"spec_id": "isis-neighbors", "output": "| ethernet-1/1.0 | 0100.0000.0011 | L2 | 10.0.1.1 | :: | up | 30 |"},
			},
		})
		if st != 200 {
			t.Fatalf("analyze: %d %s", st, raw)
		}
		if !resp.Analyzed {
			t.Fatal("analyzed must be true — output was supplied and scored")
		}
		if resp.OutputsSupplied != 1 {
			t.Errorf("outputs_supplied = %d, want 1", resp.OutputsSupplied)
		}
		if resp.NotAnalyzed != "" {
			t.Errorf("not_analyzed must be empty when the signatures ran: %q", resp.NotAnalyzed)
		}
		if !resp.Matched && strings.TrimSpace(resp.Unmatched) == "" {
			t.Error("an unmatched-but-scored analysis must still say so in `unmatched`")
		}
	})
}

// TestAIProtocolDiagnosticTotalCollectionFailure is D-4 on the Iris bridge —
// the path the live run actually exercised: 7 of 7 read-only commands rejected
// by an SR Linux box, 0 bytes captured, and the operator told "the diagnostic
// ran and no known signature matched", which reads as "we looked, IS-IS is
// fine". Nothing was looked at.
func TestAIProtocolDiagnosticTotalCollectionFailure(t *testing.T) {
	s := aiTSServer(t)
	col, err := protocoldiag.NewCollector(protocoldiag.DefaultCatalog(), pdFailingRunner{})
	if err != nil {
		t.Fatal(err)
	}
	s.protocolCollector = col

	// The capture is a device OPERATION, so the caller needs infrastructure
	// write — the same gate the HTTP collect endpoint applies.
	claims := jwtClaims{Sub: "root", Role: RoleSuperAdmin}
	deps := aiTSDeps(t, s, claims)
	rep, err := deps.ProtocolDiagnostic(context.Background(), aiTSPrincipal(), ai.DiagnosticRequest{
		DeviceID: "acme-core", Protocol: "isis", IssueID: "isis-adjacency-down",
	})
	if err != nil {
		t.Fatalf("ProtocolDiagnostic: %v", err)
	}

	if rep.Collected {
		t.Error("Collected must be false — zero bytes were captured (this is D-4)")
	}
	if !rep.Attempted {
		t.Error("Attempted must be true — the capture really did run; conflating it with " +
			"\"no transport wired\" would hide a device that rejects our commands")
	}
	if rep.Total == 0 || rep.Failed != rep.Total {
		t.Errorf("Total/Failed = %d/%d, want every command failed", rep.Total, rep.Failed)
	}
	if strings.TrimSpace(rep.CollectFailed) == "" {
		t.Fatal("CollectFailed must state what happened")
	}
	if strings.Contains(strings.ToLower(rep.CollectFailed), "signature") {
		t.Errorf("the failure reason talks about signatures, which never ran: %q", rep.CollectFailed)
	}
	if rep.Unmatched != "" {
		t.Errorf("Unmatched must stay empty — nothing was scored: %q", rep.Unmatched)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("nothing was captured, so there can be no findings: %+v", rep.Findings)
	}
	withErr := 0
	for _, c := range rep.Commands {
		if strings.TrimSpace(c.Error) != "" {
			withErr++
		}
	}
	if withErr != rep.Total {
		t.Errorf("%d of %d commands carry a per-command error; the reasons must survive the bridge",
			withErr, rep.Total)
	}

	// The assistant-facing RENDERING of this report (the notes, the UNKNOWN
	// framing and the machine fact the chain routes on) is pinned in the ai
	// package: ai/troubleshoot_uncollected_test.go.
}

// TestAIProtocolDiagnosticPartialCollectionIsDisclosed — a capture that got
// SOME output is still analysed, but the operator is told the verdict rests on
// less than the full bundle.
func TestAIProtocolDiagnosticPartialCollectionIsDisclosed(t *testing.T) {
	s := aiTSServer(t)
	cat := protocoldiag.DefaultCatalog()
	issue, ok := cat.Issue("isis-adjacency-down")
	if !ok {
		t.Fatal("catalog is missing isis-adjacency-down")
	}
	// Answer exactly ONE command; every other one fails.
	first := issue.Bundle()[0]
	col, err := protocoldiag.NewCollector(cat, pdPartialRunner{
		ok: first.Render(protocoldiag.VendorCiscoIOSXE, protocoldiag.Target{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.protocolCollector = col

	deps := aiTSDeps(t, s, jwtClaims{Sub: "root", Role: RoleSuperAdmin})
	rep, err := deps.ProtocolDiagnostic(context.Background(), aiTSPrincipal(), ai.DiagnosticRequest{
		DeviceID: "acme-core", Protocol: "isis", IssueID: "isis-adjacency-down",
	})
	if err != nil {
		t.Fatalf("ProtocolDiagnostic: %v", err)
	}
	if !rep.Collected || !rep.Attempted {
		t.Fatalf("a partial capture is still a capture: collected=%v attempted=%v", rep.Collected, rep.Attempted)
	}
	if rep.Failed == 0 || rep.Failed >= rep.Total {
		t.Fatalf("expected a PARTIAL capture, got %d of %d failed", rep.Failed, rep.Total)
	}
	captured := 0
	for _, c := range rep.Commands {
		if strings.TrimSpace(c.Error) == "" {
			captured++
		}
	}
	if captured != rep.Total-rep.Failed {
		t.Errorf("per-command errors (%d ok of %d) disagree with the counts (%d failed of %d)",
			captured, len(rep.Commands), rep.Failed, rep.Total)
	}
}

// pdFailingRunner rejects every command, like a device whose CLI does not
// understand the dialect its bundle was rendered in.
type pdFailingRunner struct{}

func (pdFailingRunner) Run(_ context.Context, _ protocoldiag.Device, command string) (string, error) {
	return "", fmt.Errorf("command %q failed: Process exited with status 1", command)
}

// pdPartialRunner answers exactly one command and rejects the rest.
type pdPartialRunner struct{ ok string }

func (p pdPartialRunner) Run(_ context.Context, _ protocoldiag.Device, command string) (string, error) {
	if command == p.ok {
		return "System Id Interface L State Holdtime\n0100.0000.0011 Gi0/0 2 Up 30", nil
	}
	return "", fmt.Errorf("command %q failed: Process exited with status 1", command)
}

// ── D-5 ─────────────────────────────────────────────────────────────────────

type pdCatalogShape struct {
	Vendor         string                   `json:"vendor"`
	VendorDisplay  string                   `json:"vendor_display"`
	Device         string                   `json:"device"`
	DevicePlatform string                   `json:"device_platform"`
	Issues         map[string][]pdIssueView `json:"issues"`
}

func pdCatalog(t *testing.T, srv *httptest.Server, token, query string) (int, pdCatalogShape, []byte) {
	t.Helper()
	st, b := do(t, srv, "GET", "/api/troubleshoot/protocol-diagnostics/catalog"+query, token, nil)
	var out pdCatalogShape
	if st == 200 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode catalog: %v (%s)", err, b)
		}
	}
	return st, out, b
}

// TestProtocolDiagCatalog_DeviceSelector is the D-5 guard: ?device= is HONOURED
// (it picks the dialect from the device's own platform), an unknown or
// cross-tenant id is a 404, ?vendor= with ?device= is refused rather than one
// silently winning, and any other query parameter is a 400 rather than a
// silently-ignored selector.
func TestProtocolDiagCatalog_DeviceSelector(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	s.discovery.Upsert(models.Device{
		ID: "pd-cat-jnpr", Name: "pd-cat-jnpr", Vendor: "juniper", OS: "Junos", Model: "MX204", TenantID: TenantGlobal,
	})

	// Baseline: no selector → the documented Cisco IOS-XE default.
	st, base, raw := pdCatalog(t, srv, admin, "")
	if st != 200 {
		t.Fatalf("catalog: %d %s", st, raw)
	}
	if base.Vendor != string(protocoldiag.VendorCiscoIOSXE) {
		t.Fatalf("default vendor = %q, want %q", base.Vendor, protocoldiag.VendorCiscoIOSXE)
	}
	if base.Device != "" || base.DevicePlatform != "" {
		t.Errorf("no ?device= was sent but the response names one: %q/%q", base.Device, base.DevicePlatform)
	}

	// ?device= resolves the dialect from the device's OWN platform string.
	st, byDev, raw := pdCatalog(t, srv, admin, "?device=pd-cat-jnpr")
	if st != 200 {
		t.Fatalf("catalog?device=: %d %s", st, raw)
	}
	if byDev.Vendor != string(protocoldiag.VendorJuniper) {
		t.Fatalf("?device= was ignored: vendor = %q, want %q (this is D-5)", byDev.Vendor, protocoldiag.VendorJuniper)
	}
	if byDev.Device != "pd-cat-jnpr" {
		t.Errorf("device echo = %q, want the resolved id", byDev.Device)
	}
	if !strings.Contains(strings.ToLower(byDev.DevicePlatform), "junos") {
		t.Errorf("device_platform = %q, want the platform the dialect was derived from", byDev.DevicePlatform)
	}
	// The commands themselves must actually differ from the default dialect —
	// the selector changing only a label would be the same trap in a new shape.
	if sameFirstCommand(base, byDev) {
		t.Error("?device= changed the vendor label but not the rendered commands")
	}
	// ?vendor= must still work exactly as before.
	st, byVendor, raw := pdCatalog(t, srv, admin, "?vendor=juniper%20junos")
	if st != 200 {
		t.Fatalf("catalog?vendor=: %d %s", st, raw)
	}
	if byVendor.Vendor != string(protocoldiag.VendorJuniper) {
		t.Errorf("?vendor= regressed: %q", byVendor.Vendor)
	}

	// Refusals.
	for _, tc := range []struct {
		name, query string
		want        int
	}{
		{"unknown device id", "?device=no-such-device", http.StatusNotFound},
		{"both selectors", "?device=pd-cat-jnpr&vendor=nokia", http.StatusBadRequest},
		{"an unknown selector is never silently ignored", "?platform=nokia", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, _, b := pdCatalog(t, srv, admin, tc.query); st != tc.want {
				t.Fatalf("%s: %d, want %d (%s)", tc.query, st, tc.want, b)
			}
		})
	}
}

func sameFirstCommand(a, b pdCatalogShape) bool {
	first := func(c pdCatalogShape) string {
		for _, proto := range []string{"bgp", "isis", "ospf"} {
			for _, is := range c.Issues[proto] {
				if len(is.Commands) > 0 {
					return is.ID + "|" + is.Commands[0].Command
				}
			}
		}
		return ""
	}
	return first(a) == first(b)
}

// TestProtocolDiagCatalogDeviceCrossOrgIsolation — §3a.5. ?device= made the
// catalog route tenant-scoped, so it ships the isolation test the ledger
// requires: own device resolves, another org's device is a 404 (never a 200
// with the default dialect, and never an existence signal), and an acting-tenant
// escalation into the other org is ignored.
func TestProtocolDiagCatalogDeviceCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "PDC Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "PDC Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "pdc-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]
	s.discovery.Upsert(models.Device{ID: "pdc-dev-a", Name: "pdc-dev-a", Vendor: "juniper", OS: "Junos", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "pdc-dev-b", Name: "pdc-dev-b", Vendor: "nokia", OS: "SR OS", TenantID: b.tenantID})

	if st, resp, raw := pdCatalog(t, srv, a.token, "?device=pdc-dev-a"); st != 200 || resp.Device != "pdc-dev-a" {
		t.Fatalf("A reading its own device: %d %s", st, raw)
	}
	if st, _, raw := pdCatalog(t, srv, a.token, "?device=pdc-dev-b"); st != http.StatusNotFound {
		t.Fatalf("A reading B's device: %d, want 404 (%s)", st, raw)
	}
	if st, _, raw := pdCatalog(t, srv, b.token, "?device=pdc-dev-a"); st != http.StatusNotFound {
		t.Fatalf("B reading A's device: %d, want 404 (%s)", st, raw)
	}
	// An unknown id and another tenant's id must be INDISTINGUISHABLE.
	stUnknown, _, bodyUnknown := pdCatalog(t, srv, a.token, "?device=pdc-dev-nope")
	stForeign, _, bodyForeign := pdCatalog(t, srv, a.token, "?device=pdc-dev-b")
	if stUnknown != stForeign || string(bodyUnknown) != string(bodyForeign) {
		t.Fatalf("unknown vs cross-tenant differ — that is an existence oracle:\n%d %s\n%d %s",
			stUnknown, bodyUnknown, stForeign, bodyForeign)
	}
	// as_tenant into the other org is ignored for a scoped caller.
	if st, _, raw := pdCatalog(t, srv, a.token, "?device=pdc-dev-b&as_tenant="+b.tenantID); st != http.StatusNotFound {
		t.Fatalf("as_tenant widened a scoped caller: %d (%s)", st, raw)
	}
	// The platform owner reaches both.
	for _, id := range []string{"pdc-dev-a", "pdc-dev-b"} {
		if st, _, raw := pdCatalog(t, srv, admin, "?device="+id); st != 200 {
			t.Fatalf("owner reading %s: %d %s", id, st, raw)
		}
	}
}

// ── D-12 ────────────────────────────────────────────────────────────────────

// TestProtocolDiagExportRouteIsRegistered — the documented route must exist. It
// was implemented, tested at its own boundary and documented in openapi.go, but
// never wired into the mux, so a live probe 404'd (D-12). No phantom routes.
func TestProtocolDiagExportRouteIsRegistered(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/export", admin, map[string]any{
		"protocol": "bgp",
		"issue_id": "bgp-session-down",
		"device":   map[string]string{"hostname": "core-01", "platform": "Cisco IOS-XE"},
		"outputs": []map[string]string{
			{"spec_id": "bgp-summary", "output": "Neighbor V AS MsgRcvd MsgSent Up/Down State\n10.0.0.2 4 65002 0 0 never Idle\nneighbor 10.0.0.2 password s3cr3tPeerPass"},
		},
	})
	if st == http.StatusNotFound {
		t.Fatal("POST …/protocol-diagnostics/export is documented but not registered — this is D-12")
	}
	if st != 200 {
		t.Fatalf("export: %d %s", st, b)
	}
	var resp struct {
		Redacted  bool   `json:"redacted"`
		Filename  string `json:"filename"`
		TACExport string `json:"tac_export"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Redacted || strings.TrimSpace(resp.TACExport) == "" || strings.TrimSpace(resp.Filename) == "" {
		t.Fatalf("export response is not the documented bundle: %s", b)
	}
	if strings.Contains(resp.TACExport, "s3cr3tPeerPass") {
		t.Fatal("the registered export leaked a secret the redaction pass must mask")
	}
	// Unauthenticated callers must not reach it.
	if st, _ := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/export", "", map[string]any{"issue_id": "bgp-session-down"}); st != 401 {
		t.Fatalf("unauthenticated export: %d, want 401", st)
	}
	// GET is refused (POST only), so the route cannot be mistaken for a link.
	if st, _ := do(t, srv, "GET", "/api/troubleshoot/protocol-diagnostics/export", admin, nil); st != http.StatusMethodNotAllowed {
		t.Fatalf("GET export: %d, want 405", st)
	}
}
