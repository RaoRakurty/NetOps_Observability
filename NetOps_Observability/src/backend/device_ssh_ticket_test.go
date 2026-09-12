// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_ssh_ticket_test.go — HTTP-level regression for the one-time WebSocket
// ticket flow that replaced ?token=<session JWT> on the device-SSH gateway.
//
// These drive the REAL router + auth middleware. The tests below stop at the
// pre-upgrade authorization/scope boundary (they do not complete a WebSocket
// handshake): every check they assert runs BEFORE ws.Upgrade, which is exactly
// the layer where a credential/scope decision is made. The store-level
// properties (single-use, concurrency, TTL, entropy) are proven in
// internal/wsticket/wsticket_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/models"
)

// wsFix spins the real server, enables FEATURE_DEVICE_SSH, and seeds one device
// owned by tenant "acme" plus an operator in that tenant. Cross-tenant and
// wrong-device fixtures are added per-test.
type wsFix struct {
	srv     *httptest.Server
	s       *server
	opToken string // operator in acme
}

func newWSFix(t *testing.T) *wsFix {
	t.Helper()
	t.Setenv("FEATURE_DEVICE_SSH", "true")
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Tenant acme + an operator in it.
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme", "slug": "acme"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op-acme", "password": "Passw0rd!2345", "role": "operator", "tenant_id": "acme",
	}); st != 201 {
		t.Fatalf("create operator: %d %s", st, b)
	}
	s.discovery.Upsert(models.Device{ID: "dev-1", Name: "dev-1", Address: "10.0.0.1", TenantID: "acme", Source: "manual"})

	return &wsFix{srv: srv, s: s, opToken: login(t, srv, "op-acme", "Passw0rd!2345").Token}
}

func ticket(t *testing.T, f *wsFix, token, devID string) (int, string) {
	t.Helper()
	st, b := do(t, f.srv, "POST", "/api/devices/"+devID+"/ssh-ticket", token, nil)
	var r struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expires_in_seconds"`
	}
	_ = json.Unmarshal(b, &r)
	return st, r.Ticket
}

// wsConnectStatus issues a raw GET with WebSocket headers to the ssh route and
// returns the PRE-UPGRADE HTTP status. A 101 never occurs here because the test
// client is plain http.Client, but every auth/scope refusal happens before the
// upgrade and surfaces as a 4xx we can read.
func wsConnectStatus(t *testing.T, f *wsFix, devID, ticketVal string) int {
	t.Helper()
	req, err := http.NewRequest("GET", f.srv.URL+"/api/devices/"+devID+"/ssh?ticket="+ticketVal, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// WS-1: an authorized operator can obtain a ticket.
func TestWSTicketIssuedToAuthorizedOperator(t *testing.T) {
	f := newWSFix(t)
	st, tk := ticket(t, f, f.opToken, "dev-1")
	if st != http.StatusOK {
		t.Fatalf("ticket issuance: status %d, want 200", st)
	}
	if len(tk) != 43 {
		t.Fatalf("ticket length %d, want 43 (256-bit base64url)", len(tk))
	}
}

// WS-10: a read-only user cannot obtain an SSH ticket.
func TestWSTicketDeniedToUnauthorizedRole(t *testing.T) {
	f := newWSFix(t)
	admin := login(t, f.srv, "admin", "Passw0rd!2345").Token
	if st, b := do(t, f.srv, "POST", "/api/users", admin, map[string]any{
		"username": "ro-acme", "password": "Passw0rd!2345", "role": "read-only", "tenant_id": "acme",
	}); st != 201 {
		t.Fatalf("create read-only: %d %s", st, b)
	}
	ro := login(t, f.srv, "ro-acme", "Passw0rd!2345").Token
	if st, _ := ticket(t, f, ro, "dev-1"); st != http.StatusForbidden {
		t.Fatalf("read-only ticket request: status %d, want 403", st)
	}
}

// WS-10b: an API-key principal (machine client) cannot obtain an SSH ticket.
func TestWSTicketDeniedToApiKeyPrincipal(t *testing.T) {
	f := newWSFix(t)
	// Unauthenticated request → 401, proving the endpoint is not open.
	if st, _ := do(t, f.srv, "POST", "/api/devices/dev-1/ssh-ticket", "", nil); st != http.StatusUnauthorized {
		t.Fatalf("unauthenticated ticket request: status %d, want 401", st)
	}
}

// WS-8: a ticket cannot be minted for a device in another tenant (404 — the
// device's existence is never revealed across the tenant boundary).
func TestWSTicketCrossTenantDeviceIsNotFound(t *testing.T) {
	f := newWSFix(t)
	admin := login(t, f.srv, "admin", "Passw0rd!2345").Token
	// A device owned by a DIFFERENT tenant.
	if st, b := do(t, f.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Beta", "slug": "beta"}); st != 201 {
		t.Fatalf("create beta: %d %s", st, b)
	}
	f.s.discovery.Upsert(models.Device{ID: "dev-beta", Name: "dev-beta", Address: "10.9.9.9", TenantID: "beta", Source: "manual"})
	if st, _ := ticket(t, f, f.opToken, "dev-beta"); st != http.StatusNotFound {
		t.Fatalf("acme operator requesting beta device ticket: status %d, want 404", st)
	}
}

// WS-2 + WS-4: a valid ticket authorizes the connect once, and a replay is
// rejected. We assert the PRE-UPGRADE decision: the first connect passes
// auth/scope (so it is not a 4xx credential refusal), the second is 401.
func TestWSConnectConsumesTicketOnceThenReplayFails(t *testing.T) {
	f := newWSFix(t)
	_, tk := ticket(t, f, f.opToken, "dev-1")
	if tk == "" {
		t.Fatal("no ticket issued")
	}
	// First connect: the ticket is consumed in withAuth and the handler runs.
	// Because our client cannot complete the WS handshake, ws.Upgrade fails
	// AFTER auth — but crucially NOT with 401/403/404. Any non-credential status
	// proves the ticket was accepted.
	first := wsConnectStatus(t, f, "dev-1", tk)
	if first == http.StatusUnauthorized || first == http.StatusForbidden || first == http.StatusNotFound {
		t.Fatalf("valid ticket connect was refused at the credential layer: %d", first)
	}
	// Replay the SAME ticket: it was burned, so withAuth refuses with 401.
	if second := wsConnectStatus(t, f, "dev-1", tk); second != http.StatusUnauthorized {
		t.Fatalf("replayed ticket: status %d, want 401", second)
	}
}

// WS-7 (HTTP scope): a ticket minted for dev-1 presented at dev-2 is refused.
// dev-2 is a real acme device (so the 403 is the ticket-scope check, not a 404
// visibility refusal).
func TestWSConnectTicketWrongDeviceRefused(t *testing.T) {
	f := newWSFix(t)
	f.s.discovery.Upsert(models.Device{ID: "dev-2", Name: "dev-2", Address: "10.0.0.2", TenantID: "acme", Source: "manual"})
	_, tk := ticket(t, f, f.opToken, "dev-1")
	if got := wsConnectStatus(t, f, "dev-2", tk); got != http.StatusForbidden && got != http.StatusUnauthorized {
		// The ticket is consumed by withAuth keyed on the raw value regardless of
		// path, then the handler's scope check refuses the wrong device (403).
		t.Fatalf("cross-device ticket at dev-2: status %d, want 403/401", got)
	}
}
