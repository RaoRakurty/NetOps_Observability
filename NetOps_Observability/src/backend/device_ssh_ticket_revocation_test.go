// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_ssh_ticket_revocation_test.go — wsticket revocation: redeeming a
// still-valid one-time ticket must re-check the LIVE account and tenant, the
// way every JWT-authenticated request does. The ticket branch of withAuth used
// to build claims straight from the consumed ticket — so a ticket minted
// seconds before an admin disabled the user (or the platform suspended the
// tenant) still opened a device-SSH session. (The ticket carries no Sid, so
// session-active cannot be checked at redemption — a separate design item, not
// covered here by design.) Uses the wsFix harness from device_ssh_ticket_test.go.

import (
	"net/http"
	"testing"
)

func TestWSTicketRefusedForDisabledUser(t *testing.T) {
	f := newWSFix(t)
	st, tk := ticket(t, f, f.opToken, "dev-1")
	if st != http.StatusOK || tk == "" {
		t.Fatalf("ticket issuance: status %d, ticket %q", st, tk)
	}
	if _, err := f.s.users.Update("op-acme", User{Status: "disabled"}); err != nil {
		t.Fatal(err)
	}
	if got := wsConnectStatus(t, f, "dev-1", tk); got != http.StatusUnauthorized {
		t.Fatalf("disabled user redeeming a valid ticket: status %d, want 401", got)
	}
}

func TestWSTicketRefusedForSuspendedTenant(t *testing.T) {
	f := newWSFix(t)
	st, tk := ticket(t, f, f.opToken, "dev-1")
	if st != http.StatusOK || tk == "" {
		t.Fatalf("ticket issuance: status %d, ticket %q", st, tk)
	}
	tn, ok := f.s.tenants.Get("acme")
	if !ok {
		t.Fatal("acme tenant missing")
	}
	if _, err := f.s.tenants.SetStatus(tn.ID, TenantStatusSuspended); err != nil {
		t.Fatal(err)
	}
	if got := wsConnectStatus(t, f, "dev-1", tk); got != http.StatusForbidden {
		t.Fatalf("suspended tenant redeeming a valid ticket: status %d, want 403", got)
	}
}
