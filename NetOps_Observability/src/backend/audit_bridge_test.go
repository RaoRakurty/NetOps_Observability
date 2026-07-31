package backend

// audit_bridge_test.go — the audit → corr_signals mirror (item 121): only
// allowed mutations are signal-worthy, the row mapping is stable and
// tenant-honest, and the v5 signal id is deterministic.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuditSignalWorthy(t *testing.T) {
	cases := []struct {
		name string
		e    AuditEvent
		want bool
	}{
		{"allowed POST", AuditEvent{Method: http.MethodPost, Decision: "allow"}, true},
		{"allowed PUT", AuditEvent{Method: http.MethodPut, Decision: "allow"}, true},
		{"synthetic TRIAGE", AuditEvent{Method: "TRIAGE", Decision: "allow"}, true},
		{"denied POST is not a change", AuditEvent{Method: http.MethodPost, Decision: "deny"}, false},
		{"errored POST is not a change", AuditEvent{Method: http.MethodPost, Decision: "error"}, false},
		{"GET denial stays out of the feed", AuditEvent{Method: http.MethodGet, Decision: "deny"}, false},
		{"GET allow", AuditEvent{Method: http.MethodGet, Decision: "allow"}, false},
	}
	for _, c := range cases {
		if got := auditSignalWorthy(c.e); got != c.want {
			t.Errorf("%s: worthy = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAuditSignalRowMapping(t *testing.T) {
	when := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	e := AuditEvent{
		ID: "ev1", Actor: "alice", Tenant: "Acme", Cross: false,
		Method: http.MethodPost, Path: "/api/alerts/maintenance-windows",
		Status: 201, Decision: "allow", Time: when,
	}
	row, scope := auditSignalRow(e)
	if row["tenant_id"] != "acme" || scope != "acme" {
		t.Fatalf("scoped action must land under its tenant: %v / %v", row["tenant_id"], scope)
	}
	if row["source"] != "audit" || row["kind"] != "audit_change" || row["severity"] != "info" {
		t.Fatalf("audit row shape wrong: %+v", row)
	}
	if row["entity_type"] != "service" || row["entity_id"] != "alerts" {
		t.Fatalf("entity must be the API area: %+v", row)
	}
	if row["observer_id"] == "" {
		t.Fatal("observer_required constraint: observer_id must never be empty")
	}
	attrs, _ := row["attrs"].(string)
	if !strings.Contains(attrs, `"actor":"alice"`) || !strings.Contains(attrs, `"status":201`) {
		t.Fatalf("attrs must carry the actor/status that make a change readable: %s", attrs)
	}

	// Determinism: same event → same signal_id (idempotent retry).
	row2, _ := auditSignalRow(e)
	if row["signal_id"] != row2["signal_id"] {
		t.Fatal("signal_id must be deterministic for the same event")
	}
	// Different event → different id.
	e2 := e
	e2.ID = "ev2"
	row3, _ := auditSignalRow(e2)
	if row["signal_id"] == row3["signal_id"] {
		t.Fatal("distinct events must not collide")
	}

	// Platform-owner action: untagged row, platform-scoped write — never a
	// tenant literal that would leak into some tenant's feed.
	owner := e
	owner.Tenant, owner.Cross = TenantGlobal, true
	rowP, scopeP := auditSignalRow(owner)
	if rowP["tenant_id"] != "" || scopeP != "__all__" {
		t.Fatalf("owner action must be untagged/platform-scoped: %v / %v", rowP["tenant_id"], scopeP)
	}
}

func TestUUIDv5Shape(t *testing.T) {
	u := uuidV5("audit|x")
	if !isUUIDToken(u) {
		t.Fatalf("uuidV5 must mint a valid UUID token: %s", u)
	}
	if u[14] != '5' {
		t.Fatalf("version nibble must be 5: %s", u)
	}
	if u != uuidV5("audit|x") {
		t.Fatal("uuidV5 must be deterministic")
	}
}
