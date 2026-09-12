// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// audit_retention_exclusions_pg_test.go — the platform floor must protect the
// same rows the FILE backend's retained trail protects, and only those.
//
// THE DEFECT. platformFloorSQL matched "mutating method + platform path
// prefix" and stopped there. IsPlatformPath checks platformPathExclusions
// FIRST, so /api/auth/login, /api/auth/refresh, /api/copilot/chat and the
// inbound webhooks are NOT platform config changes on the file path — they are
// the highest-frequency POSTs on the platform and are excluded by name. On
// Postgres they matched the floor anyway and were kept for the PLATFORM horizon
// (90 days by default) instead of the retention the operator configured. That
// is over-retention of AUTHENTICATION and LLM audit rows: a data-minimisation
// defect, and two backends that disagree about what "keep 30 days" means.
//
// The unit-level proof (internal/audit/retention_floor_test.go) captures the
// bound arrays and evaluates the predicate in Go. This one runs the REAL
// statement against a REAL Postgres, which is the only thing that proves the
// three-array binding and the `NOT (… LIKE ANY(…))` negation actually parse.
//
// Gated on DATABASE_URL_TEST exactly like its sibling, and it borrows that
// file's fixture so both suites write, assert and clean up under one dedicated
// tenant.

import (
	"context"
	"testing"
	"time"

	"netops/backend/internal/audit"
)

func TestPgRetentionDoesNotOverRetainExcludedPaths(t *testing.T) {
	ps, a := auditRetentionFixture(t)
	now := time.Now().UTC()
	// Every row is 40 days old: past the 30-day general horizon, inside the
	// 90-day platform floor. Survival therefore says exactly one thing — the
	// floor claimed this row.
	rows := []struct {
		id           string
		method, path string
		keep         bool
	}{
		// Excluded by name in platformtrail.go: authentication volume and a
		// user acting on themselves. None of them is platform CONFIG.
		{"excl-login", "POST", "/api/auth/login", false},
		{"excl-refresh", "POST", "/api/auth/refresh", false},
		{"excl-logout", "POST", "/api/auth/logout", false},
		{"excl-changepw", "POST", "/api/auth/change-password", false},
		{"excl-mfa", "POST", "/api/auth/mfa/verify", false},
		{"excl-ldap", "POST", "/api/auth/ldap/login", false},
		// The LLM proxy: prompts and completions, not provider configuration.
		{"excl-copilot", "POST", "/api/copilot/chat", false},
		// A third party calling in, not an operator changing the stack.
		{"excl-webhook", "POST", "/api/integrations/webhook/servicenow", false},
		// The controls: these ARE platform config and the floor must hold them.
		{"floor-backup", "PUT", "/api/system/backup/schedule", true},
		{"floor-oidc", "POST", "/api/auth/oidc/config", true},
		{"floor-copilot-config", "PUT", "/api/copilot/config", true},
	}
	for _, r := range rows {
		if err := a.RecordStrict(AuditEvent{
			ID: r.id, Time: now.Add(-40 * 24 * time.Hour), Actor: "rao", Tenant: auditRetentionTenant,
			Method: r.method, Path: r.path, Status: 200, Decision: "allow",
		}); err != nil {
			t.Fatalf("record %s: %v", r.id, err)
		}
		// The expectation is not hand-maintained: it IS the file backend's
		// answer, so the two paths cannot drift apart without failing here.
		if got := audit.IsPlatformChange(audit.Event{Method: r.method, Path: r.path}); got != r.keep {
			t.Fatalf("%s: the file trail says IsPlatformChange=%v but this table expects keep=%v — "+
				"fix the table, not the assertion", r.id, got, r.keep)
		}
	}

	if _, err := audit.SweepRetention(context.Background(), ps.DB(), 30, 90); err != nil {
		t.Fatalf("sweep: %v — the three-array floor did not bind, so retention would fail "+
			"silently the moment an operator switched it on", err)
	}

	left, err := a.List(auditRetentionTenant, false, auditQuery{Limit: audit.MaxQueryLimit})
	if err != nil {
		t.Fatalf("list after sweep: %v", err)
	}
	survived := map[string]bool{}
	for _, e := range left {
		survived[e.ID] = true
	}
	for _, r := range rows {
		if survived[r.id] == r.keep {
			continue
		}
		if survived[r.id] {
			t.Errorf("%s (%s %s) SURVIVED a 30-day retention at 40 days old: the SQL floor claimed it "+
				"as a platform config change, but the file trail excludes it. Authentication and LLM "+
				"rows are being kept for the platform horizon nobody asked for.", r.id, r.method, r.path)
			continue
		}
		t.Errorf("%s (%s %s) was DELETED: the floor must hold a platform config change past the "+
			"general horizon", r.id, r.method, r.path)
	}
}
