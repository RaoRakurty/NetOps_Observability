// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"netops/backend/internal/ticketing"
	"testing"
)

// ticketing_isolation_test.go — cross-tenant isolation for the ticketing store
// (CLAUDE.md §3a). The in-memory store is the default build's backend and has NO
// RLS backstop, so it must enforce tenant scoping itself. Asserts: own-only
// list, cross-tenant get/delete invisible, a scoped caller can never reach
// another tenant's rows, and the platform ('*') view sees all.

func TestTicketingStore_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	st := ticketing.NewMemStore()

	// Tenant A and B each own a policy + a ticket link.
	if err := st.PutPolicy(ctx, ticketing.IncidentPolicy{ID: "p1", TenantID: "t_a", ExternalSystem: "servicenow", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPolicy(ctx, ticketing.IncidentPolicy{ID: "p1", TenantID: "t_b", ExternalSystem: "servicenow", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutLink(ctx, ticketing.Link{TenantID: "t_a", CorrObjectID: "obj-a", ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC0001"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutLink(ctx, ticketing.Link{TenantID: "t_b", CorrObjectID: "obj-b", ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC0002"}); err != nil {
		t.Fatal(err)
	}

	// Own-only list: A sees exactly one policy, and it is A's.
	aPolicies, err := st.ListPolicies(ctx, "t_a", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(aPolicies) != 1 || aPolicies[0].TenantID != "t_a" {
		t.Fatalf("tenant A list leaked: %+v", aPolicies)
	}

	// Cross-tenant get is invisible — A cannot fetch B's link even though it
	// shares the same logical id "p1"/corr id namespace.
	if _, found, _ := st.GetLink(ctx, "t_a", false, "obj-b", "servicenow"); found {
		t.Fatalf("tenant A fetched tenant B's ticket link (cross-tenant leak)")
	}
	if _, found, _ := st.GetPolicy(ctx, "t_a", false, "p1"); !found {
		t.Fatalf("tenant A should see its OWN policy p1")
	}

	// Cross-tenant delete must not touch B's row.
	if deleted, _ := st.DeletePolicy(ctx, "t_a", false, "p1"); !deleted {
		t.Fatalf("tenant A could not delete its own policy")
	}
	if _, found, _ := st.GetPolicy(ctx, "t_b", false, "p1"); !found {
		t.Fatalf("deleting A's policy removed B's policy (cross-tenant delete leak)")
	}

	// A "p1" delete from A must not have removed B's identically-keyed policy:
	// re-create A's and confirm both still resolve independently.
	_ = st.PutPolicy(ctx, ticketing.IncidentPolicy{ID: "p1", TenantID: "t_a", Enabled: true})

	// Platform cross-tenant view sees both.
	all, err := st.ListPolicies(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("platform view should see both tenants' policies, got %d", len(all))
	}

	// Outbox + audit scope the same way.
	_, _ = st.EnqueueOutbox(ctx, ticketing.OutboxItem{TenantID: "t_a", ID: "o1", CorrObjectID: "obj-a", Action: "create", IdempotencyKey: "servicenow:create:t_a:obj-a"})
	_, _ = st.EnqueueOutbox(ctx, ticketing.OutboxItem{TenantID: "t_b", ID: "o2", CorrObjectID: "obj-b", Action: "create", IdempotencyKey: "servicenow:create:t_b:obj-b"})
	aOut, _, _ := st.ListOutbox(ctx, "t_a", false, ticketing.MaxPage, 0)
	if len(aOut) != 1 || aOut[0].TenantID != "t_a" {
		t.Fatalf("outbox leaked across tenants: %+v", aOut)
	}

	_ = st.AppendAudit(ctx, ticketing.AuditEntry{TenantID: "t_a", ID: "au1", CorrObjectID: "obj-a", Action: "create"})
	_ = st.AppendAudit(ctx, ticketing.AuditEntry{TenantID: "t_b", ID: "au2", CorrObjectID: "obj-b", Action: "create"})
	aAudit, _, _ := st.ListAudit(ctx, "t_a", false, "", ticketing.MaxPage, 0)
	if len(aAudit) != 1 || aAudit[0].TenantID != "t_a" {
		t.Fatalf("audit leaked across tenants: %+v", aAudit)
	}
}

func TestTicketingStore_OutboxIdempotent(t *testing.T) {
	ctx := context.Background()
	st := ticketing.NewMemStore()
	item := ticketing.OutboxItem{TenantID: "t_a", ID: "o1", CorrObjectID: "obj-a", Action: "create", IdempotencyKey: "k1"}
	_, _ = st.EnqueueOutbox(ctx, item)
	dup := item
	dup.ID = "o2" // different id, same idempotency key
	_, _ = st.EnqueueOutbox(ctx, dup)
	out, _, _ := st.ListOutbox(ctx, "t_a", false, ticketing.MaxPage, 0)
	if len(out) != 1 {
		t.Fatalf("idempotency key should dedupe enqueue, got %d items", len(out))
	}
}
