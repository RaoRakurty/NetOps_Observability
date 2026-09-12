// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"context"
	"testing"
	"time"
)

// outbox_epoch_test.go — M10 (2026-08-15 review): the create idempotency key
// was permanent (`provider:create:tenant:corr`, no epoch), EnqueueOutbox
// deduped against the existing row REGARDLESS of its status, and dispatch
// no-op'd every create once the link resolved. Consequences: a dead-lettered
// create could never be retried (the manual POST answered 202 while enqueuing
// nothing) and the documented reopen path — "reopen only via a NEW create
// decision from the sweeper" — was structurally dead.

// epochAdapter is a minimal fake Adapter counting external calls.
type epochAdapter struct {
	created int
	lookups int
}

func (a *epochAdapter) Name() string                                    { return "servicenow" }
func (a *epochAdapter) ValidateConfig(SystemConfig) error               { return nil }
func (a *epochAdapter) HealthCheck(context.Context, SystemConfig) error { return nil }
func (a *epochAdapter) CreateIncident(_ context.Context, _ SystemConfig, p Payload) (Ref, error) {
	a.created++
	return Ref{Number: "INC0042", SysID: "sys42", URL: "https://sn.example"}, nil
}
func (a *epochAdapter) UpdateIncident(context.Context, SystemConfig, Ref, Payload) error { return nil }
func (a *epochAdapter) AddWorkNote(context.Context, SystemConfig, Ref, string) error     { return nil }
func (a *epochAdapter) ResolveIncident(context.Context, SystemConfig, Ref, string) error { return nil }
func (a *epochAdapter) LookupByCorrelationID(context.Context, SystemConfig, string) (Ref, bool, error) {
	a.lookups++
	return Ref{}, false, nil
}
func (a *epochAdapter) FetchIncident(context.Context, SystemConfig, Ref) (RemoteIncident, bool, error) {
	return RemoteIncident{}, false, nil
}

func epochPayload(corr string) Payload {
	return Payload{CorrObjectID: corr, ExternalSystem: "servicenow", Title: "t", Verdict: "confirmed", Summary: "s"}
}

// FAILING-FIRST: enqueue create → dead-letter it → enqueue again. The second
// enqueue must land a PENDING row (revive), not vanish into the dead row's
// idempotency key.
func TestM10DeadLetterCreateIsRetriable(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()

	enq, err := EnqueueCreate(ctx, st, "t_a", "servicenow", epochPayload("obj-1"))
	if err != nil || !enq {
		t.Fatalf("first enqueue: enq=%v err=%v", enq, err)
	}
	// While the row is live, a duplicate is honestly refused (the 409 signal).
	if enq, err = EnqueueCreate(ctx, st, "t_a", "servicenow", epochPayload("obj-1")); err != nil || enq {
		t.Fatalf("duplicate while pending: enq=%v err=%v, want false/nil", enq, err)
	}

	// Dead-letter the row (the worker's path: claim, then finish as dead).
	items, err := st.ClaimDueOutbox(ctx, "w1", 10, time.Minute)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim: n=%d err=%v", len(items), err)
	}
	it := items[0]
	it.Status = "dead_letter"
	if err := st.FinishOutbox(ctx, it); err != nil {
		t.Fatalf("finish dead_letter: %v", err)
	}

	// The retry: same payload, same key — must REVIVE, not dedupe away.
	if enq, err = EnqueueCreate(ctx, st, "t_a", "servicenow", epochPayload("obj-1")); err != nil || !enq {
		t.Fatalf("re-enqueue after dead_letter: enq=%v err=%v, want true/nil (the reopen/retry path was dead)", enq, err)
	}
	out, _, err := st.ListOutbox(ctx, "t_a", false, MaxPage, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 1 || out[0].Status != "pending" {
		t.Fatalf("outbox after revive = %+v, want exactly one PENDING row", out)
	}
}

// The reopen half: once the link is RESOLVED, a fresh create decision mints a
// reopen-epoch key (fresh row) and dispatch performs the external create —
// while a stale epoch-less row from the previous life still no-ops.
func TestM10PostResolveCreateReopens(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	syncedAt := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	if err := st.PutLink(ctx, Link{
		TenantID: "t_a", CorrObjectID: "obj-9", ExternalSystem: "servicenow",
		InstanceURL: "https://sn.example", TicketNumber: "INC0001", SysID: "sys1",
		Status: "resolved", LastSyncedAt: &syncedAt,
	}); err != nil {
		t.Fatalf("seed resolved link: %v", err)
	}

	// A NEW create decision after the resolve → fresh reopen-keyed row.
	enq, err := EnqueueCreate(ctx, st, "t_a", "servicenow", epochPayload("obj-9"))
	if err != nil || !enq {
		t.Fatalf("post-resolve enqueue: enq=%v err=%v, want true", enq, err)
	}
	// And a STALE row of the previous life (epoch-less key) alongside it.
	if enq, err := st.EnqueueOutbox(ctx, OutboxItem{
		TenantID: "t_a", ID: "stale-1", CorrObjectID: "obj-9", ExternalSystem: "servicenow",
		Action: "create", IdempotencyKey: "servicenow:create:t_a:obj-9", Status: "pending",
		Payload: map[string]any{"corr_object_id": "obj-9"},
	}); err != nil || !enq {
		t.Fatalf("seed stale row: enq=%v err=%v", enq, err)
	}

	ad := &epochAdapter{}
	w := NewWorker(st,
		func(_ context.Context, tenant, system string) (SystemConfig, bool, error) {
			return SystemConfig{System: system, TenantID: tenant, InstanceURL: "https://sn.example"}, true, nil
		}, nil, nil)
	w.RegisterAdapter("servicenow", ad)
	if _, err := w.Tick(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Exactly ONE external create: the reopen row acted, the stale row no-op'd.
	if ad.created != 1 {
		t.Fatalf("external creates = %d, want 1 (0 = reopen path still dead; 2 = stale row leaked through)", ad.created)
	}
	link, found, err := st.GetLink(ctx, "t_a", false, "obj-9", "servicenow")
	if err != nil || !found {
		t.Fatalf("link after reopen: found=%v err=%v", found, err)
	}
	if link.Status != "open" || link.TicketNumber != "INC0042" {
		t.Fatalf("link = %+v, want reopened with the NEW ticket", link)
	}
}
